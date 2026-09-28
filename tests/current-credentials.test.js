'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
require('./test-isolation');

const { Sub2ApiAdminClient, safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { assertBackupCoversUpdateTargets } = require('../backend/sync');
const {
  accountTestOwnershipDigest,
  accountTestTargetDigest,
  accountTestTargetRevision,
  matchesAccountTestTargetRevision,
} = require('../backend/accountTargetRevision');
const { tokenFingerprint } = require('../backend/lib/token');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const clone = (value) => JSON.parse(JSON.stringify(value));

// These are synthetic opaque strings, never production credentials. The DTO
// deliberately has only presence metadata while export has current raw values.
function fixture(id = 124) {
  const current = {
    access_token: `fixture-current-access-${id}`,
    refresh_token: `fixture-current-refresh-${id}`,
    id_token: `fixture-current-id-${id}`,
  };
  const identity = {
    chatgpt_account_id: `fixture-account-${id}`,
    chatgpt_user_id: `fixture-user-${id}`,
  };
  const dto = {
    id,
    name: 'free' + String(id).padStart(5, '0'),
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    credentials: { ...identity },
    credentials_status: {
      has_access_token: true,
      has_refresh_token: true,
      has_id_token: true,
    },
    extra: {
      access_token_sha256: sha256(`fixture-stale-access-${id}`),
      refresh_token_sha256: sha256(`fixture-stale-refresh-${id}`),
    },
  };
  const exported = {
    name: dto.name,
    platform: dto.platform,
    type: dto.type,
    credentials: { ...identity, ...current },
    extra: { ...dto.extra },
  };
  return { dto, exported, current };
}

function mockClient(fixtures = [fixture()], options = {}) {
  const client = new Sub2ApiAdminClient({
    baseUrl: 'https://current-credentials.invalid',
    apiKey: 'fixture-admin-key',
    jwt: '',
  });
  const calls = [];
  const detailReads = new Map();
  // Keep list/get/export implementations intact, but replace the transport.
  // Every unexpected request throws, so this file cannot contact a real API.
  client.request = async (method, pathname, _body, requestOptions = {}) => {
    const query = new URL(pathname, client.baseUrl);
    const schedulerMatch = /^\/api\/v1\/admin\/accounts\/([1-9]\d*)\/schedulable$/.exec(query.pathname);
    if (method === 'POST' && schedulerMatch && options.allowSchedulerWrites === true) {
      const id = Number(schedulerMatch[1]);
      const entry = fixtures.find((item) => item.dto.id === id);
      assert.ok(entry, 'unexpected scheduler fixture ID');
      assert.equal(typeof _body?.schedulable, 'boolean');
      assert.equal(requestOptions.writeOperation, true);
      calls.push({ kind: 'schedulable', id, value: _body.schedulable });
      entry.dto.schedulable = _body.schedulable;
      options.afterSchedulerWrite?.(requestOptions);
      return clone(entry.dto);
    }
    assert.equal(method, 'GET');
    if (query.pathname === '/api/v1/admin/accounts/data') {
      const ids = String(query.searchParams.get('ids') || '').split(',').filter(Boolean).map(Number);
      calls.push({ kind: 'export', ids, includeProxies: query.searchParams.get('include_proxies') });
      assert.ok(ids.length > 0 && ids.length <= 100, 'current credentials require bounded ID-scoped exports');
      assert.equal(query.searchParams.get('include_proxies'), 'false');
      if (options.exportError) throw options.exportError;
      const selected = fixtures.filter((item) => ids.includes(item.dto.id));
      const accounts = options.exportRows
        ? options.exportRows(selected, ids)
        : selected.map((item) => item.exported);
      options.afterExport?.(requestOptions);
      return clone({ accounts, proxies: [] });
    }
    if (query.pathname === '/api/v1/admin/accounts') {
      const page = Number(query.searchParams.get('page'));
      const pageSize = Number(query.searchParams.get('page_size'));
      calls.push({ kind: 'list', page });
      return clone({
        items: fixtures.slice((page - 1) * pageSize, page * pageSize).map((item) => item.dto),
        total: fixtures.length,
        page,
        page_size: pageSize,
        pages: Math.max(1, Math.ceil(fixtures.length / pageSize)),
      });
    }
    const match = /^\/api\/v1\/admin\/accounts\/([1-9]\d*)$/.exec(query.pathname);
    if (match) {
      const id = Number(match[1]);
      const entry = fixtures.find((item) => item.dto.id === id);
      assert.ok(entry, 'unexpected detail ID');
      const count = (detailReads.get(id) || 0) + 1;
      detailReads.set(id, count);
      calls.push({ kind: 'detail', id, count });
      return clone(options.detailRow ? options.detailRow(entry, count) : entry.dto);
    }
    throw new Error('Unexpected fixture request path');
  };
  return { client, calls, detailReads };
}

function assertCurrent(account, entry) {
  assert.equal(account.schemaValid, true);
  assert.equal(account.fingerprintConflict, false);
  for (const kind of ['access', 'refresh', 'id']) {
    assert.equal(account.tokenFingerprints[kind], tokenFingerprint(entry.current[kind + '_token']));
    assert.equal(account.credentialPresence[kind], 'present');
  }
  const serialized = JSON.stringify(account);
  for (const value of Object.values(entry.current)) assert.equal(serialized.includes(value), false);
  assert.equal(Object.hasOwn(account, 'credentials'), false);
}

function assertInvalid(error) {
  assert.equal(error.code, 'SUB2API_CURRENT_CREDENTIALS_INVALID');
  assert.equal(String(error.message).includes('fixture-current-'), false);
  return true;
}

test('current credentials list resolves stale metadata through the real export adapter and passes strict backup coverage', async () => {
  const entry = fixture();
  const { client, calls } = mockClient([entry]);
  const accounts = await client.listAccounts({ requirePaginationMetadata: true });
  assert.equal(accounts.length, 1);
  assertCurrent(accounts[0], entry);
  assert.deepEqual(assertBackupCoversUpdateTargets({ accounts: [entry.exported], proxies: [] }, [{
    action: 'update', accountId: entry.dto.id, accountName: entry.dto.name, _account: accounts[0],
  }]), { updateTargetCount: 1 });
  assert.deepEqual(calls.filter((call) => call.kind === 'export').map((call) => call.ids), [[124]]);
});

test('current credentials get resolves all three token fingerprints then rechecks the same account ID', async () => {
  const entry = fixture();
  const { client, calls, detailReads } = mockClient([entry]);
  assertCurrent(await client.getAccount(entry.dto.id), entry);
  assert.equal(detailReads.get(entry.dto.id), 2);
  assert.deepEqual(calls.map((call) => call.kind), ['detail', 'export', 'detail']);
});

test('current credentials changes alter target digest even when masked DTO and old SHA metadata stay unchanged', async () => {
  const entry = fixture();
  const { client } = mockClient([entry]);
  const before = accountTestTargetDigest(await client.getAccount(entry.dto.id));
  assert.match(before, /^[a-f0-9]{64}$/);
  for (const field of ['access_token', 'refresh_token', 'id_token']) {
    const original = entry.exported.credentials[field];
    entry.exported.credentials[field] = original + '-rotated';
    const after = accountTestTargetDigest(await client.getAccount(entry.dto.id));
    assert.notEqual(after, before, field + ' must bind the current token');
    entry.exported.credentials[field] = original;
  }
});

test('current credentials rotation invalidates previously issued target revisions for every token kind', async () => {
  const entry = fixture();
  const { client } = mockClient([entry]);
  const before = await client.getAccount(entry.dto.id);
  const reviewedRevision = accountTestTargetRevision(before);
  assert.match(reviewedRevision, /^account-test-v1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(matchesAccountTestTargetRevision(reviewedRevision, before), true);
  for (const field of ['access_token', 'refresh_token', 'id_token']) {
    const original = entry.exported.credentials[field];
    entry.exported.credentials[field] = original + '-rotated';
    const current = await client.getAccount(entry.dto.id);
    assert.equal(matchesAccountTestTargetRevision(reviewedRevision, current), false, field);
    entry.exported.credentials[field] = original;
    assert.equal(matchesAccountTestTargetRevision(
      reviewedRevision, await client.getAccount(entry.dto.id),
    ), true);
  }
});

test('current credentials list chunks targeted exports at 100 IDs without exporting unrelated accounts or proxies', async () => {
  const entries = Array.from({ length: 205 }, (_, index) => fixture(index + 1));
  const { client, calls } = mockClient(entries);
  const accounts = await client.listAccounts({ requirePaginationMetadata: true });
  assert.equal(accounts.length, entries.length);
  accounts.forEach((account, index) => assertCurrent(account, entries[index]));
  const exports = calls.filter((call) => call.kind === 'export');
  assert.deepEqual(exports.map((call) => call.ids.length), [100, 100, 5]);
  assert.deepEqual(exports.flatMap((call) => call.ids), entries.map((entry) => entry.dto.id));
  assert.equal(exports.every((call) => call.includeProxies === 'false'), true);
});

test('current credentials list maps forward and reversed exports by strong identity rather than row order or name alone', async () => {
  for (const reverse of [false, true]) {
    const entries = [fixture(124), fixture(126), fixture(128)];
    for (const entry of entries) {
      entry.dto.name = 'free00124';
      entry.exported.name = 'free00124';
    }
    const { client } = mockClient(entries, {
      exportRows: (selected) => {
        const rows = selected.map((entry) => entry.exported);
        return reverse ? rows.reverse() : rows;
      },
    });
    const accounts = await client.listAccounts();
    assert.deepEqual(accounts.map((account) => account.id), [124, 126, 128]);
    accounts.forEach((account, index) => assertCurrent(account, entries[index]));
  }
});

for (const mode of ['list', 'get']) {
  const read = (client) => mode === 'list' ? client.listAccounts() : client.getAccount(124);
  test(`current credentials ${mode} rejects wrong strong identity rather than trusting the same name`, async () => {
    const entry = fixture();
    entry.exported.credentials.chatgpt_user_id = 'fixture-other-user';
    const { client } = mockClient([entry]);
    await assert.rejects(read(client), assertInvalid);
  });

  test(`current credentials ${mode} rejects matching email when exported strong identity differs`, async () => {
    const entry = fixture();
    entry.dto.credentials.email = 'same-current-fixture@example.test';
    entry.exported.credentials.email = entry.dto.credentials.email;
    entry.exported.credentials.chatgpt_account_id = 'fixture-other-account';
    const { client } = mockClient([entry]);
    await assert.rejects(read(client), assertInvalid);
  });

  test(`current credentials ${mode} rejects an explicit wrong ID in otherwise matching export rows`, async () => {
    const entry = fixture();
    entry.exported.id = 125;
    const { client } = mockClient([entry]);
    await assert.rejects(read(client), assertInvalid);
  });

  test(`current credentials ${mode} cannot infer present tokens from historical SHA when all current statuses are absent`, async () => {
    const entry = fixture();
    entry.dto.credentials_status = {
      has_access_token: false,
      has_refresh_token: false,
      has_id_token: false,
    };
    const { client, calls } = mockClient([entry]);
    const result = await read(client);
    const account = mode === 'list' ? result[0] : result;
    assert.equal(account.schemaValid, true);
    assert.equal(account.fingerprintConflict, false);
    assert.deepEqual(account.credentialPresence, { access: 'absent', refresh: 'absent', id: 'absent' });
    assert.deepEqual(account.tokenFingerprints, { access: null, refresh: null, id: null });
    assert.equal(calls.some((call) => call.kind === 'export'), false);
  });

  for (const shape of ['fully masked', 'partially raw']) {
    test(`current credentials ${mode} resolves ${shape} DTOs without credentials_status before issuing revisions`, async () => {
      const entry = fixture();
      delete entry.dto.credentials_status;
      if (shape === 'partially raw') {
        entry.dto.credentials.access_token = entry.current.access_token;
        entry.dto.extra.access_token_sha256 = sha256(entry.current.access_token);
      }
      const { client, calls } = mockClient([entry]);
      const getCurrent = async () => {
        const result = await read(client);
        return mode === 'list' ? result[0] : result;
      };
      const before = await getCurrent();
      assertCurrent(before, entry);
      const revision = accountTestTargetRevision(before);
      assert.match(revision, /^account-test-v1\.[A-Za-z0-9_-]{43}$/);
      entry.exported.credentials.refresh_token += '-rotated';
      const after = await getCurrent();
      assert.equal(after.tokenFingerprints.refresh, tokenFingerprint(entry.exported.credentials.refresh_token));
      assert.equal(matchesAccountTestTargetRevision(revision, after), false);
      assert.equal(calls.filter((call) => call.kind === 'export').length, 2);
    });
  }

  test(`current credentials ${mode} rejects duplicate matching export rows`, async () => {
    const { client } = mockClient([fixture()], {
      exportRows: (entries) => [entries[0].exported, entries[0].exported],
    });
    await assert.rejects(read(client), assertInvalid);
  });

  test(`current credentials ${mode} refuses incomplete access refresh and id credentials`, async () => {
    for (const field of ['access_token', 'refresh_token', 'id_token']) {
      const entry = fixture();
      delete entry.exported.credentials[field];
      const { client } = mockClient([entry]);
      await assert.rejects(read(client), assertInvalid);
    }
  });

  test(`current credentials ${mode} rejects exported tokens reported absent by the masked DTO`, async () => {
    for (const kind of ['refresh', 'id']) {
      const entry = fixture();
      entry.dto.credentials_status['has_' + kind + '_token'] = false;
      delete entry.dto.extra[kind + '_token_sha256'];
      const { client } = mockClient([entry]);
      await assert.rejects(read(client), assertInvalid);
    }
  });

  test(`current credentials ${mode} rejects contradictory raw credential aliases`, async () => {
    const entry = fixture();
    entry.exported.credentials.accessToken = 'fixture-different-current-access';
    const { client } = mockClient([entry]);
    await assert.rejects(read(client), assertInvalid);
  });

  test(`current credentials ${mode} fails closed when export is unavailable`, async () => {
    const exportError = Object.assign(new Error('Synthetic export unavailable'), { code: 'FIXTURE_EXPORT_UNAVAILABLE' });
    const { client } = mockClient([fixture()], { exportError });
    await assert.rejects(read(client), (error) => {
      assert.ok(['SUB2API_CURRENT_CREDENTIALS_INVALID', exportError.code].includes(error.code));
      assert.equal(String(error.message).includes('fixture-current-'), false);
      return true;
    });
  });

  test(`current credentials ${mode} cannot return success when cancellation arrives as export completes`, async () => {
    const controller = new AbortController();
    const reason = new Error('Synthetic current-credentials cancellation');
    reason.name = 'AbortError';
    const { client, calls } = mockClient([fixture()], {
      afterExport: ({ signal }) => {
        assert.equal(signal, controller.signal, 'export must retain the caller cancellation signal');
        controller.abort(reason);
      },
    });
    const result = mode === 'list'
      ? client.listAccounts({ signal: controller.signal })
      : client.getAccount(124, { signal: controller.signal });
    await assert.rejects(result);
    assert.equal(controller.signal.aborted, true);
    assert.equal(calls.filter((call) => call.kind === 'export').length, 1);
  });
}

test('current credentials get rejects a wrong detail ID before exporting any credentials', async () => {
  const { client, calls } = mockClient([fixture()], {
    detailRow: (entry) => ({ ...entry.dto, id: 125 }),
  });
  await assert.rejects(client.getAccount(124), (error) => {
    assert.equal(error.code, 'SUB2API_ACCOUNT_RESPONSE_MISMATCH');
    return true;
  });
  assert.equal(calls.some((call) => call.kind === 'export'), false);
});

test('current credentials get rejects a wrong detail ID at the post-export safety recheck', async () => {
  const { client } = mockClient([fixture()], {
    detailRow: (entry, count) => count === 1 ? entry.dto : { ...entry.dto, id: 125 },
  });
  await assert.rejects(client.getAccount(124), (error) => {
    assert.equal(error.code, 'SUB2API_CURRENT_CREDENTIALS_CHANGED');
    return true;
  });
});

test('current credentials get refuses state changes between detail reads', async () => {
  for (const changed of [
    { status: 'active', schedulable: true },
    { name: 'free00999' },
    { group_ids: [99] },
    { credentials: { chatgpt_account_id: 'fixture-other-account', chatgpt_user_id: 'fixture-user-124' } },
  ]) {
    const { client } = mockClient([fixture()], {
      detailRow: (entry, count) => count === 1 ? entry.dto : { ...entry.dto, ...changed },
    });
    await assert.rejects(client.getAccount(124), (error) => {
      assert.equal(error.code, 'SUB2API_CURRENT_CREDENTIALS_CHANGED');
      return true;
    });
  }
});

test('current credentials get allows usage-only changes during the final safety recheck', async () => {
  const entry = fixture();
  const { client, detailReads } = mockClient([entry], {
    detailRow: (item, count) => ({
      ...item.dto,
      usage: { historical: { total_tokens: count * 100, requests: count }, current: null },
    }),
  });
  assertCurrent(await client.getAccount(entry.dto.id), entry);
  assert.equal(detailReads.get(entry.dto.id), 2);
});

test('current credentials list cannot reuse one export row for two IDs sharing a name and strong identity', async () => {
  const first = fixture(124);
  const second = fixture(125);
  second.dto.name = first.dto.name;
  second.dto.credentials = { ...first.dto.credentials };
  const { client } = mockClient([first, second], {
    exportRows: () => [first.exported],
  });
  await assert.rejects(client.listAccounts(), assertInvalid);
});

test('safeAccount still rejects raw credentials contradicting stored fingerprints in the same DTO', () => {
  const entry = fixture();
  const normalized = safeAccount({
    ...entry.dto,
    credentials: { ...entry.dto.credentials, ...entry.current },
  });
  assert.equal(normalized.schemaValid, false);
  assert.equal(normalized.fingerprintConflict, true);
  assert.equal(normalized.tokenFingerprints.access, null);
  assert.equal(normalized.tokenFingerprints.refresh, null);
});

test('schedulable write resolves masked response credentials and preserves the pretest ownership digest', async () => {
  const entry = fixture();
  entry.dto.status = 'active';
  const { client, calls } = mockClient([entry], { allowSchedulerWrites: true });
  const before = await client.getAccount(entry.dto.id);
  const beforeOwnership = accountTestOwnershipDigest(before);
  assert.match(beforeOwnership, /^[a-f0-9]{64}$/);
  calls.length = 0;
  const after = await client.setSchedulable(entry.dto.id, true);
  assertCurrent(after, entry);
  assert.equal(after.schedulable, true);
  assert.equal(accountTestOwnershipDigest(after), beforeOwnership);
  assert.deepEqual(calls.map((call) => call.kind), ['schedulable', 'export', 'detail']);
  assert.deepEqual(calls.filter((call) => call.kind === 'schedulable'), [
    { kind: 'schedulable', id: entry.dto.id, value: true },
  ]);
});

for (const failure of ['export failure', 'export identity change', 'detail state change', 'abort after export', 'abort after write']) {
  test(`schedulable write requires reconciliation without a repeated POST after ${failure}`, async () => {
    const entry = fixture();
    entry.dto.status = 'active';
    const options = { allowSchedulerWrites: true };
    const { client, calls } = mockClient([entry], options);
    await client.getAccount(entry.dto.id);
    calls.length = 0;
    const controller = new AbortController();
    if (failure === 'export failure') {
      options.exportError = Object.assign(new Error('Synthetic export unavailable after write'), {
        code: 'FIXTURE_EXPORT_UNAVAILABLE',
      });
    } else if (failure === 'export identity change') {
      entry.exported.credentials.chatgpt_user_id = 'fixture-other-user';
    } else if (failure === 'detail state change') {
      options.detailRow = (item) => ({ ...item.dto, group_ids: [99] });
    } else {
      const abort = ({ signal }) => {
        assert.equal(signal, controller.signal);
        controller.abort(Object.assign(new Error('Synthetic post-write cancellation'), { name: 'AbortError' }));
      };
      if (failure === 'abort after export') options.afterExport = abort;
      else options.afterSchedulerWrite = abort;
    }
    await assert.rejects(client.setSchedulable(entry.dto.id, true, { signal: controller.signal }), (error) => {
      assert.equal(error.writeOutcomeUnknown, true);
      assert.equal(error.requiresReconciliation, true);
      assert.equal(error.writeOutcomeReason, 'response_credentials_unverified');
      assert.equal(String(error.message).includes('fixture-current-'), false);
      return true;
    });
    assert.deepEqual(calls.filter((call) => call.kind === 'schedulable'), [
      { kind: 'schedulable', id: entry.dto.id, value: true },
    ]);
    assert.equal(entry.dto.schedulable, true, 'the fixture write happened before verification failed');
  });
}
