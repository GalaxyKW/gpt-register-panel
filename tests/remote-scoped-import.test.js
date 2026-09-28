const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

require('./test-isolation');

const {
  normalizeRemoteImportTargets,
  normalizeRemoteImportSourceHashes,
  normalizeRemoteImportTargetBaselines,
  assertRemoteImportSources,
  assertRemoteImportPlan,
  buildImportPlan,
  buildImportPlanIntentVersion,
  buildSnapshot,
  executeImport,
  executeImportPlanItem,
  resolveImportExecutionBinding,
} = require('../backend/sync');
const {
  accountTestTargetRevision,
  accountTestTargetDigest,
  createAccountTargetRevisionIssuer,
} = require('../backend/accountTargetRevision');
const { tokenFingerprint } = require('../backend/lib/token');

const BASE_URL = 'http://127.0.0.1:18080';
const identityKeys = ['account:scoped-account', 'user:scoped-user'];
const expectedCode = (code) => (error) => error.code === code;
const checkpointLogger = { checkpoint() { return true; } };

function account(overrides = {}) {
  return {
    id: 71,
    name: 'free00071',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    identityKeys,
    tokenFingerprints: { access: tokenFingerprint('test-only-old-access') },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'absent' },
    groupIds: [1],
    ...overrides,
  };
}

function target(record = account()) {
  return { accountId: record.id, targetRevision: accountTestTargetRevision(record) };
}

function baseline(record = account(), reviewedTarget = target(record)) {
  return { ...reviewedTarget, targetDigest: accountTestTargetDigest(record) };
}

function item(record = account(), overrides = {}) {
  return {
    key: 'token:tokens:tokens/scoped.json',
    action: 'update',
    accountId: record.id,
    sourceIdentityKeys: [...record.identityKeys],
    _account: record,
    ...overrides,
  };
}

function token(overrides = {}) {
  return {
    source: 'tokens',
    relativePath: 'tokens/scoped.json',
    fileName: 'scoped.json',
    parseStatus: 'ok',
    raw: { access_token: 'test-only-new-access' },
    identityKeys,
    accountId: 'scoped-account',
    userId: 'scoped-user',
    contentHash: 'a'.repeat(64),
    fingerprints: { access: tokenFingerprint('test-only-new-access') },
    expiresAt: '2099-01-01T00:00:00.000Z',
    expiryStatus: 'valid',
    mtimeMs: 1,
    ...overrides,
  };
}

test('remote import target normalization is bounded, canonical and opt-in only', () => {
  assert.equal(normalizeRemoteImportTargets(undefined), undefined);
  const first = target();
  const second = target(account({ id: 72 }));
  const input = [{ ...second, accountId: '72' }, first];
  const result = normalizeRemoteImportTargets(input);
  assert.deepEqual(result, [first, second]);
  assert.equal(input[0].accountId, '72');
  for (const value of [
    null, [], {}, [first, first], [first, { ...first, accountId: '71' }],
    [{ ...first, accountId: '071' }], [{ ...first, accountId: 0 }],
    [{ ...first, accountId: Number.MAX_SAFE_INTEGER + 1 }],
    [{ ...first, targetRevision: 'invalid' }], [{ ...first, extra: true }],
    Array.from({ length: 101 }, (_, index) => ({ ...first, accountId: index + 1 })),
  ]) {
    assert.throws(() => normalizeRemoteImportTargets(value), expectedCode('REMOTE_IMPORT_TARGETS_INVALID'));
  }
});

test('remote source hashes require unique keys and canonical SHA-256 values', () => {
  const source = { selectedKey: item().key, contentHash: 'a'.repeat(64) };
  assert.equal(normalizeRemoteImportSourceHashes(undefined), undefined);
  assert.deepEqual(normalizeRemoteImportSourceHashes([source]), [source]);
  for (const value of [
    null, [], [source, source], [{ ...source, contentHash: 'A'.repeat(64) }],
    [{ ...source, selectedKey: 'account:71' }], [{ ...source, extra: true }],
    [{ ...source, contentHash: '' }],
  ]) {
    assert.throws(() => normalizeRemoteImportSourceHashes(value), expectedCode('REMOTE_IMPORT_SOURCES_INVALID'));
  }
});

test('durable remote baselines must be complete, unique and canonical server records', () => {
  assert.equal(normalizeRemoteImportTargetBaselines(undefined), undefined);
  const before = baseline();
  assert.deepEqual(normalizeRemoteImportTargetBaselines([before]), [before]);
  for (const value of [
    null, [], [target()], [before, before], [{ ...before, targetDigest: 'invalid' }],
    [{ ...before, targetDigest: 'A'.repeat(64) }], [{ ...before, accountId: '071' }],
    [{ ...before, targetRevision: 'invalid' }], [{ ...before, extra: true }],
    Array.from({ length: 101 }, (_, index) => ({ ...before, accountId: index + 1 })),
  ]) {
    assert.throws(() => normalizeRemoteImportTargetBaselines(value), expectedCode('REMOTE_IMPORT_BASELINES_INVALID'));
  }
});

test('a trusted successful-job baseline recovers an old issuer revision only for unchanged targets', () => {
  const remote = account();
  const previousIssuer = createAccountTargetRevisionIssuer(Buffer.alloc(32, 1));
  const oldTarget = { accountId: remote.id, targetRevision: previousIssuer.issue(remote) };
  const oldBaseline = baseline(remote, oldTarget);
  assert.throws(() => assertRemoteImportPlan([item(remote)], [remote], [oldTarget]), expectedCode('REMOTE_IMPORT_TARGET_STALE'));
  assert.doesNotThrow(() => assertRemoteImportPlan([item(remote)], [remote], [oldTarget], [oldBaseline]));
  for (const changed of [
    account({ groupIds: [2] }), account({ status: 'active', schedulable: true }),
    account({ identityKeys: ['account:other', 'user:scoped-user'] }),
    account({ tokenFingerprints: { access: tokenFingerprint('test-only-changed-access') } }),
  ]) {
    assert.throws(
      () => assertRemoteImportPlan([item(remote)], [changed], [oldTarget], [oldBaseline]),
      expectedCode('REMOTE_IMPORT_TARGET_STALE'),
    );
  }
  for (const badBaselines of [
    [baseline(remote)], [baseline(account({ id: 72 }), { ...oldTarget, accountId: 72 })],
    [oldBaseline, baseline(account({ id: 72 }))],
  ]) {
    assert.throws(
      () => assertRemoteImportPlan([item(remote)], [remote], [oldTarget], badBaselines),
      expectedCode('REMOTE_IMPORT_BASELINES_INVALID'),
    );
  }
});

test('scoped plans allow exact strong identity updates and preserve available skips', () => {
  const unavailable = account();
  const available = account({ id: 72, status: 'active', schedulable: true });
  const plan = [item(unavailable), item(available, { action: 'skip' })];
  assert.doesNotThrow(() => assertRemoteImportPlan(plan, [unavailable, available], [target(unavailable), target(available)]));
  assert.doesNotThrow(() => assertRemoteImportPlan([{ action: 'create' }], [], undefined));
  assert.throws(
    () => assertRemoteImportPlan([item(available)], [available], [target(available)]),
    expectedCode('REMOTE_IMPORT_PLAN_INVALID'),
  );
});

test('scoped plans reject creates, conflicts and every out-of-scope action', () => {
  const remote = account();
  for (const candidate of [
    item(remote, { action: 'create' }), item(remote, { action: 'conflict' }),
    item(remote, { accountId: 72 }), item(remote, { accountId: 72, action: 'skip' }),
    item(remote, { conflictingVersions: true }), item(remote, { identityConflict: true }),
  ]) {
    assert.throws(() => assertRemoteImportPlan([candidate], [remote], [target(remote)]), expectedCode('REMOTE_IMPORT_OUTSIDE_SCOPE'));
  }
});

test('scoped plans reject missing, duplicate, stale and identity-insufficient targets', () => {
  const remote = account();
  for (const accounts of [
    [], [remote, remote], [account({ groupIds: [2] })],
    [account({ status: 'active', schedulable: true })],
    [account({ identityKeys: ['email:scoped@example.test'] })],
  ]) {
    assert.throws(() => assertRemoteImportPlan([item(remote)], accounts, [target(remote)]), expectedCode('REMOTE_IMPORT_TARGET_STALE'));
  }
  assert.throws(() => assertRemoteImportPlan([], [remote], [target(remote)]), expectedCode('REMOTE_IMPORT_TARGET_UNCOVERED'));
  assert.throws(() => assertRemoteImportPlan([item(remote), item(remote)], [remote], [target(remote)]), expectedCode('REMOTE_IMPORT_PLAN_INVALID'));
});

test('scoped plans never authorize email-only, partial or mismatching source identities', () => {
  const remote = account();
  for (const sourceIdentityKeys of [
    [], null, ['email:scoped@example.test'], ['account:scoped-account'],
    ['account:scoped-account', 'user:different-user'],
  ]) {
    assert.throws(
      () => assertRemoteImportPlan([item(remote, { sourceIdentityKeys })], [remote], [target(remote)]),
      expectedCode('REMOTE_IMPORT_IDENTITY_MISMATCH'),
    );
  }
});

test('Phase3 output source checks reject changed, missing, historical and duplicate paths', () => {
  const record = token();
  const hashes = [{ selectedKey: item().key, contentHash: record.contentHash }];
  assert.doesNotThrow(() => assertRemoteImportSources({ tokens: [record] }, [item().key], hashes));
  for (const tokens of [
    [], [token({ contentHash: 'b'.repeat(64) })], [token({ historical: true })],
    [token({ parseStatus: 'error' })], [record, record],
  ]) {
    assert.throws(() => assertRemoteImportSources({ tokens }, [item().key], hashes), expectedCode('REMOTE_IMPORT_SOURCE_CHANGED'));
  }
  assert.throws(() => assertRemoteImportSources({ tokens: [record] }, [item().key], undefined), expectedCode('REMOTE_IMPORT_SOURCES_INVALID'));
  assert.throws(() => assertRemoteImportSources({ tokens: [record] }, ['token:tokens:tokens/other.json'], hashes), expectedCode('REMOTE_IMPORT_SOURCES_INVALID'));
});

test('Phase3 output cannot silently promote a newer token at a different path', () => {
  const record = token();
  const newer = token({ relativePath: 'tokens/newer.json', expiresAt: '2100-01-01T00:00:00.000Z' });
  const hashes = [{ selectedKey: item().key, contentHash: record.contentHash }];
  assert.throws(
    () => assertRemoteImportSources({ tokens: [record, newer] }, [item().key], hashes),
    expectedCode('REMOTE_IMPORT_SOURCE_SUPERSEDED'),
  );
});

test('import intent binds remote scope and revisions without changing ordinary imports', () => {
  const plan = [item()];
  const binding = resolveImportExecutionBinding({ baseUrl: BASE_URL }, plan);
  const args = ['a'.repeat(64), [item().key], plan, null, binding];
  const legacy = buildImportPlanIntentVersion(...args);
  assert.equal(buildImportPlanIntentVersion(...args, undefined), legacy);
  const scoped = buildImportPlanIntentVersion(...args, [target()]);
  assert.notEqual(scoped, legacy);
  assert.notEqual(scoped, buildImportPlanIntentVersion(...args, [target(account({ groupIds: [2] }))]));
  const second = target(account({ id: 72 }));
  assert.equal(buildImportPlanIntentVersion(...args, [target(), second]), buildImportPlanIntentVersion(...args, [second, target()]));
});

test('scoped execution requires server-bound output hashes before any client call', async () => {
  let reads = 0;
  for (const options of [
    { remoteTargets: [target()], remoteTargetBaselines: [baseline()] },
    { remoteSourceHashes: [{ selectedKey: item().key, contentHash: 'a'.repeat(64) }] },
  ]) {
    await assert.rejects(
      executeImport({ ...options, client: { async listAccounts() { reads += 1; return []; } } }),
      expectedCode('REMOTE_IMPORT_SOURCES_INVALID'),
    );
  }
  assert.equal(reads, 0);
});

test('scoped execution refuses missing or request-shaped baselines before client calls', async () => {
  let reads = 0;
  const client = { async listAccounts() { reads += 1; return []; } };
  const sourceHashes = [{ selectedKey: item().key, contentHash: 'a'.repeat(64) }];
  for (const options of [
    { remoteTargets: [target()], remoteSourceHashes: sourceHashes },
    { remoteTargetBaselines: [baseline()] },
    { remoteTargets: [target()], remoteSourceHashes: sourceHashes, remoteTargetBaselines: [target()] },
    { remoteTargets: [target()], remoteSourceHashes: sourceHashes, remoteTargetBaselines: [baseline(account({ id: 72 }))] },
  ]) {
    await assert.rejects(executeImport({ ...options, client }), expectedCode('REMOTE_IMPORT_BASELINES_INVALID'));
  }
  assert.equal(reads, 0);
});

test('write-time scoped revision rejects intervening changes but still skips now-available targets', async () => {
  const remote = account();
  let writes = 0;
  const client = {
    async getAccount() { return account({ groupIds: [2] }); },
    async applyOAuthCredentials() { writes += 1; },
  };
  await assert.rejects(
    executeImportPlanItem({ client, item: item(remote), remoteTargetRevision: target(remote).targetRevision }),
    expectedCode('REMOTE_IMPORT_TARGET_STALE'),
  );
  client.getAccount = async () => account({ status: 'active', schedulable: true });
  const outcome = await executeImportPlanItem({ client, item: item(remote), remoteTargetRevision: target(remote).targetRevision });
  assert.equal(outcome.skipped, true);
  assert.equal(writes, 0);
});

test('scoped update writes only the original ID and verifies its new token', async () => {
  const remote = account();
  const record = token();
  const planItem = item(remote, {
    _record: record,
    _raw: { ...record.raw, account_id: record.accountId, user_id: record.userId },
    fingerprints: record.fingerprints,
    expiresAt: record.expiresAt,
  });
  const after = account({ tokenFingerprints: record.fingerprints });
  let reads = 0;
  const writtenIds = [];
  const outcome = await executeImportPlanItem({
    item: planItem,
    remoteTargetRevision: createAccountTargetRevisionIssuer(Buffer.alloc(32, 2)).issue(remote),
    remoteTargetDigest: accountTestTargetDigest(remote),
    logger: checkpointLogger,
    client: {
      async getAccount(id) { assert.equal(id, remote.id); reads += 1; return reads === 1 ? remote : after; },
      async applyOAuthCredentials(id) { writtenIds.push(id); },
    },
  });
  assert.deepEqual(writtenIds, [remote.id]);
  assert.equal(outcome.verification.accountId, remote.id);
  assert.equal(outcome.skipped, false);
});

test('durable write-time baseline rejects changed target metadata and still skips available accounts', async () => {
  const remote = account();
  let writes = 0;
  const options = {
    item: item(remote),
    remoteTargetRevision: createAccountTargetRevisionIssuer(Buffer.alloc(32, 3)).issue(remote),
    remoteTargetDigest: accountTestTargetDigest(remote),
    client: {
      async getAccount() { return account({ groupIds: [2] }); },
      async applyOAuthCredentials() { writes += 1; },
    },
  };
  await assert.rejects(executeImportPlanItem(options), expectedCode('REMOTE_IMPORT_TARGET_STALE'));
  options.client.getAccount = async () => account({ status: 'active', schedulable: true });
  assert.equal((await executeImportPlanItem(options)).skipped, true);
  assert.equal(writes, 0);
});

test('executeImport revalidates scoped source and plan before admitting a remote mutation', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-panel-scoped-import-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  fs.writeFileSync(path.join(root, 'tokens', 'scoped.json'), JSON.stringify({
    access_token: 'test-only-new-access',
    account_id: 'scoped-account', user_id: 'scoped-user',
    expires_at: '2099-01-01T00:00:00.000Z',
  }));
  const environment = {
    GPT_REGISTER_ROOT: root, PANEL_WRITE_ENABLED: '1',
    SUB2API_BASE_URL: BASE_URL, SUB2API_ADMIN_API_KEY: 'test-only-admin-key',
  };
  const previous = new Map(Object.keys(environment).map((key) => [key, process.env[key]]));
  Object.assign(process.env, environment);
  t.after(() => {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  const remote = account();
  let backups = 0;
  let writes = 0;
  const client = {
    baseUrl: BASE_URL,
    async listAccounts() { return [remote]; },
    async exportAccounts() { backups += 1; return { accounts: [] }; },
    async applyOAuthCredentials() { writes += 1; },
    async importCodexSession() { writes += 1; },
  };
  const snapshot = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
    client, rootDirectory: root, includeRaw: true, includeInternal: true, requireCompleteSources: true,
  });
  const candidates = buildImportPlan(snapshot._internal.sources, snapshot._internal.accounts);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].action, 'update');
  const selectedKeys = [candidates[0].key];
  const plan = buildImportPlan(snapshot._internal.sources, snapshot._internal.accounts, selectedKeys);
  const oldIssuer = createAccountTargetRevisionIssuer(Buffer.alloc(32, 4));
  const remoteTargets = [{ accountId: remote.id, targetRevision: oldIssuer.issue(remote) }];
  const remoteTargetBaselines = [baseline(remote, remoteTargets[0])];
  const remoteSourceHashes = [{ selectedKey: plan[0].key, contentHash: plan[0]._record.contentHash }];
  const intentArgs = [snapshot.version, selectedKeys, plan, null, resolveImportExecutionBinding(client, plan)];
  const options = {
    snapshotVersion: snapshot.version, selectedKeys, remoteTargets, remoteSourceHashes, remoteTargetBaselines,
    planIntentVersion: buildImportPlanIntentVersion(...intentArgs, remoteTargets),
    client, logger: checkpointLogger,
  };
  await assert.rejects(executeImport({
    ...options, remoteSourceHashes: [{ selectedKey: plan[0].key, contentHash: 'b'.repeat(64) }],
  }), expectedCode('REMOTE_IMPORT_SOURCE_CHANGED'));
  await assert.rejects(executeImport({
    ...options, remoteTargets: [target(account({ id: 72 }))],
    remoteTargetBaselines: [baseline(account({ id: 72 }))],
  }), expectedCode('REMOTE_IMPORT_TARGET_STALE'));
  await assert.rejects(executeImport({
    ...options, planIntentVersion: buildImportPlanIntentVersion(...intentArgs),
  }), expectedCode('IMPORT_PLAN_STALE'));
  let admitted = 0;
  await assert.rejects(executeImport({
    ...options, jobId: 'scoped-import-test',
    db: { async startMutationJob() { admitted += 1; throw Object.assign(new Error('test admission stop'), { code: 'TEST_ADMISSION_STOP' }); } },
  }), expectedCode('TEST_ADMISSION_STOP'));
  assert.equal(admitted, 1);
  assert.equal(backups, 0);
  assert.equal(writes, 0);
});
