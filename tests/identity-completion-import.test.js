'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
require('./test-isolation');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { normalizeTokenDocument } = require('../backend/lib/token');
const { accountTestTargetDigest, accountTestTargetRevision } = require('../backend/accountTargetRevision');
const {
  buildImportPlan, buildScopedImportPlan, assertRemoteImportPlan,
  assertBackupCoversUpdateTargets, executeImportPlanItem, buildImportPlanIntentVersion,
  resolveImportExecutionBinding,
} = require('../backend/sync');

function fixture() {
  const raw = { id: 160, name: 'free00047', platform: 'openai', type: 'oauth',
    status: 'error', schedulable: false, group_ids: [],
    credentials: { chatgpt_user_id: 'fixture-user', access_token: 'fixture-old-access',
      refresh_token: 'fixture-old-refresh' },
    credentials_status: { has_access_token: true, has_refresh_token: true, has_id_token: false } };
  const account = safeAccount(raw);
  const token = normalizeTokenDocument({ source: 'tokens', relativePath: 'tokens/completion.json',
    fileName: 'completion.json', contentHash: 'a'.repeat(64), mtimeMs: 1, includeRaw: true,
    data: { chatgpt_account_id: 'fixture-account', chatgpt_user_id: 'fixture-user',
      access_token: 'fixture-new-access', refresh_token: 'fixture-new-refresh',
      expires_at: '2099-01-01T00:00:00.000Z' } });
  const sources = { tokens: [token], usernames: [] };
  const key = 'token:tokens:tokens/completion.json';
  const binding = { accountId: account.id, selectedKey: key, contentHash: token.contentHash,
    identityKeys: ['user:fixture-user'], targetDigest: accountTestTargetDigest(account) };
  const targets = [{ accountId: account.id, targetRevision: accountTestTargetRevision(account) }];
  const baselines = [{ ...targets[0], targetDigest: binding.targetDigest }];
  return { raw, account, token, sources, key, binding, targets, baselines };
}

function plan(f = fixture(), accounts = [f.account]) {
  return buildScopedImportPlan(f.sources, accounts, [f.key], [f.binding]);
}

function clientFor(f, options = {}) {
  let remote = structuredClone(f.raw);
  let writes = 0;
  const client = {
    async listAccounts() {
      const current = safeAccount(remote);
      return options.collision && (options.collision !== 'post' || writes > 0)
        ? [current, { ...current, id: 161, name: 'free00048' }] : [current];
    },
    async getAccount(id) {
      assert.equal(id, 160);
      const current = safeAccount(remote);
      return writes === 0 && options.before ? options.before(current) : current;
    },
    async applyOAuthCredentials(id, payload) {
      assert.equal(id, 160);
      writes += 1;
      remote.credentials = { ...remote.credentials, ...payload.credentials };
      if (options.after) options.after(remote);
    },
  };
  return { client, writes: () => writes };
}

function execute(f, item, client, extra = {}) {
  return executeImportPlanItem({ item, client, remoteTargetDigest: f.binding.targetDigest,
    logger: { checkpoint() { return true; } }, ...extra });
}

test('only the scoped planner authorizes completion and keeps the original backup identity', () => {
  const f = fixture();
  assert.equal(buildImportPlan(f.sources, [f.account], [f.key])[0].action, 'conflict');
  const planned = plan(f);
  const item = planned[0];
  assert.equal(item.action, 'update');
  assert.equal(item.identityCompletion, 'account_id');
  assert.equal(item.accountId, 160);
  assert.equal(item._account, f.account);
  assert.equal(item._account.accountId, '');
  assert.doesNotThrow(() => assertRemoteImportPlan(planned, [f.account], f.targets, f.baselines));
  assert.equal(assertBackupCoversUpdateTargets({ accounts: [f.raw], proxies: [] }, planned).updateTargetCount, 1);
  const corrupted = structuredClone(f.raw);
  corrupted.credentials.access_token = 'fixture-replaced-old-access';
  assert.throws(() => assertBackupCoversUpdateTargets({ accounts: [corrupted], proxies: [] }, planned));
});

test('completion consent is part of the plan intent, not a silent update', () => {
  const f = fixture();
  const item = plan(f)[0];
  const execution = resolveImportExecutionBinding({ baseUrl: 'http://127.0.0.1:18080' }, [item]);
  const intent = (value) => buildImportPlanIntentVersion('b'.repeat(64), [f.key], [value], null, execution);
  assert.notEqual(intent(item), intent({ ...item, identityCompletion: undefined }));
});

test('scoped completion rejects missing mismatched repeated and stale source-to-ID bindings', () => {
  const f = fixture();
  for (const bindings of [[], [f.binding, f.binding], [{ ...f.binding, accountId: 161 }],
    [{ ...f.binding, selectedKey: 'token:tokens:tokens/other.json' }],
    [{ ...f.binding, contentHash: 'b'.repeat(64) }], [{ ...f.binding, targetDigest: 'b'.repeat(64) }],
    [{ ...f.binding, identityKeys: ['user:other'] }],
    [{ ...f.binding, identityKeys: ['user:fixture-user', 'user:fixture-user'] }],
    [{ ...f.binding, extra: true }]]) {
    assert.throws(() => buildScopedImportPlan(f.sources, [f.account], [f.key], bindings));
  }
});

test('an existing differing account ID and account-only records are not completion candidates', () => {
  for (const credentials of [
    { chatgpt_user_id: 'fixture-user', chatgpt_account_id: 'another-account' },
    { chatgpt_account_id: 'fixture-account' },
    { chatgpt_user_id: 'another-user' },
  ]) {
    const f = fixture();
    const remote = safeAccount({ ...f.raw, credentials: { ...credentials, access_token: 'fixture-old-access',
      refresh_token: 'fixture-old-refresh' } });
    f.binding.identityKeys = remote.identityKeys;
    f.binding.targetDigest = accountTestTargetDigest(remote);
    assert.throws(() => plan(f, [remote]));
  }
});

test('completion never guesses among other rows sharing the output account or user', () => {
  const f = fixture();
  for (const identityKeys of [['user:fixture-user'], ['account:fixture-account']]) {
    assert.throws(() => plan(f, [f.account, { ...f.account, id: 161, identityKeys,
      accountId: '', userId: '' }]));
  }
});

test('completion writes once to the original ID and verifies the full new identity', async () => {
  const f = fixture();
  const c = clientFor(f);
  const result = await execute(f, plan(f)[0], c.client);
  assert.equal(result.skipped, false);
  assert.equal(result.verification.accountId, 160);
  assert.equal(c.writes(), 1);
});

test('public completion flags and copied plan items cannot bypass strict ordinary preflight', async () => {
  const f = fixture();
  for (const item of [{ ...plan(f)[0] }, { ...buildImportPlan(f.sources, [f.account], [f.key])[0],
    action: 'update', accountId: 160, _account: f.account, identityCompletion: 'account_id' }]) {
    const c = clientFor(f);
    await assert.rejects(execute(f, item, c.client));
    assert.equal(c.writes(), 0);
  }
});

test('completion preflight rejects changed proof baseline source and remote credentials before writes', async () => {
  for (const kind of ['baseline', 'source', 'credentials', 'identity', 'collision']) {
    const f = fixture();
    const item = plan(f)[0];
    if (kind === 'source') item._record.contentHash = 'b'.repeat(64);
    const c = clientFor(f, { collision: kind === 'collision' ? 'pre' : undefined,
      before: kind === 'credentials' ? (value) => ({ ...value, tokenFingerprints: { access: 'c'.repeat(16) } })
        : kind === 'identity' ? (value) => ({ ...value, userId: 'other', identityKeys: ['user:other'] }) : undefined });
    await assert.rejects(execute(f, item, c.client,
      kind === 'baseline' ? { remoteTargetDigest: 'b'.repeat(64) } : {}));
    assert.equal(c.writes(), 0);
  }
});

test('an account becoming available is still skipped without completing identity or writing tokens', async () => {
  const f = fixture();
  const c = clientFor(f, { before: (value) => ({ ...value, status: 'active', schedulable: true }) });
  const result = await execute(f, plan(f)[0], c.client);
  assert.equal(result.skipped, true);
  assert.equal(c.writes(), 0);
});

test('post-write missing or changed identity and duplicate rows retain reconciliation protection', async () => {
  for (const kind of ['missing', 'account', 'user', 'collision']) {
    const f = fixture();
    const c = clientFor(f, { collision: kind === 'collision' ? 'post' : undefined,
      after: (remote) => {
        if (kind === 'missing') delete remote.credentials.chatgpt_account_id;
        if (kind === 'account') remote.credentials.chatgpt_account_id = 'other';
        if (kind === 'user') remote.credentials.chatgpt_user_id = 'other';
      } });
    await assert.rejects(execute(f, plan(f)[0], c.client), (error) => error.requiresReconciliation === true);
    assert.equal(c.writes(), 1);
  }
});
