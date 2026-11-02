'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
require('./test-isolation');
const { createServer, shutdownServer } = require('../backend/server');
const { PanelDb } = require('../backend/db');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { managementEndpointKey } = require('../backend/accountLifecycle');
const { withControlPlaneLock } = require('../backend/taskCoordinator');

async function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'console-api-'));
  for (const directory of ['tokens', 'use_token', 'backups', 'logs']) fs.mkdirSync(path.join(root, directory), { mode: 0o700 });
  fs.writeFileSync(path.join(root, 'username.json'), '[]', { mode: 0o600 });
  const admin = crypto.randomBytes(24).toString('hex');
  const secrets = [admin];
  const secret = () => { const value = crypto.randomBytes(24).toString('hex'); secrets.push(value); return value; };
  const remote = []; const writes = []; const tested = [];
  const client = {
    baseUrl: 'http://127.0.0.1:9',
    listAccounts: async () => remote.map(safeAccount),
    getAccount: async id => {
      const raw = remote.find(a => a.id === id);
      if (!raw) throw Object.assign(new Error('not found'), { code: 'SUB2API_REQUEST_REJECTED', upstreamStatus: 404 });
      return safeAccount(raw);
    },
    getBatchTableUsageStats: async () => ({ stats: {}, errors: {} }),
    listGroups: async () => [{ id: 1, name: 'share', status: 'active', platform: 'openai', subscription_type: 'standard' }],
    exportAccounts: async ids => ({ accounts: structuredClone(ids.length ? remote.filter(a => ids.includes(a.id)) : remote), proxies: [] }),
    applyOAuthCredentials: async (id, payload) => {
      writes.push({ action: 'update', id });
      const account = remote.find(a => a.id === id);
      account.credentials = { ...payload.credentials };
      account.status = 'active'; account.error_message = ''; account.updated_at = new Date().toISOString();
    },
  };
  const saved = new Map();
  const variables = { GPT_REGISTER_ROOT: root, GPT_REGISTER_NODE_PATH: process.execPath,
    PANEL_DB_PATH: path.join(root, 'panel.sqlite3'), PANEL_BACKUP_DIR: path.join(root, 'backups'),
    PANEL_LOG_PATH: path.join(root, 'panel.log'), PANEL_CONTROL_LOCK_PATH: path.join(root, 'control.lock'),
    PANEL_REQUIRE_AUTH: '1', PANEL_ADMIN_TOKEN: admin, PANEL_WRITE_ENABLED: '1', PANEL_PHASE3_ENABLED: '1',
    PANEL_ALLOW_INSECURE_WRITE: '0', PANEL_ALLOW_UNBACKED_WRITES: '0', SUB2API_BASE_URL: client.baseUrl,
    SUB2API_ADMIN_API_KEY: secret(), SUB2API_GROUP_NAME: 'share' };
  for (const [key, value] of Object.entries(variables)) { saved.set(key, process.env[key]); process.env[key] = value; }
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  function token(id, changes = {}) {
    const data = { email: 'account-' + id + '@example.test', chatgpt_account_id: 'account-' + id,
      chatgpt_user_id: 'user-' + id, plan_type: 'free', access_token: secret(), refresh_token: secret(),
      expires_at: '2099-01-01T00:00:00.000Z', ...changes };
    const relativePath = 'tokens/account-' + id + '.json';
    const bytes = JSON.stringify(data);
    fs.writeFileSync(path.join(root, relativePath), bytes, { mode: 0o600 });
    return { data, relativePath, selectedKey: 'token:tokens:' + relativePath,
      contentHash: crypto.createHash('sha256').update(bytes).digest('hex') };
  }
  function account(id, changes = {}) {
    const item = { id, name: 'free' + String(id).padStart(5, '0'), platform: 'openai', type: 'oauth',
      status: 'active', schedulable: true, group_ids: [1], credentials: { email: 'account-' + id + '@example.test',
        chatgpt_account_id: 'account-' + id, chatgpt_user_id: 'user-' + id, plan_type: 'free',
        access_token: secret(), refresh_token: secret(), expires_at: '2099-01-01T00:00:00.000Z' }, ...changes };
    remote.push(item); return item;
  }
  const logger = { info() {}, warn() {}, error() {}, probe() { return true; }, checkpoint() { return true; } };
  const calls = { registration: 0, import: 0, phase3: 0, preflight: 0 };
  const consoleOptions = {
    preflight: async () => { calls.preflight += 1; return { ok: true, checkedAt: new Date().toISOString(),
      channels: ['sms', 'mail', 'oauth'].map(id => ({ id, ok: true, code: 'OK' })) }; },
    registrar: async ({ options: intent }) => {
      calls.registration += 1;
      const output = token(1);
      return { requestedCount: intent.count, completedCount: 1, selectedKeys: [output.selectedKey],
        artifacts: [{ selectedKey: output.selectedKey, contentHash: output.contentHash, identityKeys: ['account:account-1', 'user:user-1'] }] };
    },
    importer: async ({ selectedKeys, beforeCreate, db, jobId, persistResult }) => {
      calls.import += 1;
      assert.equal(selectedKeys.length > 0, true);
      await beforeCreate({ sourceIdentityKeys: ['account:account-1', 'user:user-1'] });
      const output = JSON.parse(fs.readFileSync(path.join(root, 'tokens/account-1.json'), 'utf8'));
      account(1, { credentials: output });
      await db.saveLink({ endpointKey: managementEndpointKey(client.baseUrl), identityKey: 'account:account-1',
        identityKeys: ['account:account-1', 'user:user-1'], sub2apiId: 1, accountName: 'free00001', tokenPath: 'tokens/account-1.json' });
      // Injected importer deliberately stops before remote HTTP. The real
      // importer/backup/CAS is exercised by the identity-completion API suite.
      const result = { succeeded: 1, failed: 0, imported: [{ verification: { accountId: 1 } }] };
      await persistResult(result); return result;
    },
    tester: async ({ accountIds, db, jobId, persistResult }) => withControlPlaneLock(async () => {
      await db.startMutationJob(jobId); tested.push(...accountIds);
      const result = { requested: accountIds.length, succeeded: accountIds.length, failed: 0, results: accountIds.map(accountId => ({ accountId, status: 'succeeded' })) };
      await persistResult(result); return result;
    }),
    ...options,
  };
  const server = createServer({ db, logger, syncClientFactory: () => client, consoleOptions });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await shutdownServer(server);
    for (const [key, value] of saved) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    fs.rmSync(root, { recursive: true, force: true });
  });
  async function request(route, body, key = crypto.randomUUID()) {
    const response = await fetch('http://127.0.0.1:' + server.address().port + route, {
      ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
      // Fixture jobs are polled directly through SQLite and may leave HTTP
      // idle beyond Node 18's 5s keep-alive timeout. Do not reuse an undici
      // socket whose server-side FIN is still queued under full-suite load.
      // Each request still occurs exactly once: no retry masks mutations.
      headers: { 'x-panel-token': admin, 'content-type': 'application/json', 'idempotency-key': key, connection: 'close' },
      signal: AbortSignal.timeout(15000),
    });
    const value = await response.json();
    for (const item of secrets) assert.equal(JSON.stringify(value).includes(item), false, 'API response must not contain credentials');
    return { status: response.status, body: value, headers: response.headers };
  }
  async function waitJob(id) {
    for (let i = 0; i < 500; i++) {
      const job = await db.getJob(id);
      if (['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)) return job;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error('task did not finish');
  }
  return { db, root, client, remote, writes, tested, calls, token, account, request, waitJob, server };
}

test('console API fixture uses one fresh connection per request without idle-socket retries', async t => {
  const f = await fixture(t);
  const sockets = new Set(); const connections = [];
  f.server.on('request', request => { sockets.add(request.socket); connections.push(request.headers.connection); });
  for (let i = 0; i < 3; i += 1) {
    f.server.closeIdleConnections();
    assert.equal((await f.request('/api/health')).status, 200);
  }
  assert.deepEqual(connections, ['close', 'close', 'close']);
  assert.equal(sockets.size, 3, 'fixture must not share an idle socket across business steps');
});

function proxyFixture(f) {
  const node = { id: 2, name: 'fixture route', protocol: 'http', status: 'active', expiresAt: null,
    fallbackMode: 'none', backupProxyId: null, revision: 'proxy-v1.' + 'a'.repeat(43) };
  f.client.listProxies = async () => [{ ...node, host: 'fixture-private-host', password: 'fixture-private-password' }];
  f.client.getProxy = async id => { assert.equal(id, 2); return { ...node }; };
  async function save(overrides = {}) {
    const settings = (await f.request('/api/console/settings')).body.importProxy;
    return f.request('/api/console/settings', { confirm: true, importProxy: { revision: settings.revision,
      proxyId: 2, proxyRevision: node.revision, requestId: crypto.randomUUID(), ...overrides } });
  }
  return { node, save };
}

test('console default proxy API projects safe metadata and saves independent CAS receipt', async t => {
  const f = await fixture(t); const p = proxyFixture(f);
  const list = await f.request('/api/console/proxies');
  assert.equal(list.status, 200); assert.equal(list.body.items[0].eligible, true);
  assert.deepEqual(Object.keys(list.body.items[0]).sort(), ['eligible', 'id', 'name', 'protocol', 'reason', 'revision', 'status']);
  assert.equal(JSON.stringify(list.body).includes('fixture-private'), false);
  const requestId = crypto.randomUUID(); const saved = await p.save({ requestId });
  assert.equal(saved.status, 200);
  assert.deepEqual(saved.body.importProxy, { revision: 1, proxyId: 2, configured: true, endpointMatches: true, lastRequestId: requestId });
  assert.equal((await f.request('/api/console/settings')).body.importProxy.lastRequestId, requestId);
  const replay = await p.save({ requestId });
  assert.equal(replay.status, 409); assert.equal(replay.body.error, 'CONSOLE_IMPORT_PROXY_SETTINGS_STALE');
  const policy = saved.body.policy;
  assert.equal((await f.request('/api/console/settings', { revision: saved.body.revision, policy })).status, 200);
  assert.deepEqual((await f.request('/api/console/settings')).body.importProxy, saved.body.importProxy);
  const otherDb = new PanelDb(path.join(f.root, 'panel.sqlite3'));
  assert.equal((await otherDb.getImportProxySettings()).settings.proxyId, 2);
});

test('console default proxy rejects stale, expired, unconfirmed or malformed selections without settings writes', async t => {
  const f = await fixture(t); const p = proxyFixture(f);
  assert.equal((await p.save({ proxyRevision: 'proxy-v1.' + 'b'.repeat(43) })).status, 409);
  p.node.expiresAt = '2000-01-01T00:00:00Z'; p.node.fallbackMode = 'direct';
  assert.equal((await f.request('/api/console/proxies')).body.items[0].eligible, false);
  assert.equal((await p.save()).status, 409);
  p.node.expiresAt = null;
  assert.equal((await p.save({ proxyId: '2' })).status, 400);
  assert.equal((await p.save({ requestId: 'bad' })).status, 400);
  assert.equal((await p.save({ requestId: [crypto.randomUUID()] })).status, 400);
  assert.equal((await f.request('/api/console/settings', { importProxy: { revision: 0, proxyId: null, requestId: crypto.randomUUID() } })).status, 400);
  assert.equal((await f.db.getImportProxySettings()).revision, 0);
});

test('console stale instance never becomes implicit direct and explicit clear needs no node read', async t => {
  const f = await fixture(t); const p = proxyFixture(f); await p.save();
  f.client.baseUrl = 'http://127.0.0.1:10';
  assert.equal((await f.request('/api/console/settings')).body.importProxy.endpointMatches, false);
  f.client.getProxy = async () => { throw new Error('must not query node when clearing'); };
  const saved = await p.save({ proxyId: null, proxyRevision: undefined });
  assert.equal(saved.status, 200); assert.equal(saved.body.importProxy.configured, false);
  assert.equal(saved.body.importProxy.endpointMatches, true);
});

test('default proxy read failure before save is definitive while post-write response failure retains a receipt', async t => {
  const f = await fixture(t); const p = proxyFixture(f);
  f.client.getProxy = async () => { throw Object.assign(new Error('fixture-private-upstream-body'), { upstreamStatus: 404 }); };
  const failed = await p.save();
  assert.equal(failed.status, 409);
  assert.equal(failed.body.error, 'CONSOLE_IMPORT_PROXY_CHECK_FAILED');
  assert.match(failed.body.message, /未写入/); assert.equal(failed.body.message.includes('fixture-private'), false);
  assert.equal((await f.db.getImportProxySettings()).revision, 0);
  f.client.getProxy = async () => ({ ...p.node });
  const requestId = crypto.randomUUID(); const persist = f.db.saveImportProxySettings.bind(f.db);
  f.db.saveImportProxySettings = async (...args) => { await persist(...args); throw new Error('fixture-response-unavailable-after-persist'); };
  const uncertain = await p.save({ requestId });
  assert.notEqual(uncertain.body.error, 'CONSOLE_IMPORT_PROXY_CHECK_FAILED');
  assert.equal((await f.request('/api/console/settings')).body.importProxy.lastRequestId, requestId);
});

test('invalid default stops registration before engine and paid actions', async t => {
  const f = await fixture(t); const p = proxyFixture(f); await p.save(); p.node.status = 'disabled';
  const admitted = await f.request('/api/console/register', { count: 1, country: 'US', operator: '', autoImport: true });
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'failed'); assert.equal(job.result.code, 'CONSOLE_IMPORT_PROXY_UNAVAILABLE');
  assert.equal(f.calls.registration, 0); assert.equal(f.calls.preflight, 0); assert.equal(f.calls.import, 0);
});

test('default proxy feature does not broaden the auto-import-only registration API contract', async t => {
  const f = await fixture(t); const p = proxyFixture(f); await p.save(); p.node.status = 'disabled';
  f.client.getProxy = async () => { throw new Error('must not inspect a destination unused by token-only generation'); };
  const admitted = await f.request('/api/console/register', { count: 1, country: 'US', operator: '', autoImport: false });
  assert.equal(admitted.status, 400); assert.equal(admitted.body.error, 'CONSOLE_REQUEST_INVALID');
  assert.equal(f.calls.registration, 0); assert.equal(f.calls.import, 0);
  assert.equal(f.remote.length, 0); assert.equal(f.tested.length, 0);
});

test('registration freezes an unconfigured default across generation and never adopts a later proxy', async t => {
  let f;
  f = await fixture(t, { registrar: async ({ beforeExecute }) => {
    await beforeExecute();
    const output = f.token(1);
    await f.db.saveImportProxySettings({ proxyId: 2, endpointDigest: require('../backend/importProxy').endpointDigest(f.client),
      lastRequestId: crypto.randomUUID() }, { expectedRevision: 0 });
    return { requestedCount: 1, completedCount: 1, selectedKeys: [output.selectedKey],
      artifacts: [{ selectedKey: output.selectedKey, contentHash: output.contentHash, identityKeys: ['account:account-1', 'user:user-1'] }] };
  } });
  proxyFixture(f);
  const admitted = await f.request('/api/console/register', { count: 1, country: 'US', operator: '', autoImport: true });
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'partial'); assert.equal(job.result.code, 'CONSOLE_IMPORT_PROXY_CHANGED');
  assert.equal(f.calls.import, 0); assert.equal(f.remote.length, 0);
  assert.equal(fs.existsSync(path.join(f.root, 'tokens/account-1.json')), true);
});

test('advanced preview and main-console import share the saved create-only default proxy', async t => {
  const f = await fixture(t, { importer: require('../backend/sync').executeImport }); const p = proxyFixture(f); await p.save();
  const source = f.token(1); let payload;
  f.client.importCodexSession = async body => {
    payload = body; f.account(1, { credentials: JSON.parse(body.content), proxy_id: body.proxy_id, name: body.name, group_ids: body.group_ids });
    return { total: 1, created: 1, updated: 0, skipped: 0, failed: 0, items: [{ index: 1, account_id: 1, action: 'created' }] };
  };
  const preview = await f.request('/api/sync/preview', { selectedKeys: [source.selectedKey] });
  assert.equal(preview.status, 200); assert.deepEqual(preview.body.importProxy, { proxyId: 2, appliesTo: 'create' });
  const firstVersion = preview.body.planIntentVersion;
  p.node.revision = 'proxy-v1.' + 'b'.repeat(43);
  const changed = await f.request('/api/sync/preview', { selectedKeys: [source.selectedKey] });
  assert.notEqual(changed.body.planIntentVersion, firstVersion);
  p.node.status = 'expired';
  const expired = await f.request('/api/sync/preview', { selectedKeys: [source.selectedKey] });
  assert.equal(expired.status, 409); assert.equal(expired.body.error, 'CONSOLE_IMPORT_PROXY_UNAVAILABLE');
  p.node.status = 'active';
  const admitted = await f.request('/api/console/maintain', { importNew: true, refreshInvalid: false, deleteBanned: false });
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'succeeded', job.error || JSON.stringify(job.result));
  assert.equal(payload.proxy_id, 2); assert.equal(f.remote[0].proxy_id, 2); assert.equal(job.result.summary.imported, 1);
});

test('console registration completes server-side register import verify and durable replay without browser continuation', async t => {
  const f = await fixture(t);
  const body = { count: 1, country: 'US', operator: '', autoImport: true };
  const key = crypto.randomUUID();
  const admission = await f.request('/api/console/register', body, key);
  assert.equal(admission.status, 202);
  const job = await f.waitJob(admission.body.jobId);
  assert.equal(job.status, 'succeeded', job.error || job.result?.code);
  assert.deepEqual(f.tested, [1]);
  assert.equal(job.result.childJobIds.length, 3);
  assert.equal(job.result.summary.imported, 1);
  assert.equal(job.result.summary.tokensGenerated, 1); assert.equal(job.result.summary.verified, 1);
  const replay = await f.request('/api/console/register', body, key);
  assert.equal(replay.body.jobId, admission.body.jobId);
  assert.equal(replay.headers.get('idempotency-replayed'), 'true');
  assert.equal(f.calls.registration, 1);
  assert.equal((await f.request('/api/console/register', { ...body, count: 2 }, key)).status, 409);
});

function existingTokenBody(rows) {
  return { accountIds: rows.map(row => row.accountId), importNew: false, refreshInvalid: false, deleteBanned: false,
    localTokenTargets: rows.map(({ selectedKey, accountId, targetRevision, sourceContentHash, executionRevision }) => (
      { selectedKey, accountId, targetRevision, sourceContentHash, executionRevision }
    )) };
}
function testOnlyBody(rows, modelId) {
  return { accountIds: rows.map(row => row.id), importNew: false, refreshInvalid: false, deleteBanned: false,
    testOnly: true, accountTargets: rows.map(({ id, targetRevision, executionRevision }) => (
      { accountId: id, targetRevision, executionRevision }
    )), ...(modelId ? { modelId } : {}) };
}
function invalidRemote(f, id, { missingAccount = false, ...changes } = {}) {
  const account = f.account(id, { status: 'error', schedulable: false,
    error_message: JSON.stringify({ error: { code: 'invalid_grant' } }), ...changes });
  if (missingAccount) delete account.credentials.chatgpt_account_id;
  return account;
}

test('main console explicitly completes three user-only identities and updates original IDs without Phase3 or creation', async t => {
  const f = await fixture(t, { importer: require('../backend/sync').executeImport });
  for (const id of [160, 174, 187]) { f.token(id); invalidRemote(f, id, { missingAccount: true }); }
  const preview = await f.request('/api/console/local-tokens');
  assert.equal(preview.status, 200);
  const rows = preview.body.items;
  assert.equal(rows.length, 3);
  assert.equal(rows.every(row => row.eligible && row.identityCompletion === 'account_id' && row.matchedBy === 'user_id'), true);
  assert.equal(rows.every(row => row.identitySummary.targetAccountId === null && row.executionRevision), true);
  const body = existingTokenBody(rows); const key = crypto.randomUUID();
  const admitted = await f.request('/api/console/maintain', body, key);
  assert.equal(admitted.status, 202);
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'succeeded', job.error || JSON.stringify(job.result.items));
  assert.deepEqual(f.writes, [160, 174, 187].map(id => ({ action: 'update', id })));
  assert.deepEqual(f.tested, [160, 174, 187]);
  assert.equal(job.result.summary.tokensUpdated, 3); assert.equal(job.result.summary.verified, 3);
  assert.equal(job.result.summary.tokensGenerated, 0); assert.equal(f.calls.registration, 0); assert.equal(f.calls.preflight, 0);
  assert.equal(f.remote.every(account => account.credentials.chatgpt_account_id === 'account-' + account.id), true);
  assert.equal(fs.readdirSync(path.join(f.root, 'backups')).length >= 3, true);
  const children = await Promise.all(job.result.childJobIds.map(id => f.db.getJob(id)));
  assert.deepEqual(children.map(child => child.type), ['token_import', 'account_test', 'token_import', 'account_test', 'token_import', 'account_test']);
  const replay = await f.request('/api/console/maintain', body, key);
  assert.equal(replay.body.jobId, job.id); assert.equal(f.writes.length, 3);
});

test('main console updates fully matched existing token and keeps written outcome when model testing fails', async t => {
  const f = await fixture(t, { importer: require('../backend/sync').executeImport,
    tester: async ({ accountIds, db, jobId, persistResult, client }) => withControlPlaneLock(async () => {
      await db.startMutationJob(jobId);
      assert.equal(client.logContext.jobId, jobId);
      assert.match(client.logContext.parentJobId, /^job_[a-f0-9]{24}$/);
      const result = { requested: 1, succeeded: 0, failed: 1,
        results: [{ accountId: accountIds[0], status: 'failed', failureCategory: 'model_unavailable', upstreamStatus: 404 }] };
      await persistResult(result); return result;
    }) });
  f.token(47); invalidRemote(f, 47);
  const rows = (await f.request('/api/console/local-tokens')).body.items;
  assert.equal(rows[0].eligible, true); assert.equal(rows[0].identityCompletion, null);
  const accepted = await f.request('/api/console/maintain', existingTokenBody(rows));
  const job = await f.waitJob(accepted.body.jobId);
  assert.equal(job.status, 'partial'); assert.equal(job.result.summary.tokensUpdated, 1);
  assert.equal(job.result.summary.tested, 1); assert.equal(job.result.summary.verified, 0); assert.equal(job.result.summary.testFailed, 1);
  assert.deepEqual(job.result.items[0].phases, { tokenGenerated: false, tokenUpdated: true, tested: true, verified: false });
  assert.equal(job.result.items[0].failureCategory, 'model_unavailable'); assert.equal(job.result.items[0].upstreamStatus, 404);
  assert.match(job.result.items[0].message, /已回写原账号/); assert.match(job.result.items[0].message, /模型/);
  assert.deepEqual(f.writes, [{ action: 'update', id: 47 }]);
});

for (const kind of ['source', 'remote', 'endpoint', 'signature', 'duplicate_identity']) {
  test('frozen main-console token review rejects ' + kind + ' changes before any write', async t => {
    const f = await fixture(t, { importer: require('../backend/sync').executeImport });
    f.token(47); const raw = invalidRemote(f, 47, { missingAccount: true });
    const body = existingTokenBody((await f.request('/api/console/local-tokens')).body.items);
    if (kind === 'source') f.token(47);
    if (kind === 'remote') raw.credentials.refresh_token = crypto.randomBytes(24).toString('hex');
    if (kind === 'endpoint') f.client.baseUrl = 'http://127.0.0.1:10';
    if (kind === 'signature') body.localTokenTargets[0].executionRevision = 'console-execution-v1.' + 'a'.repeat(43);
    if (kind === 'duplicate_identity') f.account(48, { credentials: { ...raw.credentials } });
    const response = await f.request('/api/console/maintain', body);
    assert.equal(response.status, 202);
    const job = await f.waitJob(response.body.jobId);
    assert.equal(job.status, 'failed'); assert.equal(job.result.code, 'CONSOLE_LOCAL_REVIEW_CHANGED');
    assert.deepEqual(f.writes, []); assert.deepEqual(f.tested, []); assert.equal(f.calls.preflight, 0);
  });
}

test('main-console token review explains healthy quota and manually disabled skips without enabling writes', async t => {
  const f = await fixture(t);
  f.token(1); f.account(1);
  f.token(2); invalidRemote(f, 2, { error_message: JSON.stringify({ error: { code: 'insufficient_quota' } }) });
  f.token(3); invalidRemote(f, 3, { status: 'disabled' });
  f.token(4); // New-account import stays a separate explicit action.
  const rows = (await f.request('/api/console/local-tokens')).body.items;
  assert.equal(rows.every(row => !row.eligible && !row.executionRevision), true);
  for (const id of [1, 2, 3]) assert.equal(rows.find(row => row.accountId === id).action, 'skip');
  assert.match(rows.find(row => row.accountId === 1).reason, /当前可用/);
  assert.match(rows.find(row => row.accountId === 2).reason, /额度/);
  assert.match(rows.find(row => row.accountId === 3).reason, /手动停用/);
  assert.equal(rows.find(row => row.accountId === null).action, 'create');
});

test('test-only is version-bound, model-selectable and never imports logs in or touches unselected accounts', async t => {
  let receivedModel;
  const f = await fixture(t, { tester: async ({ accountIds, modelId, db, jobId, persistResult }) => withControlPlaneLock(async () => {
    await db.startMutationJob(jobId); receivedModel = modelId;
    const result = { requested: 1, succeeded: 1, failed: 0, results: [{ accountId: accountIds[0], status: 'succeeded' }] };
    await persistResult(result); return result;
  }) });
  f.account(1); f.account(2);
  const rows = (await f.request('/api/console/overview')).body.accounts.filter(row => row.id === 1);
  const accepted = await f.request('/api/console/maintain', testOnlyBody(rows, '5.6-luna'));
  assert.equal(accepted.status, 202);
  const job = await f.waitJob(accepted.body.jobId);
  assert.equal(job.status, 'succeeded'); assert.equal(receivedModel, 'gpt-5.6-luna');
  assert.equal(job.result.summary.verified, 1); assert.equal(job.result.summary.tokensUpdated, 0);
  assert.deepEqual(f.writes, []); assert.equal(f.calls.registration, 0); assert.equal(f.calls.import, 0); assert.equal(f.calls.preflight, 0);
  const children = await Promise.all(job.result.childJobIds.map(id => f.db.getJob(id)));
  assert.deepEqual(children.map(child => child.type), ['account_test']); assert.deepEqual(children[0].payload.accountIds, [1]);
});

test('a recovery refusal before dispatch is not counted as a failed upstream test', async t => {
  const f = await fixture(t, { tester: async ({ accountIds, db, jobId, persistResult }) => withControlPlaneLock(async () => {
    await db.startMutationJob(jobId);
    const result = { requested: 1, succeeded: 0, failed: 1, results: [{ accountId: accountIds[0], status: 'failed',
      attempted: false, code: 'ACCOUNT_TEST_RECOVERY_NOT_AUTHORIZED', message: 'synthetic-do-not-forward' }] };
    await persistResult(result); return result;
  }) });
  f.account(1);
  const rows = (await f.request('/api/console/overview')).body.accounts;
  const accepted = await f.request('/api/console/maintain', testOnlyBody(rows));
  const job = await f.waitJob(accepted.body.jobId);
  assert.equal(job.status, 'failed'); assert.equal(job.result.summary.tested, 0);
  assert.equal(job.result.summary.testFailed, 0); assert.equal(job.result.summary.failed, 1);
  assert.equal(job.result.items[0].code, 'ACCOUNT_TEST_RECOVERY_NOT_AUTHORIZED');
  assert.match(job.result.items[0].message, /未发送测试/);
  assert.equal(JSON.stringify(job.result.items).includes('synthetic-do-not-forward'), false);
  assert.deepEqual(f.writes, []); assert.deepEqual(f.tested, []);
});

for (const kind of ['remote', 'endpoint', 'evidence', 'plan']) {
  test('test-only rejects changed ' + kind + ' and cannot restore scheduling on a different target', async t => {
    const f = await fixture(t); const raw = f.account(1);
    const rows = (await f.request('/api/console/overview')).body.accounts.filter(row => row.id === 1);
    if (kind === 'remote') raw.schedulable = false;
    if (kind === 'endpoint') f.client.baseUrl = 'http://127.0.0.1:10';
    if (kind === 'evidence') raw.error_message = JSON.stringify({ error: { code: 'insufficient_quota' } });
    if (kind === 'plan') raw.credentials.plan_type = 'plus';
    const accepted = await f.request('/api/console/maintain', testOnlyBody(rows));
    const job = await f.waitJob(accepted.body.jobId);
    assert.equal(job.status, 'failed'); assert.equal(job.result.code, 'CONSOLE_TEST_TARGET_CHANGED');
    assert.deepEqual(f.tested, []); assert.deepEqual(f.writes, []);
  });
}

test('main console rejects mixed workflows duplicate targets and unreviewed test requests', async t => {
  const f = await fixture(t); f.token(47); invalidRemote(f, 47);
  const body = existingTokenBody((await f.request('/api/console/local-tokens')).body.items);
  for (const invalid of [{ ...body, refreshInvalid: true }, { ...body, importNew: true },
    { ...body, testOnly: true }, { ...body, accountIds: [47, 48] },
    { ...body, localTokenTargets: [...body.localTokenTargets, ...body.localTokenTargets] },
    { accountIds: [47], importNew: false, refreshInvalid: false, deleteBanned: false, testOnly: true },
    { ...body, localTokenTargets: body.localTokenTargets.map(({ executionRevision, ...target }) => target) }]) {
    assert.equal((await f.request('/api/console/maintain', invalid)).status, 400);
  }
  assert.deepEqual(await f.db.listJobs(), []); assert.deepEqual(f.writes, []);
});

for (const point of ['verification_read', 'worker_dispatch']) {
  test('test-only refuses evidence-only quota change at ' + point, async t => {
    const f = await fixture(t, { tester: require('../backend/accountTestWorker').runAccountTestJob });
    const raw = invalidRemote(f, 1);
    const rows = (await f.request('/api/console/overview')).body.accounts;
    const originalRead = f.client.getAccount;
    let reads = 0; let calls = 0;
    f.client.getAccount = async id => {
      reads += 1;
      if (reads === (point === 'verification_read' ? 1 : 2)) raw.error_message = JSON.stringify({ error: { code: 'insufficient_quota' } });
      return originalRead(id);
    };
    f.client.testAccount = async () => { calls += 1; throw new Error('must not call upstream'); };
    const accepted = await f.request('/api/console/maintain', testOnlyBody(rows));
    const job = await f.waitJob(accepted.body.jobId);
    assert.equal(job.status, 'failed'); assert.equal(calls, 0); assert.deepEqual(f.writes, []);
    if (point === 'verification_read') assert.equal(job.result.items[0].code, 'CONSOLE_TEST_TARGET_CHANGED');
    else {
      const child = await f.db.getJob(job.result.childJobIds[0]);
      assert.equal(child.result.results[0].code, 'CONSOLE_TEST_TARGET_CHANGED');
      assert.equal(child.result.results[0].attempted, false);
      assert.equal(job.result.items[0].code, 'CONSOLE_TEST_TARGET_CHANGED');
      assert.equal(job.result.items[0].phases.tested, false);
      assert.equal(job.result.summary.tested, 0); assert.equal(job.result.summary.testFailed, 0);
    }
  });
}

test('test-only preserves manually disabled quota-wait and confirmed-ban accounts without calls', async t => {
  const f = await fixture(t);
  invalidRemote(f, 1, { status: 'disabled' });
  invalidRemote(f, 2, { error_message: JSON.stringify({ error: { code: 'insufficient_quota' } }) });
  invalidRemote(f, 3, { error_message: JSON.stringify({ error: { code: 'account_deactivated' } }) });
  const rows = (await f.request('/api/console/overview')).body.accounts;
  const accepted = await f.request('/api/console/maintain', testOnlyBody(rows));
  const job = await f.waitJob(accepted.body.jobId);
  assert.equal(job.status, 'succeeded'); assert.equal(job.result.summary.skipped, 3);
  assert.equal(job.result.stage, 'no_changes'); assert.equal(job.result.outcome, 'no_changes');
  assert.equal(new Set(job.result.items.map(item => item.message)).size, 3);
  assert.equal(job.result.summary.tested, 0); assert.deepEqual(f.tested, []); assert.deepEqual(f.writes, []);
  assert.deepEqual(job.result.childJobIds, []);
});

test('test-only projects only safe diagnostic categories and status values', async t => {
  const f = await fixture(t, { tester: async ({ accountIds, db, jobId, persistResult }) => withControlPlaneLock(async () => {
    await db.startMutationJob(jobId);
    const result = { requested: 1, succeeded: 0, failed: 1,
      results: [{ accountId: accountIds[0], status: 'failed', failureCategory: 'untrusted-upstream-text', upstreamStatus: '403' }] };
    await persistResult(result); return result;
  }) });
  f.account(1);
  const rows = (await f.request('/api/console/overview')).body.accounts;
  const accepted = await f.request('/api/console/maintain', testOnlyBody(rows));
  const job = await f.waitJob(accepted.body.jobId);
  assert.equal(job.status, 'failed'); assert.equal(job.result.items[0].failureCategory, 'unknown');
  assert.equal(job.result.items[0].upstreamStatus, null);
  assert.equal(JSON.stringify(job.result.items).includes('untrusted-upstream-text'), false);
  assert.doesNotMatch(job.result.items[0].message, /已回写/);
});

test('test-only continues ordinary account failures and reports partial only after a verified success', async t => {
  const tested = [];
  const f = await fixture(t, { tester: async ({ accountIds, db, jobId, persistResult }) => withControlPlaneLock(async () => {
    await db.startMutationJob(jobId); tested.push(...accountIds);
    const success = accountIds[0] === 2;
    const result = { requested: 1, succeeded: success ? 1 : 0, failed: success ? 0 : 1,
      results: [{ accountId: accountIds[0], status: success ? 'succeeded' : 'failed', failureCategory: 'model_unavailable' }] };
    await persistResult(result); return result;
  }) });
  f.account(1); f.account(2);
  const rows = (await f.request('/api/console/overview')).body.accounts;
  const accepted = await f.request('/api/console/maintain', testOnlyBody(rows));
  const job = await f.waitJob(accepted.body.jobId);
  assert.equal(job.status, 'partial'); assert.deepEqual(tested, [1, 2]);
  assert.equal(job.result.summary.tested, 2); assert.equal(job.result.summary.verified, 1);
  assert.equal(job.result.summary.failed, 1); assert.equal(job.result.summary.tokensUpdated, 0);
  assert.deepEqual(job.result.items.map(item => item.status), ['failed', 'verified']);
});

test('controlled registration persists paired SMS caps and binds them to the original idempotency receipt', async t => {
  const seen = [];
  const f = await fixture(t, { registrar: async ({ options }) => {
    seen.push(structuredClone(options));
    throw Object.assign(new Error('synthetic stop before any external action'), { code: 'FIXTURE_CONTROLLED_STOP' });
  } });
  const body = { count: 1, country: 'US', operator: '', autoImport: true, smsMaxPriceUsd: '0.5000', smsMaxAcquisitions: 1 };
  const key = crypto.randomUUID();
  const admitted = await f.request('/api/console/register', body, key);
  assert.equal(admitted.status, 202);
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'failed'); assert.deepEqual(job.payload, body);
  assert.deepEqual(seen, [{ count: 1, country: 'US', operator: '', smsMaxPriceUsd: '0.5000', smsMaxAcquisitions: 1 }]);
  const child = await f.db.getJob(job.result.childJobIds[0]); assert.deepEqual(child.payload, { ...body, parentJobId: job.id });
  const replay = await f.request('/api/console/register', body, key);
  assert.equal(replay.status, 202); assert.equal(replay.body.jobId, job.id); assert.equal(replay.headers.get('idempotency-replayed'), 'true');
  const changed = await f.request('/api/console/register', { ...body, smsMaxPriceUsd: '0.4' }, key);
  assert.equal(changed.status, 409); assert.equal(changed.body.error, 'IDEMPOTENCY_KEY_REUSED');
  const unbounded = await f.request('/api/console/register', { count: 1, country: 'US', operator: '', autoImport: true }, key);
  assert.equal(unbounded.status, 409); assert.equal(unbounded.body.error, 'IDEMPOTENCY_KEY_REUSED');
  assert.equal(seen.length, 1); assert.equal(f.calls.import, 0); assert.deepEqual(f.writes, []);
});

test('register API rejects incomplete, malformed or multi-account SMS caps before creating tasks', async t => {
  const f = await fixture(t);
  const base = { count: 1, country: 'US', autoImport: true };
  const invalid = [
    { smsMaxPriceUsd: '0.5' }, { smsMaxAcquisitions: 1 },
    { smsMaxPriceUsd: '0.5', smsMaxAcquisitions: '1' }, { smsMaxPriceUsd: '0.5', smsMaxAcquisitions: 2 },
    { smsMaxPriceUsd: '0.5', smsMaxAcquisitions: 1, count: 2 },
    ...['0', '1.0001', '0.00001', '1e-1', ' 0.5', '0.5\n', 0.5, null].map(smsMaxPriceUsd => ({ smsMaxPriceUsd, smsMaxAcquisitions: 1 })),
  ];
  for (const changes of invalid) {
    const response = await f.request('/api/console/register', { ...base, ...changes });
    assert.equal(response.status, 400); assert.equal(response.body.error, 'REGISTRATION_OPTIONS_INVALID');
  }
  assert.equal(f.calls.registration, 0); assert.equal(f.calls.import, 0); assert.deepEqual(await f.db.listJobs(), []);
});

test('failed registration drains progress and exposes its actual failure stage without inventing failed accounts', async t => {
  const f = await fixture(t, { registrar: async ({ onProgress }) => {
    onProgress({ stage: 'phase3_email_oauth', completedCount: 0 });
    throw Object.assign(new Error('existing local account needs continuation'), {
      code: 'BATCH_PENDING_PHASE3_CONTINUATION', details: { completedCount: 0, nextAction: 'resume_account' },
    });
  } });
  const admitted = await f.request('/api/console/register', { count: 1, country: 'US', autoImport: true });
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'failed'); assert.equal(job.result.stage, 'failed');
  assert.equal(job.result.failureStage, 'phase3_email_oauth');
  assert.equal(job.result.summary.registered, 0); assert.equal(job.result.summary.failed, 0);
  assert.equal(job.result.nextAction, 'resume_account');
  const card = (await f.request('/api/console/overview')).body.jobs.find(item => item.id === job.id);
  assert.equal(card.stage, 'failed'); assert.equal(card.failureStage, 'phase3_email_oauth');
  assert.equal(card.nextAction, 'resume_account');
  assert.equal(f.calls.import, 0);
});

test('parent task log API includes the actual bound child engine body but no unrelated run', async t => {
  const f = await fixture(t);
  const admitted = await f.request('/api/console/register', { count: 1, country: 'US', autoImport: true });
  const job = await f.waitJob(admitted.body.jobId);
  const child = job.result.childJobIds[0];
  const header = '[2020-01-01T00:00:00.000Z] [ERROR] ';
  fs.writeFileSync(path.join(f.root, 'logs', 'run-20200101T000000000Z-2147483647-' + child + '.log'),
    header + 'original engine error password=fixture-private-secret\n', { mode: 0o600 });
  fs.writeFileSync(path.join(f.root, 'logs', 'run-20200101T000000000Z-2147483646.log'),
    header + 'unrelated legacy error\n', { mode: 0o600 });
  const result = await f.request('/api/console/logs?jobId=' + job.id);
  assert.equal(result.status, 200);
  assert.equal(result.body.entries.length, 1);
  assert.equal(result.body.entries[0].jobId, child);
  assert.match(result.body.entries[0].message, /original engine error/);
  assert.equal(JSON.stringify(result.body).includes('fixture-private-secret'), false);
});

test('console maintenance respects healthy quota manual-disabled and unknown accounts without invoking refresh or delete', async t => {
  const f = await fixture(t, { phase3Runner: async () => { throw new Error('must not login'); } });
  f.account(1);
  f.account(2, { status: 'error', schedulable: false,
    error_message: JSON.stringify({ error: { code: 'insufficient_quota' } }) });
  f.account(3, { status: 'inactive', schedulable: false });
  f.account(4, { status: 'error', schedulable: false, error_message: 'HTTP 403 request failed' });
  const response = await f.request('/api/console/maintain', { accountIds: [], importNew: false, refreshInvalid: true, deleteBanned: true });
  assert.equal(response.status, 202);
  const job = await f.waitJob(response.body.jobId);
  assert.equal(job.status, 'succeeded', job.error || job.result?.code);
  assert.equal(job.result.summary.skipped, 4);
  assert.deepEqual(f.writes, []);
  assert.equal(f.calls.preflight, 0);
  const overview = await f.request('/api/console/overview');
  assert.equal(overview.status, 200);
  assert.equal(overview.body.summary.quotaWait, 1);
  assert.equal(overview.body.summary.healthy, 1);
});

test('44 refresh targets share one real Node-symlink preflight failure without inventing account failures', async t => {
  let preflights = 0; let spawned = 0;
  const { runNetworkPreflight } = require('../backend/networkPreflight');
  const f = await fixture(t, { preflight: async options => {
    preflights += 1;
    return runNetworkPreflight({ ...options, runner: async () => { spawned += 1; throw new Error('must not spawn'); } });
  } });
  fs.writeFileSync(path.join(f.root, 'index.js'), '// synthetic entry point', { mode: 0o600 });
  const nodeAlias = path.join(f.root, 'node-alias'); fs.symlinkSync(process.execPath, nodeAlias);
  process.env.GPT_REGISTER_NODE_PATH = nodeAlias;
  for (let id = 1; id <= 44; id++) invalidRemote(f, id);
  const response = await f.request('/api/console/maintain', { accountIds: [], importNew: false, refreshInvalid: true, deleteBanned: true });
  assert.equal(response.status, 202);
  const job = await f.waitJob(response.body.jobId);
  assert.equal(job.status, 'failed'); assert.equal(job.result.code, 'PHASE3_PATH_INVALID');
  assert.equal(job.result.failureStage, 'checking_network'); assert.equal(job.result.summary.failed, 0);
  assert.equal(job.result.summary.tokensGenerated, 0); assert.equal(job.result.summary.tokensUpdated, 0);
  assert.deepEqual(job.result.progress, { completed: 0, total: 44 });
  assert.deepEqual(job.result.items, []); assert.deepEqual(job.result.childJobIds, []);
  assert.match(job.result.recoveryMessage, /尚未启动任何账号刷新/);
  assert.equal(preflights, 1); assert.equal(spawned, 0); assert.equal(f.calls.import, 0);
  assert.deepEqual(f.writes, []); assert.deepEqual(f.tested, []);
  assert.equal((await f.db.listJobs()).length, 1); assert.equal(await f.db.countActiveJobs(), 0);
});

for (const kind of ['path_permissions', 'invalid_protocol', 'channels_unavailable', 'failed_process_with_ok_channels', 'unknown_result']) {
  test('shared refresh preflight ' + kind + ' stops the batch once and preserves safety', async t => {
    let preflights = 0;
    const codes = { path_permissions: 'PHASE3_PATH_PERMISSIONS_INVALID', invalid_protocol: 'NETWORK_PREFLIGHT_INVALID',
      channels_unavailable: 'CONSOLE_NETWORK_UNAVAILABLE', failed_process_with_ok_channels: 'CONSOLE_NETWORK_UNAVAILABLE',
      unknown_result: 'REGISTRATION_TERMINATION_UNCONFIRMED' };
    const f = await fixture(t, { preflight: async () => {
      preflights += 1;
      if (kind === 'channels_unavailable') return { ok: false, channels: ['mail', 'oauth'].map(id => ({ id, ok: false, code: 'FIXTURE_NETWORK_FAILED' })) };
      if (kind === 'failed_process_with_ok_channels') return { ok: false, channels: ['mail', 'oauth'].map(id => ({ id, ok: true, code: 'OK' })) };
      throw Object.assign(new Error('synthetic preflight failure'), { code: codes[kind],
        ...(kind === 'unknown_result' ? { requiresReconciliation: true, writeOutcomeUnknown: true, doNotRetry: true } : {}) });
    } });
    invalidRemote(f, 1); invalidRemote(f, 2);
    const response = await f.request('/api/console/maintain', { accountIds: [1, 2], importNew: false, refreshInvalid: true, deleteBanned: false });
    const job = await f.waitJob(response.body.jobId);
    assert.equal(job.status, 'failed'); assert.equal(job.result.code, codes[kind]);
    assert.equal(job.result.failureStage, 'checking_network'); assert.equal(job.result.summary.failed, 0);
    assert.deepEqual(job.result.items, []); assert.deepEqual(job.result.childJobIds, []);
    assert.equal(preflights, 1); assert.equal(f.calls.import, 0); assert.deepEqual(f.writes, []);
    if (kind === 'unknown_result') {
      assert.equal(job.result.reconciliationHold, true); assert.equal(job.result.requiresReconciliation, true);
      assert.equal((await f.request('/api/console/maintain', { accountIds: [1], importNew: false, refreshInvalid: true, deleteBanned: false })).status, 409);
      assert.equal(preflights, 1);
    }
  });
}

test('channel detection preserves a safe execution error code without claiming a network probe ran', async t => {
  const f = await fixture(t, { preflight: async () => { throw Object.assign(new Error('fixture-sensitive-path-and-detail'), { code: 'PHASE3_PATH_INVALID' }); } });
  const response = await f.request('/api/console/preflight', {});
  assert.equal(response.status, 200); assert.equal(response.body.ok, false);
  for (const id of ['sms', 'mail', 'oauth']) {
    const channel = response.body.channels.find(item => item.id === id);
    assert.equal(channel.ok, false); assert.equal(channel.code, 'PHASE3_PATH_INVALID');
    assert.match(channel.message, /尚未进行该通道网络检测/);
  }
  assert.equal(JSON.stringify(response.body).includes('fixture-sensitive-path-and-detail'), false);
  assert.equal(f.calls.registration, 0); assert.equal(f.calls.import, 0);
});

test('ordinary per-account mapping failures continue after one shared preflight but never count skips as success', async t => {
  const f = await fixture(t);
  invalidRemote(f, 1); invalidRemote(f, 2); f.account(3);
  const response = await f.request('/api/console/maintain', { accountIds: [], importNew: false, refreshInvalid: true, deleteBanned: false });
  const job = await f.waitJob(response.body.jobId);
  assert.equal(job.status, 'failed'); assert.equal(job.result.stage, 'failed');
  assert.equal(job.result.summary.failed, 2); assert.equal(job.result.summary.skipped, 1);
  assert.deepEqual(job.result.items.map(item => item.status), ['failed', 'failed', 'skipped']);
  assert.equal(job.result.items.filter(item => item.code === 'CONSOLE_LOGIN_MAPPING_REQUIRED').length, 2);
  assert.equal(f.calls.preflight, 1); assert.equal(f.calls.import, 0); assert.deepEqual(job.result.childJobIds, []);
});

test('refresh preflight is not required for unselected invalid accounts or import-only maintenance', async t => {
  let preflights = 0;
  const f = await fixture(t, { preflight: async () => { preflights += 1; throw new Error('must not preflight'); } });
  invalidRemote(f, 1); f.account(2);
  for (const body of [
    { accountIds: [2], importNew: false, refreshInvalid: true, deleteBanned: false },
    { accountIds: [], importNew: true, refreshInvalid: false, deleteBanned: false },
  ]) {
    const response = await f.request('/api/console/maintain', body); assert.equal(response.status, 202);
    const job = await f.waitJob(response.body.jobId); assert.equal(job.status, 'succeeded');
  }
  assert.equal(preflights, 0); assert.deepEqual(f.writes, []);
});

test('observed or deleted accounts cannot reenter automatic import after disappearing from Sub2API', async t => {
  const f = await fixture(t);
  f.account(1); f.token(1);
  let response = await f.request('/api/console/maintain', { accountIds: [], importNew: true, refreshInvalid: false, deleteBanned: false });
  assert.equal((await f.waitJob(response.body.jobId)).status, 'succeeded');
  f.remote.length = 0;
  response = await f.request('/api/console/maintain', { accountIds: [], importNew: true, refreshInvalid: false, deleteBanned: false });
  assert.equal((await f.waitJob(response.body.jobId)).status, 'succeeded');
  assert.equal(f.calls.import, 0);
});

test('console rejects selected-account scope mixed with unrelated new imports and requires write authentication', async t => {
  const f = await fixture(t);
  const response = await f.request('/api/console/maintain', { accountIds: [1], importNew: true, refreshInvalid: true, deleteBanned: true });
  assert.equal(response.status, 400);
  process.env.PANEL_WRITE_ENABLED = '0';
  assert.equal((await f.request('/api/console/register', { count: 1, country: 'US', autoImport: true })).status, 403);
  assert.equal(f.calls.registration, 0);
});

test('console settings supports GET and CAS POST with automatic maintenance opt-in only', async t => {
  const f = await fixture(t);
  const current = await f.request('/api/console/settings');
  assert.equal(current.status, 200);
  assert.equal(current.body.policy.enabled, false);
  const changed = { revision: current.body.revision, policy: { ...current.body.policy, enabled: true } };
  assert.equal((await f.request('/api/console/settings', changed)).status, 400);
  assert.equal((await f.request('/api/console/settings', { ...changed, confirm: true })).status, 200);
  assert.equal((await f.request('/api/console/settings', { ...changed, confirm: true })).status, 409);
});

test('stop cancels only the owned pipeline and repeated stop cannot launch another registration', async t => {
  const f = await fixture(t, { registrar: async ({ signal }) => new Promise((resolve, reject) => {
    const abort = () => reject(Object.assign(new Error('stopped'), { code: 'JOB_INTERRUPTED' }));
    signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort();
  }) });
  const admitted = await f.request('/api/console/register', { count: 1, country: 'US', autoImport: true });
  for (let i = 0; i < 100; i++) {
    if ((await f.db.getJob(admitted.body.jobId)).result?.childJobIds?.length) break;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  const route = '/api/console/jobs/' + admitted.body.jobId + '/stop';
  assert.equal((await f.request(route, {})).status, 202);
  assert.equal((await f.waitJob(admitted.body.jobId)).status, 'interrupted');
  assert.equal((await f.request(route, {})).body.status, 'interrupted');
  assert.equal(f.calls.import, 0);
});

test('stopping after one verified registration preserves its count without starting import', async t => {
  let f, started;
  const executing = new Promise(resolve => { started = resolve; });
  f = await fixture(t, { registrar: async ({ signal }) => {
    const output = f.token(1);
    started();
    return new Promise((resolve, reject) => {
      const abort = () => reject(Object.assign(new Error('stopped after verified output'), {
        code: 'JOB_INTERRUPTED', details: { completedCount: 1, selectedKeys: [output.selectedKey],
          artifacts: [{ selectedKey: output.selectedKey, contentHash: output.contentHash }] },
      }));
      signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort();
    });
  } });
  const admitted = await f.request('/api/console/register', { count: 2, country: 'US', autoImport: true });
  await executing;
  await f.request('/api/console/jobs/' + admitted.body.jobId + '/stop', {});
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'interrupted'); assert.equal(job.result.summary.registered, 1);
  assert.equal(job.result.summary.imported, 0); assert.equal(f.calls.import, 0);
  assert.match(job.result.recoveryMessage, /未继续导入或租号/);
  assert.equal(fs.existsSync(path.join(f.root, 'tokens/account-1.json')), true);
});

test('safe partial registration imports only proven successes and reports the remaining account for explicit continuation', async t => {
  let f;
  f = await fixture(t, { registrar: async () => {
    const output = f.token(1);
    throw Object.assign(new Error('synthetic incomplete second account'), {
      code: 'REGISTRATION_INCOMPLETE', details: { completedCount: 1,
        selectedKeys: [output.selectedKey], artifacts: [{ selectedKey: output.selectedKey, contentHash: output.contentHash }],
        nextAction: 'resume_phase2' },
    });
  } });
  const admitted = await f.request('/api/console/register', { count: 2, country: 'US', autoImport: true });
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'partial', job.error || job.result?.code);
  assert.equal(job.result.summary.registered, 1);
  assert.equal(job.result.summary.imported, 1);
  assert.equal(job.result.summary.failed, 1);
  assert.equal(job.result.nextAction, 'resume_phase2');
  assert.deepEqual(f.tested, [1]);
});

test('unknown registration output never proceeds with partial token imports', async t => {
  let f;
  f = await fixture(t, { registrar: async () => {
    const output = f.token(1);
    throw Object.assign(new Error('synthetic unknown child outcome'), {
      code: 'REGISTRATION_UNKNOWN', requiresReconciliation: true,
      details: { completedCount: 1, selectedKeys: [output.selectedKey],
        artifacts: [{ selectedKey: output.selectedKey, contentHash: output.contentHash }] },
    });
  } });
  const admitted = await f.request('/api/console/register', { count: 2, country: 'US', autoImport: true });
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'failed');
  assert.equal(f.calls.import, 0);
  assert.equal((await f.db.listJobsPage()).reconciliationHolds.total > 0, true);
});

test('resume is a distinct idempotent server workflow and never calls new registration', async t => {
  let f; let resumed = 0;
  f = await fixture(t, { resumer: async ({ target }) => {
    resumed += 1;
    assert.deepEqual(target, { selectedKey: 'registration:accounts:0', revision: 'fixture-v1' });
    const output = f.token(1);
    return { completedCount: 1, selectedKeys: [output.selectedKey],
      artifacts: [{ selectedKey: output.selectedKey, contentHash: output.contentHash }] };
  } });
  const body = { selectedKey: 'registration:accounts:0', revision: 'fixture-v1', autoImport: true };
  const key = crypto.randomUUID();
  const response = await f.request('/api/console/register/resume', body, key);
  assert.equal(response.status, 202);
  const job = await f.waitJob(response.body.jobId);
  assert.equal(job.status, 'succeeded', job.error || job.result?.code);
  assert.equal(job.type, 'console_resume');
  assert.equal(f.calls.registration, 0);
  assert.equal(resumed, 1);
  assert.equal((await f.request('/api/console/register/resume', body, key)).body.jobId, job.id);
  assert.equal(resumed, 1);
});

test('overview retains full parent progress above general-list limits and returns bounded item details', async t => {
  const f = await fixture(t);
  const parent = await f.db.createJob('console_maintain', {}, 'local', { claimKeys: ['console_pipeline'] });
  await f.db.startMutationJob(parent.id);
  await f.db.updateJob(parent.id, { result: {
    stage: 'maintaining', progress: { completed: 110, total: 128 }, summary: { skipped: 110 },
    items: Array.from({ length: 110 }, (_, n) => ({ accountId: n + 1, message: 'x'.repeat(200) })), childJobIds: [],
  } });
  const summary = (await f.db.listJobsPage()).jobs.find(job => job.id === parent.id);
  assert.equal(summary.result.summaryUnavailable, true);
  let card = (await f.request('/api/console/overview')).body.jobs.find(job => job.id === parent.id);
  assert.equal(card.stage, 'maintaining');
  assert.deepEqual(card.progress, { completed: 110, total: 128 });
  assert.equal(card.items.length, 100);
  assert.equal(card.itemsTotal, 110);
  assert.equal(card.itemsTruncated, true);
  await f.db.updateJob(parent.id, { status: 'succeeded', finishedAt: new Date().toISOString() });
  card = (await f.request('/api/console/overview')).body.jobs.find(job => job.id === parent.id);
  assert.equal(card.status, 'succeeded');
  assert.equal(card.progress.completed, 110);
});

test('console overview and configuration remain readable without a Sub2API endpoint', async t => {
  const f = await fixture(t, { clientFactory: () => ({ listAccounts: async () => { throw new Error('not configured'); } }) });
  delete process.env.SUB2API_BASE_URL;
  const response = await f.request('/api/console/overview');
  assert.equal(response.status, 200);
  assert.equal(response.body.capabilities.comparisonAvailable, false);
  assert.equal(response.body.settings.policy.enabled, false);
  assert.equal(typeof response.body.warning, 'string');
});

test('automatic import never treats paid or unknown local plans as Free', async t => {
  const f = await fixture(t);
  f.token(2, { plan_type: 'plus' });
  f.token(3, { plan_type: undefined });
  const overview = await f.request('/api/console/overview');
  assert.equal(overview.body.summary.neverImported, 0);
  assert.equal(overview.body.accounts.filter(a => a.action === 'review').length, 2);
  const response = await f.request('/api/console/maintain', { accountIds: [], importNew: true, refreshInvalid: false, deleteBanned: false });
  const job = await f.waitJob(response.body.jobId);
  assert.equal(job.status, 'succeeded');
  assert.equal(f.calls.import, 0);
  assert.equal(job.result.summary.imported, 0);
});

test('settings cannot change between child steps of an active pure orchestration parent', async t => {
  const f = await fixture(t);
  const saved = (await f.request('/api/console/settings')).body;
  const parent = await f.db.createJob('console_maintain', {}, 'local', { claimKeys: ['console_pipeline'] });
  await f.db.startMutationJob(parent.id);
  const response = await f.request('/api/console/settings', { revision: saved.revision,
    policy: { ...saved.policy, intervalMinutes: saved.policy.intervalMinutes + 1 } });
  assert.equal(response.status, 409);
  assert.equal(response.body.error, 'CONSOLE_SETTINGS_ACTIVE_CONFLICT');
  assert.equal((await f.request('/api/console/settings')).body.revision, saved.revision);
  await f.db.updateJob(parent.id, { status: 'interrupted', finishedAt: new Date().toISOString() });
});

test('ordinary test failure after batch import does not abandon the remaining already-imported accounts', async t => {
  let f; const tested = [];
  f = await fixture(t, {
    registrar: async () => {
      const outputs = [f.token(1), f.token(2)];
      return { completedCount: 2, selectedKeys: outputs.map(item => item.selectedKey),
        artifacts: outputs.map(({ selectedKey, contentHash }) => ({ selectedKey, contentHash })) };
    },
    importer: async ({ persistResult }) => {
      f.account(1); f.account(2);
      const result = { succeeded: 2, failed: 0, imported: [1, 2].map(accountId => ({ verification: { accountId } })) };
      await persistResult(result); return result;
    },
    tester: async ({ db, jobId, accountIds, persistResult }) => withControlPlaneLock(async () => {
      await db.startMutationJob(jobId);
      tested.push(...accountIds);
      const failed = accountIds[0] === 1;
      const result = { requested: 1, succeeded: failed ? 0 : 1, failed: failed ? 1 : 0,
        results: [{ accountId: accountIds[0], status: failed ? 'failed' : 'succeeded' }] };
      await persistResult(result); return result;
    }),
  });
  const response = await f.request('/api/console/register', { count: 2, country: 'US', autoImport: true });
  const job = await f.waitJob(response.body.jobId);
  assert.equal(job.status, 'partial', job.error || job.result?.code);
  assert.deepEqual(tested, [1, 2]);
  assert.equal(job.result.summary.imported, 2);
  assert.equal(job.result.summary.failed, 1);
  assert.deepEqual(job.result.items.map(item => item.status), ['failed', 'verified']);
});

test('ordinary partial import still tests its verified success without retrying failed imports', async t => {
  let f; let imports = 0;
  f = await fixture(t, {
    registrar: async () => {
      const outputs = [f.token(1), f.token(2)];
      return { completedCount: 2, selectedKeys: outputs.map(item => item.selectedKey),
        artifacts: outputs.map(({ selectedKey, contentHash }) => ({ selectedKey, contentHash })) };
    },
    importer: async ({ persistResult }) => {
      imports += 1; f.account(1);
      const result = { succeeded: 1, failed: 1, imported: [{ verification: { accountId: 1 } }] };
      await persistResult(result); return result;
    },
  });
  const response = await f.request('/api/console/register', { count: 2, country: 'US', autoImport: true });
  const job = await f.waitJob(response.body.jobId);
  assert.equal(job.status, 'partial', job.error || job.result?.code);
  assert.equal(imports, 1);
  assert.deepEqual(f.tested, [1]);
  assert.equal(job.result.summary.registered, 2);
  assert.equal(job.result.summary.imported, 1);
  assert.equal(job.result.summary.failed, 1);
});

test('stage-only registration events cannot reset the number of completed accounts', async t => {
  let f; const progress = [];
  f = await fixture(t, { registrar: async ({ onProgress }) => {
    onProgress({ type: 'account_completed', completedCount: 1 });
    onProgress({ type: 'stage', stage: 'phase2_bind_email' });
    const output = f.token(1);
    return { completedCount: 1, selectedKeys: [output.selectedKey],
      artifacts: [{ selectedKey: output.selectedKey, contentHash: output.contentHash }] };
  } });
  const original = f.db.updateJob.bind(f.db);
  f.db.updateJob = async (id, patch) => {
    if (patch.result?.stage === 'phase2_bind_email') progress.push(patch.result.progress.completed);
    return original(id, patch);
  };
  const response = await f.request('/api/console/register', { count: 1, country: 'US', autoImport: true });
  assert.equal((await f.waitJob(response.body.jobId)).status, 'succeeded');
  assert.deepEqual(progress, [1]);
});
