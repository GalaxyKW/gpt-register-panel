const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
require('./test-isolation');
const { PanelDb } = require('../backend/db');
const { safeAccount, Sub2ApiAdminClient } = require('../backend/adapters/sub2apiAdmin');
const { DEFAULT_CONSOLE_SETTINGS, managementEndpointKey, lifecycleIdentityKeys,
  recordObservedAccounts, canCreateAccount, creationEligibility } = require('../backend/accountLifecycle');
const { classifyAccountMaintenance, buildMaintenancePlan, deleteConfirmedBannedAccount,
  verifyPhase3BanEvidence } = require('../backend/accountMaintenance');
const { accountTestTargetDigest, accountTestTargetRevision } = require('../backend/accountTargetRevision');
const { remotePhase3EndpointDigest } = require('../backend/remotePhase3');

const BASE_URL = 'http://127.0.0.1:18765';
const ENDPOINT = managementEndpointKey(BASE_URL);
const NOW = Date.parse('2026-10-09T00:00:00.000Z');

function rawAccount(overrides = {}) {
  return { id: 47, name: 'free00047', platform: 'openai', type: 'oauth',
    status: 'error', schedulable: false,
    credentials_status: { has_access_token: true, has_refresh_token: true, has_id_token: false },
    credentials: { plan_type: 'free', chatgpt_account_id: 'account-forty-seven',
      chatgpt_user_id: 'user-forty-seven', access_token: 'fixture-access', refresh_token: 'fixture-refresh',
      expires_at: '2026-10-20T00:00:00.000Z' },
    error_message: '{"error":{"code":"account_deactivated","message":"fixture-private-text"}}', ...overrides };
}
function account(overrides = {}) { return safeAccount(rawAccount(overrides)); }
function planFor(value, lifecycles = [], policy = {}) {
  return buildMaintenancePlan({ accounts: [value], lifecycles, endpointKey: ENDPOINT, nowMs: NOW, policy });
}
function privateDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-maintenance-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
async function database(t) {
  const directory = privateDirectory(t);
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  await db.ready;
  return { db, directory };
}

for (const [label, raw, classification] of [
  ['healthy beats stale ban error', { status: 'active', schedulable: true }, 'healthy'],
  ['confirmed structured ban', {}, 'confirmed_banned'],
  ['unavailable quota', { error_message: '{"error":{"code":"usage_limit_reached"}}' }, 'quota_wait'],
  ['overload cooldown', { overload_until: '2026-10-10T00:00:00Z' }, 'quota_wait'],
  ['rate limit cooldown overrides stale ban', { rate_limit_reset_at: '2026-10-10T00:00:00Z' }, 'quota_wait'],
  ['quota message overrides conflicting ban', { temp_unschedulable_reason: 'HTTP 429 rate limit' }, 'quota_wait'],
  ['401 does not prove ban', { error_message: 'HTTP 401 Unauthorized' }, 'network_unknown'],
  ['403 does not prove ban', { error_message: 'HTTP 403 forbidden account disabled' }, 'network_unknown'],
  ['error does not prove ban', { error_message: '' }, 'network_unknown'],
  ['workspace ban is not account ban', { error_message: '{"error":{"code":"deactivated_workspace"}}' }, 'network_unknown'],
  ['organization ban is not account ban', { error_message: '{"error":{"code":"organization_deactivated"}}' }, 'network_unknown'],
  ['text mention is not structured proof', { error_message: 'Your account_deactivated code may be incorrect' }, 'network_unknown'],
  ['structured invalid grant needs reauth', { error_message: '{"error":{"code":"invalid_grant"}}' }, 'auth_invalid'],
  ['wrapped body refresh reused needs reauth', { error_message: 'Token refresh failed (non-retryable): OPENAI_OAUTH_TOKEN_REFRESH_FAILED: status 401, body: {"error":{"code":"refresh_token_reused"}}' }, 'auth_invalid'],
  ['known refresh prefix needs reauth', { error_message: 'Token refresh failed (non-retryable): invalid_grant: revoked' }, 'auth_invalid'],
  ['invalid client is provider config not account', { error_message: 'Token refresh failed (non-retryable): invalid_client' }, 'network_unknown'],
  ['inactive preserves manual intent', { status: 'inactive' }, 'manual_disabled'],
  ['disabled preserves manual intent', { status: 'disabled' }, 'manual_disabled'],
  ['manual scheduler stop', { status: 'active', error_message: '' }, 'manual_disabled'],
  ['administrator lifetime expiry blocks stale ban deletion', { expires_at: '2026-10-08T00:00:00Z' }, 'manual_disabled'],
  ['administrator lifetime expiry blocks stale auth refresh', { expires_at: '2026-10-08T00:00:00Z', error_message: '{"error":{"code":"invalid_grant"}}' }, 'manual_disabled'],
  ['informational lifetime expiry with auto-pause disabled does not block refresh', { expires_at: '2026-10-08T00:00:00Z', auto_pause_on_expired: false, error_message: '{"error":{"code":"invalid_grant"}}' }, 'auth_invalid'],
  ['invalid administrator lifetime preserves unknown state', { expires_at: 'not-a-date', error_message: '{"error":{"code":"invalid_grant"}}' }, 'network_unknown'],
  ['generic temporary failure', { error_message: 'network timeout' }, 'network_unknown'],
]) {
  test('maintenance classification: ' + label, () => {
    assert.equal(classifyAccountMaintenance(account(raw), { nowMs: NOW }).classification, classification);
  });
}

test('expired access token is refreshed only when not healthy, quota or manually disabled', () => {
  const expired = rawAccount({ error_message: '' });
  expired.credentials.expires_at = '2026-10-08T00:00:00Z';
  assert.equal(classifyAccountMaintenance(safeAccount(expired), { nowMs: NOW }).classification, 'expired');
  expired.status = 'active'; expired.schedulable = true;
  assert.equal(classifyAccountMaintenance(safeAccount(expired), { nowMs: NOW }).classification, 'healthy');
  expired.status = 'error'; expired.error_message = 'HTTP 429';
  assert.equal(classifyAccountMaintenance(safeAccount(expired), { nowMs: NOW }).classification, 'quota_wait');
});

test('raw upstream text and plan strings cannot escape finite maintenance projection', () => {
  const value = rawAccount({ error_message: 'some-fixture-secret-in-error', temp_unschedulable_reason: 'another-fixture-secret' });
  value.credentials.plan_type = 'free'; value.credentials.chatgpt_plan_type = 'pro';
  const safe = safeAccount(value);
  assert.equal(safe.planType, '');
  assert.equal(JSON.stringify(safe).includes('fixture-secret'), false);
  assert.equal(safe.maintenanceEvidence.category, 'network_unknown');
});

test('plan excludes paid unknown other-provider and identity conflicts; ignores free name guessing', () => {
  const values = [account(), account({ id: 48, name: 'free00048' }), account({ id: 49, platform: 'anthropic' })];
  values[1].planType = 'plus';
  const conflictPlan = buildMaintenancePlan({ accounts: values, endpointKey: ENDPOINT, nowMs: NOW });
  assert.equal(conflictPlan.items[0].action, 'review');
  assert.equal(conflictPlan.items[1].action, 'skip');
  assert.equal(conflictPlan.items[2].action, 'skip');
  const unknown = account(); unknown.planType = '';
  assert.equal(planFor(unknown).items[0].action, 'skip');
  assert.equal(planFor(account(), [], { deleteBanned: false }).items[0].action, 'skip');
});

test('lifecycle survives restarts, two writers and job retention; tombstones never reopen', async (t) => {
  const { db, directory } = await database(t);
  const value = account();
  await recordObservedAccounts(db, { endpointKey: ENDPOINT, accounts: [value] });
  const target = { endpointKey: ENDPOINT, identityKeys: lifecycleIdentityKeys(value) };
  assert.equal((await canCreateAccount(db, target)).allowed, false);
  const record = { ...target, sub2apiId: value.id, accountName: value.name,
    state: 'delete_pending', reasonCode: 'confirmed_ban_delete_pending' };
  await db.upsertAccountLifecycle(record);
  const second = new PanelDb(path.join(directory, 'panel.sqlite3')); await second.ready;
  await second.upsertAccountLifecycle({ ...record, state: 'deleted', reasonCode: 'confirmed_ban_deleted' });
  await recordObservedAccounts(db, { endpointKey: ENDPOINT, accounts: [value] });
  await db.saveLink({ identityKey: target.identityKeys[0], identityKeys: target.identityKeys,
    endpointKey: ENDPOINT, tokenPath: 'tokens/fixture.json', sub2apiId: value.id, accountName: value.name });
  assert.equal((await canCreateAccount(db, target)).reasonCode, 'lifecycle_deleted');
  assert.equal((await second.listAccountLifecycles(ENDPOINT)).filter((row) => row.state === 'deleted').length, 2);
  await db.write((sql) => sql.run('DELETE FROM sync_jobs; DELETE FROM audit_events; DELETE FROM sync_snapshots'));
  assert.equal((await canCreateAccount(second, target)).allowed, false);
});

test('lifecycle observes current aliases and rejects identities reused at another ID', async (t) => {
  const { db } = await database(t);
  await recordObservedAccounts(db, { endpointKey: ENDPOINT, accounts: [account(), account({ id: 48 })] });
  const history = await db.listAccountLifecycles(ENDPOINT);
  assert.equal(history.every((row) => row.state === 'review_required'), true);
  assert.equal(planFor(account(), history).items[0].action, 'review');
});

test('lifecycle namespaces endpoint URLs and blocks legacy links without inventing endpoint provenance', async (t) => {
  const { db, directory } = await database(t);
  await db.saveLink({ identityKey: 'account:legacy-account', sub2apiId: 4, accountName: 'free00004' });
  const reopened = new PanelDb(path.join(directory, 'panel.sqlite3')); await reopened.ready;
  const history = await reopened.listAccountLifecycles(ENDPOINT);
  assert.equal(history[0].endpointKey, 'legacy_unbound');
  assert.equal(creationEligibility(history, { endpointKey: ENDPOINT, identityKeys: ['account:legacy-account'] }).allowed, false);
  assert.equal(creationEligibility(history, { endpointKey: ENDPOINT, identityKeys: ['email:fixture@example.test'] }).allowed, false);
  const target = { endpointKey: ENDPOINT, identityKeys: ['account:new-account'] };
  await reopened.upsertAccountLifecycle({ ...target, sub2apiId: 8, accountName: 'free00008', state: 'imported', reasonCode: 'import_verified' });
  const another = managementEndpointKey(BASE_URL + '/another');
  assert.equal((await canCreateAccount(reopened, { ...target, endpointKey: another })).allowed, true);
  assert.equal(managementEndpointKey(BASE_URL + '/'), ENDPOINT);
});

test('console settings are durable CAS, bounded and non-secret only', async (t) => {
  const { db, directory } = await database(t);
  assert.deepEqual(await db.getConsoleSettings(), { revision: 0, settings: DEFAULT_CONSOLE_SETTINGS });
  const other = new PanelDb(path.join(directory, 'panel.sqlite3')); await other.ready;
  const settings = { ...DEFAULT_CONSOLE_SETTINGS, enabled: true, intervalMinutes: 10 };
  await db.saveConsoleSettings(settings, { expectedRevision: 0 });
  await assert.rejects(other.saveConsoleSettings(settings, { expectedRevision: 0 }), { code: 'CONSOLE_SETTINGS_STALE' });
  await assert.rejects(db.saveConsoleSettings({ ...settings, apiKey: 'not-allowed' }, { expectedRevision: 1 }), { code: 'CONSOLE_SETTINGS_INVALID' });
  await assert.rejects(db.saveConsoleSettings({ ...settings, intervalMinutes: 1 }, { expectedRevision: 1 }), { code: 'CONSOLE_SETTINGS_INVALID' });
  assert.deepEqual(await other.getConsoleSettings(), { revision: 1, settings });
});

test('a claimed pure console coordinator allows one real child but never two simultaneous writers', async (t) => {
  const { db } = await database(t);
  const parent = await db.createJob('console_maintain', {}, 'local', { claimKeys: ['console_pipeline'] });
  await db.startMutationJob(parent.id);
  await db.updateJob(parent.id, { result: { stage: 'planning' } });
  const first = await db.createJob('account_delete', { parentJobId: parent.id }, 'local', { claimKeys: ['account:47'] });
  const second = await db.createJob('account_delete', { parentJobId: parent.id }, 'local', { claimKeys: ['account:48'] });
  await db.startMutationJob(first.id);
  await assert.rejects(db.startMutationJob(second.id), (error) => error.code === 'JOB_BLOCKED_BY_RUNNING_MUTATION');
  await assert.rejects(db.createJob('account_test', {}, 'local', { claimKeys: ['account:49'] }), { code: 'JOB_ALREADY_CLAIMED' });
  await db.updateJob(first.id, { status: 'succeeded', result: { deleted: true }, finishedAt: new Date().toISOString() });
  await db.startMutationJob(second.id);
  assert.equal((await db.getJob(parent.id)).status, 'running');
});

test('console coordinator still owns the exclusive pipeline claim and reconciliation blocks its children', async (t) => {
  const { db } = await database(t);
  const parent = await db.createJob('console_maintain', {}, 'local', { claimKeys: ['console_pipeline'] });
  await db.startMutationJob(parent.id);
  await assert.rejects(db.createJob('console_register', {}, 'local', { claimKeys: ['console_pipeline'] }), { code: 'JOB_ALREADY_CLAIMED' });
  const first = await db.createJob('account_delete', { parentJobId: parent.id }, 'local', { claimKeys: ['account:47'] });
  await db.startMutationJob(first.id);
  await db.updateJob(first.id, { status: 'failed', result: { requiresReconciliation: true, writeOutcomeUnknown: true }, finishedAt: new Date().toISOString() });
  await assert.rejects(db.createJob('account_test', {}, 'local', { claimKeys: ['account:48'] }), (error) => error.requiresReconciliation === true);
});

test('an arbitrary console-like job without the exact coordinator claim still blocks writes', async (t) => {
  const { db } = await database(t);
  const fake = await db.createJob('console_maintain', {}, 'local', { claimKeys: ['different_claim'] });
  await db.startMutationJob(fake.id);
  await assert.rejects(db.createJob('account_test', {}, 'local', { claimKeys: ['account:48'] }), { code: 'JOB_ALREADY_CLAIMED' });
});

async function deletionFixture(t, overrides = {}) {
  const { db, directory } = await database(t);
  const raw = rawAccount();
  const safe = safeAccount(raw);
  const calls = [];
  let deleted = false;
  const client = { baseUrl: BASE_URL,
    async listAccounts() { calls.push('list'); return [safe]; },
    async getAccount(id) {
      calls.push('get:' + id);
      if (deleted) throw Object.assign(new Error('not found'), { code: 'SUB2API_REQUEST_REJECTED', upstreamStatus: 404 });
      return safe;
    },
    async exportAccounts(ids) { calls.push('export:' + ids.join(',')); return { accounts: [raw], proxies: [] }; },
    async deleteAccount(id) {
      calls.push('delete:' + id);
      const rows = await db.listAccountLifecycles(ENDPOINT);
      assert.equal(rows.every((row) => row.state === 'delete_pending'), true);
      assert.equal(rows.length, 2);
      deleted = true;
    }, ...overrides };
  const target = planFor(safe).items[0];
  const backup = (payload) => {
    calls.push('backup');
    const filename = path.join(directory, 'backup.json');
    fs.writeFileSync(filename, JSON.stringify(payload), { mode: 0o600 });
    return filename;
  };
  return { db, client, target, backup, calls, safe, raw, endpointKey: ENDPOINT, now: () => NOW,
    logger: { checkpoint: () => true } };
}

test('confirmed deletion is exact-ID, backed up, rechecked, tombstoned before DELETE and verified 404', async (t) => {
  const fixture = await deletionFixture(t);
  const result = await deleteConfirmedBannedAccount(fixture);
  assert.equal(result.outcome, 'deleted'); assert.equal(result.verifiedAbsent, true);
  assert.deepEqual(fixture.calls, ['list', 'get:47', 'export:47', 'backup', 'get:47', 'delete:47', 'get:47']);
  assert.equal((await fixture.db.listAccountLifecycles(ENDPOINT)).every((row) => row.state === 'deleted'), true);
  await assert.rejects(deleteConfirmedBannedAccount(fixture), { code: 'MAINTENANCE_DELETE_ALREADY_RECORDED' });
});

test('lost deletion response is reconciled by exact-ID 404 without retrying DELETE', async (t) => {
  const fixture = await deletionFixture(t);
  const original = fixture.client.deleteAccount;
  fixture.client.deleteAccount = async (id) => { await original(id); throw new Error('fixture connection reset'); };
  const result = await deleteConfirmedBannedAccount(fixture);
  assert.equal(result.recoveredLostResponse, true);
  assert.equal(fixture.calls.filter((call) => call.startsWith('delete:')).length, 1);
});

for (const outcome of ['still_present', 'timeout', '403']) {
  test('ambiguous deletion retains pending tombstone and reconciliation: ' + outcome, async (t) => {
    const fixture = await deletionFixture(t);
    let sent = false;
    fixture.client.deleteAccount = async () => { sent = true; };
    const original = fixture.client.getAccount;
    fixture.client.getAccount = async (id) => {
      if (sent && outcome === 'timeout') throw Object.assign(new Error('timeout'), { code: 'SUB2API_TIMEOUT' });
      if (sent && outcome === '403') throw Object.assign(new Error('denied'), { code: 'SUB2API_REQUEST_REJECTED', upstreamStatus: 403 });
      return original(id);
    };
    await assert.rejects(deleteConfirmedBannedAccount(fixture), (error) => error.requiresReconciliation === true && error.writeOutcomeUnknown === true);
    assert.equal((await fixture.db.listAccountLifecycles(ENDPOINT)).every((row) => row.state === 'delete_pending'), true);
    assert.equal((await canCreateAccount(fixture.db, { endpointKey: ENDPOINT, identityKeys: fixture.target.identityKeys })).allowed, false);
  });
}

for (const mutation of ['id', 'name', 'status', 'planType', 'identity', 'overlap', 'backup', 'missing_backup', 'abort', 'endpoint']) {
  test('deletion stops before write when ' + mutation + ' changes', async (t) => {
    const fixture = await deletionFixture(t);
    if (mutation === 'id') fixture.safe.id = 48;
    if (mutation === 'name') fixture.safe.name = 'free00048';
    if (mutation === 'status') fixture.safe.status = 'active';
    if (mutation === 'planType') fixture.safe.planType = 'pro';
    if (mutation === 'identity') fixture.safe.userId = 'different-user';
    if (mutation === 'overlap') fixture.client.listAccounts = async () => [fixture.safe, { ...fixture.safe, id: 48 }];
    if (mutation === 'backup') fixture.raw.credentials.chatgpt_account_id = 'different-account';
    if (mutation === 'missing_backup') fixture.backup = () => null;
    if (mutation === 'abort') fixture.signal = AbortSignal.abort();
    if (mutation === 'endpoint') fixture.endpointKey = managementEndpointKey(BASE_URL + '/other');
    await assert.rejects(deleteConfirmedBannedAccount(fixture));
    assert.equal(fixture.calls.some((call) => call.startsWith('delete:')), false);
  });
}

test('phase3 ban evidence requires exact persisted disposition and original target/endpoint', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: BASE_URL, apiKey: 'fixture-admin-key' });
  const value = account({ error_message: '{"error":{"code":"invalid_grant"}}' });
  const target = { ...planFor(value).items[0], action: 'delete' };
  const job = { id: 'job_' + '1'.repeat(24), type: 'phase3', status: 'failed', finishedAt: '2026-10-09T00:00:00.000Z',
    payload: { sourceMode: 'token', remoteTarget: { accountId: value.id, targetRevision: accountTestTargetRevision(value),
      identityKeys: lifecycleIdentityKeys(value), targetDigest: accountTestTargetDigest(value), endpointDigest: remotePhase3EndpointDigest(client) } },
    result: { code: 'ACCOUNT_DEACTIVATED', accountDisposition: 'discard', dispositionPersisted: true, dispositionOutcome: 'persisted' } };
  const db = { getJob: async () => job };
  assert.equal(await verifyPhase3BanEvidence(db, job.id, { target, account: value, client }), true);
  job.payload.sourceMode = 'username';
  await assert.rejects(verifyPhase3BanEvidence(db, job.id, { target, account: value, client }));
  job.payload.sourceMode = 'token';
  job.result.dispositionPersisted = false;
  await assert.rejects(verifyPhase3BanEvidence(db, job.id, { target, account: value, client }));
  job.result.dispositionPersisted = true; job.payload.remoteTarget.accountId = 99;
  await assert.rejects(verifyPhase3BanEvidence(db, job.id, { target, account: value, client }));
});

test('adapter DELETE accepts only a positive exact account ID route and marks unknown writes', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: BASE_URL, apiKey: 'fixture-admin-key' });
  await assert.rejects(client.deleteAccount('47/other'), { code: 'SUB2API_DELETE_ID_INVALID' });
  await assert.rejects(client.request('DELETE', '/api/v1/admin/accounts'), { code: 'SUB2API_REQUEST_TARGET_INVALID' });
  await assert.rejects(client.request('DELETE', '/api/v1/admin/accounts/47?all=true'), { code: 'SUB2API_REQUEST_TARGET_INVALID' });
  let request;
  client.request = async (...args) => { request = args; return { message: 'arbitrary private upstream text' }; };
  assert.deepEqual(await client.deleteAccount(47), { accountId: 47, accepted: true });
  assert.equal(request[0], 'DELETE'); assert.equal(request[1], '/api/v1/admin/accounts/47'); assert.equal(request[3].writeOperation, true);
});

test('missing audit log checkpoint prevents backup and remote DELETE', async (t) => {
  const fixture = await deletionFixture(t);
  fixture.logger = { checkpoint: () => false };
  await assert.rejects(deleteConfirmedBannedAccount(fixture), { code: 'AUDIT_LOG_UNAVAILABLE' });
  assert.equal(fixture.calls.includes('backup'), false);
  assert.equal(fixture.calls.includes('delete:47'), false);
});

test('HTTP integration deletes only reviewed original ID through authenticated admin API', async (t) => {
  const fixture = await deletionFixture(t);
  let removed = false;
  const writes = [];
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    assert.equal(request.headers['x-api-key'], 'fixture-http-admin-key');
    let data;
    if (request.method === 'DELETE') {
      writes.push(pathname);
      assert.equal(pathname, '/api/v1/admin/accounts/47');
      removed = true; data = { message: 'fixture private response' };
    } else if (pathname === '/api/v1/admin/accounts') {
      data = { items: [fixture.raw], total: 1, page: 1, page_size: 200, pages: 1 };
    } else if (pathname === '/api/v1/admin/accounts/data') {
      const query = new URL(request.url, 'http://localhost').searchParams;
      assert.equal(query.get('ids'), '47'); assert.equal(query.get('include_proxies'), 'false');
      data = { accounts: [fixture.raw], proxies: [] };
    } else if (pathname === '/api/v1/admin/accounts/47') {
      if (removed) response.statusCode = 404;
      data = removed ? { message: 'not found' } : fixture.raw;
    } else { response.statusCode = 404; data = {}; }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ code: removed && request.method === 'GET' ? 404 : 0, data }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  fixture.client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:' + server.address().port, apiKey: 'fixture-http-admin-key' });
  fixture.endpointKey = managementEndpointKey(fixture.client.baseUrl);
  const current = await fixture.client.listAccounts({ platform: 'openai', type: 'oauth',
    pageSize: 200, requireTotal: true, requirePaginationMetadata: true });
  fixture.target = planFor(current[0]).items[0];
  const result = await deleteConfirmedBannedAccount(fixture);
  assert.equal(result.verifiedAbsent, true); assert.deepEqual(writes, ['/api/v1/admin/accounts/47']);
  assert.equal((await fixture.db.listAccountLifecycles(fixture.endpointKey)).every((row) => row.state === 'deleted'), true);
});
