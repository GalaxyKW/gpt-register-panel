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
      remote.find(a => a.id === id).credentials = { ...payload.credentials };
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
      headers: { 'x-panel-token': admin, 'content-type': 'application/json', 'idempotency-key': key },
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
  const replay = await f.request('/api/console/register', body, key);
  assert.equal(replay.body.jobId, admission.body.jobId);
  assert.equal(replay.headers.get('idempotency-replayed'), 'true');
  assert.equal(f.calls.registration, 1);
  assert.equal((await f.request('/api/console/register', { ...body, count: 2 }, key)).status, 409);
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
