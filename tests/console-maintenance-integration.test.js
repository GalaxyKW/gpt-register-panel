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
const { runPhase3Job } = require('../backend/phase3Worker');
const { managementEndpointKey } = require('../backend/accountLifecycle');

// This suite uses the REAL Phase3 process supervisor, importer, account tester,
// SQLite claims and HTTP API. Only the engine entry point and Sub2API transport
// are synthetic: no browser, remote login, paid registration or real API call.
async function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'console-maintenance-integration-'));
  for (const name of ['tokens', 'use_token', 'backups', 'logs']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  const secrets = [];
  const secret = () => { const value = crypto.randomBytes(24).toString('hex'); secrets.push(value); return value; };
  const admin = secret();
  const email = 'maintained-account@example.test';
  const user = { email, password: secret(), status: 'oauth_done' };
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([user]), { mode: 0o600 });
  const document = { email, chatgpt_account_id: 'maintenance-account', chatgpt_user_id: 'maintenance-user',
    plan_type: 'free', access_token: secret(), refresh_token: secret(), expires_at: '2099-01-01T00:00:00.000Z' };
  const original = { ...document, access_token: secret(), refresh_token: secret(), expires_at: '2001-01-01T00:00:00.000Z' };
  const relativePath = 'tokens/maintained-account.json';
  if (!options.noLocalToken) fs.writeFileSync(path.join(root, relativePath), JSON.stringify(original), { mode: 0o600 });
  const output = options.wrongOutputIdentity ? { ...document, chatgpt_account_id: 'some-other-account' } : document;
  const script = options.ban ? [
    "const fs = require('node:fs');",
    "const rows=JSON.parse(fs.readFileSync('username.json','utf8'));",
    "rows[0].status='account_deleted'; rows[0].phase3Disposition='discard'; rows[0].phase3LastErrorCode='ACCOUNT_DEACTIVATED';",
    "rows[0].phase3Retryable=false; rows[0].phase3LastAttemptAt=new Date().toISOString();",
    "fs.writeFileSync('username.json',JSON.stringify(rows),{mode:0o600}); process.exitCode=1;",
  ] : [
    "const fs = require('node:fs');",
    `fs.writeFileSync(${JSON.stringify(relativePath)}, JSON.stringify(${JSON.stringify(output)}), {mode:0o600});`,
  ];
  fs.writeFileSync(path.join(root, 'index.js'), script.join('\n'), { mode: 0o600 });
  const raw = { id: 47, name: 'free00047', platform: 'openai', type: 'oauth', status: 'error', schedulable: false,
    group_ids: [1], credentials: { ...original },
    credentials_status: { has_access_token: true, has_refresh_token: true, has_id_token: false },
    error_message: '{"error":{"code":"invalid_grant"}}' };
  const extra = { id: 99, name: 'free00099', platform: 'openai', type: 'oauth', status: 'active', schedulable: true,
    group_ids: [1], credentials: { ...document, email: 'untouched@example.test', chatgpt_account_id: 'untouched-account',
      chatgpt_user_id: 'untouched-user', access_token: secret(), refresh_token: secret() },
    credentials_status: { has_access_token: true, has_refresh_token: true, has_id_token: false } };
  const remote = [raw, extra]; const writes = []; const tested = []; const events = [];
  const counters = { phase3: 0, preflight: 0, fullBackups: 0 };
  const client = {
    baseUrl: 'http://127.0.0.1:9',
    listAccounts: async () => remote.map(safeAccount),
    getAccount: async id => {
      const value = remote.find(item => item.id === id);
      if (!value) throw Object.assign(new Error('fixture not found'), { code: 'SUB2API_REQUEST_REJECTED', upstreamStatus: 404 });
      return safeAccount(value);
    },
    listGroups: async () => [{ id: 1, name: 'share', status: 'active', platform: 'openai', subscription_type: 'standard' }],
    getBatchTableUsageStats: async () => ({ stats: {}, errors: {} }),
    exportAccounts: async ids => {
      const exported = { accounts: structuredClone(ids.length ? remote.filter(item => ids.includes(item.id)) : remote), proxies: [] };
      if (!ids.length) {
        counters.fullBackups += 1;
        if (options.quotaDuringBackup) raw.error_message = '{"error":{"code":"insufficient_quota"}}';
      }
      return exported;
    },
    applyOAuthCredentials: async (id, payload) => {
      writes.push({ action: 'update', id }); assert.equal(id, 47);
      raw.credentials = { ...raw.credentials, ...payload.credentials };
      return safeAccount(raw);
    },
    importCodexSession: async payload => {
      if (!options.allowCreates) throw new Error('maintenance must never create replacement accounts');
      assert.equal(payload.update_existing, false);
      const content = JSON.parse(payload.content);
      const id = Math.max(...remote.map(item => item.id)) + 1;
      remote.push({ id, name: payload.name, platform: 'openai', type: 'oauth', status: 'active', schedulable: true,
        group_ids: payload.group_ids, credentials: content, extra: payload.extra,
        credentials_status: { has_access_token: true, has_refresh_token: true, has_id_token: false } });
      writes.push({ action: 'create', id });
      return { total: 1, created: 1, updated: 0, skipped: 0, failed: 0,
        items: [{ index: 1, action: 'created', account_id: id }] };
    },
    testAccount: async (id, args) => {
      tested.push({ id, model: args.modelId }); if (!options.allowCreates) assert.equal(id, 47);
      if (options.testFails) return { success: false };
      const target = remote.find(item => item.id === id); target.status = 'active'; target.error_message = '';
      return { success: true };
    },
    setSchedulable: async (id, enabled) => {
      writes.push({ action: 'scheduler', id, enabled }); assert.equal(id, 47);
      raw.schedulable = enabled; return safeAccount(raw);
    },
    deleteAccount: async id => {
      writes.push({ action: 'delete', id }); assert.equal(id, 47);
      if (!options.deleteUnknown) remote.splice(remote.findIndex(item => item.id === id), 1);
      return { accountId: id, accepted: true };
    },
  };
  const saved = new Map();
  for (const [key, value] of Object.entries({
    GPT_REGISTER_ROOT: root, GPT_REGISTER_NODE_PATH: process.execPath,
    PANEL_DB_PATH: path.join(root, 'panel.sqlite3'), PANEL_BACKUP_DIR: path.join(root, 'backups'),
    PANEL_CONTROL_LOCK_PATH: path.join(root, 'control.lock'), PANEL_LOG_PATH: path.join(root, 'panel.log'),
    PANEL_REQUIRE_AUTH: '1', PANEL_ADMIN_TOKEN: admin, PANEL_WRITE_ENABLED: '1', PANEL_PHASE3_ENABLED: '1',
    PANEL_ALLOW_INSECURE_WRITE: '0', PANEL_ALLOW_UNBACKED_WRITES: '0', SUB2API_BASE_URL: client.baseUrl,
    SUB2API_ADMIN_API_KEY: secret(), SUB2API_GROUP_NAME: 'share',
  })) { saved.set(key, process.env[key]); process.env[key] = value; }
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  const logger = { info(event) { events.push(event); }, warn(event) { events.push(event); },
    error(event) { events.push(event); }, probe: () => true, checkpoint: () => true };
  const server = createServer({ db, logger, syncClientFactory: () => client, consoleOptions: {
    preflight: async () => {
      counters.preflight += 1;
      if (options.quotaBeforeRefresh) raw.error_message = '{"error":{"code":"insufficient_quota"}}';
      return { ok: true, channels: ['sms', 'mail', 'oauth'].map(id => ({ id, ok: true, code: 'OK' })) };
    },
    phase3Runner: async args => {
      counters.phase3 += 1;
      if (options.quotaAtExecution) raw.error_message = '{"error":{"code":"insufficient_quota"}}';
      return runPhase3Job(args);
    },
    ...options.consoleOptions,
  } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await shutdownServer(server);
    for (const [key, value] of saved) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    fs.rmSync(root, { recursive: true, force: true });
  });
  async function request(route, body, idempotencyKey = crypto.randomUUID()) {
    const response = await fetch('http://127.0.0.1:' + server.address().port + route, {
      ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
      headers: { 'x-panel-token': admin, 'content-type': 'application/json', 'idempotency-key': idempotencyKey },
      signal: AbortSignal.timeout(15000),
    });
    const value = await response.json();
    for (const secretValue of secrets) assert.equal(JSON.stringify(value).includes(secretValue), false, 'secret escaped API');
    return { status: response.status, body: value };
  }
  async function waitJob(id) {
    for (let i = 0; i < 1000; i++) {
      const value = await db.getJob(id);
      if (['succeeded', 'partial', 'failed', 'interrupted'].includes(value.status)) return value;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error('synthetic maintenance did not finish');
  }
  async function maintain(extra = {}) {
    const admitted = await request('/api/console/maintain', { accountIds: [47], importNew: false,
      refreshInvalid: true, deleteBanned: true, ...extra });
    assert.equal(admitted.status, 202);
    return waitJob(admitted.body.jobId);
  }
  function registrationOutput(overrides = {}) {
    const contents = JSON.stringify({ ...document, email: 'new-registration@example.test',
      chatgpt_account_id: 'new-registration-account', chatgpt_user_id: 'new-registration-user',
      access_token: secret(), refresh_token: secret(), ...overrides });
    const tokenFile = 'tokens/new-registration.json';
    fs.writeFileSync(path.join(root, tokenFile), contents, { mode: 0o600 });
    const selectedKey = 'token:tokens:' + tokenFile;
    return { completedCount: 1, selectedKeys: [selectedKey], artifacts: [{ selectedKey,
      contentHash: crypto.createHash('sha256').update(contents).digest('hex'),
      identityKeys: ['account:new-registration-account', 'user:new-registration-user'] }] };
  }
  return { root, db, raw, extra, remote, document, original, writes, tested, events, counters, client,
    request, maintain, waitJob, registrationOutput, tokenPath: path.join(root, relativePath) };
}

test('real maintenance chain reauthorizes once, updates original ID and restores scheduling only after a successful test', async t => {
  const f = await fixture(t);
  const untouched = JSON.stringify(f.extra);
  const job = await f.maintain();
  assert.equal(job.status, 'succeeded', job.error || job.result?.items?.[0]?.message);
  assert.equal(job.result.summary.refreshed, 1);
  assert.equal(f.counters.phase3, 1);
  assert.deepEqual(f.writes, [{ action: 'update', id: 47 }, { action: 'scheduler', id: 47, enabled: true }]);
  assert.deepEqual(f.tested, [{ id: 47, model: 'gpt-5.6-luna' }]);
  assert.equal(f.raw.status, 'active'); assert.equal(f.raw.schedulable, true);
  assert.equal(JSON.stringify(f.extra) === untouched, true, 'unselected remote account changed');
  const children = await Promise.all(job.result.childJobIds.map(id => f.db.getJob(id)));
  assert.deepEqual(children.map(child => [child.type, child.status]), [['phase3', 'succeeded'], ['token_import', 'succeeded'], ['account_test', 'succeeded']]);
  for (let i = 1; i < children.length; i++) assert.ok(children[i - 1].finishedAt <= children[i].startedAt);
  assert.equal((await f.db.listAccountLifecycles(managementEndpointKey(f.client.baseUrl))).filter(row => row.state === 'imported').length, 2);
});

for (const change of ['quotaBeforeRefresh', 'quotaAtExecution', 'quotaDuringBackup']) {
  test('late quota change prevents automatic writes: ' + change, async t => {
    const f = await fixture(t, { [change]: true });
    const before = fs.readFileSync(f.tokenPath, 'utf8');
    const job = await f.maintain();
    assert.equal(['partial', 'failed'].includes(job.status), true);
    assert.equal(job.result.summary.refreshed, 0);
    assert.deepEqual(f.writes, []); assert.deepEqual(f.tested, []);
    if (change !== 'quotaDuringBackup') assert.equal(fs.readFileSync(f.tokenPath, 'utf8') === before, true, 'login must not rewrite token');
    assert.equal(await f.db.countActiveJobs(), 0);
  });
}

test('failed test after credential update does not enable scheduling or report a refresh success', async t => {
  const f = await fixture(t, { testFails: true });
  const job = await f.maintain();
  assert.equal(job.status, 'partial'); assert.equal(job.result.summary.refreshed, 0);
  assert.deepEqual(f.writes, [{ action: 'update', id: 47 }]);
  assert.equal(f.raw.status, 'error'); assert.equal(f.raw.schedulable, false);
});

test('real Phase3 terminal disposition plus prior strong local binding authorizes only the original remote deletion', async t => {
  const f = await fixture(t, { ban: true });
  const job = await f.maintain();
  assert.equal(job.status, 'succeeded', job.error || job.result?.items?.[0]?.message);
  assert.equal(job.result.summary.deleted, 1);
  assert.deepEqual(f.writes, [{ action: 'delete', id: 47 }]);
  assert.deepEqual(f.remote.map(item => item.id), [99]);
  assert.equal((await f.db.listAccountLifecycles(managementEndpointKey(f.client.baseUrl))).filter(row => row.state === 'deleted').length, 2);
});

test('a ban while logging into an email-only local candidate cannot authorize remote deletion', async t => {
  const f = await fixture(t, { ban: true, noLocalToken: true });
  const job = await f.maintain();
  assert.equal(job.status, 'partial'); assert.equal(job.result.summary.deleted, 0);
  assert.deepEqual(f.writes, []); assert.equal(f.remote.length, 2);
  assert.equal(await f.db.countActiveJobs(), 0);
});

test('unknown delete result keeps a permanent tombstone and blocks subsequent pipeline admission', async t => {
  const f = await fixture(t, { ban: true, deleteUnknown: true });
  const job = await f.maintain();
  assert.equal(job.status, 'failed'); assert.equal(job.result.requiresReconciliation, true);
  assert.equal((await f.db.listAccountLifecycles(managementEndpointKey(f.client.baseUrl))).filter(row => row.state === 'delete_pending').length, 2);
  const next = await f.request('/api/console/maintain', { accountIds: [47], importNew: false, refreshInvalid: true, deleteBanned: true });
  assert.equal(next.status, 409);
  assert.equal(f.writes.filter(item => item.action === 'delete').length, 1);
});

test('a new token with the wrong strong identity cannot be imported or turned into a replacement account', async t => {
  const f = await fixture(t, { wrongOutputIdentity: true });
  const job = await f.maintain();
  assert.equal(['partial', 'failed'].includes(job.status), true);
  assert.deepEqual(f.writes, []); assert.deepEqual(f.tested, []);
  assert.equal(f.remote.length, 2);
});

test('partial registration imports and verifies already completed artifacts without renting replacements', async t => {
  let f; let registrations = 0;
  f = await fixture(t, { allowCreates: true, consoleOptions: { registrar: async ({ options }) => {
    registrations += 1; assert.equal(options.count, 3);
    throw Object.assign(new Error('fixture registration stopped at an existing account'), {
      code: 'REGISTRATION_INCOMPLETE', details: { requestedCount: 3, ...f.registrationOutput(), nextAction: 'resume_phase2' },
    });
  } } });
  const admitted = await f.request('/api/console/register', { count: 3, country: 'US', operator: '', autoImport: true });
  assert.equal(admitted.status, 202);
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'partial', job.error || job.result?.code);
  assert.equal(job.result.summary.registered, 1); assert.equal(job.result.summary.imported, 1);
  assert.equal(job.result.nextAction, 'resume_phase2');
  assert.equal(registrations, 1);
  assert.deepEqual(f.writes, [{ action: 'create', id: 100 }]);
  assert.deepEqual(f.tested.map(item => item.id), [100]);
});

test('a partial registration with unconfirmed filesystem outcome never auto-imports its artifacts', async t => {
  let f;
  f = await fixture(t, { allowCreates: true, consoleOptions: { registrar: async () => {
    throw Object.assign(new Error('fixture unconfirmed output'), { code: 'REGISTRATION_OUTPUT_INVALID',
      requiresReconciliation: true, writeOutcomeUnknown: true, details: f.registrationOutput() });
  } } });
  const admitted = await f.request('/api/console/register', { count: 2, country: 'US', autoImport: true });
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'failed'); assert.equal(job.result.requiresReconciliation, true);
  assert.deepEqual(f.writes, []);
});

test('resume pipeline calls only the resume engine and imports its verified output once', async t => {
  let f; let resumed = 0;
  f = await fixture(t, { allowCreates: true, consoleOptions: {
    registrar: async () => { throw new Error('resume must never rent a new number'); },
    resumer: async ({ target }) => {
      resumed += 1; assert.equal(target.selectedKey, 'registration:accounts:0');
      assert.equal(target.revision, 'fixture-revision'); return { requestedCount: 1, ...f.registrationOutput() };
    },
  } });
  const body = { selectedKey: 'registration:accounts:0', revision: 'fixture-revision', autoImport: true };
  const key = crypto.randomUUID();
  const admitted = await f.request('/api/console/register/resume', body, key);
  assert.equal(admitted.status, 202);
  const job = await f.waitJob(admitted.body.jobId);
  assert.equal(job.status, 'succeeded', job.error || job.result?.code);
  assert.equal(job.type, 'console_resume'); assert.equal(job.result.summary.imported, 1);
  const replay = await f.request('/api/console/register/resume', body, key);
  assert.equal(replay.body.jobId, admitted.body.jobId); assert.equal(resumed, 1);
  assert.deepEqual(f.writes, [{ action: 'create', id: 100 }]);
});

for (const planType of ['plus', undefined]) {
  test('verified registration artifact with ' + (planType || 'unknown') + ' plan never becomes a Free account', async t => {
    let f;
    f = await fixture(t, { allowCreates: true, consoleOptions: {
      registrar: async () => f.registrationOutput({ plan_type: planType }),
    } });
    const admitted = await f.request('/api/console/register', { count: 1, country: 'US', autoImport: true });
    assert.equal(admitted.status, 202);
    const job = await f.waitJob(admitted.body.jobId);
    assert.equal(job.status, 'failed'); assert.equal(job.result.code, 'CONSOLE_TOKEN_PLAN_INVALID');
    assert.deepEqual(f.writes, []); assert.deepEqual(f.tested, []);
    assert.equal(f.remote.length, 2);
  });
}
