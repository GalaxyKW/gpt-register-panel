'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
require('./test-isolation');
const { createServer, shutdownServer, reconciliationReviewDetail } = require('../backend/server');
const { PanelDb } = require('../backend/db');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { accountTestTargetRevision, createAccountTargetRevisionIssuer } = require('../backend/accountTargetRevision');

const EMAIL = 'remote-phase3-api@example.test';
const logger = {
  info() {}, warn() {}, error() {}, probe() { return true; }, checkpoint() { return true; },
  requestId() { return 'remote-phase3-api-test'; },
};

async function fixture(t) {
  // Entirely synthetic runtime material; no deployment config or real account
  // data is read. Never print these values, including in assertion failures.
  const synthetic = () => crypto.randomBytes(24).toString('hex');
  const admin = synthetic();
  const password = synthetic();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-remote-phase3-api-'));
  for (const name of ['tokens', 'use_token', 'backups']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: EMAIL, password, status: 'oauth_done' },
  ]), { mode: 0o600 });
  const outputDocument = {
    email: EMAIL, chatgpt_account_id: 'fixture-remote-account', chatgpt_user_id: 'fixture-remote-user',
    access_token: synthetic(), refresh_token: synthetic(), expires_at: '2099-01-01T00:00:00.000Z',
  };
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    `if (!process.argv.includes('--email=${EMAIL}')) throw new Error('wrong local record');`,
    `fs.writeFileSync('tokens/result.json', JSON.stringify(${JSON.stringify(outputDocument)}), {mode:0o600});`,
  ].join('\n'), { mode: 0o600 });
  const raw = {
    id: 124, name: 'free00011', platform: 'openai', type: 'oauth', status: 'error', schedulable: false,
    credentials: { ...outputDocument, access_token: synthetic(), refresh_token: synthetic() }, group_ids: [],
  };
  const writes = [];
  const client = {
    baseUrl: 'http://127.0.0.1:9',
    listAccounts: async () => [safeAccount(raw)],
    getAccount: async (id) => { assert.equal(id, raw.id); return safeAccount(raw); },
    getBatchTableUsageStats: async () => ({ stats: {}, errors: {} }),
    exportAccounts: async () => ({ accounts: [structuredClone(raw)] }),
    applyOAuthCredentials: async (id, payload) => {
      writes.push(id);
      assert.equal(id, 124);
      raw.credentials = { ...raw.credentials, ...payload.credentials };
    },
    importCodexSession: async () => { throw new Error('create must never run'); },
  };
  const saved = new Map();
  for (const [key, value] of Object.entries({
    GPT_REGISTER_ROOT: root, GPT_REGISTER_NODE_PATH: process.execPath,
    PANEL_REQUIRE_AUTH: '1', PANEL_ADMIN_TOKEN: admin, PANEL_PHASE3_ENABLED: '1',
    PANEL_WRITE_ENABLED: '1', PANEL_ALLOW_INSECURE_WRITE: '0',
    PANEL_DB_PATH: path.join(root, 'panel.sqlite3'), PANEL_BACKUP_DIR: path.join(root, 'backups'),
    PANEL_CONTROL_LOCK_PATH: path.join(root, 'control-plane.lock'),
    SUB2API_BASE_URL: 'http://127.0.0.1:9', SUB2API_ADMIN_API_KEY: synthetic(),
  })) { saved.set(key, process.env[key]); process.env[key] = value; }
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  const server = createServer({ db, logger, syncClientFactory: () => client });
  t.after(async () => {
    await shutdownServer(server);
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  async function request(route, body, key = crypto.randomUUID()) {
    const response = await fetch('http://127.0.0.1:' + server.address().port + route, {
      ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
      headers: { 'x-panel-token': admin, 'content-type': 'application/json', 'idempotency-key': key },
      signal: AbortSignal.timeout(10000),
    });
    return { status: response.status, headers: response.headers, body: await response.json() };
  }
  async function selection() {
    const listing = await request('/api/phase3/local-accounts');
    assert.equal(listing.status, 200);
    const local = listing.body.accounts[0];
    return { remoteMappingConfirmed: true, selectedKeys: [local.selectedKey], accounts: [{
      selectedKey: local.selectedKey, email: local.email, phone: local.phone || '',
      phase3TargetRevision: local.phase3TargetRevision,
      remoteTarget: { accountId: raw.id, targetRevision: accountTestTargetRevision(safeAccount(raw)) },
    }] };
  }
  async function waitJob(id) {
    for (let n = 0; n < 500; n += 1) {
      const job = (await request('/api/jobs/' + id)).body;
      if (['succeeded', 'failed', 'interrupted', 'partial'].includes(job.status)) return job;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error('fixture job did not complete');
  }
  const assertRedacted = (job) => {
    const text = JSON.stringify(job);
    for (const value of [admin, password, outputDocument.access_token, outputDocument.refresh_token]) {
      assert.equal(text.includes(value), false, 'job must not expose synthetic credential material');
    }
  };
  return { root, raw, client, writes, db, request, selection, waitJob, assertRedacted, synthetic };
}

test('remote Phase3 requires explicit mapping and current remote revision before admission', async (t) => {
  const f = await fixture(t);
  const body = await f.selection();
  assert.equal((await f.request('/api/phase3/local', { ...body, remoteMappingConfirmed: false })).status, 400);
  const forged = structuredClone(body);
  forged.accounts[0].remoteTarget.identityKeys = ['account:forged'];
  assert.equal((await f.request('/api/phase3/local', forged)).status, 400);
  f.raw.status = 'active';
  f.raw.schedulable = true;
  assert.equal((await f.request('/api/phase3/local', body)).status, 409);
  assert.equal((await f.db.listJobs(10)).length, 0);
  assert.equal(fs.existsSync(path.join(f.root, 'tokens/result.json')), false);
});

test('remote Phase3 binds original ID and successful output through scoped preview and import', async (t) => {
  const f = await fixture(t);
  const body = await f.selection();
  const key = crypto.randomUUID();
  const accepted = await f.request('/api/phase3/local', body, key);
  assert.equal(accepted.status, 202);
  assert.deepEqual(accepted.body.remoteTargets, [body.accounts[0].remoteTarget]);
  const id = accepted.body.jobIds[0];
  const job = await f.waitJob(id);
  assert.equal(job.status, 'succeeded');
  assert.equal(job.result.remoteTarget.accountId, 124);
  assert.equal(job.result.tokenSource, 'tokens');
  assert.match(job.result.tokenContentHash, /^[a-f0-9]{64}$/);
  f.assertRedacted(job);
  const persisted = await f.db.getJob(id);
  const review = reconciliationReviewDetail({ ...persisted, status: 'failed', result: {
    requiresReconciliation: true, reconciliationHold: true, reconciliationResolved: false,
    reconciliationClaimDigest: 'a'.repeat(64),
  } });
  assert.equal(review.targetContext.targets[0].remoteAccountId, 124);
  assert.deepEqual(review.targetContext.targets[0].remoteIdentityKeys,
    ['account:fixture-remote-account', 'user:fixture-remote-user']);
  const replay = await f.request('/api/phase3/local', body, key);
  assert.equal(replay.status, 202);
  assert.equal(replay.headers.get('idempotency-replayed'), 'true');
  const scoped = { selectedKeys: ['token:tokens:tokens/result.json'],
    remoteTargets: [body.accounts[0].remoteTarget], phase3JobIds: [id] };
  const preview = await f.request('/api/sync/preview', scoped);
  assert.equal(preview.status, 200);
  assert.equal(preview.body.counts.update, 1);
  assert.equal(preview.body.items.some((item) => item.action === 'create'), false);
  const imported = await f.request('/api/sync/import', { ...scoped,
    snapshotVersion: preview.body.version, planIntentVersion: preview.body.planIntentVersion });
  assert.equal(imported.status, 202);
  const importJob = await f.waitJob(imported.body.jobId);
  assert.equal(importJob.status, 'succeeded');
  assert.deepEqual(f.writes, [124]);
  assert.equal(f.raw.name, 'free00011');
  assert.equal(f.raw.status, 'error', 'import must not claim a successful account test');
});

test('scoped import rejects wrong ID, missing job bindings and changed output without writes', async (t) => {
  const f = await fixture(t);
  const body = await f.selection();
  const accepted = await f.request('/api/phase3/local', body);
  assert.equal(accepted.status, 202);
  const id = accepted.body.jobIds[0];
  assert.equal((await f.waitJob(id)).status, 'succeeded');
  const scoped = { selectedKeys: ['token:tokens:tokens/result.json'],
    remoteTargets: [body.accounts[0].remoteTarget], phase3JobIds: [id] };
  assert.equal((await f.request('/api/sync/preview', { ...scoped, phase3JobIds: [] })).status, 400);
  assert.equal((await f.request('/api/sync/preview', { ...scoped, remoteTargets: undefined })).status, 400);
  assert.equal((await f.request('/api/sync/preview', { ...scoped,
    remoteTargets: [{ ...scoped.remoteTargets[0], accountId: 999 }] })).status, 409);
  f.client.baseUrl = 'http://127.0.0.1:10';
  assert.equal((await f.request('/api/sync/preview', scoped)).status, 409,
    'same account state in a different Sub2API instance must not be trusted');
  f.client.baseUrl = 'http://127.0.0.1:9';
  const file = path.join(f.root, 'tokens/result.json');
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, JSON.stringify({ ...data, access_token: f.synthetic() }));
  assert.equal((await f.request('/api/sync/preview', scoped)).status, 409);
  assert.deepEqual(f.writes, []);
});

test('successful bound output can be reviewed across revision issuer restart but not remote changes', async (t) => {
  const f = await fixture(t);
  const selection = await f.selection();
  const submitted = await f.request('/api/phase3/local', selection);
  assert.equal(submitted.status, 202);
  const original = await f.waitJob(submitted.body.jobIds[0]);
  assert.equal(original.status, 'succeeded');
  // Represent a completed task signed by another process. Stable non-secret
  // targetDigest still proves that the exact reviewed remote state is current.
  const otherIssuer = createAccountTargetRevisionIssuer();
  const targetRevision = otherIssuer.issue(safeAccount(f.raw));
  const remoteTarget = { ...original.result.remoteTarget, targetRevision };
  const copied = await f.db.createJob('phase3', { ...original.payload, remoteTarget }, 'panel-admin');
  await f.db.updateJob(copied.id, { status: 'succeeded', result: { ...original.result, remoteTarget } });
  const scoped = { selectedKeys: ['token:tokens:tokens/result.json'],
    remoteTargets: [{ accountId: 124, targetRevision }], phase3JobIds: [copied.id] };
  assert.equal((await f.request('/api/sync/preview', scoped)).status, 200);
  f.raw.credentials.access_token = f.synthetic();
  assert.equal((await f.request('/api/sync/preview', scoped)).status, 409);
  assert.deepEqual(f.writes, []);
});
