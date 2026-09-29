'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
require('./test-isolation');
const { createServer, shutdownServer } = require('../backend/server');
const { PanelDb } = require('../backend/db');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { accountTestTargetRevision } = require('../backend/accountTargetRevision');

const logger = { info() {}, warn() {}, error() {}, probe() { return true; },
  checkpoint() { return true; }, requestId() { return 'identity-review-api-fixture'; } };

async function fixture(t, count = 1) {
  const synthetic = () => crypto.randomBytes(24).toString('hex');
  const admin = synthetic(), password = synthetic(), secrets = [admin, password];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-review-api-'));
  for (const name of ['tokens', 'use_token', 'backups']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  const rawAccounts = [], documents = [], selectedKeys = [], usernames = [];
  for (const id of [160, 174].slice(0, count)) {
    const data = { email: 'review-' + id + '@example.test',
      chatgpt_account_id: 'review-account-' + id, chatgpt_user_id: 'review-user-' + id,
      access_token: synthetic(), refresh_token: synthetic(), expires_at: '2099-01-01T00:00:00.000Z' };
    const relativePath = 'tokens/review-' + id + '.json';
    fs.writeFileSync(path.join(root, relativePath), JSON.stringify(data), { mode: 0o600 });
    const credentials = { ...data, access_token: synthetic(), refresh_token: synthetic() };
    delete credentials.chatgpt_account_id;
    rawAccounts.push({ id, name: 'free' + String(id).padStart(5, '0'), platform: 'openai',
      type: 'oauth', status: 'error', schedulable: false, group_ids: [], credentials });
    documents.push({ data, relativePath });
    selectedKeys.push('token:tokens:' + relativePath);
    usernames.push({ email: data.email, password, status: 'oauth_done' });
    secrets.push(data.access_token, data.refresh_token, credentials.access_token, credentials.refresh_token);
  }
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify(usernames), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), "throw new Error('unexpected Phase3 launch');\n", { mode: 0o600 });
  const writes = [], exports = [];
  let creates = 0;
  const client = {
    baseUrl: 'http://127.0.0.1:9',
    listAccounts: async () => rawAccounts.map(safeAccount),
    getAccount: async id => safeAccount(rawAccounts.find(account => account.id === id)),
    getBatchTableUsageStats: async () => ({ stats: {}, errors: {} }),
    exportAccounts: async () => {
      const backup = { accounts: structuredClone(rawAccounts), proxies: [] };
      exports.push(backup);
      return backup;
    },
    applyOAuthCredentials: async (id, payload) => {
      const account = rawAccounts.find(item => item.id === id);
      assert.equal(!!account, true, 'only an existing reviewed ID may be updated');
      writes.push(id);
      account.credentials = { ...account.credentials, ...payload.credentials };
    },
    importCodexSession: async () => { creates += 1; throw new Error('review must not create accounts'); },
  };
  const saved = new Map();
  for (const [key, value] of Object.entries({ GPT_REGISTER_ROOT: root,
    GPT_REGISTER_NODE_PATH: process.execPath, PANEL_REQUIRE_AUTH: '1', PANEL_ADMIN_TOKEN: admin,
    PANEL_PHASE3_ENABLED: '0', PANEL_WRITE_ENABLED: '1', PANEL_ALLOW_INSECURE_WRITE: '0',
    PANEL_ALLOW_UNBACKED_WRITES: '0', PANEL_DB_PATH: path.join(root, 'panel.sqlite3'),
    PANEL_BACKUP_DIR: path.join(root, 'backups'), PANEL_CONTROL_LOCK_PATH: path.join(root, 'control.lock'),
    SUB2API_BASE_URL: client.baseUrl, SUB2API_ADMIN_API_KEY: synthetic(),
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
  function assertRedacted(value) {
    const text = JSON.stringify(value);
    for (const secret of secrets) assert.equal(text.includes(secret), false, 'API must not expose fixture credentials');
  }
  async function request(route, body, key = crypto.randomUUID()) {
    const response = await fetch('http://127.0.0.1:' + server.address().port + route, {
      ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
      headers: { 'x-panel-token': admin, 'content-type': 'application/json', 'idempotency-key': key },
      signal: AbortSignal.timeout(10000),
    });
    const value = await response.json();
    assertRedacted(value);
    return { status: response.status, body: value, headers: response.headers };
  }
  async function reviewed() {
    const ordinary = await request('/api/sync/preview', { selectedKeys });
    assert.equal(ordinary.status, 200);
    assert.equal(ordinary.body.counts.conflict, count);
    const candidates = ordinary.body.identityCompletionCandidates;
    assert.equal(candidates.length, count);
    const identityCompletionTargets = candidates.map(({ selectedKey, accountId, targetRevision, sourceContentHash }) => (
      { selectedKey, accountId, targetRevision, sourceContentHash }
    ));
    const body = { selectedKeys, identityCompletionConfirmed: true, identityCompletionTargets };
    const preview = await request('/api/sync/preview', body);
    assert.equal(preview.status, 200);
    return { body, preview: preview.body, submit: { ...body, snapshotVersion: preview.body.version,
      planIntentVersion: preview.body.planIntentVersion } };
  }
  async function waitJob(id) {
    for (let i = 0; i < 500; i += 1) {
      const job = (await request('/api/jobs/' + id)).body;
      if (['succeeded', 'failed', 'interrupted', 'partial'].includes(job.status)) return job;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error('fixture import did not complete');
  }
  return { root, rawAccounts, documents, selectedKeys, db, client, writes, exports,
    creates: () => creates, synthetic, request, reviewed, waitJob };
}

test('explicit HTTP review previews admits backs up and updates only original user-only IDs once', async t => {
  const f = await fixture(t, 2);
  const r = await f.reviewed();
  assert.equal(r.preview.identityCompletionConfirmed, true);
  assert.deepEqual(r.preview.identityCompletionTargets.map(target => target.accountId), [160, 174]);
  assert.equal(r.preview.counts.update, 2);
  assert.equal(r.preview.items.every(item => item.identityCompletion === 'account_id'), true);
  assert.equal(Object.hasOwn(r.preview, 'remoteSourceBindings'), false);
  const reordered = await f.request('/api/sync/preview', { ...r.body,
    identityCompletionTargets: [...r.body.identityCompletionTargets].reverse() });
  assert.equal(reordered.status, 200);
  assert.deepEqual(reordered.body.identityCompletionTargets.map(target => target.accountId), [160, 174]);
  const key = crypto.randomUUID();
  const submitted = await f.request('/api/sync/import', r.submit, key);
  assert.equal(submitted.status, 202);
  const job = await f.waitJob(submitted.body.jobId);
  assert.equal(job.status, 'succeeded');
  assert.deepEqual([...f.writes].sort((a, b) => a - b), [160, 174]);
  assert.equal(f.creates(), 0);
  assert.equal(f.exports.length, 1);
  assert.equal(f.exports[0].accounts.every(account => !account.credentials.chatgpt_account_id), true,
    'backup must preserve the pre-completion identity rather than synthesizing it');
  assert.equal(fs.readdirSync(path.join(f.root, 'backups')).length > 0, true);
  assert.equal(f.rawAccounts.every(account => account.credentials.chatgpt_account_id
    === 'review-account-' + account.id), true);
  assert.equal(f.rawAccounts.every(account => account.status === 'error' && !account.schedulable), true,
    'credential update is not a successful usability test');
  const replay = await f.request('/api/sync/import', r.submit, key);
  assert.equal(replay.status, 202);
  assert.equal(replay.body.jobId, submitted.body.jobId);
  assert.equal(replay.headers.get('idempotency-replayed'), 'true');
  assert.equal(f.writes.length, 2, 'completed-state changes cannot trigger a duplicate import');
  const reused = await f.request('/api/sync/import', { ...r.submit,
    identityCompletionTargets: r.submit.identityCompletionTargets.map((target, i) => i
      ? target : { ...target, sourceContentHash: 'e'.repeat(64) }) }, key);
  assert.equal(reused.status, 409);
  assert.equal(f.writes.length, 2);
});

test('HTTP review rejects missing confirmation mixed workflows and client-provided authority', async t => {
  const f = await fixture(t);
  const r = await f.reviewed();
  const missing = { ...r.body };
  delete missing.identityCompletionConfirmed;
  const invalid = [missing, { ...r.body, identityCompletionConfirmed: false },
    { ...r.body, remoteTargets: [] }, { ...r.body, phase3JobIds: [] },
    { ...r.body, remoteSourceBindings: [] }, { ...r.body, remoteSourceHashes: [] },
    { ...r.body, remoteTargetBaselines: [] }, { ...r.body, targetDigest: 'f'.repeat(64) }];
  for (const body of invalid) {
    assert.equal((await f.request('/api/sync/preview', body)).status, 400);
    assert.equal((await f.request('/api/sync/import', { ...body,
      snapshotVersion: r.preview.version, planIntentVersion: r.preview.planIntentVersion })).status, 400);
  }
  const ordinary = await f.request('/api/sync/preview', { selectedKeys: f.selectedKeys,
    remoteSourceBindings: [{ accountId: 160, identityCompletion: 'account_id' }] });
  assert.equal(ordinary.status, 200);
  assert.equal(ordinary.body.counts.conflict, 1, 'ordinary request-body flags carry no authority');
  assert.deepEqual(f.writes, []);
  assert.equal((await f.db.listJobs(20)).length, 0);
});

test('HTTP review rejects mismatched content hash signed target and stale snapshot without writes', async t => {
  const f = await fixture(t);
  const r = await f.reviewed();
  const differentRevision = accountTestTargetRevision(safeAccount({ ...f.rawAccounts[0], id: 999 }));
  for (const change of [{ sourceContentHash: 'e'.repeat(64) }, { targetRevision: differentRevision },
    { accountId: 999 }]) {
    const body = { ...r.body, identityCompletionTargets: [{ ...r.body.identityCompletionTargets[0], ...change }] };
    assert.equal((await f.request('/api/sync/preview', body)).status, 409);
    assert.equal((await f.request('/api/sync/import', { ...body,
      snapshotVersion: r.preview.version, planIntentVersion: r.preview.planIntentVersion })).status, 409);
  }
  assert.equal((await f.request('/api/sync/import', { ...r.submit, snapshotVersion: 'd'.repeat(64) })).status, 409);
  f.rawAccounts[0].status = 'active';
  f.rawAccounts[0].schedulable = true;
  assert.equal((await f.request('/api/sync/preview', r.body)).status, 409);
  assert.equal((await f.request('/api/sync/import', r.submit)).status, 409);
  assert.deepEqual(f.writes, []);
  assert.equal((await f.db.listJobs(20)).length, 0);
});

test('HTTP review cannot cross-map selected files or create a missing remote target', async t => {
  const f = await fixture(t, 2);
  const r = await f.reviewed();
  const [a, b] = r.body.identityCompletionTargets;
  const crossed = { ...r.body, identityCompletionTargets: [
    { ...a, accountId: b.accountId, targetRevision: b.targetRevision },
    { ...b, accountId: a.accountId, targetRevision: a.targetRevision },
  ] };
  assert.equal((await f.request('/api/sync/preview', crossed)).status, 409);
  assert.equal((await f.request('/api/sync/import', { ...crossed,
    snapshotVersion: r.preview.version, planIntentVersion: r.preview.planIntentVersion })).status, 409);
  f.rawAccounts.splice(0, 1);
  assert.equal((await f.request('/api/sync/preview', r.body)).status, 409);
  assert.equal((await f.request('/api/sync/import', r.submit)).status, 409);
  assert.deepEqual(f.writes, []);
  assert.equal(f.creates(), 0);
});

test('HTTP review refuses changed local output after preview instead of accepting old confirmation', async t => {
  const f = await fixture(t);
  const r = await f.reviewed();
  const document = f.documents[0];
  fs.writeFileSync(path.join(f.root, document.relativePath), JSON.stringify({ ...document.data,
    access_token: f.synthetic() }), { mode: 0o600 });
  assert.equal((await f.request('/api/sync/preview', r.body)).status, 409);
  assert.equal((await f.request('/api/sync/import', r.submit)).status, 409);
  assert.deepEqual(f.writes, []);
  assert.equal(f.creates(), 0);
});
