'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
require('./test-isolation');

const { createServer, shutdownServer, reconciliationReviewDetail, requestLogPath } = require('../backend/server');
const { PanelDb, RECONCILIATION_ACK_CONFIRMATION } = require('../backend/db');
const ADMIN = 'local-api-fixture-administrator';
const EMAIL = 'local-api@example.test';
const logger = {
  info() {}, warn() {}, error() {}, probe() { return true; }, checkpoint() { return true; },
  requestId() { return 'local-phase3-api-test'; },
};

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-local-phase3-api-'));
  fs.mkdirSync(path.join(root, 'tokens'), { mode: 0o700 });
  fs.mkdirSync(path.join(root, 'use_token'), { mode: 0o700 });
  const usernameFile = path.join(root, 'username.json');
  fs.writeFileSync(usernameFile, JSON.stringify([
    { email: EMAIL, password: 'local-api-fixture-password', status: 'oauth_done' },
  ]), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `if (!process.argv.includes('--email=${EMAIL}')) throw new Error('wrong local target');`,
    "fs.writeFileSync(path.join(process.cwd(), 'tokens', 'api-result.json'), JSON.stringify({",
    `email: '${EMAIL}', chatgpt_account_id: 'local-api-account', chatgpt_user_id: 'local-api-user',`,
    "access_token: 'local-api-fixture-access', refresh_token: 'local-api-fixture-refresh',",
    "expires_at: new Date(Date.now() + 3600000).toISOString() }), { mode: 0o600 });",
  ].join('\n'), { mode: 0o600 });
  const previous = {};
  for (const [key, value] of Object.entries({
    GPT_REGISTER_ROOT: root, GPT_REGISTER_NODE_PATH: process.execPath,
    PANEL_REQUIRE_AUTH: '1', PANEL_ADMIN_TOKEN: ADMIN, PANEL_PHASE3_ENABLED: '1',
    PANEL_WRITE_ENABLED: '1', PANEL_ALLOW_INSECURE_WRITE: '0',
    PANEL_DB_PATH: path.join(root, 'panel.sqlite3'),
    PANEL_CONTROL_LOCK_PATH: path.join(root, 'control-plane.lock'),
  })) {
    previous[key] = process.env[key];
    process.env[key] = value;
  }
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  const server = createServer({ db, logger });
  t.after(async () => {
    await shutdownServer(server);
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const base = 'http://127.0.0.1:' + server.address().port;
  async function request(route, options = {}) {
    const response = await fetch(base + route, {
      ...options,
      headers: { 'x-panel-token': ADMIN, ...options.headers },
      signal: AbortSignal.timeout(10000),
    });
    const body = await response.json();
    return { status: response.status, headers: response.headers, body };
  }
  async function post(route, body, id = 'fixture_' + crypto.randomUUID(), headers = {}) {
    return request(route, { method: 'POST', headers: {
      'content-type': 'application/json', 'idempotency-key': id, ...headers,
    }, body: JSON.stringify(body) });
  }
  async function selection() {
    const listing = await request('/api/phase3/local-accounts');
    assert.equal(listing.status, 200);
    const target = listing.body.accounts.find((item) => item.eligible);
    assert.ok(target);
    return { accounts: [{
      email: target.email, phone: target.phone || '', selectedKey: target.selectedKey,
      phase3TargetRevision: target.phase3TargetRevision,
    }], selectedKeys: [target.selectedKey] };
  }
  return { root, usernameFile, db, server, request, post, selection };
}

test('local Phase3 API has authenticated listing, exact methods, JSON and write admission', async (t) => {
  const { request, post, selection } = await fixture(t);
  const unauthorized = await request('/api/phase3/local-accounts', { headers: { 'x-panel-token': '' } });
  assert.equal(unauthorized.status, 401);
  const listing = await request('/api/phase3/local-accounts');
  assert.equal(listing.status, 200);
  assert.deepEqual(listing.body.summary, { total: 1, eligible: 1, ineligible: 0 });
  assert.equal(listing.body.readOnly, false);
  assert.equal(listing.body.capabilities.phase3Enabled, true);
  assert.doesNotMatch(JSON.stringify(listing.body), /local-api-fixture-password|contentHash|executionBinding/);
  for (const [route, method, allowed] of [
    ['/api/phase3/local', 'GET', 'POST'],
    ['/api/phase3/local-accounts', 'POST', 'GET'],
  ]) {
    const response = await request(route, { method });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get('allow'), allowed);
    assert.equal(requestLogPath(route), route);
  }
  const body = await selection();
  assert.equal((await post('/api/phase3/local', body, undefined, { 'content-type': 'text/plain' })).status, 415);
  process.env.PANEL_WRITE_ENABLED = '0';
  assert.equal((await post('/api/phase3/local', body)).status, 403);
});

test('local Phase3 API rejects mixed selection domains, forged revisions and batches above 100', async (t) => {
  const { post, selection, db } = await fixture(t);
  const body = await selection();
  const tokenBody = { accounts: [{ ...body.accounts[0], selectedKey: 'token:tokens:tokens/local.json',
    phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43) }], selectedKeys: ['token:tokens:tokens/local.json'] };
  assert.equal((await post('/api/phase3/local', tokenBody)).status, 400);
  assert.equal((await post('/api/phase3', body)).status, 400);
  const wrongRevision = { ...body, accounts: [{ ...body.accounts[0],
    phase3TargetRevision: 'phase3-local-v1.' + 'A'.repeat(43) }] };
  const denied = await post('/api/phase3/local', wrongRevision);
  assert.equal(denied.status, 409);
  assert.equal(denied.body.rejected[0].error, 'phase3_target_revision_changed');
  assert.equal((await post('/api/phase3/local', {
    accounts: Array(101).fill(body.accounts[0]), selectedKeys: Array(101).fill(body.selectedKeys[0]),
  })).status, 400);
  assert.equal((await db.listJobs(20)).length, 0);
});

test('local Phase3 HTTP submission produces a bound job, redacted review context and replay after changes', async (t) => {
  const { post, request, selection, db, usernameFile } = await fixture(t);
  const body = await selection();
  const key = 'local_api_replay_' + crypto.randomUUID();
  const submitted = await post('/api/phase3/local', body, key);
  assert.equal(submitted.status, 202);
  assert.equal(submitted.body.jobIds.length, 1);
  const id = submitted.body.jobIds[0];
  let job;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    job = (await request('/api/jobs/' + id)).body;
    if (['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)) break;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(job.status, 'succeeded', JSON.stringify(job.result));
  assert.equal(job.payload.sourceMode, 'username');
  assert.equal(job.payload.usernameIndex, 0);
  assert.equal(job.payload.sourcePath, null);
  assert.doesNotMatch(JSON.stringify(job), /local-api-fixture-password|local-api-fixture-access|executionBinding/);
  const persisted = await db.getJob(id);
  const detail = reconciliationReviewDetail({ ...persisted, status: 'failed', result: {
    requiresReconciliation: true, reconciliationHold: true,
    reconciliationResolved: false, reconciliationClaimDigest: 'a'.repeat(64),
  } });
  assert.deepEqual(detail.targetContext.targets[0], {
    sourceMode: 'username', usernameIndex: 0, email: EMAIL, phone: undefined,
    phase3TargetRevision: body.accounts[0].phase3TargetRevision,
  });
  fs.writeFileSync(usernameFile, JSON.stringify([{ email: EMAIL, password: 'changed-local-fixture' }]));
  process.env.PANEL_PHASE3_ENABLED = '0';
  const replayed = await post('/api/phase3/local', body, key);
  assert.equal(replayed.status, 202);
  assert.equal(replayed.headers.get('idempotency-replayed'), 'true');
  assert.deepEqual(replayed.body, submitted.body);
  assert.equal((await db.listJobs(20)).length, 1);
});

test('local Phase3 shares token workflow claims and never starts a duplicate account', async (t) => {
  const { db, post, selection } = await fixture(t);
  const body = await selection();
  await db.createJob('phase3', { email: EMAIL }, 'panel-admin', {
    claimKeys: ['phase3:email:' + EMAIL],
  });
  const result = await post('/api/phase3/local', body);
  assert.equal(result.status, 409);
  assert.equal(result.body.rejected[0].error, 'phase3_already_running');
  assert.equal((await db.listJobs(20)).length, 1);
});

test('local Phase3 durable review requires exact source mode, index, revision domain and digest', () => {
  const payload = {
    sourceMode: 'username', usernameIndex: 0, email: EMAIL, phone: null,
    canonicalKeys: ['email:' + EMAIL], sourcePath: null,
    selectedKeyDigest: crypto.createHash('sha256')
      .update('gpt-register-panel/phase3-local-selected-key/v1\0').update('username:0').digest('hex'),
    phase3TargetRevision: 'phase3-local-v1.' + 'A'.repeat(43),
  };
  const base = { id: 'job_' + '7'.repeat(24), type: 'phase3', status: 'failed', payload,
    result: { requiresReconciliation: true, reconciliationHold: true,
      reconciliationResolved: false, reconciliationClaimDigest: '7'.repeat(64) } };
  assert.equal(reconciliationReviewDetail(base).targetContext.available, true);
  for (const patch of [
    { sourceMode: 'token' }, { sourceMode: undefined }, { sourceMode: 'unknown' },
    { usernameIndex: 1 }, { usernameIndex: '0' }, { usernameIndex: -1 },
    { selectedKeyDigest: 'b'.repeat(64) }, { sourcePath: 'tokens/other.json' },
    { phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43) },
  ]) {
    assert.throws(() => reconciliationReviewDetail({ ...base, payload: { ...payload, ...patch } }),
      (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE');
  }
});

test('local Phase3 hold survives database reopen and can only be acknowledged with its reviewed context', async (t) => {
  const { root, db, server, selection } = await fixture(t);
  const selected = (await selection()).accounts[0];
  const held = await db.createJob('phase3', {
    sourceMode: 'username', usernameIndex: 0, email: EMAIL, phone: null,
    canonicalKeys: ['email:' + EMAIL], sourcePath: null,
    selectedKeyDigest: crypto.createHash('sha256')
      .update('gpt-register-panel/phase3-local-selected-key/v1\0')
      .update(selected.selectedKey).digest('hex'),
    phase3TargetRevision: selected.phase3TargetRevision,
  }, 'panel-admin', { claimKeys: ['phase3:email:' + EMAIL] });
  await db.updateJob(held.id, { status: 'failed', result: {
    requiresReconciliation: true, writeOutcomeUnknown: true,
  }, finishedAt: new Date().toISOString() });
  await shutdownServer(server);
  const reopenedDb = new PanelDb(path.join(root, 'panel.sqlite3'));
  const reopenedServer = createServer({ db: reopenedDb, logger });
  try {
    await new Promise((resolve, reject) => {
      reopenedServer.once('error', reject);
      reopenedServer.listen(0, '127.0.0.1', resolve);
    });
    const base = 'http://127.0.0.1:' + reopenedServer.address().port;
    const read = async (route) => {
      const response = await fetch(base + route, { headers: { 'x-panel-token': ADMIN } });
      assert.equal(response.status, 200);
      return response.json();
    };
    assert.equal((await read('/api/jobs?limit=200')).reconciliationHolds.total, 1);
    const review = await read('/api/jobs/' + held.id + '/reconciliation');
    assert.equal(review.targetContext.targets[0].sourceMode, 'username');
    assert.equal(review.targetContext.targets[0].usernameIndex, 0);
    assert.doesNotMatch(JSON.stringify(review), /local-api-fixture-password|executionBinding|passwordDigest/);
    const body = { jobId: held.id, confirmation: RECONCILIATION_ACK_CONFIRMATION,
      resolution: 'state_manually_reconciled', claimDigest: review.reconciliationClaimDigest,
      contextDigest: review.reconciliationContextDigest };
    const acknowledge = async (value) => fetch(base + '/api/jobs/' + held.id + '/reconciliation/acknowledge', {
      method: 'POST', headers: { 'x-panel-token': ADMIN, 'content-type': 'application/json' },
      body: JSON.stringify(value),
    });
    const stale = await acknowledge({ ...body, contextDigest: 'b'.repeat(64) });
    assert.equal(stale.status, 409);
    await stale.arrayBuffer();
    assert.equal((await read('/api/jobs?limit=200')).reconciliationHolds.total, 1);
    const acknowledged = await acknowledge(body);
    assert.equal(acknowledged.status, 200);
    await acknowledged.arrayBuffer();
    assert.equal((await read('/api/jobs?limit=200')).reconciliationHolds.total, 0);
    assert.equal((await reopenedDb.getJob(held.id)).result.reconciliationResolved, true);
  } finally {
    await shutdownServer(reopenedServer);
  }
});
