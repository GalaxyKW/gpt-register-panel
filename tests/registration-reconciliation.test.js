'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { PanelDb, RECONCILIATION_ACK_CONFIRMATION } = require('../backend/db');
const { createServer, reconciliationReviewDetail } = require('../backend/server');
const review = require('../backend/registrationReconciliation');
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const emptySummary = () => Object.fromEntries(['registered', 'imported', 'refreshed', 'deleted', 'skipped', 'failed',
  'tokensGenerated', 'tokensUpdated', 'tested', 'verified', 'testFailed'].map(key => [key, 0]));

const verification = { originalRoot: 'manually_verified', processTree: 'verified_stopped',
  localRecords: 'reviewed_preserved', remoteImport: 'not_reached', smsStatus: 'cancelled',
  smsSettlement: 'unknown', providerEvidenceDigest: digest('supplier terminal without refund proof'),
  originalRunEvidenceDigest: digest('original run bound manually'), orderIdDigest: digest('synthetic order'),
  originalProcess: { pid: 999999991, pgid: 999999991, profile: 'gpt-register-panel-phase3-testNoProcess' } };
function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-registration-reconcile-'));
  const rootDirectory = path.join(directory, 'engine'); const evidenceDirectory = path.join(directory, 'evidence');
  const processRoot = path.join(directory, 'proc');
  fs.mkdirSync(rootDirectory, { mode: 0o700 }); fs.mkdirSync(evidenceDirectory, { mode: 0o700 }); fs.mkdirSync(processRoot);
  fs.writeFileSync(path.join(rootDirectory, 'accounts.json'), '[]');
  fs.writeFileSync(path.join(rootDirectory, 'username.json'), '[]');
  fs.writeFileSync(path.join(rootDirectory, 'sms-activations.json'), '[{"state":"settlement_pending"}]');
  return { directory, rootDirectory, evidenceDirectory, processRoot };
}
function fakeJobs() {
  const parent = 'job_' + 'a'.repeat(24); const child = 'job_' + 'b'.repeat(24);
  return [
    { id: parent, type: 'console_register', payload: { count: 1 }, result: { code: 'REGISTRATION_TERMINATION_UNCONFIRMED', childJobIds: [child], items: [], summary: emptySummary() } },
    { id: child, type: 'registration', payload: { count: 1, parentJobId: parent }, result: { code: 'REGISTRATION_TERMINATION_UNCONFIRMED' } },
  ].map((job, index) => ({ ...job, status: 'failed', claimKeys: [index ? 'registration' : 'console_pipeline'],
    reconciliationScope: 'claims', reconciliationClaimDigest: digest('claim' + index), reconciliationHold: true,
    result: { ...job.result, requiresReconciliation: true, reconciliationHold: true,
      reconciliationClaimDigest: digest('claim' + index), reconciliationHoldScope: 'claim_keys', reconciliationBlockScope: 'all_mutating_operations' } }));
}
function prepare(fx, jobs = fakeJobs()) {
  const evidence = review.buildRegistrationEvidence({ jobs, rootDirectory: fx.rootDirectory, processRoot: fx.processRoot, verification });
  const file = review.writeRegistrationEvidence(evidence, fx.evidenceDirectory);
  return { jobs, evidence, file };
}
function detail(fx, jobs, index = 0) {
  return reconciliationReviewDetail(jobs[index], { registrationReviewJobs: jobs, registrationReviewOptions: fx });
}
test('historical registration review explicitly binds reconstructed evidence and unknown fees without modifying journal', () => {
  const fx = fixture();
  try {
    const before = fs.readFileSync(path.join(fx.rootDirectory, 'sms-activations.json'));
    const { jobs } = prepare(fx); const output = detail(fx, jobs);
    assert.equal(output.targetContext.targets[0].evidenceMode, 'manual_reconstructed');
    assert.equal(output.targetContext.targets[0].smsSettlement, 'unknown');
    assert.equal(output.targetContext.targets[0].remoteImport, 'not_reached');
    assert.deepEqual(fs.readFileSync(path.join(fx.rootDirectory, 'sms-activations.json')), before);
    assert.doesNotMatch(JSON.stringify(output), /settlement_pending|accounts\.json|synthetic order/);
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
test('missing evidence never permits acknowledgement', () => {
  const fx = fixture(); try {
    assert.throws(() => detail(fx, fakeJobs()), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
    fs.rmdirSync(fx.evidenceDirectory);
    assert.throws(() => detail(fx, fakeJobs()), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
  }
  finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
for (const [name, mutate] of [
  ['expired evidence', (evidence) => { evidence.checkedAt = '2020-01-01T00:00:00.000Z'; evidence.expiresAt = '2020-01-02T00:00:00.000Z'; }],
  ['future evidence', (evidence) => { evidence.checkedAt = '2099-01-01T00:00:00.000Z'; evidence.expiresAt = '2099-01-02T00:00:00.000Z'; }],
  ['active SMS order', (evidence) => { evidence.verification.smsStatus = 'active'; }],
  ['missing supplier evidence', (evidence) => { delete evidence.verification.providerEvidenceDigest; }],
  ['changed original root', (evidence) => { evidence.root.inode = '0'; }],
  ['forged other task', (evidence) => { evidence.jobs[1].id = 'job_' + 'c'.repeat(24); }],
  ['import not inspected', (evidence) => { evidence.verification.remoteImport = 'unknown'; }],
]) test(name + ' fails closed', () => {
  const fx = fixture(); try {
    const { jobs, evidence, file } = prepare(fx); mutate(evidence); fs.writeFileSync(file, JSON.stringify(evidence));
    assert.throws(() => detail(fx, jobs), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
for (const relative of ['accounts.json', 'username.json', 'sms-activations.json', 'config.json', 'tokens/new.json']) {
  test('local changes invalidate review: ' + relative, () => {
    const fx = fixture(); try {
      const { jobs } = prepare(fx); fs.mkdirSync(path.dirname(path.join(fx.rootDirectory, relative)), { recursive: true });
      fs.writeFileSync(path.join(fx.rootDirectory, relative), '{"changed":true}');
      assert.throws(() => detail(fx, jobs), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
    } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
  });
}
test('evidence file permissions, symlinks and existing evidence overwrite are rejected', () => {
  const fx = fixture(); try {
    const { jobs, evidence, file } = prepare(fx);
    assert.throws(() => review.writeRegistrationEvidence(evidence, fx.evidenceDirectory));
    fs.chmodSync(file, 0o644); assert.throws(() => detail(fx, jobs)); fs.chmodSync(file, 0o600);
    const other = file + '.copy'; fs.renameSync(file, other); fs.symlinkSync(other, file);
    assert.throws(() => detail(fx, jobs));
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
for (const relative of ['state-transactions', 'token-transactions', '.token-transactions', '.state-transactions', '.panel-quarantine']) {
  test('a new recovery or quarantine directory invalidates prior evidence: ' + relative, () => {
    const fx = fixture(); try {
      const { jobs } = prepare(fx);
      fs.mkdirSync(path.join(fx.rootDirectory, relative));
      assert.throws(() => detail(fx, jobs), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
    } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
  });
  test('a changed recovery or quarantine manifest invalidates prior evidence: ' + relative, () => {
    const fx = fixture(); try {
      const directory = path.join(fx.rootDirectory, relative);
      fs.mkdirSync(directory); const file = path.join(directory, 'synthetic-manifest.json');
      fs.writeFileSync(file, '{"version":1,"entries":[]}');
      const { jobs } = prepare(fx);
      fs.writeFileSync(file, '{"version":1,"entries":[{"pending":true}]}');
      assert.throws(() => detail(fx, jobs), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
    } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
  });
}
test('a different child, original result or claim cannot reuse reconstructed evidence', () => {
  const fx = fixture(); try {
    const { jobs } = prepare(fx);
    for (const mutate of [copy => { copy[1].payload.parentJobId = 'job_' + 'c'.repeat(24); },
      copy => { copy[1].result.unexpectedField = true; }, copy => { copy[1].claimKeys = ['registration:other']; },
      copy => { copy[0].result.childJobIds.push('job_' + 'c'.repeat(24)); }]) {
      const copy = structuredClone(jobs); mutate(copy); assert.throws(() => detail(fx, copy));
    }
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
test('project lease is exclusive, does not remove preexisting locks and cleans only its own lock', async () => {
  const fx = fixture(); const lock = path.join(fx.rootDirectory, '.registration.lock');
  try {
    fs.writeFileSync(lock, 'original');
    await assert.rejects(review.withRegistrationProjectLock(fx.rootDirectory, () => assert.fail(), fx));
    assert.equal(fs.readFileSync(lock, 'utf8'), 'original'); fs.unlinkSync(lock);
    await review.withRegistrationProjectLock(fx.rootDirectory, async () => {
      assert.equal(JSON.parse(fs.readFileSync(lock)).pid, process.pid);
      await assert.rejects(review.withRegistrationProjectLock(fx.rootDirectory, () => assert.fail(), fx));
    }, fx);
    assert.equal(fs.existsSync(lock), false);
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
for (const [name, options] of [
  ['original pid', { pid: verification.originalProcess.pid, command: 'unrelated', group: 123 }],
  ['original group', { pid: 991992993, command: 'unrelated', group: verification.originalProcess.pgid }],
  ['original profile', { pid: 991992993, command: '/chrome\0--user-data-dir=/tmp/' + verification.originalProcess.profile, group: 123 }],
  ['other panel profile with merged argv', { pid: 991992993, command: '/chrome --user-data-dir=/tmp/gpt-register-panel-phase3-anotherProfile --flag ', group: 123 }],
  ['node rooted in registration project', { pid: 991992993, command: '/usr/bin/node\0index.js', group: 123, rootCwd: true }],
]) test('live process detection rejects ' + name, () => {
  const fx = fixture(); try {
    const { jobs } = prepare(fx); const directory = path.join(fx.processRoot, String(options.pid)); fs.mkdirSync(directory);
    fs.writeFileSync(path.join(directory, 'stat'), options.pid + ' (synthetic) S 1 ' + options.group + ' 0 0');
    fs.writeFileSync(path.join(directory, 'cmdline'), options.command);
    fs.symlinkSync(options.rootCwd ? fx.rootDirectory : fx.directory, path.join(directory, 'cwd'));
    assert.throws(() => detail(fx, jobs), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
test('a missing source appearing during traversal cannot produce an apparently complete snapshot', () => {
  const fx = fixture(); const originalRead = fs.readSync; const target = path.join(fx.rootDirectory, 'accounts.json');
  try {
    fs.unlinkSync(target); let changed = false;
    fs.readSync = function (...args) {
      const count = originalRead.apply(this, args);
      if (!changed) { changed = true; fs.writeFileSync(target, '[]'); }
      return count;
    };
    assert.throws(() => review.localSnapshot(fx.rootDirectory), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
  } finally { fs.readSync = originalRead; fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
test('a post-callback project-lock release failure is an unknown outcome, not a pre-write rejection', async () => {
  const fx = fixture();
  try {
    await assert.rejects(review.withRegistrationProjectLock(fx.rootDirectory, () => {
      fs.writeFileSync(path.join(fx.rootDirectory, '.registration.lock'), 'changed-owner');
    }, fx), { code: 'CONTROL_PLANE_LOCK_RELEASE_FAILED' });
    assert.equal(fs.readFileSync(path.join(fx.rootDirectory, '.registration.lock'), 'utf8'), 'changed-owner');
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});
for (const activeStatus of ['queued', 'running']) test('a ' + activeStatus + ' job prevents registration preview and transactional acknowledgement', async () => {
  const fx = fixture(); const db = new PanelDb(path.join(fx.directory, 'active-panel.sqlite3'));
  try {
    const parent = await db.createJob('console_register', { count: 1 }, 'panel-admin', { claimKeys: ['console_pipeline'] });
    const child = await db.createJob('registration', { count: 1, parentJobId: parent.id }, 'panel-admin', { claimKeys: ['registration'] });
    const active = await db.createJob('account_test', { accountIds: [123] }, 'panel-admin', { claimKeys: ['account_test:123'] });
    if (activeStatus === 'running') await db.updateJob(active.id, { status: 'running', startedAt: new Date().toISOString() });
    for (const job of [parent, child]) await db.updateJob(job.id, { status: 'failed', result: {
      code: 'REGISTRATION_TERMINATION_UNCONFIRMED', requiresReconciliation: true, writeOutcomeUnknown: true,
      ...(job.id === parent.id ? { childJobIds: [child.id], items: [], summary: emptySummary() } : {}),
    }, finishedAt: new Date().toISOString() });
    const ids = [parent.id, child.id];
    await assert.rejects(db.getRegistrationReconciliationJobs(ids), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
    const held = await db.getJob(child.id); let validated = false;
    await assert.rejects(db.acknowledgeJobReconciliation(child.id, {
      actor: 'panel-admin', confirmation: RECONCILIATION_ACK_CONFIRMATION, resolution: 'state_manually_reconciled',
      claimDigest: held.result.reconciliationClaimDigest, contextDigest: 'a'.repeat(64), registrationReviewJobIds: ids,
      validateContext() { validated = true; return true; }, beforeRelease() { assert.fail('active task forbids release'); },
    }), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
    assert.equal(validated, false); assert.equal((await db.getJob(child.id)).result.reconciliationHold, true);
  } finally { fs.rmSync(fx.directory, { recursive: true, force: true }); }
});

test('API verifies evidence inside the DB transaction and releases exactly one hold; related acknowledgement stays valid', async () => {
  const fx = fixture(); const db = new PanelDb(path.join(fx.directory, 'panel.sqlite3'));
  const previous = Object.fromEntries(['PANEL_ADMIN_TOKEN', 'PANEL_REQUIRE_AUTH', 'PANEL_WRITE_ENABLED', 'PANEL_ALLOW_INSECURE_WRITE', 'PANEL_DB_PATH'].map(key => [key, process.env[key]]));
  const admin = 'synthetic-review-admin-16'; Object.assign(process.env, { PANEL_ADMIN_TOKEN: admin, PANEL_REQUIRE_AUTH: '1', PANEL_WRITE_ENABLED: '1', PANEL_ALLOW_INSECURE_WRITE: '0', PANEL_DB_PATH: db.dbPath });
  let server;
  try {
    const parent = await db.createJob('console_register', { count: 1 }, 'panel-admin', { claimKeys: ['console_pipeline'] });
    const child = await db.createJob('registration', { count: 1, parentJobId: parent.id }, 'panel-admin', { claimKeys: ['registration'] });
    for (const job of [parent, child]) await db.updateJob(job.id, { status: 'failed', result: {
      code: 'REGISTRATION_TERMINATION_UNCONFIRMED', requiresReconciliation: true, writeOutcomeUnknown: true,
      ...(job.id === parent.id ? { childJobIds: [child.id], items: [], summary: emptySummary() } : {}),
    }, finishedAt: new Date().toISOString() });
    const jobs = await db.getRegistrationReconciliationJobs([parent.id, child.id]); prepare(fx, jobs);
    let allowCheckpoint = true;
    const logger = { requestId: () => 'registration-review-test', checkpoint: () => allowCheckpoint, probe: () => true, info() {}, warn() {}, error() {} };
    server = createServer({ db, logger, registrationReviewOptions: fx });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const base = 'http://127.0.0.1:' + server.address().port;
    const request = async (id, body, token = admin) => {
      const response = await fetch(base + '/api/jobs/' + id + '/reconciliation' + (body ? '/acknowledge' : ''), {
        method: body ? 'POST' : 'GET', headers: { 'x-panel-token': token, ...(body ? { 'content-type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
      }); return { status: response.status, json: await response.json() };
    };
    const before = await request(child.id); assert.equal(before.status, 200);
    const body = { jobId: child.id, confirmation: RECONCILIATION_ACK_CONFIRMATION, resolution: 'state_manually_reconciled',
      claimDigest: before.json.reconciliationClaimDigest, contextDigest: before.json.reconciliationContextDigest };
    assert.equal((await request(child.id, body, 'incorrect')).status, 401);
    assert.equal((await request(child.id, { ...body, resolution: 'no_effect_confirmed' })).status, 400);
    const policy = await db.getConsoleSettings();
    await db.saveConsoleSettings({ ...policy.settings, enabled: true }, { expectedRevision: policy.revision });
    assert.equal((await request(child.id)).status, 409);
    assert.equal((await request(child.id, body)).status, 409);
    const changedPolicy = await db.getConsoleSettings();
    await db.saveConsoleSettings({ ...changedPolicy.settings, enabled: false }, { expectedRevision: changedPolicy.revision });
    allowCheckpoint = false;
    assert.equal((await request(child.id, body)).status, 503);
    assert.equal((await db.getJob(child.id)).result.reconciliationHold, true);
    allowCheckpoint = true;
    fs.writeFileSync(path.join(fx.rootDirectory, 'username.json'), '[{}]');
    assert.equal((await request(child.id, body)).status, 409);
    assert.equal((await db.getJob(child.id)).result.reconciliationHold, true);
    fs.writeFileSync(path.join(fx.rootDirectory, 'username.json'), '[]');
    assert.equal((await request(child.id, body)).status, 200);
    assert.equal((await db.getJob(parent.id)).result.reconciliationHold, true);
    const released = await db.getJob(child.id);
    assert.equal(released.status, 'failed'); assert.equal(released.result.retryAllowed, false);
    assert.equal(released.result.reconciliationReviewedContextDigest, body.contextDigest);
    assert.equal((await request(child.id, body)).json.idempotent, true);
    const parentDetail = await request(parent.id); assert.equal(parentDetail.status, 200);
    const parentBody = { ...body, jobId: parent.id, claimDigest: parentDetail.json.reconciliationClaimDigest, contextDigest: parentDetail.json.reconciliationContextDigest };
    assert.equal((await request(parent.id, parentBody)).status, 200);
    assert.equal((await db.listJobsPage(100)).reconciliationHolds.total, 0);
    assert.equal((await db.getJob(parent.id)).status, 'failed');
    assert.equal(JSON.parse(fs.readFileSync(path.join(fx.rootDirectory, 'sms-activations.json')))[0].state, 'settlement_pending');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    fs.rmSync(fx.directory, { recursive: true, force: true });
  }
});
