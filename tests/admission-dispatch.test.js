'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { accountTestTargetRevision } = require('../backend/accountTargetRevision');
const { PanelDb } = require('../backend/db');
const {
  createAdmissionDispatchGuard,
  createBackgroundJobManager,
} = require('../backend/jobLifecycle');
const { createServer, shutdownServer } = require('../backend/server');
const { CONFIRMATION: TOKEN_CLEANUP_CONFIRMATION } = require('../backend/tokenCleanup');

const silentLogger = {
  checkpoint() { return true; },
  error() {},
  info() {},
  probe() { return true; },
  requestId() { return 'admission-dispatch-test'; },
  tail() { return []; },
  warn() {},
};

function postJson(baseUrl, pathname, body, idempotencyKey) {
  return new Promise((resolve, reject) => {
    const request = http.request(baseUrl + pathname, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': idempotencyKey,
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        json: JSON.parse(responseBody),
      }));
    });
    request.on('error', reject);
    request.end(JSON.stringify(body));
  });
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  return 'http://127.0.0.1:' + String(server.address().port);
}

async function committedThenReleaseFails(callback) {
  await callback();
  const error = new Error('控制面锁释放失败');
  error.code = 'CONTROL_PLANE_LOCK_RELEASE_FAILED';
  error.criticalSectionCompleted = true;
  error.controlPlaneLeaseReleaseFailed = true;
  error.requiresReconciliation = true;
  error.retryAllowed = false;
  error.doNotRetry = true;
  throw error;
}

function testAccount(id = 71) {
  return {
    id,
    name: 'free' + String(id).padStart(5, '0'),
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    account_id: 'admission-account-' + String(id),
    user_id: 'admission-user-' + String(id),
    identityKeys: [
      'account:admission-account-' + String(id),
      'user:admission-user-' + String(id),
    ],
    tokenFingerprints: { access: 'admission-access-' + String(id) },
    group_ids: [1],
  };
}

test('all mutation routes interrupt committed jobs when the admission lease release fails', async (t) => {
  const previousWrite = process.env.PANEL_WRITE_ENABLED;
  const previousInsecure = process.env.PANEL_ALLOW_INSECURE_WRITE;
  const previousPhase3 = process.env.PANEL_PHASE3_ENABLED;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  process.env.PANEL_PHASE3_ENABLED = '1';
  const version = 'b'.repeat(64);
  const account = testAccount();
  const selectedKey = 'token:tokens:tokens/admission-phase3.json';
  const cases = [
    {
      name: 'token import',
      pathname: '/api/sync/import',
      body: {
        snapshotVersion: 'a'.repeat(64),
        planIntentVersion: 'sync-plan-v1.' + 'A'.repeat(43),
        selectedKeys: ['token:tokens:tokens/admission-import.json'],
      },
    },
    {
      name: 'Phase3',
      pathname: '/api/phase3',
      body: {
        accounts: [{
          email: 'admission-phase3@example.test',
          selectedKey,
          phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
        }],
        selectedKeys: [selectedKey],
      },
      options: {
        phase3RequestResolver(requests) {
          return {
            eligible: requests.map((item) => ({
              ...item,
              canonicalKeys: ['email:admission-phase3@example.test'],
              executionBinding: { version: 1 },
            })),
            rejected: [],
          };
        },
      },
    },
    {
      name: 'account test',
      pathname: '/api/account-tests',
      body: {
        targets: [{
          accountId: account.id,
          targetRevision: accountTestTargetRevision(account),
        }],
        modelId: 'gpt-5.6-luna',
      },
      options: {
        accountTestClientFactory() {
          return { async listAccounts() { return [account]; } };
        },
      },
    },
    {
      name: 'expired-token cleanup',
      pathname: '/api/tokens/expired/delete',
      body: { confirmation: TOKEN_CLEANUP_CONFIRMATION, version },
      options: {
        expiredTokenLister() {
          return {
            generatedAt: new Date().toISOString(),
            version,
            count: 1,
            items: [],
            _internalItems: [{
              source: 'tokens',
              relativePath: 'tokens/expired.json',
              contentHash: 'a'.repeat(64),
              fingerprint: 'b'.repeat(16),
            }],
            recoveryRequired: false,
            claimCount: 0,
          };
        },
      },
    },
  ];
  try {
    for (const item of cases) {
      await t.test(item.name, async () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-route-'));
        const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
        const server = createServer({
          db,
          logger: silentLogger,
          admissionControlPlaneLock: committedThenReleaseFails,
          ...(item.options || {}),
        });
        try {
          const baseUrl = await listen(server);
          const idempotencyKey = 'admission_' + crypto.randomUUID() + '_release_failure';
          const failed = await postJson(baseUrl, item.pathname, item.body, idempotencyKey);
          assert.equal(failed.status, 503);
          assert.equal(failed.json.error, 'CONTROL_PLANE_LOCK_RELEASE_FAILED');

          const jobs = await db.listJobs(20);
          assert.equal(jobs.length, 1);
          const persisted = await db.getJob(jobs[0].id);
          assert.equal(persisted.status, 'interrupted');
          assert.equal(persisted.result.code, 'CONTROL_PLANE_LOCK_RELEASE_FAILED');
          assert.equal(persisted.result.blockedBeforeStart, true);
          assert.equal(persisted.result.executionOutcome, 'not_started');
          assert.equal(persisted.startedAt, null);
          if (item.name === 'Phase3') {
            assert.equal(
              persisted.payload.phase3TargetRevision,
              'phase3-target-v1.' + 'A'.repeat(43),
            );
            assert.equal(persisted.payload.sourcePath, 'tokens/admission-phase3.json');
            assert.match(persisted.payload.selectedKeyDigest, /^[a-f0-9]{64}$/);
          }
          const claimCount = await db.read((database) => Number(
            database.exec('SELECT COUNT(*) FROM job_claims')[0]?.values?.[0]?.[0],
          ));
          assert.equal(claimCount, 0);

          const replayed = await postJson(baseUrl, item.pathname, item.body, idempotencyKey);
          assert.equal(replayed.status, 202);
          assert.equal(replayed.headers['idempotency-replayed'], 'true');
          assert.equal(replayed.json.jobId, persisted.id);
          assert.equal((await db.getJob(persisted.id)).status, 'interrupted');
        } finally {
          await shutdownServer(server, { signal: 'test', timeoutMs: 1000 });
        }
      });
    }
  } finally {
    if (previousWrite === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previousWrite;
    if (previousInsecure === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previousInsecure;
    if (previousPhase3 === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previousPhase3;
  }
});

test('dispatch guard interrupts only the undispatched remainder after a partial batch failure', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-partial-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const first = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:dispatched@example.test'],
  });
  const second = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:not-dispatched@example.test'],
  });
  const manager = createBackgroundJobManager({ db });
  const guard = createAdmissionDispatchGuard({ db, jobManager: manager });
  let finishFirst;
  const firstObservation = new Promise((resolve) => { finishFirst = resolve; });

  await assert.rejects(
    guard.run(async ({ recordCommitted, dispatch }) => {
      recordCommitted([{ job: first }, { job: second }]);
      dispatch(first, 'phase3', 'local', (record) => manager.track(record, firstObservation));
      const error = new Error('second observer setup failed');
      error.code = 'OBSERVER_SETUP_FAILED';
      throw error;
    }),
    (error) => error.code === 'OBSERVER_SETUP_FAILED',
  );

  assert.equal((await db.getJob(first.id)).status, 'queued');
  const interrupted = await db.getJob(second.id);
  assert.equal(interrupted.status, 'interrupted');
  assert.equal(interrupted.result.code, 'OBSERVER_SETUP_FAILED');
  assert.equal(interrupted.result.executionOutcome, 'not_started');
  assert.equal(manager.activeCount, 1);
  const claimsWhileFirstRuns = await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM job_claims')[0]?.values?.[0]?.[0],
  ));
  assert.equal(claimsWhileFirstRuns, 1);

  await db.updateJob(first.id, {
    status: 'interrupted',
    result: { code: 'TEST_COMPLETED', executionOutcome: 'not_started' },
    finishedAt: new Date().toISOString(),
  });
  finishFirst();
  await firstObservation;
  const claimsAfterFirstFinishes = await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM job_claims')[0]?.values?.[0]?.[0],
  ));
  assert.equal(claimsAfterFirstFinishes, 0);
});

test('Phase3 route keeps an already registered observer when a later batch begin fails', async () => {
  const previousWrite = process.env.PANEL_WRITE_ENABLED;
  const previousInsecure = process.env.PANEL_ALLOW_INSECURE_WRITE;
  const previousPhase3 = process.env.PANEL_PHASE3_ENABLED;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  process.env.PANEL_PHASE3_ENABLED = '1';
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-phase3-partial-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const underlying = createBackgroundJobManager({ db });
  let begins = 0;
  const jobManager = {
    abandon: underlying.abandon,
    get activeCount() { return underlying.activeCount; },
    begin(job, type, actor) {
      begins += 1;
      if (begins === 2) {
        const error = new Error('injected second begin failure');
        error.code = 'OBSERVER_SETUP_FAILED';
        throw error;
      }
      return underlying.begin(job, type, actor);
    },
    get shuttingDown() { return underlying.shuttingDown; },
    shutdown: underlying.shutdown,
    track: underlying.track,
    withAdmission: underlying.withAdmission,
  };
  const selectedKeys = [
    'token:tokens:tokens/phase3-first.json',
    'token:tokens:tokens/phase3-second.json',
  ];
  const server = createServer({
    db,
    jobManager,
    logger: silentLogger,
    admissionControlPlaneLock: async (callback) => callback(),
    phase3RequestResolver(requests) {
      return {
        eligible: requests.map((item, index) => ({
          ...item,
          canonicalKeys: ['email:phase3-partial-' + String(index) + '@example.test'],
          executionBinding: { version: 1 },
        })),
        rejected: [],
      };
    },
  });
  try {
    const baseUrl = await listen(server);
    const response = await postJson(baseUrl, '/api/phase3', {
      accounts: selectedKeys.map((selectedKey, index) => ({
        email: 'phase3-partial-' + String(index) + '@example.test',
        selectedKey,
        phase3TargetRevision: 'phase3-target-v1.' + String(index ? 'B' : 'A').repeat(43),
      })),
      selectedKeys,
    }, 'phase3_partial_' + crypto.randomUUID());
    assert.equal(response.status, 503);
    assert.equal(response.json.error, 'phase3_failed');
    assert.equal(JSON.stringify(response.json).includes('OBSERVER_SETUP_FAILED'), false);
    assert.equal(begins, 2);

    let jobs = await db.listJobs(20);
    assert.equal(jobs.length, 2);
    const undispatched = jobs.find((job) => job.result?.code === 'OBSERVER_SETUP_FAILED');
    assert.ok(undispatched);
    assert.equal(undispatched.status, 'interrupted');
    assert.equal(undispatched.result.executionOutcome, 'not_started');
    const registeredId = jobs.find((job) => job.id !== undispatched.id)?.id;
    assert.ok(registeredId);
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const registered = await db.getJob(registeredId);
      if (['succeeded', 'partial', 'failed', 'interrupted'].includes(registered.status)) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    const registered = await db.getJob(registeredId);
    assert.notEqual(registered.result?.code, 'OBSERVER_SETUP_FAILED');
  } finally {
    await shutdownServer(server, { signal: 'test', timeoutMs: 1000 });
    if (previousWrite === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previousWrite;
    if (previousInsecure === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previousInsecure;
    if (previousPhase3 === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previousPhase3;
  }
});

test('dispatch guard leaves a queued claim fail-closed when interruption persistence fails', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-persist-fail-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const job = await db.createJob('token_import', {}, 'local', { claimKeys: ['token_import'] });
  const manager = createBackgroundJobManager({ db });
  const guard = createAdmissionDispatchGuard({
    db: {
      async interruptOwnedQueuedJobsBeforeDispatch() {
        const error = new Error('injected persistence failure');
        error.code = 'SQLITE_WRITE_FAILED';
        throw error;
      },
    },
    jobManager: manager,
  });
  await assert.rejects(
    guard.run(async ({ recordCommitted }) => {
      recordCommitted([{ job }]);
      const error = new Error('observer setup failed');
      error.code = 'OBSERVER_SETUP_FAILED';
      throw error;
    }),
    (error) => error.code === 'JOB_ADMISSION_RECOVERY_FAILED'
      && error.admissionFailureCode === 'OBSERVER_SETUP_FAILED'
      && error.persistenceFailureCode === 'SQLITE_WRITE_FAILED',
  );
  assert.equal((await db.getJob(job.id)).status, 'queued');
  const claimCount = await db.read((database) => Number(
    database.exec("SELECT COUNT(*) FROM job_claims WHERE claim_key = 'token_import'")[0]
      ?.values?.[0]?.[0],
  ));
  assert.equal(claimCount, 1);
  await db.updateJob(job.id, { status: 'interrupted', finishedAt: new Date().toISOString() });
});

test('shutdown during a committed admission eventually interrupts the not-started job', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-shutdown-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const manager = createBackgroundJobManager({ db });
  const guard = createAdmissionDispatchGuard({ db, jobManager: manager });
  let releaseCommit;
  let committedJob;
  const admission = manager.withAdmission((signal) => guard.run(async ({ recordCommitted }) => {
    committedJob = await db.createJob('token_import', {}, 'local', { claimKeys: ['token_import'] });
    recordCommitted([{ job: committedJob }]);
    await new Promise((resolve) => { releaseCommit = resolve; });
    if (signal.aborted) {
      const error = new Error('stopping');
      error.code = 'JOB_INTERRUPTED';
      throw error;
    }
  }));
  while (!committedJob || !releaseCommit) {
    await new Promise((resolve) => setImmediate(resolve));
  }

  const shutdown = manager.shutdown({ timeoutMs: 0 });
  await assert.rejects(admission, (error) => error.code === 'JOB_INTERRUPTED');
  releaseCommit();
  await shutdown;
  for (let attempt = 0; manager.admissionCount > 0 && attempt < 100; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  const persisted = await db.getJob(committedJob.id);
  assert.equal(persisted.status, 'interrupted');
  assert.equal(persisted.result.executionOutcome, 'not_started');
  assert.equal(persisted.result.blockedBeforeStart, true);
  assert.equal(manager.admissionCount, 0);
});

test('recordCommitted validates a durable batch atomically before tracking any item', () => {
  const guard = createAdmissionDispatchGuard({});
  assert.throws(
    () => guard.recordCommitted([
      { id: 'valid-first-job' },
      { id: 'invalid job id' },
    ]),
    (error) => error.code === 'JOB_ADMISSION_TRACKING_INVALID',
  );
  assert.equal(guard.committedCount, 0);

  assert.throws(
    () => guard.recordCommitted([
      { id: 'duplicate-job' },
      { id: 'duplicate-job' },
    ]),
    (error) => error.code === 'JOB_ADMISSION_TRACKING_INVALID',
  );
  assert.equal(guard.committedCount, 0);
});

test('dispatch guard interrupts a job when an observer returns without manager tracking', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-untracked-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const job = await db.createJob('token_import', {}, 'local', { claimKeys: ['token_import'] });
  const manager = createBackgroundJobManager({ db });
  const guard = createAdmissionDispatchGuard({ db, jobManager: manager });

  await assert.rejects(
    guard.run(async ({ recordCommitted, dispatch }) => {
      recordCommitted([{ job }]);
      dispatch(job, 'token_import', 'local', (record) => {
        // A callback cannot impersonate jobManager.track with an arbitrary
        // truthy marker; the guard requires the tracked promise contract.
        record.promise = {};
        return Promise.resolve();
      });
    }),
    (error) => error.code === 'JOB_ADMISSION_OBSERVER_UNTRACKED'
      && error.blockedBeforeStart === true
      && error.executionOutcome === 'not_started',
  );

  const persisted = await db.getJob(job.id);
  assert.equal(persisted.status, 'interrupted');
  assert.equal(persisted.startedAt, null);
  assert.equal(persisted.result.blockedBeforeStart, true);
  assert.equal(persisted.result.executionOutcome, 'not_started');
  assert.equal(manager.activeCount, 0);
  const claimCount = await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM job_claims')[0]?.values?.[0]?.[0],
  ));
  assert.equal(claimCount, 0);
});

test('existing interrupted jobs are safe only with strict not-started evidence', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-proof-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const safeResult = {
    blockedBeforeStart: true,
    executionOutcome: 'not_started',
    requiresReconciliation: false,
  };

  const safelyInterrupted = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:safe-proof@example.test'],
  });
  await db.updateJob(safelyInterrupted.id, {
    status: 'interrupted',
    result: safeResult,
    finishedAt: new Date().toISOString(),
  });
  const safeReplay = await db.interruptOwnedQueuedJobsBeforeDispatch([safelyInterrupted.id]);
  assert.deepEqual(safeReplay.skipped, [{
    id: safelyInterrupted.id,
    status: 'interrupted',
    safeNotStarted: true,
  }]);

  const previouslyRunning = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:ran-before-interrupt@example.test'],
  });
  await db.updateJob(previouslyRunning.id, {
    status: 'running',
    startedAt: new Date().toISOString(),
  });
  await db.updateJob(previouslyRunning.id, {
    status: 'interrupted',
    result: safeResult,
    finishedAt: new Date().toISOString(),
  });
  const runningReplay = await db.interruptOwnedQueuedJobsBeforeDispatch([previouslyRunning.id]);
  assert.deepEqual(runningReplay.skipped, [{
    id: previouslyRunning.id,
    status: 'interrupted',
    safeNotStarted: false,
  }]);

  const runningDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-running-'));
  const runningDb = new PanelDb(path.join(runningDirectory, 'panel.sqlite3'));
  const stillRunning = await runningDb.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:still-running-proof@example.test'],
  });
  await runningDb.updateJob(stillRunning.id, {
    status: 'running',
    startedAt: new Date().toISOString(),
  });
  const runningResult = await runningDb.interruptOwnedQueuedJobsBeforeDispatch([stillRunning.id]);
  assert.deepEqual(runningResult.skipped, [{
    id: stillRunning.id,
    status: 'running',
    safeNotStarted: false,
  }]);
  assert.equal((await runningDb.getJob(stillRunning.id)).status, 'running');
  const runningClaims = await runningDb.read((database) => Number(
    database.exec(`SELECT COUNT(*) FROM job_claims
      WHERE job_id = '${stillRunning.id}'`)[0]?.values?.[0]?.[0],
  ));
  assert.equal(runningClaims, 1);

  const held = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:held-proof@example.test'],
  });
  await db.updateJob(held.id, {
    status: 'interrupted',
    result: {
      ...safeResult,
      requiresReconciliation: true,
      writeOutcomeUnknown: true,
    },
    finishedAt: new Date().toISOString(),
  });
  const heldReplay = await db.interruptOwnedQueuedJobsBeforeDispatch([held.id]);
  assert.deepEqual(heldReplay.skipped, [{
    id: held.id,
    status: 'interrupted',
    safeNotStarted: false,
  }]);
  assert.equal((await db.getJob(held.id)).result.reconciliationHold, true);
});

test('queued execution traces reject an admission batch atomically', async (t) => {
  const cases = [
    ['started_at', new Date().toISOString()],
    ['finished_at', new Date().toISOString()],
    ['result_json', '{}'],
    ['error', 'stored execution error'],
  ];
  for (const [column, value] of cases) {
    await t.test(column, async () => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-trace-'));
      const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
      const clean = await db.createJob('phase3', {}, 'local', {
        claimKeys: ['phase3:email:clean-' + column + '@example.test'],
      });
      const tainted = await db.createJob('phase3', {}, 'local', {
        claimKeys: ['phase3:email:tainted-' + column + '@example.test'],
      });
      await db.write((database) => {
        const statement = database.prepare(
          'UPDATE sync_jobs SET ' + column + ' = ? WHERE id = ?',
        );
        try { statement.run([value, tainted.id]); } finally { statement.free(); }
      });

      await assert.rejects(
        db.interruptOwnedQueuedJobsBeforeDispatch([clean.id, tainted.id]),
        (error) => error.code === 'JOB_QUEUED_STATE_INCONSISTENT',
      );
      assert.equal((await db.getJob(clean.id)).status, 'queued');
      assert.equal((await db.getJob(tainted.id)).status, 'queued');
      const claims = await db.read((database) => Number(
        database.exec('SELECT COUNT(*) FROM job_claims')[0]?.values?.[0]?.[0],
      ));
      assert.equal(claims, 2);
    });
  }
});

test('owner mismatch rejects an admission batch without releasing any claim', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-owner-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const owned = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:owned-admission@example.test'],
  });
  const changed = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:changed-owner@example.test'],
  });
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET owner_pid = ?, owner_start_id = ?, owner_boot_id = ? WHERE id = ?`);
    try {
      statement.run([2147483647, 'different-start', 'different-boot', changed.id]);
    } finally {
      statement.free();
    }
  });

  await assert.rejects(
    db.interruptOwnedQueuedJobsBeforeDispatch([owned.id, changed.id]),
    (error) => error.code === 'JOB_OWNER_CONFLICT',
  );
  assert.equal((await db.getJob(owned.id)).status, 'queued');
  assert.equal((await db.getJob(changed.id)).status, 'queued');
  const claims = await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM job_claims')[0]?.values?.[0]?.[0],
  ));
  assert.equal(claims, 2);
});

test('a coercible text PID cannot impersonate the current job owner', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-owner-type-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const claimKey = 'phase3:email:owner-type@example.test';
  const job = await db.createJob('phase3', {}, 'local', { claimKeys: [claimKey] });
  const hexadecimalPid = '0x' + process.pid.toString(16);
  assert.equal(Number(hexadecimalPid), process.pid);
  await db.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET owner_pid = ? WHERE id = ?');
    try {
      statement.run([hexadecimalPid, job.id]);
    } finally {
      statement.free();
    }
  });
  assert.equal(await db.read((database) => database.exec(`SELECT typeof(owner_pid)
    FROM sync_jobs WHERE id = '${job.id}'`)[0]?.values?.[0]?.[0]), 'text');

  await assert.rejects(
    db.interruptOwnedQueuedJobsBeforeDispatch([job.id]),
    (error) => error.code === 'JOB_OWNER_CONFLICT',
  );
  assert.equal((await db.getJob(job.id)).status, 'queued');
  assert.equal(await db.read((database) => Number(database.exec(`SELECT COUNT(*)
    FROM job_claims WHERE job_id = '${job.id}'`)[0]?.values?.[0]?.[0])), 1);
});

test('dispatch guard never relabels a previously running interruption as not started', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-unsafe-skip-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const job = await db.createJob('phase3', {}, 'local', {
    claimKeys: ['phase3:email:unsafe-skip@example.test'],
  });
  const manager = createBackgroundJobManager({ db });
  const guard = createAdmissionDispatchGuard({ db, jobManager: manager });
  const dispatchError = new Error('observer setup failed after an external state transition');
  dispatchError.code = 'OBSERVER_SETUP_FAILED';

  await assert.rejects(
    guard.run(async ({ recordCommitted }) => {
      recordCommitted([{ job }]);
      await db.updateJob(job.id, {
        status: 'running',
        startedAt: new Date().toISOString(),
      });
      await db.updateJob(job.id, {
        status: 'interrupted',
        result: {
          blockedBeforeStart: true,
          executionOutcome: 'not_started',
          requiresReconciliation: false,
        },
        finishedAt: new Date().toISOString(),
      });
      throw dispatchError;
    }),
    (error) => error.code === 'JOB_ADMISSION_RECOVERY_FAILED'
      && error.admissionFailureCode === 'OBSERVER_SETUP_FAILED'
      && error.blockedBeforeStart === undefined
      && error.executionOutcome === undefined,
  );
  assert.equal(manager.admissionHoldCount, 1);
});

test('temporary admission recovery failures are retried in background under a write fuse', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-admission-background-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const job = await db.createJob('token_import', {}, 'local', { claimKeys: ['token_import'] });
  const manager = createBackgroundJobManager({ db });
  let attempts = 0;
  const guardedDb = {
    async interruptOwnedQueuedJobsBeforeDispatch(ids, options) {
      attempts += 1;
      if (attempts <= 4) {
        const error = new Error('temporary persistence failure');
        error.code = 'SQLITE_WRITE_FAILED';
        throw error;
      }
      return db.interruptOwnedQueuedJobsBeforeDispatch(ids, options);
    },
  };
  const guard = createAdmissionDispatchGuard({ db: guardedDb, jobManager: manager });
  const setupError = new Error('observer setup failed');
  setupError.code = 'OBSERVER_SETUP_FAILED';

  await assert.rejects(
    guard.run(async ({ recordCommitted }) => {
      recordCommitted([{ job }]);
      throw setupError;
    }),
    (error) => error.code === 'JOB_ADMISSION_RECOVERY_FAILED'
      && error.admissionFailureCode === 'OBSERVER_SETUP_FAILED',
  );
  assert.equal(attempts, 4);
  assert.equal(manager.admissionHoldCount, 1);
  await assert.rejects(
    manager.withAdmission(async () => 'must not run'),
    (error) => error.code === 'JOB_ADMISSION_RECOVERY_FAILED'
      && error.recoveryPending === true,
  );

  let persisted = await db.getJob(job.id);
  for (let attempt = 0; persisted.status !== 'interrupted' && attempt < 100; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    persisted = await db.getJob(job.id);
  }
  assert.equal(persisted.status, 'interrupted');
  assert.equal(persisted.result.executionOutcome, 'not_started');
  assert.equal(attempts, 5);
  assert.equal(manager.admissionHoldCount, 0);
  assert.equal(await manager.withAdmission(async () => 'recovered'), 'recovered');
  const claimCount = await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM job_claims')[0]?.values?.[0]?.[0],
  ));
  assert.equal(claimCount, 0);
});
