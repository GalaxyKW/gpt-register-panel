const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { PanelDb } = require('../backend/db');
const { Sub2ApiAdminClient } = require('../backend/adapters/sub2apiAdmin');
const { runCommand } = require('../backend/phase3Worker');
const {
  accountTestTargetBaseline,
  runAccountTestJobNow,
} = require('../backend/accountTestWorker');
const {
  createBackgroundJobManager,
  throwIfJobInterrupted,
  updateTerminalJob,
} = require('../backend/jobLifecycle');
const {
  createServer,
  installShutdownSignalHandlers,
  shutdownServer,
} = require('../backend/server');
const { withControlPlaneLock } = require('../backend/taskCoordinator');
const testAuditLogger = {
  checkpoint() { return true; },
  info() {},
  warn() {},
  error() {},
};

test('terminal job updates retry a bounded number of times with one stable timestamp', async () => {
  const patches = [];
  const db = {
    async updateJob(id, patch) {
      patches.push({ id, patch: { ...patch } });
      if (patches.length < 3) throw new Error('temporary sqlite failure');
      return 'persisted';
    },
  };
  const result = await updateTerminalJob(db, 'job-retry', {
    status: 'succeeded',
    result: { count: 1 },
  }, { attempts: 3, initialDelayMs: 0 });
  assert.equal(result, 'persisted');
  assert.equal(patches.length, 3);
  assert.equal(new Set(patches.map((item) => item.patch.finishedAt)).size, 1);
  assert.deepEqual(patches.map((item) => item.patch.status), [
    'succeeded',
    'succeeded',
    'succeeded',
  ]);

  let failures = 0;
  await assert.rejects(
    updateTerminalJob({
      async updateJob() {
        failures += 1;
        throw new Error('persistent sqlite failure');
      },
    }, 'job-fail', { status: 'failed' }, { attempts: 2, initialDelayMs: 0 }),
    /persistent sqlite failure/,
  );
  assert.equal(failures, 2);

  const hostile = new Error('hostile terminal persistence failure');
  let codeGetterCalls = 0;
  Object.defineProperty(hostile, 'code', {
    get() {
      codeGetterCalls += 1;
      throw new Error('credential-hostile-terminal-code');
    },
  });
  let hostileAttempts = 0;
  let hostileRetries = 0;
  await assert.rejects(
    updateTerminalJob({
      async updateJob() {
        hostileAttempts += 1;
        throw hostile;
      },
    }, 'job-hostile-error', { status: 'failed' }, {
      attempts: 3,
      initialDelayMs: 0,
      onRetry() { hostileRetries += 1; },
    }),
    (error) => error === hostile,
  );
  assert.equal(hostileAttempts, 3);
  assert.equal(hostileRetries, 2);
  assert.equal(codeGetterCalls, 0);
});

test('terminal job updates fail closed when durable storage is unavailable', async () => {
  for (const db of [null, {}, { updateJob: true }]) {
    await assert.rejects(
      updateTerminalJob(db, 'job-missing-store', { status: 'failed' }),
      (error) => error.code === 'JOB_TERMINAL_STORE_UNAVAILABLE'
        && /\u7ec8\u6001存储不可用/.test(error.message),
    );
  }
});

test('background manager rejects duplicate active job IDs without losing the first observer', async () => {
  const manager = createBackgroundJobManager({});
  const first = manager.begin({ id: 'job-duplicate-active' }, 'phase3');
  assert.throws(
    () => manager.begin({ id: 'job-duplicate-active' }, 'phase3'),
    (error) => error.code === 'JOB_ALREADY_ACTIVE',
  );
  assert.equal(manager.activeCount, 1);
  await manager.track(first, Promise.resolve('completed'));
  assert.equal(manager.activeCount, 0);
});

test('terminal job updates surface a rejected CAS without retrying it', async () => {
  let attempts = 0;
  let retries = 0;
  await assert.rejects(
    updateTerminalJob({
      async updateJob() {
        attempts += 1;
        return { applied: false, currentStatus: 'interrupted' };
      },
    }, 'job-terminal-conflict', {
      status: 'succeeded',
      result: { completed: true },
    }, {
      attempts: 4,
      initialDelayMs: 0,
      onRetry() { retries += 1; },
    }),
    (error) => error.code === 'JOB_TERMINAL_STATUS_CONFLICT'
      && error.requestedStatus === 'succeeded'
      && error.currentStatus === 'interrupted',
  );
  assert.equal(attempts, 1);
  assert.equal(retries, 0);
});

test('Sub2API requests distinguish an external shutdown abort from a timeout', async () => {
  const originalFetch = global.fetch;
  const controller = new AbortController();
  try {
    global.fetch = async (url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const error = new Error('aborted');
        error.name = 'AbortError';
        reject(error);
      }, { once: true });
    });
    const client = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: 'test-key',
      timeoutMs: 10_000,
      testTimeoutMs: 10_000,
    });
    const request = client.request(
      'GET',
      '/api/v1/admin/accounts/1',
      undefined,
      { signal: controller.signal },
    );
    controller.abort();
    await assert.rejects(request, (error) => error.code === 'JOB_INTERRUPTED');
  } finally {
    global.fetch = originalFetch;
  }

  const testController = new AbortController();
  try {
    global.fetch = async (url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const error = new Error('aborted');
        error.name = 'AbortError';
        reject(error);
      }, { once: true });
    });
    const client = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: 'test-key',
      timeoutMs: 10_000,
      testTimeoutMs: 10_000,
    });
    const request = client.testAccount(1, { signal: testController.signal });
    testController.abort();
    await assert.rejects(request, (error) => error.code === 'JOB_INTERRUPTED');
  } finally {
    global.fetch = originalFetch;
  }
});

test('token-import adapter methods forward shutdown cancellation to fetch', async () => {
  const originalFetch = global.fetch;
  try {
    const client = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: 'test-key',
      timeoutMs: 10_000,
    });
    const calls = [
      (signal) => client.listAccounts({ signal }),
      (signal) => client.getAccount(1, { signal }),
      (signal) => client.listGroups({ signal }),
      (signal) => client.getBatchTableUsageStats([1], { signal }),
      (signal) => client.exportAccounts([], { signal }),
      (signal) => client.importCodexSession(
        { content: '{}' },
        { idempotencyKey: 'test-import-key', signal },
      ),
      (signal) => client.applyOAuthCredentials(
        1,
        { type: 'oauth', credentials: {} },
        { signal },
      ),
    ];
    for (const invoke of calls) {
      const controller = new AbortController();
      global.fetch = async (url, options) => new Promise((resolve, reject) => {
        options.signal.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        }, { once: true });
      });
      const request = invoke(controller.signal);
      controller.abort();
      await assert.rejects(request, (error) => error.code === 'JOB_INTERRUPTED');
    }
  } finally {
    global.fetch = originalFetch;
  }
});

test('account-test worker records reconciliation when shutdown follows test dispatch', async () => {
  const account = {
    id: 17,
    name: 'free00017',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys: ['account:test-account-17', 'user:test-user-17'],
  };
  const controller = new AbortController();
  let notifyStarted;
  const started = new Promise((resolve) => { notifyStarted = resolve; });
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() { return { ...account }; },
    async testAccount(id, options) {
      assert.equal(id, 17);
      notifyStarted();
      return new Promise((resolve, reject) => {
        options.signal.addEventListener('abort', () => {
          const error = new Error('stopped');
          error.code = 'JOB_INTERRUPTED';
          // Mirror the adapter contract: this mock has crossed its dispatch
          // boundary, so an abort leaves the remote test outcome unknown.
          error.requiresReconciliation = true;
          error.testOutcomeUnknown = true;
          error.reconciliationScope = 'test';
          error.reconciliationReason = 'external_abort';
          reject(error);
        }, { once: true });
      });
    },
  };
  const run = runAccountTestJobNow({
    accountIds: [17],
    targetBaselines: [accountTestTargetBaseline(account)],
    db: { async startMutationJob() {}, async updateJob() {}, async audit() {} },
    jobId: 'job-account-interrupt',
    client,
    logger: testAuditLogger,
    signal: controller.signal,
  });
  await started;
  controller.abort();
  const outcome = await run;
  assert.equal(outcome.jobStatus, 'failed');
  assert.equal(outcome.stopReason, 'interrupted');
  assert.equal(outcome.attemptedCount, 1);
  assert.equal(outcome.notAttemptedCount, 0);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].testOutcomeUnknown, true);
  assert.equal(outcome.results[0].reconciliationReason, 'external_abort');
});

test('account-test cancellation after a successful probe records reconciliation without scheduler mutation', async () => {
  const account = {
    id: 18,
    name: 'free00018',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: ['account:test-account-18', 'user:test-user-18'],
  };
  const controller = new AbortController();
  let schedulerWrites = 0;
  let reads = 0;
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() {
      reads += 1;
      return { ...account };
    },
    async testAccount() {
      controller.abort();
      return { success: true, model: 'gpt-5.6-luna' };
    },
    async setSchedulable() {
      schedulerWrites += 1;
      return { ...account, schedulable: true };
    },
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [18],
    targetBaselines: [accountTestTargetBaseline(account)],
    db: { async startMutationJob() {}, async updateJob() {}, async audit() {} },
    jobId: 'job-account-post-test-interrupt',
    client,
    logger: testAuditLogger,
    signal: controller.signal,
  });
  assert.equal(reads, 1);
  assert.equal(schedulerWrites, 0);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].testSuccess, true);
  assert.equal(outcome.results[0].testSuccessKnown, true);
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.equal(outcome.results[0].reconciliationReason, 'post_test_interrupted');
});

test('shutdown drains a concurrently completed job before interrupting remaining DB jobs', async () => {
  const events = [];
  let jobStatus = 'running';
  const db = {
    async interruptOwnedActiveJobs(reason, options) {
      events.push('interrupt-db');
      assert.deepEqual(options.excludeJobIds, []);
      if (['queued', 'running'].includes(jobStatus)) jobStatus = 'interrupted';
      return [];
    },
  };
  const manager = createBackgroundJobManager({ db });
  const record = manager.begin({ id: 'job-race' }, 'phase3');
  const operation = new Promise((resolve) => {
    record.controller.signal.addEventListener('abort', () => {
      events.push('worker-aborted');
      queueMicrotask(() => {
        events.push('worker-finished');
        jobStatus = 'succeeded';
        resolve();
      });
    }, { once: true });
  });
  manager.track(record, operation);
  const result = await manager.shutdown({ timeoutMs: 100 });
  assert.equal(result.active, 0);
  assert.equal(result.remaining, 0);
  assert.equal(result.outstandingAdmissions, 0);
  assert.equal(jobStatus, 'succeeded');
  assert.deepEqual(events, ['worker-aborted', 'worker-finished', 'interrupt-db']);
});

test('shutdown timeout retains an active job claim until its real terminal outcome is persisted', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-shutdown-claim-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const protectedClaim = 'phase3:email:still-unwinding@example.test';
  const orphanClaim = 'phase3:email:unobserved@example.test';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [protectedClaim] });
  const orphan = await db.createJob('phase3', {}, 'tester', { claimKeys: [orphanClaim] });
  await db.updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });
  const manager = createBackgroundJobManager({ db });
  const record = manager.begin(job, 'phase3');
  let releaseWorker;
  const workerGate = new Promise((resolve) => { releaseWorker = resolve; });
  const worker = (async () => {
    // Deliberately model a non-cancellable operation that must finish its
    // unwind and persist the real result after the shutdown drain expires.
    await workerGate;
    await updateTerminalJob(db, job.id, {
      status: 'succeeded',
      result: { completed: true },
    });
  })();
  const tracked = manager.track(record, worker);

  const result = await manager.shutdown({ timeoutMs: 0 });
  assert.equal(result.remaining, 1);
  assert.equal(result.active, 1);
  assert.equal(result.outstandingAdmissions, 0);
  assert.deepEqual(result.interrupted, [orphan.id]);
  assert.equal((await db.getJob(job.id)).status, 'running');
  assert.equal((await db.getJob(orphan.id)).status, 'interrupted');
  await assert.rejects(
    db.createJob('phase3', {}, 'tester', { claimKeys: [protectedClaim] }),
    (error) => error.code === 'JOB_ALREADY_CLAIMED'
      && error.existingJobId === job.id,
  );

  releaseWorker();
  await tracked;
  assert.equal(manager.activeCount, 0);
  const completed = await db.getJob(job.id);
  assert.equal(completed.status, 'succeeded');
  assert.deepEqual(completed.result, { completed: true });

  const replacement = await db.createJob('phase3', {}, 'tester', {
    claimKeys: [protectedClaim],
  });
  await db.updateJob(replacement.id, { status: 'failed', error: 'test cleanup' });
});

test('shutdown drain timeout is not extended when the wall clock stops', async () => {
  const manager = createBackgroundJobManager({
    db: {
      async interruptOwnedActiveJobs() { return []; },
    },
  });
  const record = manager.begin({ id: 'job-monotonic-shutdown' }, 'phase3');
  manager.track(record, new Promise(() => {}));
  const originalDateNow = Date.now;
  const frozenNow = originalDateNow();
  let safetyTimer;
  const realStartedAt = process.hrtime.bigint();
  try {
    Date.now = () => frozenNow;
    // Restore the civil clock as a safety valve so the regression test also
    // terminates against an implementation that still uses Date.now().
    safetyTimer = setTimeout(() => { Date.now = originalDateNow; }, 300);
    const result = await manager.shutdown({ timeoutMs: 40 });
    const elapsedMs = Number(process.hrtime.bigint() - realStartedAt) / 1e6;
    assert.equal(result.remaining, 1);
    assert.ok(elapsedMs < 200, 'shutdown should use a monotonic deadline');
  } finally {
    if (safetyTimer) clearTimeout(safetyTimer);
    Date.now = originalDateNow;
  }
});

test('shutdown does not exclude a begun job until its observer promise is tracked', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-shutdown-untracked-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const job = await db.createJob('token_import', {}, 'tester', { claimKeys: ['token_import'] });
  const manager = createBackgroundJobManager({ db });
  const record = manager.begin(job, 'token_import');

  const result = await manager.shutdown({ timeoutMs: 0 });
  assert.equal(result.remaining, 1);
  assert.deepEqual(result.interrupted, [job.id]);
  const persisted = await db.getJob(job.id);
  assert.equal(persisted.status, 'interrupted');
  assert.equal(persisted.result.executionOutcome, 'not_started');
  assert.equal(persisted.result.blockedBeforeStart, true);
  assert.equal(manager.abandon(record), true);
  assert.equal(manager.activeCount, 0);
});

test('shutdown aborts admission callers while tracking their underlying unwind', async () => {
  let releaseAdmission;
  let markAdmissionEntered;
  let mutations = 0;
  let interruptedWrites = 0;
  let interruptOptions = null;
  const admissionEntered = new Promise((resolve) => { markAdmissionEntered = resolve; });
  const manager = createBackgroundJobManager({
    db: {
      async interruptOwnedActiveJobs(reason, options) {
        interruptedWrites += 1;
        interruptOptions = options;
        return [];
      },
    },
  });
  const admission = manager.withAdmission(async (signal) => {
    markAdmissionEntered(signal);
    await new Promise((resolve) => { releaseAdmission = resolve; });
    throwIfJobInterrupted(signal);
    mutations += 1;
  });
  const signal = await admissionEntered;
  assert.equal(signal.aborted, false);

  const shutdown = manager.shutdown({ timeoutMs: 0 });
  await assert.rejects(admission, (error) => error.code === 'JOB_INTERRUPTED');
  assert.equal(signal.aborted, true);
  assert.equal(manager.admissionCount, 1);
  assert.throws(
    () => manager.begin({ id: 'must-not-start' }, 'phase3'),
    (error) => error.code === 'JOB_INTERRUPTED',
  );
  const shutdownResult = await shutdown;
  assert.equal(interruptedWrites, 1);
  assert.deepEqual(interruptOptions.excludeJobIds, []);
  assert.equal(shutdownResult.remaining, 0);
  assert.equal(shutdownResult.outstandingAdmissions, 1);

  releaseAdmission();
  for (let attempt = 0; manager.admissionCount > 0 && attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(manager.admissionCount, 0);
  assert.equal(mutations, 0);
});

test('HTTP shutdown cancels a queued import admission before job creation', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let releaseLock;
  let markLockEntered;
  let server;
  let createdJobs = 0;
  const lockEntered = new Promise((resolve) => { markLockEntered = resolve; });
  const heldLock = withControlPlaneLock(async () => {
    markLockEntered();
    await new Promise((resolve) => { releaseLock = resolve; });
  });
  try {
    await lockEntered;
    const db = {
      dbPath: path.join(os.tmpdir(), 'unused-panel-admission-shutdown.sqlite3'),
      async getMutationReceipt() { return null; },
      async createMutationSubmission() {
        createdJobs += 1;
        throw new Error('unexpected task creation');
      },
      async createJob() {
        createdJobs += 1;
        return { id: 'must-not-exist', type: 'token_import', status: 'queued' };
      },
      async interruptOwnedActiveJobs() { return []; },
    };
    server = createServer({
      db,
      logger: {
        requestId: () => 'admission-shutdown-test',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    const responsePromise = new Promise((resolve, reject) => {
      const request = http.request({
        host: '127.0.0.1',
        port: address.port,
        path: '/api/sync/import',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'idempotency-key': 'test-idem-admission-shutdown-1234567890',
        },
      }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve({ status: response.statusCode, body }));
      });
      request.on('error', reject);
      request.end(JSON.stringify({
        snapshotVersion: 'a'.repeat(64),
        planIntentVersion: 'sync-plan-v1.' + 'A'.repeat(43),
        selectedKeys: ['account:queued-during-stop'],
      }));
    });
    for (let attempt = 0;
      server.panelJobManager.admissionCount === 0 && attempt < 100;
      attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(server.panelJobManager.admissionCount, 1);

    const shutdown = shutdownServer(server, { signal: 'test', timeoutMs: 500 });
    const response = await responsePromise;
    assert.equal(response.status, 503);
    assert.equal(JSON.parse(response.body).error, 'JOB_INTERRUPTED');
    await shutdown;
    assert.equal(createdJobs, 0);
    assert.equal(server.panelJobManager.activeCount, 0);
  } finally {
    if (releaseLock) releaseLock();
    await heldLock;
    await withControlPlaneLock(async () => {});
    if (server?.listening) {
      await new Promise((resolve) => server.close(resolve));
    }
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('Phase3 command abort terminates the child and reports an interrupted job', async () => {
  const controller = new AbortController();
  const startedAt = Date.now();
  const running = runCommand(process.execPath, ['-e', [
    "process.on('SIGTERM', () => {});",
    'setInterval(() => {}, 1000);',
  ].join('\n')], {
    cwd: os.tmpdir(),
    env: { PATH: process.env.PATH || '' },
    timeoutMs: 10_000,
    terminationGraceMs: 100,
    terminationHardDeadlineMs: 100,
    maxOutputBytes: 4096,
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(), 50);
  await assert.rejects(
    running,
    (error) => error.code === 'JOB_INTERRUPTED'
      && ['SIGTERM', 'SIGKILL'].includes(error.details?.signal),
  );
  assert.equal(Date.now() - startedAt < 2000, true);
});

test('PanelDb terminal transitions cannot overwrite an earlier shutdown interruption', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-terminal-'));
  const db = new PanelDb(path.join(directory, 'panel.sqlite3'));
  const claimKey = 'phase3:email:terminal-guard@example.test';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  const interruption = await db.updateJob(job.id, {
    status: 'interrupted',
    error: 'service stopped',
    finishedAt: new Date().toISOString(),
  });
  assert.equal(interruption.applied, true);
  assert.equal(interruption.currentStatus, 'interrupted');
  const replay = await updateTerminalJob(db, job.id, {
    status: 'interrupted',
    error: 'must not replace the first terminal error',
    result: { mustNotBeStored: true },
  });
  assert.equal(replay.applied, false);
  assert.equal(replay.idempotent, true);
  assert.equal(replay.currentStatus, 'interrupted');
  await assert.rejects(
    db.updateJob(job.id, {
      status: 'succeeded',
      result: { shouldNotReplace: true },
      finishedAt: new Date().toISOString(),
    }),
    (error) => error.code === 'JOB_STATUS_CONFLICT'
      && error.currentStatus === 'interrupted',
  );
  await assert.rejects(
    updateTerminalJob(db, job.id, {
      status: 'succeeded',
      result: { shouldNotReplace: true },
    }),
    (error) => error.code === 'JOB_STATUS_CONFLICT'
      && error.currentStatus === 'interrupted',
  );
  const persisted = await db.getJob(job.id);
  assert.equal(persisted.status, 'interrupted');
  assert.equal(persisted.result, null);
  assert.equal(persisted.error, 'service stopped');

  const replacement = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  assert.equal(replacement.status, 'queued');
  await db.updateJob(replacement.id, { status: 'failed', error: 'test cleanup' });
});

test('SIGTERM handler closes admission, drains jobs once, and exits successfully', async () => {
  const emitter = new EventEmitter();
  const events = [];
  let resolveClose;
  const fakeServer = {
    listening: true,
    panelLogger: {
      info(event) { events.push(event); },
      warn(event) { events.push(event); },
      error(event) { events.push(event); },
    },
    panelJobManager: {
      activeCount: 1,
      async shutdown() {
        events.push('jobs.shutdown');
        return { active: 0, interrupted: ['job-one'] };
      },
    },
    close(callback) {
      this.listening = false;
      resolveClose = callback;
    },
    closeIdleConnections() { events.push('http.idle_closed'); },
    closeAllConnections() {
      events.push('http.all_closed');
      resolveClose?.();
    },
  };
  const exits = [];
  const remove = installShutdownSignalHandlers(fakeServer, {
    emitter,
    exit(code) { exits.push(code); },
  });
  emitter.emit('SIGTERM');
  emitter.emit('SIGTERM');
  emitter.emit('SIGINT');
  for (let attempt = 0; exits.length === 0 && attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.deepEqual(exits, [0]);
  assert.equal(events.filter((event) => event === 'jobs.shutdown').length, 1);
  assert.equal(emitter.listenerCount('SIGTERM'), 1);
  remove();
  assert.equal(emitter.listenerCount('SIGTERM'), 0);
  assert.equal(events.includes('server.shutdown_started'), true);
  assert.equal(events.includes('server.shutdown_completed'), true);
  assert.equal(fakeServer.listening, false);
  const firstResult = await fakeServer.panelShutdownPromise;
  const repeatedResult = await shutdownServer(fakeServer);
  assert.equal(repeatedResult, firstResult);
});
