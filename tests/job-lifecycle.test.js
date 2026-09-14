const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
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
  updateTerminalJob,
} = require('../backend/jobLifecycle');
const {
  installShutdownSignalHandlers,
  shutdownServer,
} = require('../backend/server');

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

test('account-test worker propagates shutdown cancellation as a job interruption', async () => {
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
          reject(error);
        }, { once: true });
      });
    },
  };
  const run = runAccountTestJobNow({
    accountIds: [17],
    targetBaselines: [accountTestTargetBaseline(account)],
    db: { async updateJob() {}, async audit() {} },
    jobId: 'job-account-interrupt',
    client,
    signal: controller.signal,
  });
  await started;
  controller.abort();
  await assert.rejects(run, (error) => error.code === 'JOB_INTERRUPTED');
});

test('account-test cancellation after a successful probe starts no scheduler mutation', async () => {
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
  await assert.rejects(runAccountTestJobNow({
    accountIds: [18],
    targetBaselines: [accountTestTargetBaseline(account)],
    db: { async updateJob() {}, async audit() {} },
    jobId: 'job-account-post-test-interrupt',
    client,
    signal: controller.signal,
  }), (error) => error.code === 'JOB_INTERRUPTED');
  assert.equal(reads, 1);
  assert.equal(schedulerWrites, 0);
});

test('shutdown drains a concurrently completed job before interrupting remaining DB jobs', async () => {
  const events = [];
  let jobStatus = 'running';
  const db = {
    async interruptOwnedActiveJobs() {
      events.push('interrupt-db');
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
  assert.equal(jobStatus, 'succeeded');
  assert.deepEqual(events, ['worker-aborted', 'worker-finished', 'interrupt-db']);
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
  await db.updateJob(job.id, {
    status: 'interrupted',
    error: 'service stopped',
    finishedAt: new Date().toISOString(),
  });
  await db.updateJob(job.id, {
    status: 'succeeded',
    result: { shouldNotReplace: true },
    finishedAt: new Date().toISOString(),
  });
  const persisted = await db.getJob(job.id);
  assert.equal(persisted.status, 'interrupted');
  assert.equal(persisted.result, null);

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
  emitter.emit('SIGINT');
  for (let attempt = 0; exits.length === 0 && attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  remove();
  assert.deepEqual(exits, [0]);
  assert.equal(events.filter((event) => event === 'jobs.shutdown').length, 1);
  assert.equal(events.includes('server.shutdown_started'), true);
  assert.equal(events.includes('server.shutdown_completed'), true);
  assert.equal(fakeServer.listening, false);
  const firstResult = await fakeServer.panelShutdownPromise;
  const repeatedResult = await shutdownServer(fakeServer);
  assert.equal(repeatedResult, firstResult);
});
