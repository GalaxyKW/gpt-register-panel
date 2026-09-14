const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const {
  accountTestTargetBaseline,
  assertAccountTestTargetRevisions,
  classifyAccountTestTargets,
  normalizeAccountTestModelId,
  normalizeAccountTestRequest,
  runAccountTestJob: runAccountTestJobWithoutLogger,
  runAccountTestJobNow: runAccountTestJobNowWithoutLogger,
} = require('../backend/accountTestWorker');
const {
  accountTestTargetRevision,
  createAccountTargetRevisionIssuer,
} = require('../backend/accountTargetRevision');
const { parseSseEvents } = require('../backend/adapters/sub2apiAdmin');
const { withControlPlaneLock } = require('../backend/taskCoordinator');
const { PanelDb } = require('../backend/db');

const testAuditLogger = {
  checkpoint() { return true; },
  info() {},
  warn() {},
  error() {},
};

function runAccountTestJob(args = {}) {
  return runAccountTestJobWithoutLogger({ logger: testAuditLogger, ...args });
}

function runAccountTestJobNow(args = {}) {
  return runAccountTestJobNowWithoutLogger({ logger: testAuditLogger, ...args });
}

test('queued mutation workers persist a normal failure before the next worker starts', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-terminal-before-unlock-'));
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  const previousLockPath = process.env.PANEL_CONTROL_LOCK_PATH;
  process.env.PANEL_CONTROL_LOCK_PATH = path.join(root, 'control-plane.lock');
  try {
    const first = await db.createJob('account_test', {}, 'tester', {
      claimKeys: ['account_test:terminal-before-unlock:first'],
    });
    const second = await db.createJob('account_test', {}, 'tester', {
      claimKeys: ['account_test:terminal-before-unlock:second'],
    });
    const run = (job, code) => runAccountTestJob({
      accountIds: [],
      targetBaselines: [],
      db,
      jobId: job.id,
      client: {
        async listAccounts() {
          const error = new Error(code);
          error.code = code;
          throw error;
        },
      },
      async persistFailure(error) {
        await db.updateJob(job.id, {
          status: 'failed',
          result: { code: error.code },
          error: error.message,
          finishedAt: new Date().toISOString(),
        });
      },
    });

    const outcomes = await Promise.allSettled([
      run(first, 'FIRST_WORKER_FAILED'),
      run(second, 'SECOND_WORKER_FAILED'),
    ]);
    assert.deepEqual(outcomes.map((outcome) => outcome.reason?.code), [
      'FIRST_WORKER_FAILED',
      'SECOND_WORKER_FAILED',
    ]);
    assert.equal((await db.getJob(first.id)).status, 'failed');
    assert.equal((await db.getJob(second.id)).status, 'failed');
  } finally {
    if (previousLockPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousLockPath;
  }
});

function requestJson(baseUrl, pathname, options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(baseUrl + pathname, {
      method: options.method || 'GET',
      headers: {
        ...(options.body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(options.headers || {}),
      },
    }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => {
        let json = null;
        try { json = body ? JSON.parse(body) : null; } catch {}
        resolve({ status: response.statusCode, body, json });
      });
    });
    request.on('error', reject);
    if (options.body !== undefined) request.end(JSON.stringify(options.body));
    else request.end();
  });
}

function oauthTestAccount(id, status, schedulable, extra = {}) {
  return {
    id,
    name: 'free' + String(id).padStart(5, '0'),
    platform: 'openai',
    type: 'oauth',
    status,
    schedulable,
    identityKeys: ['account:test-account-' + id, 'user:test-user-' + id],
    tokenFingerprints: { access: 'test-fingerprint-' + id },
    ...extra,
  };
}

function targetBaselines(...accounts) {
  return accounts.map((account) => accountTestTargetBaseline(account));
}

test('account test aborts promptly while waiting for the control-plane lock', async () => {
  let markEntered;
  let releaseBlocker;
  const entered = new Promise((resolve) => { markEntered = resolve; });
  const blockerReleased = new Promise((resolve) => { releaseBlocker = resolve; });
  const blocker = withControlPlaneLock(async () => {
    markEntered();
    await blockerReleased;
  });
  await entered;

  const controller = new AbortController();
  let remoteCalls = 0;
  const running = runAccountTestJob({
    accountIds: [1],
    targetBaselines: [],
    jobId: 'account-test-lock-wait',
    signal: controller.signal,
    client: {
      async listAccounts() {
        remoteCalls += 1;
        return [];
      },
    },
  });

  controller.abort();
  const outcome = await Promise.race([
    running.then(
      () => ({ resolved: true }),
      (error) => ({ error }),
    ),
    new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), 500)),
  ]);
  releaseBlocker();
  await blocker;
  await Promise.allSettled([running]);

  assert.equal(outcome.timedOut, undefined);
  assert.equal(outcome.error?.code, 'JOB_INTERRUPTED');
  assert.equal(remoteCalls, 0);
});

async function closeHttpServer(server) {
  if (!server || !server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

test('account test request validation requires one opaque revision per unique positive id', () => {
  const revision4 = 'account-test-v1.' + 'A'.repeat(43);
  const revision2 = 'account-test-v1.' + 'B'.repeat(43);
  assert.deepEqual(normalizeAccountTestRequest({
    targets: [
      { accountId: '4', targetRevision: revision4 },
      { accountId: 2, targetRevision: revision2 },
    ],
    modelId: '5.6-luna',
  }), {
    targets: [
      { accountId: 4, targetRevision: revision4 },
      { accountId: 2, targetRevision: revision2 },
    ],
    accountIds: [4, 2],
    modelId: 'gpt-5.6-luna',
    prompt: '',
  });
  assert.equal(normalizeAccountTestModelId('5.6-luna'), 'gpt-5.6-luna');
  assert.equal(normalizeAccountTestModelId('gpt-5.6-luna'), 'gpt-5.6-luna');
  assert.throws(
    () => normalizeAccountTestRequest({ accountIds: [4] }),
    (error) => error.code === 'ACCOUNT_TEST_TARGET_REVISION_REQUIRED',
  );
  assert.throws(
    () => normalizeAccountTestRequest({
      targets: [{ accountId: 0, targetRevision: revision4 }],
    }),
    /正整数/,
  );
  assert.throws(
    () => normalizeAccountTestRequest({
      targets: [
        { accountId: 4, targetRevision: revision4 },
        { accountId: 4, targetRevision: revision4 },
      ],
    }),
    (error) => error.code === 'ACCOUNT_TEST_TARGET_DUPLICATE',
  );
  assert.throws(
    () => normalizeAccountTestRequest({
      targets: [{ accountId: 4, targetRevision: revision4, ignored: true }],
    }),
    (error) => error.code === 'ACCOUNT_TEST_TARGET_INVALID',
  );
  assert.throws(
    () => normalizeAccountTestRequest({
      targets: [{ accountId: 4, targetRevision: 'forged' }],
    }),
    (error) => error.code === 'ACCOUNT_TEST_TARGET_REVISION_INVALID',
  );
  assert.throws(() => normalizeAccountTestRequest({
    targets: [{ accountId: 4, targetRevision: revision4 }],
    modelId: 5,
  }), /modelId/);
});

test('account test target revisions are process-scoped, opaque, and bind recovery inputs', () => {
  const account = oauthTestAccount(41, 'active', true, {
    schemaValid: true,
    platform: 'OpenAI',
    type: 'OAuth',
    accountId: '{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}',
    userId: 'user-41',
    identityKeys: [
      'user:user-41',
      'account:{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}',
    ],
    tokenFingerprints: { access: '1111111111111111', refresh: '2222222222222222', id: null },
    credentialPresence: { access: 'present', refresh: 'present', id: 'absent' },
    autoPauseOnExpired: true,
    expiresAt: '2099-01-01T00:00:00.000Z',
    expiryStatus: 'valid',
    credentialExpiresAt: '2098-01-01T00:00:00.000Z',
    credentialExpiryStatus: 'valid',
    tempUnschedulableUntil: null,
    tempUnschedulableUntilStatus: 'missing',
    rateLimitResetAt: null,
    rateLimitResetStatus: 'missing',
    overloadUntil: null,
    overloadUntilStatus: 'missing',
  });
  const issuerA = createAccountTargetRevisionIssuer(Buffer.alloc(32, 1));
  const issuerB = createAccountTargetRevisionIssuer(Buffer.alloc(32, 2));
  const revision = issuerA.issue(account);
  assert.match(revision, /^account-test-v1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(revision.includes('user-41'), false);
  assert.equal(revision.includes('1111111111111111'), false);
  assert.equal(issuerA.matches(revision, account), true);
  assert.equal(issuerB.matches(revision, account), false);
  assert.equal(accountTestTargetRevision(account), accountTestTargetRevision({
    ...account,
    platform: 'openai',
    type: 'oauth',
    accountId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    identityKeys: [
      'account:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      'user:user-41',
    ],
  }));

  const changes = [
    { status: 'error' },
    { schedulable: false },
    { tokenFingerprints: { ...account.tokenFingerprints, access: '3333333333333333' } },
    { credentialPresence: { ...account.credentialPresence, refresh: 'absent' } },
    { userId: 'replacement-user', identityKeys: ['account:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'user:replacement-user'] },
    { expiresAt: '2099-02-01T00:00:00.000Z' },
    { tempUnschedulableUntil: '2097-01-01T00:00:00.000Z', tempUnschedulableUntilStatus: 'valid' },
  ];
  for (const change of changes) {
    assert.equal(issuerA.matches(revision, { ...account, ...change }), false);
  }
  assert.doesNotThrow(() => assertAccountTestTargetRevisions(
    [account],
    [{ accountId: 41, targetRevision: accountTestTargetRevision(account) }],
  ));
  assert.throws(
    () => assertAccountTestTargetRevisions(
      [{ ...account, userId: 'replacement-user', identityKeys: ['user:replacement-user'] }],
      [{ accountId: 41, targetRevision: accountTestTargetRevision(account) }],
    ),
    (error) => error.code === 'ACCOUNT_TEST_TARGET_REVISION_STALE',
  );
});

test('account test target classification accepts non-error accounts and rejects duplicates', () => {
  const activeJob = { id: 'job_existing', status: 'running', type: 'account_test' };
  const result = classifyAccountTestTargets([
    oauthTestAccount(1, 'error', false, { name: 'error' }),
    oauthTestAccount(2, 'active', true, { name: 'active' }),
    oauthTestAccount(3, 'error', false, { name: 'other-error' }),
  ], [1, 2, 3, 4], new Map([['3', activeJob]]));
  assert.deepEqual(result.eligible.map((item) => item.id), [1, 2]);
  assert.deepEqual(result.rejected.map((item) => item.code), [
    'account_test_already_running',
    'account_not_found',
  ]);
});

test('account test baseline binds normalized submission state without raw identity values', () => {
  const account = oauthTestAccount(21, 'ACTIVE', true);
  const baseline = accountTestTargetBaseline(account);
  assert.deepEqual({
    accountId: baseline.accountId,
    status: baseline.status,
    statusKnown: baseline.statusKnown,
    schedulable: baseline.schedulable,
    schedulableKnown: baseline.schedulableKnown,
  }, {
    accountId: 21,
    status: 'active',
    statusKnown: true,
    schedulable: true,
    schedulableKnown: true,
  });
  assert.match(baseline.identityDigest, /^[a-f0-9]{64}$/);
  assert.match(baseline.targetDigest, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(baseline).includes('test-account-21'), false);
  assert.equal(JSON.stringify(baseline).includes('test-user-21'), false);
  assert.equal(JSON.stringify(baseline).includes('test-fingerprint-21'), false);
});

function fakeWorkerDb() {
  return {
    async startMutationJob() {},
    async updateJob() {},
    async audit() {},
  };
}

test('account test requires a durable log checkpoint immediately before dispatch', async () => {
  const account = oauthTestAccount(9, 'active', true);
  const events = [];
  let testCalls = 0;
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() { return { ...account }; },
    async testAccount() {
      testCalls += 1;
      events.push('test');
      return { success: true };
    },
  };
  const logger = {
    checkpoint(event) {
      events.push(event);
      return false;
    },
    info() {},
    warn() {},
    error() {},
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [9],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-audit-checkpoint-blocks-probe',
    client,
    logger,
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_test_failed');
  assert.equal(testCalls, 0);
  assert.deepEqual(events, ['account_test.test_mutation_checkpoint']);
});

test('account test checkpoints the probe before calling Sub2API', async () => {
  const account = oauthTestAccount(10, 'active', true);
  const events = [];
  const client = {
    async listAccounts(options) {
      assert.equal(options.requireTotal, true);
      assert.equal(options.requirePaginationMetadata, true);
      return [{ ...account }];
    },
    async getAccount() { return { ...account }; },
    async testAccount() {
      events.push('test');
      return { success: true };
    },
  };
  const logger = {
    checkpoint(event) {
      events.push(event);
      return true;
    },
    info() {},
    warn() {},
    error() {},
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [10],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-audit-checkpoint-before-probe',
    client,
    logger,
  });
  assert.equal(outcome.succeeded, 1);
  assert.deepEqual(events.slice(0, 2), [
    'account_test.test_mutation_checkpoint',
    'test',
  ]);
});

test('scheduler enable is not dispatched when its log checkpoint fails', async () => {
  const account = oauthTestAccount(13, 'error', false);
  const checkpoints = [];
  let schedulerWrites = 0;
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() { return { ...account }; },
    async testAccount() { return { success: true }; },
    async setSchedulable() {
      schedulerWrites += 1;
      return { ...account, schedulable: true };
    },
  };
  const logger = {
    checkpoint(event) {
      checkpoints.push(event);
      return event !== 'account_test.scheduler_enable_checkpoint';
    },
    info() {},
    warn() {},
    error() {},
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [13],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-audit-checkpoint-blocks-enable',
    client,
    logger,
  });
  assert.equal(schedulerWrites, 0);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.deepEqual(checkpoints, [
    'account_test.test_mutation_checkpoint',
    'account_test.scheduler_enable_checkpoint',
  ]);
});

test('scheduler rollback is not dispatched when its log checkpoint fails', async () => {
  let account = oauthTestAccount(14, 'error', false);
  const schedulerWrites = [];
  const checkpoints = [];
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() { return { ...account }; },
    async testAccount() {
      account = {
        ...account,
        status: 'active',
        tempUnschedulableUntil: '2099-01-01T00:00:00.000Z',
      };
      return { success: true };
    },
    async setSchedulable(id, value) {
      assert.equal(id, 14);
      schedulerWrites.push(value);
      account = { ...account, schedulable: value };
      return { ...account };
    },
  };
  const logger = {
    checkpoint(event) {
      checkpoints.push(event);
      return event !== 'account_test.scheduler_rollback_checkpoint';
    },
    info() {},
    warn() {},
    error() {},
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [14],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-audit-checkpoint-blocks-rollback',
    client,
    logger,
  });
  assert.deepEqual(schedulerWrites, [true]);
  assert.equal(account.schedulable, true);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.results[0].code, 'account_scheduler_reconciliation_required');
  assert.equal(outcome.results[0].reconciliationScope, 'scheduler');
  assert.deepEqual(checkpoints, [
    'account_test.test_mutation_checkpoint',
    'account_test.scheduler_enable_checkpoint',
    'account_test.scheduler_rollback_checkpoint',
  ]);
});

test('error-account recovery preserves an originally enabled scheduler when recovery is unconfirmed', async () => {
  let account = oauthTestAccount(11, 'error', true);
  const schedulableCalls = [];
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() { return { ...account }; },
    async testAccount() { return { success: true }; },
    async setSchedulable(id, value) {
      assert.equal(id, 11);
      schedulableCalls.push(value);
      account = { ...account, schedulable: value };
      return { ...account };
    },
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [11],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-error-enabled',
    client,
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_recovery_not_confirmed');
  assert.equal(outcome.results[0].enabled, true);
  assert.deepEqual(schedulableCalls, []);
  assert.equal(account.schedulable, true);
});

test('error-account recovery checks temporary blockers and confirms scheduler rollback', async () => {
  let account = oauthTestAccount(12, 'error', false);
  const schedulableCalls = [];
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() { return { ...account }; },
    async testAccount() {
      account = {
        ...account,
        status: 'active',
        tempUnschedulableUntil: '2099-01-01T00:00:00.000Z',
      };
      return { success: true };
    },
    async setSchedulable(id, value) {
      assert.equal(id, 12);
      schedulableCalls.push(value);
      account = { ...account, schedulable: value };
      return { ...account };
    },
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [12],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-error-blocked',
    client,
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_recovery_not_confirmed');
  assert.equal(outcome.results[0].enabled, false);
  assert.deepEqual(schedulableCalls, [true, false]);
  assert.equal(account.schedulable, false);
});

test('non-error success re-reads state and does not report a stale pre-test snapshot', async () => {
  let account = oauthTestAccount(13, 'active', true);
  const client = {
    async listAccounts() { return [{ ...account }]; },
    async getAccount() { return { ...account }; },
    async testAccount() {
      account = { ...account, status: 'error', schedulable: false };
      return { success: true };
    },
    async setSchedulable() { throw new Error('non-error account must not be modified'); },
  };
  const outcome = await runAccountTestJobNow({
    accountIds: [13],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-active-state-change',
    client,
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_state_changed_after_test');
  assert.equal(outcome.results[0].testSuccess, true);
  assert.equal(outcome.results[0].statusBefore, 'active');
  assert.equal(outcome.results[0].statusAfter, 'error');
  assert.equal(outcome.results[0].enabled, false);
});

test('account tests do not probe an ID whose strong identity changed after listing', async () => {
  const listed = oauthTestAccount(14, 'error', false);
  const replaced = oauthTestAccount(14, 'error', false, {
    identityKeys: ['account:replacement-account', 'user:replacement-user'],
  });
  let testCalls = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [14],
    targetBaselines: targetBaselines(listed),
    db: fakeWorkerDb(),
    jobId: 'test-target-replaced-before-probe',
    client: {
      async listAccounts() { return [listed]; },
      async getAccount() { return replaced; },
      async testAccount() { testCalls += 1; return { success: true }; },
      async setSchedulable() { throw new Error('replacement must not be modified'); },
    },
  });
  assert.equal(outcome.failed, 1);
  assert.equal(testCalls, 0);
  assert.equal(outcome.results[0].testSuccess, false);
});

test('account tests reject a numeric ID reused before the worker takes its first snapshot', async () => {
  const submitted = oauthTestAccount(19, 'error', false);
  const replacement = oauthTestAccount(19, 'error', false, {
    identityKeys: ['account:replacement-before-worker', 'user:replacement-before-worker'],
  });
  let testCalls = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [19],
    targetBaselines: targetBaselines(submitted),
    db: fakeWorkerDb(),
    jobId: 'test-target-reused-before-worker-list',
    client: {
      async listAccounts() { return [replacement]; },
      async getAccount() { return replacement; },
      async testAccount() { testCalls += 1; return { success: true }; },
      async setSchedulable() { throw new Error('replacement must not be modified'); },
    },
  });
  assert.equal(outcome.failed, 1);
  assert.equal(testCalls, 0);
  assert.match(outcome.results[0].message, /强身份/);
});

test('account tests reject submission state changes before the first worker snapshot', async () => {
  const submitted = oauthTestAccount(22, 'active', true);
  const changed = oauthTestAccount(22, 'error', false);
  let getCalls = 0;
  let testCalls = 0;
  let schedulableCalls = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [22],
    targetBaselines: targetBaselines(submitted),
    db: fakeWorkerDb(),
    jobId: 'test-submitted-state-changed-before-worker-list',
    client: {
      async listAccounts() { return [changed]; },
      async getAccount() { getCalls += 1; return changed; },
      async testAccount() { testCalls += 1; return { success: true }; },
      async setSchedulable() { schedulableCalls += 1; return changed; },
    },
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'ACCOUNT_TEST_SUBMITTED_STATE_CHANGED');
  assert.equal(outcome.results[0].statusBefore, 'active');
  assert.equal(testCalls, 0);
  assert.equal(schedulableCalls, 0);
  // A failure snapshot is allowed, but no mutating/test endpoint is called.
  assert.equal(getCalls, 1);
});

test('account tests reject submission state changes between list and pre-test detail reads', async () => {
  const submitted = oauthTestAccount(24, 'active', true);
  const changed = oauthTestAccount(24, 'error', false);
  let testCalls = 0;
  let schedulableCalls = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [24],
    targetBaselines: targetBaselines(submitted),
    db: fakeWorkerDb(),
    jobId: 'test-submitted-state-changed-before-detail-read',
    client: {
      async listAccounts() { return [submitted]; },
      async getAccount() { return changed; },
      async testAccount() { testCalls += 1; return { success: true }; },
      async setSchedulable() { schedulableCalls += 1; return changed; },
    },
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'ACCOUNT_TEST_SUBMITTED_STATE_CHANGED');
  assert.equal(outcome.results[0].testSuccess, false);
  assert.equal(testCalls, 0);
  assert.equal(schedulableCalls, 0);
});

test('account tests reject credential changes in the admission-to-worker queue window', async () => {
  const submitted = oauthTestAccount(42, 'active', true, {
    tokenFingerprints: { access: '1111111111111111', refresh: null, id: null },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'absent' },
  });
  const changed = {
    ...submitted,
    tokenFingerprints: { ...submitted.tokenFingerprints, access: '2222222222222222' },
  };
  let testCalls = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [42],
    targetBaselines: targetBaselines(submitted),
    db: fakeWorkerDb(),
    jobId: 'test-submitted-credential-changed-before-worker-list',
    client: {
      async listAccounts() { return [changed]; },
      async getAccount() { return changed; },
      async testAccount() { testCalls += 1; return { success: true }; },
    },
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'ACCOUNT_TEST_SUBMITTED_TARGET_CHANGED');
  assert.equal(testCalls, 0);
});

test('account test workers fail closed when a persisted target baseline is missing', async () => {
  const account = oauthTestAccount(20, 'active', true);
  let listCalls = 0;
  await assert.rejects(
    runAccountTestJobNow({
      accountIds: [20],
      targetBaselines: [],
      db: fakeWorkerDb(),
      jobId: 'test-target-baseline-missing',
      client: {
        async listAccounts() { listCalls += 1; return [account]; },
      },
    }),
    (error) => error?.code === 'ACCOUNT_TEST_BASELINE_INVALID',
  );
  assert.equal(listCalls, 0);
});

test('account test workers fail closed for pre-revision persisted baselines', async () => {
  const account = oauthTestAccount(23, 'active', true);
  const legacyBaseline = accountTestTargetBaseline(account);
  delete legacyBaseline.targetDigest;
  let listCalls = 0;
  await assert.rejects(
    runAccountTestJobNow({
      accountIds: [23],
      targetBaselines: [legacyBaseline],
      db: fakeWorkerDb(),
      jobId: 'test-legacy-target-baseline',
      client: {
        async listAccounts() { listCalls += 1; return [account]; },
      },
    }),
    (error) => error?.code === 'ACCOUNT_TEST_BASELINE_INVALID',
  );
  assert.equal(listCalls, 0);
});

test('scheduler recovery rejects a write response for a replaced identity', async () => {
  let account = oauthTestAccount(15, 'error', false);
  const replacement = oauthTestAccount(15, 'active', true, {
    identityKeys: ['account:replacement-account', 'user:replacement-user'],
  });
  const schedulableCalls = [];
  let reads = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [15],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-target-replaced-during-enable',
    client: {
      async listAccounts() { return [{ ...account }]; },
      async getAccount() {
        reads += 1;
        return reads <= 2 ? { ...account } : { ...replacement };
      },
      async testAccount() {
        account = { ...account, status: 'active' };
        return { success: true };
      },
      async setSchedulable(id, value) {
        schedulableCalls.push({ id, value });
        return { ...replacement };
      },
    },
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].testSuccess, true);
  assert.equal(outcome.results[0].code, 'account_scheduler_reconciliation_required');
  assert.equal(outcome.results[0].requiresReconciliation, true);
  assert.equal(outcome.results[0].writeOutcomeUnknown, true);
  assert.equal(outcome.results[0].enabled, null);
  assert.deepEqual(schedulableCalls, [{ id: 15, value: true }]);
});

test('scheduler rollback does not adopt state changed after its write response', async () => {
  let account = oauthTestAccount(18, 'error', false);
  const schedulableCalls = [];
  let concurrentChangePending = false;
  const outcome = await runAccountTestJobNow({
    accountIds: [18],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-concurrent-change-after-enable',
    client: {
      async listAccounts() { return [{ ...account }]; },
      async getAccount() {
        if (concurrentChangePending) {
          concurrentChangePending = false;
          account = {
            ...account,
            tokenFingerprints: { access: 'concurrent-admin-fingerprint' },
          };
        }
        return { ...account, tokenFingerprints: { ...account.tokenFingerprints } };
      },
      async testAccount() {
        account = {
          ...account,
          status: 'active',
          tempUnschedulableUntil: '2099-01-01T00:00:00.000Z',
        };
        return { success: true };
      },
      async setSchedulable(id, value) {
        assert.equal(id, 18);
        schedulableCalls.push(value);
        account = { ...account, schedulable: value };
        if (value === true) concurrentChangePending = true;
        return { ...account, tokenFingerprints: { ...account.tokenFingerprints } };
      },
    },
  });
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_scheduler_reconciliation_required');
  assert.equal(outcome.results[0].requiresReconciliation, true);
  assert.equal(outcome.results[0].reconciliationReason, 'rollback_state_changed');
  assert.equal(outcome.results[0].writeOutcomeUnknown, false);
  assert.equal(outcome.results[0].enabled, null);
  assert.deepEqual(schedulableCalls, [true]);
  assert.equal(account.schedulable, true);
  assert.equal(account.tokenFingerprints.access, 'concurrent-admin-fingerprint');
});

test('mismatched scheduler-rollback response marks the write outcome unknown', async () => {
  let account = oauthTestAccount(30, 'error', false);
  const replacement = oauthTestAccount(30, 'active', false, {
    identityKeys: ['account:replacement-account', 'user:replacement-user'],
  });
  const schedulableCalls = [];
  const outcome = await runAccountTestJobNow({
    accountIds: [30],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-rollback-response-mismatch',
    client: {
      async listAccounts() { return [{ ...account }]; },
      async getAccount() { return { ...account }; },
      async testAccount() {
        account = {
          ...account,
          status: 'active',
          tempUnschedulableUntil: '2099-01-01T00:00:00.000Z',
        };
        return { success: true };
      },
      async setSchedulable(id, value) {
        assert.equal(id, 30);
        schedulableCalls.push(value);
        if (value === true) {
          account = { ...account, schedulable: true };
          return { ...account };
        }
        return { ...replacement };
      },
    },
  });

  assert.deepEqual(schedulableCalls, [true, false]);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_scheduler_reconciliation_required');
  assert.equal(outcome.results[0].reconciliationReason, 'rollback_response_mismatch');
  assert.equal(outcome.results[0].writeOutcomeUnknown, true);
  assert.equal(outcome.results[0].enabled, null);
});

test('unknown scheduler-enable outcome is persisted and halts the remaining batch without retry', async () => {
  const controller = new AbortController();
  const accounts = [
    oauthTestAccount(25, 'error', false),
    oauthTestAccount(26, 'active', true),
  ];
  let first = accounts[0];
  const schedulableCalls = [];
  const tested = [];
  let persisted = null;
  const outcome = await runAccountTestJobNow({
    accountIds: [25, 26],
    targetBaselines: targetBaselines(...accounts),
    db: fakeWorkerDb(),
    jobId: 'test-enable-outcome-unknown',
    signal: controller.signal,
    persistResult: async (result) => { persisted = result; },
    client: {
      async listAccounts() { return [{ ...first }, { ...accounts[1] }]; },
      async getAccount(id) {
        return id === 25 ? { ...first } : { ...accounts[1] };
      },
      async testAccount(id) {
        tested.push(id);
        first = { ...first, status: 'active' };
        return { success: true };
      },
      async setSchedulable(id, value, options) {
        schedulableCalls.push({ id, value });
        assert.equal(options.signal, controller.signal);
        controller.abort();
        const error = new Error('scheduler response unavailable');
        error.code = 'JOB_INTERRUPTED';
        error.writeOutcomeUnknown = true;
        error.requiresReconciliation = true;
        error.writeOutcomeReason = 'external_abort';
        throw error;
      },
    },
  });

  assert.deepEqual(tested, [25]);
  assert.deepEqual(schedulableCalls, [{ id: 25, value: true }]);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.skipped, 1);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.reconciliationCount, 1);
  assert.equal(outcome.notAttemptedCount, 1);
  assert.equal(outcome.results[0].code, 'account_scheduler_reconciliation_required');
  assert.equal(outcome.results[0].causeCode, 'JOB_INTERRUPTED');
  assert.equal(outcome.results[0].reconciliationReason, 'external_abort');
  assert.equal(outcome.results[0].writeOutcomeUnknown, true);
  assert.equal(outcome.results[0].enabled, null);
  assert.equal(outcome.results[1].code, 'account_test_not_attempted_reconciliation');
  assert.deepEqual(persisted, outcome);
});

test('unknown scheduler-rollback outcome requires reconciliation and is never retried', async () => {
  const controller = new AbortController();
  let account = oauthTestAccount(27, 'error', false);
  const schedulableCalls = [];
  const outcome = await runAccountTestJobNow({
    accountIds: [27],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-rollback-outcome-unknown',
    signal: controller.signal,
    client: {
      async listAccounts() { return [{ ...account }]; },
      async getAccount() { return { ...account }; },
      async testAccount() {
        account = {
          ...account,
          status: 'active',
          tempUnschedulableUntil: '2099-01-01T00:00:00.000Z',
        };
        return { success: true };
      },
      async setSchedulable(id, value, options) {
        schedulableCalls.push({ id, value });
        assert.equal(options.signal, controller.signal);
        if (value === true) {
          account = { ...account, schedulable: true };
          return { ...account };
        }
        const error = new Error('scheduler rollback timed out');
        error.code = 'SUB2API_TIMEOUT';
        error.writeOutcomeUnknown = true;
        error.requiresReconciliation = true;
        error.writeOutcomeReason = 'timeout';
        throw error;
      },
    },
  });

  assert.deepEqual(schedulableCalls, [
    { id: 27, value: true },
    { id: 27, value: false },
  ]);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.results[0].code, 'account_scheduler_reconciliation_required');
  assert.equal(outcome.results[0].causeCode, 'SUB2API_TIMEOUT');
  assert.equal(outcome.results[0].reconciliationReason, 'timeout');
  assert.equal(outcome.results[0].writeOutcomeUnknown, true);
  assert.equal(outcome.results[0].enabled, null);
});

test('unknown dispatched account-test outcome is persisted and halts without scheduler writes', async () => {
  const controller = new AbortController();
  const accounts = [
    oauthTestAccount(31, 'error', false),
    oauthTestAccount(32, 'active', true),
  ];
  const tested = [];
  let schedulerWrites = 0;
  let persisted = null;
  const audits = [];
  const outcome = await runAccountTestJobNow({
    accountIds: [31, 32],
    targetBaselines: targetBaselines(...accounts),
    db: {
      async startMutationJob() {},
      async updateJob() {},
      async audit(entry) { audits.push(entry); },
    },
    jobId: 'test-account-outcome-unknown',
    signal: controller.signal,
    persistResult: async (result) => { persisted = result; },
    client: {
      async listAccounts() { return accounts.map((account) => ({ ...account })); },
      async getAccount(id) { return { ...accounts.find((account) => account.id === id) }; },
      async testAccount(id) {
        tested.push(id);
        controller.abort();
        const error = new Error('Bearer must-not-enter-the-result');
        error.code = 'JOB_INTERRUPTED';
        error.requiresReconciliation = true;
        error.testOutcomeUnknown = true;
        error.reconciliationScope = 'test';
        error.reconciliationReason = 'external_abort';
        throw error;
      },
      async setSchedulable() { schedulerWrites += 1; },
    },
  });

  assert.deepEqual(tested, [31]);
  assert.equal(schedulerWrites, 0);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.skipped, 1);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].causeCode, 'JOB_INTERRUPTED');
  assert.equal(outcome.results[0].testOutcomeUnknown, true);
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.equal(outcome.results[0].reconciliationReason, 'external_abort');
  assert.equal(outcome.results[0].testSuccess, null);
  assert.equal(outcome.results[0].testSuccessKnown, false);
  assert.equal(outcome.results[0].enabled, null);
  assert.equal(outcome.results[0].statusAfter, null);
  assert.equal(outcome.results[1].code, 'account_test_not_attempted_reconciliation');
  assert.deepEqual(persisted, outcome);
  assert.equal(audits[0].details.testSuccess, null);
  assert.equal(audits[0].details.testSuccessKnown, false);
  assert.equal(audits[0].details.enabled, null);
  assert.equal(audits[0].details.enabledKnown, false);
  assert.equal(audits[0].details.statusAfter, null);
  assert.equal(audits[0].details.statusAfterKnown, false);
  assert.equal(JSON.stringify(outcome).includes('must-not-enter-the-result'), false);
});

test('successful test interrupted before postflight is persisted for reconciliation', async () => {
  const controller = new AbortController();
  const accounts = [
    oauthTestAccount(33, 'active', true),
    oauthTestAccount(34, 'active', true),
  ];
  const tested = [];
  let reads = 0;
  let schedulerWrites = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [33, 34],
    targetBaselines: targetBaselines(...accounts),
    db: fakeWorkerDb(),
    jobId: 'test-success-postflight-interrupted',
    signal: controller.signal,
    client: {
      async listAccounts() { return accounts.map((account) => ({ ...account })); },
      async getAccount(id) {
        reads += 1;
        return { ...accounts.find((account) => account.id === id) };
      },
      async testAccount(id) {
        tested.push(id);
        controller.abort();
        return { success: true };
      },
      async setSchedulable() { schedulerWrites += 1; },
    },
  });

  assert.deepEqual(tested, [33]);
  assert.equal(reads, 1);
  assert.equal(schedulerWrites, 0);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.skipped, 1);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].testOutcomeUnknown, false);
  assert.equal(outcome.results[0].testSuccess, true);
  assert.equal(outcome.results[0].testSuccessKnown, true);
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.equal(outcome.results[0].reconciliationReason, 'post_test_interrupted');
  assert.equal(outcome.results[0].enabled, null);
  assert.equal(outcome.results[0].statusAfter, null);
});

test('known successful model mismatch is reconciled and stops the remaining batch', async () => {
  const accounts = [
    oauthTestAccount(36, 'active', true),
    oauthTestAccount(37, 'active', true),
  ];
  const tested = [];
  let schedulerWrites = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [36, 37],
    targetBaselines: targetBaselines(...accounts),
    db: fakeWorkerDb(),
    jobId: 'test-model-mismatch-reconciliation',
    client: {
      async listAccounts() { return accounts.map((account) => ({ ...account })); },
      async getAccount(id) { return { ...accounts.find((account) => account.id === id) }; },
      async testAccount(id) {
        tested.push(id);
        const error = new Error('Bearer must-not-enter-the-result');
        error.code = 'SUB2API_TEST_MODEL_MISMATCH';
        error.requiresReconciliation = true;
        error.reconciliationScope = 'test';
        error.reconciliationReason = 'model_mismatch';
        error.testSuccess = true;
        error.testSuccessKnown = true;
        throw error;
      },
      async setSchedulable() { schedulerWrites += 1; },
    },
  });

  assert.deepEqual(tested, [36]);
  assert.equal(schedulerWrites, 0);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.skipped, 1);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].causeCode, 'SUB2API_TEST_MODEL_MISMATCH');
  assert.equal(outcome.results[0].testOutcomeUnknown, false);
  assert.equal(outcome.results[0].testSuccess, true);
  assert.equal(outcome.results[0].testSuccessKnown, true);
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.equal(outcome.results[0].reconciliationReason, 'model_mismatch');
  assert.equal(outcome.results[0].enabled, null);
  assert.equal(outcome.results[0].statusAfter, null);
  assert.equal(outcome.results[1].code, 'account_test_not_attempted_reconciliation');
  assert.equal(JSON.stringify(outcome).includes('must-not-enter-the-result'), false);
});

test('successful test reconciles a replaced non-error account without scheduler writes', async () => {
  const account = oauthTestAccount(38, 'active', true);
  const replacement = oauthTestAccount(38, 'active', true, {
    identityKeys: ['account:replacement-account-38', 'user:replacement-user-38'],
  });
  let reads = 0;
  let schedulerWrites = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [38],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-non-error-postflight-target-replaced',
    client: {
      async listAccounts() { return [{ ...account }]; },
      async getAccount() {
        reads += 1;
        return reads === 1 ? { ...account } : { ...replacement };
      },
      async testAccount() { return { success: true }; },
      async setSchedulable() { schedulerWrites += 1; },
    },
  });

  assert.equal(reads, 2);
  assert.equal(schedulerWrites, 0);
  assert.equal(outcome.failed, 1);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].causeCode, 'ACCOUNT_TEST_TARGET_CHANGED');
  assert.equal(outcome.results[0].testSuccess, true);
  assert.equal(outcome.results[0].testSuccessKnown, true);
  assert.equal(outcome.results[0].testOutcomeUnknown, false);
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.equal(outcome.results[0].reconciliationReason, 'post_test_target_changed');
  assert.equal(outcome.results[0].enabled, null);
  assert.equal(outcome.results[0].statusAfter, null);
});

test('failed test with an unavailable postflight state requires reconciliation and stops the batch', async () => {
  const account = oauthTestAccount(35, 'active', true);
  const laterAccount = oauthTestAccount(36, 'active', true);
  let reads = 0;
  let testCalls = 0;
  const outcome = await runAccountTestJobNow({
    accountIds: [35, 36],
    targetBaselines: targetBaselines(account, laterAccount),
    db: fakeWorkerDb(),
    jobId: 'test-failure-diagnostic-unavailable',
    client: {
      async listAccounts() { return [{ ...account }, { ...laterAccount }]; },
      async getAccount() {
        reads += 1;
        if (reads === 1) return { ...account };
        throw new Error('diagnostic unavailable');
      },
      async testAccount() { testCalls += 1; return { success: false }; },
    },
  });

  assert.equal(outcome.failed, 1);
  assert.equal(outcome.skipped, 1);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.reconciliationCount, 1);
  assert.equal(outcome.notAttemptedCount, 1);
  assert.equal(testCalls, 1);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].causeCode, 'ACCOUNT_TEST_POSTFLIGHT_UNAVAILABLE');
  assert.equal(outcome.results[0].testSuccess, false);
  assert.equal(outcome.results[0].testSuccessKnown, true);
  assert.equal(outcome.results[0].testOutcomeUnknown, false);
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.equal(outcome.results[0].reconciliationReason, 'post_test_state_unconfirmed');
  assert.equal(outcome.results[0].enabled, null);
  assert.equal(outcome.results[0].enabledKnown, false);
  assert.equal(outcome.results[0].statusAfter, null);
  assert.equal(outcome.results[0].statusAfterKnown, false);
  assert.equal(outcome.results[1].accountId, 36);
  assert.equal(outcome.results[1].code, 'account_test_not_attempted_reconciliation');
  assert.equal(JSON.stringify(outcome).includes('diagnostic unavailable'), false);
});

test('shutdown after a known failed test persists reconciliation and stops the remaining batch', async () => {
  const account = oauthTestAccount(28, 'active', true);
  const unattempted = oauthTestAccount(39, 'active', true);
  const controller = new AbortController();
  let reads = 0;
  let testCalls = 0;
  let persistedResult = null;
  let markDiagnosticStarted;
  const diagnosticStarted = new Promise((resolve) => { markDiagnosticStarted = resolve; });
  const running = runAccountTestJobNow({
    accountIds: [28, 39],
    targetBaselines: targetBaselines(account, unattempted),
    db: fakeWorkerDb(),
    jobId: 'test-failure-diagnostic-cancellation',
    signal: controller.signal,
    async persistResult(result) { persistedResult = result; },
    client: {
      async listAccounts() { return [{ ...account }, { ...unattempted }]; },
      async getAccount(id, options = {}) {
        assert.equal(id, 28);
        reads += 1;
        if (reads === 1) return { ...account };
        assert.equal(options.signal, controller.signal);
        markDiagnosticStarted();
        return new Promise((resolve, reject) => {
          options.signal.addEventListener('abort', () => {
            const error = new Error('diagnostic read interrupted');
            error.code = 'JOB_INTERRUPTED';
            reject(error);
          }, { once: true });
        });
      },
      async testAccount() {
        testCalls += 1;
        return { success: false, message: 'safe failure' };
      },
    },
  });
  await diagnosticStarted;
  controller.abort();
  const outcome = await running;
  assert.equal(reads, 2);
  assert.equal(testCalls, 1);
  assert.equal(outcome.requiresReconciliation, true);
  assert.equal(outcome.reconciliationCount, 1);
  assert.equal(outcome.notAttemptedCount, 1);
  assert.equal(outcome.results[0].code, 'account_test_reconciliation_required');
  assert.equal(outcome.results[0].testSuccess, false);
  assert.equal(outcome.results[0].testSuccessKnown, true);
  assert.equal(outcome.results[0].testOutcomeUnknown, false);
  assert.equal(outcome.results[0].reconciliationScope, 'test');
  assert.equal(outcome.results[0].reconciliationReason, 'post_test_interrupted');
  assert.equal(outcome.results[1].accountId, 39);
  assert.equal(outcome.results[1].code, 'account_test_not_attempted_reconciliation');
  assert.equal(persistedResult, outcome);
});

test('shutdown cancels the diagnostic read after an account test exception', async () => {
  const account = oauthTestAccount(29, 'active', true);
  const controller = new AbortController();
  let reads = 0;
  let markDiagnosticStarted;
  const diagnosticStarted = new Promise((resolve) => { markDiagnosticStarted = resolve; });
  const running = runAccountTestJobNow({
    accountIds: [29],
    targetBaselines: targetBaselines(account),
    db: fakeWorkerDb(),
    jobId: 'test-exception-diagnostic-cancellation',
    signal: controller.signal,
    client: {
      async listAccounts() { return [{ ...account }]; },
      async getAccount(id, options = {}) {
        assert.equal(id, 29);
        reads += 1;
        if (reads === 1) return { ...account };
        assert.equal(options.signal, controller.signal);
        markDiagnosticStarted();
        return new Promise((resolve, reject) => {
          options.signal.addEventListener('abort', () => {
            const error = new Error('diagnostic read interrupted');
            error.code = 'JOB_INTERRUPTED';
            reject(error);
          }, { once: true });
        });
      },
      async testAccount() {
        const error = new Error('safe test exception');
        error.code = 'SAFE_TEST_FAILURE';
        throw error;
      },
    },
  });
  await diagnosticStarted;
  controller.abort();
  await assert.rejects(running, (error) => error.code === 'JOB_INTERRUPTED');
  assert.equal(reads, 2);
});

test('account-test job deadline skips remaining accounts instead of holding the control lock indefinitely', async () => {
  const accounts = [
    oauthTestAccount(16, 'active', true),
    oauthTestAccount(17, 'active', true),
  ];
  const tested = [];
  const outcome = await runAccountTestJobNow({
    accountIds: [16, 17],
    targetBaselines: targetBaselines(...accounts),
    db: fakeWorkerDb(),
    jobId: 'test-job-deadline',
    jobTimeoutMs: 200,
    client: {
      async listAccounts() { return accounts; },
      async getAccount(id) { return { ...accounts.find((item) => item.id === id) }; },
      async testAccount(id) {
        tested.push(id);
        await new Promise((resolve) => setTimeout(resolve, 250));
        return { success: true };
      },
      async setSchedulable() { throw new Error('active accounts must not be modified'); },
    },
  });
  assert.deepEqual(tested, [16]);
  assert.equal(outcome.succeeded, 1);
  assert.equal(outcome.skipped, 1);
  assert.equal(outcome.results[1].code, 'account_test_job_timeout');
});

test('SSE parsing keeps account test completion and error events without raw credentials', () => {
  const events = parseSseEvents([
    'data: {"type":"test_start","model":"gpt-5"}',
    '',
    'data: {"type":"test_complete","success":true}',
    '',
  ].join('\n'));
  assert.deepEqual(events.map((event) => event.type), ['test_start', 'test_complete']);
});

test('panel account-test endpoint tests error and non-error accounts with scoped recovery', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-account-test-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  const accounts = new Map([
    [1, oauthTestAccount(1, 'error', false, {
      account_id: 'test-account-1',
      user_id: 'test-user-1',
    })],
    [2, oauthTestAccount(2, 'active', true, {
      account_id: 'test-account-2',
      user_id: 'test-user-2',
    })],
    [3, oauthTestAccount(3, 'error', false, {
      account_id: 'test-account-3',
      user_id: 'test-user-3',
    })],
    [4, oauthTestAccount(4, 'error', false, {
      account_id: 'test-account-4',
      user_id: 'test-user-4',
    })],
  ]);
  const testCalls = [];
  const schedulableCalls = [];
  let omitPaginationMetadataOnce = false;
  const upstream = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://upstream.test');
    const idMatch = url.pathname.match(/^\/api\/v1\/admin\/accounts\/(\d+)(?:\/(.*))?$/);
    if (request.method === 'GET' && url.pathname === '/api/v1/admin/accounts') {
      response.setHeader('content-type', 'application/json');
      const page = Number(url.searchParams.get('page') || 1);
      const pageSize = Number(url.searchParams.get('page_size') || 20);
      const rows = page === 1 ? [...accounts.values()] : [];
      const data = {
        items: rows,
        total: accounts.size,
        page,
        page_size: pageSize,
        pages: Math.max(1, Math.ceil(accounts.size / pageSize)),
      };
      if (omitPaginationMetadataOnce) {
        omitPaginationMetadataOnce = false;
        delete data.pages;
      }
      response.end(JSON.stringify({
        code: 0,
        message: 'success',
        data,
      }));
      return;
    }
    if (!idMatch) {
      response.statusCode = 404;
      response.end(JSON.stringify({ message: 'not found' }));
      return;
    }
    const id = Number(idMatch[1]);
    const suffix = idMatch[2] || '';
    const account = accounts.get(id);
    if (!account) {
      response.statusCode = 404;
      response.end(JSON.stringify({ message: 'not found' }));
      return;
    }
    if (request.method === 'GET' && suffix === 'models') {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ data: [{ id: 'gpt-5' }, { id: 'gpt-5-mini' }] }));
      return;
    }
    if (request.method === 'GET' && suffix === '') {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ data: account }));
      return;
    }
    if (request.method === 'POST' && suffix === 'test') {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk) => { body += chunk; });
      request.on('end', () => {
        testCalls.push({ id, body: JSON.parse(body || '{}') });
        response.setHeader('content-type', 'text/event-stream');
        response.setHeader('cache-control', 'no-cache');
        response.write('data: {"type":"test_start","model":"gpt-5"}\n\n');
        if (id === 1 || id === 2) {
          // The real Sub2API test handler performs this recovery before its
          // SSE stream closes; the fake mirrors that contract.
          account.status = 'active';
          response.end('data: {"type":"test_complete","success":true}\n\n');
        } else {
          response.end('data: {"type":"error","error":"upstream rejected probe"}\n\n');
        }
      });
      return;
    }
    if (request.method === 'POST' && suffix === 'schedulable') {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk) => { body += chunk; });
      request.on('end', () => {
        schedulableCalls.push({ id, body: JSON.parse(body || '{}') });
        account.schedulable = JSON.parse(body || '{}').schedulable === true;
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ data: account }));
      });
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ message: 'not found' }));
  });
  const previous = {
    panelWrite: process.env.PANEL_WRITE_ENABLED,
    panelToken: process.env.PANEL_ADMIN_TOKEN,
    baseUrl: process.env.SUB2API_BASE_URL,
    apiKey: process.env.SUB2API_ADMIN_API_KEY,
    jwt: process.env.SUB2API_JWT,
    testTimeout: process.env.SUB2API_TEST_TIMEOUT_MS,
    registerRoot: process.env.GPT_REGISTER_ROOT,
    controlLock: process.env.PANEL_CONTROL_LOCK_PATH,
  };
  let server = null;
  try {
    await new Promise((resolve, reject) => {
      upstream.once('error', reject);
      upstream.listen(0, '127.0.0.1', () => {
        upstream.off('error', reject);
        resolve();
      });
    });
    process.env.PANEL_WRITE_ENABLED = '1';
    process.env.PANEL_ADMIN_TOKEN = 'panel-account-test';
    process.env.SUB2API_BASE_URL = 'http://127.0.0.1:' + upstream.address().port;
    process.env.SUB2API_ADMIN_API_KEY = 'sub2-account-test';
    delete process.env.SUB2API_JWT;
    process.env.SUB2API_TEST_TIMEOUT_MS = '3000';
    process.env.GPT_REGISTER_ROOT = root;
    process.env.PANEL_CONTROL_LOCK_PATH = path.join(root, 'control-plane.lock');

    // server.js is intentionally loaded after the fake environment setup.
    const { createServer } = require('../backend/server');
    server = createServer({
      dbPath: path.join(root, 'panel.sqlite3'),
      logger: {
        checkpoint() { return true; },
        info() {},
        warn() {},
        error() {},
        requestId(value) { return value || 'test-request'; },
        tail() { return []; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    const headers = { 'x-panel-token': 'panel-account-test' };
    const snapshotTargets = async (accountIds) => {
      const snapshot = await requestJson(baseUrl, '/api/snapshot', { headers });
      assert.equal(snapshot.status, 200, snapshot.body);
      return accountIds.map((accountId) => {
        const matches = snapshot.json.rows.filter((row) => Number(row.accountId) === accountId);
        assert.equal(matches.length, 1, 'snapshot must expose exactly one row for account ' + accountId);
        assert.match(matches[0].targetRevision, /^account-test-v1\.[A-Za-z0-9_-]{43}$/);
        return { accountId, targetRevision: matches[0].targetRevision };
      });
    };
    const models = await requestJson(baseUrl, '/api/account-tests/models?accountId=1', { headers });
    assert.equal(models.status, 200);
    assert.deepEqual(models.json.models, ['gpt-5', 'gpt-5-mini']);

    const initialTargets = await snapshotTargets([1, 2, 3, 4]);
    const targetFor = (id) => initialTargets.find((target) => target.accountId === id);

    const legacyNumericOnly = await requestJson(baseUrl, '/api/account-tests', {
      method: 'POST',
      headers,
      body: { accountIds: [2], modelId: 'gpt-5.6-luna' },
    });
    assert.equal(legacyNumericOnly.status, 400);
    assert.equal(legacyNumericOnly.json.error, 'ACCOUNT_TEST_TARGET_REVISION_REQUIRED');
    assert.equal(testCalls.length, 0);

    omitPaginationMetadataOnce = true;
    const incompleteSelection = await requestJson(baseUrl, '/api/account-tests', {
      method: 'POST',
      headers,
      body: { targets: [targetFor(2)], modelId: 'gpt-5.6-luna' },
    });
    assert.equal(incompleteSelection.status, 400);
    assert.equal(incompleteSelection.json.error, 'SUB2API_ACCOUNTS_PAGINATION_REQUIRED');
    assert.equal(testCalls.length, 0);

    const forgedRevision = await requestJson(baseUrl, '/api/account-tests', {
      method: 'POST',
      headers,
      body: {
        targets: [{ accountId: 2, targetRevision: 'account-test-v1.' + 'Z'.repeat(43) }],
        modelId: 'gpt-5.6-luna',
      },
    });
    assert.equal(forgedRevision.status, 409);
    assert.equal(forgedRevision.json.error, 'ACCOUNT_TEST_TARGET_REVISION_STALE');
    assert.equal(testCalls.length, 0);

    accounts.get(3).schedulable = true;
    const staleState = await requestJson(baseUrl, '/api/account-tests', {
      method: 'POST',
      headers,
      body: { targets: [targetFor(3)], modelId: 'gpt-5.6-luna' },
    });
    assert.equal(staleState.status, 409);
    assert.equal(staleState.json.error, 'ACCOUNT_TEST_TARGET_REVISION_STALE');
    assert.equal(testCalls.length, 0);
    accounts.get(3).schedulable = false;

    const queued = await requestJson(baseUrl, '/api/account-tests', {
      method: 'POST',
      headers,
      body: {
        targets: [targetFor(1), targetFor(2)],
        modelId: '5.6-luna',
        prompt: 'unlabelled-private-probe-text',
      },
    });
    assert.equal(queued.status, 202, queued.body);
    assert.deepEqual(queued.json.accountIds, [1, 2]);
    assert.equal(queued.json.rejected?.length || 0, 0);

    let job;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      job = (await requestJson(baseUrl, '/api/jobs/' + encodeURIComponent(queued.json.jobId), { headers })).json;
      if (['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(job.status, 'succeeded');
    assert.equal(JSON.stringify(job.payload).includes('unlabelled-private-probe-text'), false);
    assert.equal(JSON.stringify(job.payload).includes('account-test-v1.'), false);
    assert.equal(job.payload.targetBaselines.every(
      (baseline) => /^[a-f0-9]{64}$/.test(baseline.targetDigest),
    ), true);
    assert.equal(job.payload.promptPresent, true);
    assert.equal(job.payload.promptLength, 'unlabelled-private-probe-text'.length);
    assert.equal(job.result.succeeded, 2);
    assert.equal(accounts.get(1).status, 'active');
    assert.equal(accounts.get(1).schedulable, true);
    assert.deepEqual(testCalls.map((call) => call.id), [1, 2]);
    assert.equal(testCalls[0].body.model_id, 'gpt-5.6-luna');
    assert.equal(testCalls[0].body.prompt, 'unlabelled-private-probe-text');
    assert.deepEqual(schedulableCalls.map((call) => call.id), [1]);
    assert.equal(accounts.get(2).status, 'active');
    assert.equal(accounts.get(2).schedulable, true);

    const failed = await requestJson(baseUrl, '/api/account-tests', {
      method: 'POST',
      headers,
      body: { targets: [targetFor(3)], modelId: 'gpt-5.6-luna' },
    });
    assert.equal(failed.status, 202);
    for (let attempt = 0; attempt < 50; attempt += 1) {
      job = (await requestJson(baseUrl, '/api/jobs/' + encodeURIComponent(failed.json.jobId), { headers })).json;
      if (['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(job.status, 'failed');
    assert.equal(JSON.stringify(job).includes('upstream rejected probe'), false);
    assert.equal(accounts.get(3).status, 'error');
    assert.equal(accounts.get(3).schedulable, false);
    assert.deepEqual(testCalls.map((call) => call.id), [1, 2, 3]);

    accounts.set(4, oauthTestAccount(4, 'error', false, {
      account_id: 'replacement-account-4',
      user_id: 'replacement-user-4',
      identityKeys: ['account:replacement-account-4', 'user:replacement-user-4'],
    }));
    const reused = await requestJson(baseUrl, '/api/account-tests', {
      method: 'POST',
      headers,
      body: { targets: [targetFor(4)], modelId: 'gpt-5.6-luna' },
    });
    assert.equal(reused.status, 409);
    assert.equal(reused.json.error, 'ACCOUNT_TEST_TARGET_REVISION_STALE');
    assert.deepEqual(testCalls.map((call) => call.id), [1, 2, 3]);
    assert.equal(accounts.get(4).account_id, 'replacement-account-4');
    assert.equal(accounts.get(4).schedulable, false);
  } finally {
    let closeFailure = null;
    try {
      const closeResults = await Promise.allSettled([
        closeHttpServer(server),
        closeHttpServer(upstream),
      ]);
      closeFailure = closeResults.find((result) => result.status === 'rejected') || null;
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        const environmentName = {
          panelWrite: 'PANEL_WRITE_ENABLED',
          panelToken: 'PANEL_ADMIN_TOKEN',
          baseUrl: 'SUB2API_BASE_URL',
          apiKey: 'SUB2API_ADMIN_API_KEY',
          jwt: 'SUB2API_JWT',
          testTimeout: 'SUB2API_TEST_TIMEOUT_MS',
          registerRoot: 'GPT_REGISTER_ROOT',
          controlLock: 'PANEL_CONTROL_LOCK_PATH',
        }[key];
        if (value === undefined) delete process.env[environmentName];
        else process.env[environmentName] = value;
      }
    }
    if (closeFailure) throw closeFailure.reason;
  }
});
