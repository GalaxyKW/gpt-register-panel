'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const {
  classifyPhase3ProcessError,
  findUsernameEntry,
  resolvePhase3Requests,
  runPhase3Job,
} = require('../backend/phase3Worker');
const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
const { phase3TargetRevision } = require('../backend/phase3TargetRevision');
const { withControlPlaneLock } = require('../backend/taskCoordinator');

function phase3Fixture(email, script) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-audit-'));
  fs.mkdirSync(path.join(root, 'tokens'), { mode: 0o700 });
  fs.mkdirSync(path.join(root, 'use_token'), { mode: 0o700 });
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email, password: 'test-only-password', status: 'oauth_done' },
  ]), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), script, { mode: 0o600 });
  return root;
}

function terminalDispositionScript() {
  return [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const file = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(file, 'utf8'));",
    "records[0].status = 'account_deactivated';",
    "records[0].phase3Disposition = 'discard';",
    'records[0].phase3LastAttemptAt = new Date().toISOString();',
    "records[0].phase3LastErrorCode = 'ACCOUNT_DEACTIVATED';",
    'records[0].phase3Retryable = false;',
    "fs.writeFileSync(file, JSON.stringify(records, null, 2));",
    'process.exitCode = 1;',
  ].join('\n');
}

function recordingLogger(checkpoint) {
  const events = [];
  return {
    events,
    checkpoint(event, fields) {
      events.push({ level: 'checkpoint', event, fields });
      return checkpoint(event, fields);
    },
    info(event, fields) { events.push({ level: 'info', event, fields }); },
    warn(event, fields) { events.push({ level: 'warn', event, fields }); },
    error(event, fields) { events.push({ level: 'error', event, fields }); },
  };
}

async function withPhase3Environment(root, callback) {
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  try {
    return await callback();
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
}

function phase3Db() {
  return {
    async audit() {},
    async startMutationJob() {},
    async updateJob() {},
  };
}

function resolveBoundTarget(root, { email, phone = '', selectedKey }) {
  const sources = readGptRegisterSources({
    rootDirectory: root,
    requireValidUsername: true,
    strictCompleteSnapshot: true,
  });
  const selectedToken = sources.tokens.find((token) => (
    `token:${token.source}:${token.relativePath}` === selectedKey
  ));
  const username = sources.usernames.find((record) => (
    String(record.email || '').toLowerCase() === String(email || '').toLowerCase()
  ));
  const revision = phase3TargetRevision({
    token: selectedToken,
    username,
    usernameContentHash: sources.usernameContentHash,
  });
  assert.match(revision, /^phase3-target-v1\.[A-Za-z0-9_-]{43}$/);
  const resolved = resolvePhase3Requests([{
    originalIndex: 0,
    email,
    phone,
    selectedKey,
    phase3TargetRevision: revision,
  }]);
  assert.deepEqual(resolved.rejected, []);
  assert.equal(resolved.eligible.length, 1);
  return resolved.eligible[0];
}

test('Phase3 requires a durable checkpoint immediately before spawning', async () => {
  const email = 'spawn-checkpoint@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "fs.writeFileSync(path.join(process.cwd(), 'spawned'), 'yes');",
  ].join('\n'));
  const logger = recordingLogger(() => false);
  let terminalPersisted = false;
  let followerObservedTerminal = false;
  let markWorkerStarted;
  const workerStarted = new Promise((resolve) => { markWorkerStarted = resolve; });

  await withPhase3Environment(root, async () => {
    const running = runPhase3Job({
      email,
      db: {
        ...phase3Db(),
        async startMutationJob() { markWorkerStarted(); },
      },
      jobId: 'spawn-checkpoint',
      logger,
      async persistFailure(error) {
        assert.equal(error.code, 'AUDIT_LOG_UNAVAILABLE');
        terminalPersisted = true;
      },
    });
    await workerStarted;
    const follower = withControlPlaneLock(() => {
      followerObservedTerminal = terminalPersisted;
    });
    await assert.rejects(
      running,
      (error) => error.code === 'AUDIT_LOG_UNAVAILABLE',
    );
    await follower;
  });

  assert.equal(fs.existsSync(path.join(root, 'spawned')), false);
  assert.equal(followerObservedTerminal, true);
  assert.deepEqual(
    logger.events.filter((item) => item.level === 'checkpoint').map((item) => item.event),
    ['phase3.process_spawn_checkpoint'],
  );
  const startingIndex = logger.events.findIndex(
    (item) => item.event === 'phase3.process_starting',
  );
  const checkpointIndex = logger.events.findIndex(
    (item) => item.event === 'phase3.process_spawn_checkpoint',
  );
  assert.ok(startingIndex >= 0);
  assert.ok(checkpointIndex > startingIndex);
  assert.equal(
    logger.events.some((item) => item.event === 'phase3.process_started'),
    false,
  );
});

test('Phase3 logs process_started only after a successful spawn checkpoint', async () => {
  const email = 'spawn-success@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `const email = ${JSON.stringify(email)};`,
    "fs.writeFileSync(path.join(process.cwd(), 'tokens', 'spawn-success.json'), JSON.stringify({",
    "  email,",
    "  access_token: 'test-only-access-token',",
    "  refresh_token: 'test-only-refresh-token',",
    "  expires_at: '2099-01-01T00:00:00.000Z',",
    "  last_refresh: '2098-01-01T00:00:00.000Z',",
    '}));',
  ].join('\n'));
  const logger = recordingLogger(() => true);

  await withPhase3Environment(root, async () => {
    const result = await runPhase3Job({
      email,
      db: phase3Db(),
      jobId: 'spawn-success',
      logger,
    });
    assert.equal(result.tokenFile, 'tokens/spawn-success.json');
  });

  const eventIndex = (event) => logger.events.findIndex((item) => item.event === event);
  assert.ok(eventIndex('phase3.process_starting') >= 0);
  assert.ok(eventIndex('phase3.process_spawn_checkpoint') > eventIndex('phase3.process_starting'));
  assert.ok(eventIndex('phase3.process_started') > eventIndex('phase3.process_spawn_checkpoint'));
  assert.ok(eventIndex('phase3.process_completed') > eventIndex('phase3.process_started'));
});

test('Phase3 disposition checkpoint failure leaves the child disposition untouched', async () => {
  const email = 'disposition-checkpoint@example.test';
  const root = phase3Fixture(email, terminalDispositionScript());
  const logger = recordingLogger((event) => event !== 'phase3.account_disposition_checkpoint');
  let failure;

  await withPhase3Environment(root, async () => {
    await assert.rejects(
      runPhase3Job({ email, db: phase3Db(), jobId: 'disposition-checkpoint', logger }),
      (error) => {
        failure = error;
        return error.code === 'ACCOUNT_DEACTIVATED';
      },
    );
  });

  const [record] = JSON.parse(fs.readFileSync(path.join(root, 'username.json'), 'utf8'));
  assert.equal(record.status, 'account_deactivated');
  assert.equal(Object.hasOwn(record, 'phase3DispositionAt'), false);
  assert.equal(Object.hasOwn(record, 'phase3ErrorCode'), false);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.notEqual(failure.writeOutcomeUnknown, true);
  assert.equal(failure.dispositionPersisted, false);
  assert.equal(failure.dispositionOutcome, 'not_persisted');
  assert.equal(failure.dispositionErrorCode, 'AUDIT_LOG_UNAVAILABLE');
  assert.equal(failure.reconciliationReason, 'account_disposition_checkpoint_unavailable');
  assert.deepEqual(
    logger.events.filter((item) => item.level === 'checkpoint').map((item) => item.event),
    ['phase3.process_spawn_checkpoint', 'phase3.account_disposition_checkpoint'],
  );
});

test('Phase3 marks a disposition failure after replace dispatch as write-outcome unknown', async () => {
  const email = 'disposition-unknown@example.test';
  const root = phase3Fixture(email, terminalDispositionScript());
  const usernamePath = path.join(root, 'username.json');
  const logger = recordingLogger(() => true);
  const originalRenameSync = fs.renameSync;
  const diagnosticSecret = 'Bearer synthetic-disposition-secret';
  let replacementInjected = false;
  let failure;

  fs.renameSync = function renameThenFail(source, target) {
    const result = originalRenameSync.call(fs, source, target);
    if (path.basename(String(target)) === 'username.json'
        && String(source).startsWith(String(target) + '.tmp-')) {
      replacementInjected = true;
      const error = new Error('simulated flush failure ' + diagnosticSecret);
      error.code = 'EIO';
      throw error;
    }
    return result;
  };
  try {
    await withPhase3Environment(root, async () => {
      await assert.rejects(
        runPhase3Job({ email, db: phase3Db(), jobId: 'disposition-unknown', logger }),
        (error) => {
          failure = error;
          return error.code === 'ACCOUNT_DEACTIVATED';
        },
      );
    });
  } finally {
    fs.renameSync = originalRenameSync;
  }

  assert.equal(replacementInjected, true);
  const [record] = JSON.parse(fs.readFileSync(usernamePath, 'utf8'));
  assert.equal(record.status, 'account_deleted');
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.dispositionWriteOutcomeUnknown, true);
  assert.equal(failure.dispositionPersisted, null);
  assert.equal(failure.dispositionOutcome, 'unknown');
  assert.equal(failure.dispositionErrorCode, 'EIO');
  assert.equal(failure.reconciliationReason, 'account_disposition_write_unknown');
  assert.equal(JSON.stringify(logger.events).includes(diagnosticSecret), false);
});

test('unconfirmed Phase3 process trees remain the primary failure and block disposition writes', () => {
  const email = 'unconfirmed-disposition@example.test';
  const root = phase3Fixture(email, '');
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
    email,
    password: 'test-only-password',
    status: 'account_deactivated',
    phase3Disposition: 'discard',
    phase3LastErrorCode: 'ACCOUNT_DEACTIVATED',
  }]), { mode: 0o600 });
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    const error = new Error('Phase3 child tree is still running');
    error.code = 'PHASE3_TERMINATION_UNCONFIRMED';
    error.details = {
      terminationConfirmed: false,
      remainingDescendantCount: 1,
      stderr: 'Authorization: Bearer synthetic-child-output',
    };
    classifyPhase3ProcessError(error, { index: 0, email, phone: '' });
    assert.equal(error.code, 'PHASE3_TERMINATION_UNCONFIRMED');
    assert.equal(error.dispositionCode, 'ACCOUNT_DEACTIVATED');
    assert.equal(error.accountDisposition, 'discard');
    assert.equal(error.requiresReconciliation, true);
    assert.equal(error.retryAllowed, false);
    assert.equal(error.doNotRetry, true);
    assert.equal(error.writeOutcomeUnknown, true);
    assert.equal(error.reconciliationScope, 'phase3_process_tree');
    assert.equal(error.reconciliationReason, 'phase3_process_tree_unconfirmed');
    assert.equal(error.dispositionOutcome, 'not_attempted');
    assert.equal(JSON.stringify(error).includes('synthetic-child-output'), false);
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('Phase3 accepts the terminal child transition that clears continuation markers', async () => {
  const email = 'terminal-continuation@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const file = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(file, 'utf8'));",
    "records[0].status = 'account_deactivated';",
    "records[0].phase3Disposition = 'discard';",
    'records[0].phase3LastAttemptAt = new Date().toISOString();',
    "records[0].phase3LastErrorCode = 'ACCOUNT_DEACTIVATED';",
    'records[0].phase3Retryable = false;',
    'delete records[0].continuationRequired;',
    'delete records[0].continuationStage;',
    "fs.writeFileSync(file, JSON.stringify(records, null, 2));",
    'process.exitCode = 1;',
  ].join('\n'));
  const usernamePath = path.join(root, 'username.json');
  fs.writeFileSync(usernamePath, JSON.stringify([{
    email,
    password: 'test-only-password',
    status: 'oauth_phase3_failed',
    continuationRequired: true,
    continuationStage: 'phase3',
  }]), { mode: 0o600 });
  let failure;

  await withPhase3Environment(root, async () => {
    await assert.rejects(
      runPhase3Job({
        email,
        db: phase3Db(),
        jobId: 'terminal-continuation',
        logger: recordingLogger(() => true),
      }),
      (error) => {
        failure = error;
        return error.code === 'ACCOUNT_DEACTIVATED';
      },
    );
  });

  const [record] = JSON.parse(fs.readFileSync(usernamePath, 'utf8'));
  assert.equal(record.status, 'account_deleted');
  assert.equal(record.phase3Disposition, 'discard');
  assert.equal(Object.hasOwn(record, 'continuationRequired'), false);
  assert.equal(Object.hasOwn(record, 'continuationStage'), false);
  assert.equal(failure.dispositionPersisted, true);
  assert.equal(failure.dispositionOutcome, 'persisted');
});

test('Phase3 direct resolution rejects a whitespace-only password', () => {
  const email = 'blank-password@example.test';
  const root = phase3Fixture(email, '');
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
    email,
    password: '   \t   ',
    status: 'oauth_done',
  }]), { mode: 0o600 });
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    assert.throws(
      () => findUsernameEntry({ email }),
      (error) => error.code === 'PHASE3_ACCOUNT_NOT_FOUND',
    );
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('Phase3 requires reconciliation after publishing an invalid token artifact', async () => {
  const email = 'invalid-output@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'partial.json'), JSON.stringify({`,
    `  email: ${JSON.stringify(email)},`,
    "  refresh_token: 'test-only-refresh-token',",
    '}));',
  ].join('\n'));
  let failure;

  await withPhase3Environment(root, async () => {
    await assert.rejects(
      runPhase3Job({
        email,
        db: phase3Db(),
        jobId: 'invalid-token-output',
        logger: recordingLogger(() => true),
      }),
      (error) => {
        failure = error;
        return error.code === 'PHASE3_TOKEN_OUTPUT_UNCONFIRMED';
      },
    );
  });

  assert.equal(fs.existsSync(path.join(root, 'tokens', 'partial.json')), true);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(failure.reconciliationScope, 'phase3_token_output');
  assert.equal(
    failure.reconciliationReason,
    'phase3_token_artifact_changed_without_verified_output',
  );
});

test('Phase3 output must preserve every reviewed strong identity dimension', async () => {
  const email = 'partial-strong-output@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'output.json'), JSON.stringify({`,
    `  email: ${JSON.stringify(email)},`,
    "  access_token: 'new-test-access-token',",
    "  refresh_token: 'new-test-refresh-token',",
    "  chatgpt_account_id: 'shared-workspace',",
    '}));',
  ].join('\n'));
  const selectedKey = 'token:tokens:tokens/selected.json';
  fs.writeFileSync(path.join(root, 'tokens', 'selected.json'), JSON.stringify({
    email,
    access_token: 'old-test-access-token',
    refresh_token: 'old-test-refresh-token',
    chatgpt_account_id: 'shared-workspace',
    chatgpt_user_id: 'reviewed-user',
  }), { mode: 0o600 });

  await withPhase3Environment(root, async () => {
    const target = resolveBoundTarget(root, { email, selectedKey });
    await assert.rejects(
      runPhase3Job({
        ...target,
        executionBinding: target.executionBinding,
        db: phase3Db(),
        jobId: 'partial-strong-output',
        logger: recordingLogger(() => true),
      }),
      (error) => error.code === 'PHASE3_TOKEN_IDENTITY_MISMATCH'
        && error.requiresReconciliation === true
        && error.doNotRetry === true,
    );
  });
});

test('Phase3 rejects mutually conflicting strong outputs from an email-only source', async () => {
  const email = 'conflicting-strong-output@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `const email = ${JSON.stringify(email)};`,
    "for (const [name, account] of [['one.json', 'workspace-one'], ['two.json', 'workspace-two']]) {",
    "  fs.writeFileSync(path.join(process.cwd(), 'tokens', name), JSON.stringify({",
    "    email, account_id: account, access_token: 'new-access-' + account,",
    "  }));",
    '}',
  ].join('\n'));
  const selectedKey = 'token:tokens:tokens/selected.json';
  fs.writeFileSync(path.join(root, 'tokens', 'selected.json'), JSON.stringify({
    email,
    access_token: 'old-email-only-access-token',
  }), { mode: 0o600 });

  await withPhase3Environment(root, async () => {
    const target = resolveBoundTarget(root, { email, selectedKey });
    await assert.rejects(
      runPhase3Job({
        ...target,
        executionBinding: target.executionBinding,
        db: phase3Db(),
        jobId: 'conflicting-strong-output',
        logger: recordingLogger(() => true),
      }),
      (error) => error.code === 'PHASE3_TOKEN_IDENTITY_MISMATCH'
        && error.requiresReconciliation === true
        && error.doNotRetry === true,
    );
  });
});

test('Phase3 duration logs remain monotonic across a wall-clock rollback', async () => {
  const email = 'monotonic-duration@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'success.json'), JSON.stringify({`,
    `  email: ${JSON.stringify(email)},`,
    "  access_token: 'new-duration-access-token',",
    "  refresh_token: 'new-duration-refresh-token',",
    '}));',
  ].join('\n'));
  let wallClock = 10_000_000;
  const originalDateNow = Date.now;
  const logger = recordingLogger(() => true);
  const recordInfo = logger.info.bind(logger);
  logger.info = (event, fields) => {
    recordInfo(event, fields);
    if (event === 'phase3.process_started') wallClock = 1;
  };
  Date.now = () => wallClock;
  try {
    await withPhase3Environment(root, async () => {
      await runPhase3Job({
        email,
        db: phase3Db(),
        jobId: 'monotonic-duration',
        logger,
      });
    });
  } finally {
    Date.now = originalDateNow;
  }

  const timed = logger.events.filter((item) => Number.isFinite(item.fields?.durationMs));
  assert.equal(timed.some((item) => item.event === 'phase3.process_completed'), true);
  assert.equal(timed.some((item) => item.event === 'phase3.completed'), true);
  assert.equal(timed.every((item) => item.fields.durationMs >= 0), true);
  const queueEvent = logger.events.find((item) => item.event === 'phase3.started_after_queue');
  assert.equal(Number.isFinite(queueEvent?.fields?.queueWaitMs), true);
  assert.equal(queueEvent.fields.queueWaitMs >= 0, true);
});

test('Phase3 refuses success when the username ledger changes outside allowed child fields', async () => {
  const scenarios = [
    {
      label: 'target-password',
      prepare(root, email) {
        fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
          email,
          password: 'test-only-password',
          status: 'oauth_done',
        }]), { mode: 0o600 });
      },
      mutation: "records[0].password = 'changed-test-only-password';",
      expectedReason: 'phase3_password_reset_unconfirmed',
    },
    {
      label: 'other-row',
      prepare(root, email) {
        fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
          { email, password: 'test-only-password', status: 'oauth_done' },
          {
            email: 'unrelated-ledger-row@example.test',
            password: 'unrelated-test-only-password',
            status: 'oauth_done',
          },
        ]), { mode: 0o600 });
      },
      mutation: "records[1].status = 'changed-by-wrong-scope';",
      expectedReason: 'phase3_username_ledger_changed',
    },
    {
      label: 'prototype-key',
      prepare(root, email) {
        fs.writeFileSync(
          path.join(root, 'username.json'),
          '[{"email":' + JSON.stringify(email)
            + ',"password":"test-only-password","status":"oauth_done",'
            + '"__proto__":"original-value"}]',
          { mode: 0o600 },
        );
      },
      mutation: "records[0]['__proto__'] = 'changed-value';",
      expectedReason: 'phase3_username_ledger_changed',
    },
  ];

  for (const scenario of scenarios) {
    const email = scenario.label + '-ledger@example.test';
    const script = [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const usernamePath = path.join(process.cwd(), 'username.json');",
      "const records = JSON.parse(fs.readFileSync(usernamePath, 'utf8'));",
      scenario.mutation,
      "fs.writeFileSync(usernamePath, JSON.stringify(records, null, 2));",
      `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'success.json'), JSON.stringify({`,
      `  email: ${JSON.stringify(email)},`,
      "  access_token: 'new-ledger-test-access-token',",
      '}));',
    ].join('\n');
    const root = phase3Fixture(email, script);
    scenario.prepare(root, email);
    let failure;
    await withPhase3Environment(root, async () => {
      await assert.rejects(
        runPhase3Job({
          email,
          db: phase3Db(),
          jobId: 'username-ledger-' + scenario.label,
          logger: recordingLogger(() => true),
        }),
        (error) => {
          failure = error;
          return error.code === 'PHASE3_USERNAME_OUTPUT_UNCONFIRMED';
        },
      );
    });
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'success.json')), true);
    assert.equal(failure.writeOutcomeUnknown, true);
    assert.equal(failure.requiresReconciliation, true);
    assert.equal(failure.doNotRetry, true);
    assert.equal(failure.reconciliationScope, 'phase3_username_output');
    assert.equal(failure.reconciliationReason, scenario.expectedReason);
  }
});

test('Phase3 accepts a bound password reset and canonical email transition with a verified token', async () => {
  const scenarios = [
    {
      label: 'password-reset',
      storedEmail: 'password-reset-success@example.test',
      mutation: [
        "records[0].passwordResetCandidate = 'new-reset-test-password';",
        "records[0].passwordResetPreparedAt = new Date().toISOString();",
        "records[0].password = records[0].passwordResetCandidate;",
        'delete records[0].passwordResetCandidate;',
        'delete records[0].passwordResetPreparedAt;',
      ],
      passwordResetExpected: true,
    },
    {
      label: 'email-canonicalization',
      storedEmail: 'Email-Canonical-Success@Example.Test',
      mutation: ["records[0].email = records[0].email.toLowerCase();"],
      passwordResetExpected: false,
    },
  ];

  for (const scenario of scenarios) {
    const email = scenario.storedEmail.toLowerCase();
    const script = [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const usernamePath = path.join(process.cwd(), 'username.json');",
      "const records = JSON.parse(fs.readFileSync(usernamePath, 'utf8'));",
      ...scenario.mutation,
      "records[0].status = 'oauth_done';",
      "for (const key of Object.keys(records[0])) if (key.startsWith('phase3')) delete records[0][key];",
      "fs.writeFileSync(usernamePath, JSON.stringify(records, null, 2));",
      `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'output.json'), JSON.stringify({`,
      `  email: ${JSON.stringify(email)},`,
      "  access_token: 'new-bound-reset-test-access-token',",
      "  refresh_token: 'new-bound-reset-test-refresh-token',",
      "  chatgpt_account_id: 'bound-reset-workspace',",
      "  chatgpt_user_id: 'bound-reset-user',",
      "  expires_at: '2099-01-01T00:00:00.000Z',",
      '}));',
    ].join('\n');
    const root = phase3Fixture(scenario.storedEmail, script);
    const usernamePath = path.join(root, 'username.json');
    fs.writeFileSync(usernamePath, JSON.stringify([{
      email: scenario.storedEmail,
      password: 'old-test-only-password',
      status: 'oauth_phase3_failed',
      phase3LegacyDiagnostic: 'safe-to-clear',
    }]), { mode: 0o600 });
    const selectedKey = 'token:tokens:tokens/selected.json';
    fs.writeFileSync(path.join(root, 'tokens', 'selected.json'), JSON.stringify({
      email,
      access_token: 'old-bound-reset-test-access-token',
      refresh_token: 'old-bound-reset-test-refresh-token',
      chatgpt_account_id: 'bound-reset-workspace',
      chatgpt_user_id: 'bound-reset-user',
    }), { mode: 0o600 });
    const logger = recordingLogger(() => true);

    await withPhase3Environment(root, async () => {
      const target = resolveBoundTarget(root, { email, selectedKey });
      const result = await runPhase3Job({
        ...target,
        executionBinding: target.executionBinding,
        requireExecutionBinding: true,
        db: phase3Db(),
        jobId: 'trusted-transition-' + scenario.label,
        logger,
      });
      assert.equal(result.tokenFile, 'tokens/output.json');
    });

    const [record] = JSON.parse(fs.readFileSync(usernamePath, 'utf8'));
    assert.equal(record.email, email);
    assert.equal(Object.hasOwn(record, 'passwordResetCandidate'), false);
    assert.equal(Object.hasOwn(record, 'passwordResetPreparedAt'), false);
    assert.equal(
      logger.events.some((item) => item.event === 'phase3.password_reset_confirmed'),
      scenario.passwordResetExpected,
    );
  }
});

test('Phase3 rejects a bound password change when the reviewed token has only email identity', async () => {
  const email = 'email-only-password-reset@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const usernamePath = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(usernamePath, 'utf8'));",
    "records[0].password = 'new-test-only-password';",
    "records[0].status = 'oauth_done';",
    "fs.writeFileSync(usernamePath, JSON.stringify(records, null, 2));",
    `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'output.json'), JSON.stringify({`,
    `  email: ${JSON.stringify(email)},`,
    "  access_token: 'new-email-only-reset-test-access-token',",
    "  refresh_token: 'new-email-only-reset-test-refresh-token',",
    "  chatgpt_account_id: 'unbound-reset-workspace',",
    "  chatgpt_user_id: 'unbound-reset-user',",
    "  expires_at: '2099-01-01T00:00:00.000Z',",
    '}));',
  ].join('\n'));
  const selectedKey = 'token:tokens:tokens/selected.json';
  fs.writeFileSync(path.join(root, 'tokens', 'selected.json'), JSON.stringify({
    email,
    access_token: 'old-email-only-reset-test-access-token',
    refresh_token: 'old-email-only-reset-test-refresh-token',
  }), { mode: 0o600 });

  await withPhase3Environment(root, async () => {
    const target = resolveBoundTarget(root, { email, selectedKey });
    await assert.rejects(
      runPhase3Job({
        ...target,
        executionBinding: target.executionBinding,
        requireExecutionBinding: true,
        db: phase3Db(),
        jobId: 'email-only-password-reset',
        logger: recordingLogger(() => true),
      }),
      (error) => error.code === 'PHASE3_USERNAME_OUTPUT_UNCONFIRMED'
        && error.reconciliationReason === 'phase3_password_reset_unconfirmed'
        && error.requiresReconciliation === true
        && error.doNotRetry === true,
    );
  });
});

test('Phase3 expiry checks keep the launch-time lower bound across a wall-clock rollback', async () => {
  const email = 'rollback-expiry@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'expired.json'), JSON.stringify({`,
    `  email: ${JSON.stringify(email)},`,
    "  access_token: 'new-expired-test-access-token',",
    "  expires_at: '2025-01-01T00:00:00.000Z',",
    '}));',
  ].join('\n'));
  const originalDateNow = Date.now;
  let wallClock = Date.parse('2030-01-01T00:00:00.000Z');
  const logger = recordingLogger(() => true);
  const recordInfo = logger.info.bind(logger);
  logger.info = (event, fields) => {
    recordInfo(event, fields);
    if (event === 'phase3.process_started') {
      wallClock = Date.parse('2020-01-01T00:00:00.000Z');
    }
  };
  Date.now = () => wallClock;
  try {
    await withPhase3Environment(root, async () => {
      await assert.rejects(
        runPhase3Job({ email, db: phase3Db(), jobId: 'rollback-expiry', logger }),
        (error) => error.code === 'PHASE3_TOKEN_OUTPUT_UNCONFIRMED'
          && error.requiresReconciliation === true
          && error.doNotRetry === true,
      );
    });
  } finally {
    Date.now = originalDateNow;
  }
});

test('Phase3 rejects an invalid wall clock before spawning a child', async () => {
  const email = 'invalid-clock@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "fs.writeFileSync(path.join(process.cwd(), 'spawned'), 'yes');",
  ].join('\n'));
  const originalDateNow = Date.now;
  Date.now = () => Number.NaN;
  try {
    await withPhase3Environment(root, async () => {
      await assert.rejects(
        runPhase3Job({ email, db: phase3Db(), jobId: 'invalid-clock' }),
        (error) => error.code === 'PHASE3_CLOCK_INVALID',
      );
    });
  } finally {
    Date.now = originalDateNow;
  }
  assert.equal(fs.existsSync(path.join(root, 'spawned')), false);
});

test('Phase3 success survives hostile persistence and audit errors after token publication', async () => {
  const email = 'hostile-after-success@example.test';
  const root = phase3Fixture(email, [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'success.json'), JSON.stringify({`,
    `  email: ${JSON.stringify(email)},`,
    "  access_token: 'new-hostile-test-access-token',",
    '}));',
  ].join('\n'));
  const hostile = {};
  Object.defineProperty(hostile, 'message', {
    get() { throw new Error('message getter must not run'); },
  });
  hostile.toString = () => { throw new Error('toString must not run'); };
  const logger = recordingLogger(() => true);

  await withPhase3Environment(root, async () => {
    const result = await runPhase3Job({
      email,
      db: {
        ...phase3Db(),
        async audit() { throw hostile; },
      },
      jobId: 'hostile-after-success',
      logger,
      async persistSuccess() { throw hostile; },
    });
    assert.equal(result.tokenFile, 'tokens/success.json');
  });

  assert.equal(logger.events.some((item) => item.event === 'phase3.job_update_deferred'), true);
  assert.equal(logger.events.some((item) => item.event === 'phase3.audit_failed_after_success'), true);
  assert.equal(logger.events.some((item) => item.event === 'phase3.completed'), true);
});

test('Phase3 rejects token changes outside the resolved account scope', async () => {
  const cases = [
    {
      label: 'created-other-account',
      prepare() {},
      mutation(email) {
        return [
          `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'other.json'), JSON.stringify({`,
          "  email: 'other-token-account@example.test',",
          "  access_token: 'other-test-access-token',",
          '}));',
        ];
      },
    },
    {
      label: 'deleted-other-account',
      prepare(root) {
        fs.writeFileSync(path.join(root, 'tokens', 'other-existing.json'), JSON.stringify({
          email: 'other-existing-account@example.test',
          access_token: 'other-existing-test-access-token',
          expires_at: '2099-01-01T00:00:00.000Z',
        }), { mode: 0o600 });
      },
      mutation() {
        return ["fs.unlinkSync(path.join(process.cwd(), 'tokens', 'other-existing.json'));" ];
      },
    },
  ];

  for (const scenario of cases) {
    const email = scenario.label + '@example.test';
    const script = [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      ...scenario.mutation(email),
      `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'target.json'), JSON.stringify({`,
      `  email: ${JSON.stringify(email)},`,
      "  access_token: 'target-test-access-token',",
      '}));',
    ].join('\n');
    const root = phase3Fixture(email, script);
    scenario.prepare(root, email);
    let failure;
    await withPhase3Environment(root, async () => {
      await assert.rejects(
        runPhase3Job({
          email,
          db: phase3Db(),
          jobId: 'token-scope-' + scenario.label,
          logger: recordingLogger(() => true),
        }),
        (error) => {
          failure = error;
          return error.code === 'PHASE3_TOKEN_SCOPE_VIOLATION';
        },
      );
    });
    assert.equal(failure.writeOutcomeUnknown, true);
    assert.equal(failure.requiresReconciliation, true);
    assert.equal(failure.doNotRetry, true);
    assert.equal(failure.reconciliationReason, 'phase3_token_artifact_outside_target');
  }
});

test('Phase3 bound output replacement allows partial history but rejects contradictory identity', async () => {
  const scenarios = [
    { label: 'partial-same-account', priorAccountId: 'replacement-workspace', accepted: true },
    { label: 'contradictory-account', priorAccountId: 'other-workspace', accepted: false },
  ];
  for (const scenario of scenarios) {
    const email = scenario.label + '@example.test';
    const root = phase3Fixture(email, [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      `fs.writeFileSync(path.join(process.cwd(), 'tokens', 'output.json'), JSON.stringify({`,
      `  email: ${JSON.stringify(email)},`,
      "  access_token: 'new-replacement-test-access-token',",
      "  refresh_token: 'new-replacement-test-refresh-token',",
      "  chatgpt_account_id: 'replacement-workspace',",
      "  chatgpt_user_id: 'replacement-user',",
      "  expires_at: '2099-01-01T00:00:00.000Z',",
      '}));',
    ].join('\n'));
    const selectedKey = 'token:tokens:tokens/selected.json';
    fs.writeFileSync(path.join(root, 'tokens', 'selected.json'), JSON.stringify({
      email,
      access_token: 'selected-replacement-test-access-token',
      refresh_token: 'selected-replacement-test-refresh-token',
      chatgpt_account_id: 'replacement-workspace',
      chatgpt_user_id: 'replacement-user',
    }), { mode: 0o600 });
    fs.writeFileSync(path.join(root, 'tokens', 'output.json'), JSON.stringify({
      email,
      access_token: 'old-replacement-test-access-token',
      chatgpt_account_id: scenario.priorAccountId,
    }), { mode: 0o600 });

    await withPhase3Environment(root, async () => {
      const target = resolveBoundTarget(root, { email, selectedKey });
      const run = runPhase3Job({
        ...target,
        executionBinding: target.executionBinding,
        requireExecutionBinding: true,
        db: phase3Db(),
        jobId: 'replacement-' + scenario.label,
        logger: recordingLogger(() => true),
      });
      if (scenario.accepted) {
        assert.equal((await run).tokenFile, 'tokens/output.json');
      } else {
        await assert.rejects(
          run,
          (error) => error.code === 'PHASE3_TOKEN_SCOPE_VIOLATION'
            && error.requiresReconciliation === true
            && error.doNotRetry === true,
        );
      }
    });
  }
});
