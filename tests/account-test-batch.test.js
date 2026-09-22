const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const { run } = require('../frontend/account-test-batch');

function jobId(index) {
  return 'job_' + index.toString(16).padStart(24, '0');
}

function fixture(count = 142, overrides = {}) {
  const targets = Array.from({ length: count }, (_, index) => ({
    accountId: index + 1,
    targetRevision: 'account-test-v1.' + String(index).padStart(43, 'a'),
  }));
  const events = [];
  const submissions = [];
  let snapshotCount = 0;
  const options = {
    targets,
    modelId: 'gpt-5.6-luna',
    loadInventory: async () => ({ jobs: [],
      activeJobs: { total: 0, returned: 0, truncated: false },
      reconciliationHolds: { total: 0, returned: 0, truncated: false } }),
    loadSnapshot: async () => {
      snapshotCount += 1;
      return { readOnly: false, sub2api: { readStatus: 'ok' },
        diff: { comparisonStatus: 'complete' },
        rows: targets.map((target) => ({ ...target, platform: 'openai', type: 'oauth', status: 'active' })) };
    },
    submitBatch: async ({ targets: batch, modelId, batchIndex }) => {
      submissions.push({ targets: batch, modelId, batchIndex });
      return { jobId: jobId(batchIndex), status: 'queued', rejected: [],
        accountIds: batch.map((target) => target.accountId) };
    },
    waitForTerminal: async ({ jobId, accountIds }) => successfulJob(jobId, accountIds),
    onProgress: async (event) => { events.push(event); },
    ...overrides,
  };
  return { options, targets, events, submissions, snapshotCount: () => snapshotCount };
}

function successfulJob(jobId, accountIds) {
  return { id: jobId, type: 'account_test', status: 'succeeded', error: null,
    payload: { accountIds: [...accountIds], modelId: 'gpt-5.6-luna' },
    result: { jobStatus: 'succeeded', model: 'gpt-5.6-luna', requested: accountIds.length,
      succeeded: accountIds.length, attemptedCount: accountIds.length,
      failed: 0, skipped: 0, reconciliationCount: 0, notAttemptedCount: 0,
      reconciliationNotAttemptedCount: 0, timeoutCount: 0, interruptedCount: 0,
      requiresReconciliation: false, executionStarted: true, executionComplete: true,
      stopReason: null,
      results: accountIds.map((accountId) => ({ accountId, status: 'succeeded',
        testSuccess: true, code: 'account_test_succeeded' })) } };
}

test('account-test batch exposes a browser global without CommonJS or networking', () => {
  const context = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../frontend/account-test-batch.js'), 'utf8'), context);
  assert.equal(typeof context.PanelAccountTestBatch.run, 'function');
  assert.equal(context.PanelAccountTestBatch.MAXIMUM_TARGETS, 1000);
  assert.equal(context.PanelAccountTestBatch.MAXIMUM_BATCH_SIZE, 100);
});

test('142 approved targets execute as strictly sequential batches of 100 and 42', async () => {
  const state = fixture();
  let terminal = 0;
  const submit = state.options.submitBatch;
  state.options.submitBatch = async (args) => {
    assert.equal(terminal, args.batchIndex - 1);
    return submit(args);
  };
  state.options.waitForTerminal = async ({ jobId, accountIds }) => {
    terminal += 1;
    return successfulJob(jobId, accountIds);
  };
  const result = await run(state.options);
  assert.deepEqual(state.submissions.map((batch) => batch.targets.length), [100, 42]);
  assert.equal(state.snapshotCount(), 2);
  assert.equal(result.completed, 142);
  assert.deepEqual(result.jobIds, [jobId(1), jobId(2)]);
  assert.deepEqual(state.events.map((event) => event.phase),
    ['checking', 'submitting', 'submitted', 'completed', 'checking', 'submitting', 'submitted', 'completed']);
});

test('target and batch limits reject excess values before any submission', async () => {
  for (const options of [fixture(1001).options, fixture(2, { maximumTargets: 1 }).options,
    fixture(1, { maximumTargets: 1001 }).options, fixture(1, { batchSize: 101 }).options]) {
    await assert.rejects(run(options), { code: /ACCOUNT_TEST_BATCH_(TARGET_LIMIT|LIMIT_INVALID)/ });
  }
  const state = fixture(5, { batchSize: 2, maximumTargets: 5 });
  await run(state.options);
  assert.deepEqual(state.submissions.map((batch) => batch.targets.length), [2, 2, 1]);
});

test('duplicate IDs and invalid approved targets fail before callbacks run', async () => {
  const state = fixture(2);
  state.targets[1] = { ...state.targets[0] };
  await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_TARGET_DUPLICATE' });
  for (const target of [{ accountId: 1, targetRevision: null },
    { accountId: '1', targetRevision: state.targets[0].targetRevision },
    { ...state.targets[0], credentials: 'never-forward-this-value' }]) {
    state.options.targets = [target];
    await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_TARGET_INVALID' });
  }
  assert.equal(state.snapshotCount(), 0);
  assert.equal(state.submissions.length, 0);
});

test('initial ineligible or missing selected account prevents all submissions', async () => {
  for (const change of [(rows) => { rows[0].targetRevision = null; },
    (rows) => { rows[0].platform = 'other'; },
    (rows) => { rows[0].accountTestEligible = false; }, (rows) => { rows.pop(); }]) {
    const state = fixture(2);
    const load = state.options.loadSnapshot;
    state.options.loadSnapshot = async () => {
      const snapshot = await load();
      change(snapshot.rows);
      return snapshot;
    };
    await assert.rejects(run(state.options), { code: /ACCOUNT_TEST_BATCH_TARGET_(INELIGIBLE|MISSING)/ });
    assert.equal(state.submissions.length, 0);
  }
});

test('every still-unsubmitted target is checked, including a later batch', async () => {
  const state = fixture(142);
  const load = state.options.loadSnapshot;
  state.options.loadSnapshot = async () => {
    const snapshot = await load();
    snapshot.rows[141].targetRevision = 'account-test-v1.' + 'z'.repeat(43);
    return snapshot;
  };
  await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_TARGET_CHANGED' });
  assert.equal(state.submissions.length, 0);
});

test('changed revision after first batch stops and never adopts the new target', async () => {
  const state = fixture();
  const load = state.options.loadSnapshot;
  state.options.loadSnapshot = async () => {
    const snapshot = await load();
    if (state.snapshotCount() > 1) snapshot.rows[100].targetRevision = 'account-test-v1.' + 'z'.repeat(43);
    return snapshot;
  };
  await assert.rejects(run(state.options), (error) => {
    assert.equal(error.code, 'ACCOUNT_TEST_BATCH_TARGET_CHANGED');
    assert.equal(error.completed, 100);
    assert.deepEqual(error.submittedJobIds, [jobId(1)]);
    return true;
  });
  assert.equal(state.submissions.length, 1);
});

test('changes to already-completed target do not stop later approved targets', async () => {
  const state = fixture();
  const load = state.options.loadSnapshot;
  state.options.loadSnapshot = async () => {
    const snapshot = await load();
    if (state.snapshotCount() > 1) snapshot.rows[0].targetRevision = 'account-test-v1.' + 'z'.repeat(43);
    return snapshot;
  };
  assert.equal((await run(state.options)).completed, 142);
});

test('incomplete inventory, active tasks and reconciliation holds fail closed', async () => {
  for (const change of [
    (body) => { delete body.activeJobs; },
    (body) => { body.activeJobs.truncated = true; },
    (body) => { body.reconciliationHolds.total = 1; },
    (body) => { body.jobs.push({ status: 'running' }); },
    (body) => { body.jobs.push({ status: 'unknown' }); },
    (body) => { body.jobs.push({ status: 'running' }); body.activeJobs.total = body.activeJobs.returned = 1; },
    (body) => { body.jobs.push({ status: 'failed', result: { reconciliationHold: true } });
      body.reconciliationHolds.total = body.reconciliationHolds.returned = 1; },
  ]) {
    const state = fixture();
    const load = state.options.loadInventory;
    state.options.loadInventory = async () => { const body = await load(); change(body); return body; };
    await assert.rejects(run(state.options), { code: /^ACCOUNT_TEST_BATCH_INVENTORY_/ });
    assert.equal(state.submissions.length, 0);
  }
});

test('read-only or failed/partial remote snapshot cannot submit', async () => {
  for (const change of [(body) => { body.readOnly = true; },
    (body) => { delete body.readOnly; }, (body) => { body.sub2api.readStatus = 'failed'; },
    (body) => { body.diff.comparisonStatus = 'unknown'; }]) {
    const state = fixture();
    const load = state.options.loadSnapshot;
    state.options.loadSnapshot = async () => { const body = await load(); change(body); return body; };
    await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_SNAPSHOT_UNAVAILABLE' });
    assert.equal(state.submissions.length, 0);
  }
});

test('partial acceptance, unexpected IDs and rejected entries stop after first submit', async () => {
  for (const change of [(body) => { body.accountIds.pop(); },
    (body) => { body.accountIds[0] = 99999; }, (body) => { body.accountIds[1] = body.accountIds[0]; },
    (body) => { body.rejected.push({ accountId: 1 }); }, (body) => { delete body.rejected; }]) {
    const state = fixture();
    const submit = state.options.submitBatch;
    state.options.submitBatch = async (args) => { const body = await submit(args); change(body); return body; };
    await assert.rejects(run(state.options), (error) => {
      assert.equal(error.code, 'ACCOUNT_TEST_BATCH_SUBMISSION_INCOMPLETE');
      assert.deepEqual(error.submittedJobIds, [jobId(1)]);
      return true;
    });
    assert.equal(state.submissions.length, 1);
  }
});

test('lost submission response and lost terminal response never start another batch or leak errors', async () => {
  for (const stage of ['submitBatch', 'waitForTerminal']) {
    const state = fixture();
    const original = state.options[stage];
    state.options[stage] = async (args) => {
      await original(args);
      throw new Error('sensitive-upstream-diagnostic-do-not-return');
    };
    await assert.rejects(run(state.options), (error) => {
      assert.match(error.code, /^ACCOUNT_TEST_BATCH_(SUBMISSION_UNCONFIRMED|RESULT_UNAVAILABLE)$/);
      assert.doesNotMatch(error.message, /sensitive-upstream/);
      return true;
    });
    assert.equal(state.submissions.length, 1);
  }
});

test('only exact fully successful terminal results allow a next batch', async () => {
  for (const change of [(job) => { job.status = 'running'; },
    (job) => { job.status = 'partial'; }, (job) => { job.status = 'failed'; },
    (job) => { job.result.reconciliationHold = true; },
    (job) => { job.result.requiresReconciliation = true; },
    (job) => { job.result.results[0].writeOutcomeUnknown = true; },
    (job) => { job.result.results[0].schedulerStateUnknown = true; },
    (job) => { job.result.results[0].testSuccess = false; },
    (job) => { job.result.results[0].status = 'failed'; },
    (job) => { job.result.results.pop(); },
    (job) => { job.result.results[1].accountId = job.result.results[0].accountId; },
    (job) => { job.payload.accountIds[0] = 99999; },
    (job) => { job.result.results[0].code = 'unrecognized_success'; },
    (job) => { job.result.notAttemptedCount = 1; },
    (job) => { job.payload.modelId = 'different-model'; },
  ]) {
    const state = fixture();
    state.options.waitForTerminal = async ({ jobId, accountIds }) => {
      const job = successfulJob(jobId, accountIds); change(job); return job;
    };
    await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_RESULT_UNCONFIRMED' });
    assert.equal(state.submissions.length, 1);
  }
});

test('abort after submission stops observation without cancelling or submitting next batch', async () => {
  const controller = new AbortController();
  const state = fixture(142, { signal: controller.signal });
  state.options.waitForTerminal = async () => {
    controller.abort();
    return new Promise(() => {});
  };
  await assert.rejects(run(state.options), (error) => {
    assert.equal(error.code, 'ACCOUNT_TEST_BATCH_ABORTED');
    assert.deepEqual(error.submittedJobIds, [jobId(1)]);
    assert.equal(error.completed, 0);
    return true;
  });
  assert.equal(state.submissions.length, 1);
});

test('abort after first successful result prevents the second submission', async () => {
  const controller = new AbortController();
  const state = fixture(142, { signal: controller.signal });
  state.options.onProgress = async (event) => {
    if (event.phase === 'completed') controller.abort();
  };
  await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_ABORTED', completed: 100 });
  assert.equal(state.submissions.length, 1);
});

test('approved target copies cannot be replaced while a batch is running', async () => {
  const state = fixture();
  const load = state.options.loadInventory;
  state.options.loadInventory = async () => {
    state.targets[0].targetRevision = 'account-test-v1.' + 'z'.repeat(43);
    return load();
  };
  await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_TARGET_CHANGED' });
  assert.equal(state.submissions.length, 0);
});

test('concurrent coordinators are rejected and a finished run does not retain its queue', async () => {
  const state = fixture(1);
  state.options.loadInventory = async () => {
    await assert.rejects(run(fixture(1).options), { code: 'ACCOUNT_TEST_BATCH_ALREADY_RUNNING' });
    return { jobs: [], activeJobs: { total: 0, returned: 0, truncated: false },
      reconciliationHolds: { total: 0, returned: 0, truncated: false } };
  };
  await run(state.options);
  assert.equal((await run(fixture(1).options)).completed, 1);
});

test('reusing a previous batch job ID cannot masquerade as acceptance of a new batch', async () => {
  const state = fixture();
  const submit = state.options.submitBatch;
  state.options.submitBatch = async (args) => {
    const body = await submit(args);
    body.jobId = jobId(1);
    return body;
  };
  await assert.rejects(run(state.options), {
    code: 'ACCOUNT_TEST_BATCH_JOB_REUSED', completed: 100,
  });
  assert.equal(state.submissions.length, 2);
});

test('aborts during either read-only preflight stop before submission', async () => {
  for (const stage of ['loadInventory', 'loadSnapshot']) {
    const controller = new AbortController();
    const state = fixture(142, { signal: controller.signal });
    const original = state.options[stage];
    state.options[stage] = async (args) => {
      const body = await original(args);
      controller.abort();
      return body;
    };
    await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_ABORTED' });
    assert.equal(state.submissions.length, 0);
  }
});

test('an already-aborted run performs no preflight or submissions', async () => {
  const controller = new AbortController();
  controller.abort();
  const state = fixture(1, { signal: controller.signal });
  state.options.loadInventory = async () => { assert.fail('must not load inventory'); };
  await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_ABORTED' });
  assert.equal(state.snapshotCount(), 0);
  assert.equal(state.submissions.length, 0);
});

test('an uncertain submission abortion never starts a later batch', async () => {
  const controller = new AbortController();
  const state = fixture(142, { signal: controller.signal });
  const submit = state.options.submitBatch;
  state.options.submitBatch = async (args) => {
    const body = await submit(args);
    controller.abort();
    return body;
  };
  await assert.rejects(run(state.options), { code: 'ACCOUNT_TEST_BATCH_ABORTED', completed: 0 });
  assert.equal(state.submissions.length, 1);
});

test('rendering failure stops and redacts callback diagnostics', async () => {
  const state = fixture();
  state.options.onProgress = async () => { throw new Error('private-render-diagnostic'); };
  await assert.rejects(run(state.options), (error) => {
    assert.equal(error.code, 'ACCOUNT_TEST_BATCH_PROGRESS_FAILED');
    assert.doesNotMatch(error.message, /private-render/);
    return true;
  });
  assert.equal(state.submissions.length, 0);
});

test('submission job IDs must match the exact backend-issued namespace', async () => {
  for (const invalidId of ['job-1', 'job_' + 'A'.repeat(24), 'job_' + 'a'.repeat(23),
    'job_' + 'a'.repeat(25), '../jobs/other', 'account_test_' + 'a'.repeat(24)]) {
    const state = fixture();
    const submit = state.options.submitBatch;
    state.options.submitBatch = async (args) => {
      const body = await submit(args);
      body.jobId = invalidId;
      return body;
    };
    state.options.waitForTerminal = async () => { assert.fail('must not poll an untrusted job ID'); };
    await assert.rejects(run(state.options), (error) => {
      assert.equal(error.code, 'ACCOUNT_TEST_BATCH_SUBMISSION_INCOMPLETE');
      assert.deepEqual(error.submittedJobIds, []);
      return true;
    });
    assert.equal(state.submissions.length, 1);
  }
});
