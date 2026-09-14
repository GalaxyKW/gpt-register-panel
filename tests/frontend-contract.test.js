const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

require('./test-isolation');

const { tokenImportJobStatus } = require('../backend/server');

const source = fs.readFileSync(path.resolve(__dirname, '..', 'frontend', 'app.js'), 'utf8');
const htmlSource = fs.readFileSync(path.resolve(__dirname, '..', 'frontend', 'index.html'), 'utf8');
const stylesSource = fs.readFileSync(path.resolve(__dirname, '..', 'frontend', 'styles.css'), 'utf8');

function sourceSection(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, startMarker + ' missing');
  assert.notEqual(end, -1, endMarker + ' missing');
  return source.slice(start, end);
}

test('frontend treats every blocking plan item as a conflict and explains terminal sources', () => {
  const actionContracts = sourceSection('function actionReasonLabel', 'function statusClass');
  const lockingContracts = sourceSection('function actionRequestPending', 'function renderMetrics');
  const renderPlan = sourceSection('function renderPlan', 'function applyFilters');
  const context = {
    elements: {
      planPanel: {},
      planSummary: {},
      planVersion: {},
      planRows: {},
      importButton: {},
    },
    state: {
      plan: null,
      importRequestPending: false,
      snapshot: { readOnly: false },
      reconciliationHolds: { total: 0 },
      job: null,
    },
    reconciliationHoldJobs: () => [],
    hiddenSelectionProblem: () => '',
    escapeHtml: (value) => String(value ?? ''),
    actionLabel: (value) => value,
    formatFingerprint: (value) => value || '-',
    finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0,
  };
  vm.runInNewContext(actionContracts + '\n' + lockingContracts + '\n' + renderPlan + `
    renderPlan({
      version: 'a'.repeat(64),
      selectedKeys: ['token:one'],
      items: [
        { action: 'create', reason: 'token_only', fingerprints: {} },
        {
          action: 'update',
          reason: 'token_changed',
          conflictingVersions: true,
          source: 'tokens',
          relativePath: 'tokens/fresh.json',
          sourceVersionCount: 2,
          selectedSourceSuperseded: true,
          selectedSupersededPaths: ['use_token/old.json'],
          fingerprints: {},
        },
      ],
    });
    result = {
      disabled: elements.importButton.disabled,
      summary: elements.planSummary.textContent,
      rows: elements.planRows.innerHTML,
      terminal: actionReasonLabel('source_account_terminal'),
    identityReasons: [
        actionReasonLabel('source_identity_insufficient'),
        actionReasonLabel('conflicting_strong_identity'),
        actionReasonLabel('incomparable_strong_identity'),
        actionReasonLabel('ambiguous_sub2api_identity'),
        actionReasonLabel('free_name_exhausted'),
        actionReasonLabel('free_name_conflict'),
        actionReasonLabel('sub2api_account_schema_invalid'),
        actionReasonLabel('sub2api_target_kind_invalid'),
      ],
      unknownAvailability: actionReasonLabel('sub2api_status_missing'),
      invalidAutoPause: actionReasonLabel('sub2api_auto_pause_invalid'),
    };
  `, context);
  assert.equal(context.result.disabled, true);
  assert.match(context.result.summary, /冲突 1/);
  assert.match(context.result.summary, /旧副本改用最新 1/);
  assert.match(context.result.rows, /来源 token 版本冲突，禁止导入/);
  assert.match(context.result.rows, /同身份 2 个版本/);
  assert.match(context.result.rows, /已选旧副本/);
  assert.match(context.result.rows, /tokens\/fresh\.json/);
  assert.match(context.result.rows, /use_token\/old\.json/);
  assert.equal(context.result.terminal, '来源账号已处置，跳过');
  assert.equal(context.result.identityReasons.every((label) => label.includes('禁止导入')), true);
  assert.match(context.result.unknownAvailability, /跳过/);
  assert.match(context.result.invalidAutoPause, /跳过/);
  assert.match(source, /unknown:\s*'未知'/);
  assert.match(source, /可用性未知/);
  assert.match(source, /所选旧副本将按有效性与新鲜度规则改用首选版本/);
  assert.match(source, /所选旧副本将改用预览所示的排序首选版本/);
});

test('frontend import confirmation calls out selected superseded token files', async () => {
  const importHandler = sourceSection(
    "elements.importButton.addEventListener('click'",
    "elements.phase3Button.addEventListener('click'",
  );
  let clickHandler;
  let confirmation = '';
  const context = {
    elements: {
      importButton: {
        addEventListener(event, handler) {
          assert.equal(event, 'click');
          clickHandler = handler;
        },
      },
    },
    state: {
      plan: {
        version: 'a'.repeat(64),
        selectedKeys: ['token:use_token:use_token/old.json'],
        items: [{ selectedSourceSuperseded: true }],
      },
      importRequestPending: false,
      snapshot: { sub2api: { readStatus: 'ok' } },
    },
    comparisonAvailable: () => true,
    hiddenSelectionProblem: () => '',
    syncSelectionProblem: () => '',
    showNotice() {},
    window: {
      confirm(message) {
        confirmation = message;
        return false;
      },
    },
  };
  vm.runInNewContext(importHandler, context);
  await clickHandler();
  assert.match(confirmation, /1 个所选旧副本/);
  assert.match(confirmation, /排序首选版本/);
  assert.match(confirmation, /确认将预览中的新增\/更新写入 Sub2API/);
});

test('frontend rejects non-importable sync selections before requesting either preview or import', async () => {
  const comparisonContract = sourceSection('function sub2ApiReadStatus', 'function updateImportButtonState');
  const previewContract = sourceSection(
    'async function previewSelection',
    "elements.previewButton.addEventListener('click', previewSelection);",
  );
  const importHandler = sourceSection(
    "elements.importButton.addEventListener('click'",
    "elements.phase3Button.addEventListener('click'",
  );
  const validKey = 'token:tokens:tokens/valid.json';
  const remoteKey = 'account:27';
  const historicalKey = 'token:tokens:tokens/old_codex-valid.json';
  const invalidKey = 'token:use_token:use_token/invalid.json';
  const malformedKey = 'token:tokens:tokens/../outside.json';
  const rows = [
    {
      key: validKey,
      source: 'tokens',
      sourceDetails: { relativePath: 'tokens/valid.json' },
      diffKind: 'token_only',
      historical: false,
    },
    {
      key: remoteKey,
      source: 'sub2api',
      sourceDetails: null,
      diffKind: 'sub2api_only',
      historical: false,
    },
    {
      key: historicalKey,
      source: 'tokens',
      sourceDetails: { relativePath: 'tokens/old_codex-valid.json' },
      diffKind: 'historical_backup',
      historical: true,
    },
    {
      key: invalidKey,
      source: 'use_token',
      sourceDetails: { relativePath: 'use_token/invalid.json' },
      diffKind: 'invalid_file',
      historical: false,
    },
    {
      key: malformedKey,
      source: 'tokens',
      sourceDetails: { relativePath: 'tokens/../outside.json' },
      diffKind: 'token_only',
      historical: false,
    },
  ];
  const helperContext = {
    state: { snapshot: { rows } },
  };
  vm.runInNewContext(comparisonContract + `
    result = {
      valid: syncSelectionProblem([${JSON.stringify(validKey)}]),
      remote: syncSelectionProblem([${JSON.stringify(remoteKey)}]),
      historical: syncSelectionProblem([${JSON.stringify(historicalKey)}]),
      invalid: syncSelectionProblem([${JSON.stringify(invalidKey)}]),
      malformed: syncSelectionProblem([${JSON.stringify(malformedKey)}]),
      stale: syncSelectionProblem(['missing-row']),
    };
  `, helperContext);
  assert.equal(helperContext.result.valid, '');
  assert.match(helperContext.result.remote, /仅 Sub2API 账号/);
  assert.match(helperContext.result.historical, /historical\/old_codex 历史备份/);
  assert.match(helperContext.result.invalid, /无法解析的 token 文件/);
  assert.match(helperContext.result.malformed, /活动 token 文件键/);
  assert.match(helperContext.result.stale, /当前快照/);

  let previewRequests = 0;
  const previewNotices = [];
  const previewContext = {
    state: {
      snapshot: {
        rows,
        sub2api: { readStatus: 'ok' },
        diff: { comparisonStatus: 'complete' },
      },
      selected: new Set([remoteKey]),
      previewRequestPending: false,
    },
    hiddenSelectionProblem: () => '',
    apiFetch: async () => { previewRequests += 1; throw new Error('must not request'); },
    showNotice: (...args) => previewNotices.push(args),
  };
  vm.runInNewContext(comparisonContract + '\n' + previewContract
    + '\npreviewPromise = previewSelection();', previewContext);
  assert.equal(await previewContext.previewPromise, false);
  assert.equal(previewRequests, 0);
  assert.match(previewNotices.at(-1)[0], /无法检查差异：.*仅 Sub2API 账号/);

  let importRequests = 0;
  let confirmations = 0;
  let importClickHandler;
  const importNotices = [];
  const importContext = {
    state: {
      snapshot: {
        rows,
        sub2api: { readStatus: 'ok' },
        diff: { comparisonStatus: 'complete' },
      },
      plan: {
        selectedKeys: [historicalKey],
        items: [],
      },
      importRequestPending: false,
    },
    elements: {
      importButton: {
        addEventListener(event, handler) {
          assert.equal(event, 'click');
          importClickHandler = handler;
        },
      },
    },
    hiddenSelectionProblem: () => '',
    idempotentMutationFetch: async () => { importRequests += 1; throw new Error('must not request'); },
    showNotice: (...args) => importNotices.push(args),
    window: { confirm: () => { confirmations += 1; return true; } },
  };
  vm.runInNewContext(comparisonContract + '\n' + importHandler, importContext);
  await importClickHandler();
  assert.equal(importRequests, 0);
  assert.equal(confirmations, 0);
  assert.match(importNotices.at(-1)[0], /无法确认导入：.*historical\/old_codex 历史备份/);
});

test('frontend polling helper keeps an unknown task locked and schedules a slower retry', () => {
  const pollingContract = sourceSection('function jobPollFailureState', 'async function watchJobs');
  const context = {};
  vm.runInNewContext(pollingContract + `
    result = {
      first: jobPollFailureState(0),
      exhausted: jobPollFailureState(6),
    };
  `, context);
  assert.deepEqual({ ...context.result.first }, {
    unknown: false,
    nextAttempt: 1,
    delayMs: 1000,
  });
  assert.deepEqual({ ...context.result.exhausted }, {
    unknown: true,
    nextAttempt: 0,
    delayMs: 15000,
  });
  const unknownBranch = sourceSection('// A polling failure says nothing', '    }\n  };');
  assert.doesNotMatch(unknownBranch, /RequestPending\s*=\s*false/);
  assert.match(unknownBranch, /status:\s*'unknown'/);
});

test('frontend ignores an older same-id watcher after a newer generation starts', async () => {
  const pollingSupport = sourceSection('function stopJobPolling', 'async function watchJobs');
  const watchContract = sourceSection('async function watchJobs', 'async function watchJob');
  const requests = [];
  const timers = [];
  const rendered = [];
  const stateForTest = {
    jobPollTimer: null,
    watchGeneration: 0,
    watchIds: [],
    jobs: [],
    job: null,
  };
  const context = {
    state: stateForTest,
    apiFetch: (url) => new Promise((resolve) => requests.push({ url, resolve })),
    renderJob: (job) => rendered.push(job),
    jobNeedsReconciliation: () => false,
    reconciliationNoticeForJobs: () => '',
    renderPlan() {},
    updateActionState() {},
    loadSnapshot: async () => true,
    showNotice() {},
    elements: { jobMeta: {} },
    window: {
      clearTimeout() {},
      setTimeout(callback, delayMs) {
        timers.push({ callback, delayMs });
        return timers.length;
      },
    },
  };
  vm.runInNewContext(pollingSupport + '\n' + watchContract + `
    olderPromise = watchJobs(['same-job'], 'phase3');
  `, context);
  stateForTest.snapshotRefreshPending = true;
  vm.runInNewContext("newerPromise = watchJobs(['same-job'], 'phase3');", context);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].url, requests[1].url);
  assert.equal(stateForTest.snapshotRefreshPending, true);

  requests[1].resolve({
    ok: true,
    json: async () => ({ id: 'same-job', type: 'phase3', status: 'running', marker: 'newer' }),
  });
  await context.newerPromise;
  assert.equal(stateForTest.jobs[0].marker, 'newer');
  assert.equal(timers.length, 1);

  requests[0].resolve({
    ok: true,
    json: async () => ({ id: 'same-job', type: 'phase3', status: 'running', marker: 'older' }),
  });
  await context.olderPromise;
  assert.equal(stateForTest.jobs[0].marker, 'newer');
  assert.equal(rendered.at(-1).marker, 'newer');
  assert.equal(timers.length, 1);
  assert.match(watchContract, /watchGeneration === generation/);
  assert.doesNotMatch(watchContract, /watchIds\.join/);
});

test('frontend locks the initial UI when active-job recovery cannot be confirmed', () => {
  const resumeContract = sourceSection('async function resumeActiveJob', 'async function loadSnapshot');
  const firstRequest = resumeContract.indexOf("apiFetch('/api/jobs?limit=200')");
  const initialLock = resumeContract.indexOf("status: 'unknown'");
  assert.notEqual(firstRequest, -1);
  assert.ok(initialLock >= 0 && initialLock < firstRequest);
  assert.match(resumeContract.slice(0, firstRequest), /renderJob\(state\.job\);\s*updateActionState\(\)/);
  const failureBranch = resumeContract.slice(resumeContract.indexOf('  } catch (error) {'));
  assert.match(failureBranch, /status:\s*'unknown'/);
  assert.match(failureBranch, /resumeProbe:\s*true/);
  assert.match(failureBranch, /renderJob\(state\.job\);\s*updateActionState\(\)/);
  assert.match(failureBranch, /window\.setTimeout\(\(\) => loadSnapshot\(\{ resumeJobs: true \}\), 15000\)/);
  assert.match(resumeContract, /if \(state\.job\?\.resumeProbe\)[\s\S]*recentReconciliation[\s\S]*state\.job = recentReconciliation \|\| null;[\s\S]*updateActionState\(\)/);
  assert.match(resumeContract, /activeListingInvalid \|\| activeListing\.truncated === true \|\| activeTotal > activeReturned/);
  assert.match(resumeContract, /activeReturned !== activeJobs\.length/);
  assert.match(resumeContract, /id:\s*'active-list-truncated'[\s\S]*status:\s*'unknown'/);
  assert.match(resumeContract, /活跃任务列表不完整，无法安全解除操作锁/);
  assert.match(resumeContract, /state\.jobInventoryVerified = false/);
  assert.match(resumeContract, /holdReturned !== heldJobs\.length/);
  assert.match(resumeContract, /holdListing\.truncated === true \|\| holdTotal > holdReturned/);
  assert.match(resumeContract, /state\.jobInventoryVerified = true/);
});

test('frontend serializes inventory before snapshot, retries the whole flow, and stays fail-closed', async () => {
  const lockContract = sourceSection('function actionRequestPending', 'function renderMetrics');
  const resumeContract = sourceSection('async function resumeActiveJob', 'async function loadSnapshot');
  const snapshotContract = sourceSection('async function loadSnapshot', "elements.refreshButton.addEventListener('click'");
  const calls = [];
  const timers = [];
  const notices = [];
  let inventoryAttempt = 0;
  let snapshotAttempt = 0;
  const stateForTest = {
    snapshot: { marker: 'old', rows: [] },
    selected: new Set(['old-key']),
    selectionRevision: 2,
    plan: { version: 'old-plan', selectedKeys: ['old-key'], items: [] },
    jobs: [],
    job: null,
    reconciliationHolds: { total: 0, returned: 0, truncated: false },
    previewRequestPending: false,
    importRequestPending: false,
    phase3RequestPending: false,
    accountTestRequestPending: false,
    cleanupRequestPending: false,
    reconciliationAckPending: false,
    snapshotRefreshPending: false,
    snapshotRequestSequence: 0,
    snapshotRequestsPending: 0,
    jobInventoryVerified: false,
    jobInventoryProbeSequence: 0,
  };
  const context = {
    URLSearchParams,
    state: stateForTest,
    elements: {
      historicalToggle: { checked: false },
      loadingLabel: {},
      refreshButton: {},
      statusFilter: {},
      availabilityFilter: {},
      diffFilter: {},
    },
    apiFetch(url) {
      calls.push(url);
      if (url === '/api/jobs?limit=200') {
        inventoryAttempt += 1;
        return Promise.resolve({
          ok: true,
          json: async () => ({
            jobs: [],
            activeJobs: inventoryAttempt === 1
              ? { total: 1, returned: 0, truncated: true }
              : { total: 0, returned: 0, truncated: false },
            reconciliationHolds: { total: 0, returned: 0, truncated: false },
          }),
        });
      }
      snapshotAttempt += 1;
      if (snapshotAttempt === 1) return Promise.reject(new Error('snapshot offline'));
      return Promise.resolve({
        ok: true,
        json: async () => ({
          marker: 'fresh',
          rows: [],
          filters: { statuses: [], availabilities: [], diffKinds: [] },
          sub2api: { readStatus: 'ok', apiError: null, statsError: null },
        }),
      });
    },
    renderJob() {},
    stopJobPolling() {},
    beginJobWatchGeneration() {},
    updateActionState() {},
    showNotice: (...args) => notices.push(args),
    aggregateJobs: (jobs) => jobs[0] || null,
    watchJobs: async () => {},
    terminalJob: () => false,
    jobNeedsReconciliation: () => false,
    sub2ApiReadStatus: () => 'ok',
    applyFilters() {},
    loadAccountTestModels() {},
    renderMetrics() {},
    renderPlan: (plan) => { stateForTest.plan = plan; },
    renderSelectOptions() {},
    reconciliationHoldJobs: () => [],
    window: {
      clearTimeout() {},
      setTimeout(callback, delayMs) {
        timers.push({ callback, delayMs });
        return timers.length;
      },
    },
  };
  vm.runInNewContext(lockContract + '\n' + resumeContract + '\n' + snapshotContract + `
    snapshotPromise = loadSnapshot({ resumeJobs: true });
  `, context);
  assert.deepEqual(calls, ['/api/jobs?limit=200']);
  assert.equal(await context.snapshotPromise, false);
  assert.equal(stateForTest.jobInventoryVerified, false);
  assert.equal(stateForTest.snapshot.marker, 'old');
  assert.equal(stateForTest.plan, null);
  assert.equal(stateForTest.snapshotRefreshPending, true);
  assert.equal(context.actionsLocked(), true);
  assert.equal(timers.length, 1);
  assert.equal(timers[0].delayMs, 15000);

  timers[0].callback();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls, [
    '/api/jobs?limit=200',
    '/api/jobs?limit=200',
    '/api/snapshot?withSub2api=1',
  ]);
  assert.equal(stateForTest.jobInventoryVerified, true);
  assert.equal(stateForTest.snapshot.marker, 'old');
  assert.equal(stateForTest.snapshotRefreshPending, true);
  assert.equal(context.actionsLocked(), true);
  assert.match(notices.at(-1)[0], /snapshot offline/);

  assert.equal(await vm.runInNewContext('loadSnapshot({ resumeJobs: true })', context), true);
  assert.deepEqual(calls.slice(-2), ['/api/jobs?limit=200', '/api/snapshot?withSub2api=1']);
  assert.equal(stateForTest.snapshot.marker, 'fresh');
  assert.equal(stateForTest.snapshotRefreshPending, false);
  assert.equal(context.actionsLocked(), false);
});

test('frontend starts an active-job watcher without blocking the inventory-aligned snapshot', async () => {
  const resumeContract = sourceSection('async function resumeActiveJob', 'async function loadSnapshot');
  const snapshotContract = sourceSection('async function loadSnapshot', "elements.refreshButton.addEventListener('click'");
  const calls = [];
  const watched = [];
  const jobId = 'job_' + 'a'.repeat(24);
  const stateForTest = {
    snapshot: { marker: 'old' },
    selected: new Set(),
    selectionRevision: 0,
    jobs: [],
    job: null,
    reconciliationHolds: { total: 0, returned: 0, truncated: false },
    snapshotRefreshPending: false,
    snapshotRequestSequence: 0,
    snapshotRequestsPending: 0,
    jobInventoryVerified: true,
    jobInventoryProbeSequence: 0,
  };
  const context = {
    URLSearchParams,
    state: stateForTest,
    elements: {
      historicalToggle: { checked: false },
      loadingLabel: {},
      refreshButton: {},
      statusFilter: {},
      availabilityFilter: {},
      diffFilter: {},
    },
    apiFetch: async (url) => {
      calls.push(url);
      if (url === '/api/jobs?limit=200') {
        return {
          ok: true,
          json: async () => ({
            jobs: [{ id: jobId, type: 'phase3', status: 'queued' }],
            activeJobs: { total: 1, returned: 1, truncated: false },
            reconciliationHolds: { total: 0, returned: 0, truncated: false },
          }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          marker: 'fresh',
          rows: [],
          filters: { statuses: [], availabilities: [], diffKinds: [] },
          sub2api: { readStatus: 'ok', apiError: null, statsError: null },
        }),
      };
    },
    renderJob() {},
    renderPlan() {},
    stopJobPolling() {},
    beginJobWatchGeneration() {},
    updateActionState() {},
    showNotice() {},
    aggregateJobs: (jobs) => jobs[0] || null,
    watchJobs: (ids, type) => {
      watched.push({ ids, type });
      return new Promise(() => {});
    },
    terminalJob: () => false,
    jobNeedsReconciliation: () => false,
    sub2ApiReadStatus: () => 'ok',
    applyFilters() {},
    loadAccountTestModels() {},
    renderMetrics() {},
    renderSelectOptions() {},
    window: { clearTimeout() {}, setTimeout() {} },
  };
  vm.runInNewContext(resumeContract + '\n' + snapshotContract + `
    snapshotPromise = loadSnapshot({ resumeJobs: true });
  `, context);
  assert.equal(await context.snapshotPromise, true);
  assert.deepEqual(calls, ['/api/jobs?limit=200', '/api/snapshot?withSub2api=1']);
  assert.deepEqual(watched.map((item) => ({ ...item, ids: [...item.ids] })), [{
    ids: [jobId],
    type: 'phase3',
  }]);
  assert.equal(stateForTest.snapshot.marker, 'fresh');
  assert.equal(stateForTest.snapshotRefreshPending, false);
});

test('frontend restores the newest terminal reconciliation warning when no job is active', async () => {
  const resultContract = sourceSection('function tokenImportResultCounts', 'function renderJob');
  const resumeContract = sourceSection('async function resumeActiveJob', 'async function loadSnapshot');
  let listedJobs = [];
  const rendered = [];
  const notices = [];
  const snapshotRefreshes = [];
  const stateForTest = { jobs: [], job: null };
  const context = {
    state: stateForTest,
    finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0,
    apiFetch: async () => ({
      ok: true,
      json: async () => ({
        jobs: listedJobs,
        activeJobs: {
          total: listedJobs.filter((job) => ['queued', 'running'].includes(job.status)).length,
          returned: listedJobs.filter((job) => ['queued', 'running'].includes(job.status)).length,
          truncated: false,
        },
        reconciliationHolds: {
          total: listedJobs.filter((job) => job?.result?.reconciliationHold === true).length,
          returned: listedJobs.filter((job) => job?.result?.reconciliationHold === true).length,
          truncated: false,
        },
      }),
    }),
    renderJob: (job) => rendered.push(job),
    renderPlan() {},
    stopJobPolling() {},
    beginJobWatchGeneration() {},
    updateActionState() {},
    showNotice: (...args) => notices.push(args),
    aggregateJobs: (jobs) => jobs[0] || null,
    watchJobs: async () => {},
    loadSnapshot: async (options) => {
      snapshotRefreshes.push(options);
      stateForTest.snapshotRefreshPending = false;
      return true;
    },
    terminalJob: (status) => ['succeeded', 'partial', 'failed', 'interrupted'].includes(status),
    window: { setTimeout() {} },
  };
  vm.runInNewContext(resultContract + '\n' + resumeContract, context);

  listedJobs = [
    { id: 'newer-ordinary', type: 'account_test', status: 'failed', result: { failed: 1 } },
    {
      id: 'account-reconciliation',
      type: 'account_test',
      status: 'failed',
      result: {
        requiresReconciliation: true,
        results: [{
          accountId: 25,
          status: 'failed',
          code: 'account_scheduler_reconciliation_required',
          requiresReconciliation: true,
          reconciliationScope: 'scheduler',
          reconciliationReason: 'timeout',
          enabled: null,
          enabledKnown: false,
        }],
      },
    },
  ];
  await vm.runInNewContext('resumeActiveJob()', context);
  assert.equal(stateForTest.job.id, 'account-reconciliation');
  assert.equal(rendered.at(-1).id, 'account-reconciliation');
  assert.equal(notices.at(-1)[1], 'notice-warning');
  assert.match(notices.at(-1)[0], /账号 ID #25/);
  assert.match(notices.at(-1)[0], /不要重复测试/);
  assert.deepEqual({ ...snapshotRefreshes.at(-1) }, { expectedInventoryProbeSequence: 1 });

  listedJobs = [{
    id: 'token-reconciliation',
    type: 'token_import',
    status: 'partial',
    result: {
      requiresReconciliation: true,
      imported: [{ requiresReconciliation: true, outcome: 'requires_reconciliation' }],
    },
  }];
  await vm.runInNewContext('resumeActiveJob()', context);
  assert.equal(stateForTest.job.id, 'token-reconciliation');
  assert.match(notices.at(-1)[0], /Token 导入/);
  assert.match(notices.at(-1)[0], /不要重复提交/);
  assert.deepEqual({ ...snapshotRefreshes.at(-1) }, { expectedInventoryProbeSequence: 2 });
});

test('frontend usage formatting never turns missing statistics into zero', () => {
  const usageContract = sourceSection('function finiteNumber', 'function badgeClass');
  const context = {};
  vm.runInNewContext(usageContract + `
    result = {
      missing: formatUsage({}),
      invalid: formatUsage({ totalTokens: 'not-a-number', requests: '' }),
      explicitZero: formatUsage({ totalTokens: 0, requests: 0 }),
      partialZero: formatUsage({ totalTokens: 0 }),
      requestsOnly: formatUsage({ requests: 4 }),
      nestedMissing: formatPeriodUsage({ current: {} }),
    };
  `, context);
  assert.deepEqual({ ...context.result }, {
    missing: '-',
    invalid: '-',
    explicitZero: '0',
    partialZero: '0 / - 次',
    requestsOnly: '- / 4 次',
    nestedMissing: '-',
  });
});

test('frontend token import totals separate errors, runtime skips, and successes', () => {
  const countsContract = sourceSection('function tokenImportResultCounts', 'function renderJob');
  const context = { finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0 };
  vm.runInNewContext(countsContract + `
    result = tokenImportResultCounts({
      imported: [
        { action: 'create' },
        { action: 'update', error: 'failed' },
        { action: 'skip', skipped: true },
      ],
      failed: 99,
      runtimeSkipped: 99,
    });
  `, context);
  assert.deepEqual({ ...context.result }, {
    succeeded: 1,
    skipped: 1,
    failed: 1,
    reconciliation: 0,
    notAttempted: 0,
  });
});

test('frontend separates unknown write outcomes from failures and shows halted items', () => {
  const countsContract = sourceSection('function tokenImportResultCounts', 'function renderJob');
  const renderContract = sourceSection('function renderJob', 'function stopJobPolling');
  const context = {
    finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0,
    elements: {
      jobPanel: { dataset: {} },
      jobTitle: {},
      jobStatus: {},
      jobMeta: {},
    },
    jobStatusClass: () => 'badge-danger',
    jobStatusLabel: () => '失败',
    formatDate: () => '现在',
  };
  vm.runInNewContext(countsContract + '\n' + renderContract + `
    const importResult = {
      imported: [
        { action: 'create' },
        {
          action: 'update',
          error: 'request timed out',
          outcome: 'requires_reconciliation',
          requiresReconciliation: true,
          writeOutcomeUnknown: true,
          reconciliationReason: 'timeout',
        },
      ],
      notAttempted: [
        { action: 'create', outcome: 'not_attempted' },
        { action: 'update', outcome: 'not_attempted' },
      ],
      failed: 1,
      requiresReconciliation: true,
    };
    counts = tokenImportResultCounts(importResult);
    notice = tokenImportReconciliationNotice(importResult);
    renderJob({
      id: 'import-job',
      type: 'token_import',
      status: 'partial',
      result: importResult,
      finishedAt: 'now',
    });
    rendered = {
      status: elements.jobStatus.textContent,
      statusClass: elements.jobStatus.className,
      detail: elements.jobMeta.textContent,
    };
  `, context);
  assert.deepEqual({ ...context.counts }, {
    succeeded: 1,
    skipped: 0,
    failed: 0,
    reconciliation: 1,
    notAttempted: 2,
  });
  assert.deepEqual({ ...context.rendered }, {
    status: '待人工核对',
    statusClass: 'badge badge-warning',
    detail: '成功 1 · 跳过 0 · 失败 0 · 待人工核对 1 · 未执行 2 · 已停止后续写入 · 原因：请求超时，远端是否写入未知 · 现在',
  });
  assert.equal(
    context.notice,
    'Token 导入有 1 个写入结果待人工核对，另有 2 个账号未执行。请先按账号 ID 和强身份字段核对 Sub2API，确认前不要重复提交。',
  );
  const terminalBranch = sourceSection(
    'if (loaded.every((job) => terminalJob(job.status)))',
    '// Even a failed/interrupted operation',
  );
  assert.match(terminalBranch, /loaded\.filter\(jobNeedsReconciliation\)/);
  assert.match(terminalBranch, /reconciliationNoticeForJobs\(reconciliationJobs\)/);
  assert.match(terminalBranch, /terminalNoticeKind = 'notice-warning'/);
});

test('frontend renders account-test reconciliation as a separate yellow outcome for single and batch jobs', () => {
  const resultContract = sourceSection('function tokenImportResultCounts', 'function renderJob');
  const renderContract = sourceSection('function renderJob', 'function stopJobPolling');
  const context = {
    finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0,
    elements: {
      jobPanel: { dataset: {} },
      jobTitle: {},
      jobStatus: {},
      jobMeta: {},
    },
    jobStatusClass: () => 'badge-danger',
    jobStatusLabel: () => '失败',
    formatDate: () => '现在',
  };
  vm.runInNewContext(resultContract + '\n' + renderContract + `
    const accountResult = {
      requested: 5,
      succeeded: 1,
      failed: 2,
      skipped: 2,
      requiresReconciliation: true,
      reconciliationCount: 1,
      notAttemptedCount: 1,
      results: [
        { accountId: 21, status: 'succeeded', code: 'account_test_succeeded' },
        { accountId: 22, status: 'failed', code: 'upstream_test_failed' },
        { accountId: 23, status: 'skipped', code: 'account_not_found' },
        {
          accountId: 25,
          status: 'failed',
          code: 'account_scheduler_reconciliation_required',
          requiresReconciliation: true,
          reconciliationScope: 'scheduler',
          reconciliationReason: 'rollback_state_changed',
          enabled: null,
          enabledKnown: false,
        },
        { accountId: 26, status: 'skipped', code: 'account_test_not_attempted_reconciliation' },
      ],
    };
    counts = accountTestResultCounts(accountResult);
    notice = accountTestReconciliationNotice([accountResult]);
    renderJob({
      id: 'account-job',
      type: 'account_test',
      status: 'failed',
      result: accountResult,
      finishedAt: 'now',
    });
    single = {
      status: elements.jobStatus.textContent,
      statusClass: elements.jobStatus.className,
      panelStatus: elements.jobPanel.dataset.status,
      detail: elements.jobMeta.textContent,
    };
    renderJob({
      id: 'account-job,account-job-two',
      type: 'batch',
      status: 'partial',
      jobs: [
        { id: 'account-job', type: 'account_test', status: 'failed', result: accountResult },
        {
          id: 'account-job-two',
          type: 'account_test',
          status: 'succeeded',
          result: { results: [{ accountId: 27, status: 'succeeded' }] },
        },
      ],
    });
    batch = {
      title: elements.jobTitle.textContent,
      status: elements.jobStatus.textContent,
      statusClass: elements.jobStatus.className,
      detail: elements.jobMeta.textContent,
    };
  `, context);

  assert.deepEqual({ ...context.counts }, {
    succeeded: 1,
    failed: 1,
    skipped: 1,
    reconciliation: 1,
    notAttempted: 1,
  });
  assert.equal(context.single.status, '待人工核对');
  assert.equal(context.single.statusClass, 'badge badge-warning');
  assert.equal(context.single.panelStatus, 'partial');
  assert.match(context.single.detail, /成功 1 · 失败 1 · 跳过 1 · 待人工核对 1 · 未执行 1/);
  assert.match(context.single.detail, /账号 ID #25/);
  assert.match(context.single.detail, /范围：调度写入与回滚/);
  assert.match(context.single.detail, /调度状态未知/);
  assert.match(context.single.detail, /原因：回滚前账号状态已被修改/);
  assert.match(context.single.detail, /确认前勿重试/);
  assert.match(context.notice, /另有 1 个账号未执行/);
  assert.match(context.notice, /按账号 ID 和强身份字段核对 Sub2API/);
  assert.equal(context.batch.title, '上游账号批量测试');
  assert.equal(context.batch.status, '待人工核对');
  assert.equal(context.batch.statusClass, 'badge badge-warning');
  assert.match(context.batch.detail, /成功 2 · 失败 1 · 跳过 1 · 待人工核对 1 · 未执行 1/);
  assert.match(context.batch.detail, /完成 2\/2/);
});

test('frontend recognizes explicitly unattempted account tests without downgrading reconciliation', () => {
  const resultContract = sourceSection('function tokenImportResultCounts', 'function renderJob');
  const context = {
    finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0,
  };
  vm.runInNewContext(resultContract + `
    result = accountTestResultCounts({
      results: [
        {
          attempted: false,
          status: 'skipped',
          code: 'account_test_job_timeout',
          interruptionReason: 'timeout',
        },
        {
          attempted: false,
          status: 'skipped',
          code: 'account_test_not_attempted_interrupted',
          interruptionReason: 'interrupted',
        },
        {
          attempted: false,
          status: 'skipped',
          code: 'account_test_not_attempted_reconciliation',
        },
        {
          attempted: true,
          status: 'failed',
          code: 'account_scheduler_reconciliation_required',
          requiresReconciliation: true,
        },
      ],
    });
  `, context);
  assert.deepEqual({ ...context.result }, {
    succeeded: 0,
    failed: 0,
    skipped: 0,
    reconciliation: 1,
    notAttempted: 3,
  });
});

test('frontend gives recovery probes and unknown jobs unambiguous titles', () => {
  const renderContract = sourceSection('function renderJob', 'function stopJobPolling');
  const context = {
    elements: {
      jobPanel: { dataset: {} },
      jobTitle: {},
      jobStatus: {},
      jobMeta: {},
    },
    jobStatusClass: () => 'badge-neutral',
    jobStatusLabel: () => '未知',
    jobNeedsReconciliation: () => false,
    formatDate: () => '现在',
  };
  vm.runInNewContext(renderContract + `
    const titleFor = (job) => {
      renderJob(job);
      return elements.jobTitle.textContent;
    };
    result = {
      resume: titleFor({ id: 'resume-probe', type: 'batch', status: 'unknown' }),
      activeTruncated: titleFor({
        id: 'active-list-truncated', type: 'batch', status: 'unknown', jobs: [],
      }),
      holdTruncated: titleFor({
        id: 'hold-list-truncated', type: 'batch', status: 'unknown', jobs: [],
      }),
      emptyUnknown: titleFor({ id: 'unknown-empty', type: 'batch', status: 'unknown', jobs: [] }),
      unknown: titleFor({ id: 'unknown-job', type: 'future_job', status: 'unknown' }),
      tokenImport: titleFor({ id: 'known-import', type: 'token_import', status: 'running' }),
    };
  `, context);
  assert.deepEqual({ ...context.result }, {
    resume: '后台任务状态检查',
    activeTruncated: '后台任务状态检查',
    holdTruncated: '后台任务状态检查',
    emptyUnknown: '后台任务',
    unknown: '后台任务',
    tokenImport: 'Token 导入任务',
  });
});

test('frontend renders a completed Phase3 result without bogus zero counters', () => {
  const renderJob = sourceSection('function renderJob', 'function stopJobPolling');
  const context = {
    elements: {
      jobPanel: { dataset: {} },
      jobTitle: {},
      jobStatus: {},
      jobMeta: {},
    },
    jobStatusClass: () => 'badge-success',
    jobStatusLabel: () => '已完成',
    jobNeedsReconciliation: () => false,
    formatDate: () => '现在',
  };
  vm.runInNewContext(renderJob + `
    renderJob({
      id: 'phase3-job',
      type: 'phase3',
      status: 'succeeded',
      result: { tokenFile: 'redacted.json' },
      finishedAt: 'now',
    });
    result = elements.jobMeta.textContent;
  `, context);
  assert.match(context.result, /检测到 token 更新/);
  assert.doesNotMatch(context.result, /成功 0/);
});

test('frontend reports an omitted large job summary without inventing zero totals', () => {
  const renderJob = sourceSection('function renderJob', 'function stopJobPolling');
  const context = {
    elements: {
      jobPanel: { dataset: {} },
      jobTitle: {},
      jobStatus: {},
      jobMeta: {},
    },
    jobStatusClass: () => 'badge-success',
    jobStatusLabel: () => '已完成',
    jobNeedsReconciliation: () => false,
    formatDate: () => '现在',
  };
  vm.runInNewContext(renderJob + `
    renderJob({
      id: 'large-account-test',
      type: 'account_test',
      status: 'succeeded',
      result: { summaryUnavailable: true, summaryReason: 'result_too_large' },
      finishedAt: 'now',
    });
    accountDetail = elements.jobMeta.textContent;
    renderJob({
      id: 'large-token-import',
      type: 'token_import',
      status: 'succeeded',
      result: { summaryUnavailable: true, summaryReason: 'result_too_large' },
      finishedAt: 'now',
    });
    tokenDetail = elements.jobMeta.textContent;
  `, context);
  for (const detail of [context.accountDetail, context.tokenDetail]) {
    assert.match(detail, /列表未加载详细摘要/);
    assert.doesNotMatch(detail, /成功 0|失败 0|跳过 0/);
  }
});

test('token import terminal status distinguishes total failure from partial success', () => {
  assert.equal(tokenImportJobStatus({
    imported: [{ action: 'update', error: 'failed' }, { action: 'create', error: 'failed' }],
  }), 'failed');
  assert.equal(tokenImportJobStatus({
    imported: [{ action: 'update', error: 'failed' }, { action: 'create' }],
  }), 'partial');
  assert.equal(tokenImportJobStatus({
    imported: [{ action: 'skip', skipped: true }],
  }), 'succeeded');
  assert.equal(tokenImportJobStatus({ failed: 1 }), 'failed');
});

test('frontend difference metric excludes in-sync rows and starts imports with the right task type', () => {
  const comparisonContract = sourceSection('function sub2ApiReadStatus', 'function updateImportButtonState');
  const renderMetrics = sourceSection('function renderMetrics', 'function selectedRowsFromView');
  const context = {
    elements: {
      tokenCount: {},
      tokenDetail: {},
      accountCount: {},
      accountDetail: {},
      diffCount: {},
      diffDetail: {},
      lastRead: {},
      modeBadge: {},
      cleanupButton: null,
    },
    state: {},
    finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0,
    kindLabel: (value) => value,
    formatDate: (value) => value,
    actionsLocked: () => false,
  };
  vm.runInNewContext(comparisonContract + '\n' + renderMetrics + `
    renderMetrics({
      sources: { summary: { tokenCount: 4, validTokenCount: 4, invalidTokenCount: 0 } },
      sub2api: { readStatus: 'ok', accountCount: 4, apiError: null, statsError: null },
      diff: { comparisonStatus: 'complete', counts: { in_sync: 3, token_only: 1 } },
      generatedAt: 'now',
      readOnly: true,
    });
    complete = {
      accountCount: elements.accountCount.textContent,
      count: elements.diffCount.textContent,
      detail: elements.diffDetail.textContent,
    };
    renderMetrics({
      sources: { summary: { tokenCount: 4, validTokenCount: 4, invalidTokenCount: 0 } },
      sub2api: { readStatus: 'failed', accountCount: null, apiError: 'offline', statsError: null },
      diff: { comparisonStatus: 'unavailable', counts: { remote_unknown: 4 } },
      generatedAt: 'now',
      readOnly: true,
    });
    unavailable = {
      accountCount: elements.accountCount.textContent,
      count: elements.diffCount.textContent,
      detail: elements.diffDetail.textContent,
    };
  `, context);
  assert.deepEqual({ ...context.complete }, { accountCount: '4', count: '1', detail: 'token_only 1' });
  assert.deepEqual({ ...context.unavailable }, {
    accountCount: '-',
    count: '-',
    detail: 'Sub2API 状态未知，无法比较',
  });
  assert.match(source, /remote_unknown:\s*'远端未知'/);
  const importHandler = sourceSection("elements.importButton.addEventListener('click'", "elements.phase3Button.addEventListener('click'");
  assert.match(importHandler, /watchJob\(body\.jobId, 'token_import'\)/);
});

test('frontend treats expired token cleanup as a durable polled task', () => {
  const cleanupHandler = sourceSection(
    "if (elements.cleanupButton) {",
    "elements.clearSelectionButton.addEventListener",
  );
  const watchContract = sourceSection('async function watchJobs', 'async function watchJob');
  const resumeContract = sourceSection('async function resumeActiveJob', 'async function loadSnapshot');
  assert.match(cleanupHandler, /\^job_\[a-f0-9\]\{24\}\$/);
  assert.match(cleanupHandler, /watchJob\(result\.jobId, 'token_cleanup'\)/);
  assert.doesNotMatch(cleanupHandler, /已隔离 ' \+ \(result\.count/);
  assert.match(watchContract, /job\.type === 'token_cleanup'/);
  assert.match(watchContract, /state\.cleanupRequestPending = false/);
  assert.match(resumeContract, /job\.type === 'token_cleanup'/);
  assert.match(resumeContract, /state\.cleanupRequestPending = true/);
});

test('frontend blocks global cleanup when stranded quarantine claims require recovery', async () => {
  const cleanupHandler = sourceSection(
    "if (elements.cleanupButton) {",
    "elements.clearSelectionButton.addEventListener",
  );
  let clickHandler;
  let mutationRequests = 0;
  let confirmations = 0;
  const notices = [];
  const context = {
    elements: {
      cleanupButton: {
        addEventListener(event, handler) {
          assert.equal(event, 'click');
          clickHandler = handler;
        },
      },
    },
    state: { cleanupRequestPending: false },
    updateActionState() {},
    apiFetch: async () => ({
      ok: true,
      async json() {
        return {
          version: 'a'.repeat(64),
          count: 0,
          items: [],
          recoveryRequired: true,
          claimCount: 2,
        };
      },
    }),
    idempotentMutationFetch: async () => { mutationRequests += 1; },
    showNotice: (...args) => notices.push(args),
    watchJob: async () => {},
    window: { confirm: () => { confirmations += 1; return true; } },
  };
  vm.runInNewContext(cleanupHandler, context);
  await clickHandler();
  assert.equal(mutationRequests, 0);
  assert.equal(confirmations, 0);
  assert.equal(context.state.cleanupRequestPending, false);
  assert.match(notices.at(-1)[0], /2 个未完成的过期 token 隔离 claim/);
});

test('frontend globally locks mutating actions while any request or task is unresolved', () => {
  const lockContract = sourceSection('function actionRequestPending', 'function renderMetrics');
  const updateContract = sourceSection('function updateActionState', 'function applyColumnVisibility');
  assert.match(lockContract, /previewRequestPending/);
  assert.match(lockContract, /importRequestPending/);
  assert.match(lockContract, /phase3RequestPending/);
  assert.match(lockContract, /accountTestRequestPending/);
  assert.match(lockContract, /cleanupRequestPending/);
  assert.match(lockContract, /snapshotRequestsPending > 0/);
  assert.match(lockContract, /\['queued', 'running', 'unknown'\]/);
  assert.match(updateContract, /phase3Button\.disabled = mutationLocked/);
  assert.match(updateContract, /accountTestButton\.disabled = mutationLocked/);
  assert.match(updateContract, /previewButton\.disabled = locked/);
  assert.match(updateContract, /previewButton\.disabled = locked[\s\S]*!comparisonAvailable\(\)[\s\S]*Boolean\(syncProblem\)/);
  assert.match(updateContract, /phase3Button\.disabled = mutationLocked \|\| !canRunPhase3/);
  assert.match(updateContract, /clearSelectionButton\.disabled = locked/);
  assert.match(updateContract, /selectAll\.disabled = locked/);
  assert.match(updateContract, /input\.disabled = locked/);
  assert.match(updateContract, /updateImportButtonState\(\)/);
  assert.match(updateContract, /cleanupButton\.disabled = Boolean\(state\.snapshot\?\.readOnly\) \|\| mutationLocked/);
  assert.match(updateContract, /writeBlocked = reconciliationWriteBlocked\(\)/);
  assert.match(updateContract, /当前全部写操作已阻止/);
});

test('mobile layout keeps controls usable and wide tables horizontally scrollable', () => {
  assert.match(stylesSource, /\.table-wrap, \.plan-wrap \{ overflow: auto; \}/);
  const mobile = stylesSource.slice(stylesSource.indexOf('@media (max-width: 700px)'));
  assert.match(mobile, /\.toolbar \{ position: static;[^}]*flex-direction: column;/);
  assert.match(mobile, /\.toolbar label, \.toolbar \.search-field \{ width: 100%; min-width: 0; \}/);
  assert.match(mobile, /\.toolbar \.search-field \{ flex: 0 0 auto; \}/);
  assert.match(mobile, /\.job-copy p \{ white-space: normal; \}/);
  assert.match(mobile, /\.reconciliation-ack-button \{ width: calc\(100% - 43px\); margin-left: 43px; \}/);
});

test('frontend refreshes every terminal job outcome before preserving its notice', () => {
  const watchContract = sourceSection('async function watchJobs', 'async function watchJob');
  const terminalStart = watchContract.indexOf('if (loaded.every((job) => terminalJob(job.status)))');
  const terminalEnd = watchContract.indexOf('schedulePoll(() => poll(0), 1200)', terminalStart);
  const terminalBranch = watchContract.slice(terminalStart, terminalEnd);
  assert.notEqual(terminalStart, -1);
  assert.notEqual(terminalEnd, -1);
  assert.match(terminalBranch, /snapshotRefreshPending = true;[\s\S]*const snapshotRefreshed = await loadSnapshot\(\{ isCurrent: watcherIsCurrent \}\)/);
  assert.match(terminalBranch, /if \(!snapshotRefreshed\)[\s\S]*保持操作锁定[\s\S]*schedulePoll\(\(\) => poll\(0\), 5000\);\s*return;/);
  assert.match(terminalBranch, /snapshotRefreshPending = false;\s*showNotice\(terminalNotice, terminalNoticeKind\)/);
  assert.match(sourceSection('async function loadSnapshot', "elements.refreshButton.addEventListener('click'"), /return loaded;/);
});

test('frontend retries a 401 with a fresh bounded signal and a password dialog token', async () => {
  const apiHeadersContract = sourceSection('let memoryPanelToken', 'const API_REQUEST_TIMEOUT_MS');
  const apiFetchContract = sourceSection('const API_REQUEST_TIMEOUT_MS', 'function renderSelectOptions');
  const values = new Map();
  const calls = [];
  const listeners = new Map();
  const input = { value: '', focus() {} };
  const dialog = {
    returnValue: '',
    addEventListener(type, listener) { listeners.set(type, listener); },
    removeEventListener(type, listener) {
      if (listeners.get(type) === listener) listeners.delete(type);
    },
    showModal() {
      queueMicrotask(() => {
        input.value = 'new-admin-token';
        this.returnValue = 'confirm';
        listeners.get('close')?.();
      });
    },
  };
  const context = {
    AbortController,
    Headers,
    Response,
    URL,
    elements: {
      adminTokenDialog: dialog,
      adminTokenInput: input,
      adminTokenOrigin: {},
    },
    fetch: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ attempt: calls.length }), {
        status: calls.length === 1 ? 401 : 200,
        headers: { 'content-type': 'application/json' },
      });
    },
    sessionStorage: {
      getItem: (key) => values.get(key) || null,
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    window: {
      clearTimeout,
      location: { origin: 'http://127.0.0.1:4170' },
      setTimeout,
    },
  };
  vm.runInNewContext(apiHeadersContract + '\n' + apiFetchContract + `
    resultPromise = apiFetch('/api/health', {
      timeoutMs: 1000,
      headers: { 'Idempotency-Key': 'idem_v1_401_retry_12345678901234567890' },
    });
    blockedPromise = resultPromise.then(() => apiFetch('https://example.invalid/api/health', { timeoutMs: 1000 }));
  `, context);
  const response = await context.resultPromise;
  assert.equal(response.status, 200);
  assert.equal(calls.length, 2);
  assert.notEqual(calls[0].options.signal, calls[1].options.signal);
  assert.equal(calls[0].options.headers.get('x-panel-token'), null);
  assert.equal(calls[1].options.headers.get('x-panel-token'), 'new-admin-token');
  assert.equal(calls[0].options.headers.get('idempotency-key'), 'idem_v1_401_retry_12345678901234567890');
  assert.equal(calls[1].options.headers.get('idempotency-key'), 'idem_v1_401_retry_12345678901234567890');
  assert.equal(calls.every((call) => call.options.redirect === 'error'), true);
  assert.equal(input.value, '');
  assert.equal(context.elements.adminTokenOrigin.textContent, 'http://127.0.0.1:4170');
  await assert.rejects(context.blockedPromise, /拒绝向非同源地址发送面板凭证/);
  assert.equal(calls.length, 2);
});

test('frontend keeps independent unknown intent keys and clears only their confirmed 202', async () => {
  const contract = sourceSection('const MUTATION_PENDING_PREFIX', 'function renderSelectOptions');
  const values = new Map();
  const calls = [];
  let attempt = 0;
  const crypto = require('node:crypto').webcrypto;
  const context = {
    TextEncoder,
    apiFetch: async (url, options) => {
      calls.push({ url, options });
      attempt += 1;
      if (attempt < 3) throw new TypeError('simulated lost response');
      return {
        ok: true,
        status: 202,
        async json() { return { jobId: 'job_' + 'a'.repeat(24), status: 'queued' }; },
      };
    },
    sessionStorage: {
      getItem: (key) => values.get(key) || null,
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    window: { crypto },
  };
  vm.runInNewContext(contract + `
    firstPromise = idempotentMutationFetch('account_test', '/api/account-tests', {
      targets: [{ accountId: 7, targetRevision: 'revision' }],
      modelId: 'model-a',
      prompt: 'prompt-marker-must-not-enter-storage',
    });
  `, context);
  await assert.rejects(context.firstPromise, /simulated lost response/);
  const firstKey = calls[0].options.headers['Idempotency-Key'];
  assert.match(firstKey, /^[A-Za-z0-9][A-Za-z0-9._:-]{19,127}$/);
  assert.equal([...values.values()].join('').includes('prompt-marker-must-not-enter-storage'), false);
  const firstStored = JSON.parse([...values.values()][0]);
  assert.equal(firstStored.entries.length, 1);
  assert.equal(Number.isSafeInteger(firstStored.entries[0].createdAt), true);
  assert.ok(Date.now() - firstStored.entries[0].createdAt < 10000);

  vm.runInNewContext(`
    secondPromise = idempotentMutationFetch('account_test', '/api/account-tests', {
      targets: [{ accountId: 7, targetRevision: 'revision' }],
      modelId: 'model-b',
      prompt: 'prompt-marker-must-not-enter-storage',
    });
  `, context);
  await assert.rejects(context.secondPromise, /simulated lost response/);
  const secondKey = calls[1].options.headers['Idempotency-Key'];
  assert.notEqual(secondKey, firstKey);
  assert.equal(values.size, 1);
  assert.equal(JSON.parse([...values.values()][0]).entries.length, 2);

  vm.runInNewContext(`
    thirdPromise = idempotentMutationFetch('account_test', '/api/account-tests', {
      targets: [{ accountId: 7, targetRevision: 'revision' }],
      modelId: 'model-a',
      prompt: 'prompt-marker-must-not-enter-storage',
    });
  `, context);
  const accepted = await context.thirdPromise;
  assert.equal(accepted.response.status, 202);
  assert.equal(calls[2].options.headers['Idempotency-Key'], firstKey);
  assert.equal(JSON.parse([...values.values()][0]).entries.length, 1);

  vm.runInNewContext(`
    fourthPromise = idempotentMutationFetch('account_test', '/api/account-tests', {
      targets: [{ accountId: 7, targetRevision: 'revision' }],
      modelId: 'model-b',
      prompt: 'prompt-marker-must-not-enter-storage',
    });
  `, context);
  assert.equal((await context.fourthPromise).response.status, 202);
  assert.equal(calls[3].options.headers['Idempotency-Key'], secondKey);
  assert.equal(values.size, 0);
  assert.equal(calls.every((call) => call.options.method === 'POST'), true);
});

test('frontend treats a malformed accepted receipt as unknown and retains its idempotency key', async () => {
  const contract = sourceSection('const MUTATION_PENDING_PREFIX', 'function renderSelectOptions');
  const values = new Map();
  const calls = [];
  const crypto = require('node:crypto').webcrypto;
  const context = {
    TextEncoder,
    apiFetch: async (url, options) => {
      calls.push({ url, options });
      return {
        ok: true,
        status: 202,
        async json() {
          return { status: 'queued', jobIds: ['job_' + 'a'.repeat(24)] };
        },
      };
    },
    sessionStorage: {
      getItem: (key) => values.get(key) || null,
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    window: { crypto },
  };
  const invocation = `idempotentMutationFetch('token_import', '/api/sync/import', {
    snapshotVersion: '${'a'.repeat(64)}',
    selectedKeys: ['token:tokens:tokens/example.json'],
  })`;
  vm.runInNewContext(contract, context);
  vm.runInNewContext('firstPromise = ' + invocation, context);
  await assert.rejects(context.firstPromise, /任务回执格式无效.*结果未知.*同一幂等键/);
  assert.equal(JSON.parse(values.get('panelMutationPending:v2:store')).entries.length, 1);
  const firstKey = calls[0].options.headers['Idempotency-Key'];

  vm.runInNewContext('secondPromise = ' + invocation, context);
  await assert.rejects(context.secondPromise, /任务回执格式无效/);
  assert.equal(calls[1].options.headers['Idempotency-Key'], firstKey);
  assert.equal(JSON.parse(values.get('panelMutationPending:v2:store')).entries.length, 1);
});

test('frontend refuses to fetch when an idempotency key cannot be durably read back', async () => {
  const contract = sourceSection('const MUTATION_PENDING_PREFIX', 'function renderSelectOptions');
  const crypto = require('node:crypto').webcrypto;
  for (const failureMode of ['quota', 'silent']) {
    let fetches = 0;
    const values = new Map();
    const context = {
      TextEncoder,
      apiFetch: async () => {
        fetches += 1;
        throw new Error('fetch must not run');
      },
      sessionStorage: {
        getItem: (key) => values.get(key) || null,
        setItem(key, value) {
          if (failureMode === 'quota') throw new DOMException('quota', 'QuotaExceededError');
          if (failureMode !== 'silent') values.set(key, value);
        },
        removeItem: (key) => values.delete(key),
      },
      window: { crypto },
    };
    vm.runInNewContext(contract + `
      resultPromise = idempotentMutationFetch('token_import', '/api/sync/import', {
        snapshotVersion: '${'a'.repeat(64)}',
        selectedKeys: ['token:tokens:tokens/example.json'],
      });
    `, context);
    await assert.rejects(context.resultPromise, /无法可靠保存.*发送前安全停止/);
    assert.equal(fetches, 0, failureMode);
  }
});

test('frontend fails closed instead of evicting sixteen unresolved intents', async () => {
  const contract = sourceSection('const MUTATION_PENDING_PREFIX', 'function renderSelectOptions');
  const crypto = require('node:crypto').webcrypto;
  const values = new Map();
  values.set('panelMutationPending:v2:store', JSON.stringify({
    version: 2,
    entries: Array.from({ length: 16 }, (_, index) => ({
      version: 2,
      workflow: 'account_test',
      bodyDigest: index.toString(16).padStart(64, '0'),
      key: 'idem_v1_pending_' + String(index).padStart(24, '0'),
      createdAt: Date.now(),
    })),
  }));
  let fetches = 0;
  const context = {
    TextEncoder,
    apiFetch: async () => { fetches += 1; },
    sessionStorage: {
      getItem: (key) => values.get(key) || null,
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    window: { crypto },
  };
  vm.runInNewContext(contract + `
    resultPromise = idempotentMutationFetch('token_cleanup', '/api/tokens/expired/delete', {
      version: '${'b'.repeat(64)}',
      confirmation: 'DELETE_EXPIRED_TOKENS',
    });
  `, context);
  await assert.rejects(context.resultPromise, /待确认写操作已达到安全上限/);
  assert.equal(fetches, 0);
  assert.equal(JSON.parse(values.get('panelMutationPending:v2:store')).entries.length, 16);
});

test('frontend refuses expired, unknown-age and future pending keys without fetching', async () => {
  const contract = sourceSection('const MUTATION_PENDING_PREFIX', 'function renderSelectOptions');
  const crypto = require('node:crypto').webcrypto;
  const now = Date.now();
  for (const [label, createdAt] of [
    ['expired', now - 20 * 60 * 60 * 1000],
    ['unknown', undefined],
    ['future', now + 6 * 60 * 1000],
  ]) {
    const values = new Map();
    const entry = {
      version: 2,
      workflow: 'account_test',
      bodyDigest: 'a'.repeat(64),
      key: 'idem_v1_unsafe_age_12345678901234567890',
    };
    if (createdAt !== undefined) entry.createdAt = createdAt;
    values.set('panelMutationPending:v2:store', JSON.stringify({ version: 2, entries: [entry] }));
    let fetches = 0;
    const context = {
      TextEncoder,
      apiFetch: async () => { fetches += 1; },
      sessionStorage: {
        getItem: (key) => values.get(key) || null,
        setItem: (key, value) => values.set(key, value),
        removeItem: (key) => values.delete(key),
      },
      window: { crypto },
    };
    vm.runInNewContext(contract + `
      resultPromise = idempotentMutationFetch('token_cleanup', '/api/tokens/expired/delete', {
        version: '${'b'.repeat(64)}',
        confirmation: 'DELETE_EXPIRED_TOKENS',
      });
    `, context);
    await assert.rejects(context.resultPromise, /\u4eba工核对.*禁止自动更换幂等键/, label);
    assert.equal(fetches, 0, label);
    assert.equal(values.has('panelMutationPending:v2:store'), true, label);
  }
});

test('frontend accepts only bounded unique queued job receipts', () => {
  const contract = sourceSection('const MUTATION_PENDING_PREFIX', 'async function idempotentMutationFetch');
  const context = {};
  vm.runInNewContext(contract + `
    const id = 'job_' + 'a'.repeat(24);
    const secondId = 'job_' + 'b'.repeat(24);
    accepted = [
      acceptedMutationResponse('token_import', { status: 'queued', jobId: id }),
      acceptedMutationResponse('account_test', { status: 'queued', jobId: id }),
      acceptedMutationResponse('token_cleanup', { status: 'queued', jobId: id }),
      acceptedMutationResponse('phase3', { status: 'queued', jobId: id, jobIds: [id] }),
      acceptedMutationResponse('phase3', { status: 'queued', jobId: null, jobIds: [id, secondId] }),
      acceptedMutationResponse('token_import', { status: 'queued', jobIds: [id] }),
      acceptedMutationResponse('phase3', { status: 'queued', jobId: id }),
      acceptedMutationResponse('phase3', { status: 'queued', jobId: null, jobIds: [id, id] }),
      acceptedMutationResponse('account_test', { status: 'queued', jobId: 'invalid' }),
      acceptedMutationResponse('phase3', { status: 'queued', jobId: id, jobIds: [secondId] }),
    ];
  `, context);
  assert.deepEqual([...context.accepted], [
    true, true, true, true, true,
    false, false, false, false, false,
  ]);
});

test('frontend API deadline also bounds a response body that never finishes', async () => {
  const apiHeadersContract = sourceSection('let memoryPanelToken', 'const API_REQUEST_TIMEOUT_MS');
  const apiFetchContract = sourceSection('const API_REQUEST_TIMEOUT_MS', 'function renderSelectOptions');
  const context = {
    AbortController,
    Headers,
    ReadableStream,
    Response,
    URL,
    elements: {},
    fetch: async (url, options) => new Response(new ReadableStream({
      start(controller) {
        options.signal.addEventListener('abort', () => {
          controller.error(new DOMException('aborted', 'AbortError'));
        }, { once: true });
      },
    }), { status: 200 }),
    sessionStorage: {
      getItem: () => null,
      setItem() {},
      removeItem() {},
    },
    window: {
      clearTimeout,
      location: { origin: 'http://127.0.0.1:4170' },
      setTimeout,
    },
  };
  vm.runInNewContext(apiHeadersContract + '\n' + apiFetchContract + `
    resultPromise = apiFetch('/api/snapshot', { timeoutMs: 10 });
  `, context);
  await assert.rejects(context.resultPromise, (error) => (
    error?.name === 'TimeoutError' && /请求超时/.test(error.message)
  ));
});

test('frontend keeps an in-memory token fallback when session storage is unavailable', () => {
  const tokenContract = sourceSection('let memoryPanelToken', 'const API_REQUEST_TIMEOUT_MS');
  const context = {
    Headers,
    sessionStorage: {
      getItem() { throw new DOMException('blocked', 'SecurityError'); },
      setItem() { throw new DOMException('blocked', 'SecurityError'); },
      removeItem() { throw new DOMException('blocked', 'SecurityError'); },
    },
  };
  vm.runInNewContext(tokenContract + `
    savePanelToken('memory-only-token');
    result = {
      saved: readPanelToken(),
      header: apiHeaders().get('x-panel-token'),
    };
    clearPanelToken();
    result.cleared = readPanelToken();
  `, context);
  assert.deepEqual({ ...context.result }, {
    saved: 'memory-only-token',
    header: 'memory-only-token',
    cleared: '',
  });
});

test('frontend keeps concurrent snapshot requests locked and clears selection on replacement', async () => {
  const comparisonContract = sourceSection('function sub2ApiReadStatus', 'function updateImportButtonState');
  const loadSnapshotContract = sourceSection('async function loadSnapshot', "elements.refreshButton.addEventListener('click'");
  const requests = [];
  const lockStates = [];
  const stateForTest = {
    snapshot: null,
    selected: new Set(['same-key']),
    plan: { version: 'old-plan', selectedKeys: ['same-key'], items: [] },
    snapshotRequestSequence: 0,
    snapshotRequestsPending: 0,
    snapshotRefreshPending: false,
    selectionRevision: 4,
    jobInventoryVerified: true,
    jobInventoryProbeSequence: 7,
    job: null,
  };
  const context = {
    URLSearchParams,
    elements: {
      historicalToggle: { checked: false },
      loadingLabel: {},
      refreshButton: {},
      statusFilter: {},
      availabilityFilter: {},
      diffFilter: {},
    },
    state: stateForTest,
    apiFetch: () => new Promise((resolve, reject) => requests.push({ resolve, reject })),
    applyFilters() {},
    loadAccountTestModels() {},
    renderMetrics() {},
    renderPlan: (plan) => { stateForTest.plan = plan; },
    renderSelectOptions() {},
    resumeActiveJob: async () => {},
    showNotice() {},
    updateActionState() {
      lockStates.push(stateForTest.snapshotRequestsPending > 0
        || stateForTest.snapshotRefreshPending);
    },
    watchJobs: async () => {},
  };
  vm.runInNewContext(comparisonContract + '\n' + loadSnapshotContract + `
    firstPromise = loadSnapshot();
    secondPromise = loadSnapshot();
  `, context);
  assert.equal(requests.length, 2);
  assert.equal(stateForTest.snapshotRequestsPending, 2);
  assert.equal(stateForTest.snapshotRefreshPending, true);
  assert.equal(stateForTest.plan, null);
  assert.equal(context.elements.refreshButton.disabled, true);
  const newer = {
    marker: 'newer',
    rows: [{ key: 'same-key' }],
    filters: { statuses: [], availabilities: [], diffKinds: [] },
    sub2api: { apiError: null, statsError: null },
  };
  requests[1].resolve({ ok: true, json: async () => newer });
  assert.equal(await context.secondPromise, true);
  assert.equal(stateForTest.snapshotRequestsPending, 1);
  assert.equal(stateForTest.snapshotRefreshPending, false);
  assert.equal(context.elements.refreshButton.disabled, true);
  assert.equal(context.elements.loadingLabel.hidden, false);
  assert.deepEqual([...stateForTest.selected], []);
  assert.equal(stateForTest.selectionRevision, 5);
  const older = {
    marker: 'older',
    rows: [{ key: 'older' }],
    filters: { statuses: [], availabilities: [], diffKinds: [] },
    sub2api: { apiError: null, statsError: null },
  };
  requests[0].resolve({ ok: true, json: async () => older });
  assert.equal(await context.firstPromise, false);
  assert.equal(stateForTest.snapshot.marker, 'newer');
  assert.equal(stateForTest.snapshotRequestsPending, 0);
  assert.equal(context.elements.refreshButton.disabled, false);
  assert.equal(context.elements.loadingLabel.hidden, true);
  assert.equal(lockStates.at(-1), false);

  vm.runInNewContext('failurePromise = loadSnapshot();', context);
  assert.equal(stateForTest.snapshotRequestsPending, 1);
  assert.equal(stateForTest.snapshotRefreshPending, true);
  requests[2].reject(new Error('offline'));
  assert.equal(await context.failurePromise, false);
  assert.equal(stateForTest.snapshotRequestsPending, 0);
  assert.equal(context.elements.refreshButton.disabled, false);
  assert.equal(stateForTest.snapshot.marker, 'newer');
  assert.equal(stateForTest.snapshotRefreshPending, true);
  assert.equal(lockStates.at(-1), true);
});

test('frontend selection mutations are blocked while actions are locked', () => {
  const selectionContract = sourceSection('function selectionsEqual', 'function renderRows');
  let locked = true;
  let invalidations = 0;
  let renders = 0;
  const context = {
    state: { selected: new Set(['one']), selectionRevision: 7 },
    actionsLocked: () => locked,
    invalidatePlan: () => { invalidations += 1; },
    renderRows: () => { renders += 1; },
    selectedRowsFromSelection: () => [],
    loadAccountTestModels: () => {},
  };
  vm.runInNewContext(selectionContract + `
    blocked = changeSelection(new Set(['two']));
  `, context);
  assert.equal(context.blocked, false);
  assert.deepEqual([...context.state.selected], ['one']);
  assert.equal(context.state.selectionRevision, 7);

  locked = false;
  vm.runInNewContext(`
    changed = changeSelection(new Set(['two']));
    unchanged = changeSelection(new Set(['two']));
  `, context);
  assert.equal(context.changed, true);
  assert.equal(context.unchanged, false);
  assert.deepEqual([...context.state.selected], ['two']);
  assert.equal(context.state.selectionRevision, 8);
  assert.equal(invalidations, 1);
  assert.equal(renders, 1);

  const rowContract = sourceSection('function renderRows', 'function renderPlan');
  assert.match(rowContract, /changeSelection\(next\)/);
  const bulkHandlers = sourceSection("elements.clearSelectionButton.addEventListener", "\[elements.searchInput");
  assert.equal((bulkHandlers.match(/changeSelection\(/g) || []).length, 2);
});

test('frontend blocks bulk actions when a prior selection is hidden by filters', async () => {
  const visibilityContract = sourceSection('function selectedRowsFromView', 'function selectedRowsFromSelection');
  const selectionContract = sourceSection('function selectionsEqual', 'function rowSideData');
  const filterContract = sourceSection('function applyFilters', 'function showNotice');
  const previewContract = sourceSection('async function previewSelection', "elements.previewButton.addEventListener('click', previewSelection);");
  const allBulkHandlers = sourceSection(
    'async function previewSelection',
    "elements.clearSelectionButton.addEventListener",
  );
  const cleanupHandler = sourceSection(
    'if (elements.cleanupButton) {',
    "elements.clearSelectionButton.addEventListener",
  );
  const notices = [];
  let requests = 0;
  const context = {
    state: {
      snapshot: {
        rows: [
          { key: 'account-a', accountName: 'Alpha' },
          { key: 'account-b', accountName: 'Beta' },
        ],
      },
      rows: [],
      selected: new Set(['account-a']),
      selectionRevision: 1,
      previewRequestPending: false,
    },
    elements: {
      searchInput: { value: 'Beta' },
      statusFilter: { value: '' },
      availabilityFilter: { value: '' },
      sourceFilter: { value: '' },
      diffFilter: { value: '' },
    },
    actionsLocked: () => false,
    invalidatePlan() {},
    renderRows() {},
    selectedRowsFromSelection: () => [],
    loadAccountTestModels: () => {},
    comparisonAvailable: () => true,
    apiFetch: async () => { requests += 1; throw new Error('must not request'); },
    showNotice: (...args) => notices.push(args),
    renderPlan() {},
    updateActionState() {},
  };
  vm.runInNewContext(visibilityContract + '\n' + selectionContract + '\n' + filterContract + '\n'
    + previewContract + `
      applyFilters();
      changeSelection(new Set([...state.selected, 'account-b']));
      visibilityProblem = hiddenSelectionProblem();
      previewPromise = previewSelection();
    `, context);
  assert.deepEqual(context.state.rows.map((row) => row.key), ['account-b']);
  assert.deepEqual([...context.state.selected].sort(), ['account-a', 'account-b']);
  assert.match(context.visibilityProblem, /1 个已选账号被当前筛选条件隐藏/);
  assert.equal(await context.previewPromise, false);
  assert.equal(requests, 0);
  assert.match(notices.at(-1)[0], /请先清除选择或调整筛选/);
  assert.equal((allBulkHandlers.match(/hiddenSelectionProblem/g) || []).length, 4);
  assert.doesNotMatch(cleanupHandler, /hiddenSelectionProblem/);
  assert.match(cleanupHandler, /listing\.recoveryRequired === true/);
  assert.match(cleanupHandler, /未完成的过期 token 隔离 claim/);
  assert.match(cleanupHandler, /这是 tokens 与 use_token 活动目录的全局操作/);
  assert.match(cleanupHandler, /historical\/old_codex 历史备份不在扫描和隔离范围内/);
  assert.match(htmlSource, /全局维护 · 不受筛选和选择影响/);
  assert.match(htmlSource, /全局扫描并隔离过期 token/);
  assert.match(htmlSource, /不含 historical\/old_codex 历史备份/);
  assert.doesNotMatch(htmlSource, /所有已过期 JSON 文件/);
  assert.match(sourceSection('function updateActionState', 'function applyColumnVisibility'),
    /cleanupButton\.disabled = Boolean\(state\.snapshot\?\.readOnly\) \|\| mutationLocked \|\| !state\.snapshot/);
});

test('frontend distinguishes healthy availability and never force-adds an unsupported model', () => {
  const modelContract = sourceSection('function renderAccountTestModels', 'function accountTestRows');
  const remoteStateContract = sourceSection('function renderRemoteState', 'function renderDiffDecision');
  assert.doesNotMatch(modelContract, /values\.unshift\('gpt-5\.6-luna'\)/);
  assert.match(source, /candidates\.length === 1/);
  assert.match(source, /state\.accountTestModelsPending/);
  assert.match(remoteStateContract, /availability-note-success/);
  assert.match(remoteStateContract, /availability-note-warning/);
  assert.match(stylesSource, /\.availability-note-success\s*\{[^}]*var\(--success\)/s);
});

test('frontend submits one snapshot-bound revision per unambiguous account test target', () => {
  const targetContract = sourceSection('function accountTestRows', 'async function loadAccountTestModels');
  const handlerContract = sourceSection(
    'if (elements.accountTestButton) {',
    'if (elements.cleanupButton) {',
  );
  const context = {};
  vm.runInNewContext(targetContract + `
    valid = accountTestTargetsFromRows([
      { accountId: 7, targetRevision: 'revision-seven' },
      { accountId: 8, targetRevision: 'revision-eight' },
    ]);
    duplicate = accountTestTargetsFromRows([
      { accountId: 7, targetRevision: 'revision-seven' },
      { accountId: 7, targetRevision: 'revision-seven' },
    ]);
    conflicting = accountTestTargetsFromRows([
      { accountId: 7, targetRevision: 'revision-seven' },
      { accountId: 7, targetRevision: 'revision-replaced' },
    ]);
    stale = accountTestTargetsFromRows([{ accountId: 7 }]);
  `, context);
  assert.deepEqual(JSON.parse(JSON.stringify(context.valid.targets)), [
    { accountId: 7, targetRevision: 'revision-seven' },
    { accountId: 8, targetRevision: 'revision-eight' },
  ]);
  assert.equal(context.valid.problem, '');
  assert.match(context.duplicate.problem, /同一 Sub2API 账号 ID/);
  assert.match(context.conflicting.problem, /多个不同 revision/);
  assert.match(context.stale.problem, /刷新后重新选择/);
  assert.match(handlerContract, /idempotentMutationFetch\(\s*'account_test',\s*'\/api\/account-tests',\s*\{\s*targets,\s*modelId,/);
  assert.doesNotMatch(handlerContract, /accountIds\s*:/);
});

test('frontend labels the remote-only source filter unambiguously', () => {
  assert.match(htmlSource, /<option value="sub2api">仅 Sub2API（无本地 token）<\/option>/);
});

test('frontend discards a preview when the selected keys or revision changes in flight', async () => {
  const comparisonContract = sourceSection('function sub2ApiReadStatus', 'function updateImportButtonState');
  const freshnessContract = sourceSection('function selectionStillCurrent', 'function renderRows');
  const previewContract = sourceSection('async function previewSelection', "elements.previewButton.addEventListener('click', previewSelection);");
  const requests = [];
  const plans = [];
  const notices = [];
  const stateForTest = {
    snapshot: { sub2api: { readStatus: 'ok' }, diff: { comparisonStatus: 'complete' } },
    selected: new Set(['one']),
    selectionRevision: 3,
    previewRequestPending: false,
  };
  const context = {
    state: stateForTest,
    apiFetch: () => new Promise((resolve) => requests.push(resolve)),
    hiddenSelectionProblem: () => '',
    renderPlan: (plan) => plans.push(plan),
    showNotice: (...args) => notices.push(args),
    updateActionState() {},
  };
  vm.runInNewContext(comparisonContract + '\n' + freshnessContract + '\n' + previewContract + `
    changedKeysPromise = previewSelection();
  `, context);
  assert.equal(stateForTest.previewRequestPending, true);
  stateForTest.selected.add('two');
  requests[0]({ ok: true, json: async () => ({ version: 'stale-keys', items: [] }) });
  assert.equal(await context.changedKeysPromise, false);
  assert.equal(stateForTest.previewRequestPending, false);
  assert.deepEqual(plans, [null]);
  assert.equal(notices.length, 0);

  stateForTest.selected = new Set(['one']);
  vm.runInNewContext('changedRevisionPromise = previewSelection();', context);
  stateForTest.selectionRevision += 1;
  requests[1]({ ok: true, json: async () => ({ version: 'stale-revision', items: [] }) });
  assert.equal(await context.changedRevisionPromise, false);
  assert.deepEqual(plans, [null, null]);
  assert.equal(notices.length, 0);

  vm.runInNewContext('supersededPromise = previewSelection();', context);
  requests[2]({
    ok: true,
    json: async () => ({
      version: 'current',
      items: [{ selectedSourceSuperseded: true }],
    }),
  });
  assert.equal(await context.supersededPromise, true);
  assert.equal(notices.length, 1);
  assert.match(notices[0][0], /所选旧副本/);
  assert.equal(notices[0][1], 'notice-warning');
});

test('frontend refuses sync preview when remote comparison is unavailable', async () => {
  const comparisonContract = sourceSection('function sub2ApiReadStatus', 'function updateImportButtonState');
  const previewContract = sourceSection('async function previewSelection', "elements.previewButton.addEventListener('click', previewSelection);");
  let requests = 0;
  const notices = [];
  const context = {
    state: {
      snapshot: { sub2api: { readStatus: 'failed' }, diff: { comparisonStatus: 'unavailable' } },
      selected: new Set(['one']),
      selectionRevision: 1,
      previewRequestPending: false,
    },
    apiFetch: async () => { requests += 1; throw new Error('must not request'); },
    hiddenSelectionProblem: () => '',
    renderPlan() {},
    showNotice: (...args) => notices.push(args),
    updateActionState() {},
  };
  vm.runInNewContext(comparisonContract + '\n' + previewContract + '\nblocked = previewSelection();', context);
  assert.equal(await context.blocked, undefined);
  assert.equal(requests, 0);
  assert.equal(context.state.previewRequestPending, false);
  assert.match(notices[0][0], /无法检查同步差异/);
});

test('frontend keeps a successful legacy snapshot comparable during a rolling restart', () => {
  const comparisonContract = sourceSection('function sub2ApiReadStatus', 'function updateImportButtonState');
  const context = { state: { snapshot: null } };
  vm.runInNewContext(comparisonContract + `
    legacyOk = {
      sub2api: { accountCount: 0, apiError: null },
      diff: { counts: { token_only: 1 } },
    };
    legacyFailed = {
      sub2api: { accountCount: 0, apiError: 'offline' },
      diff: { counts: { token_only: 1 } },
    };
    result = {
      okStatus: sub2ApiReadStatus(legacyOk),
      okComparable: comparisonAvailable(legacyOk),
      failedStatus: sub2ApiReadStatus(legacyFailed),
      failedComparable: comparisonAvailable(legacyFailed),
      invalidStatus: sub2ApiReadStatus({
        sub2api: { readStatus: 'unexpected', accountCount: 0, apiError: null },
        diff: { comparisonStatus: 'complete' },
      }),
    };
  `, context);
  assert.deepEqual({ ...context.result }, {
    okStatus: 'ok',
    okComparable: true,
    failedStatus: 'failed',
    failedComparable: false,
    invalidStatus: 'failed',
  });
});

test('frontend account search includes phone numbers', () => {
  const filterContract = sourceSection('function applyFilters', 'function showNotice');
  const context = {
    elements: {
      searchInput: { value: '13800138000' },
      statusFilter: { value: '' },
      availabilityFilter: { value: '' },
      sourceFilter: { value: '' },
      diffFilter: { value: '' },
    },
    renderRows() {},
    state: {
      rows: [],
      snapshot: {
        rows: [
          { key: 'phone', phone: '+86 138-0013-8000' },
          { key: 'other', phone: '13900139000' },
        ],
      },
    },
  };
  vm.runInNewContext(filterContract + '\napplyFilters(); result = state.rows.map((row) => row.key);', context);
  assert.deepEqual([...context.result], ['phone']);
});

test('frontend Phase3 uses the token email plus uniquely joined phone and rejects explicit ineligibility', () => {
  const reasonContract = sourceSection('function phase3ReasonLabel', 'function effectivePlanAction');
  const targetContract = sourceSection('function selectedRowsFromView', 'function invalidatePlan');
  const context = {};
  vm.runInNewContext(reasonContract + '\n' + targetContract + `
    const revision = 'phase3-target-v1.' + 'A'.repeat(43);
    const eligible = {
      key: 'eligible',
      email: 'stale-remote@example.test',
      phase3Email: 'source-token@example.test',
      phone: '+86 138-0013-8000',
      phase3Eligible: true,
      phase3TargetRevision: revision,
    };
    const rejected = {
      key: 'ambiguous',
      email: 'ambiguous@example.test',
      phase3Email: 'ambiguous@example.test',
      phase3Eligible: false,
      phase3Reason: 'username_ambiguous',
    };
    result = {
      eligible: phase3TargetsFromRows([eligible]),
      rejected: phase3TargetsFromRows([rejected]),
      rejectedProblem: phase3SelectionProblem([rejected], 1),
      legacy: phase3TargetsFromRows([{
        key: 'legacy',
        source: 'tokens',
        email: 'legacy@example.test',
      }]),
      legacyRemote: phase3TargetsFromRows([{
        key: 'legacy-remote',
        source: 'sub2api',
        email: 'remote-only@example.test',
      }]),
      malformedEligibility: phase3TargetsFromRows([{
        key: 'malformed',
        source: 'tokens',
        email: 'malformed@example.test',
        phase3Eligible: null,
      }]),
      missingRevisionProblem: phase3SelectionProblem([{
        key: 'missing-revision',
        phase3Eligible: true,
        phase3Email: 'missing-revision@example.test',
      }], 1),
      historicalReason: phase3ReasonLabel('phase3_source_historical'),
      invalidPhoneReason: phase3ReasonLabel('username_phone_invalid'),
      invalidTargetReason: phase3ReasonLabel('phase3_target_invalid'),
    };
  `, context);
  assert.deepEqual(JSON.parse(JSON.stringify(context.result.eligible)), [{
    email: 'source-token@example.test',
    phone: '8613800138000',
    selectedKey: 'eligible',
    phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
  }]);
  assert.deepEqual([...context.result.rejected], []);
  assert.match(context.result.rejectedProblem, /匹配到多个账号/);
  assert.deepEqual([...context.result.legacy], []);
  assert.deepEqual([...context.result.legacyRemote], []);
  assert.deepEqual([...context.result.malformedEligibility], []);
  assert.match(context.result.missingRevisionProblem, /快照凭证/);
  assert.match(context.result.historicalReason, /historical\/old_codex 历史 token/);
  assert.match(context.result.invalidPhoneReason, /手机号格式无效/);
  assert.match(context.result.invalidTargetReason, /快照字段不完整或格式无效/);
});

test('frontend Phase3 preserves every selected row when strong identities overlap', () => {
  const targetContract = sourceSection('function selectedRowsFromView', 'function invalidatePlan');
  const context = {};
  vm.runInNewContext(targetContract + `
    const revision = 'phase3-target-v1.' + 'B'.repeat(43);
    result = phase3TargetsFromRows([
      {
        key: 'first-token',
        phase3Email: 'shared@example.test',
        phone: '+86 138-0013-8000',
        phase3Eligible: true,
        phase3TargetRevision: revision,
      },
      {
        key: 'second-token',
        phase3Email: 'shared@example.test',
        phone: '+86 138-0013-8000',
        phase3Eligible: true,
        phase3TargetRevision: revision,
      },
    ]);
  `, context);
  assert.deepEqual(JSON.parse(JSON.stringify(context.result)), [
    {
      email: 'shared@example.test',
      phone: '8613800138000',
      selectedKey: 'first-token',
      phase3TargetRevision: 'phase3-target-v1.' + 'B'.repeat(43),
    },
    {
      email: 'shared@example.test',
      phone: '8613800138000',
      selectedKey: 'second-token',
      phase3TargetRevision: 'phase3-target-v1.' + 'B'.repeat(43),
    },
  ]);
});

test('frontend Phase3 submits selected keys in the same order as account targets', async () => {
  const phase3Handler = sourceSection(
    "elements.phase3Button.addEventListener('click'",
    'if (elements.accountTestButton)',
  );
  let clickHandler;
  let submittedBody = null;
  const targets = [
    { selectedKey: 'snapshot-first', email: 'first@example.test' },
    { selectedKey: 'snapshot-second', email: 'second@example.test' },
  ];
  const context = {
    elements: {
      phase3Button: {
        addEventListener(event, handler) {
          assert.equal(event, 'click');
          clickHandler = handler;
        },
      },
    },
    state: {
      phase3RequestPending: false,
      selected: new Set(['snapshot-second', 'snapshot-first']),
    },
    hiddenSelectionProblem: () => '',
    selectedRowsFromSelection: () => [{ key: 'snapshot-first' }, { key: 'snapshot-second' }],
    phase3TargetsFromRows: () => targets,
    phase3SelectionProblem: () => '',
    updateActionState() {},
    idempotentMutationFetch: async (workflow, path, body) => {
      assert.equal(workflow, 'phase3');
      assert.equal(path, '/api/phase3');
      submittedBody = body;
      return {
        response: { ok: true },
        body: { jobIds: ['job_' + 'a'.repeat(24)], rejected: [] },
      };
    },
    showNotice() {},
    watchJobs: async () => {},
    window: { confirm: () => true },
  };
  vm.runInNewContext(phase3Handler, context);
  await clickHandler();
  assert.deepEqual(JSON.parse(JSON.stringify(submittedBody)), {
    accounts: targets,
    selectedKeys: ['snapshot-first', 'snapshot-second'],
  });
});

test('frontend disables Phase3 and explains a backend-rejected selected row', () => {
  const reasonContract = sourceSection('function phase3ReasonLabel', 'function effectivePlanAction');
  const targetContract = sourceSection('function selectedRowsFromView', 'function invalidatePlan');
  const updateContract = sourceSection('function updateActionState', 'function applyColumnVisibility');
  const context = {
    state: {
      selected: new Set(['row-one']),
      rows: [{ key: 'row-one' }],
      jobInventoryVerified: true,
      snapshot: {
        readOnly: false,
        rows: [{
          key: 'row-one',
          phase3Email: 'source@example.test',
          phase3Eligible: false,
          phase3Reason: 'username_password_missing',
        }],
      },
    },
    elements: {
      phase3Button: {},
      accountTestButton: null,
      clearSelectionButton: {},
      selectAll: {},
      previewButton: {},
      importButton: {},
      cleanupButton: {},
    },
    document: { querySelectorAll: () => [] },
    accountTestTargetsFromRows: () => ({ targets: [], problem: '' }),
    actionsLocked: () => false,
    reconciliationWriteBlocked: () => false,
    syncSelectionProblem: () => '',
    updateImportButtonState() {},
    comparisonAvailable: () => true,
  };
  vm.runInNewContext(reasonContract + '\n' + targetContract + '\n' + updateContract
    + '\nupdateActionState(); result = { disabled: elements.phase3Button.disabled, title: elements.phase3Button.title };', context);
  assert.equal(context.result.disabled, true);
  assert.match(context.result.title, /缺少密码/);
  assert.match(source, /Phase 3：.*phase3ReasonLabel/);
});

test('frontend administrator credential uses an origin-labelled password dialog', () => {
  assert.match(htmlSource, /<dialog id="adminTokenDialog"[^>]*aria-labelledby="adminTokenTitle"/);
  assert.match(htmlSource, /<input id="adminTokenInput"[^>]*type="password"[^>]*required>/);
  assert.match(htmlSource, /<code id="adminTokenOrigin"><\/code>/);
  assert.doesNotMatch(source, /window\.prompt\s*\(/);
  assert.match(stylesSource, /\.auth-dialog::backdrop/);
  const mobile = stylesSource.slice(stylesSource.indexOf('@media (max-width: 700px)'));
  assert.match(mobile, /\.auth-dialog-form \{ padding: 18px; \}/);
  assert.match(mobile, /\.auth-dialog-actions \.button \{ flex: 1 1 0; \}/);
});
