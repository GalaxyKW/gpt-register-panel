const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

require('./test-isolation');

const source = fs.readFileSync(path.resolve(__dirname, '..', 'frontend', 'app.js'), 'utf8');
const html = fs.readFileSync(path.resolve(__dirname, '..', 'frontend', 'index.html'), 'utf8');
const styles = fs.readFileSync(path.resolve(__dirname, '..', 'frontend', 'styles.css'), 'utf8');

function section(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, startMarker + ' missing');
  assert.notEqual(end, -1, endMarker + ' missing');
  return source.slice(start, end);
}

function heldJob(extra = {}) {
  return {
    id: 'job_' + 'a'.repeat(24),
    type: 'token_import',
    status: 'failed',
    result: {
      requiresReconciliation: true,
      reconciliationHold: true,
      reconciliationResolved: false,
      reconciliationClaimDigest: 'b'.repeat(64),
      reconciliationBlockScope: 'all_mutating_operations',
    },
    ...extra,
  };
}

test('reconciliation controls expose only the three operation-neutral resolutions and explicit warnings', () => {
  assert.match(html, /id="reconciliationAckDialog"/);
  assert.match(html, /id="reconciliationAckButton"[^>]*hidden/);
  assert.match(html, /id="reconciliationAckScope"/);
  assert.match(html, /value="operation_applied"/);
  assert.match(html, /value="operation_not_applied"/);
  assert.match(html, /value="state_manually_reconciled"/);
  assert.doesNotMatch(html, /value="remote_(?:applied|not_applied)"/);
  assert.match(html, /面板不会自动核对实际状态/);
  assert.match(html, /不会使原任务变得可重试/);
  assert.match(source, /全部新写操作（旧版任务无法还原原保护键）/);
  assert.match(source, /安全策略阻止全部新写操作/);
  assert.match(html, /二次确认/);
  assert.match(styles, /\.reconciliation-dialog/);
  assert.match(styles, /\.reconciliation-ack-button/);
  assert.match(styles, /@media \(max-width: 700px\)[\s\S]*\.reconciliation-ack-button/);
});

test('frontend offers acknowledgement only for an unresolved persisted hold', () => {
  const contracts = section('function tokenImportResultCounts', 'function renderJob');
  const context = {
    state: {
      job: null,
      snapshot: { readOnly: false },
      reconciliationAckPending: false,
      reconciliationHolds: { total: 1 },
    },
    elements: { reconciliationAckButton: {} },
    finiteNumber: (value) => Number.isFinite(Number(value)) ? Number(value) : 0,
    terminalJob: (status) => ['succeeded', 'partial', 'failed', 'interrupted'].includes(status),
  };
  vm.runInNewContext(contracts + `
    const held = ${JSON.stringify(heldJob())};
    const resolved = ${JSON.stringify(heldJob({ result: {
      requiresReconciliation: false,
      reconciliationHold: false,
      reconciliationResolved: true,
      reconciliationClaimDigest: 'b'.repeat(64),
      imported: [{ requiresReconciliation: true }],
    } }))};
    const unavailable = ${JSON.stringify(heldJob({ result: {
      requiresReconciliation: true,
      reconciliationHold: false,
      reconciliationHoldUnavailable: true,
      reconciliationClaimDigest: null,
    } }))};
    result = {
      heldCount: reconciliationHoldJobs(held).length,
      resolvedCount: reconciliationHoldJobs(resolved).length,
      unavailableCount: reconciliationHoldJobs(unavailable).length,
      resolvedNeedsReconciliation: jobNeedsReconciliation(resolved),
    };
    renderReconciliationAction(held);
  `, context);
  assert.deepEqual({ ...context.result }, {
    heldCount: 1,
    resolvedCount: 0,
    unavailableCount: 0,
    resolvedNeedsReconciliation: false,
  });
  assert.equal(context.elements.reconciliationAckButton.hidden, false);
  assert.match(context.elements.reconciliationAckButton.title, /不会自动核对/);
});

test('a Phase 3 reconciliation hold never claims that token creation succeeded', () => {
  const renderContract = section('function renderJob', 'function setReconciliationDialogError');
  const context = {
    elements: {
      jobPanel: { hidden: true, dataset: {} },
      jobTitle: { textContent: '' },
      jobStatus: { className: '', textContent: '' },
      jobMeta: { textContent: '' },
    },
    jobNeedsReconciliation: (job) => job?.result?.requiresReconciliation === true,
    renderReconciliationAction() {},
    jobStatusClass: () => 'badge-danger',
    jobStatusLabel: () => '失败',
    accountTestResultsDetail: () => '',
    tokenImportResultDetail: () => '',
    formatDate: () => '2026-09-14 00:00:00',
  };
  vm.runInNewContext(renderContract + `
    renderJob(${JSON.stringify(heldJob({
      type: 'phase3',
      error: null,
      result: {
        requiresReconciliation: true,
        writeOutcomeUnknown: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: 'b'.repeat(64),
      },
    }))});
  `, context);
  assert.match(context.elements.jobMeta.textContent, /执行结果未知/);
  assert.match(context.elements.jobMeta.textContent, /确认前勿重试/);
  assert.doesNotMatch(context.elements.jobMeta.textContent, /已完成并检测到 token 更新/);
});

test('frontend disables mutation controls while preserving read-only inspection during a hold', () => {
  const lockContracts = section('function actionRequestPending', 'function sub2ApiReadStatus');
  const updateContract = section('function updateActionState', 'function applyColumnVisibility');
  assert.match(lockContracts, /reconciliationHolds\?\.total/);
  assert.match(updateContract, /mutationLocked = locked \|\| writeBlocked/);
  assert.match(updateContract, /phase3Button\.disabled = mutationLocked/);
  assert.match(updateContract, /accountTestButton\.disabled = mutationLocked/);
  assert.match(updateContract, /cleanupButton\.disabled = Boolean\(state\.snapshot\?\.readOnly\) \|\| mutationLocked/);
  assert.match(updateContract, /previewButton\.disabled = locked \|\| !comparisonAvailable\(\)/);

  const context = {
    state: {
      reconciliationHolds: { total: 1 },
      job: null,
      previewRequestPending: false,
      importRequestPending: false,
      phase3RequestPending: false,
      accountTestRequestPending: false,
      cleanupRequestPending: false,
      reconciliationAckPending: false,
      snapshotRefreshPending: false,
      snapshotRequestsPending: 0,
    },
    reconciliationHoldJobs: () => [],
  };
  vm.runInNewContext(lockContracts + '\nresult = {'
    + ' ordinaryLock: actionsLocked(), writeBlocked: reconciliationWriteBlocked() };', context);
  assert.deepEqual({ ...context.result }, { ordinaryLock: false, writeBlocked: true });
});

test('frontend submits the path-bound job id, exact digest, fixed phrase, and selected resolution', async () => {
  const holdContracts = section('function reconciliationHoldJobs', 'function renderJob');
  const dialogContracts = section('function setReconciliationDialogError', 'function stopJobPolling');
  const job = heldJob();
  job.result.reconciliationHoldScope = 'all_future_jobs';
  let request;
  let closedWith = '';
  let notice = '';
  const context = {
    state: {
      job,
      snapshot: { readOnly: false },
      reconciliationAckPending: false,
      reconciliationAckTarget: null,
      reconciliationHolds: { total: 1 },
    },
    elements: {
      reconciliationAckButton: {},
      reconciliationAckDialog: {
        close(value) { closedWith = value; },
        showModal() {},
        returnValue: '',
      },
      reconciliationAckJobId: { textContent: '' },
      reconciliationAckScope: { textContent: '' },
      reconciliationAckDigest: { textContent: '' },
      reconciliationAckResolution: { value: '', disabled: false, focus() {} },
      reconciliationAckConfirmation: { value: '', disabled: false },
      reconciliationAckCancel: { disabled: false },
      reconciliationAckConfirm: { disabled: false },
      reconciliationAckError: { hidden: true, textContent: '' },
    },
    terminalJob: (status) => ['succeeded', 'partial', 'failed', 'interrupted'].includes(status),
    RECONCILIATION_ACK_CONFIRMATION: '我已按强身份完成人工核对',
    RECONCILIATION_ACK_RESOLUTIONS: new Set([
      'operation_applied', 'operation_not_applied', 'state_manually_reconciled',
    ]),
    window: { confirm: () => true },
    async apiFetch(url, options) {
      request = { url, options };
      return { ok: true, json: async () => ({ idempotent: false }) };
    },
    async resumeActiveJob() { context.state.job = null; },
    updateActionState() {},
    showNotice(message) { notice = message; },
    jobNeedsReconciliation: () => false,
    reconciliationNoticeForJobs: () => '',
  };
  vm.runInNewContext(holdContracts + '\n' + dialogContracts, context);
  context.openReconciliationDialog();
  assert.equal(context.elements.reconciliationAckScope.textContent,
    '全部新写操作（旧版任务无法还原原保护键）');
  context.elements.reconciliationAckResolution.value = 'operation_not_applied';
  context.elements.reconciliationAckConfirmation.value = '我已按强身份完成人工核对';
  await context.submitReconciliationAcknowledgement({
    preventDefault() {},
    submitter: { value: 'confirm' },
  });
  assert.equal(
    request.url,
    '/api/jobs/' + encodeURIComponent(job.id) + '/reconciliation/acknowledge',
  );
  assert.deepEqual(JSON.parse(request.options.body), {
    jobId: job.id,
    confirmation: '我已按强身份完成人工核对',
    resolution: 'operation_not_applied',
    claimDigest: job.result.reconciliationClaimDigest,
  });
  assert.equal(closedWith, 'acknowledged');
  assert.match(notice, /原任务仍不可重试/);
  assert.doesNotMatch(dialogContracts, /innerHTML/);
});
