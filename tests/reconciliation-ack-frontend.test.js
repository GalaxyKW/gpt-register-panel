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

function validReviewDetail(job) {
  return {
    version: 1,
    id: job.id,
    type: job.type,
    status: job.status,
    reconciliationHold: true,
    reconciliationResolved: false,
    reconciliationClaimDigest: job.result.reconciliationClaimDigest,
    reconciliationHoldScope: 'claims',
    targetContext: {
      available: true,
      total: 1,
      returned: 1,
      truncated: false,
      targets: [{ sourcePath: 'tokens/free-account.json', remoteAccountId: 266 }],
    },
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

test('token cleanup reconciliation requires a path-bound content hash', () => {
  const contracts = section(
    'function boundedReconciliationDisplay',
    'function reconciliationReviewDetailError',
  );
  const context = {};
  vm.runInNewContext(contracts, context);
  assert.equal(context.reconciliationTargetIsValid('token_cleanup', {
    cleanupScope: 'expired_tokens',
    expectedVersion: 'a'.repeat(64),
    targetCount: 1,
  }), true);
  assert.equal(context.reconciliationTargetIsValid('token_cleanup', {
    sourcePath: 'tokens/expired.json',
    contentHash: 'b'.repeat(64),
    accessFingerprint: 'c'.repeat(16),
  }), true);
  assert.equal(context.reconciliationTargetIsValid('token_cleanup', {
    sourcePath: 'tokens/expired.json',
    accessFingerprint: 'c'.repeat(16),
  }), false);
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
  assert.match(updateContract, /cleanupButton\.disabled = state\.snapshot\?\.readOnly !== false \|\| mutationLocked/);
  assert.match(updateContract, /previewButton\.disabled = locked\s*\n\s*\|\| !comparisonAvailable\(\)/);
  assert.doesNotMatch(updateContract, /previewButton\.disabled = mutationLocked/);

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
      jobInventoryVerified: true,
      snapshot: { readOnly: false },
    },
    reconciliationHoldJobs: () => [],
  };
  vm.runInNewContext(lockContracts + '\nresult = {'
    + ' ordinaryLock: actionsLocked(), writeBlocked: reconciliationWriteBlocked() };', context);
  assert.deepEqual({ ...context.result }, { ordinaryLock: false, writeBlocked: true });
});

test('frontend fetches and validates target detail before submitting the path-bound acknowledgement', async () => {
  const holdContracts = section('function reconciliationHoldJobs', 'function renderJob');
  const dialogContracts = section('function setReconciliationDialogError', 'function stopJobPolling');
  const job = heldJob();
  job.result.reconciliationHoldScope = 'all_future_jobs';
  const requests = [];
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
      reconciliationAckContext: { textContent: '' },
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
    RECONCILIATION_AVAILABILITY_REASONS: new Set(['sub2api_status_error']),
    window: { confirm: () => true },
    async apiFetch(url, options) {
      requests.push({ url, options });
      if (!options) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            version: 1,
            id: job.id,
            type: job.type,
            status: job.status,
            reconciliationHold: true,
            reconciliationResolved: false,
            reconciliationClaimDigest: job.result.reconciliationClaimDigest,
            reconciliationHoldScope: 'all_future_jobs',
            targetContext: {
              available: true,
              total: 1,
              returned: 1,
              truncated: false,
              targets: [{
                sourcePath: 'tokens/free-account.json',
                remoteAccountId: 266,
                action: 'update',
                accessFingerprint: 'c'.repeat(16),
                strongIdentityKeys: [
                  'account:11111111-1111-4111-8111-111111111111',
                  'user:22222222-2222-4222-8222-222222222222',
                ],
                availability: 'unavailable',
                availabilityReason: 'sub2api_status_error',
              }],
            },
          }),
        };
      }
      return { ok: true, status: 200, json: async () => ({ idempotent: false }) };
    },
    async resumeActiveJob() { context.state.job = null; },
    updateActionState() {},
    showNotice(message) { notice = message; },
    jobNeedsReconciliation: () => false,
    reconciliationNoticeForJobs: () => '',
  };
  vm.runInNewContext(holdContracts + '\n' + dialogContracts, context);
  assert.equal(context.reconciliationTargetIsValid('token_import', {
    sourcePath: 'tokens/free-account.json',
    strongIdentityKeys: ['account:11111111-1111-4111-8111-111111111111'],
    strongIdentityTruncated: true,
  }), false);
  await context.openReconciliationDialog();
  assert.equal(requests[0].url,
    '/api/jobs/' + encodeURIComponent(job.id) + '/reconciliation');
  assert.equal(context.elements.reconciliationAckScope.textContent,
    '全部新写操作（旧版任务无法还原原保护键）');
  assert.match(context.elements.reconciliationAckContext.textContent, /tokens\/free-account\.json/);
  assert.match(context.elements.reconciliationAckContext.textContent, /Sub2API ID 266/);
  assert.match(context.elements.reconciliationAckContext.textContent, /account:11111111/);
  assert.match(context.elements.reconciliationAckContext.textContent,
    /unavailable \(sub2api_status_error\)/);
  context.elements.reconciliationAckResolution.value = 'operation_not_applied';
  context.elements.reconciliationAckConfirmation.value = '我已按强身份完成人工核对';
  await context.submitReconciliationAcknowledgement({
    preventDefault() {},
    submitter: { value: 'confirm' },
  });
  assert.equal(
    requests[1].url,
    '/api/jobs/' + encodeURIComponent(job.id) + '/reconciliation/acknowledge',
  );
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    jobId: job.id,
    confirmation: '我已按强身份完成人工核对',
    resolution: 'operation_not_applied',
    claimDigest: job.result.reconciliationClaimDigest,
  });
  assert.equal(closedWith, 'acknowledged');
  assert.match(notice, /原任务仍不可重试/);
  assert.doesNotMatch(dialogContracts, /innerHTML/);
});

test('frontend refuses to open acknowledgement when path-bound detail digest does not match the list', async () => {
  const holdContracts = section('function reconciliationHoldJobs', 'function renderJob');
  const dialogContracts = section('function setReconciliationDialogError', 'function stopJobPolling');
  const job = heldJob();
  let modalCount = 0;
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
      reconciliationAckDialog: { showModal() { modalCount += 1; }, returnValue: '' },
      reconciliationAckJobId: { textContent: '' },
      reconciliationAckScope: { textContent: '' },
      reconciliationAckDigest: { textContent: '' },
      reconciliationAckContext: { textContent: '' },
      reconciliationAckResolution: { value: '', disabled: false, focus() {} },
      reconciliationAckConfirmation: { value: '', disabled: false },
      reconciliationAckCancel: { disabled: false },
      reconciliationAckConfirm: { disabled: false },
      reconciliationAckError: { hidden: true, textContent: '' },
    },
    terminalJob: (status) => ['succeeded', 'partial', 'failed', 'interrupted'].includes(status),
    async apiFetch() {
      const detail = validReviewDetail(job);
      detail.reconciliationClaimDigest = 'c'.repeat(64);
      return { ok: true, status: 200, json: async () => detail };
    },
    async resumeActiveJob() {},
    updateActionState() {},
    showNotice(message) { notice = message; },
  };
  vm.runInNewContext(holdContracts + '\n' + dialogContracts, context);
  await context.openReconciliationDialog();
  assert.equal(modalCount, 0);
  assert.equal(context.state.reconciliationAckTarget, null);
  assert.equal(context.state.reconciliationAckPending, false);
  assert.match(notice, /任务标识或保护键摘要与列表不一致/);
});

test('frontend refreshes job holds after an acknowledgement conflict', async () => {
  const holdContracts = section('function reconciliationHoldJobs', 'function renderJob');
  const dialogContracts = section('function setReconciliationDialogError', 'function stopJobPolling');
  const job = heldJob();
  let requestCount = 0;
  let refreshCount = 0;
  let closedWith = '';
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
        showModal() {},
        close(value) { closedWith = value; },
        returnValue: '',
      },
      reconciliationAckJobId: { textContent: '' },
      reconciliationAckScope: { textContent: '' },
      reconciliationAckDigest: { textContent: '' },
      reconciliationAckContext: { textContent: '' },
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
    async apiFetch() {
      requestCount += 1;
      if (requestCount === 1) {
        return { ok: true, status: 200, json: async () => validReviewDetail(job) };
      }
      return {
        ok: false,
        status: 409,
        json: async () => ({ message: '任务保护键摘要已变化' }),
      };
    },
    async resumeActiveJob() { refreshCount += 1; },
    updateActionState() {},
    showNotice() {},
    jobNeedsReconciliation: () => false,
    reconciliationNoticeForJobs: () => '',
  };
  vm.runInNewContext(holdContracts + '\n' + dialogContracts, context);
  await context.openReconciliationDialog();
  context.elements.reconciliationAckResolution.value = 'operation_not_applied';
  context.elements.reconciliationAckConfirmation.value = '我已按强身份完成人工核对';
  await context.submitReconciliationAcknowledgement({
    preventDefault() {},
    submitter: { value: 'confirm' },
  });
  assert.equal(refreshCount, 1);
  assert.equal(closedWith, 'stale');
  assert.equal(context.state.reconciliationAckTarget, null);
});

test('ordinary refresh requests an independent jobs/hold refresh', () => {
  assert.match(source, /refreshButton\.addEventListener\('click', \(\) => loadSnapshot\(\{ resumeJobs: true \}\)\)/);
});
