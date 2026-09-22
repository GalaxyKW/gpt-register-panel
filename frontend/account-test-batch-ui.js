'use strict';

const accountTestBatchUi = {
  plan: null,
  controller: null,
  running: false,
  submissionInFlight: null,
  acceptedIds: [],
  completed: 0,
  summaryBase: null,
  summarySucceeded: false,
  lastSummary: null,
  lastSummaryKind: null,
  summaryOwnsNotice: false,
};
const accountTestBatchElements = Object.fromEntries([
  'SelectionHint', 'Panel', 'Progress', 'Stop', 'Dialog', 'Form', 'Summary',
  'Targets', 'SkippedSection', 'Skipped', 'SkipAcknowledged', 'Error', 'Confirm',
].map((name) => [name, document.querySelector('#accountTestBatch' + name)]));

function accountTestBatchSelection(rows) {
  const result = { targets: [], skipped: [], problem: '' };
  if (!Array.isArray(rows) || rows.length === 0) {
    result.problem = '请至少选择一个已导入 Sub2API 的上游账号';
    return result;
  }
  if (rows.length > 1000) {
    result.problem = '分批测试本次最多核对 1000 个所选项目，请减少选择';
    return result;
  }
  const seen = new Set();
  for (const [index, row] of rows.entries()) {
    const id = row?.accountId;
    const validId = Number.isSafeInteger(id) && id > 0;
    if (validId && seen.has(id)) {
      return { targets: [], skipped: [], problem: '所选多行指向 Sub2API #' + id + '，请只保留其中一行' };
    }
    if (validId) seen.add(id);
    let reason = '';
    if (!validId) reason = '没有对应的 Sub2API 账号 ID，不能测试本地文件';
    else if (row.platform !== 'openai' || row.type !== 'oauth') reason = '不是 OpenAI OAuth 账号';
    else if (!['active', 'inactive', 'disabled', 'error'].includes(row.status)) reason = '账号状态不在可安全测试的范围内';
    else if (!/^account-test-v1\.[A-Za-z0-9_-]{43}$/.test(String(row.targetRevision || ''))
        || row.accountTestEligible === false) {
      const identity = row.remoteDetails || row;
      reason = !identity.chatgptAccountId && !identity.userId
        ? '缺少 accountId / userId 强身份，不能安全测试；需先核对并修复账号身份'
        : '身份或状态无法生成有效测试快照凭证，需先核对账号后重新读取';
    }
    if (reason) result.skipped.push({ label: validId ? 'Sub2API #' + id : '所选本地项 ' + (index + 1), reason });
    else result.targets.push({ accountId: id, targetRevision: row.targetRevision });
  }
  if (result.targets.length === 0) {
    result.problem = '所选项目均不可安全测试；'
      + result.skipped.slice(0, 3).map((item) => item.label + '：' + item.reason).join('；')
      + (result.skipped.length > 3 ? '；另有 ' + (result.skipped.length - 3) + ' 个不可测项目' : '');
  }
  return result;
}

function accountTestBatchActionProblem() {
  if (typeof PanelAccountTestBatch === 'undefined'
      || typeof PanelAccountTestBatch.run !== 'function') return '分批测试组件未加载，请刷新页面';
  if (actionsLocked()) return '其他任务、请求或快照核验仍在执行';
  if (reconciliationWriteBlocked()) return '存在待人工对账任务，已阻止测试';
  if (state.snapshot?.readOnly !== false) return '当前面板未确认可写';
  if (state.accountTestModelsPending) return '所选账号模型列表仍在读取';
  if (!comparisonAvailable()) return 'Sub2API 账号快照未完整读取';
  return hiddenSelectionProblem();
}

function updateAccountTestBatchUi() {
  const running = accountTestBatchUi.running || state.accountTestBatchPending === true;
  for (const control of [elements.searchInput, elements.statusFilter, elements.availabilityFilter,
    elements.sourceFilter, elements.diffFilter, elements.historicalToggle]) {
    if (control) control.disabled = running;
  }
  if (elements.refreshButton) {
    elements.refreshButton.disabled = running || state.snapshotRequestsPending > 0;
  }
  if (accountTestBatchElements.Stop) {
    accountTestBatchElements.Stop.disabled = !running || accountTestBatchUi.controller?.signal.aborted === true;
  }
  if (accountTestBatchElements.SelectionHint) {
    const rows = selectedRowsFromSelection();
    const selection = accountTestBatchSelection(rows);
    accountTestBatchElements.SelectionHint.hidden = rows.length === 0;
    accountTestBatchElements.SelectionHint.textContent = rows.length === 0 ? ''
      : '账号测试：' + (selection.problem || ('可测试 ' + selection.targets.length + ' 个 · '
        + Math.ceil(selection.targets.length / 100) + ' 批，每批最多 100 个'
        + (selection.skipped.length ? ' · ' + selection.skipped.length + ' 个不可测试，提交前必须核对跳过清单' : '')));
  }
  if (accountTestBatchElements.Dialog?.open) {
    const plan = accountTestBatchUi.plan;
    accountTestBatchElements.Confirm.disabled = !plan || running
      || (plan.skipped.length > 0 && !accountTestBatchElements.SkipAcknowledged.checked)
      || Boolean(accountTestBatchActionProblem());
  }
  if (!running && accountTestBatchUi.summaryBase) renderAccountTestBatchSummary();
}

function renderAccountTestBatchSummary(forceNotice = false) {
  const recoveryPending = state.jobInventoryVerified !== true
    || state.snapshotRefreshPending === true || state.snapshotRequestsPending > 0;
  const recoveredJobs = Array.isArray(state.job?.jobs) ? state.job.jobs : (state.job ? [state.job] : []);
  const reconciliationBlocked = reconciliationWriteBlocked();
  const reconciliationPending = reconciliationBlocked
    || recoveredJobs.some((job) => jobNeedsReconciliation(job));
  const active = activeJobPending();
  const summary = accountTestBatchUi.summaryBase
    + (reconciliationPending ? ' 当前后台存在待人工核对任务，请先核对；'
      + (reconciliationBlocked ? '写操作保持锁定。' : '不要重复提交待核对任务。') : '')
    + (active ? ' 后台仍有任务执行或状态待确认，已恢复任务状态跟踪。' : '')
    + (recoveryPending ? ' 任务或快照尚未核验，操作保持锁定。' : '');
  const kind = accountTestBatchUi.summarySucceeded && !recoveryPending && !reconciliationPending && !active
    ? 'notice-info' : 'notice-warning';
  if (!forceNotice && summary === accountTestBatchUi.lastSummary
      && kind === accountTestBatchUi.lastSummaryKind) return;
  accountTestBatchElements.Progress.textContent = summary;
  // Keep the progress panel current as its watcher finishes, but do not replace
  // a later operation's notice with an older batch's status update.
  if (forceNotice || (accountTestBatchUi.summaryOwnsNotice
      && elements.notice?.textContent === accountTestBatchUi.lastSummary)) {
    showNotice(summary, kind);
    accountTestBatchUi.summaryOwnsNotice = true;
  } else {
    accountTestBatchUi.summaryOwnsNotice = false;
  }
  accountTestBatchUi.lastSummary = summary;
  accountTestBatchUi.lastSummaryKind = kind;
}

function showAccountTestBatchError(message) {
  accountTestBatchElements.Error.hidden = !message;
  accountTestBatchElements.Error.textContent = message || '';
}

async function openAccountTestBatchDialog() {
  const problem = accountTestBatchActionProblem();
  if (problem) { showNotice(problem, 'notice-warning'); return; }
  const selectedRows = selectedRowsFromSelection();
  const selection = accountTestBatchSelection(selectedRows);
  if (selectedRows.length !== state.selected.size || selection.problem) {
    showNotice(selection.problem || '所选项目不在当前快照中，请重新选择', 'notice-warning');
    return;
  }
  const modelId = normalizeAccountTestModel(elements.accountTestModelSelect?.value);
  if (!modelId) { showNotice('请选择测试模型。', 'notice-warning'); return; }
  const dialog = accountTestBatchElements.Dialog;
  if (!dialog || typeof dialog.showModal !== 'function') {
    showNotice('浏览器无法打开账号测试确认框，未提交测试。', 'notice-warning');
    return;
  }
  accountTestBatchUi.plan = {
    targets: selection.targets.map((target) => Object.freeze({ ...target })),
    skipped: selection.skipped,
    modelId,
    selectedKeys: [...state.selected],
    selectionRevision: state.selectionRevision,
  };
  accountTestBatchElements.Summary.textContent = '模型 ' + accountTestModelLabel(modelId)
    + ' · 已选 ' + selectedRows.length + ' 项 · 测试 ' + selection.targets.length + ' 个 · 跳过 '
    + selection.skipped.length + ' 个 · ' + Math.ceil(selection.targets.length / 100) + ' 批（每批最多 100）';
  accountTestBatchElements.Targets.textContent = selection.targets.map((target) => '#' + target.accountId).join('、');
  accountTestBatchElements.SkippedSection.hidden = selection.skipped.length === 0;
  accountTestBatchElements.Skipped.innerHTML = selection.skipped.map((item) => (
    '<li>' + escapeHtml(item.label) + '：' + escapeHtml(item.reason) + '</li>'
  )).join('');
  accountTestBatchElements.SkipAcknowledged.checked = false;
  showAccountTestBatchError('');
  dialog.returnValue = '';
  dialog.showModal();
  updateAccountTestBatchUi();
}

async function readAccountTestBatchJson(url, signal) {
  const response = await apiFetch(url, { signal });
  if (!response.ok) throw new Error('ACCOUNT_TEST_BATCH_HTTP_FAILED');
  return response.json();
}

function accountTestBatchPollDelay(signal) {
  return new Promise((resolve, reject) => {
    let timer;
    const abort = () => {
      window.clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(new Error('ACCOUNT_TEST_BATCH_POLL_ABORTED'));
    };
    if (signal?.aborted) { abort(); return; }
    signal?.addEventListener('abort', abort, { once: true });
    timer = window.setTimeout(() => {
      signal?.removeEventListener('abort', abort);
      resolve();
    }, 1200);
  });
}

async function waitForAccountTestBatchTerminal({ jobId, signal }) {
  while (!signal.aborted) {
    const job = await readAccountTestBatchJson('/api/jobs/' + encodeURIComponent(jobId), signal);
    if (signal.aborted) throw new Error('ACCOUNT_TEST_BATCH_POLL_ABORTED');
    if (job?.id !== jobId || job.type !== 'account_test'
        || !['queued', 'running', 'succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)) {
      throw new Error('ACCOUNT_TEST_BATCH_JOB_INVALID');
    }
    state.jobs = [job];
    state.job = job;
    renderJob(job);
    if (job.result?.requiresReconciliation === true || job.result?.reconciliationHold === true
        || terminalJob(job.status)) return job;
    await accountTestBatchPollDelay(signal);
  }
  throw new Error('ACCOUNT_TEST_BATCH_POLL_ABORTED');
}

async function submitAccountTestBatchRequest({ targets, modelId }) {
  // Do not cancel an in-flight mutation when the operator stops future batches.
  // Keep its promise and await settlement before any inventory-based unlock.
  const submitting = idempotentMutationFetch('account_test', '/api/account-tests', { targets, modelId });
  accountTestBatchUi.submissionInFlight = submitting;
  // Keep the settled promise through recovery, including an abort racing its
  // rejection: the coordinator may have already stopped awaiting this adapter.
  const { response, body } = await submitting;
  if (/^job_[a-f0-9]{24}$/.test(String(body?.jobId || ''))) {
    accountTestBatchUi.acceptedIds.push(body.jobId);
  }
  if (!response.ok) throw new Error('ACCOUNT_TEST_BATCH_ADMISSION_UNCONFIRMED');
  return body;
}

function accountTestBatchProgress(event) {
  const phases = { checking: '核验完整清单和原始目标', submitting: '提交本批', submitted: '等待本批终态', completed: '本批完整成功' };
  accountTestBatchUi.completed = event.completed;
  accountTestBatchElements.Progress.textContent = '第 ' + event.batchIndex + '/' + event.batchCount
    + ' 批 · 已确认整批成功覆盖 ' + event.completed + '/' + event.total + ' 个 · ' + phases[event.phase];
  if (event.phase === 'submitted') {
    state.accountTestRequestPending = true;
    state.jobs = [{ id: event.jobId, type: 'account_test', status: 'queued' }];
    state.job = state.jobs[0];
    renderJob(state.job);
  }
  updateActionState();
}

async function runAccountTestBatchPlan(plan) {
  accountTestBatchUi.running = true;
  accountTestBatchUi.controller = new AbortController();
  accountTestBatchUi.submissionInFlight = null;
  accountTestBatchUi.acceptedIds = [];
  accountTestBatchUi.completed = 0;
  accountTestBatchUi.summaryBase = null;
  accountTestBatchUi.summaryOwnsNotice = false;
  state.accountTestBatchPending = true;
  accountTestBatchElements.Panel.hidden = false;
  accountTestBatchElements.Progress.textContent = '正在核验所选测试目标';
  updateActionState();
  let outcome = null;
  let failure = null;
  try {
    outcome = await PanelAccountTestBatch.run({
      targets: plan.targets, modelId: plan.modelId,
      signal: accountTestBatchUi.controller.signal,
      loadInventory: ({ signal }) => readAccountTestBatchJson('/api/jobs?limit=200', signal),
      // Deliberately ignore search, table filters and historical visibility.
      // The helper verifies every remaining original revision, never replaces it.
      loadSnapshot: ({ signal }) => readAccountTestBatchJson('/api/snapshot?withSub2api=1', signal),
      submitBatch: submitAccountTestBatchRequest,
      waitForTerminal: waitForAccountTestBatchTerminal,
      onProgress: accountTestBatchProgress,
    });
  } catch (error) {
    failure = error;
  } finally {
    if (accountTestBatchUi.submissionInFlight) {
      accountTestBatchElements.Progress.textContent = '正在确认最后一次提交回执，保持操作锁定；不会提交后续批次';
      try { await accountTestBatchUi.submissionInFlight; } catch {}
    }
    // Existing recovery owns queued/running/unknown jobs after this coordinator
    // stops. Refresh never restarts the unsubmitted part of this client plan.
    accountTestBatchElements.Progress.textContent = '已停止新提交，正在重新核验后台任务和账号快照';
    try { await loadSnapshot({ resumeJobs: true }); } catch {
      state.jobInventoryVerified = false;
      state.snapshotRefreshPending = true;
    }
    accountTestBatchUi.running = false;
    accountTestBatchUi.controller = null;
    accountTestBatchUi.plan = null;
    state.accountTestBatchPending = false;
    if (state.jobInventoryVerified === true && !activeJobPending()) state.accountTestRequestPending = false;
    const finished = outcome?.status === 'succeeded';
    accountTestBatchUi.summaryBase = finished
      ? '分批测试完成：' + outcome.completed + ' 个，' + outcome.batches + ' 批。'
      : '已停止后续批次；已确认整批成功覆盖 ' + accountTestBatchUi.completed + '/' + plan.targets.length
        + ' 个，当前批具体结果请查看任务详情。'
        + (failure?.code?.startsWith('ACCOUNT_TEST_BATCH_') ? failure.message : '请核对后台任务结果，不会自动重试。');
    accountTestBatchUi.summarySucceeded = finished;
    renderAccountTestBatchSummary(true);
    updateActionState();
  }
}

async function submitAccountTestBatchConfirmation(event) {
  event.preventDefault();
  if (accountTestBatchUi.running) return;
  if (event.submitter?.value !== 'confirm') {
    accountTestBatchElements.Dialog.close('cancel');
    return;
  }
  const plan = accountTestBatchUi.plan;
  const problem = accountTestBatchActionProblem();
  if (!plan || problem || !selectionStillCurrent(plan.selectionRevision, plan.selectedKeys)
      || normalizeAccountTestModel(elements.accountTestModelSelect?.value) !== plan.modelId) {
    showAccountTestBatchError(problem || '选择、模型或快照已变化，请关闭后重新确认');
    return;
  }
  if (plan.skipped.length && !accountTestBatchElements.SkipAcknowledged.checked) {
    showAccountTestBatchError('请先逐项核对不可测原因，并明确确认本次跳过这些项目');
    return;
  }
  accountTestBatchElements.Dialog.close('confirmed');
  await runAccountTestBatchPlan(plan);
}

accountTestBatchElements.Form?.addEventListener('submit', submitAccountTestBatchConfirmation);
accountTestBatchElements.SkipAcknowledged?.addEventListener('change', updateAccountTestBatchUi);
accountTestBatchElements.Dialog?.addEventListener('close', () => {
  accountTestBatchUi.plan = null;
  showAccountTestBatchError('');
});
accountTestBatchElements.Stop?.addEventListener('click', () => {
  if (!accountTestBatchUi.running || !accountTestBatchUi.controller) return;
  accountTestBatchUi.controller.abort();
  accountTestBatchElements.Progress.textContent = '已请求停止后续批次；当前已提交任务不会被取消，正在核实状态';
  updateAccountTestBatchUi();
});
updateActionState();
