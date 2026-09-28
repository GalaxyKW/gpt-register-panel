'use strict';

// Email proposes a login record; it never proves the remote account identity.
// The operator confirms the mapping, and the worker checks the resulting token
// against the frozen remote strong identity before offering a targeted update.
const remotePhase3State = {
  rows: [], mappings: [], confirmed: new Set(), listing: null,
  loading: false, submitting: false, generation: 0, selectionRevision: null,
  recoveryJobs: [], recoverySelected: new Set(), recoveryPlan: null,
  recoveryBinding: null, recoveryBusy: false, recoveryGeneration: 0,
};
const remotePhase3Elements = Object.fromEntries([
  'Dialog', 'Form', 'Summary', 'Rows', 'Skipped', 'SkipAcknowledged', 'Error', 'Confirm', 'Cancel',
  'ConfirmAll', 'ConfirmationProgress', 'SubmitStatus',
  'RecoveryButton', 'RecoveryDialog', 'RecoverySummary', 'RecoveryRows', 'RecoveryError',
  'RecoveryPreview', 'RecoveryImport', 'RecoveryClose', 'RecoveryPlan', 'RecoveryStatus',
].map((name) => [name, document.querySelector('#remotePhase3' + name)]));
const REMOTE_PHASE3_REVISION = /^account-test-v1\.[A-Za-z0-9_-]{43}$/;

function remotePhase3SelectionApplicable(rows = selectedRowsFromSelection()) {
  return Array.isArray(rows) && rows.some((row) => row?.source === 'sub2api');
}

function remotePhase3SelectionProblem(rows = selectedRowsFromSelection()) {
  if (!Array.isArray(rows) || !rows.length) return '请选择需要本地重新登录的远端账号';
  if (rows.length !== state.selected.size) return '所选账号已变化，请刷新重选';
  if (rows.length > 100) return '本地 Phase 3 每批最多 100 个，不会自动分批或跳过超出项';
  const seen = new Set();
  for (const row of rows) {
    if (Number.isSafeInteger(row?.accountId) && row.accountId > 0) {
      if (seen.has(row.accountId)) return '同一远端 ID 被重复选择，请只保留其中一行';
      seen.add(row.accountId);
    }
  }
  return '';
}

function remotePhase3ActionProblem() {
  if (state.jobInventoryVerified !== true) return '后台任务状态尚未核实';
  if (reconciliationWriteBlocked()) return '存在待人工对账任务，写操作保持锁定';
  if (actionsLocked()) return '其他任务、请求或快照核验正在执行';
  if (state.snapshot?.readOnly !== false) return '当前面板未确认可写';
  if (!phase3CapabilityAvailable()) return '服务端尚未启用本地 Phase 3';
  if (!comparisonAvailable()) return 'Sub2API 账号快照未完整读取';
  return '';
}

function remotePhase3MappingPlan(rows, listing) {
  const invalid = localPhase3ListingProblem(listing);
  if (invalid || listing.readOnly !== false || listing.capabilities?.phase3Enabled !== true) {
    return { mappings: [], problem: invalid || '本地清单未确认可执行' };
  }
  const mappings = rows.map((row) => {
    const remote = row.remoteDetails || {};
    const email = localPhase3Email(remote.email);
    const candidates = email ? listing.accounts.filter((entry) => entry.email === email) : [];
    const local = candidates.length === 1 ? candidates[0] : null;
    let reason = '';
    if (!Number.isSafeInteger(row.accountId) || row.accountId <= 0) reason = '没有有效的远端账号 ID';
    else if (row.source !== 'sub2api') reason = '已有本地 token，请单独选择该行使用原本地 Phase 3 流程';
    else if (row.platform !== 'openai' || row.type !== 'oauth') reason = '不是 OpenAI OAuth 账号';
    else if (!remote.chatgptAccountId && !remote.userId) reason = '缺少远端强身份，禁止仅按邮箱回写';
    else if (!REMOTE_PHASE3_REVISION.test(String(row.targetRevision || ''))) reason = '远端快照凭证无效，请刷新后核对';
    else if (row.availability !== 'unavailable') reason = '远端并非明确不可用，本次不重新登录或更新';
    else if (!email || candidates.length === 0) reason = '未找到同邮箱本地登录候选；不能推断或新建本地凭据';
    else if (candidates.length > 1) reason = '本地候选重复，无法唯一选择登录记录';
    else if (!local.eligible) reason = localPhase3Reason(local.reason);
    return { accountId: row.accountId, name: boundedReconciliationDisplay(row.accountName, 128) || '',
      email, local, reason, targetRevision: row.targetRevision,
      identityNotice: !remote.chatgptAccountId && remote.userId
        ? '远端仅有 User ID：新 token 必须保持同一 User ID；仅可补缺失 Account ID，已有身份不改。'
        : '新 token 必须与已有 Account ID / User ID 一致；不替换已有身份。',
      remoteIdentity: [remote.chatgptAccountId, remote.userId]
        .map((value) => boundedReconciliationDisplay(value, 512)).filter(Boolean).join(' / ') };
  });
  const localCounts = new Map();
  for (const entry of mappings) {
    if (!entry.reason) localCounts.set(entry.local.selectedKey, (localCounts.get(entry.local.selectedKey) || 0) + 1);
  }
  for (const entry of mappings) {
    if (!entry.reason && localCounts.get(entry.local.selectedKey) !== 1) {
      entry.reason = '多个远端账号指向同一本地登录记录，禁止批量关联';
    }
  }
  return { mappings, problem: '' };
}

function remotePhase3ConfirmedTargets() {
  const mappings = remotePhase3State.mappings;
  const eligible = mappings.filter((entry) => !entry.reason);
  const skipped = mappings.filter((entry) => entry.reason);
  if (!mappings.length || !eligible.length) return { problem: '所选账号没有可安全执行的本地登录映射', targets: [] };
  const remaining = eligible.filter((entry) => !remotePhase3State.confirmed.has(entry.accountId)).length;
  const problems = [];
  if (remaining) problems.push('还需确认 ' + remaining + ' 个本地登录映射：请逐项确认左侧勾选框，或核对后勾选“确认全部可执行映射”');
  if (skipped.length && !remotePhase3Elements.SkipAcknowledged.checked) {
    problems.push('还需明确确认本次跳过 ' + skipped.length + ' 个不可执行账号（表格下方勾选框）');
  }
  if (problems.length) return { problem: problems.join('。') + '。不会静默执行已勾选的子集。', targets: [] };
  return { problem: '', targets: eligible.map((entry) => ({
    selectedKey: entry.local.selectedKey, email: entry.local.email, phone: entry.local.phone || '',
    phase3TargetRevision: entry.local.phase3TargetRevision,
    remoteTarget: { accountId: entry.accountId, targetRevision: entry.targetRevision },
  })) };
}

function remotePhase3SelectionUnchanged() {
  if (remotePhase3State.selectionRevision !== state.selectionRevision) return false;
  const current = selectedRowsFromSelection();
  return current.length === remotePhase3State.rows.length
    && current.every((row) => remotePhase3State.rows.some((saved) => saved.key === row.key
      && saved.accountId === row.accountId && saved.targetRevision === row.targetRevision));
}

function remotePhase3Error(message, recovery = false) {
  const element = recovery ? remotePhase3Elements.RecoveryError : remotePhase3Elements.Error;
  element.hidden = !message;
  element.textContent = message || '';
}

function remotePhase3MappingSubmitProblem() {
  if (remotePhase3State.loading) return '正在读取并核验本地登录候选，请稍候；尚未提交任务。';
  if (remotePhase3State.submitting) return '正在提交本地 Phase 3 任务，请勿重复提交或关闭页面。';
  if (!remotePhase3State.listing) return '本地登录清单未读取成功，请关闭后重新打开；未提交任务。';
  if (!remotePhase3SelectionUnchanged()) return '所选远端账号或快照已变化，请关闭后重新核对。';
  return remotePhase3ActionProblem() || remotePhase3ConfirmedTargets().problem;
}

function updateRemotePhase3Ui() {
  const problem = remotePhase3ActionProblem();
  if (remotePhase3Elements.RecoveryButton) {
    remotePhase3Elements.RecoveryButton.disabled = Boolean(problem);
    remotePhase3Elements.RecoveryButton.title = problem || '从最近成功任务手动选择新 token，定向回写原远端 ID；不会重新运行 Phase 3';
  }
  if (remotePhase3Elements.Dialog?.open) {
    const busy = remotePhase3State.loading || remotePhase3State.submitting;
    const eligible = remotePhase3State.mappings.filter((entry) => !entry.reason);
    const skipped = remotePhase3State.mappings.length - eligible.length;
    const confirmed = eligible.filter((entry) => remotePhase3State.confirmed.has(entry.accountId)).length;
    const controlsLocked = busy || Boolean(problem) || !remotePhase3State.listing || !remotePhase3SelectionUnchanged();
    const submitProblem = remotePhase3MappingSubmitProblem();
    const progress = '已确认 ' + confirmed + ' / ' + eligible.length + ' 个可执行映射';
    remotePhase3Elements.ConfirmationProgress.textContent = progress;
    remotePhase3Elements.ConfirmAll.checked = eligible.length > 0 && confirmed === eligible.length;
    remotePhase3Elements.ConfirmAll.indeterminate = confirmed > 0 && confirmed < eligible.length;
    remotePhase3Elements.ConfirmAll.disabled = controlsLocked || eligible.length === 0;
    remotePhase3Elements.SubmitStatus.textContent = submitProblem
      ? '暂不能提交：' + submitProblem
      : progress + '；将重新登录 ' + eligible.length + ' 个账号、跳过 ' + skipped + ' 个。不会自动导入，完成后还需预览并确认回写。';
    remotePhase3Elements.SubmitStatus.dataset.state = submitProblem ? 'blocked' : 'ready';
    remotePhase3Elements.Confirm.disabled = Boolean(submitProblem);
    remotePhase3Elements.Confirm.title = remotePhase3Elements.SubmitStatus.textContent;
    remotePhase3Elements.Confirm.textContent = remotePhase3State.submitting ? '正在提交…'
      : '确认映射并重新登录' + (eligible.length ? '（' + eligible.length + ' 个）' : '');
    remotePhase3Elements.Cancel.disabled = remotePhase3State.submitting;
    remotePhase3Elements.SkipAcknowledged.disabled = controlsLocked;
    for (const input of remotePhase3Elements.Rows.querySelectorAll('input[data-remote-phase3-id]')) {
      input.disabled = controlsLocked;
      input.checked = remotePhase3State.confirmed.has(Number(input.dataset.remotePhase3Id));
    }
  }
  if (remotePhase3Elements.RecoveryDialog?.open) {
    const busy = remotePhase3State.recoveryBusy;
    const selection = remotePhase3RecoverySelection();
    const busyReason = busy ? state.importRequestPending
      ? '正在提交定向回写，请等待结果，不要重复操作'
      : state.previewRequestPending ? '正在核验成功任务和定向回写预览，请稍候'
        : '正在读取并核验最近的成功任务，请稍候' : '';
    const previewProblem = busyReason || problem || selection.problem;
    const importProblem = previewProblem || remotePhase3RecoveryImportProblem(selection);
    remotePhase3Elements.RecoveryPreview.disabled = Boolean(previewProblem);
    remotePhase3Elements.RecoveryPreview.title = previewProblem || '核验所选成功任务并预览原 ID 的回写动作';
    remotePhase3Elements.RecoveryImport.disabled = Boolean(importProblem);
    remotePhase3Elements.RecoveryImport.title = importProblem || '确认预览中的更新项，只更新原 ID，不新增账号';
    if (remotePhase3Elements.RecoveryStatus) {
      const plan = remotePhase3State.recoveryPlan;
      remotePhase3Elements.RecoveryStatus.textContent = previewProblem
        || (plan ? importProblem || '预览已核验：更新 ' + plan.items.filter((item) => item.action === 'update').length
          + ' 个，跳过 ' + plan.items.filter((item) => item.action === 'skip').length + ' 个。核对后可确认更新原 ID。'
          : '已选 ' + selection.entries.length + ' 个成功任务，请先点击“预览定向回写”。');
      remotePhase3Elements.RecoveryStatus.dataset.state = busy ? 'busy'
        : previewProblem || (plan && importProblem) ? 'blocked' : 'ready';
    }
    remotePhase3Elements.RecoveryClose.disabled = busy;
    for (const input of remotePhase3Elements.RecoveryRows.querySelectorAll('input[data-remote-phase3-job]')) {
      input.disabled = busy || Boolean(problem);
    }
  }
}

function renderRemotePhase3Mappings() {
  const mappings = remotePhase3State.mappings;
  remotePhase3Elements.Rows.innerHTML = mappings.map((entry) => {
    const label = Number.isSafeInteger(entry.accountId) ? 'Sub2API #' + entry.accountId : '无远端 ID';
    return '<tr><td>' + (entry.reason ? '跳过' : '<input type="checkbox" data-remote-phase3-id="'
      + entry.accountId + '" aria-label="确认 ' + label + ' 的本地登录映射"'
      + (remotePhase3State.confirmed.has(entry.accountId) ? ' checked' : '') + '>')
      + '</td><td>' + escapeHtml(label + ' ' + entry.name) + '<small>' + escapeHtml(entry.email || '邮箱未知')
      + '</small><small>远端强身份：' + escapeHtml(entry.remoteIdentity || '缺失') + '</small></td><td>'
      + (entry.local ? 'username.json #' + escapeHtml(entry.local.selectedKey.slice(9))
        + '<small>' + escapeHtml(entry.local.email) + '</small>' : '没有唯一候选')
      + '</td><td>' + escapeHtml(entry.reason || '邮箱仅作候选提示；需人工确认登录映射，新 token 仍须通过强身份核验。'
        + (entry.identityNotice || ''))
      + '</td></tr>';
  }).join('');
  const skipped = mappings.filter((entry) => entry.reason);
  remotePhase3Elements.Skipped.hidden = skipped.length === 0;
  if (!remotePhase3State.loading) {
    remotePhase3Elements.Summary.textContent = '冻结所选 ' + remotePhase3State.rows.length + ' 个远端账号 · 可确认 '
      + (mappings.length - skipped.length) + ' · 本次须跳过 ' + skipped.length
      + '。不会选择其他远端账号，不会自动导入。';
  }
  updateRemotePhase3Ui();
}

async function openRemotePhase3Dialog() {
  const rows = selectedRowsFromSelection();
  const problem = remotePhase3ActionProblem() || hiddenSelectionProblem() || remotePhase3SelectionProblem(rows);
  if (problem) { showNotice(problem, 'notice-warning'); return; }
  if (typeof remotePhase3Elements.Dialog?.showModal !== 'function') {
    showNotice('浏览器无法打开远端账号登录映射确认框，未提交任务。', 'notice-warning'); return;
  }
  const generation = ++remotePhase3State.generation;
  remotePhase3State.rows = rows.map((row) => ({ ...row, remoteDetails: { ...row.remoteDetails } }));
  remotePhase3State.selectionRevision = state.selectionRevision;
  remotePhase3State.confirmed = new Set();
  remotePhase3State.mappings = [];
  remotePhase3State.listing = null;
  remotePhase3State.loading = true;
  state.localPhase3ListingPending = true;
  remotePhase3Elements.SkipAcknowledged.checked = false;
  remotePhase3Elements.Dialog.showModal();
  remotePhase3Elements.Summary.textContent = '只为所选远端账号读取本地登录候选…';
  remotePhase3Error('');
  renderRemotePhase3Mappings();
  updateActionState();
  try {
    const response = await apiFetch('/api/phase3/local-accounts');
    const listing = await response.json();
    if (generation !== remotePhase3State.generation || !remotePhase3Elements.Dialog.open) return;
    if (!response.ok) throw new Error('LISTING_FAILED');
    const plan = remotePhase3MappingPlan(remotePhase3State.rows, listing);
    if (plan.problem) throw new Error('LISTING_INVALID');
    remotePhase3State.listing = listing;
    remotePhase3State.mappings = plan.mappings;
  } catch {
    if (generation === remotePhase3State.generation) remotePhase3Error('本地清单读取失败或无法核验，未提交任何任务。请关闭后重新读取。');
  } finally {
    if (generation === remotePhase3State.generation) {
      remotePhase3State.loading = false;
      state.localPhase3ListingPending = false;
      renderRemotePhase3Mappings();
      updateActionState();
    }
  }
}

function remotePhase3ReceiptMatches(body, targets) {
  if (!Array.isArray(body?.jobIds) || body.jobIds.length !== targets.length
      || new Set(body.jobIds).size !== body.jobIds.length
      || body.jobIds.some((id) => !/^job_[a-f0-9]{24}$/.test(String(id)))
      || !Array.isArray(body.rejected) || body.rejected.length !== 0
      || !Array.isArray(body.remoteTargets) || body.remoteTargets.length !== targets.length) return false;
  const seen = new Set();
  return body.remoteTargets.every((target) => {
    if (seen.has(target?.accountId)) return false;
    seen.add(target?.accountId);
    return targets.some((entry) => entry.remoteTarget.accountId === target?.accountId
      && entry.remoteTarget.targetRevision === target?.targetRevision);
  });
}

async function submitRemotePhase3(event) {
  event.preventDefault();
  if (remotePhase3State.submitting) return;
  if (event.submitter?.value !== 'confirm') { remotePhase3Elements.Dialog.close('cancel'); return; }
  const selection = remotePhase3ConfirmedTargets();
  const problem = remotePhase3MappingSubmitProblem();
  // The live status follows later checkbox changes; do not leave a stale copy
  // of this validation error next to an otherwise ready submit button.
  if (problem) { updateRemotePhase3Ui(); return; }
  const targets = selection.targets;
  if (!window.confirm('确认对这 ' + targets.length + ' 个远端 ID 对应的本地记录重新登录？\n远端 ID：'
      + targets.map((entry) => entry.remoteTarget.accountId).join('、')
      + '\n远端仅有 User ID 时，新 token 必须保持相同 User ID，才可补缺失 Account ID；不改已有 Account ID / User ID。'
      + '\n本批串行执行；新 token 必须通过强身份核验，完成后需单独确认定向回写，不自动新增或导入。')) return;
  remotePhase3State.submitting = true;
  state.phase3RequestPending = true;
  remotePhase3Error('');
  updateActionState();
  try {
    const { response, body } = await idempotentMutationFetch('phase3', '/api/phase3/local', {
      accounts: targets, selectedKeys: targets.map((entry) => entry.selectedKey), remoteMappingConfirmed: true,
    });
    if (!response.ok || !remotePhase3ReceiptMatches(body, targets)) throw new Error('REMOTE_PHASE3_RECEIPT_UNKNOWN');
    remotePhase3State.submitting = false;
    remotePhase3Elements.Dialog.close('submitted');
    showNotice('已提交 ' + targets.length + ' 个所选远端账号的本地 Phase 3。完成后点击“Phase 3 成功任务回写”核对并更新原 ID。', 'notice-info');
    await watchJobs(body.jobIds);
  } catch {
    remotePhase3Error('本批未获完整确认，已停止后续提交；后台仍可能执行。请先核实任务状态，不要更改目标重复提交。');
    await loadSnapshot({ resumeJobs: true });
  } finally {
    remotePhase3State.submitting = false;
    if (!state.job || !['queued', 'running', 'unknown'].includes(state.job.status)) state.phase3RequestPending = false;
    updateActionState();
  }
}

function remotePhase3SuccessfulResult(job) {
  const result = job?.result;
  const remote = result?.remoteTarget;
  if (job?.type !== 'phase3' || job.status !== 'succeeded' || job.error || jobNeedsReconciliation(job)
      || !/^job_[a-f0-9]{24}$/.test(String(job.id || ''))
      || !Number.isSafeInteger(remote?.accountId) || remote.accountId <= 0
      || !REMOTE_PHASE3_REVISION.test(String(remote.targetRevision || ''))
      || !/^[a-f0-9]{64}$/.test(String(remote.targetDigest || ''))
      || !/^[a-f0-9]{64}$/.test(String(remote.endpointDigest || ''))
      || !Array.isArray(remote.identityKeys) || remote.identityKeys.length < 1 || remote.identityKeys.length > 2
      || remote.identityKeys.some((key) => !/^(account|user):[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/.test(
        boundedReconciliationDisplay(key, 520) || '',
      ))
      || new Set(remote.identityKeys.map((key) => key.slice(0, key.indexOf(':')))).size !== remote.identityKeys.length
      || !['tokens', 'use_token'].includes(result?.tokenSource)
      || !/^[a-f0-9]{64}$/.test(String(result?.tokenContentHash || ''))) return null;
  const path = reconciliationSourcePath(result.tokenFile);
  if (!path || !path.startsWith(result.tokenSource + '/')) return null;
  return { jobId: job.id, selectedKey: 'token:' + result.tokenSource + ':' + path,
    tokenSource: result.tokenSource, tokenFile: path, tokenContentHash: result.tokenContentHash,
    remoteTargetDigest: remote.targetDigest,
    remoteEndpointDigest: remote.endpointDigest,
    remoteTarget: { accountId: remote.accountId, targetRevision: remote.targetRevision } };
}

function remotePhase3RecoverySelection(jobs = remotePhase3State.recoveryJobs,
  selected = remotePhase3State.recoverySelected) {
  const entries = jobs.filter(({ job }) => selected.has(job.id));
  let problem = '';
  if (!selected.size) problem = jobs.length ? '请先勾选需要回写的成功任务'
    : '没有可核验的成功任务；请先完成绑定远端 ID 的本地 Phase 3，再重新打开回写窗口';
  else if (entries.length !== selected.size) problem = '所选任务已不在当前清单中，请关闭后重新读取';
  else if (entries.length > 100) problem = '每批最多回写 100 个成功任务，请减少选择；不会自动省略超出项';
  else if (new Set(entries.map(({ target }) => target.remoteTarget.accountId)).size !== entries.length) {
    problem = '同一远端 ID 只能选择一个成功任务，请取消重复项后预览';
  } else if (new Set(entries.map(({ target }) => target.selectedKey)).size !== entries.length) {
    problem = '同一新 token 文件只能选择一次，请取消重复项后预览';
  }
  return { entries, problem };
}

function remotePhase3RecoveryImportProblem(selection = remotePhase3RecoverySelection()) {
  if (selection.problem) return selection.problem;
  const plan = remotePhase3State.recoveryPlan;
  if (!plan || !remotePhase3State.recoveryBinding) return '请先点击“预览定向回写”，核对每个原 ID 的动作';
  const invalid = remotePhase3ImportPlanProblem(plan, selection.entries.map((entry) => entry.target));
  if (invalid) return invalid;
  if (!plan.items.some((item) => item.action === 'update')) {
    return '本次预览全部跳过，无需更新；请查看上方每一项的跳过原因';
  }
  return '';
}

function renderRemotePhase3Recovery() {
  remotePhase3Elements.RecoveryRows.innerHTML = remotePhase3State.recoveryJobs.map(({ job, target }) => (
    '<tr><td><input type="checkbox" data-remote-phase3-job="' + escapeHtml(job.id)
    + '" aria-label="选择成功任务回写 Sub2API #' + target.remoteTarget.accountId + '"'
    + (remotePhase3State.recoverySelected.has(job.id) ? ' checked' : '') + '></td><td>Sub2API #'
    + target.remoteTarget.accountId + '<small>' + escapeHtml(formatDate(job.finishedAt))
    + '</small></td><td>' + escapeHtml(target.tokenFile) + '<small>任务 ' + escapeHtml(job.id)
    + '</small></td></tr>'
  )).join('');
  if (!remotePhase3State.recoveryBusy) {
    remotePhase3Elements.RecoverySummary.textContent = '最近任务中可核验成功 ' + remotePhase3State.recoveryJobs.length
      + ' 个 · 已选 ' + remotePhase3State.recoverySelected.size
      + '。这里只恢复回写预览，不会重新执行 Phase 3；失败、结果未知或已清理的任务不参与。';
  }
  updateRemotePhase3Ui();
}

async function openRemotePhase3Recovery() {
  const problem = remotePhase3ActionProblem();
  if (problem) { showNotice(problem, 'notice-warning'); return; }
  if (typeof remotePhase3Elements.RecoveryDialog?.showModal !== 'function') return;
  const generation = ++remotePhase3State.recoveryGeneration;
  remotePhase3State.recoveryJobs = [];
  remotePhase3State.recoverySelected = new Set();
  remotePhase3State.recoveryPlan = null;
  remotePhase3State.recoveryBinding = null;
  remotePhase3State.recoveryBusy = true;
  state.localPhase3ListingPending = true;
  remotePhase3Elements.RecoveryDialog.showModal();
  remotePhase3Elements.RecoverySummary.textContent = '读取最近成功的远端绑定 Phase 3 任务…';
  remotePhase3Elements.RecoveryPlan.textContent = '';
  remotePhase3Error('', true);
  renderRemotePhase3Recovery();
  updateActionState();
  try {
    const response = await apiFetch('/api/jobs?limit=200');
    const body = await response.json();
    if (generation !== remotePhase3State.recoveryGeneration || !remotePhase3Elements.RecoveryDialog.open) return;
    if (!response.ok || !Array.isArray(body.jobs) || body.jobs.length > 1000) throw new Error('INVENTORY_INVALID');
    const seen = new Set();
    const candidates = body.jobs.filter((entry) => entry?.type === 'phase3'
      && entry.status === 'succeeded' && !jobNeedsReconciliation(entry)).slice(0, 200);
    for (const job of candidates) {
      if (!/^job_[a-f0-9]{24}$/.test(String(job.id || ''))) throw new Error('INVENTORY_INVALID');
      if (seen.has(job.id)) throw new Error('INVENTORY_DUPLICATE');
      seen.add(job.id);
    }
    // The bounded inventory intentionally omits output fields. Fetch each
    // candidate's authenticated detail, with at most four requests in flight.
    const details = new Array(candidates.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(4, candidates.length) }, async () => {
      while (next < candidates.length) {
        const index = next++;
        if (generation !== remotePhase3State.recoveryGeneration || !remotePhase3Elements.RecoveryDialog.open) return;
        const detailResponse = await apiFetch('/api/jobs/' + encodeURIComponent(candidates[index].id));
        const job = await detailResponse.json();
        if (!detailResponse.ok || job.id !== candidates[index].id) throw new Error('DETAIL_INVALID');
        const target = remotePhase3SuccessfulResult(job);
        if (target) details[index] = { job, target };
      }
    }));
    if (generation === remotePhase3State.recoveryGeneration && remotePhase3Elements.RecoveryDialog.open) {
      remotePhase3State.recoveryJobs = details.filter(Boolean);
    }
  } catch {
    if (generation === remotePhase3State.recoveryGeneration) {
      remotePhase3State.recoveryJobs = [];
      remotePhase3Error('任务记录无法核验，未执行任何回写。请关闭后刷新任务状态。', true);
    }
  } finally {
    if (generation === remotePhase3State.recoveryGeneration) {
      remotePhase3State.recoveryBusy = false;
      state.localPhase3ListingPending = false;
      renderRemotePhase3Recovery();
      updateActionState();
    }
  }
}

function remotePhase3ImportPlanProblem(plan, targets) {
  const base = importPlanContractProblem(plan);
  if (base) return base;
  if (!validImportPlanIntentVersion(plan.planIntentVersion) || typeof plan.version !== 'string'
      || !plan.version || plan.items.length !== targets.length) return '回写预览版本或完整性无法确认';
  const seen = new Set();
  for (const item of plan.items) {
    if (Object.prototype.hasOwnProperty.call(item, 'identityCompletion')
        && item.identityCompletion !== 'account_id') {
      return '回写预览身份补全标记无效，已禁止导入';
    }
    const target = targets.find((entry) => entry.remoteTarget.accountId === item.accountId);
    if (!target || seen.has(item.accountId) || !['update', 'skip'].includes(item.action)
        || item.conflictingVersions === true || item.identityConflict === true
        || item.selectedSourceSuperseded === true
        || item.source !== target.tokenSource || item.relativePath !== target.tokenFile) {
      return '回写预览包含新增、其他 ID、不同来源或冲突，已禁止导入';
    }
    seen.add(item.accountId);
  }
  return '';
}

function remotePhase3IdentityCompletionLabel(item) {
  if (item.identityCompletion !== 'account_id') return '';
  return item.action === 'update'
    ? '同 User ID 核验一致，仅补缺失 Account ID，保留原 ID / 已有身份'
    : item.action === 'skip' ? '跳过：本次不补 Account ID，保留原 ID / 已有身份' : '';
}

async function previewRemotePhase3Import() {
  if (remotePhase3State.recoveryBusy || remotePhase3ActionProblem()) return;
  const { entries, problem } = remotePhase3RecoverySelection();
  if (problem) {
    remotePhase3Error(problem, true);
    remotePhase3Elements.RecoveryError.dataset.kind = 'selection';
    updateRemotePhase3Ui();
    return;
  }
  const generation = remotePhase3State.recoveryGeneration;
  remotePhase3State.recoveryBusy = true;
  remotePhase3State.recoveryPlan = null;
  remotePhase3State.recoveryBinding = null;
  state.previewRequestPending = true;
  remotePhase3Elements.RecoveryPlan.textContent = '';
  remotePhase3Error('', true);
  updateActionState();
  try {
    const targets = [];
    for (const entry of entries) {
      const response = await apiFetch('/api/jobs/' + encodeURIComponent(entry.job.id));
      const target = remotePhase3SuccessfulResult(await response.json());
      if (!response.ok || !target || JSON.stringify(target) !== JSON.stringify(entry.target)) throw new Error('JOB_CHANGED');
      targets.push(target);
    }
    const binding = { selectedKeys: targets.map((entry) => entry.selectedKey),
      remoteTargets: targets.map((entry) => ({ ...entry.remoteTarget })),
      phase3JobIds: targets.map((entry) => entry.jobId) };
    const response = await apiFetch('/api/sync/preview', { method: 'POST', body: JSON.stringify(binding) });
    const plan = await response.json();
    if (generation !== remotePhase3State.recoveryGeneration || !remotePhase3Elements.RecoveryDialog.open) return;
    if (!response.ok || remotePhase3ImportPlanProblem(plan, targets)) throw new Error('TARGETED_PLAN_INVALID');
    remotePhase3State.recoveryPlan = plan;
    remotePhase3State.recoveryBinding = binding;
    remotePhase3Elements.RecoveryPlan.textContent = plan.items.map((item) => 'Sub2API #' + item.accountId
      + '：' + actionLabel(item.action) + ' · ' + actionReasonLabel(item.reason) + ' · ' + item.relativePath
      + (remotePhase3IdentityCompletionLabel(item) ? ' · ' + remotePhase3IdentityCompletionLabel(item) : '')).join('\n')
      + '\n仅更新以上原 ID；可用账号跳过，绝不新增。';
  } catch {
    remotePhase3Error('任务、新 token 文件或目标快照已变化，或回写预览不能保证原 ID。未执行导入；请刷新核对，勿改用普通导入绕过。', true);
    remotePhase3Elements.RecoveryError.dataset.kind = 'preview';
  } finally {
    remotePhase3State.recoveryBusy = false;
    state.previewRequestPending = false;
    updateActionState();
  }
}

async function importRemotePhase3Tokens() {
  if (remotePhase3State.recoveryBusy || remotePhase3ActionProblem()) return;
  const selection = remotePhase3RecoverySelection();
  const problem = remotePhase3RecoveryImportProblem(selection);
  if (problem) {
    remotePhase3Error(problem, true);
    remotePhase3Elements.RecoveryError.dataset.kind = selection.problem ? 'selection' : 'preview';
    updateRemotePhase3Ui();
    return;
  }
  const plan = remotePhase3State.recoveryPlan;
  const binding = remotePhase3State.recoveryBinding;
  if (!window.confirm('确认仅向预览中的原 Sub2API ID 回写新 token？\n'
      + plan.items.map((item) => '#' + item.accountId + ' ' + actionLabel(item.action)
        + (remotePhase3IdentityCompletionLabel(item) ? '（' + remotePhase3IdentityCompletionLabel(item) + '）' : '')).join('、')
      + '\n不会新增账号；当前已可用账号跳过。')) return;
  remotePhase3State.recoveryBusy = true;
  state.importRequestPending = true;
  remotePhase3Error('', true);
  updateActionState();
  try {
    const { response, body } = await idempotentMutationFetch('token_import', '/api/sync/import', {
      ...binding, snapshotVersion: plan.version, planIntentVersion: plan.planIntentVersion,
    });
    if (!response.ok || !/^job_[a-f0-9]{24}$/.test(String(body.jobId || ''))) throw new Error('IMPORT_UNKNOWN');
    remotePhase3State.recoveryBusy = false;
    remotePhase3State.recoveryPlan = null;
    remotePhase3State.recoveryBinding = null;
    remotePhase3Elements.RecoveryDialog.close('submitted');
    showNotice('已提交定向回写任务，只处理确认的原 Sub2API ID。', 'notice-info');
    await watchJob(body.jobId, 'token_import');
  } catch {
    remotePhase3State.recoveryPlan = null;
    remotePhase3State.recoveryBinding = null;
    remotePhase3Error('回写提交结果无法确认，后台可能已执行。请先核对任务状态，不要改选目标重复导入。', true);
    remotePhase3Elements.RecoveryError.dataset.kind = 'submission';
    await loadSnapshot({ resumeJobs: true });
  } finally {
    remotePhase3State.recoveryBusy = false;
    if (!state.job || !['queued', 'running', 'unknown'].includes(state.job.status)) state.importRequestPending = false;
    updateActionState();
  }
}

remotePhase3Elements.Form?.addEventListener('submit', submitRemotePhase3);
remotePhase3Elements.Rows?.addEventListener('change', (event) => {
  if (remotePhase3State.loading || remotePhase3State.submitting || remotePhase3ActionProblem()
      || !remotePhase3State.listing || !remotePhase3SelectionUnchanged()) { updateRemotePhase3Ui(); return; }
  const id = Number(event.target?.dataset?.remotePhase3Id);
  if (!remotePhase3State.mappings.some((entry) => entry.accountId === id && !entry.reason)) return;
  if (event.target.checked) remotePhase3State.confirmed.add(id);
  else remotePhase3State.confirmed.delete(id);
  updateRemotePhase3Ui();
});
remotePhase3Elements.ConfirmAll?.addEventListener('change', (event) => {
  if (remotePhase3State.loading || remotePhase3State.submitting || remotePhase3ActionProblem()
      || !remotePhase3State.listing || !remotePhase3SelectionUnchanged()) { updateRemotePhase3Ui(); return; }
  // An explicit operator gesture confirms only the frozen, actionable mappings.
  // It neither acknowledges skipped rows nor submits a task.
  remotePhase3State.confirmed = new Set(event.target.checked
    ? remotePhase3State.mappings.filter((entry) => !entry.reason).map((entry) => entry.accountId) : []);
  updateRemotePhase3Ui();
});
remotePhase3Elements.SkipAcknowledged?.addEventListener('change', updateRemotePhase3Ui);
remotePhase3Elements.Dialog?.addEventListener('cancel', (event) => {
  if (remotePhase3State.submitting) event.preventDefault();
});
remotePhase3Elements.Dialog?.addEventListener('close', () => {
  if (remotePhase3State.submitting) return;
  remotePhase3State.generation += 1;
  remotePhase3State.loading = false;
  state.localPhase3ListingPending = false;
  remotePhase3State.listing = null;
  remotePhase3State.confirmed = new Set();
  updateActionState();
});
remotePhase3Elements.RecoveryButton?.addEventListener('click', openRemotePhase3Recovery);
remotePhase3Elements.RecoveryPreview?.addEventListener('click', previewRemotePhase3Import);
remotePhase3Elements.RecoveryImport?.addEventListener('click', importRemotePhase3Tokens);
remotePhase3Elements.RecoveryClose?.addEventListener('click', () => {
  if (!remotePhase3State.recoveryBusy) remotePhase3Elements.RecoveryDialog.close('cancel');
});
remotePhase3Elements.RecoveryRows?.addEventListener('change', (event) => {
  if (remotePhase3State.recoveryBusy || remotePhase3ActionProblem()) return;
  const id = event.target?.dataset?.remotePhase3Job;
  if (!remotePhase3State.recoveryJobs.some(({ job }) => job.id === id)) return;
  if (event.target.checked) remotePhase3State.recoverySelected.add(id);
  else remotePhase3State.recoverySelected.delete(id);
  remotePhase3State.recoveryPlan = null;
  remotePhase3State.recoveryBinding = null;
  remotePhase3Elements.RecoveryPlan.textContent = '';
  if (['selection', 'preview'].includes(remotePhase3Elements.RecoveryError.dataset.kind)) {
    remotePhase3Error('', true);
    remotePhase3Elements.RecoveryError.dataset.kind = '';
  }
  renderRemotePhase3Recovery();
});
remotePhase3Elements.RecoveryDialog?.addEventListener('cancel', (event) => {
  if (remotePhase3State.recoveryBusy) event.preventDefault();
});
remotePhase3Elements.RecoveryDialog?.addEventListener('close', () => {
  if (remotePhase3State.recoveryBusy) return;
  remotePhase3State.recoveryGeneration += 1;
  remotePhase3State.recoveryPlan = null;
  remotePhase3State.recoveryBinding = null;
  updateActionState();
});
// A fast initial snapshot can finish before this deferred component loads.
// Re-evaluate the shared controls once the new workflow is actually available.
if (state.snapshot && typeof renderRows === 'function') renderRows();
else updateActionState();
