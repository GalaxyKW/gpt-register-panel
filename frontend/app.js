const state = {
  snapshot: null,
  rows: [],
  selected: new Set(),
  plan: null,
  phase3RequestPending: false,
  previewRequestPending: false,
  importRequestPending: false,
  accountTestRequestPending: false,
  snapshotRefreshPending: false,
  job: null,
  jobs: [],
  watchIds: [],
  jobPollTimer: null,
  cleanupRequestPending: false,
  reconciliationAckPending: false,
  reconciliationAckTarget: null,
  reconciliationHolds: { total: 0, returned: 0, truncated: false },
  snapshotRequestSequence: 0,
  snapshotRequestsPending: 0,
  selectionRevision: 0,
  resumeJobsPending: false,
};

const elements = {
  notice: document.querySelector('#notice'),
  refreshButton: document.querySelector('#refreshButton'),
  modeBadge: document.querySelector('#modeBadge'),
  tokenCount: document.querySelector('#tokenCount'),
  tokenDetail: document.querySelector('#tokenDetail'),
  accountCount: document.querySelector('#accountCount'),
  accountDetail: document.querySelector('#accountDetail'),
  diffCount: document.querySelector('#diffCount'),
  diffDetail: document.querySelector('#diffDetail'),
  lastRead: document.querySelector('#lastRead'),
  searchInput: document.querySelector('#searchInput'),
  statusFilter: document.querySelector('#statusFilter'),
  availabilityFilter: document.querySelector('#availabilityFilter'),
  sourceFilter: document.querySelector('#sourceFilter'),
  diffFilter: document.querySelector('#diffFilter'),
  historicalToggle: document.querySelector('#historicalToggle'),
  selectionCount: document.querySelector('#selectionCount'),
  clearSelectionButton: document.querySelector('#clearSelectionButton'),
  selectAll: document.querySelector('#selectAll'),
  accountRows: document.querySelector('#accountRows'),
  emptyState: document.querySelector('#emptyState'),
  tableSummary: document.querySelector('#tableSummary'),
  loadingLabel: document.querySelector('#loadingLabel'),
  previewButton: document.querySelector('#previewButton'),
  importButton: document.querySelector('#importButton'),
  phase3Button: document.querySelector('#phase3Button'),
  accountTestButton: document.querySelector('#accountTestButton'),
  accountTestModelSelect: document.querySelector('#accountTestModelSelect'),
  cleanupButton: document.querySelector('#cleanupButton'),
  planPanel: document.querySelector('#planPanel'),
  planSummary: document.querySelector('#planSummary'),
  planVersion: document.querySelector('#planVersion'),
  planRows: document.querySelector('#planRows'),
  jobPanel: document.querySelector('#jobPanel'),
  jobTitle: document.querySelector('#jobTitle'),
  jobStatus: document.querySelector('#jobStatus'),
  jobMeta: document.querySelector('#jobMeta'),
  reconciliationAckButton: document.querySelector('#reconciliationAckButton'),
  reconciliationAckDialog: document.querySelector('#reconciliationAckDialog'),
  reconciliationAckForm: document.querySelector('#reconciliationAckForm'),
  reconciliationAckJobId: document.querySelector('#reconciliationAckJobId'),
  reconciliationAckScope: document.querySelector('#reconciliationAckScope'),
  reconciliationAckDigest: document.querySelector('#reconciliationAckDigest'),
  reconciliationAckResolution: document.querySelector('#reconciliationAckResolution'),
  reconciliationAckConfirmation: document.querySelector('#reconciliationAckConfirmation'),
  reconciliationAckError: document.querySelector('#reconciliationAckError'),
  reconciliationAckCancel: document.querySelector('#reconciliationAckCancel'),
  reconciliationAckConfirm: document.querySelector('#reconciliationAckConfirm'),
  adminTokenDialog: document.querySelector('#adminTokenDialog'),
  adminTokenInput: document.querySelector('#adminTokenInput'),
  adminTokenOrigin: document.querySelector('#adminTokenOrigin'),
};

const RECONCILIATION_ACK_CONFIRMATION = '我已按强身份完成人工核对';
const RECONCILIATION_ACK_RESOLUTIONS = new Set([
  'operation_applied',
  'operation_not_applied',
  'state_manually_reconciled',
]);

function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function formatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? date.toLocaleString('zh-CN', { hour12: false })
    : String(value);
}

function formatFingerprint(value) {
  if (!value) return '-';
  return String(value).slice(0, 8);
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function optionalUsageNumber(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    if (typeof value !== 'number' && typeof value !== 'string') continue;
    if (typeof value === 'string' && !value.trim()) continue;
    const number = Number(value);
    if (Number.isFinite(number) && number >= 0) return number;
  }
  return null;
}

function formatUsage(usage) {
  if (!usage) return '-';
  if (usage.error) return '读取失败';
  if (usage.historical || usage.current) return formatUsage(usage.historical || null);
  const total = optionalUsageNumber(usage.totalTokens, usage.tokens);
  const requests = optionalUsageNumber(usage.requests, usage.totalRequests);
  if (total === null && requests === null) return '-';
  if (total === 0 && requests === 0) return '0';
  return (total === null ? '-' : total.toLocaleString('en-US'))
    + ' / ' + (requests === null ? '-' : requests.toLocaleString('en-US')) + ' 次';
}

function formatPeriodUsage(usage) {
  if (!usage) return '-';
  if (usage.historical || usage.current) return formatUsage(usage.current || null);
  return formatUsage(usage);
}

function badgeClass(kind) {
  return {
    in_sync: 'badge-success',
    token_only: 'badge-warning',
    remote_unknown: 'badge-neutral',
    sub2api_only: 'badge-neutral',
    token_changed: 'badge-danger',
    expired: 'badge-danger',
    expiry_invalid: 'badge-danger',
    invalid_file: 'badge-danger',
    duplicate_identity: 'badge-danger',
    mapping_conflict: 'badge-danger',
    historical_backup: 'badge-neutral',
    missing_refresh_token: 'badge-warning',
  }[kind] || 'badge-neutral';
}

function kindLabel(kind) {
  return {
    in_sync: '一致',
    token_only: '仅文件',
    remote_unknown: '远端未知',
    sub2api_only: '仅 Sub2API',
    token_changed: 'Token 不同',
    expired: '已过期',
    expiry_invalid: '过期时间无效',
    invalid_file: '文件异常',
    duplicate_identity: '身份重复',
    mapping_conflict: '身份冲突',
    historical_backup: '历史备份',
    missing_refresh_token: '缺少续期',
  }[kind] || kind || '-';
}

function actionLabel(action) {
  return { create: '新增', update: '更新', skip: '跳过', conflict: '冲突' }[action] || action || '-';
}

function actionReasonLabel(reason) {
  return {
    token_only: 'Sub2API 没有对应账号',
    already_in_sync: '已经一致',
    sub2api_available: 'Sub2API 当前可用，跳过',
    source_token_expired: '来源 token 已过期，跳过',
    source_expiry_invalid: '来源过期时间无效，禁止自动导入',
    source_disabled: '来源文件已禁用，跳过',
    source_account_terminal: '来源账号已处置，跳过',
    superseded_by_newer_source: '已有更新来源，跳过旧文件',
    token_changed: 'Sub2API 不可用且 token 不同',
    multiple_sub2api_accounts: '匹配到多个 Sub2API 账号',
    duplicate_token_versions: '来源存在多个冲突版本',
    conflicting_token_versions: '来源 token 版本冲突，禁止导入',
    source_identity_insufficient: '来源缺少可验证的强身份，禁止导入',
    conflicting_strong_identity: '来源强身份字段相互冲突，禁止导入',
    incomparable_strong_identity: '来源强身份无法安全比较，禁止导入',
    ambiguous_sub2api_identity: 'Sub2API 身份匹配不唯一，禁止导入',
    free_name_exhausted: 'free 五位编号已用尽，禁止导入',
    free_name_conflict: '目标 free 编号存在大小写或空白冲突，禁止导入',
    sub2api_account_schema_invalid: 'Sub2API 账号字段不完整或相互冲突，禁止导入',
    sub2api_target_kind_invalid: 'Sub2API 目标不是 OpenAI OAuth 账号，禁止导入',
    sub2api_availability_unknown: 'Sub2API 可用性未知，跳过',
    sub2api_status_unknown: 'Sub2API 状态未知，跳过',
    sub2api_status_missing: 'Sub2API 缺少状态，跳过',
    sub2api_schedulable_missing: 'Sub2API 缺少调度状态，跳过',
    sub2api_auto_pause_invalid: 'Sub2API 自动停用字段无效，跳过',
    sub2api_expiry_invalid: 'Sub2API 过期时间无效，跳过',
    sub2api_temp_unschedulable_invalid: 'Sub2API 临时停调时间无效，跳过',
    sub2api_rate_limit_invalid: 'Sub2API 限流恢复时间无效，跳过',
    sub2api_overload_invalid: 'Sub2API 过载恢复时间无效，跳过',
    sub2api_read_failed: 'Sub2API 读取失败',
    sub2api_not_read: '本次未读取 Sub2API',
  }[reason] || (reason ? '操作原因未识别' : '-');
}

function phase3ReasonLabel(reason) {
  return {
    token_missing: '该行仅来自 Sub2API，缺少对应 token 文件',
    username_missing: 'token 邮箱在 username.json 中没有对应账号',
    username_ambiguous: 'token 邮箱在 username.json 中匹配到多个账号',
    username_password_missing: 'username.json 对应账号缺少密码',
    username_terminal: 'username.json 对应账号已删除、停用或禁用',
  }[reason] || '该账号不符合 Phase 3 条件';
}

function effectivePlanAction(item) {
  return item?.action === 'conflict' || item?.conflictingVersions === true
    ? 'conflict'
    : item?.action;
}

function effectivePlanReason(item) {
  return item?.conflictingVersions === true
    ? 'conflicting_token_versions'
    : item?.reason;
}

function statusClass(value) {
  const status = String(value || '').toLowerCase();
  if (status === 'active' || status === 'enabled') return 'status-active';
  if (status === 'error' || status === 'disabled' || status === 'account_deleted') return 'status-error';
  return 'status-unknown';
}

function statusLabel(value) {
  return {
    account_deleted: '已处置',
  }[String(value || '')] || value || '-';
}

function sourceClass(value) {
  const source = String(value || '').toLowerCase();
  if (source === 'tokens') return 'source-tokens';
  if (source === 'use_token') return 'source-use-token';
  return 'source-sub2api';
}

let memoryPanelToken = '';

function readPanelToken() {
  try {
    const stored = sessionStorage.getItem('panelToken');
    if (stored) memoryPanelToken = stored;
  } catch {}
  return memoryPanelToken;
}

function savePanelToken(token) {
  memoryPanelToken = String(token || '');
  try { sessionStorage.setItem('panelToken', memoryPanelToken); } catch {}
}

function clearPanelToken() {
  memoryPanelToken = '';
  try { sessionStorage.removeItem('panelToken'); } catch {}
}

function apiHeaders(options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('accept', 'application/json');
  if (options.body !== undefined && !headers.has('content-type')) headers.set('content-type', 'application/json');
  const token = readPanelToken();
  if (token) headers.set('x-panel-token', token);
  return headers;
}

const API_REQUEST_TIMEOUT_MS = 45000;
let adminTokenRequest = null;

function requestAdminToken() {
  if (adminTokenRequest) return adminTokenRequest;
  const dialog = elements.adminTokenDialog;
  const input = elements.adminTokenInput;
  if (!dialog || !input || typeof dialog.showModal !== 'function') return Promise.resolve('');

  let resolveRequest;
  let finished = false;
  const request = new Promise((resolve) => { resolveRequest = resolve; });
  adminTokenRequest = request;
  const finish = (token) => {
    if (finished) return;
    finished = true;
    dialog.removeEventListener('close', onClose);
    input.value = '';
    if (adminTokenRequest === request) adminTokenRequest = null;
    resolveRequest(token);
  };
  const onClose = () => finish(dialog.returnValue === 'confirm' ? input.value : '');
  dialog.addEventListener('close', onClose, { once: true });
  dialog.returnValue = '';
  input.value = '';
  if (elements.adminTokenOrigin) elements.adminTokenOrigin.textContent = window.location.origin;
  try {
    dialog.showModal();
    input.focus();
  } catch {
    finish('');
  }
  return request;
}

function normalizedApiTimeout(value) {
  if (value === undefined) return API_REQUEST_TIMEOUT_MS;
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return API_REQUEST_TIMEOUT_MS;
  return Math.min(Math.max(1, Math.trunc(number)), 120000);
}

function apiTimeoutError() {
  const error = new Error('请求超时，请检查网络后重试。');
  error.name = 'TimeoutError';
  return error;
}

function sameOriginApiUrl(value) {
  const resolved = new URL(String(value), window.location.origin);
  if (resolved.origin !== window.location.origin || resolved.username || resolved.password) {
    throw new Error('拒绝向非同源地址发送面板凭证。');
  }
  return resolved.href;
}

async function apiFetchAttempt(url, options = {}) {
  const { timeoutMs, signal: callerSignal, ...requestOptions } = options;
  const controller = new AbortController();
  let timedOut = false;
  const abortFromCaller = () => controller.abort();
  if (callerSignal?.aborted) controller.abort();
  else callerSignal?.addEventListener('abort', abortFromCaller, { once: true });
  const timer = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, normalizedApiTimeout(timeoutMs));
  try {
    const response = await fetch(sameOriginApiUrl(url), {
      ...requestOptions,
      headers: apiHeaders(requestOptions),
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
    });
    // Buffer the same-origin JSON response while the deadline is active. This
    // also bounds response.json(), rather than stopping the timer at headers.
    const hasBody = !['HEAD'].includes(String(requestOptions.method || 'GET').toUpperCase())
      && ![204, 205, 304].includes(response.status);
    const body = hasBody ? await response.arrayBuffer() : null;
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch (error) {
    if (timedOut) throw apiTimeoutError();
    throw error;
  } finally {
    window.clearTimeout(timer);
    callerSignal?.removeEventListener('abort', abortFromCaller);
  }
}

async function apiFetch(url, options = {}) {
  const attemptedToken = readPanelToken();
  const response = await apiFetchAttempt(url, options);
  if (response.status !== 401) return response;
  const latestToken = readPanelToken();
  if (latestToken && latestToken !== attemptedToken) return apiFetchAttempt(url, options);
  clearPanelToken();
  const token = await requestAdminToken();
  if (!token) return response;
  savePanelToken(token);
  // apiFetchAttempt creates a new AbortController for the retry. Reusing the
  // first attempt's signal would make a valid credential retry abort at once.
  return apiFetchAttempt(url, options);
}

function renderSelectOptions(select, values, labelMap, emptyLabel) {
  const current = select.value;
  select.innerHTML = '<option value="">' + emptyLabel + '</option>';
  for (const value of values || []) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = labelMap?.[value] || value;
    select.appendChild(option);
  }
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}

const fallbackAccountTestModels = [
  'gpt-5.6-luna',
  'gpt-5.6-terra',
  'gpt-5.6-sol',
  'gpt-5.4',
  'gpt-5.4-mini',
];

function normalizeAccountTestModel(value) {
  const model = String(value || '').trim();
  return model.toLowerCase() === '5.6-luna' ? 'gpt-5.6-luna' : model;
}

function accountTestModelLabel(value) {
  return value === 'gpt-5.6-luna' ? '5.6-luna' : value;
}

function renderAccountTestModels(models) {
  if (!elements.accountTestModelSelect) return;
  const current = elements.accountTestModelSelect.value;
  const values = [...new Set((models || []).map(normalizeAccountTestModel).filter(Boolean))];
  if (!values.includes('gpt-5.6-luna')) values.unshift('gpt-5.6-luna');
  elements.accountTestModelSelect.innerHTML = '';
  for (const value of values) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = accountTestModelLabel(value);
    elements.accountTestModelSelect.appendChild(option);
  }
  if ([...elements.accountTestModelSelect.options].some((option) => option.value === current)) {
    elements.accountTestModelSelect.value = current;
  } else if (values.length > 0) {
    elements.accountTestModelSelect.value = values[0];
  }
}

function accountTestRows(rows) {
  const seen = new Set();
  return (rows || []).filter((row) => {
    const id = Number(row?.accountId);
    if (!Number.isSafeInteger(id) || id <= 0) return false;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

async function loadAccountTestModels(snapshot) {
  renderAccountTestModels(fallbackAccountTestModels);
  const candidate = accountTestRows(snapshot?.rows || [])[0];
  if (!candidate || sub2ApiReadStatus(snapshot) !== 'ok') return;
  try {
    const response = await apiFetch('/api/account-tests/models?accountId=' + encodeURIComponent(String(candidate.accountId)));
    const body = await response.json();
    if (!response.ok || !Array.isArray(body.models) || body.models.length === 0) return;
    if (state.snapshot !== snapshot) return;
    renderAccountTestModels(body.models);
  } catch {
    // Keep the safe fallback list when the optional model lookup is unavailable.
  }
}

function actionRequestPending() {
  return state.previewRequestPending
    || state.importRequestPending
    || state.phase3RequestPending
    || state.accountTestRequestPending
    || state.cleanupRequestPending
    || state.reconciliationAckPending;
}

function activeJobPending() {
  return ['queued', 'running', 'unknown'].includes(state.job?.status);
}

function actionsLocked() {
  return actionRequestPending()
    || activeJobPending()
    || state.snapshotRefreshPending
    || state.snapshotRequestsPending > 0;
}

function reconciliationWriteBlocked() {
  const reportedTotal = Number(state.reconciliationHolds?.total);
  return (Number.isSafeInteger(reportedTotal) && reportedTotal > 0)
    || reconciliationHoldJobs(state.job).length > 0;
}

function sub2ApiReadStatus(snapshot = state.snapshot) {
  const explicit = snapshot?.sub2api?.readStatus;
  if (['ok', 'failed', 'omitted'].includes(explicit)) return explicit;
  if (explicit !== undefined && explicit !== null) return 'failed';
  // Compatibility for the already-running pre-upgrade backend: its snapshot
  // has no readStatus/comparisonStatus, but a successful read exposes an
  // integer accountCount and failures expose apiError.
  if (snapshot?.sub2api?.apiError) return 'failed';
  const legacyCount = snapshot?.sub2api?.accountCount;
  return Number.isSafeInteger(legacyCount) && legacyCount >= 0 ? 'ok' : 'omitted';
}

function comparisonAvailable(snapshot = state.snapshot) {
  const status = snapshot?.diff?.comparisonStatus;
  return sub2ApiReadStatus(snapshot) === 'ok'
    && (status === undefined || status === 'complete');
}

function updateImportButtonState() {
  const items = state.plan?.items || [];
  const hasBlockingConflict = items.some((item) => effectivePlanAction(item) === 'conflict');
  elements.importButton.disabled = !state.plan
    || actionsLocked()
    || reconciliationWriteBlocked()
    || !comparisonAvailable()
    || Boolean(state.snapshot?.readOnly)
    || state.plan.selectedKeys.length === 0
    || hasBlockingConflict
    || !items.some((item) => ['create', 'update'].includes(effectivePlanAction(item)));
}

function renderMetrics(snapshot) {
  const summary = snapshot.sources.summary || {};
  const counts = snapshot.diff.counts || {};
  const differenceEntries = Object.entries(counts).filter(([kind]) => kind !== 'in_sync');
  const diffCount = differenceEntries.reduce((sum, [, value]) => sum + finiteNumber(value), 0);
  const activeTokenCount = summary.activeTokenCount ?? summary.tokenCount;
  const activeValidTokenCount = summary.activeValidTokenCount ?? summary.validTokenCount;
  const activeInvalidTokenCount = summary.activeInvalidTokenCount ?? summary.invalidTokenCount;
  const historicalTokenCount = finiteNumber(summary.historicalTokenCount);
  elements.tokenCount.textContent = String(activeTokenCount ?? '-');
  elements.tokenDetail.textContent = String(activeValidTokenCount ?? 0) + ' 可解析 · ' + String(activeInvalidTokenCount ?? 0) + ' 异常'
    + (historicalTokenCount ? ' · ' + historicalTokenCount + ' 个历史备份已隐藏' : '');
  const canCompare = comparisonAvailable(snapshot);
  const readStatus = sub2ApiReadStatus(snapshot);
  elements.accountCount.textContent = readStatus === 'ok'
    ? String(snapshot.sub2api.accountCount)
    : '-';
  elements.accountDetail.textContent = readStatus === 'failed'
    ? 'API 未连接'
    : readStatus === 'omitted'
      ? '本次未读取'
      : (snapshot.sub2api.statsError ? '统计暂不可用' : '管理员 API 正常');
  elements.diffCount.textContent = canCompare ? String(diffCount) : '-';
  elements.diffDetail.textContent = canCompare
    ? (differenceEntries.map(([key, value]) => kindLabel(key) + ' ' + value).join(' · ') || '暂无差异')
    : 'Sub2API 状态未知，无法比较';
  elements.lastRead.textContent = formatDate(snapshot.generatedAt);
  elements.modeBadge.textContent = snapshot.readOnly ? '只读模式' : '可写模式';
  elements.modeBadge.className = 'badge ' + (snapshot.readOnly ? 'badge-neutral' : 'badge-success');
  if (elements.cleanupButton) elements.cleanupButton.disabled = snapshot.readOnly || actionsLocked();
}

function selectedRowsFromView() {
  return state.rows.filter((row) => state.selected.has(row.key));
}

function selectedRowsFromSelection() {
  return (state.snapshot?.rows || []).filter((row) => state.selected.has(row.key));
}

function phase3EmailFromRow(row) {
  const value = Object.prototype.hasOwnProperty.call(row || {}, 'phase3Email')
    ? row.phase3Email
    : row?.email;
  return String(value || '').trim().toLowerCase();
}

function phase3RowRejected(row) {
  if (Object.prototype.hasOwnProperty.call(row || {}, 'phase3Eligible')) {
    return row.phase3Eligible !== true;
  }
  return !['tokens', 'use_token'].includes(String(row?.source || ''));
}

function phase3TargetsFromRows(rows) {
  const targets = [];
  const seen = new Set();
  for (const row of rows || []) {
    // Old snapshots did not expose phase3Eligible/phase3Email. Keep their
    // email-only behavior only for rows that still prove a local token source.
    if (phase3RowRejected(row)) continue;
    const email = phase3EmailFromRow(row);
    const phone = String(row.phone || '').trim();
    if (!email && !phone) continue;
    const phoneKey = phone.replace(/[^0-9]/g, '');
    const keys = [email ? 'email:' + email : null, phoneKey ? 'phone:' + phoneKey : null].filter(Boolean);
    if (keys.some((key) => seen.has(key))) continue;
    keys.forEach((key) => seen.add(key));
    targets.push({ email: email || '', phone: phoneKey || phone || '', selectedKey: row.key });
  }
  return targets;
}

function phase3SelectionProblem(rows, selectedCount) {
  if (selectedCount === 0) return '请至少选择一个账号';
  if (rows.length !== selectedCount) return '所选账号已不在当前快照中，请刷新后重选';
  const rejected = rows.find(phase3RowRejected);
  if (rejected) return phase3ReasonLabel(rejected.phase3Reason || 'token_missing');
  const missingTarget = rows.some((row) => (
    !phase3EmailFromRow(row) && !String(row?.phone || '').trim()
  ));
  return missingTarget ? '所选账号缺少可用于 Phase 3 的邮箱或手机号' : '';
}

function invalidatePlan() {
  if (!state.plan) return;
  renderPlan(null);
  showNotice('选择已变化，请重新执行“检查差异”。', 'notice-warning');
}

function selectionsEqual(left, right) {
  if (left.size !== right.size) return false;
  return [...left].every((key) => right.has(key));
}

function changeSelection(nextSelected) {
  if (actionsLocked()) return false;
  const next = new Set(nextSelected);
  if (selectionsEqual(state.selected, next)) return false;
  state.selected = next;
  state.selectionRevision += 1;
  invalidatePlan();
  renderRows();
  return true;
}

function selectionStillCurrent(revision, selectedKeys) {
  if (state.selectionRevision !== revision || state.selected.size !== selectedKeys.length) return false;
  return selectedKeys.every((key) => state.selected.has(key));
}

function rowSideData(row) {
  const splitContract = Object.prototype.hasOwnProperty.call(row || {}, 'sourceDetails')
    || Object.prototype.hasOwnProperty.call(row || {}, 'remoteDetails');
  if (splitContract) {
    return {
      source: row?.sourceDetails || null,
      remote: row?.remoteDetails || null,
      legacyMerged: false,
    };
  }
  const legacy = {
    email: row?.email || '',
    chatgptAccountId: row?.chatgptAccountId || '',
    userId: row?.userId || '',
    expiresAt: row?.expiresAt || null,
    fingerprints: row?.fingerprints || {},
    relativePath: row?.relativePath || null,
    fileName: row?.fileName || null,
  };
  const localSource = ['tokens', 'use_token'].includes(String(row?.source || ''));
  const remoteId = Number(row?.accountId);
  const hasRemote = Number.isSafeInteger(remoteId) && remoteId > 0;
  if (localSource && hasRemote) {
    return { source: legacy, remote: null, legacyMerged: true };
  }
  return {
    source: localSource ? legacy : null,
    remote: hasRemote || row?.source === 'sub2api' ? legacy : null,
    legacyMerged: false,
  };
}

function comparableText(value, options = {}) {
  const text = String(value === undefined || value === null ? '' : value).trim();
  return options.caseInsensitive ? text.toLowerCase() : text;
}

function comparableDate(value) {
  if (!value) return '';
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? String(time) : String(value);
}

function comparisonDiffers(sides, sourceValue, remoteValue, options = {}) {
  if (sides.legacyMerged || !sides.source || !sides.remote) return false;
  const normalize = options.date ? comparableDate : (value) => comparableText(value, options);
  return normalize(sourceValue) !== normalize(remoteValue);
}

function comparisonLine(label, value, differs, valueClass = '') {
  return '<div class="comparison-line' + (differs ? ' is-different' : '') + '"'
    + (differs ? ' title="gpt_register 与 Sub2API 不同"' : '') + '>'
    + '<span class="comparison-label">' + escapeHtml(label) + '</span>'
    + '<span class="comparison-value ' + escapeHtml(valueClass) + '">' + escapeHtml(value || '-') + '</span>'
    + (differs ? '<span class="comparison-marker" aria-label="不同">≠</span>' : '')
    + '</div>';
}

function legacyComparison(value) {
  return '<div class="legacy-comparison">'
    + '<div class="comparison-line"><span class="comparison-label">旧快照</span>'
    + '<span class="comparison-value">' + escapeHtml(value || '-') + '</span></div>'
    + '<small>后端尚未提供分侧字段，请刷新服务后再比较</small></div>';
}

function renderEmailComparison(row, sides, phase3Note) {
  if (sides.legacyMerged) return legacyComparison(row?.email || '-') + phase3Note;
  const sourceEmail = sides.source?.email || '';
  const remoteEmail = sides.remote?.email || '';
  const differs = comparisonDiffers(sides, sourceEmail, remoteEmail, { caseInsensitive: true });
  return '<div class="comparison-pair">'
    + comparisonLine('文件', sourceEmail, differs)
    + comparisonLine('远端', remoteEmail, differs)
    + '</div>' + phase3Note;
}

function identityText(details) {
  if (!details) return '-';
  const account = details.chatgptAccountId || '-';
  const user = details.userId || '-';
  return 'Account ID ' + account + ' · User ID ' + user;
}

function renderIdentityComparison(row, sides) {
  if (sides.legacyMerged) return legacyComparison(identityText({
    chatgptAccountId: row?.chatgptAccountId,
    userId: row?.userId,
  }));
  const sourceText = identityText(sides.source);
  const remoteText = identityText(sides.remote);
  const differs = comparisonDiffers(sides, sourceText, remoteText, { caseInsensitive: true });
  return '<div class="comparison-pair">'
    + comparisonLine('文件', sourceText, differs, 'identity-value')
    + comparisonLine('远端', remoteText, differs, 'identity-value')
    + '</div>';
}

function renderExpiryComparison(row, sides) {
  if (sides.legacyMerged) return legacyComparison(formatDate(row?.expiresAt));
  const sourceExpiry = sides.source?.expiresAt || null;
  const remoteExpiry = sides.remote?.credentialExpiresAt
    // Compatibility with a short-lived development snapshot contract that
    // exposed only `remoteDetails.expiresAt`.
    || sides.remote?.expiresAt
    || null;
  const accountExpiry = sides.remote?.accountExpiresAt || null;
  const differs = comparisonDiffers(sides, sourceExpiry, remoteExpiry, { date: true });
  return '<div class="comparison-pair">'
    + comparisonLine('文件 OAuth', formatDate(sourceExpiry), differs)
    + comparisonLine('远端 OAuth', formatDate(remoteExpiry), differs)
    + (accountExpiry ? comparisonLine('账号期限', formatDate(accountExpiry), false) : '')
    + '</div>';
}

function fingerprintText(details) {
  const fingerprints = details?.fingerprints || {};
  return 'A ' + formatFingerprint(fingerprints.access)
    + ' · R ' + formatFingerprint(fingerprints.refresh)
    + ' · ID ' + formatFingerprint(fingerprints.id);
}

function fingerprintComparisonKey(details) {
  const fingerprints = details?.fingerprints || {};
  return ['access', 'refresh', 'id']
    .map((key) => comparableText(fingerprints[key]))
    .join('|');
}

function renderFingerprintComparison(row, sides) {
  if (sides.legacyMerged) return legacyComparison(fingerprintText({ fingerprints: row?.fingerprints }));
  const sourceText = fingerprintText(sides.source);
  const remoteText = fingerprintText(sides.remote);
  const differs = comparisonDiffers(
    sides,
    fingerprintComparisonKey(sides.source),
    fingerprintComparisonKey(sides.remote),
  );
  return '<div class="comparison-pair">'
    + comparisonLine('文件', sourceText, differs, 'fingerprint-value')
    + comparisonLine('远端', remoteText, differs, 'fingerprint-value')
    + '</div>';
}

function renderAccountSummary(row, sides, displayName) {
  const remoteId = sides.remote?.id ?? row?.accountId;
  const sourcePath = sides.source?.relativePath || row?.relativePath || '';
  const details = [];
  if (remoteId) details.push('Sub2API ID #' + remoteId);
  if (sourcePath) details.push('文件 ' + sourcePath);
  if (details.length === 0) details.push('尚未关联来源文件');
  return '<strong>' + escapeHtml(displayName) + '</strong>'
    + details.map((detail) => '<small>' + escapeHtml(detail) + '</small>').join('');
}

function availabilityReasonLabel(reason) {
  return {
    sub2api_available: '可用',
    sub2api_status_active: '账号状态正常',
    sub2api_status_disabled: '账号已禁用',
    sub2api_status_error: '账号处于 error',
    sub2api_status_unknown: '账号状态无法识别',
    sub2api_status_missing: '缺少账号状态',
    sub2api_schema_invalid: '账号字段不完整或冲突',
    sub2api_schedulable_missing: '缺少调度状态',
    sub2api_unschedulable: '调度已关闭',
    sub2api_auto_pause_invalid: '过期自动停调配置无效',
    sub2api_expired: '账号已过期',
    sub2api_expiry_invalid: '账号过期时间无效',
    sub2api_temp_unschedulable: '账号临时停调',
    sub2api_temp_unschedulable_invalid: '临时停调时间无效',
    sub2api_rate_limited: '账号限流中',
    sub2api_rate_limit_invalid: '限流恢复时间无效',
    sub2api_overloaded: '账号过载停调中',
    sub2api_overload_invalid: '过载恢复时间无效',
    sub2api_read_failed: 'Sub2API 读取失败',
    sub2api_not_read: '本次未读取 Sub2API',
    not_in_sub2api: '未导入 Sub2API',
  }[String(reason || '').trim().toLowerCase()] || '原因无法安全识别';
}

function renderRemoteState(row, sides) {
  const remoteId = Number(sides.remote?.id ?? row?.accountId);
  if (!Number.isSafeInteger(remoteId) || remoteId <= 0) return '';
  const hasKnownFlag = Object.prototype.hasOwnProperty.call(row || {}, 'schedulableKnown');
  const schedulableKnown = hasKnownFlag
    ? row.schedulableKnown === true && typeof row.schedulable === 'boolean'
    : typeof row?.schedulable === 'boolean';
  const scheduler = schedulableKnown
    ? (row.schedulable ? '调度：开启' : '调度：关闭')
    : '调度：未知';
  const availability = String(row?.availability || 'unknown');
  const availabilityText = availability === 'available'
    ? '可用'
    : availability === 'unavailable'
      ? '不可用：' + availabilityReasonLabel(row?.availabilityReason)
      : '可用性未知：' + availabilityReasonLabel(row?.availabilityReason);
  return '<small class="availability-note">' + escapeHtml(scheduler) + '</small>'
    + '<small class="availability-note">' + escapeHtml(availabilityText) + '</small>';
}

function renderDiffDecision(row, sides) {
  const action = ['create', 'update', 'skip', 'conflict'].includes(row?.decisionAction)
    ? row.decisionAction
    : null;
  if (action) {
    const reason = actionReasonLabel(row?.decisionReason);
    return '<small class="availability-note">同步：' + escapeHtml(actionLabel(action))
      + (reason === '-' ? '' : ' · ' + escapeHtml(reason)) + '</small>';
  }
  const previewable = Boolean(sides?.source)
    && row?.historical !== true
    && !['invalid_file', 'remote_unknown'].includes(row?.diffKind);
  const label = previewable ? '同步：需先预览' : '同步：不可决策';
  const reason = actionReasonLabel(row?.decisionReason);
  return '<small class="availability-note">' + escapeHtml(label)
    + (reason === '-' ? '' : ' · ' + escapeHtml(reason)) + '</small>';
}

function renderRows() {
  const rows = state.rows;
  const checkboxDisabled = actionsLocked() ? ' disabled' : '';
  elements.accountRows.innerHTML = rows.map((row) => {
    const checked = state.selected.has(row.key) ? ' checked' : '';
    const sides = rowSideData(row);
    const displayName = sides.remote?.name || row.accountName || row.fileName || '(未命名)';
    const issueText = row.issues?.length ? ' title="' + escapeHtml(row.issues.join(', ')) + '"' : '';
    const usageTitle = row.usageError ? ' title="' + escapeHtml(row.usageError) + '"' : '';
    const phase3Note = row.phase3Eligible === false
      ? '<small class="availability-note">Phase 3：' + escapeHtml(phase3ReasonLabel(row.phase3Reason)) + '</small>'
      : (row.phone ? '<small>手机号 ' + escapeHtml(row.phone) + '</small>' : '');
    return '<tr class="' + (state.selected.has(row.key) ? 'is-selected' : '') + '">'
      + '<td class="check-col"><input class="row-check" data-key="' + escapeHtml(row.key) + '" type="checkbox" aria-label="选择 ' + escapeHtml(displayName) + '"' + checked + checkboxDisabled + '></td>'
      + '<td>' + renderAccountSummary(row, sides, displayName) + '</td>'
      + '<td class="comparison-cell">' + renderEmailComparison(row, sides, phase3Note) + '</td>'
      + '<td class="comparison-cell">' + renderIdentityComparison(row, sides) + '</td>'
      + '<td><span class="status-text ' + statusClass(row.status) + '"><span class="status-dot" aria-hidden="true"></span>' + escapeHtml(statusLabel(row.status)) + '</span>'
      + renderRemoteState(row, sides) + '</td>'
      + '<td><span class="source-text ' + sourceClass(row.source) + '">' + escapeHtml(row.source || '-') + '</span></td>'
      + '<td' + issueText + '><span class="badge ' + badgeClass(row.diffKind) + '">' + escapeHtml(kindLabel(row.diffKind)) + '</span>'
      + renderDiffDecision(row, sides) + '</td>'
      + '<td class="comparison-cell">' + renderExpiryComparison(row, sides) + '</td>'
      + '<td class="comparison-cell">' + renderFingerprintComparison(row, sides) + '</td>'
      + '<td class="col-historical"' + usageTitle + '>' + escapeHtml(row.usageError ? '读取失败' : formatUsage(row.usage)) + '</td>'
      + '<td class="col-current"' + usageTitle + '>' + escapeHtml(row.usageError ? '读取失败' : formatPeriodUsage(row.usage)) + '</td>'
      + '</tr>';
  }).join('');
  elements.emptyState.hidden = rows.length !== 0;
  const selectedVisible = rows.filter((row) => state.selected.has(row.key)).length;
  elements.tableSummary.textContent = '当前显示 ' + rows.length + ' 项 · 已选 ' + state.selected.size
    + (selectedVisible !== state.selected.size ? '（当前列表 ' + selectedVisible + '）' : '');
  elements.selectionCount.textContent = '已选 ' + state.selected.size;
  elements.selectAll.checked = rows.length > 0 && rows.every((row) => state.selected.has(row.key));
  elements.selectAll.indeterminate = selectedVisible > 0 && !elements.selectAll.checked;
  document.querySelectorAll('.row-check').forEach((input) => {
    input.addEventListener('change', () => {
      const next = new Set(state.selected);
      if (input.checked) next.add(input.dataset.key);
      else next.delete(input.dataset.key);
      if (!changeSelection(next)) input.checked = state.selected.has(input.dataset.key);
    });
  });
  updateActionState();
  applyColumnVisibility();
}

function renderPlan(plan) {
  state.plan = plan ? { ...plan, selectedKeys: [...(plan.selectedKeys || [])] } : null;
  const items = plan?.items || [];
  elements.planPanel.hidden = !plan;
  if (!plan) {
    elements.planSummary.textContent = '-';
    elements.planVersion.textContent = '';
    elements.planRows.innerHTML = '';
    elements.importButton.disabled = true;
    return;
  }
  const counts = items.reduce((result, item) => {
    const action = effectivePlanAction(item);
    result[action] = (result[action] || 0) + 1;
    return result;
  }, {});
  const supersededSelectionCount = items.filter((item) => (
    item?.selectedSourceSuperseded === true
  )).length;
  elements.planSummary.textContent = '新增 ' + (counts.create || 0) + ' · 更新 ' + (counts.update || 0)
    + ' · 跳过 ' + (counts.skip || 0) + ' · 冲突 ' + (counts.conflict || 0)
    + (supersededSelectionCount ? ' · 旧副本改用最新 ' + supersededSelectionCount : '');
  elements.planVersion.textContent = '快照 ' + String(plan.version || '').slice(0, 12)
    + ' · 选择 ' + state.plan.selectedKeys.length;
  elements.planRows.innerHTML = items.map((item) => {
    const action = effectivePlanAction(item);
    const reason = effectivePlanReason(item);
    const selectedSupersededPaths = Array.isArray(item.selectedSupersededPaths)
      ? item.selectedSupersededPaths.filter(Boolean)
      : [];
    const sourceVersionCount = Math.max(1, finiteNumber(item.sourceVersionCount));
    const actualPath = item.relativePath || item.fileName || item.source || '-';
    const duplicateNote = sourceVersionCount > 1
      ? '<small>同身份 ' + sourceVersionCount + ' 个版本，实际仅使用排序首选版本</small>'
      : '';
    const supersededPathText = selectedSupersededPaths.join('、') || '（旧版本路径未提供）';
    const selectionNote = item.selectedSourceSuperseded === true
      ? '<small class="availability-note" title="' + escapeHtml(supersededPathText)
        + '">已选旧副本 ' + escapeHtml(supersededPathText) + ' → 实际使用 '
        + escapeHtml(actualPath) + '</small>'
      : '';
    return '<tr>'
    + '<td><span class="badge ' + (action === 'conflict' ? 'badge-danger' : action === 'skip' ? 'badge-neutral' : action === 'update' ? 'badge-warning' : 'badge-success') + '">' + escapeHtml(actionLabel(action)) + '</span></td>'
    + '<td>' + escapeHtml(item.accountName || '-') + '</td>'
    + '<td>' + escapeHtml(item.email || '-') + '</td>'
    + '<td><strong>' + escapeHtml(item.source || '-') + '</strong><small title="' + escapeHtml(actualPath)
    + '">实际文件 ' + escapeHtml(actualPath) + '</small>' + duplicateNote + selectionNote + '</td>'
    + '<td><code>' + escapeHtml(formatFingerprint(item.fingerprints?.access)) + '</code></td>'
    + '<td>' + escapeHtml(actionReasonLabel(reason)) + '</td></tr>';
  }).join('');
  updateImportButtonState();
}

function applyFilters() {
  if (!state.snapshot) return;
  const search = elements.searchInput.value.trim().toLowerCase();
  const phoneSearch = /^[+\d\s().-]+$/.test(search) ? search.replace(/[^0-9]/g, '') : '';
  state.rows = state.snapshot.rows.filter((row) => {
    if (elements.statusFilter.value && row.status !== elements.statusFilter.value) return false;
    if (elements.availabilityFilter.value && row.availability !== elements.availabilityFilter.value) return false;
    if (elements.sourceFilter.value && row.source !== elements.sourceFilter.value) return false;
    if (elements.diffFilter.value && row.diffKind !== elements.diffFilter.value) return false;
    if (!search) return true;
    const textMatch = [
      row.accountName,
      row.email,
      row.phone,
      row.chatgptAccountId,
      row.userId,
      row.fileName,
      row.relativePath,
      row.sourceDetails?.email,
      row.sourceDetails?.chatgptAccountId,
      row.sourceDetails?.userId,
      row.sourceDetails?.relativePath,
      row.remoteDetails?.name,
      row.remoteDetails?.email,
      row.remoteDetails?.chatgptAccountId,
      row.remoteDetails?.userId,
      row.remoteDetails?.id,
    ]
      .some((value) => String(value || '').toLowerCase().includes(search));
    const phoneMatch = phoneSearch && String(row.phone || '').replace(/[^0-9]/g, '').includes(phoneSearch);
    return textMatch || Boolean(phoneMatch);
  });
  renderRows();
}

function showNotice(message, kind = 'notice-info') {
  elements.notice.hidden = !message;
  elements.notice.className = 'notice ' + kind;
  elements.notice.textContent = message || '';
}

function jobStatusLabel(status) {
  return {
    queued: '排队中',
    running: '执行中',
    succeeded: '已完成',
    partial: '部分成功',
    failed: '失败',
    interrupted: '已中断',
    unknown: '状态未知',
  }[status] || status || '-';
}

function jobStatusClass(status) {
  if (status === 'succeeded') return 'badge-success';
  if (status === 'partial') return 'badge-warning';
  if (status === 'failed' || status === 'interrupted') return 'badge-danger';
  return 'badge-neutral';
}

function tokenImportResultCounts(result) {
  const items = Array.isArray(result?.imported) ? result.imported : null;
  if (items) {
    const reconciliation = items.filter((item) => item?.requiresReconciliation === true
      || item?.writeOutcomeUnknown === true
      || item?.outcome === 'requires_reconciliation').length;
    const failed = items.filter((item) => Boolean(item?.error)
      && item?.requiresReconciliation !== true
      && item?.writeOutcomeUnknown !== true
      && item?.outcome !== 'requires_reconciliation').length;
    const skipped = items.filter((item) => !item?.error
      && (item?.skipped === true || item?.action === 'skip')).length;
    const notAttempted = Array.isArray(result?.notAttempted)
      ? result.notAttempted.length
      : Math.max(0, finiteNumber(result?.notAttemptedCount));
    return {
      succeeded: Math.max(0, items.length - failed - skipped - reconciliation),
      skipped,
      failed,
      reconciliation,
      notAttempted,
    };
  }
  return {
    succeeded: Math.max(0, finiteNumber(result?.succeeded)),
    skipped: Math.max(0, finiteNumber(result?.runtimeSkipped)),
    failed: Math.max(0, finiteNumber(result?.failed)),
    reconciliation: Math.max(
      0,
      finiteNumber(result?.reconciliationCount),
      result?.requiresReconciliation === true ? 1 : 0,
    ),
    notAttempted: Math.max(0, finiteNumber(result?.notAttemptedCount)),
  };
}

function tokenImportReconciliationReason(result) {
  const item = Array.isArray(result?.imported)
    ? result.imported.find((entry) => entry?.requiresReconciliation === true
      || entry?.writeOutcomeUnknown === true
      || entry?.outcome === 'requires_reconciliation')
    : null;
  const reason = String(item?.reconciliationReason || '').trim().toLowerCase();
  return {
    timeout: '请求超时，远端是否写入未知',
    external_abort: '停机中断请求，远端是否写入未知',
    post_write_abort: '停机中断写后核验',
    transport: '连接中断，远端是否写入未知',
    response_too_large: '响应过大，无法核验写入结果',
    empty_response: '响应为空，无法核验写入结果',
    invalid_json: '响应格式无效，无法核验写入结果',
    response_rejected: '远端拒绝响应，实际写入状态仍需核验',
    response_schema: '响应结构无效，无法核验写入结果',
    response_mismatch: '响应目标不一致，无法核验写入结果',
    update_postflight: '更新后的账号核验失败',
    create_postflight: '新建账号的写后核验失败',
    post_write_verification: '写后核验失败',
    write_outcome_unknown: '写入结果未知',
    unknown: '写入结果未知',
  }[reason] || (reason ? '写入结果未知' : '');
}

function tokenImportNeedsReconciliation(result) {
  return result?.requiresReconciliation === true
    || tokenImportResultCounts(result).reconciliation > 0;
}

function tokenImportReconciliationNotice(result) {
  const counts = tokenImportResultCounts(result);
  const pending = counts.reconciliation > 0
    ? counts.reconciliation + ' 个写入结果'
    : '写入结果';
  const halted = counts.notAttempted > 0 ? '，另有 ' + counts.notAttempted + ' 个账号未执行' : '';
  return 'Token 导入有 ' + pending + '待人工核对' + halted
    + '。请先按账号 ID 和强身份字段核对 Sub2API，确认前不要重复提交。';
}

function tokenImportResultDetail(result) {
  const counts = tokenImportResultCounts(result);
  const parts = [
    '成功 ' + counts.succeeded,
    '跳过 ' + counts.skipped,
    '失败 ' + counts.failed,
  ];
  const requiresReconciliation = tokenImportNeedsReconciliation(result);
  if (requiresReconciliation) parts.push('待人工核对 ' + counts.reconciliation);
  if (counts.notAttempted > 0) parts.push('未执行 ' + counts.notAttempted);
  if (requiresReconciliation) {
    parts.push('已停止后续写入');
    const reason = tokenImportReconciliationReason(result);
    if (reason) parts.push('原因：' + reason);
  }
  return parts.join(' · ');
}

function accountTestItemNeedsReconciliation(item) {
  return item?.requiresReconciliation === true
    || item?.code === 'account_test_reconciliation_required'
    || item?.code === 'account_scheduler_reconciliation_required';
}

function accountTestItemNotAttempted(item) {
  return item?.outcome === 'not_attempted'
    || item?.code === 'account_test_not_attempted_reconciliation';
}

function accountTestResultCounts(result) {
  const items = Array.isArray(result?.results) ? result.results : null;
  if (items) {
    const counts = {
      succeeded: 0,
      failed: 0,
      skipped: 0,
      reconciliation: 0,
      notAttempted: 0,
    };
    for (const item of items) {
      if (accountTestItemNeedsReconciliation(item)) counts.reconciliation += 1;
      else if (accountTestItemNotAttempted(item)) counts.notAttempted += 1;
      else if (item?.status === 'succeeded') counts.succeeded += 1;
      else if (item?.status === 'failed') counts.failed += 1;
      else if (item?.status === 'skipped') counts.skipped += 1;
    }
    return counts;
  }
  const reconciliation = Math.max(
    0,
    Math.trunc(finiteNumber(result?.reconciliationCount)),
    result?.requiresReconciliation === true ? 1 : 0,
  );
  const notAttempted = Math.max(0, Math.trunc(finiteNumber(result?.notAttemptedCount)));
  return {
    succeeded: Math.max(0, Math.trunc(finiteNumber(result?.succeeded))),
    failed: Math.max(0, Math.trunc(finiteNumber(result?.failed)) - reconciliation),
    skipped: Math.max(0, Math.trunc(finiteNumber(result?.skipped)) - notAttempted),
    reconciliation,
    notAttempted,
  };
}

function accountTestNeedsReconciliation(result) {
  return result?.requiresReconciliation === true
    || accountTestResultCounts(result).reconciliation > 0;
}

function accountTestScopeLabel(scope) {
  return {
    test: '账号测试与状态恢复',
    scheduler: '调度写入与回滚',
  }[String(scope || '').trim().toLowerCase()] || '账号状态核验';
}

function accountTestReasonLabel(reason) {
  return {
    external_abort: '停机中断后结果无法确认',
    timeout: '请求超时，结果无法确认',
    transport: '连接中断，结果无法确认',
    response_too_large: '响应过大，无法确认结果',
    empty_response: '响应为空，无法确认结果',
    invalid_json: '响应格式无效，无法确认结果',
    request_validation: '请求校验失败，结果无法确认',
    response_rejected: '远端拒绝响应，结果仍需核对',
    invalid_terminal: '远端返回了矛盾的终态',
    missing_terminal: '远端未返回可确认的终态',
    model_mismatch: '返回模型与请求模型不一致',
    post_test_interrupted: '测试后状态恢复流程被中断',
    post_test_target_changed: '测试后账号强身份发生变化',
    account_test_state_unknown: '测试后账号状态无法确认',
    scheduler_write_unknown: '调度写入结果无法确认',
    enable_response_mismatch: '启用调度响应与目标不一致',
    rollback_state_unavailable: '回滚前账号状态无法读取',
    rollback_state_changed: '回滚前账号状态已被修改',
    rollback_response_mismatch: '回滚响应与目标不一致',
    rollback_verification_mismatch: '回滚后的状态核验不一致',
    rollback_failed: '调度回滚结果无法确认',
    response_schema: '调度响应结构无效',
    response_mismatch: '调度响应与请求不一致',
    post_write_verification: '调度写后核验失败',
  }[String(reason || '').trim().toLowerCase()] || '结果无法安全确认';
}

function accountTestReconciliationFacts(results) {
  const items = (results || []).flatMap((result) => (
    Array.isArray(result?.results)
      ? result.results.filter(accountTestItemNeedsReconciliation)
      : []
  ));
  const ids = [...new Set(items.map((item) => Number(item?.accountId)).filter((id) => (
    Number.isSafeInteger(id) && id > 0
  )))];
  const scopes = [...new Set(items.map((item) => accountTestScopeLabel(item?.reconciliationScope)))];
  const reasons = [...new Set(items.map((item) => accountTestReasonLabel(item?.reconciliationReason)))];
  return {
    ids,
    scopes,
    reasons,
    schedulerUnknown: items.length === 0 || items.some((item) => (
      item?.enabledKnown !== true || typeof item?.enabled !== 'boolean'
    )),
  };
}

function accountTestIdsLabel(ids) {
  if (!ids?.length) return '';
  const visible = ids.slice(0, 5).map((id) => '#' + id).join('、');
  return '账号 ID ' + visible + (ids.length > 5 ? ' 等 ' + ids.length + ' 个' : '');
}

function accountTestResultsDetail(results) {
  const counts = (results || []).map(accountTestResultCounts).reduce((total, current) => {
    for (const key of Object.keys(total)) total[key] += current[key] || 0;
    return total;
  }, { succeeded: 0, failed: 0, skipped: 0, reconciliation: 0, notAttempted: 0 });
  const parts = [
    '成功 ' + counts.succeeded,
    '失败 ' + counts.failed,
    '跳过 ' + counts.skipped,
  ];
  if (counts.reconciliation > 0) parts.push('待人工核对 ' + counts.reconciliation);
  if (counts.notAttempted > 0) parts.push('未执行 ' + counts.notAttempted);
  if (counts.reconciliation > 0) {
    const facts = accountTestReconciliationFacts(results);
    const ids = accountTestIdsLabel(facts.ids);
    if (ids) parts.push(ids);
    if (facts.scopes.length) parts.push('范围：' + facts.scopes.join('、'));
    if (facts.schedulerUnknown) parts.push('调度状态未知');
    if (facts.reasons.length) parts.push('原因：' + facts.reasons.join('、'));
    parts.push('已停止后续测试，确认前勿重试');
  }
  return parts.join(' · ');
}

function accountTestReconciliationNotice(results) {
  const counts = (results || []).map(accountTestResultCounts).reduce((total, current) => ({
    reconciliation: total.reconciliation + current.reconciliation,
    notAttempted: total.notAttempted + current.notAttempted,
  }), { reconciliation: 0, notAttempted: 0 });
  const facts = accountTestReconciliationFacts(results);
  const ids = accountTestIdsLabel(facts.ids);
  const scope = facts.scopes.length ? '，核对范围：' + facts.scopes.join('、') : '';
  const reason = facts.reasons.length ? '，原因：' + facts.reasons.join('、') : '';
  const halted = counts.notAttempted > 0 ? '，另有 ' + counts.notAttempted + ' 个账号未执行' : '';
  return '账号测试有 ' + Math.max(1, counts.reconciliation) + ' 个账号待人工核对'
    + halted + (ids ? '，涉及' + ids : '') + scope + reason
    + '。调度状态未知；请先按账号 ID 和强身份字段核对 Sub2API，确认前不要重复测试。';
}

function jobNeedsReconciliation(job) {
  if (Array.isArray(job?.jobs)) return job.jobs.some(jobNeedsReconciliation);
  if (job?.result?.reconciliationResolved === true
      && job?.result?.reconciliationHold === false) return false;
  if (job?.type === 'token_import') return tokenImportNeedsReconciliation(job.result);
  if (job?.type === 'account_test') return accountTestNeedsReconciliation(job.result);
  return job?.result?.requiresReconciliation === true;
}

function reconciliationNoticeForJobs(jobs) {
  const list = Array.isArray(jobs) ? jobs : [];
  const notices = [];
  const accountResults = list.filter((job) => (
    job?.type === 'account_test' && accountTestNeedsReconciliation(job.result)
  )).map((job) => job.result);
  if (accountResults.length) notices.push(accountTestReconciliationNotice(accountResults));
  const tokenJobs = list.filter((job) => (
    job?.type === 'token_import' && tokenImportNeedsReconciliation(job.result)
  ));
  if (tokenJobs.length === 1) notices.push(tokenImportReconciliationNotice(tokenJobs[0].result));
  else if (tokenJobs.length > 1) {
    const totals = tokenJobs.map((job) => tokenImportResultCounts(job.result)).reduce((total, current) => ({
      reconciliation: total.reconciliation + current.reconciliation,
      notAttempted: total.notAttempted + current.notAttempted,
    }), { reconciliation: 0, notAttempted: 0 });
    notices.push('Token 导入有 ' + Math.max(1, totals.reconciliation) + ' 个写入结果待人工核对'
      + (totals.notAttempted ? '，另有 ' + totals.notAttempted + ' 个账号未执行' : '')
      + '。请先按账号 ID 和强身份字段核对 Sub2API，确认前不要重复提交。');
  }
  const genericJobs = list.filter((job) => (
    jobNeedsReconciliation(job)
      && job?.type !== 'token_import'
      && job?.type !== 'account_test'
  ));
  if (genericJobs.length) {
    notices.push('有 ' + genericJobs.length + ' 个任务的执行结果待人工核对。'
      + '面板不会自动确认实际状态，核对完成前请勿重试。');
  }
  const hasHold = list.some((job) => job?.result?.reconciliationHold === true);
  if (hasHold) notices.push('当前安全策略会保守阻止全部新写操作，直到所有持久 hold 均完成人工核对。');
  return notices.join(' ');
}

function reconciliationHoldJobs(job) {
  const jobs = Array.isArray(job?.jobs) ? job.jobs : (job ? [job] : []);
  return jobs.filter((item) => (
    terminalJob(item?.status)
      && item?.result?.requiresReconciliation === true
      && item?.result?.reconciliationHold === true
      && item?.result?.reconciliationResolved !== true
      && /^job_[a-f0-9]{24}$/.test(String(item?.id || ''))
      && /^[a-f0-9]{64}$/.test(String(item?.result?.reconciliationClaimDigest || ''))
  ));
}

function reconciliationHoldTarget(job = state.job) {
  return reconciliationHoldJobs(job)[0] || null;
}

function renderReconciliationAction(job) {
  const button = elements.reconciliationAckButton;
  if (!button) return;
  const heldJobs = reconciliationHoldJobs(job);
  const target = heldJobs[0] || null;
  button.hidden = !target;
  button.disabled = !target || state.reconciliationAckPending || Boolean(state.snapshot?.readOnly);
  const knownHeldCount = Math.max(heldJobs.length, Number(state.reconciliationHolds?.total) || 0);
  button.textContent = knownHeldCount > 1
    ? '逐项人工核对（待处理 ' + knownHeldCount + '）'
    : '人工核对并解除阻挡';
  button.title = state.snapshot?.readOnly
    ? '当前面板为只读模式，无法解除持久阻挡'
    : '仅在外部人工核对完成后使用；面板不会自动核对';
}

function renderJob(job) {
  if (!job) {
    elements.jobPanel.hidden = true;
    if (typeof renderReconciliationAction === 'function') renderReconciliationAction(null);
    return;
  }
  elements.jobPanel.hidden = false;
  const jobs = Array.isArray(job.jobs) ? job.jobs : [job];
  const reconciliationJobs = jobs.filter(jobNeedsReconciliation);
  const needsReconciliation = reconciliationJobs.length > 0;
  if (typeof renderReconciliationAction === 'function') renderReconciliationAction(job);
  elements.jobPanel.dataset.status = needsReconciliation ? 'partial' : (job.status || '');
  const isPhase3 = jobs.every((item) => item.type === 'phase3');
  const isAccountTest = jobs.every((item) => item.type === 'account_test');
  elements.jobTitle.textContent = isAccountTest
    ? (jobs.length > 1 ? '上游账号批量测试' : '上游账号测试')
    : isPhase3
    ? (jobs.length > 1 ? 'Phase 3 批量任务' : 'Phase 3 任务')
    : (jobs.length > 1 ? '批量任务' : 'Token 导入任务');
  elements.jobStatus.className = 'badge '
    + (needsReconciliation ? 'badge-warning' : jobStatusClass(job.status));
  elements.jobStatus.textContent = needsReconciliation
    ? '待人工核对'
    : jobStatusLabel(job.status);
  if (jobs.length > 1) {
    const terminalCount = jobs.filter((item) => ['succeeded', 'partial', 'failed', 'interrupted'].includes(item.status)).length;
    const failedCount = jobs.filter((item) => ['failed', 'interrupted', 'partial'].includes(item.status)).length;
    const activeCount = jobs.length - terminalCount;
    const baseDetail = '完成 ' + terminalCount + '/' + jobs.length
      + ' · 失败/部分 ' + failedCount
      + (activeCount ? ' · 进行中 ' + activeCount : '')
      + ' · 最近任务 ' + String(jobs[jobs.length - 1].id || '').slice(0, 16);
    const accountResults = reconciliationJobs.filter((item) => item.type === 'account_test')
      .map((item) => item.result);
    elements.jobMeta.textContent = isAccountTest && accountResults.length
      ? accountTestResultsDetail(jobs.map((item) => item.result)) + ' · ' + baseDetail
      : baseDetail + (needsReconciliation ? ' · 存在待人工核对结果，确认前勿重试' : '');
    return;
  }
  let detail = needsReconciliation && job.type === 'account_test'
    ? accountTestResultsDetail([job.result])
    : job.error;
  if (!detail && job.result) {
    if (job.type === 'account_test') {
      detail = '测试成功 ' + (job.result.succeeded || 0)
        + ' · 失败 ' + (job.result.failed || 0)
        + ' · 跳过 ' + (job.result.skipped || 0);
    } else if (job.type === 'token_import') {
      detail = tokenImportResultDetail(job.result);
    } else if (job.type === 'phase3') {
      detail = needsReconciliation
        ? 'Phase 3 执行结果未知；请按账号 ID 和强身份字段人工核对，确认前勿重试'
        : 'Phase 3 已完成并检测到 token 更新';
    } else {
      detail = '成功 ' + (job.result.imported?.length || 0) + ' · 失败 ' + (job.result.failed || 0);
    }
  }
  if (!detail) detail = '任务编号 ' + job.id;
  elements.jobMeta.textContent = detail + ' · ' + formatDate(job.finishedAt || job.startedAt || job.createdAt);
}

function setReconciliationDialogError(message) {
  if (!elements.reconciliationAckError) return;
  elements.reconciliationAckError.hidden = !message;
  elements.reconciliationAckError.textContent = message || '';
}

function setReconciliationDialogPending(pending) {
  for (const element of [
    elements.reconciliationAckResolution,
    elements.reconciliationAckConfirmation,
    elements.reconciliationAckCancel,
    elements.reconciliationAckConfirm,
  ]) {
    if (element) element.disabled = Boolean(pending);
  }
}

function openReconciliationDialog() {
  const target = reconciliationHoldTarget();
  const dialog = elements.reconciliationAckDialog;
  if (!target || !dialog || typeof dialog.showModal !== 'function') {
    showNotice('无法打开人工核对确认框，持久阻挡未变更。', 'notice-danger');
    return;
  }
  state.reconciliationAckTarget = {
    id: target.id,
    digest: target.result.reconciliationClaimDigest,
  };
  if (elements.reconciliationAckJobId) elements.reconciliationAckJobId.textContent = target.id;
  if (elements.reconciliationAckScope) {
    elements.reconciliationAckScope.textContent = target.result.reconciliationHoldScope === 'all_future_jobs'
      ? '全部新写操作（旧版任务无法还原原保护键）'
      : '当前键已保留；安全策略阻止全部新写操作';
  }
  if (elements.reconciliationAckDigest) {
    elements.reconciliationAckDigest.textContent = target.result.reconciliationClaimDigest;
  }
  if (elements.reconciliationAckResolution) elements.reconciliationAckResolution.value = '';
  if (elements.reconciliationAckConfirmation) elements.reconciliationAckConfirmation.value = '';
  setReconciliationDialogError('');
  setReconciliationDialogPending(false);
  try {
    dialog.returnValue = '';
    dialog.showModal();
    elements.reconciliationAckResolution?.focus();
  } catch {
    state.reconciliationAckTarget = null;
    showNotice('无法打开人工核对确认框，持久阻挡未变更。', 'notice-danger');
  }
}

async function submitReconciliationAcknowledgement(event) {
  event.preventDefault();
  const submitterValue = String(event.submitter?.value || '');
  if (submitterValue !== 'confirm') {
    if (!state.reconciliationAckPending) elements.reconciliationAckDialog?.close('cancel');
    return;
  }
  if (state.reconciliationAckPending) return;
  const target = state.reconciliationAckTarget;
  const current = reconciliationHoldJobs(state.job).find((job) => (
    job.id === target?.id && job.result.reconciliationClaimDigest === target?.digest
  ));
  if (!current) {
    setReconciliationDialogError('任务或保护键摘要已变化，请关闭后刷新。');
    return;
  }
  const resolution = String(elements.reconciliationAckResolution?.value || '');
  const confirmation = String(elements.reconciliationAckConfirmation?.value || '');
  if (!RECONCILIATION_ACK_RESOLUTIONS.has(resolution)) {
    setReconciliationDialogError('请选择与人工核对结果完全一致的结论。');
    return;
  }
  if (confirmation !== RECONCILIATION_ACK_CONFIRMATION) {
    setReconciliationDialogError('二次确认语不正确，持久阻挡未变更。');
    return;
  }
  if (!window.confirm('最后确认：你已在对应系统中人工核对实际状态。面板不会自动验证此结论，是否解除该任务对未来操作的阻挡？')) return;

  state.reconciliationAckPending = true;
  setReconciliationDialogError('');
  setReconciliationDialogPending(true);
  updateActionState();
  try {
    const response = await apiFetch(
      '/api/jobs/' + encodeURIComponent(target.id) + '/reconciliation/acknowledge',
      {
        method: 'POST',
        body: JSON.stringify({
          jobId: target.id,
          confirmation,
          resolution,
          claimDigest: target.digest,
        }),
      },
    );
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error || '人工对账确认失败');
    elements.reconciliationAckDialog?.close('acknowledged');
    state.reconciliationAckTarget = null;
    await resumeActiveJob();
    if (state.job && jobNeedsReconciliation(state.job)) {
      showNotice('已解除任务 ' + target.id + ' 的未来操作阻挡；原任务仍不可重试。'
        + reconciliationNoticeForJobs(Array.isArray(state.job.jobs) ? state.job.jobs : [state.job]), 'notice-warning');
    } else {
      showNotice('已记录人工核对结论并解除该任务对未来操作的阻挡；原任务仍不可重试。', 'notice-info');
    }
  } catch (error) {
    setReconciliationDialogError(error.message || '人工对账确认失败；持久阻挡未变更。');
    showNotice(error.message || '人工对账确认失败。', 'notice-danger');
  } finally {
    state.reconciliationAckPending = false;
    setReconciliationDialogPending(false);
    renderReconciliationAction(state.job);
    updateActionState();
  }
}

function stopJobPolling() {
  if (state.jobPollTimer) window.clearTimeout(state.jobPollTimer);
  state.jobPollTimer = null;
}

function aggregateJobs(jobs) {
  const list = Array.isArray(jobs) ? jobs.filter(Boolean) : [];
  if (list.length === 0) return null;
  if (list.length === 1) return list[0];
  const terminal = list.every((job) => ['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status));
  let status = 'queued';
  if (!terminal) status = list.some((job) => job.status === 'running') ? 'running' : 'queued';
  else if (list.every((job) => job.status === 'succeeded')) status = 'succeeded';
  else if (list.some((job) => job.status === 'succeeded' || job.status === 'partial')) status = 'partial';
  else if (list.some((job) => job.status === 'interrupted')) status = 'interrupted';
  else status = 'failed';
  return {
    id: list.map((job) => job.id).join(','),
    type: list.every((job) => job.type === 'phase3') ? 'phase3' : 'batch',
    status,
    jobs: list,
    batch: true,
  };
}

function terminalJob(status) {
  return ['succeeded', 'partial', 'failed', 'interrupted'].includes(status);
}

function jobPollFailureState(attempt) {
  const safeAttempt = Math.max(0, Number(attempt) || 0);
  if (safeAttempt < 6) {
    return {
      unknown: false,
      nextAttempt: safeAttempt + 1,
      delayMs: Math.min(5000, 1000 * (safeAttempt + 1)),
    };
  }
  return { unknown: true, nextAttempt: 0, delayMs: 15000 };
}

async function watchJobs(jobIds, initialType = 'phase3') {
  const ids = [...new Set((jobIds || []).filter(Boolean).map(String))];
  if (ids.length === 0) return;
  stopJobPolling();
  state.watchIds = ids;
  state.jobs = ids.map((id) => ({ id, status: 'queued', type: initialType }));
  state.job = aggregateJobs(state.jobs);
  renderJob(state.job);
  const poll = async (attempt = 0) => {
    try {
      const loaded = await Promise.all(ids.map(async (jobId) => {
        const response = await apiFetch('/api/jobs/' + encodeURIComponent(jobId));
        const body = await response.json();
        if (!response.ok) throw new Error(body.message || body.error || '任务状态读取失败');
        return body;
      }));
      if (!state.watchIds || state.watchIds.join(',') !== ids.join(',')) return;
      state.jobs = loaded;
      state.job = aggregateJobs(loaded);
      renderJob(state.job);
      if (loaded.every((job) => terminalJob(job.status))) {
        stopJobPolling();
        let terminalNotice;
        let terminalNoticeKind;
        const reconciliationJobs = loaded.filter(jobNeedsReconciliation);
        if (reconciliationJobs.length) {
          terminalNotice = reconciliationNoticeForJobs(reconciliationJobs);
          terminalNoticeKind = 'notice-warning';
        } else if (loaded.every((job) => job.status === 'succeeded')) {
          terminalNotice = '任务已完成，账号状态已刷新。';
          terminalNoticeKind = 'notice-info';
        } else if (loaded.some((job) => job.status === 'succeeded' || job.status === 'partial')) {
          terminalNotice = '任务部分成功，账号状态已刷新，请查看任务详情和日志。';
          terminalNoticeKind = 'notice-warning';
        } else {
          terminalNotice = loaded.find((job) => job.error)?.error || '任务未完成，请查看日志。';
          terminalNoticeKind = 'notice-danger';
        }
        // Even a failed/interrupted operation may have created a Phase3 token,
        // changed an account disposition, or partially restored test state.
        // Always refresh before showing the final outcome, and show the notice
        // afterwards because loadSnapshot intentionally clears stale notices.
        renderPlan(null);
        state.snapshotRefreshPending = true;
        updateActionState();
        const snapshotRefreshed = await loadSnapshot();
        if (!snapshotRefreshed) {
          showNotice('任务已结束，但账号快照刷新失败；为避免基于陈旧状态重复操作，已保持操作锁定并将在后台重试。', 'notice-warning');
          state.jobPollTimer = window.setTimeout(() => poll(0), 5000);
          return;
        }
        state.snapshotRefreshPending = false;
        showNotice(terminalNotice, terminalNoticeKind);
        if (loaded.some((job) => job.type === 'token_import')) state.importRequestPending = false;
        if (loaded.some((job) => job.type === 'phase3')) state.phase3RequestPending = false;
        if (loaded.some((job) => job.type === 'account_test')) state.accountTestRequestPending = false;
        renderPlan(state.plan);
        updateActionState();
        return;
      }
      state.jobPollTimer = window.setTimeout(() => poll(0), 1200);
    } catch (error) {
      if (!state.watchIds || state.watchIds.join(',') !== ids.join(',')) return;
      const failureState = jobPollFailureState(attempt);
      if (!failureState.unknown) {
        elements.jobMeta.textContent = '任务状态暂时不可读，正在重试（'
          + String(failureState.nextAttempt) + '/6）';
        state.jobPollTimer = window.setTimeout(
          () => poll(failureState.nextAttempt),
          failureState.delayMs,
        );
        return;
      }
      // A polling failure says nothing about the worker outcome. Keep action
      // locks in place and continue at a lower frequency so the UI cannot
      // mislabel a live task as failed or invite a duplicate submission.
      renderJob({
        ...state.job,
        status: 'unknown',
        error: '任务状态暂时无法确认，后台任务仍可能执行',
        jobs: state.jobs,
      });
      showNotice('任务状态暂时无法确认；已保持操作锁定，并将在后台继续检查。', 'notice-warning');
      state.jobPollTimer = window.setTimeout(() => poll(failureState.nextAttempt), failureState.delayMs);
    }
  };
  await poll();
}

async function watchJob(jobId, type = 'phase3') {
  return watchJobs([jobId], type);
}

async function resumeActiveJob() {
  // Until the initial list request succeeds, absence of a rendered task is not
  // evidence that no worker is active. Lock mutations before yielding to I/O.
  state.jobs = [];
  state.job = {
    id: 'resume-probe',
    type: 'batch',
    status: 'unknown',
    error: '正在确认后台任务状态',
    resumeProbe: true,
  };
  renderJob(state.job);
  updateActionState();
  try {
    const response = await apiFetch('/api/jobs?limit=200');
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error || '任务列表读取失败');
    const listedJobs = Array.isArray(body.jobs) ? body.jobs : [];
    const holdListing = body.reconciliationHolds && typeof body.reconciliationHolds === 'object'
      ? body.reconciliationHolds
      : { total: listedJobs.filter((job) => job?.result?.reconciliationHold === true).length,
          returned: listedJobs.filter((job) => job?.result?.reconciliationHold === true).length,
          truncated: false };
    state.reconciliationHolds = {
      total: Math.max(0, Number(holdListing.total) || 0),
      returned: Math.max(0, Number(holdListing.returned) || 0),
      truncated: holdListing.truncated === true,
    };
    const activeJobs = listedJobs.filter((job) => ['queued', 'running'].includes(job.status));
    if (!activeJobs.length) {
      if (state.job?.resumeProbe) {
        const recentReconciliation = listedJobs.find((job) => (
          terminalJob(job?.status) && jobNeedsReconciliation(job)
        ));
        state.jobs = recentReconciliation ? [recentReconciliation] : [];
        state.job = recentReconciliation || null;
        renderJob(state.job);
        if (recentReconciliation) {
          showNotice(reconciliationNoticeForJobs([recentReconciliation])
            + (state.reconciliationHolds.truncated
              ? '待核对任务超过单次响应上限，当前显示 '
                + state.reconciliationHolds.returned + '/' + state.reconciliationHolds.total
                + ' 个；请逐项处理并刷新，不得将未显示项视为已解除。'
              : ''), 'notice-warning');
        }
        updateActionState();
      }
      return;
    }
    if (activeJobs.some((job) => job.type === 'phase3')) state.phase3RequestPending = true;
    if (activeJobs.some((job) => job.type === 'token_import')) state.importRequestPending = true;
    if (activeJobs.some((job) => job.type === 'account_test')) state.accountTestRequestPending = true;
    state.jobs = activeJobs;
    state.job = aggregateJobs(activeJobs);
    renderJob(state.job);
    updateActionState();
    await watchJobs(activeJobs.map((job) => job.id), activeJobs.length === 1 ? activeJobs[0].type : 'batch');
    if (state.reconciliationHolds.total > 0 && !activeJobPending()) await resumeActiveJob();
  } catch (error) {
    // A task can still run even when the optional resume request is not
    // available. Treat the initial state as unknown and keep all mutations
    // locked until a later list request proves there is no active task.
    state.job = {
      ...state.job,
      id: 'resume-probe',
      type: 'batch',
      status: 'unknown',
      error: '任务状态恢复失败，后台仍可能有任务执行',
      resumeProbe: true,
    };
    renderJob(state.job);
    updateActionState();
    showNotice('任务状态恢复失败：' + error.message + '。已保持操作锁定，并将在后台重试。', 'notice-warning');
    state.jobPollTimer = window.setTimeout(() => resumeActiveJob(), 15000);
  }
}

async function loadSnapshot(options = {}) {
  const requestId = ++state.snapshotRequestSequence;
  state.snapshotRequestsPending += 1;
  if (options.resumeJobs) state.resumeJobsPending = true;
  let loaded = false;
  elements.loadingLabel.hidden = false;
  elements.refreshButton.disabled = true;
  updateActionState();
  try {
    const query = new URLSearchParams({ withSub2api: '1' });
    if (elements.historicalToggle?.checked) query.set('includeHistorical', '1');
    const response = await apiFetch('/api/snapshot?' + query.toString());
    const snapshot = await response.json();
    if (requestId !== state.snapshotRequestSequence) return false;
    if (!response.ok) throw new Error(snapshot.message || snapshot.error || '读取失败');
    state.snapshot = snapshot;
    // A stable row key does not prove that the file at that path still belongs
    // to the same account. Never carry a selection across snapshot versions.
    state.selected = new Set();
    state.selectionRevision += 1;
    renderPlan(null);
    renderMetrics(snapshot);
    renderSelectOptions(elements.statusFilter, snapshot.filters.statuses, {}, '全部状态');
    renderSelectOptions(elements.availabilityFilter, snapshot.filters.availabilities, {
      available: '可用',
      unavailable: '不可用',
      unknown: '未知',
      not_present: '未导入 Sub2API',
    }, '全部');
    renderSelectOptions(elements.diffFilter, snapshot.filters.diffKinds, {
      in_sync: '一致',
      token_only: '仅文件',
      remote_unknown: '远端未知',
      sub2api_only: '仅 Sub2API',
      token_changed: 'Token 不同',
      expired: '已过期',
      expiry_invalid: '过期时间无效',
      invalid_file: '文件异常',
      duplicate_identity: '身份重复',
      mapping_conflict: '身份冲突',
      historical_backup: '历史备份',
      missing_refresh_token: '缺少续期',
    }, '全部差异');
    const readStatus = sub2ApiReadStatus(snapshot);
    if (readStatus === 'failed') {
      showNotice('Sub2API 管理 API 暂未连接：' + snapshot.sub2api.apiError + '。当前仍显示 gpt_register 文件来源，但无法比较或同步。', 'notice-warning');
    } else if (readStatus === 'omitted') {
      showNotice('本次未读取 Sub2API；当前仅显示 gpt_register 文件事实，无法比较或同步。', 'notice-warning');
    } else if (snapshot.sub2api.statsError) {
      showNotice('账号已读取，但统计接口暂不可用：' + snapshot.sub2api.statsError, 'notice-warning');
    } else if (state.job && jobNeedsReconciliation(state.job)) {
      const jobs = Array.isArray(state.job.jobs) ? state.job.jobs : [state.job];
      showNotice(reconciliationNoticeForJobs(jobs.filter(jobNeedsReconciliation)), 'notice-warning');
    } else if (!state.job || ['succeeded', 'partial', 'failed', 'interrupted'].includes(state.job.status)) {
      showNotice('', '');
    }
    applyFilters();
    void loadAccountTestModels(snapshot);
    loaded = true;
    if (requestId === state.snapshotRequestSequence && state.resumeJobsPending) {
      state.resumeJobsPending = false;
      await resumeActiveJob();
    }
  } catch (error) {
    if (requestId === state.snapshotRequestSequence) showNotice(error.message, 'notice-danger');
  } finally {
    state.snapshotRequestsPending = Math.max(0, state.snapshotRequestsPending - 1);
    elements.loadingLabel.hidden = state.snapshotRequestsPending === 0;
    elements.refreshButton.disabled = state.snapshotRequestsPending > 0;
    updateActionState();
  }
  return loaded;
}

elements.refreshButton.addEventListener('click', loadSnapshot);
async function previewSelection() {
  if (state.previewRequestPending) return;
  if (!comparisonAvailable()) {
    showNotice('Sub2API 账号尚未成功读取，无法检查同步差异。', 'notice-warning');
    return;
  }
  state.previewRequestPending = true;
  const selectedKeys = [...state.selected];
  const selectionRevision = state.selectionRevision;
  // Do not leave an older plan importable if this request later proves stale.
  renderPlan(null);
  updateActionState();
  try {
    const response = await apiFetch('/api/sync/preview', {
      method: 'POST',
      body: JSON.stringify({ selectedKeys }),
    });
    const body = await response.json();
    if (!selectionStillCurrent(selectionRevision, selectedKeys)) return false;
    if (!response.ok) throw new Error(body.message || body.error || '差异检查失败');
    renderPlan({ ...body, selectedKeys });
    const supersededSelectionCount = (body.items || []).filter((item) => (
      item?.selectedSourceSuperseded === true
    )).length;
    showNotice(supersededSelectionCount
      ? '差异预览已生成：有 ' + supersededSelectionCount + ' 个所选旧副本将按有效性与新鲜度规则改用首选版本，请核对“实际文件”后再确认。'
      : selectedKeys.length
        ? '差异预览已生成，确认前仍会重新检查来源版本。'
        : '已生成全部差异预览；如需导入，请先选择账号后重新检查。',
    supersededSelectionCount ? 'notice-warning' : 'notice-info');
    return true;
  } catch (error) {
    if (selectionStillCurrent(selectionRevision, selectedKeys)) {
      showNotice(error.message, 'notice-danger');
    }
    return false;
  } finally {
    state.previewRequestPending = false;
    updateActionState();
  }
}

elements.previewButton.addEventListener('click', previewSelection);

elements.importButton.addEventListener('click', async () => {
  if (!state.plan || state.importRequestPending) return;
  if (!comparisonAvailable()) {
    showNotice('Sub2API 账号尚未成功读取，无法执行同步导入。', 'notice-warning');
    return;
  }
  const selectedKeys = [...state.plan.selectedKeys];
  if (!selectedKeys.length) {
    showNotice('导入前请先选择账号并重新检查差异。', 'notice-warning');
    return;
  }
  const supersededSelectionCount = (state.plan.items || []).filter((item) => (
    item?.selectedSourceSuperseded === true
  )).length;
  const replacementWarning = supersededSelectionCount
    ? '其中 ' + supersededSelectionCount + ' 个所选旧副本将改用预览所示的排序首选版本。\n'
    : '';
  if (!window.confirm(replacementWarning + '确认将预览中的新增/更新写入 Sub2API？')) return;
  state.importRequestPending = true;
  updateActionState();
  try {
    const response = await apiFetch('/api/sync/import', {
      method: 'POST',
      body: JSON.stringify({ snapshotVersion: state.plan.version, selectedKeys }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error || '导入任务创建失败');
    showNotice('导入任务已排队，正在等待执行结果。', 'notice-info');
    await watchJob(body.jobId, 'token_import');
  } catch (error) {
    state.importRequestPending = false;
    showNotice(error.message, 'notice-danger');
    renderPlan(state.plan);
    updateActionState();
  }
});

elements.phase3Button.addEventListener('click', async () => {
  if (state.phase3RequestPending) return;
  const selectedRows = selectedRowsFromSelection();
  const targets = phase3TargetsFromRows(selectedRows);
  const selectionProblem = phase3SelectionProblem(selectedRows, state.selected.size);
  if (selectionProblem || targets.length === 0) {
    showNotice('无法提交 Phase 3：' + (selectionProblem || '没有符合条件的账号'), 'notice-warning');
    return;
  }
  if (!window.confirm('确认排队更新已选的 ' + targets.length + ' 个账号 token？任务会按顺序执行。')) return;
  state.phase3RequestPending = true;
  updateActionState();
  try {
    const response = await apiFetch('/api/phase3', {
      method: 'POST',
      body: JSON.stringify({ accounts: targets, selectedKeys: [...state.selected] }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error || 'Phase 3 任务创建失败');
    const jobIds = Array.isArray(body.jobIds) ? body.jobIds : (body.jobId ? [body.jobId] : []);
    if (!jobIds.length) throw new Error('Phase 3 未返回任务编号');
    const rejectedCount = Array.isArray(body.rejected) ? body.rejected.length : 0;
    showNotice('Phase 3 已排队 ' + jobIds.length + ' 个任务'
      + (rejectedCount ? '，拒绝 ' + rejectedCount + ' 个重复或不符合条件的账号' : '') + '，正在等待执行结果。', 'notice-info');
    await watchJobs(jobIds);
  } catch (error) {
    state.phase3RequestPending = false;
    showNotice(error.message, 'notice-danger');
    updateActionState();
  }
});

if (elements.accountTestButton) {
  elements.accountTestButton.addEventListener('click', async () => {
    if (state.accountTestRequestPending) return;
    const selectedRows = selectedRowsFromSelection();
    const targets = accountTestRows(selectedRows);
    const invalidSelectedRow = selectedRows.some((row) => (
      !Number.isSafeInteger(Number(row?.accountId)) || Number(row.accountId) <= 0
    ));
    if (state.selected.size === 0 || selectedRows.length !== state.selected.size || invalidSelectedRow || targets.length === 0) {
      showNotice('请只选择已导入 Sub2API 的上游账号后再测试。', 'notice-warning');
      return;
    }
    const modelId = normalizeAccountTestModel(elements.accountTestModelSelect?.value);
    if (!modelId) {
      showNotice('请选择测试模型。', 'notice-warning');
      return;
    }
    if (!window.confirm('确认使用 ' + accountTestModelLabel(modelId) + ' 测试已选的 ' + targets.length + ' 个上游账号？error 账号成功后会恢复并启用，其他账号只测试不修改调度设置。')) return;
    state.accountTestRequestPending = true;
    updateActionState();
    try {
      const response = await apiFetch('/api/account-tests', {
        method: 'POST',
        body: JSON.stringify({
          accountIds: targets.map((row) => Number(row.accountId)),
          modelId,
        }),
      });
      const body = await response.json();
      if (!response.ok) {
        const rejected = Array.isArray(body.rejected) ? body.rejected.length : 0;
        throw new Error(body.message || body.error || (rejected ? '没有可测试的上游账号' : '账号测试任务创建失败'));
      }
      const rejectedCount = Array.isArray(body.rejected) ? body.rejected.length : 0;
      showNotice('账号测试已排队 ' + (body.accountIds?.length || targets.length) + ' 个账号'
        + (rejectedCount ? '，拒绝 ' + rejectedCount + ' 个已在执行、不存在或状态无法安全确认的账号' : '')
        + '，正在等待结果。', 'notice-info');
      await watchJob(body.jobId, 'account_test');
    } catch (error) {
      state.accountTestRequestPending = false;
      showNotice(error.message, 'notice-danger');
      updateActionState();
    }
  });
}

if (elements.cleanupButton) {
  elements.cleanupButton.addEventListener('click', async () => {
    if (state.cleanupRequestPending) return;
    state.cleanupRequestPending = true;
    updateActionState();
    try {
      const scanResponse = await apiFetch('/api/tokens/expired');
      const listing = await scanResponse.json();
      if (!scanResponse.ok) throw new Error(listing.message || listing.error || '过期 token 扫描失败');
      if (!listing.count) {
        showNotice('没有发现可安全删除的过期 token。', 'notice-info');
        return;
      }
      const preview = (listing.items || []).slice(0, 3).map((item) => item.relativePath).join('、');
      const suffix = listing.count > 3 ? ' 等' : '';
      if (!window.confirm('将把 ' + listing.count + ' 个已过期 token 文件移入隔离目录（' + preview + suffix + '），之后仍可手动恢复。确认继续？')) return;
      const deleteResponse = await apiFetch('/api/tokens/expired/delete', {
        method: 'POST',
        body: JSON.stringify({ version: listing.version, confirmation: 'DELETE_EXPIRED_TOKENS' }),
      });
      const result = await deleteResponse.json();
      if (!deleteResponse.ok) throw new Error(result.message || result.error || '过期 token 删除失败');
      showNotice('已隔离 ' + (result.count || 0) + ' 个过期 token。'
        + (result.skipped?.length ? '另有 ' + result.skipped.length + ' 个文件变化，已跳过。' : ''), 'notice-info');
      await loadSnapshot();
    } catch (error) {
      showNotice(error.message, 'notice-danger');
    } finally {
      state.cleanupRequestPending = false;
      updateActionState();
    }
  });
}

elements.clearSelectionButton.addEventListener('click', () => {
  changeSelection(new Set());
});

elements.selectAll.addEventListener('change', () => {
  const next = new Set(state.selected);
  if (elements.selectAll.checked) state.rows.forEach((row) => next.add(row.key));
  else state.rows.forEach((row) => next.delete(row.key));
  if (!changeSelection(next)) {
    elements.selectAll.checked = state.rows.length > 0 && state.rows.every((row) => state.selected.has(row.key));
  }
});

[elements.searchInput, elements.statusFilter, elements.availabilityFilter, elements.sourceFilter, elements.diffFilter]
  .forEach((element) => element.addEventListener(element.tagName === 'SELECT' ? 'change' : 'input', applyFilters));

if (elements.historicalToggle) {
  elements.historicalToggle.addEventListener('change', () => loadSnapshot());
}

function updateActionState() {
  const selectedRows = selectedRowsFromSelection();
  const phase3Targets = phase3TargetsFromRows(selectedRows);
  const phase3Problem = phase3SelectionProblem(selectedRows, state.selected.size);
  const testTargets = accountTestRows(selectedRows);
  const invalidTestRow = selectedRows.some((row) => (
    !Number.isSafeInteger(Number(row?.accountId)) || Number(row.accountId) <= 0
  ));
  const canRunAccountTest = state.selected.size > 0
    && selectedRows.length === state.selected.size
    && !invalidTestRow
    && testTargets.length > 0
    && !state.snapshot?.readOnly;
  const canRunPhase3 = state.selected.size > 0
    && selectedRows.length === state.selected.size
    && phase3Targets.length > 0
    && !phase3Problem
    && !state.snapshot?.readOnly;
  const locked = actionsLocked();
  const writeBlocked = reconciliationWriteBlocked();
  const mutationLocked = locked || writeBlocked;
  elements.phase3Button.disabled = mutationLocked || !canRunPhase3;
  if (elements.accountTestButton) {
    elements.accountTestButton.disabled = mutationLocked || !canRunAccountTest;
    if (writeBlocked) {
      elements.accountTestButton.title = '存在待人工对账任务，当前全部写操作已阻止';
    } else if (locked) {
      elements.accountTestButton.title = '另一个任务或请求执行中';
    } else if (!canRunAccountTest) {
      elements.accountTestButton.title = '请选择已导入 Sub2API 的上游账号';
    } else {
      elements.accountTestButton.title = '使用所选模型测试上游账号；error 账号成功后恢复并启用';
    }
  }
  elements.clearSelectionButton.disabled = locked || state.selected.size === 0;
  elements.selectAll.disabled = locked;
  document.querySelectorAll('.row-check').forEach((input) => { input.disabled = locked; });
  elements.previewButton.disabled = locked || !comparisonAvailable();
  updateImportButtonState();
  elements.importButton.title = writeBlocked
    ? '存在待人工对账任务，当前全部写操作已阻止'
    : '';
  if (elements.cleanupButton) {
    elements.cleanupButton.disabled = Boolean(state.snapshot?.readOnly) || mutationLocked;
    elements.cleanupButton.title = writeBlocked
      ? '存在待人工对账任务，当前全部写操作已阻止'
      : '';
  }
  if (elements.reconciliationAckButton) {
    const target = reconciliationHoldTarget();
    elements.reconciliationAckButton.disabled = !target
      || state.reconciliationAckPending
      || Boolean(state.snapshot?.readOnly);
  }
  if (writeBlocked) {
    elements.phase3Button.title = '存在待人工对账任务，当前全部写操作已阻止';
  } else if (locked) {
    elements.phase3Button.title = '另一个任务或请求执行中';
  } else if (!canRunPhase3) {
    elements.phase3Button.title = phase3Problem || '请选择至少一个符合条件的账号';
  } else {
    elements.phase3Button.title = '按顺序为已选账号运行 Phase 3';
  }
  elements.previewButton.title = comparisonAvailable()
    ? '检查所选账号与 Sub2API 的同步差异'
    : 'Sub2API 账号尚未成功读取，无法比较或同步';
}

function applyColumnVisibility() {
  document.querySelectorAll('[data-column-toggle]').forEach((input) => {
    const column = input.dataset.columnToggle;
    document.querySelectorAll('.col-' + column).forEach((cell) => {
      cell.classList.toggle('col-hidden', !input.checked);
    });
    try { localStorage.setItem('panel-column-' + column, input.checked ? '1' : '0'); } catch {}
  });
}

document.querySelectorAll('[data-column-toggle]').forEach((input) => {
  try {
    const saved = localStorage.getItem('panel-column-' + input.dataset.columnToggle);
    if (saved !== null) input.checked = saved === '1';
  } catch {}
  input.addEventListener('change', applyColumnVisibility);
});

if (elements.reconciliationAckButton) {
  elements.reconciliationAckButton.addEventListener('click', openReconciliationDialog);
}
if (elements.reconciliationAckForm) {
  elements.reconciliationAckForm.addEventListener('submit', submitReconciliationAcknowledgement);
}
if (elements.reconciliationAckDialog) {
  elements.reconciliationAckDialog.addEventListener('cancel', (event) => {
    if (state.reconciliationAckPending) event.preventDefault();
  });
  elements.reconciliationAckDialog.addEventListener('close', () => {
    if (!state.reconciliationAckPending) state.reconciliationAckTarget = null;
    setReconciliationDialogError('');
  });
}

loadSnapshot({ resumeJobs: true });
applyColumnVisibility();
