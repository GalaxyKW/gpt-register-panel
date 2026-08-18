const state = {
  snapshot: null,
  rows: [],
  selected: new Set(),
  plan: null,
  phase3RequestPending: false,
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
  planPanel: document.querySelector('#planPanel'),
  planSummary: document.querySelector('#planSummary'),
  planVersion: document.querySelector('#planVersion'),
  planRows: document.querySelector('#planRows'),
};

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

function formatUsage(usage) {
  if (!usage) return '-';
  if (usage.historical || usage.current) {
    return formatUsage(usage.historical || null);
  }
  const total = Number(usage.totalTokens || 0);
  const requests = Number(usage.requests || 0);
  if (!total && !requests) return '0';
  return total.toLocaleString('en-US') + ' / ' + requests.toLocaleString('en-US') + ' 次';
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
    sub2api_only: 'badge-neutral',
    token_changed: 'badge-danger',
    expired: 'badge-danger',
    invalid_file: 'badge-danger',
    duplicate_identity: 'badge-danger',
    mapping_conflict: 'badge-danger',
    missing_refresh_token: 'badge-warning',
  }[kind] || 'badge-neutral';
}

function kindLabel(kind) {
  return {
    in_sync: '一致',
    token_only: '仅文件',
    sub2api_only: '仅 Sub2API',
    token_changed: 'Token 不同',
    expired: '已过期',
    invalid_file: '文件异常',
    duplicate_identity: '身份重复',
    mapping_conflict: '身份冲突',
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
    superseded_by_newer_source: '已有更新来源，跳过旧文件',
    token_changed: 'Sub2API 不可用且 token 不同',
    multiple_sub2api_accounts: '匹配到多个 Sub2API 账号',
    duplicate_token_versions: '来源存在多个冲突版本',
  }[reason] || reason || '-';
}

function statusClass(value) {
  const status = String(value || '').toLowerCase();
  if (status === 'active' || status === 'enabled') return 'status-active';
  if (status === 'error' || status === 'disabled') return 'status-error';
  return 'status-unknown';
}

function sourceClass(value) {
  const source = String(value || '').toLowerCase();
  if (source === 'tokens') return 'source-tokens';
  if (source === 'use_token') return 'source-use-token';
  return 'source-sub2api';
}

function apiHeaders(options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('accept', 'application/json');
  if (options.body !== undefined && !headers.has('content-type')) headers.set('content-type', 'application/json');
  const token = sessionStorage.getItem('panelToken');
  if (token) headers.set('x-panel-token', token);
  return headers;
}

async function apiFetch(url, options = {}) {
  const response = await fetch(url, { ...options, headers: apiHeaders(options), cache: 'no-store' });
  if (response.status === 401) {
    const token = window.prompt('请输入面板管理员令牌');
    if (token) {
      sessionStorage.setItem('panelToken', token);
      const retry = await fetch(url, { ...options, headers: apiHeaders(options), cache: 'no-store' });
      return retry;
    }
  }
  return response;
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

function renderMetrics(snapshot) {
  const summary = snapshot.sources.summary || {};
  const counts = snapshot.diff.counts || {};
  elements.tokenCount.textContent = String(summary.tokenCount ?? '-');
  elements.tokenDetail.textContent = String(summary.validTokenCount ?? 0) + ' 可解析 · ' + String(summary.invalidTokenCount ?? 0) + ' 异常';
  elements.accountCount.textContent = String(snapshot.sub2api.accountCount ?? 0);
  elements.accountDetail.textContent = snapshot.sub2api.apiError ? 'API 未连接' : '管理员 API';
  elements.diffCount.textContent = String(Object.values(counts).reduce((sum, value) => sum + Number(value || 0), 0));
  elements.diffDetail.textContent = Object.entries(counts).map(([key, value]) => kindLabel(key) + ' ' + value).join(' · ') || '暂无差异';
  elements.lastRead.textContent = formatDate(snapshot.generatedAt);
  elements.modeBadge.textContent = snapshot.readOnly ? '只读模式' : '受限模式';
}

function renderRows() {
  const rows = state.rows;
  elements.accountRows.innerHTML = rows.map((row) => {
    const checked = state.selected.has(row.key) ? ' checked' : '';
    const displayName = row.accountName || row.fileName || '(未命名)';
    const issueText = row.issues.length ? ' title="' + escapeHtml(row.issues.join(', ')) + '"' : '';
    return '<tr>' +
      '<td class="check-col"><input class="row-check" data-key="' + escapeHtml(row.key) + '" type="checkbox" aria-label="选择 ' + escapeHtml(displayName) + '"' + checked + '></td>' +
      '<td><strong>' + escapeHtml(displayName) + '</strong><small>' + escapeHtml(row.chatgptAccountId || row.userId || row.relativePath || '-') + '</small></td>' +
      '<td>' + escapeHtml(row.email || '-') + '</td>' +
      '<td><span class="status-text ' + statusClass(row.status) + '"><span class="status-dot" aria-hidden="true"></span>' + escapeHtml(row.status || '-') + '</span></td>' +
      '<td><span class="source-text ' + sourceClass(row.source) + '">' + escapeHtml(row.source || '-') + '</span></td>' +
      '<td' + issueText + '><span class="badge ' + badgeClass(row.diffKind) + '">' + escapeHtml(kindLabel(row.diffKind)) + '</span></td>' +
      '<td>' + escapeHtml(formatDate(row.expiresAt)) + '</td>' +
      '<td><code>' + escapeHtml(formatFingerprint(row.fingerprints?.access)) + '</code></td>' +
      '<td class="col-historical">' + escapeHtml(formatUsage(row.usage)) + '</td>' +
      '<td class="col-current">' + escapeHtml(formatPeriodUsage(row.usage)) + '</td>' +
      '</tr>';
  }).join('');
  elements.emptyState.hidden = rows.length !== 0;
  elements.tableSummary.textContent = '当前显示 ' + rows.length + ' 项，共选中 ' + state.selected.size + ' 项';
  elements.selectionCount.textContent = '已选 ' + state.selected.size;
  elements.selectAll.checked = rows.length > 0 && rows.every((row) => state.selected.has(row.key));
  elements.selectAll.indeterminate = rows.some((row) => state.selected.has(row.key)) && !elements.selectAll.checked;
  document.querySelectorAll('.row-check').forEach((input) => {
    input.addEventListener('change', () => {
      if (input.checked) state.selected.add(input.dataset.key);
      else state.selected.delete(input.dataset.key);
      renderRows();
    });
  });
}

function renderPlan(plan) {
  state.plan = plan;
  const items = plan?.items || [];
  elements.planPanel.hidden = !plan;
  if (!plan) {
    elements.planSummary.textContent = '-';
    elements.planVersion.textContent = '';
    elements.planRows.innerHTML = '';
    elements.importButton.disabled = true;
    return;
  }
  const counts = plan.counts || {};
  elements.planSummary.textContent = '新增 ' + (counts.create || 0) + ' · 更新 ' + (counts.update || 0)
    + ' · 跳过 ' + (counts.skip || 0) + ' · 冲突 ' + (counts.conflict || 0);
  elements.planVersion.textContent = '快照 ' + String(plan.version || '').slice(0, 12);
  elements.planRows.innerHTML = items.map((item) => '<tr>'
    + '<td><span class="badge ' + (item.action === 'conflict' ? 'badge-danger' : item.action === 'skip' ? 'badge-neutral' : item.action === 'update' ? 'badge-warning' : 'badge-success') + '">' + escapeHtml(actionLabel(item.action)) + '</span></td>'
    + '<td>' + escapeHtml(item.accountName || '-') + '</td>'
    + '<td>' + escapeHtml(item.email || '-') + '</td>'
    + '<td>' + escapeHtml(item.source || '-') + '</td>'
    + '<td><code>' + escapeHtml(formatFingerprint(item.fingerprints?.access)) + '</code></td>'
    + '<td>' + escapeHtml(actionReasonLabel(item.reason)) + '</td></tr>').join('');
  elements.importButton.disabled = !items.some((item) => item.action === 'create' || item.action === 'update');
}

function applyFilters() {
  if (!state.snapshot) return;
  const search = elements.searchInput.value.trim().toLowerCase();
  const rows = state.snapshot.rows;
  state.rows = rows.filter((row) => {
    if (elements.statusFilter.value && row.status !== elements.statusFilter.value) return false;
    if (elements.availabilityFilter.value && row.availability !== elements.availabilityFilter.value) return false;
    if (elements.sourceFilter.value && row.source !== elements.sourceFilter.value) return false;
    if (elements.diffFilter.value && row.diffKind !== elements.diffFilter.value) return false;
    if (!search) return true;
    return [row.accountName, row.email, row.chatgptAccountId, row.userId, row.fileName, row.relativePath]
      .some((value) => String(value || '').toLowerCase().includes(search));
  });
  renderRows();
}

function showNotice(message, kind) {
  elements.notice.hidden = !message;
  elements.notice.className = 'notice ' + (kind || 'notice-info');
  elements.notice.textContent = message || '';
}

async function loadSnapshot() {
  elements.loadingLabel.hidden = false;
  elements.refreshButton.disabled = true;
  try {
    const response = await apiFetch('/api/snapshot?withSub2api=1');
    const snapshot = await response.json();
    if (!response.ok) throw new Error(snapshot.message || snapshot.error || '读取失败');
    state.snapshot = snapshot;
    renderPlan(null);
    renderMetrics(snapshot);
    renderSelectOptions(elements.statusFilter, snapshot.filters.statuses, {}, '全部状态');
    renderSelectOptions(elements.availabilityFilter, snapshot.filters.availabilities, {
      available: '可用',
      unavailable: '不可用',
      not_present: '未导入 Sub2API',
    }, '全部');
    renderSelectOptions(elements.diffFilter, snapshot.filters.diffKinds, {
      in_sync: '一致',
      token_only: '仅文件',
      sub2api_only: '仅 Sub2API',
      token_changed: 'Token 不同',
      expired: '已过期',
      invalid_file: '文件异常',
      duplicate_identity: '身份重复',
      mapping_conflict: '身份冲突',
      missing_refresh_token: '缺少续期',
    }, '全部差异');
    if (snapshot.sub2api.apiError) {
      showNotice('Sub2API 管理 API 暂未连接：' + snapshot.sub2api.apiError + '。当前仍显示 gpt_register 文件来源。', 'notice-warning');
    } else if (snapshot.sub2api.statsError) {
      showNotice('账号已读取，但统计接口暂不可用：' + snapshot.sub2api.statsError, 'notice-warning');
    } else {
      showNotice('', '');
    }
    applyFilters();
  } catch (error) {
    showNotice(error.message, 'notice-danger');
  } finally {
    elements.loadingLabel.hidden = true;
    elements.refreshButton.disabled = false;
  }
}

elements.refreshButton.addEventListener('click', loadSnapshot);
elements.previewButton.addEventListener('click', async () => {
  elements.previewButton.disabled = true;
  try {
    const response = await apiFetch('/api/sync/preview', {
      method: 'POST',
      body: JSON.stringify({ selectedKeys: [...state.selected] }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error || '差异检查失败');
    renderPlan(body);
    showNotice('差异预览已生成，确认前仍会重新检查来源版本。', 'notice-info');
  } catch (error) {
    showNotice(error.message, 'notice-danger');
  } finally {
    elements.previewButton.disabled = false;
  }
});

elements.importButton.addEventListener('click', async () => {
  if (!state.plan || !window.confirm('确认将预览中的新增/更新写入 Sub2API？')) return;
  elements.importButton.disabled = true;
  try {
    const response = await apiFetch('/api/sync/import', {
      method: 'POST',
      body: JSON.stringify({ snapshotVersion: state.plan.version, selectedKeys: [...state.selected] }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error || '导入任务创建失败');
    showNotice('导入任务已排队：' + body.jobId, 'notice-info');
    renderPlan(null);
    setTimeout(loadSnapshot, 1000);
  } catch (error) {
    showNotice(error.message, 'notice-danger');
    elements.importButton.disabled = false;
  }
});

elements.phase3Button.addEventListener('click', async () => {
  if (state.phase3RequestPending) return;
  const selectedRows = state.rows.filter((row) => state.selected.has(row.key));
  if (selectedRows.length !== 1 || !selectedRows[0].email) {
    showNotice('Phase 3 需要选择一个有邮箱的账号。', 'notice-warning');
    return;
  }
  if (!window.confirm('确认排队更新 ' + selectedRows[0].email + ' 的 token？')) return;
  state.phase3RequestPending = true;
  updateActionState();
  try {
    const response = await apiFetch('/api/phase3', {
      method: 'POST',
      body: JSON.stringify({ email: selectedRows[0].email, selectedKeys: [selectedRows[0].key] }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error || 'Phase 3 任务创建失败');
    showNotice('Phase 3 任务已排队：' + body.jobId, 'notice-info');
  } catch (error) {
    showNotice(error.message, 'notice-danger');
  } finally {
    state.phase3RequestPending = false;
    updateActionState();
  }
});
elements.clearSelectionButton.addEventListener('click', () => {
  state.selected.clear();
  renderRows();
});
elements.selectAll.addEventListener('change', () => {
  if (elements.selectAll.checked) state.rows.forEach((row) => state.selected.add(row.key));
  else state.rows.forEach((row) => state.selected.delete(row.key));
  renderRows();
});
[elements.searchInput, elements.statusFilter, elements.availabilityFilter, elements.sourceFilter, elements.diffFilter]
  .forEach((element) => element.addEventListener('input', applyFilters));

function updateActionState() {
  const selectedRows = state.rows.filter((row) => state.selected.has(row.key));
  const canRunPhase3 = state.selected.size === 1
    && selectedRows.length === 1
    && Boolean(selectedRows[0].email);
  elements.phase3Button.disabled = state.phase3RequestPending || !canRunPhase3;
  elements.clearSelectionButton.disabled = state.selected.size === 0;
  if (state.phase3RequestPending) {
    elements.phase3Button.title = 'Phase 3 任务提交中';
  } else if (state.selected.size > 1) {
    elements.phase3Button.title = '批量选择不能提交 Phase 3，请只选择一个账号';
  } else if (!canRunPhase3) {
    elements.phase3Button.title = '请选择一个有邮箱的账号';
  } else {
    elements.phase3Button.title = '为当前账号运行 Phase 3';
  }
}

function applyColumnVisibility() {
  document.querySelectorAll('[data-column-toggle]').forEach((input) => {
    const column = input.dataset.columnToggle;
    document.querySelectorAll('.col-' + column).forEach((cell) => {
      cell.classList.toggle('col-hidden', !input.checked);
    });
  });
}

document.querySelectorAll('[data-column-toggle]').forEach((input) => {
  input.addEventListener('change', applyColumnVisibility);
});

const originalRenderRows = renderRows;
renderRows = function patchedRenderRows() {
  originalRenderRows();
  updateActionState();
};

loadSnapshot();
applyColumnVisibility();
