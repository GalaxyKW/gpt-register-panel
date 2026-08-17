const state = {
  snapshot: null,
  rows: [],
  selected: new Set(),
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
  sourceFilter: document.querySelector('#sourceFilter'),
  diffFilter: document.querySelector('#diffFilter'),
  selectionCount: document.querySelector('#selectionCount'),
  clearSelectionButton: document.querySelector('#clearSelectionButton'),
  selectAll: document.querySelector('#selectAll'),
  accountRows: document.querySelector('#accountRows'),
  emptyState: document.querySelector('#emptyState'),
  tableSummary: document.querySelector('#tableSummary'),
  loadingLabel: document.querySelector('#loadingLabel'),
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
  const total = Number(usage.totalTokens || 0);
  const requests = Number(usage.requests || 0);
  if (!total && !requests) return '0';
  return total.toLocaleString('en-US') + ' / ' + requests.toLocaleString('en-US') + ' 次';
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
      '<td><span class="status-text">' + escapeHtml(row.status || '-') + '</span></td>' +
      '<td><span class="source-text">' + escapeHtml(row.source || '-') + '</span></td>' +
      '<td' + issueText + '><span class="badge ' + badgeClass(row.diffKind) + '">' + escapeHtml(kindLabel(row.diffKind)) + '</span></td>' +
      '<td>' + escapeHtml(formatDate(row.expiresAt)) + '</td>' +
      '<td><code>' + escapeHtml(formatFingerprint(row.fingerprints?.access)) + '</code></td>' +
      '<td>' + escapeHtml(formatUsage(row.usage)) + '</td>' +
      '<td>' + escapeHtml(formatUsage(row.usage?.today || null)) + '</td>' +
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

function applyFilters() {
  if (!state.snapshot) return;
  const search = elements.searchInput.value.trim().toLowerCase();
  const rows = state.snapshot.rows;
  state.rows = rows.filter((row) => {
    if (elements.statusFilter.value && row.status !== elements.statusFilter.value) return false;
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
    const response = await fetch('/api/snapshot?withSub2api=1', { cache: 'no-store' });
    const snapshot = await response.json();
    if (!response.ok) throw new Error(snapshot.message || snapshot.error || '读取失败');
    state.snapshot = snapshot;
    renderMetrics(snapshot);
    renderSelectOptions(elements.statusFilter, snapshot.filters.statuses, {}, '全部状态');
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
elements.clearSelectionButton.addEventListener('click', () => {
  state.selected.clear();
  renderRows();
});
elements.selectAll.addEventListener('change', () => {
  if (elements.selectAll.checked) state.rows.forEach((row) => state.selected.add(row.key));
  else state.rows.forEach((row) => state.selected.delete(row.key));
  renderRows();
});
[elements.searchInput, elements.statusFilter, elements.sourceFilter, elements.diffFilter]
  .forEach((element) => element.addEventListener('input', applyFilters));

loadSnapshot();

