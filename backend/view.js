function rowFromDiffItem(item) {
  const token = item.token;
  const account = item.account;
  const source = token ? token.source : 'sub2api';
  const key = account
    ? 'account:' + String(account.id)
    : 'token:' + source + ':' + String(token?.relativePath || token?.fileName || Math.random());
  const fingerprints = account?.tokenFingerprints || token?.fingerprints || {};
  return {
    key,
    accountId: account?.id ?? null,
    accountName: account?.name || '',
    email: account?.email || token?.email || '',
    userId: account?.userId || token?.userId || '',
    chatgptAccountId: account?.accountId || token?.accountId || '',
    platform: account?.platform || '',
    type: account?.type || token?.type || '',
    status: account?.status || (item.kind === 'token_only' ? '未导入' : '未知'),
    source,
    diffKind: item.kind,
    issues: Array.isArray(item.issues) ? item.issues : [],
    expiresAt: account?.expiresAt || token?.expiresAt || null,
    lastRefresh: token?.lastRefresh || null,
    fingerprints,
    groupIds: account?.groupIds || [],
    usage: account?.usage || null,
    relativePath: token?.relativePath || null,
    fileName: token?.fileName || null,
  };
}

function buildRows(diff) {
  return (diff?.items || []).map(rowFromDiffItem).sort((left, right) => {
    const leftName = left.accountName || left.email || left.fileName || '';
    const rightName = right.accountName || right.email || right.fileName || '';
    return leftName.localeCompare(rightName, 'zh-CN', { numeric: true, sensitivity: 'base' });
  });
}

function filterRows(rows, filters = {}) {
  const search = String(filters.search || '').trim().toLowerCase();
  const status = String(filters.status || '').trim();
  const source = String(filters.source || '').trim();
  const diffKind = String(filters.diffKind || '').trim();
  return rows.filter((row) => {
    if (status && row.status !== status) return false;
    if (source && row.source !== source) return false;
    if (diffKind && row.diffKind !== diffKind) return false;
    if (!search) return true;
    return [
      row.accountName,
      row.email,
      row.chatgptAccountId,
      row.userId,
      row.fileName,
      row.relativePath,
    ].some((value) => String(value || '').toLowerCase().includes(search));
  });
}

function statusOptions(rows) {
  return [...new Set(rows.map((row) => row.status).filter(Boolean))].sort();
}

function diffOptions(rows) {
  return [...new Set(rows.map((row) => row.diffKind).filter(Boolean))].sort();
}

module.exports = {
  rowFromDiffItem,
  buildRows,
  filterRows,
  statusOptions,
  diffOptions,
};

