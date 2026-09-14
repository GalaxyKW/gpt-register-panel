const { getAccountAvailability } = require('./accountAvailability');

function rowFromDiffItem(item) {
  const token = item.token;
  const account = item.account;
  const source = token ? token.source : 'sub2api';
  const availability = getAccountAvailability(account);
  // Duplicate source rows can share one Sub2API account. Keep their keys
  // file-specific so each checkbox remains stable and selectable.
  const tokenKey = 'token:' + source + ':' + String(token?.relativePath || token?.fileName || token?.identityKeys?.join('|') || 'unknown');
  const key = account && !['duplicate_identity', 'historical_backup'].includes(item.kind)
    ? 'account:' + String(account.id)
    : tokenKey;
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
    status: account?.status || (['token_only', 'expired', 'expiry_invalid'].includes(item.kind) ? '未导入' : '未知'),
    availability: availability.key,
    availabilityReason: availability.reason,
    schedulable: typeof account?.schedulable === 'boolean' ? account.schedulable : null,
    source,
    diffKind: item.kind,
    issues: Array.isArray(item.issues) ? item.issues : [],
    historical: token?.historical === true,
    expiresAt: account?.credentialExpiresAt || account?.expiresAt || token?.expiresAt || null,
    lastRefresh: token?.lastRefresh || null,
    fingerprints,
    groupIds: account?.groupIds || [],
    usage: account?.usage || null,
    usageError: account?.usageError || null,
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
  const availability = String(filters.availability || '').trim();
  return rows.filter((row) => {
    if (status && row.status !== status) return false;
    if (source && row.source !== source) return false;
    if (diffKind && row.diffKind !== diffKind) return false;
    if (availability && row.availability !== availability) return false;
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

function availabilityOptions(rows) {
  return [...new Set(rows.map((row) => row.availability).filter(Boolean))].sort();
}

module.exports = {
  rowFromDiffItem,
  buildRows,
  filterRows,
  statusOptions,
  diffOptions,
  availabilityOptions,
};
