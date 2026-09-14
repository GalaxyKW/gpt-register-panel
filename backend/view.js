const { getAccountAvailability } = require('./accountAvailability');
const { normalizeEmail } = require('./lib/token');

const TERMINAL_USERNAME_STATUSES = new Set([
  'account_deactivated',
  'account_deleted',
  'account_disabled',
]);

function buildUsernameIndex(usernames = []) {
  const index = new Map();
  if (!Array.isArray(usernames)) return index;
  for (const record of usernames) {
    const email = normalizeEmail(record?.email);
    if (!email) continue;
    const matches = index.get(email) || [];
    // Only uniqueness matters. Keeping at most two records also bounds the
    // per-email memory cost for a malformed username.json full of duplicates.
    if (matches.length < 2) matches.push(record);
    index.set(email, matches);
  }
  return index;
}

function usernameAssociation(token, usernameIndex) {
  if (!token) {
    return {
      phone: '',
      phase3Email: '',
      phase3Eligible: false,
      phase3Reason: 'token_missing',
      usernameMatch: 'not_applicable',
    };
  }
  const email = normalizeEmail(token.email);
  const matches = email ? (usernameIndex.get(email) || []) : [];
  if (matches.length === 0) {
    return {
      phone: '',
      phase3Email: email,
      phase3Eligible: false,
      phase3Reason: 'username_missing',
      usernameMatch: 'missing',
    };
  }
  if (matches.length !== 1) {
    return {
      phone: '',
      phase3Email: email,
      phase3Eligible: false,
      phase3Reason: 'username_ambiguous',
      usernameMatch: 'ambiguous',
    };
  }
  const username = matches[0];
  const phone = String(username?.phone || '').trim();
  const status = String(username?.status || '').trim().toLowerCase();
  if (username?.hasPassword !== true) {
    return {
      phone,
      phase3Email: email,
      phase3Eligible: false,
      phase3Reason: 'username_password_missing',
      usernameMatch: 'unique',
    };
  }
  if (TERMINAL_USERNAME_STATUSES.has(status)) {
    return {
      phone,
      phase3Email: email,
      phase3Eligible: false,
      phase3Reason: 'username_terminal',
      usernameMatch: 'unique',
    };
  }
  return {
    phone,
    phase3Email: email,
    phase3Eligible: true,
    phase3Reason: null,
    usernameMatch: 'unique',
  };
}

function fingerprintDetails(value) {
  return {
    access: value?.access || null,
    refresh: value?.refresh || null,
    id: value?.id || null,
  };
}

function sourceDetails(token) {
  if (!token) return null;
  return {
    email: token.email || '',
    chatgptAccountId: token.accountId || '',
    userId: token.userId || '',
    expiresAt: token.expiresAt || null,
    lastRefresh: token.lastRefresh || null,
    mtimeMs: Number.isFinite(token.mtimeMs) ? token.mtimeMs : null,
    fingerprints: fingerprintDetails(token.fingerprints),
    relativePath: token.relativePath || null,
    fileName: token.fileName || null,
  };
}

function remoteDetails(account) {
  if (!account) return null;
  return {
    id: account.id ?? null,
    name: account.name || '',
    email: account.email || '',
    chatgptAccountId: account.accountId || '',
    userId: account.userId || '',
    // OAuth credential expiry and the account-level administrative expiry
    // have different operational meanings. Never substitute one for the
    // other in the side-by-side token comparison.
    credentialExpiresAt: account.credentialExpiresAt || null,
    accountExpiresAt: account.expiresAt || null,
    fingerprints: fingerprintDetails(account.tokenFingerprints),
  };
}

function rowFromDiffItem(item, options = {}) {
  const token = item.token;
  const account = item.account;
  const usernameIndex = options.usernameIndex instanceof Map
    ? options.usernameIndex
    : buildUsernameIndex(options.usernames);
  const username = usernameAssociation(token, usernameIndex);
  const source = token ? token.source : 'sub2api';
  const availability = item?.availability
    ? { key: item.availability, reason: item.availabilityReason || null }
    : getAccountAvailability(account);
  // A partial remote identity can match more than one distinct source row.
  // Every source-backed row therefore needs a file-specific selection key;
  // only a pure Sub2API row may use its numeric account ID as the row key.
  const tokenKey = 'token:' + source + ':' + String(token?.relativePath || token?.fileName || token?.identityKeys?.join('|') || 'unknown');
  const key = token ? tokenKey : 'account:' + String(account?.id ?? 'unknown');
  const fingerprints = account?.tokenFingerprints || token?.fingerprints || {};
  return {
    key,
    // Keep the legacy flattened fields below during the rolling upgrade. New
    // clients must use these side-specific summaries so a remote value cannot
    // hide a different gpt_register value.
    sourceDetails: sourceDetails(token),
    remoteDetails: remoteDetails(account),
    accountId: account?.id ?? null,
    accountName: account?.name || '',
    email: account?.email || token?.email || '',
    phone: username.phone,
    phase3Email: username.phase3Email,
    phase3Eligible: username.phase3Eligible,
    phase3Reason: username.phase3Reason,
    usernameMatch: username.usernameMatch,
    userId: account?.userId || token?.userId || '',
    chatgptAccountId: account?.accountId || token?.accountId || '',
    platform: account?.platform || '',
    type: account?.type || token?.type || '',
    status: account?.status || (availability.reason === 'sub2api_read_failed'
      || availability.reason === 'sub2api_not_read'
      ? '未知'
      : (['token_only', 'expired', 'expiry_invalid'].includes(item.kind) ? '未导入' : '未知')),
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

function buildRows(diff, options = {}) {
  const usernameIndex = buildUsernameIndex(options.usernames);
  const rowOptions = { ...options, usernameIndex };
  return (diff?.items || []).map((item) => rowFromDiffItem(item, rowOptions)).sort((left, right) => {
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
  const phoneSearch = /^[+\d\s().-]+$/.test(search) ? search.replace(/[^0-9]/g, '') : '';
  return rows.filter((row) => {
    if (status && row.status !== status) return false;
    if (source && row.source !== source) return false;
    if (diffKind && row.diffKind !== diffKind) return false;
    if (availability && row.availability !== availability) return false;
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
    ].some((value) => String(value || '').toLowerCase().includes(search));
    const phoneMatch = phoneSearch
      && String(row.phone || '').replace(/[^0-9]/g, '').includes(phoneSearch);
    return textMatch || Boolean(phoneMatch);
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
