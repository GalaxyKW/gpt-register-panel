function accountKeys(account) {
  if (Array.isArray(account?.identityKeys) && account.identityKeys.length > 0) {
    return account.identityKeys;
  }
  const keys = [];
  const add = (prefix, value) => {
    const text = value === undefined || value === null ? '' : String(value).trim().toLowerCase();
    if (text && !keys.includes(prefix + text)) keys.push(prefix + text);
  };
  add('account:', account?.accountId);
  add('user:', account?.userId);
  add('email:', account?.email);
  return keys;
}

function isExpired(record, nowMs) {
  if (!record?.expiresAt) return false;
  const timestamp = Date.parse(record.expiresAt);
  return Number.isFinite(timestamp) && timestamp <= nowMs;
}

function addIndex(index, key, value) {
  if (!key) return;
  const list = index.get(key) || [];
  list.push(value);
  index.set(key, list);
}

function indexByIdentity(records, getKeys) {
  const index = new Map();
  for (const record of records) {
    for (const key of getKeys(record)) addIndex(index, key, record);
  }
  return index;
}

function uniqueRecords(list) {
  const seen = new Set();
  return list.filter((record) => {
    const id = String(record?.id ?? record?.relativePath ?? record?.fileName ?? '');
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

function buildDiff(tokenRecords = [], accountRecords = [], options = {}) {
  const nowMs = Number(options.nowMs || Date.now());
  const tokenIndex = indexByIdentity(
    tokenRecords.filter((record) => record.parseStatus === 'ok'),
    (record) => Array.isArray(record.identityKeys) ? record.identityKeys : [],
  );
  const accountIndex = indexByIdentity(accountRecords, accountKeys);
  const matchedAccountIds = new Set();
  const items = [];

  for (const token of tokenRecords) {
    if (token.parseStatus !== 'ok') {
      items.push({
        kind: 'invalid_file',
        source: token.source,
        relativePath: token.relativePath,
        fileName: token.fileName,
        token,
        account: null,
        issues: [token.parseError || '无法解析 token 文件'],
      });
      continue;
    }

    const duplicateKeys = (token.identityKeys || []).filter((key) => (tokenIndex.get(key) || []).length > 1);
    if (duplicateKeys.length > 0) {
      items.push({
        kind: 'duplicate_identity',
        source: token.source,
        relativePath: token.relativePath,
        fileName: token.fileName,
        token,
        account: null,
        issues: duplicateKeys,
      });
      continue;
    }

    const candidates = uniqueRecords(
      (token.identityKeys || []).flatMap((key) => accountIndex.get(key) || []),
    );
    if (candidates.length === 0) {
      items.push({
        kind: 'token_only',
        source: token.source,
        relativePath: token.relativePath,
        fileName: token.fileName,
        token,
        account: null,
        issues: isExpired(token, nowMs) ? ['expired'] : [],
      });
      continue;
    }
    if (candidates.length > 1) {
      items.push({
        kind: 'mapping_conflict',
        source: token.source,
        relativePath: token.relativePath,
        fileName: token.fileName,
        token,
        account: null,
        issues: candidates.map((item) => item.id),
      });
      continue;
    }

    const account = candidates[0];
    matchedAccountIds.add(String(account.id));
    const issues = [];
    if (isExpired(token, nowMs)) issues.push('expired');
    const tokenAccess = token.fingerprints?.access || null;
    const accountAccess = account.tokenFingerprints?.access || null;
    if (tokenAccess && accountAccess && tokenAccess !== accountAccess) {
      issues.push('token_changed');
    }
    if (!token.fingerprints?.refresh && !account.tokenFingerprints?.refresh) {
      issues.push('missing_refresh_token');
    }
    items.push({
      kind: issues[0] || 'in_sync',
      source: token.source,
      relativePath: token.relativePath,
      fileName: token.fileName,
      token,
      account,
      issues,
    });
  }

  for (const account of accountRecords) {
    if (!matchedAccountIds.has(String(account.id))) {
      items.push({
        kind: 'sub2api_only',
        source: 'sub2api',
        relativePath: null,
        fileName: null,
        token: null,
        account,
        issues: [],
      });
    }
  }

  const counts = {};
  for (const item of items) counts[item.kind] = (counts[item.kind] || 0) + 1;
  return { generatedAt: new Date(nowMs).toISOString(), items, counts };
}

function toSafeDiff(diff) {
  return {
    generatedAt: diff.generatedAt,
    counts: diff.counts,
    items: diff.items.map((item) => ({
      kind: item.kind,
      source: item.source,
      relativePath: item.relativePath,
      fileName: item.fileName,
      issues: item.issues,
      token: item.token
        ? {
            source: item.token.source,
            relativePath: item.token.relativePath,
            fileName: item.token.fileName,
            parseStatus: item.token.parseStatus,
            parseError: item.token.parseError || null,
            email: item.token.email,
            accountId: item.token.accountId,
            userId: item.token.userId,
            expiresAt: item.token.expiresAt,
            lastRefresh: item.token.lastRefresh,
            fingerprints: item.token.fingerprints,
          }
        : null,
      account: item.account
        ? {
            id: item.account.id,
            name: item.account.name,
            platform: item.account.platform,
            type: item.account.type,
            status: item.account.status,
            email: item.account.email,
            accountId: item.account.accountId,
            userId: item.account.userId,
            expiresAt: item.account.expiresAt,
            tokenFingerprints: item.account.tokenFingerprints,
            groupIds: item.account.groupIds,
          }
        : null,
    })),
  };
}

module.exports = {
  accountKeys,
  buildDiff,
  toSafeDiff,
};

