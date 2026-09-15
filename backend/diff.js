const { normalizeIdentityValue } = require('./lib/token');
const { getAccountAvailability } = require('./accountAvailability');

const TERMINAL_SOURCE_STATUS_PRIORITY = Object.freeze([
  'account_deleted',
  'account_deactivated',
  'account_disabled',
]);
const TERMINAL_SOURCE_STATUSES = new Set(TERMINAL_SOURCE_STATUS_PRIORITY);

function accountKeys(account) {
  if (Array.isArray(account?.identityKeys) && account.identityKeys.length > 0) {
    return account.identityKeys;
  }
  const keys = [];
  const add = (prefix, value) => {
    const raw = value === undefined || value === null ? '' : String(value).trim();
    const text = normalizeIdentityValue(prefix, raw);
    if (text && !keys.includes(prefix + text)) keys.push(prefix + text);
  };
  add('account:', account?.accountId);
  add('user:', account?.userId);
  add('email:', account?.email);
  return keys;
}

function identityParts(keys = []) {
  const parts = { account: new Set(), user: new Set(), email: new Set() };
  for (const key of keys) {
    const raw = String(key || '').trim();
    const separator = raw.indexOf(':');
    if (separator <= 0) continue;
    const kind = raw.slice(0, separator).toLowerCase();
    const value = normalizeIdentityValue(kind + ':', raw.slice(separator + 1));
    if (!value) continue;
    if (kind === 'account') parts.account.add(value);
    else if (kind === 'user') parts.user.add(value);
    else if (kind === 'email') parts.email.add(value);
  }
  return parts;
}

function hasStrongIdentity(keys = []) {
  const parts = identityParts(keys);
  return parts.account.size > 0 || parts.user.size > 0;
}

function identitiesStronglyCompatible(leftKeys = [], rightKeys = []) {
  const left = identityParts(leftKeys);
  const right = identityParts(rightKeys);
  let strongMatch = false;
  for (const kind of ['account', 'user']) {
    if (left[kind].size > 0 && right[kind].size > 0) {
      const shares = [...left[kind]].some((value) => right[kind].has(value));
      if (!shares) return false;
      strongMatch = true;
    }
  }
  return strongMatch;
}

// Mapping a local source identity to a remote account is stricter than
// grouping local token versions. Every account/user dimension present on
// either side must be present on the other side with the exact same values.
// This prevents an account-only record from authorizing an update to an
// account+user row (and vice versa) while still allowing partial local token
// versions to be grouped by identitiesStronglyCompatible above.
function strongIdentitiesFullyMatch(leftKeys = [], rightKeys = []) {
  const left = identityParts(leftKeys);
  const right = identityParts(rightKeys);
  let hasStrong = false;
  for (const kind of ['account', 'user']) {
    if (left[kind].size > 0 || right[kind].size > 0) hasStrong = true;
    if (left[kind].size !== right[kind].size) return false;
    if ([...left[kind]].some((value) => !right[kind].has(value))) return false;
  }
  return hasStrong;
}

// Strong identifiers must never contradict each other just because an email
// happens to be shared or stale. Email remains a compatibility fallback only
// when neither side has a stronger identifier. If either side has an account
// or user ID, an email match alone is not enough to authorize a mapping.
function identitiesCompatible(leftKeys = [], rightKeys = []) {
  const left = identityParts(leftKeys);
  const right = identityParts(rightKeys);
  const leftHasStrong = left.account.size > 0 || left.user.size > 0;
  const rightHasStrong = right.account.size > 0 || right.user.size > 0;
  // Account/user IDs are authoritative. An email can change or be shared,
  // so it must not veto an otherwise exact strong-identity match.
  if (leftHasStrong || rightHasStrong) {
    return identitiesStronglyCompatible(leftKeys, rightKeys);
  }
  if (left.email.size > 0 && right.email.size > 0) {
    return [...left.email].some((value) => right.email.has(value));
  }
  return false;
}

function ambiguousAccountHints(candidate, accounts) {
  const candidateKeys = candidate?.sourceIdentityKeys || [];
  const candidateIdentity = identityParts(candidateKeys);
  return (accounts || []).filter((account) => {
    const keys = Array.isArray(account?.identityKeys) && account.identityKeys.length > 0
      ? account.identityKeys
      : accountKeys(account);
    const remoteIdentity = identityParts(keys);
    if (strongIdentitiesFullyMatch(candidateKeys, keys)) return false;
    const sharesStrong = ['account', 'user'].some((kind) => (
      [...candidateIdentity[kind]].some((value) => remoteIdentity[kind].has(value))
    ));
    // A shared strong value with incomplete or contradictory dimensions is
    // evidence of a possible existing account, never permission to create a
    // duplicate or update a partially identified row.
    if (sharesStrong) return true;
    const sharesEmail = [...candidateIdentity.email].some((value) => (
      remoteIdentity.email.has(value)
    ));
    if (!sharesEmail) return false;
    if (remoteIdentity.account.size === 0 && remoteIdentity.user.size === 0) return true;
    const hasComparableDimension = (candidateIdentity.account.size > 0
        && remoteIdentity.account.size > 0)
      || (candidateIdentity.user.size > 0 && remoteIdentity.user.size > 0);
    return !hasComparableDimension;
  });
}

function incomparableSourceRecords(tokenRecords = []) {
  const emailIndex = new Map();
  for (const record of tokenRecords || []) {
    if (record?.parseStatus !== 'ok' || record?.historical === true) continue;
    const identity = identityParts(record.identityKeys || []);
    const hasAccount = identity.account.size > 0;
    const hasUser = identity.user.size > 0;
    // A record with both dimensions is comparable with every strong record.
    // Only account-only versus user-only records need to fail closed.
    if (hasAccount === hasUser) continue;
    for (const email of identity.email) {
      const bucket = emailIndex.get(email) || { accountOnly: [], userOnly: [] };
      bucket[hasAccount ? 'accountOnly' : 'userOnly'].push(record);
      emailIndex.set(email, bucket);
    }
  }
  const conflicts = new Set();
  for (const bucket of emailIndex.values()) {
    if (bucket.accountOnly.length === 0 || bucket.userOnly.length === 0) continue;
    for (const record of bucket.accountOnly) conflicts.add(record);
    for (const record of bucket.userOnly) conflicts.add(record);
  }
  return conflicts;
}

function strongIdentityContradiction(leftKeys = [], rightKeys = []) {
  const left = identityParts(leftKeys);
  const right = identityParts(rightKeys);
  for (const kind of ['account', 'user']) {
    if (left[kind].size > 0 && right[kind].size > 0
        && ![...left[kind]].some((value) => right[kind].has(value))) {
      return true;
    }
  }
  return false;
}

function isExpired(record, nowMs) {
  if (!record?.expiresAt) return false;
  const timestamp = Date.parse(record.expiresAt);
  return Number.isFinite(timestamp) && timestamp <= nowMs;
}

function isExpiryInvalid(record) {
  return record?.expiryStatus === 'invalid';
}

function accountCredentialPresence(account, field) {
  const explicit = account?.credentialPresence?.[field];
  if (['present', 'absent', 'unknown'].includes(explicit)) return explicit;
  return account?.tokenFingerprints?.[field] ? 'present' : 'unknown';
}

function credentialsInSync(token, account) {
  const sourceAccess = token?.fingerprints?.access || null;
  const remoteAccess = account?.tokenFingerprints?.access || null;
  if (!sourceAccess || !remoteAccess || sourceAccess !== remoteAccess
      || accountCredentialPresence(account, 'access') === 'absent') return false;
  const sourceRefresh = token?.fingerprints?.refresh || null;
  if (sourceRefresh && (accountCredentialPresence(account, 'refresh') !== 'present'
      || !account?.tokenFingerprints?.refresh
      || sourceRefresh !== account.tokenFingerprints.refresh)) return false;

  const sourceId = token?.fingerprints?.id || null;
  if (!sourceId) return true;
  const remoteIdPresence = accountCredentialPresence(account, 'id');
  const remoteId = account?.tokenFingerprints?.id || null;
  // Some Sub2API versions expose only an authoritative id-token presence bit,
  // so absence of a digest alone cannot prove a difference. When the server
  // does expose a digest, however, a known mismatch must not be labelled
  // `in_sync` and silently skip an unavailable account update.
  if (remoteIdPresence === 'absent') return false;
  if (!remoteId) return remoteIdPresence === 'present';
  return sourceId === remoteId;
}

// Keep the human-facing credential difference and the import planner reason
// on one contract.  A remote account that explicitly lacks the refresh token
// carried by the source needs a more useful reason than the generic
// `token_changed`, while an access-only source must not claim that refresh is
// missing.
function credentialDifferenceReason(token, account) {
  if (credentialsInSync(token, account)) return null;
  if (token?.fingerprints?.refresh
      && accountCredentialPresence(account, 'refresh') === 'absent') {
    return 'missing_refresh_token';
  }
  return 'token_changed';
}

function sourceTerminalEvidence(usernames = [], record) {
  const email = String(record?.email || '').trim().toLowerCase();
  if (!email) return null;
  // username.json does not carry account/user IDs, so this email-only match
  // is a conservative write blocker, never identity authorization. More than
  // one row can share an email; choose a stable most-terminal result rather
  // than letting file order alter the import-plan intent.
  const matches = (Array.isArray(usernames) ? usernames : [])
    .filter((item) => String(item?.email || '').trim().toLowerCase() === email);
  const statuses = new Set(matches
    .map((item) => String(item?.status || '').trim().toLowerCase())
    .filter((status) => TERMINAL_SOURCE_STATUSES.has(status)));
  const status = TERMINAL_SOURCE_STATUS_PRIORITY.find((candidate) => statuses.has(candidate));
  if (!status) return null;
  return {
    status,
    identityBasis: 'email_only',
    usernameMatch: matches.length === 1 ? 'unique' : 'ambiguous',
  };
}

function sourceTerminalStatus(usernames = [], record) {
  return sourceTerminalEvidence(usernames, record)?.status || null;
}

function isExpectedSub2ApiAccount(account) {
  return String(account?.platform || '').trim().toLowerCase() === 'openai'
    && String(account?.type || '').trim().toLowerCase() === 'oauth';
}

// These checks precede identity and target policy checks in the import
// planner. Keeping them separate preserves that precedence when callers have
// not yet established a unique strong-identity mapping.
function sourceStateImportDecision(token, options = {}) {
  const terminalEvidence = options.terminalEvidence
    || (options.terminalStatus
      ? {
          status: options.terminalStatus,
          identityBasis: 'email_only',
          usernameMatch: 'unknown',
        }
      : sourceTerminalEvidence(options.usernames, token));
  const terminalStatus = terminalEvidence?.status || null;
  if (terminalStatus) {
    return {
      action: 'skip',
      reason: 'source_account_terminal',
      terminalStatus,
      sourceTerminalIdentityBasis: terminalEvidence.identityBasis,
      sourceTerminalUsernameMatch: terminalEvidence.usernameMatch,
    };
  }
  if (isExpiryInvalid(token)) {
    return { action: 'skip', reason: 'source_expiry_invalid', terminalStatus: null };
  }
  return null;
}

// This helper assumes the caller has already established one unambiguous
// strong-identity match. It is shared by the diff metadata and the actual
// import planner so policy blockers cannot silently appear as actionable
// credential changes (or vice versa).
function matchedAccountImportDecision(token, account, options = {}) {
  const nowMs = Number(options.nowMs || Date.now());
  const sourceDecision = sourceStateImportDecision(token, options);
  if (sourceDecision) return sourceDecision;
  if (account?.schemaValid === false) {
    return { action: 'conflict', reason: 'sub2api_account_schema_invalid' };
  }
  if (!isExpectedSub2ApiAccount(account)) {
    return { action: 'conflict', reason: 'sub2api_target_kind_invalid' };
  }
  if (token?.disabled === true) return { action: 'skip', reason: 'source_disabled' };
  if (options.superseded === true) {
    return { action: 'skip', reason: 'superseded_by_newer_source' };
  }
  const availability = getAccountAvailability(account, nowMs);
  if (availability.key === 'available') {
    return { action: 'skip', reason: 'sub2api_available', availability };
  }
  if (availability.key !== 'unavailable') {
    return {
      action: 'skip',
      reason: availability.reason || 'sub2api_availability_unknown',
      availability,
    };
  }
  if (isExpired(token, nowMs)) {
    return { action: 'skip', reason: 'source_token_expired', availability };
  }
  const differenceReason = credentialDifferenceReason(token, account);
  if (!differenceReason) {
    return { action: 'skip', reason: 'already_in_sync', availability };
  }
  return { action: 'update', reason: differenceReason, availability };
}

function normalizedIdentityKey(key) {
  const raw = String(key || '').trim();
  const separator = raw.indexOf(':');
  if (separator <= 0) return raw;
  const prefix = raw.slice(0, separator).toLowerCase() + ':';
  return prefix + normalizeIdentityValue(prefix, raw.slice(separator + 1));
}

function addIndex(index, key, value) {
  const normalizedKey = normalizedIdentityKey(key);
  if (!normalizedKey) return;
  const list = index.get(normalizedKey) || [];
  list.push(value);
  index.set(normalizedKey, list);
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

function operationalAccountCandidates(token, accountIndex) {
  return uniqueRecords(
    (token?.identityKeys || [])
      .flatMap((key) => accountIndex.get(normalizedIdentityKey(key)) || [])
      // Email is useful for a human-facing hint, but it must never attach a
      // remote numeric ID to a source row.  Every account object returned here
      // can be consumed by ID-scoped UI actions, so require a compatible
      // account/user identity even when both records only expose the same
      // email address.
      .filter((account) => strongIdentitiesFullyMatch(
        token?.identityKeys || [],
        accountKeys(account),
      )),
  );
}

function buildDiff(tokenRecords = [], accountRecords = [], options = {}) {
  const nowMs = Number(options.nowMs || Date.now());
  // Files prefixed with old_codex are retained as backups, but are not part
  // of the active source set. They can be included as diagnostic rows.
  const includeHistorical = options.includeHistorical === true;
  const comparisonStatus = options.sub2apiReadStatus === 'failed'
    || options.sub2apiReadStatus === 'omitted'
    ? 'unavailable'
    : 'complete';
  const comparisonUnavailable = comparisonStatus === 'unavailable';
  const comparisonUnavailableReason = options.sub2apiReadStatus === 'failed'
    ? 'sub2api_read_failed'
    : 'sub2api_not_read';
  // Never consume a possibly partial or stale account array after the remote
  // read was reported unavailable. Local duplicate/expiry/file checks below
  // still run exactly as they do for a complete comparison.
  const comparableAccountRecords = comparisonUnavailable ? [] : accountRecords;
  const activeTokenRecords = tokenRecords.filter((record) => (
    record?.historical !== true
  ));
  const incomparableTokens = incomparableSourceRecords(activeTokenRecords);
  const tokenIndex = indexByIdentity(
    activeTokenRecords.filter((record) => record.parseStatus === 'ok'),
    (record) => Array.isArray(record.identityKeys) ? record.identityKeys : [],
  );
  const accountIndex = indexByIdentity(comparableAccountRecords, accountKeys);
  const matchedAccountIds = new Set();
  const items = [];

  for (const token of tokenRecords) {
    if (token?.historical === true) {
      if (!includeHistorical) continue;
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
      const historicalCandidates = operationalAccountCandidates(token, accountIndex);
      items.push({
        kind: 'historical_backup',
        source: token.source,
        relativePath: token.relativePath,
        fileName: token.fileName,
        token,
        account: historicalCandidates.length === 1 ? historicalCandidates[0] : null,
        issues: ['historical_backup'],
      });
      continue;
    }
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

    // Email is a fallback identity and can legitimately be shared or stale.
    // Only duplicate strong IDs should block automatic mapping.
    const duplicateKeys = (token.identityKeys || []).filter((key) => {
      const kind = String(key || '').split(':', 1)[0].toLowerCase();
      if (!['account', 'user'].includes(kind)) return false;
      return uniqueRecords(tokenIndex.get(normalizedIdentityKey(key)) || []).some((candidate) => (
        candidate !== token
          && identitiesStronglyCompatible(token.identityKeys || [], candidate.identityKeys || [])
      ));
    });
    if (duplicateKeys.length > 0) {
      // Duplicate source files are still surfaced individually, but they do
      // not make a uniquely matching Sub2API account look untracked. The
      // import planner applies the same identity matching rule and chooses a
      // single freshest source before writing.
      const duplicateCandidates = operationalAccountCandidates(token, accountIndex);
      const duplicateAccount = duplicateCandidates.length === 1 ? duplicateCandidates[0] : null;
      if (duplicateAccount) matchedAccountIds.add(String(duplicateAccount.id));
      items.push({
        kind: 'duplicate_identity',
        source: token.source,
        relativePath: token.relativePath,
        fileName: token.fileName,
        token,
        account: duplicateAccount,
        issues: duplicateKeys,
      });
      continue;
    }

    const candidates = operationalAccountCandidates(token, accountIndex);
    if (candidates.length === 0) {
      const expiryInvalid = isExpiryInvalid(token);
      const expired = isExpired(token, nowMs);
      const ambiguousHints = ambiguousAccountHints({
        sourceIdentityKeys: token.identityKeys || [],
      }, uniqueRecords((token.identityKeys || [])
        .flatMap((key) => accountIndex.get(normalizedIdentityKey(key)) || [])));
      let decision = null;
      if (comparisonUnavailable) {
        decision = { action: null, reason: comparisonUnavailableReason };
      } else {
        decision = sourceStateImportDecision(token, {
          nowMs,
          usernames: options.usernames,
        });
        if (!decision) {
          const identity = identityParts(token.identityKeys || []);
          if (identity.account.size > 1 || identity.user.size > 1) {
            decision = { action: 'conflict', reason: 'conflicting_strong_identity' };
          } else if (!hasStrongIdentity(token.identityKeys || [])) {
            decision = { action: 'conflict', reason: 'source_identity_insufficient' };
          } else if (incomparableTokens.has(token)) {
            decision = { action: 'conflict', reason: 'incomparable_strong_identity' };
          } else if (ambiguousHints.length > 0) {
            decision = { action: 'conflict', reason: 'ambiguous_sub2api_identity' };
          } else if (token.disabled === true) {
            decision = { action: 'skip', reason: 'source_disabled' };
          } else if (expired) {
            decision = { action: 'skip', reason: 'source_token_expired' };
          }
        }
      }
      if (decision?.reason === 'ambiguous_sub2api_identity') {
        for (const hint of ambiguousHints) {
          if (hint?.id !== undefined && hint?.id !== null) matchedAccountIds.add(String(hint.id));
        }
      }
      const identityAmbiguous = decision?.reason === 'ambiguous_sub2api_identity';
      items.push({
        kind: identityAmbiguous
          ? 'mapping_conflict'
          : expiryInvalid
          ? 'expiry_invalid'
          : expired
            ? 'expired'
            : comparisonUnavailable ? 'remote_unknown' : 'token_only',
        source: token.source,
        relativePath: token.relativePath,
        fileName: token.fileName,
        token,
        account: null,
        decisionAction: decision?.action ?? null,
        decisionReason: decision?.reason || null,
        sourceTerminalIdentityBasis: decision?.sourceTerminalIdentityBasis || null,
        sourceTerminalUsernameMatch: decision?.sourceTerminalUsernameMatch || null,
        issues: identityAmbiguous
          ? [
              'ambiguous_sub2api_identity',
              ...ambiguousHints
                .map((hint) => hint?.id)
                .filter((id) => id !== undefined && id !== null),
            ]
          : expiryInvalid ? ['expiry_invalid'] : expired ? ['expired'] : [],
      });
      continue;
    }
    if (candidates.length > 1) {
      for (const candidate of candidates) matchedAccountIds.add(String(candidate.id));
      items.push({
        kind: 'mapping_conflict',
        observedKind: 'mapping_conflict',
        decisionAction: 'conflict',
        decisionReason: 'multiple_sub2api_accounts',
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
    if (isExpiryInvalid(token)) issues.push('expiry_invalid');
    else if (isExpired(token, nowMs)) issues.push('expired');
    const credentialReason = credentialDifferenceReason(token, account);
    if (credentialReason) issues.push(credentialReason);
    const observedKind = issues[0] || 'in_sync';
    const decision = matchedAccountImportDecision(token, account, {
      nowMs,
      usernames: options.usernames,
    });
    items.push({
      // `kind` remains the backwards-compatible observation used by the
      // difference filters. Import policy is deliberately carried in
      // separate fields: a matching token can still be skipped because the
      // source is disabled or the remote account is already available.
      kind: observedKind,
      observedKind,
      decisionAction: decision.action,
      decisionReason: decision.reason,
      sourceTerminalIdentityBasis: decision.sourceTerminalIdentityBasis || null,
      sourceTerminalUsernameMatch: decision.sourceTerminalUsernameMatch || null,
      source: token.source,
      relativePath: token.relativePath,
      fileName: token.fileName,
      token,
      account,
      issues,
    });
  }

  // A remote account can omit one strong-identity dimension. In that case,
  // two distinct source users in the same workspace (or one user in two
  // workspaces) can each look compatible with that partial remote identity.
  // Surface the ambiguity before the row is allowed to authorize an
  // ID-scoped operation. The import planner performs the same fail-closed
  // check; the diff must not present these rows as ordinary token changes.
  const matchedItemsByAccount = new Map();
  for (const item of items) {
    if (!item.token || item.token.historical === true || !item.account) continue;
    const key = String(item.account.id);
    const bucket = matchedItemsByAccount.get(key) || [];
    bucket.push(item);
    matchedItemsByAccount.set(key, bucket);
  }
  for (const bucket of matchedItemsByAccount.values()) {
    const contradictory = bucket.some((left, leftIndex) => bucket.some((right, rightIndex) => (
      rightIndex > leftIndex
        && strongIdentityContradiction(
          left.token.identityKeys || [],
          right.token.identityKeys || [],
        )
    )));
    if (!contradictory) continue;
    for (const item of bucket) {
      item.kind = 'mapping_conflict';
      item.issues = [...new Set([...(item.issues || []), 'ambiguous_sub2api_identity'])];
      item.observedKind = 'mapping_conflict';
      item.decisionAction = 'conflict';
      item.decisionReason = 'ambiguous_sub2api_identity';
      // Keep the conflicting account ID only as an issue hint. Removing the
      // operational account object prevents account testing from treating a
      // partial identity match as authorization for that numeric ID.
      item.issues.push(item.account.id);
      item.account = null;
    }
  }

  for (const account of comparableAccountRecords) {
    if (!matchedAccountIds.has(String(account.id))) {
      const keys = accountKeys(account);
      const duplicateStrongKeys = keys.filter((key) => {
        const kind = String(key || '').split(':', 1)[0].toLowerCase();
        if (!['account', 'user'].includes(kind)) return false;
        return uniqueRecords(accountIndex.get(normalizedIdentityKey(key)) || []).some((candidate) => (
          String(candidate?.id) !== String(account.id)
            && identitiesStronglyCompatible(keys, accountKeys(candidate))
        ));
      });
      items.push({
        kind: duplicateStrongKeys.length > 0 ? 'mapping_conflict' : 'sub2api_only',
        source: 'sub2api',
        relativePath: null,
        fileName: null,
        token: null,
        account,
        issues: duplicateStrongKeys,
      });
    }
  }

  if (comparisonUnavailable) {
    for (const item of items) {
      item.availability = 'unknown';
      item.availabilityReason = comparisonUnavailableReason;
      if (item.token?.parseStatus === 'ok' && item.token?.historical !== true) {
        item.decisionAction = null;
        item.decisionReason = comparisonUnavailableReason;
      }
    }
  }
  const counts = {};
  for (const item of items) {
    // Normalize the contract after mapping-conflict post-processing so
    // callers never see a stale pre-conflict observation or decision.
    item.observedKind = item.kind;
    if (!Object.hasOwn(item, 'decisionAction')) item.decisionAction = null;
    if (!Object.hasOwn(item, 'decisionReason')) item.decisionReason = null;
    counts[item.kind] = (counts[item.kind] || 0) + 1;
  }
  return { generatedAt: new Date(nowMs).toISOString(), comparisonStatus, items, counts };
}

function toSafeDiff(diff) {
  return {
    generatedAt: diff.generatedAt,
    comparisonStatus: diff.comparisonStatus || 'complete',
    counts: diff.counts,
    items: diff.items.map((item) => ({
      kind: item.kind,
      observedKind: item.observedKind || item.kind,
      decisionAction: item.decisionAction || null,
      decisionReason: item.decisionReason || null,
      sourceTerminalIdentityBasis: item.sourceTerminalIdentityBasis || null,
      sourceTerminalUsernameMatch: item.sourceTerminalUsernameMatch || null,
      source: item.source,
      relativePath: item.relativePath,
      fileName: item.fileName,
      issues: item.issues,
      availability: item.availability || null,
      availabilityReason: item.availabilityReason || null,
      token: item.token
        ? {
            source: item.token.source,
            relativePath: item.token.relativePath,
            fileName: item.token.fileName,
            historical: item.token.historical === true,
            parseStatus: item.token.parseStatus,
            parseError: item.token.parseError || null,
            email: item.token.email,
            accountId: item.token.accountId,
            userId: item.token.userId,
            expiresAt: item.token.expiresAt,
            expiryStatus: item.token.expiryStatus || null,
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
            credentialExpiresAt: item.account.credentialExpiresAt,
            tokenFingerprints: item.account.tokenFingerprints,
            credentialPresence: item.account.credentialPresence,
            groupIds: item.account.groupIds,
          }
        : null,
    })),
  };
}

module.exports = {
  accountKeys,
  hasStrongIdentity,
  strongIdentityContradiction,
  identitiesStronglyCompatible,
  strongIdentitiesFullyMatch,
  identitiesCompatible,
  ambiguousAccountHints,
  isExpired,
  isExpiryInvalid,
  accountCredentialPresence,
  credentialsInSync,
  credentialDifferenceReason,
  sourceTerminalEvidence,
  sourceTerminalStatus,
  sourceStateImportDecision,
  isExpectedSub2ApiAccount,
  matchedAccountImportDecision,
  buildDiff,
  toSafeDiff,
};
