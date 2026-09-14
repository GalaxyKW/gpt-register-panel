const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { readGptRegisterSources, toSafeSources } = require('./adapters/gptRegisterFs');
const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const {
  buildDiff,
  toSafeDiff,
  isExpired,
  isExpiryInvalid,
  strongIdentityContradiction,
  identitiesCompatible,
  identitiesStronglyCompatible,
  strongIdentitiesFullyMatch,
  ambiguousAccountHints,
  hasStrongIdentity,
  accountKeys,
  accountCredentialPresence,
  credentialsInSync,
  sourceTerminalStatus,
  sourceStateImportDecision,
  isExpectedSub2ApiAccount,
  matchedAccountImportDecision,
} = require('./diff');
const {
  buildRows,
  filterRows,
  statusOptions,
  diffOptions,
  availabilityOptions,
} = require('./view');
const { getAccountAvailability } = require('./accountAvailability');
const { interruptedJobError, throwIfJobInterrupted } = require('./jobLifecycle');
const { assertAuditLogCheckpoint, redactText } = require('./logger');
const {
  parseJwtPayload,
  normalizeIdentityValue,
  tokenCredentialField,
} = require('./lib/token');
const { withControlPlaneLock } = require('./taskCoordinator');
const { ensureDirectoryTree, syncDirectory } = require('./lib/safeFs');

let syncQueue = Promise.resolve();
const OPENAI_CODEX_OAUTH_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const POSTFLIGHT_READ_ATTEMPTS = 3;
const POSTFLIGHT_RETRY_DELAY_MS = 25;

function safeErrorMessage(error) {
  return redactText(String(error?.message || error || 'unknown error')).slice(0, 1000);
}

function safeRemoteError(value) {
  if (value === undefined || value === null || value === '') return null;
  let detail = value;
  if (value && typeof value === 'object') {
    const code = value.code ?? value.status ?? value.error_code ?? value.errorCode;
    const message = value.message ?? value.error_message ?? value.errorMessage ?? value.error;
    if (code !== undefined || message !== undefined) {
      detail = [code === undefined ? '' : String(code), message === undefined ? '' : String(message)]
        .filter(Boolean)
        .join(': ');
    } else {
      try { detail = JSON.stringify(value); } catch { detail = '[unavailable remote error]'; }
    }
  }
  return redactText(String(detail)).slice(0, 1000);
}

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Logging must never change the outcome of a sync operation.
  }
}

function rethrowIfJobInterrupted(error, signal) {
  if (error?.code === 'JOB_INTERRUPTED') throw error;
  throwIfJobInterrupted(signal);
}

function reconciliationRequiredError(error, reason = 'post_write_verification') {
  const target = error instanceof Error
    ? error
    : new Error('Sub2API 写入结果需要人工对账');
  if (!target.code) target.code = 'SUB2API_WRITE_RECONCILIATION_REQUIRED';
  target.writeOutcomeUnknown = true;
  target.requiresReconciliation = true;
  const normalizedReason = String(reason || '').trim().toLowerCase();
  target.reconciliationReason = /^[a-z0-9_]{1,64}$/.test(normalizedReason)
    ? normalizedReason
    : 'post_write_verification';
  return target;
}

function writeRequiresReconciliation(error) {
  return error?.writeOutcomeUnknown === true || error?.requiresReconciliation === true;
}

function throwIfPostWriteInterrupted(signal) {
  if (!signal?.aborted) return;
  throw reconciliationRequiredError(
    interruptedJobError('面板停机中断了 Sub2API 写后核验，需要对账'),
    'post_write_abort',
  );
}

async function postflightRetryDelay(milliseconds, signal) {
  throwIfJobInterrupted(signal);
  await new Promise((resolve, reject) => {
    let timer;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      try { signal?.removeEventListener('abort', onAbort); } catch {}
    };
    const onAbort = () => {
      cleanup();
      reject(interruptedJobError());
    };
    if (signal && typeof signal.addEventListener === 'function') {
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) {
        onAbort();
        return;
      }
    }
    timer = setTimeout(() => {
      cleanup();
      resolve();
    }, milliseconds);
  });
}

async function retryPostflightRead(callback, options = {}) {
  const signal = options.signal;
  let lastError;
  for (let attempt = 1; attempt <= POSTFLIGHT_READ_ATTEMPTS; attempt += 1) {
    throwIfJobInterrupted(signal);
    try {
      const value = await callback();
      throwIfJobInterrupted(signal);
      return value;
    } catch (error) {
      rethrowIfJobInterrupted(error, signal);
      lastError = error;
      if (attempt < POSTFLIGHT_READ_ATTEMPTS) {
        await postflightRetryDelay(POSTFLIGHT_RETRY_DELAY_MS * attempt, signal);
      }
    }
  }
  throw lastError;
}

function queueCancelableRun(predecessor, callback, signal) {
  let started = false;
  let stopListening = () => {};
  const run = predecessor.then(async () => {
    started = true;
    stopListening();
    throwIfJobInterrupted(signal);
    return callback();
  });
  if (!signal || typeof signal.addEventListener !== 'function') {
    return { run, result: run };
  }
  const result = new Promise((resolve, reject) => {
    let settled = false;
    const settle = (callbackFn, value) => {
      if (settled) return;
      settled = true;
      stopListening();
      callbackFn(value);
    };
    const onAbort = () => {
      if (!started) settle(reject, interruptedJobError());
    };
    stopListening = () => {
      try { signal.removeEventListener('abort', onAbort); } catch {}
    };
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
    run.then(
      (value) => settle(resolve, value),
      (error) => settle(reject, error),
    );
  });
  return { run, result };
}

function withSyncLock(callback, options = {}) {
  const queued = queueCancelableRun(syncQueue, callback, options.signal);
  const run = queued.run;
  syncQueue = run.catch(() => {});
  return queued.result;
}

function configuredForSub2Api() {
  return Boolean(
    process.env.SUB2API_BASE_URL
      && (process.env.SUB2API_ADMIN_API_KEY || process.env.SUB2API_JWT),
  );
}

function safeVersionInput(snapshot) {
  const sub2apiReadStatus = snapshot.sub2apiReadStatus
    || (snapshot.sub2apiRead === true ? 'ok' : (snapshot.apiError ? 'failed' : 'omitted'));
  return {
    // A failed or intentionally omitted remote read must never produce the
    // same CAS token as a confirmed, genuinely empty Sub2API account list.
    sub2apiRead: snapshot.sub2apiRead === true,
    sub2apiReadFailed: Boolean(snapshot.apiError),
    sub2apiReadStatus,
    tokens: snapshot.sources.tokens.map((token) => ({
      source: token.source,
      relativePath: token.relativePath,
      mtimeMs: token.mtimeMs,
      historical: token.historical === true,
      parseStatus: token.parseStatus,
      expiryStatus: token.expiryStatus,
      contentHash: token.contentHash || null,
      identityKeys: token.identityKeys,
      fingerprints: token.fingerprints,
      expiresAt: token.expiresAt,
      lastRefresh: token.lastRefresh,
      disabled: token.disabled,
    })),
    usernameContentHash: snapshot.sources.usernameContentHash || null,
    usernameMtimeMs: Number(snapshot.sources.usernameMtimeMs) || 0,
    usernameSize: Number(snapshot.sources.usernameSize) || 0,
    accounts: snapshot.accounts.map((account) => ({
      id: account.id,
      name: account.name,
      status: account.status,
      schemaValid: account.schemaValid,
      identityConflict: account.identityConflict,
      fingerprintConflict: account.fingerprintConflict,
      credentialsStatusConflict: account.credentialsStatusConflict,
      statusKnown: account.statusKnown,
      schedulable: account.schedulable,
      schedulableKnown: account.schedulableKnown,
      tempUnschedulableUntil: account.tempUnschedulableUntil,
      tempUnschedulableUntilStatus: account.tempUnschedulableUntilStatus,
      tempUnschedulableReason: account.tempUnschedulableReason,
      rateLimitResetAt: account.rateLimitResetAt,
      rateLimitResetStatus: account.rateLimitResetStatus,
      overloadUntil: account.overloadUntil,
      overloadUntilStatus: account.overloadUntilStatus,
      autoPauseOnExpired: account.autoPauseOnExpired,
      expiresAt: account.expiresAt,
      expiryStatus: account.expiryStatus,
      credentialExpiresAt: account.credentialExpiresAt,
      credentialExpiryStatus: account.credentialExpiryStatus,
      identityKeys: account.identityKeys,
      tokenFingerprints: account.tokenFingerprints,
      credentialPresence: account.credentialPresence,
      groupIds: account.groupIds,
    })),
  };
}

function snapshotVersion(snapshot) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(safeVersionInput(snapshot)))
    .digest('hex');
}

function confirmedSub2ApiRead(snapshot) {
  const internal = snapshot?._internal && typeof snapshot._internal === 'object'
    ? snapshot._internal
    : snapshot;
  if (!internal) return false;
  const internalReadStatus = internal.sub2apiReadStatus
    || (internal.sub2apiRead === true ? 'ok' : (internal.apiError ? 'failed' : 'omitted'));
  const publicReadStatus = snapshot?.sub2api?.readStatus;
  return internalReadStatus === 'ok'
    && (publicReadStatus === undefined || publicReadStatus === 'ok')
    && internal.sub2apiRead === true
    && !internal.apiError
    && !snapshot?.sub2api?.apiError;
}

function normalizeAccountUsage(account) {
  if (!account?.usage || typeof account.usage !== 'object') return null;
  if (account.usage.historical || account.usage.current) return account.usage;
  return {
    historical: account.usage,
    current: null,
    currentWindowStart: null,
    currentWindowEnd: null,
  };
}

function safeAccountForSnapshot(account) {
  return {
    id: account.id,
    name: account.name,
    platform: account.platform,
    type: account.type,
    status: account.status,
    schemaValid: account.schemaValid,
    identityConflict: account.identityConflict,
    fingerprintConflict: account.fingerprintConflict,
    credentialsStatusConflict: account.credentialsStatusConflict,
    statusKnown: account.statusKnown,
    schedulable: account.schedulable,
    schedulableKnown: account.schedulableKnown,
    tempUnschedulableUntil: account.tempUnschedulableUntil,
    tempUnschedulableUntilStatus: account.tempUnschedulableUntilStatus || null,
    tempUnschedulableReason: account.tempUnschedulableReason || null,
    rateLimitResetAt: account.rateLimitResetAt || null,
    rateLimitResetStatus: account.rateLimitResetStatus || null,
    overloadUntil: account.overloadUntil || null,
    overloadUntilStatus: account.overloadUntilStatus || null,
    autoPauseOnExpired: account.autoPauseOnExpired === undefined
      ? true
      : account.autoPauseOnExpired,
    errorMessage: safeRemoteError(account.errorMessage),
    email: account.email,
    accountId: account.accountId,
    userId: account.userId,
    expiresAt: account.expiresAt,
    expiryStatus: account.expiryStatus || null,
    credentialExpiresAt: account.credentialExpiresAt || null,
    credentialExpiryStatus: account.credentialExpiryStatus || null,
    tokenFingerprints: account.tokenFingerprints,
    credentialPresence: account.credentialPresence,
    groupIds: account.groupIds,
    usage: account.usage || null,
    usageError: safeRemoteError(account.usageError),
  };
}

async function readSub2ApiAccounts(client, options = {}) {
  const signal = options.signal;
  throwIfJobInterrupted(signal);
  const accounts = await client.listAccounts({
    platform: 'openai',
    type: 'oauth',
    pageSize: 200,
    signal,
  });
  throwIfJobInterrupted(signal);
  let statsError = null;
  const ids = accounts.map((account) => account.id).filter((id) => Number.isFinite(id) && id > 0);
  if (ids.length > 0) {
    try {
      const tableStats = await client.getBatchTableUsageStats(ids, { signal });
      throwIfJobInterrupted(signal);
      for (const account of accounts) {
        account.usage = tableStats.stats[String(account.id)] || normalizeAccountUsage(account);
        if (tableStats.errors?.[String(account.id)]) {
          account.usageError = safeRemoteError(tableStats.errors[String(account.id)]);
        }
      }
      const failedCount = Object.keys(tableStats.errors || {}).length;
      if (failedCount > 0) statsError = failedCount + ' 个账号统计读取失败';
    } catch (error) {
      rethrowIfJobInterrupted(error, signal);
      statsError = safeErrorMessage(error);
      for (const account of accounts) account.usage = normalizeAccountUsage(account);
    }
  }
  return { accounts, statsError };
}

async function buildSnapshot(query = new URLSearchParams(), options = {}) {
  const startedAt = Date.now();
  const logger = options.logger;
  const signal = options.signal;
  const logContext = {
    requestId: options.requestId || null,
    jobId: options.jobId || null,
    actor: options.actor || null,
  };
  const shouldReadSub2Api = options.readSub2Api !== false
    && (query.get('withSub2api') === '1' || configuredForSub2Api());
  writeLog(logger, 'info', 'snapshot.started', {
    ...logContext,
    withSub2api: shouldReadSub2Api,
    includeRaw: options.includeRaw === true,
  });
  try {
    throwIfJobInterrupted(signal);
    const sources = readGptRegisterSources({
      includeRaw: options.includeRaw === true,
      strictCompleteSnapshot: options.requireCompleteSources === true,
      rootDirectory: options.rootDirectory,
    });
    throwIfJobInterrupted(signal);
    let accounts = [];
    let apiError = null;
    let statsError = null;
    let readStatus = 'omitted';

    if (shouldReadSub2Api) {
      try {
        const client = options.client || new Sub2ApiAdminClient({ logger, logContext });
        const loaded = await readSub2ApiAccounts(client, { signal });
        accounts = loaded.accounts;
        statsError = loaded.statsError;
        readStatus = 'ok';
      } catch (error) {
        rethrowIfJobInterrupted(error, signal);
        readStatus = 'failed';
        apiError = safeErrorMessage(error);
        writeLog(logger, 'warn', 'snapshot.sub2api_failed', { ...logContext, error: apiError });
      }
    }

    const internal = {
      generatedAt: sources.generatedAt,
      sources,
      accounts,
      apiError,
      statsError,
      sub2apiReadStatus: readStatus,
      sub2apiRead: readStatus === 'ok',
    };
    const diff = buildDiff(sources.tokens, accounts, {
      includeHistorical: query.get('includeHistorical') === '1',
      sub2apiReadStatus: readStatus,
      usernames: sources.usernames,
    });
    const allRows = buildRows(diff, { usernames: sources.usernames });
    const rows = filterRows(allRows, {
      search: query.get('search'),
      status: query.get('status'),
      source: query.get('source'),
      diffKind: query.get('diff'),
      availability: query.get('availability'),
    });
    const version = snapshotVersion(internal);
    const result = {
      readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
      generatedAt: sources.generatedAt,
      version,
      sources: toSafeSources(sources),
      sub2api: {
        readStatus,
        accountCount: readStatus === 'ok' ? accounts.length : null,
        apiError,
        statsError,
        statsAvailable: accounts.some((account) => account.usage?.historical || account.usage?.current),
        accounts: accounts.map(safeAccountForSnapshot),
      },
      diff: toSafeDiff(diff),
      rows,
      filters: {
        statuses: statusOptions(allRows),
        sources: ['tokens', 'use_token', 'sub2api'],
        diffKinds: diffOptions(allRows),
        availabilities: availabilityOptions(allRows),
      },
      _internal: options.includeInternal === true ? internal : undefined,
    };
    throwIfJobInterrupted(signal);
    writeLog(logger, 'info', 'snapshot.completed', {
      ...logContext,
      version,
      durationMs: Date.now() - startedAt,
      tokenCount: sources.summary.tokenCount,
      validTokenCount: sources.summary.validTokenCount,
      sub2apiReadStatus: readStatus,
      accountCount: readStatus === 'ok' ? accounts.length : null,
      rowCount: rows.length,
      diffCounts: diff.counts,
      apiError,
      statsError,
    });
    return result;
  } catch (error) {
    writeLog(logger, 'error', 'snapshot.failed', {
      ...logContext,
      durationMs: Date.now() - startedAt,
      error: safeErrorMessage(error),
    });
    throw error;
  }
}

function primaryIdentity(record) {
  return record?.identityKeys?.[0] || 'file:' + String(record?.source || '') + ':' + String(record?.relativePath || record?.fileName || '');
}

function candidateKey(record) {
  return 'token:' + String(record.source) + ':' + String(record.relativePath || record.fileName);
}

function compareNaturalPath(leftValue, rightValue) {
  const left = String(leftValue || '');
  const right = String(rightValue || '');
  const naturalOrder = left.localeCompare(
    right,
    'en',
    { numeric: true, sensitivity: 'base' },
  );
  if (naturalOrder !== 0) return naturalOrder;
  if (left === right) return 0;

  // The natural collation intentionally ignores case and some Unicode
  // distinctions. Resolve those ties using the original UTF-8 bytes so a
  // token winner never depends on filesystem or API input order. The final
  // code-unit comparison also keeps this a strict total order for malformed
  // surrogate strings that UTF-8 encodes as the same replacement character.
  const byteOrder = Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
  if (byteOrder !== 0) return byteOrder;
  return left < right ? -1 : 1;
}

function compareTokenRecordFreshness(leftRecord, rightRecord, nowMs = Date.now()) {
  const left = leftRecord || {};
  const right = rightRecord || {};
  const leftExpiryInvalid = isExpiryInvalid(left);
  const rightExpiryInvalid = isExpiryInvalid(right);
  if (leftExpiryInvalid !== rightExpiryInvalid) return leftExpiryInvalid ? 1 : -1;

  const leftExpired = isExpired(left, nowMs);
  const rightExpired = isExpired(right, nowMs);
  if (leftExpired !== rightExpired) return leftExpired ? 1 : -1;

  const leftDisabled = left.disabled === true;
  const rightDisabled = right.disabled === true;
  if (leftDisabled !== rightDisabled) return leftDisabled ? 1 : -1;

  for (const field of ['expiresAt', 'lastRefresh']) {
    const leftValue = dateMilliseconds(left[field]);
    const rightValue = dateMilliseconds(right[field]);
    if (leftValue !== rightValue) return leftValue > rightValue ? -1 : 1;
  }

  const leftMtime = Number(left.mtimeMs) || 0;
  const rightMtime = Number(right.mtimeMs) || 0;
  if (leftMtime !== rightMtime) return leftMtime > rightMtime ? -1 : 1;

  // Credential presence is only a deterministic final tie-breaker. It must
  // never make an earlier-expiring token beat a later valid token.
  for (const field of ['access', 'refresh']) {
    const leftHasCredential = Boolean(left.fingerprints?.[field]);
    const rightHasCredential = Boolean(right.fingerprints?.[field]);
    if (leftHasCredential !== rightHasCredential) return leftHasCredential ? -1 : 1;
  }

  // Prefer the primary tokens directory only when all freshness signals tie.
  const leftSourcePriority = left.source === 'tokens' ? 1 : 0;
  const rightSourcePriority = right.source === 'tokens' ? 1 : 0;
  if (leftSourcePriority !== rightSourcePriority) {
    return leftSourcePriority > rightSourcePriority ? -1 : 1;
  }
  return compareNaturalPath(left.relativePath, right.relativePath);
}

function identityValues(keys = [], prefix) {
  const values = new Set();
  for (const key of keys || []) {
    const text = String(key || '').trim();
    if (!text.toLowerCase().startsWith(prefix)) continue;
    const value = normalizeIdentityValue(prefix, text.slice(prefix.length));
    if (value) values.add(value);
  }
  return values;
}

function aggregateIdentityKeys(records = []) {
  const keys = [];
  for (const prefix of ['account:', 'user:', 'email:']) {
    const values = new Set();
    for (const record of records) {
      for (const value of identityValues(record?.identityKeys || [], prefix)) values.add(value);
    }
    for (const value of [...values].sort((left, right) => left.localeCompare(right, 'en'))) {
      keys.push(prefix + value);
    }
  }
  return keys;
}

function candidateIdentityKey(records, selected) {
  const keys = aggregateIdentityKeys(records);
  // A ChatGPT user can belong to multiple workspaces. Prefer user ID for the
  // candidate key so two members of the same workspace are not collapsed.
  return keys.find((key) => key.startsWith('user:'))
    || keys.find((key) => key.startsWith('account:'))
    || keys.find((key) => key.startsWith('email:'))
    || primaryIdentity(selected);
}

function identitySummary(keys = []) {
  return {
    account: identityValues(keys, 'account:'),
    user: identityValues(keys, 'user:'),
    email: identityValues(keys, 'email:'),
  };
}

function markIdentityConflict(candidate, reason) {
  if (!candidate.identityConflict) candidate.identityConflictReason = reason;
  candidate.identityConflict = true;
}

function collectCandidates(sources, options = {}) {
  const nowMs = Number(options.nowMs || Date.now());
  const records = (sources.tokens || [])
    .filter((record) => record.parseStatus === 'ok' && record.raw && record.historical !== true)
    .sort((left, right) => compareNaturalPath(left.relativePath, right.relativePath));
  const parent = records.map((_, index) => index);
  const find = (index) => {
    let root = index;
    while (parent[root] !== root) root = parent[root];
    while (parent[index] !== index) {
      const next = parent[index];
      parent[index] = root;
      index = next;
    }
    return root;
  };
  const union = (left, right) => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) parent[rightRoot] = leftRoot;
  };
  const index = new Map();
  records.forEach((record, recordIndex) => {
    const keys = record.identityKeys || [];
    const strongKeys = keys.filter((key) => /^(account|user):/i.test(String(key || '')));
    const groupingKeys = strongKeys.length > 0
      ? strongKeys
      : keys.filter((key) => /^email:/i.test(String(key || '')));
    for (const key of groupingKeys) {
      const bucket = index.get(key) || [];
      for (const otherIndex of bucket) {
        if (identitiesCompatible(keys, records[otherIndex].identityKeys || [])) {
          union(recordIndex, otherIndex);
        }
      }
      bucket.push(recordIndex);
      index.set(key, bucket);
    }
  });
  const groups = new Map();
  records.forEach((record, recordIndex) => {
    const root = find(recordIndex);
    const list = groups.get(root) || [];
    list.push(record);
    groups.set(root, list);
  });
  const candidates = [...groups.values()].map((groupRecords) => {
    const recordsByFreshness = [...groupRecords];
    recordsByFreshness.sort((left, right) => compareTokenRecordFreshness(left, right, nowMs));
    const selected = recordsByFreshness[0];
    const sourceIdentityKeys = aggregateIdentityKeys(groupRecords);
    const summary = identitySummary(sourceIdentityKeys);
    const identityKey = candidateIdentityKey(groupRecords, selected);
    const identityConflict = summary.account.size > 1 || summary.user.size > 1;
    const candidate = {
      key: candidateKey(selected),
      identityKey,
      sourceIdentityKeys,
      record: selected,
      duplicates: groupRecords.length > 1,
      // Different fingerprints are normal when a token was refreshed. The
      // freshness comparator above already selected the winner.
      conflictingVersions: false,
      identityConflict,
      identityConflictReason: identityConflict ? 'conflicting_strong_identity' : null,
      records: recordsByFreshness,
    };
    if (!hasStrongIdentity(sourceIdentityKeys)) {
      markIdentityConflict(candidate, 'source_identity_insufficient');
    }
    Object.defineProperty(candidate, '_identitySummary', {
      value: summary,
      enumerable: false,
    });
    return candidate;
  });

  // Email is only a hint. If two strong candidates share an email but expose
  // no comparable strong-ID dimension (for example account-only vs user-only),
  // creating both could duplicate one real account. Fail closed instead.
  const emailIndex = new Map();
  for (const candidate of candidates) {
    for (const email of candidate._identitySummary.email) {
      const bucket = emailIndex.get(email) || [];
      bucket.push(candidate);
      emailIndex.set(email, bucket);
    }
  }
  for (const bucket of emailIndex.values()) {
    for (let leftIndex = 0; leftIndex < bucket.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < bucket.length; rightIndex += 1) {
        const left = bucket[leftIndex];
        const right = bucket[rightIndex];
        const comparable = (left._identitySummary.account.size > 0 && right._identitySummary.account.size > 0)
          || (left._identitySummary.user.size > 0 && right._identitySummary.user.size > 0);
        if (!comparable && hasStrongIdentity(left.sourceIdentityKeys)
            && hasStrongIdentity(right.sourceIdentityKeys)) {
          markIdentityConflict(left, 'incomparable_strong_identity');
          markIdentityConflict(right, 'incomparable_strong_identity');
        }
      }
    }
  }

  return candidates.sort((left, right) => compareNaturalPath(
    left.record.relativePath,
    right.record.relativePath,
  ));
}

function accountMatches(candidate, accounts) {
  const matches = new Map();
  for (const account of accounts || []) {
    if (account?.id === undefined || account?.id === null) continue;
    const keys = Array.isArray(account.identityKeys) && account.identityKeys.length > 0
      ? account.identityKeys
      : accountKeys(account);
    if (strongIdentitiesFullyMatch(candidate.sourceIdentityKeys || [], keys)) {
      matches.set(String(account.id), account);
    }
  }
  return [...matches.values()];
}

function parseCanonicalFreeName(value) {
  if (typeof value !== 'string') return null;
  const match = /^free([0-9]{5})$/.exec(value);
  if (!match) return null;
  const number = Number(match[1]);
  return Number.isSafeInteger(number) && number >= 1 && number <= 99999 ? number : null;
}

function freeNameCollisionKey(value) {
  if (typeof value !== 'string') return null;
  const folded = value.trim().toLowerCase();
  return /^free[0-9]{5}$/.test(folded) ? folded : null;
}

function accountsMatchingFreeName(accounts, expectedName) {
  const expectedNumber = parseCanonicalFreeName(expectedName);
  if (expectedNumber === null) return [];
  const expectedKey = freeName(expectedNumber);
  return (accounts || []).filter((account) => (
    freeNameCollisionKey(account?.name) === expectedKey
  ));
}

function nextFreeNumber(accounts) {
  let maximum = 0;
  for (const account of accounts) {
    const number = parseCanonicalFreeName(account?.name);
    if (number !== null) maximum = Math.max(maximum, number);
  }
  return maximum + 1;
}

function freeName(number) {
  if (!Number.isSafeInteger(number) || number < 1 || number > 99999) return null;
  return 'free' + String(number).padStart(5, '0');
}

function selectedTokenRecords(candidate, selectedKeys) {
  if (!Array.isArray(selectedKeys) || selectedKeys.length === 0) return [];
  const keys = new Set(selectedKeys.map((key) => String(key)));
  return candidate.records.filter((record) => keys.has(candidateKey(record)));
}

function selectedCandidate(candidate, selectedKeys) {
  if (!Array.isArray(selectedKeys) || selectedKeys.length === 0) return true;
  // Selection keys come from source-backed table rows. Do not accept a
  // candidate identity key or a Sub2API numeric account key here: both use
  // the `account:` namespace and can otherwise authorize an unrelated local
  // token whose ChatGPT account ID happens to equal a remote numeric ID.
  return selectedTokenRecords(candidate, selectedKeys).length > 0;
}

function sourceSelectionMetadata(candidate, selectedKeys) {
  const selectedRecords = selectedTokenRecords(candidate, selectedKeys);
  const selectedSuperseded = selectedRecords.filter((record) => (
    candidateKey(record) !== candidate.key
  ));
  const relativePath = (record) => record.relativePath || record.fileName || '';
  return {
    sourceVersionCount: candidate.records.length,
    selectedSourcePaths: selectedRecords.map(relativePath).filter(Boolean),
    selectedSupersededPaths: selectedSuperseded.map(relativePath).filter(Boolean),
    selectedSourceSuperseded: selectedSuperseded.length > 0,
  };
}

function assertImportSelectionCovered(candidates, selectedKeys) {
  if (!Array.isArray(selectedKeys) || selectedKeys.length > 500
      || selectedKeys.some((key) => typeof key !== 'string' || !key || key.length > 512)) {
    const error = new Error('导入选择参数无效，请刷新账号列表后重新选择');
    error.code = 'IMPORT_SELECTION_INVALID';
    throw error;
  }
  if (selectedKeys.length === 0) return;
  const availableKeys = new Set();
  for (const candidate of candidates) {
    for (const record of candidate.records || []) availableKeys.add(candidateKey(record));
  }
  const unknownCount = selectedKeys.reduce((count, key) => (
    typeof key === 'string' && availableKeys.has(key) ? count : count + 1
  ), 0);
  if (unknownCount === 0) return;
  const error = new Error('所选项目不再对应可导入的 token，请刷新账号列表后重新选择');
  error.code = 'IMPORT_SELECTION_MISMATCH';
  error.unknownSelectionCount = unknownCount;
  throw error;
}

function dateMilliseconds(value) {
  const timestamp = Date.parse(String(value || ''));
  return Number.isFinite(timestamp) ? timestamp : Number.NEGATIVE_INFINITY;
}

// A single Sub2API account can have both a freshly refreshed token in
// `tokens` and an older copy in `use_token`. Importing both in sequence makes
// the older copy win. Pick one deterministic winner before writing anything.
function compareCandidateFreshness(left, right, nowMs) {
  return compareTokenRecordFreshness(left?.record, right?.record, nowMs);
}

function buildImportPlan(sources, accounts, selectedKeys = []) {
  const nowMs = Date.now();
  const candidates = collectCandidates(sources, { nowMs });
  // A mixed selection used to silently discard unknown, invalid, historical,
  // or Sub2API-only row keys while executing the remaining writes. Require
  // complete coverage so the reviewed selection and the executable plan are
  // always the same set of source rows.
  assertImportSelectionCovered(candidates, selectedKeys);
  const entries = candidates.map((candidate) => {
    const matches = accountMatches(candidate, accounts);
    return {
      candidate,
      matches,
      ambiguousHints: matches.length === 0 ? ambiguousAccountHints(candidate, accounts) : [],
      account: matches.length === 1 ? matches[0] : null,
    };
  });
  const entriesByAccount = new Map();
  for (const entry of entries) {
    if (!entry.account || entry.account.id === undefined || entry.account.id === null) continue;
    const key = String(entry.account.id);
    const bucket = entriesByAccount.get(key) || [];
    bucket.push(entry);
    entriesByAccount.set(key, bucket);
  }
  for (const bucket of entriesByAccount.values()) {
    const contradictory = bucket.some((left, leftIndex) => bucket.some((right, rightIndex) => (
      rightIndex > leftIndex
        && strongIdentityContradiction(
          left.candidate.sourceIdentityKeys,
          right.candidate.sourceIdentityKeys,
        )
    )));
    // A remote row that omits one strong-ID dimension can otherwise make two
    // distinct users in one workspace (or one user in distinct workspaces)
    // look like versions of the same account. Freshness must never resolve a
    // contradictory identity mapping.
    if (contradictory) bucket.forEach((entry) => { entry.remoteIdentityAmbiguous = true; });
  }
  const preferredByAccount = new Map();
  for (const entry of entries) {
    if (!entry.account || entry.candidate.identityConflict
        || !hasStrongIdentity(entry.candidate.sourceIdentityKeys)
        || !selectedCandidate(entry.candidate, selectedKeys)
        || isExpiryInvalid(entry.candidate.record)
        || sourceTerminalStatus(sources?.usernames, entry.candidate.record)) continue;
    const accountId = entry.account.id;
    if (accountId === undefined || accountId === null) continue;
    const key = String(accountId);
    const current = preferredByAccount.get(key);
    if (!current || compareCandidateFreshness(entry.candidate, current.candidate, nowMs) < 0) {
      preferredByAccount.set(key, entry);
    }
  }
  const plan = [];
  let nextNumber = nextFreeNumber(accounts);
  for (const entry of entries) {
    const { candidate, matches, ambiguousHints, account } = entry;
    if (!selectedCandidate(candidate, selectedKeys)) continue;
    const terminalStatus = sourceTerminalStatus(sources?.usernames, candidate.record);
    const sourceDecision = sourceStateImportDecision(candidate.record, { terminalStatus });
    let action = 'create';
    let reason = 'token_only';
    let assignedName = null;
    const preferred = account && account.id !== undefined && account.id !== null
      ? preferredByAccount.get(String(account.id))
      : null;
    const superseded = Boolean(preferred && preferred.candidate !== candidate);
    if (sourceDecision) {
      action = sourceDecision.action;
      reason = sourceDecision.reason;
    } else if (candidate.identityConflict || !hasStrongIdentity(candidate.sourceIdentityKeys)) {
      action = 'conflict';
      reason = candidate.identityConflictReason || 'source_identity_insufficient';
    } else if (matches.length > 1) {
      action = 'conflict';
      reason = 'multiple_sub2api_accounts';
    } else if (ambiguousHints.length > 0) {
      action = 'conflict';
      reason = 'ambiguous_sub2api_identity';
    } else if (entry.remoteIdentityAmbiguous) {
      action = 'conflict';
      reason = 'ambiguous_sub2api_identity';
    } else if (account) {
      assignedName = account.name;
      const decision = matchedAccountImportDecision(candidate.record, account, {
        nowMs,
        terminalStatus,
        superseded,
      });
      action = decision.action;
      reason = decision.reason;
    } else if (candidate.record.disabled) {
      action = 'skip';
      reason = 'source_disabled';
    } else if (isExpired(candidate.record, nowMs)) {
      action = 'skip';
      reason = 'source_token_expired';
    } else {
      assignedName = freeName(nextNumber);
      if (!assignedName) {
        action = 'conflict';
        reason = 'free_name_exhausted';
      } else {
        if (accountsMatchingFreeName(accounts, assignedName).length > 0) {
          action = 'conflict';
          reason = 'free_name_conflict';
        }
        nextNumber += 1;
      }
    }
    const item = {
      key: candidate.key,
      identityKey: candidate.identityKey,
      sourceIdentityKeys: candidate.sourceIdentityKeys || [],
      action,
      reason,
      accountId: account?.id ?? null,
      accountName: assignedName,
      email: candidate.record.email || '',
      source: candidate.record.source,
      relativePath: candidate.record.relativePath,
      fileName: candidate.record.fileName,
      expiresAt: candidate.record.expiresAt || null,
      expiryStatus: candidate.record.expiryStatus || 'missing',
      fingerprints: candidate.record.fingerprints || {},
      duplicateSource: candidate.duplicates,
      conflictingVersions: candidate.conflictingVersions,
      identityConflict: candidate.identityConflict === true,
      identityConflictReason: candidate.identityConflictReason || null,
      availability: account ? getAccountAvailability(account, nowMs).key : 'not_present',
      availabilityReason: account ? getAccountAvailability(account, nowMs).reason : 'not_in_sub2api',
      sourceExpired: isExpired(candidate.record, nowMs),
      sourceDisabled: candidate.record.disabled === true,
      sourceTerminalStatus: terminalStatus,
      supersededBy: superseded ? preferred.candidate.record.relativePath : null,
      ...sourceSelectionMetadata(candidate, selectedKeys),
      _raw: candidate.record.raw,
      _record: candidate.record,
      _account: account,
    };
    plan.push(item);
  }
  return plan;
}

function safeImportItem(item) {
  return {
    key: item.key,
    identityKey: item.identityKey,
    sourceIdentityKeys: item.sourceIdentityKeys || [],
    action: item.action,
    reason: item.reason,
    accountId: item.accountId,
    accountName: item.accountName,
    email: item.email,
    source: item.source,
    relativePath: item.relativePath,
    fileName: item.fileName,
    expiresAt: item.expiresAt,
    expiryStatus: item.expiryStatus || 'missing',
    fingerprints: item.fingerprints,
    duplicateSource: item.duplicateSource,
    conflictingVersions: item.conflictingVersions,
    identityConflict: item.identityConflict === true,
    identityConflictReason: item.identityConflictReason || null,
    availability: item.availability,
    availabilityReason: item.availabilityReason,
    sourceExpired: item.sourceExpired,
    sourceDisabled: item.sourceDisabled,
    sourceTerminalStatus: item.sourceTerminalStatus || null,
    supersededBy: item.supersededBy || null,
    sourceVersionCount: Number(item.sourceVersionCount) || 1,
    selectedSourcePaths: Array.isArray(item.selectedSourcePaths) ? item.selectedSourcePaths : [],
    selectedSupersededPaths: Array.isArray(item.selectedSupersededPaths)
      ? item.selectedSupersededPaths
      : [],
    selectedSourceSuperseded: item.selectedSourceSuperseded === true,
  };
}

function importPlanSummary(plan) {
  const counts = {};
  for (const item of plan) counts[item.action] = (counts[item.action] || 0) + 1;
  return { counts, items: plan.map(safeImportItem) };
}

function configuredGroupIds() {
  const raw = String(process.env.SUB2API_GROUP_IDS || '').trim();
  if (!raw) return [];
  const values = raw.split(',').map((value) => value.trim());
  const ids = values.map((value) => Number(value));
  if (values.some((value, index) => !/^[1-9]\d*$/.test(value)
      || !Number.isSafeInteger(ids[index]) || ids[index] <= 0)) {
    const error = new Error('SUB2API_GROUP_IDS 必须只包含安全正整数');
    error.code = 'SUB2API_GROUP_CONFIG_INVALID';
    throw error;
  }
  return [...new Set(ids)];
}

async function resolveGroupIds(client, options = {}) {
  const signal = options.signal;
  throwIfJobInterrupted(signal);
  const configured = configuredGroupIds();
  if (configured.length > 0) return configured;
  const wanted = String(process.env.SUB2API_GROUP_NAME || 'share').trim().toLowerCase();
  if (!wanted) return [];
  try {
    const groups = await client.listGroups({ signal });
    throwIfJobInterrupted(signal);
    const resolved = groups
      .filter((group) => [group?.name, group?.slug, group?.code]
        .some((value) => String(value || '').trim().toLowerCase() === wanted))
      .map((group) => {
        const value = group?.id;
        if (!['string', 'number'].includes(typeof value)) return null;
        const text = String(value).trim();
        if (!/^[1-9]\d*$/.test(text)) return null;
        return Number(text);
      })
      .filter((id) => Number.isSafeInteger(id) && id > 0);
    if (resolved.length === 0) {
      const error = new Error('未找到配置的 Sub2API 分组：' + wanted);
      error.code = 'SUB2API_GROUP_NOT_FOUND';
      throw error;
    }
    const unique = [...new Set(resolved)];
    if (unique.length !== 1) {
      const error = new Error('配置的 Sub2API 分组名称匹配到多个 ID：' + wanted);
      error.code = 'SUB2API_GROUP_AMBIGUOUS';
      throw error;
    }
    return unique;
  } catch (error) {
    rethrowIfJobInterrupted(error, signal);
    if (['SUB2API_GROUP_NOT_FOUND', 'SUB2API_GROUP_AMBIGUOUS'].includes(error?.code)) throw error;
    const wrapped = new Error('读取 Sub2API 分组失败：' + safeErrorMessage(error));
    wrapped.code = 'SUB2API_GROUP_RESOLVE_FAILED';
    throw wrapped;
  }
}

function safeImportResult(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return null;
  const counterKeys = ['total', 'created', 'updated', 'skipped', 'failed'];
  const counterOrNull = (value) => (
    Number.isSafeInteger(value) && value >= 0 ? value : null
  );
  const counters = Object.fromEntries(counterKeys.map((key) => [key, counterOrNull(result[key])]));
  return {
    success: result.success === false || String(result.success || '').toLowerCase() === 'false'
      || result.ok === false ? false : true,
    schemaValid: counterKeys.every((key) => (
      Object.prototype.hasOwnProperty.call(result, key) && counters[key] !== null
    )),
    accountId: importResultAccountId(result),
    ...counters,
    errorCount: Array.isArray(result.errors) ? result.errors.length : 0,
    warningCount: Array.isArray(result.warnings) ? result.warnings.length : 0,
    message: result.message ? redactText(String(result.message)).slice(0, 500) : null,
  };
}

function importResultItems(result) {
  return Array.isArray(result?.items) ? result.items.filter((item) => item && typeof item === 'object') : [];
}

function importResultAccountId(result) {
  const direct = Number(result?.account_id ?? result?.accountId);
  if (Number.isSafeInteger(direct) && direct > 0) return direct;
  const ids = [...new Set(importResultItems(result)
    .map((item) => Number(item.account_id ?? item.accountId))
    .filter((id) => Number.isSafeInteger(id) && id > 0))];
  return ids.length === 1 ? ids[0] : null;
}

function importResultAction(result) {
  const actions = [...new Set(importResultItems(result)
    .map((item) => String(item.action || '').trim().toLowerCase())
    .filter(Boolean))];
  return actions.length === 1 ? actions[0] : null;
}

function assertImportResultSucceeded(result) {
  const failed = Number(result?.failed || 0);
  const errorCount = Array.isArray(result?.errors) ? result.errors.length : 0;
  const explicitFailure = result?.success === false
    || String(result?.success || '').toLowerCase() === 'false'
    || result?.ok === false
    || Boolean(result?.error);
  if (failed <= 0 && errorCount === 0 && !explicitFailure) return;
  const error = new Error('Sub2API 导入返回部分失败，未确认该账号已更新');
  error.code = 'SUB2API_PARTIAL_IMPORT';
  error.result = safeImportResult(result);
  throw error;
}

async function verifyImportedAccount(client, item, result, logger, context = {}, options = {}) {
  const signal = options.signal;
  throwIfJobInterrupted(signal);
  const reportedId = importResultAccountId(result);
  let account = Number.isSafeInteger(reportedId) && reportedId > 0
    ? await retryPostflightRead(
        () => client.getAccount(reportedId, { signal }),
        { signal },
      )
    : null;
  throwIfJobInterrupted(signal);
  if (!account) {
    const accounts = await retryPostflightRead(
      () => client.listAccounts({
        platform: 'openai',
        type: 'oauth',
        pageSize: 200,
        sortBy: 'id',
        sortOrder: 'asc',
        requireTotal: true,
        signal,
      }),
      { signal },
    );
    throwIfJobInterrupted(signal);
    const matches = accounts.filter((candidate) => strongIdentitiesFullyMatch(
      item.sourceIdentityKeys?.length ? item.sourceIdentityKeys : item._account?.identityKeys || [item.identityKey],
      candidate.identityKeys || accountKeys(candidate),
    ));
    if (matches.length !== 1) {
      const error = new Error('导入后无法唯一定位 Sub2API 账号');
      error.code = 'SUB2API_IMPORT_VERIFY_NOT_FOUND';
      throw error;
    }
    account = matches[0];
  }
  verifyTargetIdentity(item, account, reportedId);
  const expectedIdentity = item.sourceIdentityKeys?.length
    ? item.sourceIdentityKeys
    : item._account?.identityKeys || [item.identityKey];
  const actualIdentity = account.identityKeys || accountKeys(account);
  if (!strongIdentitiesFullyMatch(expectedIdentity, actualIdentity)) {
    const error = new Error('导入后账号身份与来源不一致');
    error.code = 'SUB2API_IMPORT_VERIFY_IDENTITY_MISMATCH';
    throw error;
  }
  const actualFingerprint = verifyTargetFingerprint(item, account);
  // update_existing=false is not a create-only compare-and-swap in Sub2API:
  // a matching account that appears after its initial list can still race with
  // CreateAccount. Re-list every account type after the write and fail closed
  // unless both the strong identity and allocated free name resolve uniquely
  // to the reported row. Do not attempt an unsafe automatic rollback or
  // deletion here.
  const accounts = await retryPostflightRead(
    () => client.listAccounts({
      pageSize: 200,
      sortBy: 'id',
      sortOrder: 'asc',
      requireTotal: true,
      signal,
    }),
    { signal },
  );
  throwIfJobInterrupted(signal);
  const identityMatches = accountMatches({ sourceIdentityKeys: expectedIdentity }, accounts);
  if (identityMatches.length !== 1 || Number(identityMatches[0]?.id) !== Number(account.id)) {
    throw targetVerificationError(
      '导入后发现来源强身份对应多个 Sub2API 账号',
      'SUB2API_CREATE_RACE_IDENTITY_CONFLICT',
    );
  }
  const expectedName = item?.accountName;
  const nameMatches = accountsMatchingFreeName(accounts, expectedName);
  if (parseCanonicalFreeName(expectedName) === null
      || String(account?.name || '') !== expectedName
      || nameMatches.length !== 1
      || Number(nameMatches[0]?.id) !== Number(account.id)) {
    throw targetVerificationError(
      '导入后发现 Sub2API 账号名称发生竞态或冲突',
      'SUB2API_CREATE_RACE_NAME_CONFLICT',
    );
  }
  writeLog(logger, 'info', 'import.account_verified', {
    ...context,
    accountId: account.id,
    accountName: account.name || null,
    fingerprint: actualFingerprint,
  });
  return {
    accountId: account.id,
    accountName: account.name || null,
    fingerprint: actualFingerprint,
    status: account.status || null,
  };
}

function targetVerificationError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function verifyTargetIdentity(item, account, expectedId = null) {
  const actualId = Number(account?.id);
  if (!Number.isSafeInteger(actualId) || actualId <= 0
      || (expectedId !== null && actualId !== Number(expectedId))) {
    throw targetVerificationError('Sub2API 返回的账号 ID 与计划目标不一致', 'SUB2API_TARGET_ID_MISMATCH');
  }
  if (account?.schemaValid === false) {
    throw targetVerificationError('Sub2API 目标账号结构存在冲突', 'SUB2API_TARGET_SCHEMA_INVALID');
  }
  if (!isExpectedSub2ApiAccount(account)) {
    throw targetVerificationError('Sub2API 目标不是 OpenAI OAuth 账号', 'SUB2API_TARGET_KIND_MISMATCH');
  }
  const expectedIdentity = item.sourceIdentityKeys || [];
  const actualIdentity = account.identityKeys || accountKeys(account);
  if (!hasStrongIdentity(expectedIdentity)
      || !strongIdentitiesFullyMatch(expectedIdentity, actualIdentity)) {
    throw targetVerificationError('Sub2API 目标账号强身份与来源不一致', 'SUB2API_TARGET_IDENTITY_MISMATCH');
  }
  return actualId;
}

function verifyPlannedTargetIdentity(item, account) {
  const plannedAccount = item?._account;
  const plannedIdentity = plannedAccount?.identityKeys?.length
    ? plannedAccount.identityKeys
    : accountKeys(plannedAccount);
  if (!plannedAccount || !hasStrongIdentity(plannedIdentity)) {
    throw targetVerificationError(
      '更新计划缺少可绑定的 Sub2API 目标强身份',
      'SUB2API_TARGET_SNAPSHOT_IDENTITY_MISSING',
    );
  }
  const actualIdentity = account?.identityKeys?.length
    ? account.identityKeys
    : accountKeys(account);
  for (const prefix of ['account:', 'user:']) {
    const plannedValues = identityValues(plannedIdentity, prefix);
    const actualValues = identityValues(actualIdentity, prefix);
    if (plannedValues.size !== actualValues.size
        || [...plannedValues].some((value) => !actualValues.has(value))) {
      throw targetVerificationError(
        'Sub2API 目标账号强身份与计划快照不一致',
        'SUB2API_TARGET_CHANGED',
      );
    }
  }
}

function verifyUpdatedTargetIdentity(item, account) {
  const verifiedAccount = item?._verifiedAccount || item?._account;
  const verifiedIdentity = verifiedAccount?.identityKeys?.length
    ? verifiedAccount.identityKeys
    : accountKeys(verifiedAccount);
  const actualIdentity = account?.identityKeys?.length
    ? account.identityKeys
    : accountKeys(account);
  for (const prefix of ['account:', 'user:']) {
    const sourceValues = identityValues(item?.sourceIdentityKeys || [], prefix);
    if (sourceValues.size > 1) {
      throw targetVerificationError(
        '更新来源的强身份字段存在冲突',
        'SOURCE_IDENTITY_CONFLICT',
      );
    }
    const expectedValues = sourceValues.size === 1
      ? sourceValues
      : identityValues(verifiedIdentity, prefix);
    const actualValues = identityValues(actualIdentity, prefix);
    if (expectedValues.size !== actualValues.size
        || [...expectedValues].some((value) => !actualValues.has(value))) {
      throw targetVerificationError(
        'Sub2API 更新后的强身份与已验证目标不一致',
        'SUB2API_TARGET_CHANGED',
      );
    }
  }
}

function verifyTargetFingerprint(item, account) {
  const expectedFingerprint = item.fingerprints?.access || null;
  const actualFingerprint = account?.tokenFingerprints?.access || null;
  if (!expectedFingerprint || !actualFingerprint) {
    throw targetVerificationError('更新后无法取得 access token 指纹', 'SUB2API_IMPORT_VERIFY_FINGERPRINT_MISSING');
  }
  if (expectedFingerprint !== actualFingerprint) {
    throw targetVerificationError('更新后 access token 指纹不一致', 'SUB2API_IMPORT_VERIFY_FINGERPRINT_MISMATCH');
  }
  const expectedRefreshFingerprint = item.fingerprints?.refresh || null;
  if (expectedRefreshFingerprint) {
    const actualRefreshFingerprint = account?.tokenFingerprints?.refresh || null;
    if (accountCredentialPresence(account, 'refresh') !== 'present' || !actualRefreshFingerprint) {
      throw targetVerificationError('更新后无法确认 refresh token', 'SUB2API_IMPORT_VERIFY_REFRESH_FINGERPRINT_MISSING');
    }
    if (expectedRefreshFingerprint !== actualRefreshFingerprint) {
      throw targetVerificationError('更新后 refresh token 指纹不一致', 'SUB2API_IMPORT_VERIFY_REFRESH_FINGERPRINT_MISMATCH');
    }
  }
  return actualFingerprint;
}

function plannedCredentialStateMatches(plannedAccount, account) {
  if (!plannedAccount) return false;
  for (const field of ['access', 'refresh']) {
    const expectedFingerprint = plannedAccount.tokenFingerprints?.[field] || null;
    const actualFingerprint = account?.tokenFingerprints?.[field] || null;
    if (expectedFingerprint && expectedFingerprint !== actualFingerprint) return false;
    const expectedPresence = accountCredentialPresence(plannedAccount, field);
    const actualPresence = accountCredentialPresence(account, field);
    if (expectedPresence !== 'unknown' && expectedPresence !== actualPresence) return false;
  }
  return true;
}

function sourceCredentialValue(raw, snakeKey, camelKey, maximumLength = 1024) {
  const value = raw?.[snakeKey] ?? raw?.[camelKey];
  if (value === undefined || value === null || value === '') return '';
  if (typeof value !== 'string'
      && !(typeof value === 'number' && Number.isFinite(value))) return '';
  const text = String(value).trim();
  if (!text || text.length > maximumLength || /[\u0000-\u001f\u007f]/.test(text)) return '';
  return text;
}

function sourceTokenValue(raw, kind) {
  const field = tokenCredentialField(raw, kind);
  if (field.invalid) {
    throw targetVerificationError('来源 token 字段类型或长度无效', 'SOURCE_CREDENTIAL_SCHEMA_INVALID');
  }
  return field.value;
}

function verifiedIdentityValue(item, recordKey, prefix) {
  const recordValue = sourceCredentialValue(item?._record || {}, recordKey, recordKey, 512);
  if (recordValue) return recordValue;
  const sourceValues = identityValues(item?.sourceIdentityKeys || [], prefix);
  if (sourceValues.size === 1) return [...sourceValues][0];
  const account = item?._verifiedAccount || item?._account;
  const directValue = sourceCredentialValue(account || {}, recordKey, recordKey, 512);
  if (directValue) return directValue;
  const values = identityValues(account?.identityKeys || accountKeys(account), prefix);
  return values.size === 1 ? [...values][0] : '';
}

function credentialFingerprintExtra(raw) {
  const accessToken = sourceTokenValue(raw, 'access');
  const refreshToken = sourceTokenValue(raw, 'refresh');
  return {
    ...(accessToken ? {
      access_token_sha256: crypto.createHash('sha256').update(accessToken).digest('hex'),
    } : {}),
    ...(refreshToken ? {
      refresh_token_sha256: crypto.createHash('sha256').update(refreshToken).digest('hex'),
    } : {}),
  };
}

function buildOAuthUpdatePayload(item) {
  const raw = item?._raw && typeof item._raw === 'object' ? item._raw : {};
  const record = item?._record || {};
  const accessToken = sourceTokenValue(raw, 'access');
  if (!accessToken) {
    throw targetVerificationError('来源缺少可更新的 access_token', 'SOURCE_ACCESS_TOKEN_MISSING');
  }
  const credentials = { access_token: accessToken };
  const refreshToken = sourceTokenValue(raw, 'refresh');
  const idToken = sourceTokenValue(raw, 'id');
  if (refreshToken) credentials.refresh_token = refreshToken;
  // Sub2API preserves an existing refresh_token when an access-only update is
  // applied, but client_id is not treated as sensitive. Send the fixed public
  // Codex client identifier on every update so the preserved refresh token is
  // still usable; never trust an arbitrary source client_id.
  credentials.client_id = OPENAI_CODEX_OAUTH_CLIENT_ID;
  if (idToken) credentials.id_token = idToken;
  if (record.email || item.email) credentials.email = record.email || item.email;
  const accountId = verifiedIdentityValue(item, 'accountId', 'account:');
  const userId = verifiedIdentityValue(item, 'userId', 'user:');
  if (accountId) credentials.chatgpt_account_id = accountId;
  if (userId) credentials.chatgpt_user_id = userId;
  if (item.expiresAt) credentials.expires_at = item.expiresAt;
  for (const [key, maximumLength] of [['token_type', 64], ['scope', 4096], ['last_refresh', 64]]) {
    const value = sourceCredentialValue(raw, key, key, maximumLength);
    if (value) credentials[key] = value;
  }
  const accessPayload = parseJwtPayload(accessToken) || {};
  const rawAuth = accessPayload['https://api.openai.com/auth'];
  const auth = rawAuth && typeof rawAuth === 'object' ? rawAuth : {};
  const planType = sourceCredentialValue(raw, 'plan_type', 'planType', 128)
    || sourceCredentialValue(raw, 'chatgpt_plan_type', 'chatgptPlanType', 128)
    || sourceCredentialValue(auth, 'chatgpt_plan_type', 'chatgptPlanType', 128);
  if (planType) credentials.plan_type = planType;
  let organizationId = sourceCredentialValue(raw, 'organization_id', 'organizationId', 512)
    || sourceCredentialValue(raw, 'poid', 'poid', 512)
    || sourceCredentialValue(auth, 'poid', 'poid', 512);
  if (!organizationId && Array.isArray(auth.organizations)) {
    const preferred = auth.organizations.find((organization) => organization?.is_default === true)
      || auth.organizations[0];
    organizationId = sourceCredentialValue(preferred, 'id', 'id', 512);
  }
  if (organizationId) credentials.organization_id = organizationId;
  return {
    type: 'oauth',
    credentials,
    extra: credentialFingerprintExtra(raw),
  };
}

function buildCodexSessionDocument(item) {
  const { credentials } = buildOAuthUpdatePayload(item);
  return {
    access_token: credentials.access_token,
    ...(credentials.refresh_token ? { refresh_token: credentials.refresh_token } : {}),
    ...(credentials.id_token ? { id_token: credentials.id_token } : {}),
    ...(credentials.email ? { email: credentials.email } : {}),
    ...(credentials.chatgpt_account_id ? { account_id: credentials.chatgpt_account_id } : {}),
    ...(credentials.chatgpt_user_id ? { user_id: credentials.chatgpt_user_id } : {}),
    // Current Sub2API Codex imports read expires_at. `expired` is a legacy
    // gpt_register source field and is ignored by the import parser.
    ...(credentials.expires_at ? { expires_at: credentials.expires_at } : {}),
    ...(credentials.last_refresh ? { last_refresh: credentials.last_refresh } : {}),
    type: 'codex',
  };
}

function buildCodexImportIdempotencyKey(item, context = {}) {
  const contentHash = String(item?._record?.contentHash || '').toLowerCase();
  const strongIdentity = [];
  for (const prefix of ['account:', 'user:']) {
    for (const value of identityValues(item?.sourceIdentityKeys || [], prefix)) {
      strongIdentity.push(prefix + value);
    }
  }
  strongIdentity.sort((left, right) => left.localeCompare(right, 'en'));
  const material = {
    jobId: String(context?.jobId || ''),
    action: 'create',
    sourceIdentityKeys: strongIdentity,
    sourceContentHash: /^[a-f0-9]{64}$/.test(contentHash) ? contentHash : '',
    // Real filesystem records always carry contentHash. The fingerprint-only
    // fallback keeps direct/test callers deterministic without ever placing a
    // credential in the seed or header.
    fallbackFingerprints: /^[a-f0-9]{64}$/.test(contentHash)
      ? []
      : [item?.fingerprints?.access || '', item?.fingerprints?.refresh || ''],
    relativePath: String(item?.relativePath || ''),
    targetName: String(item?.accountName || ''),
  };
  const digest = crypto.createHash('sha256')
    .update('gpt-register-panel/create/v1\n')
    .update(JSON.stringify(material))
    .digest('hex');
  // Printable ASCII, 81 bytes. The key contains only a domain label and a
  // one-way digest; raw tokens, identities and account names never cross the
  // HTTP header or logs through this value.
  return 'gptreg-create-v1-' + digest;
}

function canonicalIdentitySet(keys = []) {
  const normalized = [];
  for (const prefix of ['account:', 'user:', 'email:']) {
    for (const value of identityValues(keys, prefix)) normalized.push(prefix + value);
  }
  return normalized.sort((left, right) => left.localeCompare(right, 'en'));
}

function sourceTokenChanged(message = '来源 token 在写入前已变化') {
  return targetVerificationError(message, 'SOURCE_TOKEN_CHANGED');
}

function revalidateSourceToken(item, rootDirectory, nowMs = Date.now()) {
  const expected = item?._record;
  if (!expected?.contentHash || !item?.source || !item?.relativePath) {
    throw sourceTokenChanged('来源 token 快照缺少可复核的内容指纹');
  }
  let sources;
  try {
    sources = readGptRegisterSources({
      rootDirectory,
      includeRaw: true,
      strictCompleteSnapshot: true,
    });
  } catch {
    throw sourceTokenChanged();
  }
  const candidates = collectCandidates(sources, { nowMs });
  const identityMatches = candidates.filter((candidate) => identitiesStronglyCompatible(
    item.sourceIdentityKeys || [],
    candidate.sourceIdentityKeys || [],
  ));
  if (identityMatches.length !== 1 || identityMatches[0].identityConflict) {
    throw sourceTokenChanged('来源身份候选在写入前变得不唯一或冲突');
  }
  const candidate = identityMatches[0];
  const record = candidate.record;
  if (record.source !== item.source
      || record.relativePath !== item.relativePath
      || record.contentHash !== expected.contentHash
      || Number(record.mtimeMs) !== Number(expected.mtimeMs)
      || record.parseStatus !== 'ok'
      || record.historical === true
      || record.type !== expected.type
      || record.expiryStatus !== expected.expiryStatus
      || record.expiresAt !== expected.expiresAt
      || record.lastRefresh !== expected.lastRefresh
      || record.disabled !== expected.disabled
      || JSON.stringify(record.fingerprints || {}) !== JSON.stringify(expected.fingerprints || {})
      || JSON.stringify(canonicalIdentitySet(candidate.sourceIdentityKeys))
        !== JSON.stringify(canonicalIdentitySet(item.sourceIdentityKeys || []))) {
    throw sourceTokenChanged();
  }
  if (isExpiryInvalid(record) || isExpired(record, nowMs) || record.disabled
      || sourceTerminalStatus(sources?.usernames, record)) {
    throw sourceTokenChanged('来源 token 在写入前已不可用');
  }
  return record;
}

async function preflightUpdateAccount(client, item, nowMs = Date.now(), options = {}) {
  const signal = options.signal;
  throwIfJobInterrupted(signal);
  const expectedId = Number(item?.accountId);
  if (!Number.isSafeInteger(expectedId) || expectedId <= 0) {
    throw targetVerificationError('更新计划缺少有效的 Sub2API 账号 ID', 'SUB2API_TARGET_ID_REQUIRED');
  }
  const account = await client.getAccount(expectedId, { signal });
  throwIfJobInterrupted(signal);
  verifyTargetIdentity(item, account, expectedId);
  verifyPlannedTargetIdentity(item, account);
  const availability = getAccountAvailability(account, nowMs);
  if (availability.key !== 'unavailable') {
    return { account, skipReason: availability.reason || 'sub2api_availability_unknown' };
  }
  if (isExpiryInvalid(item?._record) || isExpired(item?._record, nowMs)) {
    return { account, skipReason: isExpiryInvalid(item?._record) ? 'source_expiry_invalid' : 'source_token_expired' };
  }
  const sourceRecord = item?._record || { fingerprints: item?.fingerprints || {} };
  if (credentialsInSync(sourceRecord, account)) {
    return { account, skipReason: 'already_in_sync' };
  }
  if (!plannedCredentialStateMatches(item?._account, account)) {
    throw targetVerificationError('Sub2API 目标账号在写入前已变化', 'SUB2API_TARGET_CHANGED');
  }
  return { account, skipReason: null };
}

async function preflightCreateAccount(client, item, options = {}) {
  const signal = options.signal;
  throwIfJobInterrupted(signal);
  if (!hasStrongIdentity(item.sourceIdentityKeys || [])) {
    throw targetVerificationError('新建账号缺少强身份，已拒绝写入', 'SOURCE_STRONG_IDENTITY_REQUIRED');
  }
  if (parseCanonicalFreeName(item?.accountName) === null) {
    throw targetVerificationError(
      '新建账号名称必须是规范的 free 五位编号',
      'SUB2API_CREATE_NAME_INVALID',
    );
  }
  const accounts = await client.listAccounts({
    pageSize: 200,
    signal,
  });
  throwIfJobInterrupted(signal);
  const strongMatches = accounts.filter((account) => identitiesStronglyCompatible(
    item.sourceIdentityKeys || [],
    account.identityKeys || accountKeys(account),
  ));
  if (strongMatches.length > 0) {
    throw targetVerificationError('写入前发现相同强身份的 Sub2API 账号', 'SUB2API_CREATE_IDENTITY_APPEARED');
  }
  if (ambiguousAccountHints({ sourceIdentityKeys: item.sourceIdentityKeys || [] }, accounts).length > 0) {
    throw targetVerificationError('写入前发现仅能通过邮箱关联的 Sub2API 账号', 'SUB2API_CREATE_IDENTITY_AMBIGUOUS');
  }
  if (accountsMatchingFreeName(accounts, item.accountName).length > 0) {
    throw targetVerificationError(
      '写入前发现账号名称已被占用或存在大小写冲突',
      'SUB2API_CREATE_NAME_CONFLICT',
    );
  }
  return new Set(accounts
    .map((account) => Number(account?.id))
    .filter((id) => Number.isSafeInteger(id) && id > 0));
}

function assertCreatedImportResult(result, knownAccountIds = new Set()) {
  assertImportResultSucceeded(result);
  const items = Array.isArray(result?.items) ? result.items : null;
  const item = items?.length === 1
    && items[0]
    && typeof items[0] === 'object'
    && !Array.isArray(items[0])
    ? items[0]
    : null;
  const accountId = item?.account_id;
  const exactCounter = (key, expected) => (
    Object.prototype.hasOwnProperty.call(result || {}, key)
      && Number.isSafeInteger(result[key])
      && result[key] === expected
  );
  const idAliasMatches = (object, key) => (
    !Object.prototype.hasOwnProperty.call(object || {}, key)
      || (Number.isSafeInteger(object[key]) && object[key] === accountId)
  );
  if (!result
      || typeof result !== 'object'
      || Array.isArray(result)
      || items?.length !== 1
      || !item
      || item.action !== 'created'
      || !Number.isSafeInteger(accountId)
      || accountId <= 0
      || !idAliasMatches(item, 'accountId')
      || !idAliasMatches(result, 'account_id')
      || !idAliasMatches(result, 'accountId')
      || knownAccountIds.has(accountId)
      || !exactCounter('total', 1)
      || !exactCounter('created', 1)
      || !exactCounter('updated', 0)
      || !exactCounter('skipped', 0)
      || !exactCounter('failed', 0)) {
    const error = targetVerificationError(
      'Sub2API 新建请求返回了不一致的创建结果',
      'SUB2API_CREATE_ACTION_MISMATCH',
    );
    error.result = safeImportResult(result);
    throw error;
  }
  return accountId;
}

async function executeImportPlanItem({
  client,
  item,
  groups = [],
  logger = null,
  context = {},
  sourceRoot = null,
  signal = null,
}) {
  throwIfJobInterrupted(signal);
  if (item.action === 'update') {
    let freshRecord = sourceRoot ? revalidateSourceToken(item, sourceRoot) : null;
    throwIfJobInterrupted(signal);
    let preflight = await preflightUpdateAccount(client, item, Date.now(), { signal });
    if (preflight.skipReason) {
      return { skipped: true, reason: preflight.skipReason, verification: null, result: null };
    }
    if (sourceRoot) {
      // Sandwich the mutable source scan between two target reads. This
      // catches a source replacement during the first GET while ensuring the
      // final operation immediately preceding the write is an exact-ID,
      // strong-identity and availability check of the remote target.
      freshRecord = revalidateSourceToken(item, sourceRoot);
      throwIfJobInterrupted(signal);
      preflight = await preflightUpdateAccount(client, item, Date.now(), { signal });
      if (preflight.skipReason) {
        return { skipped: true, reason: preflight.skipReason, verification: null, result: null };
      }
    }
    const writeItem = {
      ...item,
      ...(freshRecord ? { _record: freshRecord, _raw: freshRecord.raw } : {}),
      _verifiedAccount: preflight.account,
    };
    const payload = buildOAuthUpdatePayload(writeItem);
    throwIfJobInterrupted(signal);
    let writeResponseReceived = false;
    try {
      assertAuditLogCheckpoint(logger, 'import.oauth_update_checkpoint', {
        jobId: context?.jobId || null,
        actor: context?.actor || null,
        action: 'update',
        accountId: item.accountId,
        accountName: item.accountName || preflight.account?.name || null,
        source: item.source || null,
        relativePath: item.relativePath || null,
        beforeFingerprint: preflight.account?.tokenFingerprints?.access || null,
        afterFingerprint: item.fingerprints?.access || null,
      });
      await client.applyOAuthCredentials(
        item.accountId,
        payload,
        { signal },
      );
      writeResponseReceived = true;
      throwIfPostWriteInterrupted(signal);
      const account = await retryPostflightRead(
        () => client.getAccount(item.accountId, { signal }),
        { signal },
      );
      throwIfPostWriteInterrupted(signal);
      const accountId = verifyTargetIdentity(item, account, item.accountId);
      verifyUpdatedTargetIdentity(writeItem, account);
      const fingerprint = verifyTargetFingerprint(item, account);
      const verification = {
        accountId,
        accountName: account.name || null,
        fingerprint,
        status: account.status || null,
      };
      writeLog(logger, 'info', 'import.account_verified', { ...context, ...verification });
      return {
        skipped: false,
        reason: null,
        result: safeImportResult({
          success: true,
          account_id: accountId,
          total: 1,
          created: 0,
          updated: 1,
          skipped: 0,
          failed: 0,
        }),
        verification,
      };
    } catch (error) {
      if (writeResponseReceived || writeRequiresReconciliation(error)) {
        throw reconciliationRequiredError(
          error,
          error?.reconciliationReason || error?.writeOutcomeReason || 'update_postflight',
        );
      }
      throw error;
    }
  }
  throwIfJobInterrupted(signal);
  if (item.action !== 'create') {
    throw targetVerificationError('不支持的导入计划动作', 'IMPORT_ACTION_INVALID');
  }
  if (isExpiryInvalid(item?._record) || isExpired(item?._record, Date.now())) {
    return {
      skipped: true,
      reason: isExpiryInvalid(item?._record) ? 'source_expiry_invalid' : 'source_token_expired',
      verification: null,
      result: null,
    };
  }
  let freshRecord = sourceRoot ? revalidateSourceToken(item, sourceRoot) : null;
  throwIfJobInterrupted(signal);
  let knownAccountIds = await preflightCreateAccount(client, item, { signal });
  if (sourceRoot) {
    freshRecord = revalidateSourceToken(item, sourceRoot);
    throwIfJobInterrupted(signal);
    const finalKnownAccountIds = await preflightCreateAccount(client, item, { signal });
    knownAccountIds = new Set([...knownAccountIds, ...finalKnownAccountIds]);
  }
  const writeItem = freshRecord ? { ...item, _record: freshRecord, _raw: freshRecord.raw } : item;
  const payload = {
    // Only the validated Codex fields cross the adapter boundary. Unknown
    // nested source objects must never be forwarded as import credentials.
    content: JSON.stringify(buildCodexSessionDocument(writeItem)),
    extra: credentialFingerprintExtra(writeItem._raw || {}),
    name: item.accountName || undefined,
    group_ids: groups,
    // If an identity appears after preflight, fail instead of silently
    // updating that potentially available account.
    update_existing: false,
    skip_default_group_bind: false,
    confirm_mixed_channel_risk: process.env.SUB2API_CONFIRM_MIXED_CHANNEL_RISK === '1',
  };
  const idempotencyKey = buildCodexImportIdempotencyKey(writeItem, context);
  throwIfJobInterrupted(signal);
  let writeResponseReceived = false;
  let rawResult = null;
  try {
    assertAuditLogCheckpoint(logger, 'import.codex_create_checkpoint', {
      jobId: context?.jobId || null,
      actor: context?.actor || null,
      action: 'create',
      accountId: null,
      accountName: item.accountName || null,
      source: item.source || null,
      relativePath: item.relativePath || null,
      beforeFingerprint: null,
      afterFingerprint: item.fingerprints?.access || null,
    });
    rawResult = await client.importCodexSession(payload, {
      idempotencyKey,
      signal,
    });
    writeResponseReceived = true;
    throwIfPostWriteInterrupted(signal);
    assertCreatedImportResult(rawResult, knownAccountIds);
    const verification = await verifyImportedAccount(
      client,
      item,
      rawResult,
      logger,
      context,
      { signal },
    );
    throwIfPostWriteInterrupted(signal);
    return {
      skipped: false,
      reason: null,
      result: safeImportResult(rawResult),
      verification,
    };
  } catch (error) {
    if (writeResponseReceived || writeRequiresReconciliation(error)) {
      const marked = reconciliationRequiredError(
        error,
        error?.reconciliationReason || error?.writeOutcomeReason || 'create_postflight',
      );
      if (!marked.result && rawResult) marked.result = safeImportResult(rawResult);
      throw marked;
    }
    throw error;
  }
}

function backupDirectory() {
  return path.resolve(process.env.PANEL_BACKUP_DIR || path.join(__dirname, '..', 'runtime', 'backups'));
}

function sameFileIdentity(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function backupLimit(name, fallback, minimum, maximum) {
  const value = Number(process.env[name]);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(value)));
}

function openPinnedBackupDirectory(directory) {
  ensureDirectoryTree(directory, 'Sub2API 备份目录');
  const realDirectory = fs.realpathSync(directory);
  const descriptor = fs.openSync(
    realDirectory,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const stat = fs.fstatSync(descriptor);
    const latest = fs.lstatSync(realDirectory);
    if (!stat.isDirectory() || latest.isSymbolicLink() || !latest.isDirectory()
        || !sameFileIdentity(stat, latest)) {
      throw new Error('Sub2API 备份目录在固定期间发生变化');
    }
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if ((currentUid !== null && stat.uid !== currentUid) || (stat.mode & 0o077) !== 0) {
      const error = new Error('Sub2API 备份目录必须由当前用户持有且权限为 0700 或更严格');
      error.code = 'SUB2API_BACKUP_PERMISSIONS_INVALID';
      throw error;
    }
    const accessDirectory = process.platform === 'linux'
      ? '/proc/self/fd/' + descriptor
      : realDirectory;
    if (process.platform === 'linux' && fs.realpathSync(accessDirectory) !== realDirectory) {
      throw new Error('Sub2API 备份目录 FD 校验失败');
    }
    return { descriptor, accessDirectory, realDirectory, stat };
  } catch (error) {
    try { fs.closeSync(descriptor); } catch {}
    throw error;
  }
}

function unlinkBackupIfSame(filePath, expected) {
  try {
    const latest = fs.lstatSync(filePath);
    if (!latest.isSymbolicLink() && latest.isFile() && sameFileIdentity(latest, expected)) {
      fs.unlinkSync(filePath);
    }
  } catch {}
}

function pruneBackups(pinned, newestName) {
  const retentionDays = backupLimit('PANEL_BACKUP_RETENTION_DAYS', 30, 1, 3650);
  const maximumFiles = backupLimit('PANEL_BACKUP_MAX_FILES', 100, 1, 1000);
  const maximumBytes = backupLimit(
    'PANEL_BACKUP_MAX_TOTAL_BYTES',
    512 * 1024 * 1024,
    1024 * 1024,
    4 * 1024 * 1024 * 1024,
  );
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  const entries = fs.readdirSync(pinned.accessDirectory)
    .filter((name) => /^sub2api-[A-Za-z0-9-]+\.json$/.test(name))
    .map((name) => {
      const filePath = path.join(pinned.accessDirectory, name);
      const stat = fs.lstatSync(filePath);
      if (stat.isSymbolicLink() || !stat.isFile()) {
        const error = new Error('Sub2API 备份目录包含不安全的同名条目');
        error.code = 'SUB2API_BACKUP_PATH_INVALID';
        throw error;
      }
      return { name, filePath, stat };
    })
    .sort((left, right) => {
      if (left.name === newestName) return -1;
      if (right.name === newestName) return 1;
      return right.stat.mtimeMs - left.stat.mtimeMs
        || right.name.localeCompare(left.name, 'en');
    });
  let keptFiles = 0;
  let keptBytes = 0;
  let newestKept = false;
  for (const entry of entries) {
    const keep = entry.name === newestName
      || (entry.stat.mtimeMs >= cutoff
        && keptFiles < maximumFiles
        && keptBytes + entry.stat.size <= maximumBytes);
    if (keep && keptFiles < maximumFiles && keptBytes + entry.stat.size <= maximumBytes) {
      keptFiles += 1;
      keptBytes += entry.stat.size;
      if (entry.name === newestName) newestKept = true;
      continue;
    }
    unlinkBackupIfSame(entry.filePath, entry.stat);
  }
  if (!newestKept || keptFiles > maximumFiles || keptBytes > maximumBytes) {
    const error = new Error('Sub2API 备份保留上限不足以保存本次备份');
    error.code = 'SUB2API_BACKUP_LIMIT_EXCEEDED';
    throw error;
  }
}

function writeBackup(payload) {
  const directory = backupDirectory();
  let pinned;
  try { pinned = openPinnedBackupDirectory(directory); } catch (error) {
    const wrapped = new Error('Sub2API 备份目录不存在、不可读取或包含符号链接');
    wrapped.code = error?.code || 'SUB2API_BACKUP_PATH_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
  const fileName = 'sub2api-' + new Date().toISOString().replace(/[:.]/g, '-')
    + '-' + crypto.randomBytes(8).toString('hex') + '.json';
  const filePath = path.join(pinned.accessDirectory, fileName);
  const logicalFilePath = path.join(directory, fileName);
  const temporaryPath = path.join(
    pinned.accessDirectory,
    '.sub2api-backup-' + process.pid + '-' + crypto.randomBytes(12).toString('hex'),
  );
  let descriptor;
  let temporaryStat = null;
  let published = false;
  let completed = false;
  try {
    const content = Buffer.from(JSON.stringify(payload), 'utf8');
    const maximumSingleBytes = 32 * 1024 * 1024;
    if (content.length > maximumSingleBytes) {
      const error = new Error('Sub2API 备份响应超过安全上限');
      error.code = 'SUB2API_BACKUP_TOO_LARGE';
      throw error;
    }
    descriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.writeFileSync(descriptor, content);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
    temporaryStat = fs.fstatSync(descriptor);
    const namedTemporary = fs.lstatSync(temporaryPath);
    if (!temporaryStat.isFile() || !sameFileIdentity(temporaryStat, namedTemporary)) {
      throw new Error('Sub2API 备份临时文件在发布前发生变化');
    }
    fs.linkSync(temporaryPath, filePath);
    const publishedStat = fs.lstatSync(filePath);
    if (publishedStat.isSymbolicLink() || !publishedStat.isFile()
        || !sameFileIdentity(publishedStat, temporaryStat)) {
      throw new Error('Sub2API 备份发布后身份校验失败');
    }
    published = true;
    fs.closeSync(descriptor);
    descriptor = undefined;
    unlinkBackupIfSame(temporaryPath, temporaryStat);
    fs.fsyncSync(pinned.descriptor);
    pruneBackups(pinned, fileName);
    fs.fsyncSync(pinned.descriptor);
    completed = true;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (temporaryStat) unlinkBackupIfSame(temporaryPath, temporaryStat);
    if (published && !completed && temporaryStat) unlinkBackupIfSame(filePath, temporaryStat);
    if (pinned?.descriptor !== undefined) {
      try { fs.closeSync(pinned.descriptor); } catch {}
    }
  }
  if (!published) throw new Error('Sub2API 备份未安全发布');
  return logicalFilePath;
}

async function executeImport({
  snapshotVersion: expectedVersion,
  selectedKeys = [],
  actor = 'local',
  db,
  jobId = null,
  logger = null,
  signal = null,
  client: providedClient = null,
  persistResult = null,
  persistFailure = null,
}) {
  const startedAt = Date.now();
  writeLog(logger, 'info', 'import.started', {
    jobId,
    actor,
    expectedVersion: expectedVersion || null,
    selectedCount: Array.isArray(selectedKeys) ? selectedKeys.length : 0,
  });
  try {
    throwIfJobInterrupted(signal);
    if (process.env.PANEL_WRITE_ENABLED !== '1') {
      const error = new Error('写操作未启用，请设置 PANEL_WRITE_ENABLED=1 后重启面板');
      error.code = 'WRITE_DISABLED';
      throw error;
    }
    if (!configuredForSub2Api()) throw new Error('Sub2API 管理 API 未配置');
    if (!/^[a-f0-9]{64}$/i.test(String(expectedVersion || ''))) {
      const error = new Error('缺少有效的差异快照版本，请先执行“检查差异”');
      error.code = 'SNAPSHOT_VERSION_REQUIRED';
      throw error;
    }
    if (!Array.isArray(selectedKeys) || selectedKeys.length === 0) {
      const error = new Error('没有选择任何账号，已拒绝导入');
      error.code = 'IMPORT_SELECTION_REQUIRED';
      throw error;
    }
    const result = await withControlPlaneLock(async () => {
      let lockedResult;
      try {
        lockedResult = await withSyncLock(async () => {
      throwIfJobInterrupted(signal);
      const client = providedClient
        || new Sub2ApiAdminClient({ logger, logContext: { jobId, actor } });
      const current = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
        includeRaw: true,
        includeInternal: true,
        requireCompleteSources: true,
        client,
        logger,
        jobId,
        actor,
        signal,
      });
      throwIfJobInterrupted(signal);
      if (!confirmedSub2ApiRead(current)) {
        const readError = current?._internal?.apiError
          || current?.sub2api?.apiError
          || '未确认远端读取状态';
        const error = new Error('无法确认 Sub2API 当前账号列表，已停止导入：' + readError);
        error.code = 'SUB2API_READ_FAILED';
        throw error;
      }
      if (expectedVersion !== current.version) {
        const error = new Error('来源在确认前已变化，请重新检查差异');
        error.code = 'SNAPSHOT_STALE';
        throw error;
      }
      throwIfJobInterrupted(signal);
      if (db && jobId) {
        if (typeof db.startMutationJob !== 'function') {
          const error = new Error('任务执行安全检查不可用，尚未开始导入');
          error.code = 'JOB_RECONCILIATION_GUARD_UNAVAILABLE';
          throw error;
        }
        await db.startMutationJob(jobId);
      }
      throwIfJobInterrupted(signal);
      const fullPlan = buildImportPlan(current._internal.sources, current._internal.accounts, selectedKeys);
      const fullSummary = importPlanSummary(fullPlan);
      writeLog(logger, 'info', 'import.plan_built', {
        jobId,
        actor,
        snapshotVersion: current.version,
        counts: fullSummary.counts,
        selectedCount: Array.isArray(selectedKeys) ? selectedKeys.length : 0,
      });
      for (const item of fullPlan.filter((candidate) => candidate.action === 'skip')) {
        writeLog(logger, 'info', 'import.account_skipped', {
          jobId,
          actor,
          action: item.action,
          reason: item.reason,
          accountId: item.accountId,
          accountName: item.accountName,
          email: item.email,
          source: item.source,
          relativePath: item.relativePath,
          availability: item.availability,
          beforeFingerprint: item._account?.tokenFingerprints?.access || null,
          afterFingerprint: item.fingerprints?.access || null,
        });
      }
      const plan = fullPlan.filter((item) => item.action !== 'skip');
      const conflicts = plan.filter((item) => item.action === 'conflict' || item.conflictingVersions);
      if (conflicts.length > 0) {
        for (const item of conflicts) {
          writeLog(logger, 'error', 'import.account_blocked', {
            jobId,
            actor,
            action: item.action,
            reason: item.reason,
            accountId: item.accountId,
            accountName: item.accountName,
            email: item.email,
            source: item.source,
            relativePath: item.relativePath,
          });
        }
        throw new Error('存在身份或版本冲突，已停止导入');
      }
      throwIfJobInterrupted(signal);
      if (plan.length === 0) return { ...importPlanSummary([]), imported: [], skipped: true };

      let backupPath = null;
      writeLog(logger, 'info', 'import.backup_started', { jobId, actor });
      try {
        const exported = await client.exportAccounts([], { signal });
        throwIfJobInterrupted(signal);
        backupPath = writeBackup(exported);
        writeLog(logger, 'info', 'import.backup_succeeded', { jobId, actor, backupPath });
      } catch (error) {
        rethrowIfJobInterrupted(error, signal);
        const message = safeErrorMessage(error);
        writeLog(logger, process.env.PANEL_ALLOW_UNBACKED_WRITES === '1' ? 'warn' : 'error', 'import.backup_failed', {
          jobId,
          actor,
          error: message,
          continuedWithoutBackup: process.env.PANEL_ALLOW_UNBACKED_WRITES === '1',
        });
        if (process.env.PANEL_ALLOW_UNBACKED_WRITES !== '1') {
          throw new Error('导入前备份失败，已停止写入：' + message);
        }
      }

      const groups = plan.some((item) => item.action === 'create')
        ? await resolveGroupIds(client, { signal })
        : [];
      throwIfJobInterrupted(signal);
      writeLog(logger, 'info', 'import.accounts_started', {
        jobId,
        actor,
        count: plan.length,
        groupCount: groups.length,
      });
      const imported = [];
      let notAttempted = [];
      let haltedForReconciliation = false;
      for (let itemIndex = 0; itemIndex < plan.length; itemIndex += 1) {
        const item = plan[itemIndex];
        throwIfJobInterrupted(signal);
        const itemStartedAt = Date.now();
        const baseFields = {
          jobId,
          actor,
          action: item.action,
          accountId: item.accountId,
          accountName: item.accountName,
          email: item.email,
          source: item.source,
          relativePath: item.relativePath,
          beforeFingerprint: item._account?.tokenFingerprints?.access || null,
          afterFingerprint: item.fingerprints?.access || null,
        };
        writeLog(logger, 'info', 'import.account_started', baseFields);
        try {
          const outcome = await executeImportPlanItem({
            client,
            item,
            groups,
            logger,
            context: baseFields,
            sourceRoot: current._internal.sources.rootDirectory,
            signal,
          });
          if (outcome.skipped) {
            const skippedItem = { ...item, action: 'skip', reason: outcome.reason };
            imported.push({
              ...safeImportItem(skippedItem),
              result: null,
              verification: null,
              skipped: true,
            });
            try {
              await db?.audit({
                jobId,
                actor,
                action: item.action === 'create' ? 'account_import' : 'token_update',
                targetKey: item.identityKey,
                beforeFingerprint: item._account?.tokenFingerprints?.access || null,
                afterFingerprint: item.fingerprints?.access || null,
                result: 'skipped',
                details: { accountId: item.accountId, reason: outcome.reason },
              });
            } catch (auditError) {
              writeLog(logger, 'error', 'import.audit_failed', {
                ...baseFields,
                error: safeErrorMessage(auditError),
              });
            }
            writeLog(logger, 'info', 'import.account_skipped_after_recheck', {
              ...baseFields,
              reason: outcome.reason,
              durationMs: Date.now() - itemStartedAt,
            });
            continue;
          }
          const result = outcome.result;
          const verification = outcome.verification;
          // The remote response may contain credentials or the imported
          // session. Keep only counters and identifiers in the local job DB
          // and API response.
          imported.push({
            ...safeImportItem(item),
            result,
            verification,
          });
          try {
            await db?.audit({
              jobId,
              actor,
              action: item.action === 'create' ? 'account_import' : 'token_update',
              targetKey: item.identityKey,
              beforeFingerprint: item._account?.tokenFingerprints?.access || null,
              afterFingerprint: item.fingerprints?.access || null,
              result: 'ok',
              details: {
                accountId: verification.accountId,
                accountName: verification.accountName || item.accountName,
                backupPath,
                sub2api: result,
                verification,
              },
            });
            await db?.saveLink({
              identityKey: item.identityKey,
              tokenPath: item.relativePath,
              sub2apiId: verification.accountId,
              accountName: verification.accountName || item.accountName,
            });
          } catch (auditError) {
            writeLog(logger, 'error', 'import.audit_failed_after_remote_success', {
              ...baseFields,
              error: safeErrorMessage(auditError),
            });
          }
          writeLog(logger, 'info', 'import.account_succeeded', {
            ...baseFields,
            durationMs: Date.now() - itemStartedAt,
            sub2apiAccountId: verification.accountId,
          });
        } catch (error) {
          if (writeRequiresReconciliation(error)) {
            const message = safeErrorMessage(error);
            const reconciliationReason = String(
              error?.reconciliationReason || error?.writeOutcomeReason || 'write_outcome_unknown',
            ).slice(0, 64);
            imported.push({
              ...safeImportItem(item),
              result: safeImportResult(error?.result),
              verification: null,
              error: message,
              code: error?.code || 'SUB2API_WRITE_RECONCILIATION_REQUIRED',
              outcome: 'requires_reconciliation',
              writeOutcomeUnknown: true,
              requiresReconciliation: true,
              reconciliationReason,
            });
            notAttempted = plan.slice(itemIndex + 1).map((remainingItem) => ({
              ...safeImportItem(remainingItem),
              outcome: 'not_attempted',
              notAttemptedReason: 'requires_reconciliation',
            }));
            haltedForReconciliation = true;
            try {
              await db?.audit({
                jobId,
                actor,
                action: item.action === 'create' ? 'account_import' : 'token_update',
                targetKey: item.identityKey,
                beforeFingerprint: item._account?.tokenFingerprints?.access || null,
                afterFingerprint: null,
                result: 'requires_reconciliation',
                details: {
                  error: message,
                  code: error?.code || null,
                  writeOutcomeUnknown: true,
                  requiresReconciliation: true,
                  reconciliationReason,
                  sub2api: safeImportResult(error?.result),
                },
              });
            } catch (auditError) {
              writeLog(logger, 'error', 'import.audit_failed', {
                ...baseFields,
                error: safeErrorMessage(auditError),
              });
            }
            writeLog(logger, 'error', 'import.account_reconciliation_required', {
              ...baseFields,
              durationMs: Date.now() - itemStartedAt,
              error: message,
              code: error?.code || null,
              reconciliationReason,
              remainingCount: notAttempted.length,
            });
            break;
          }
          rethrowIfJobInterrupted(error, signal);
          const message = safeErrorMessage(error);
          imported.push({ ...safeImportItem(item), result: null, error: message, code: error?.code || null });
          try {
            await db?.audit({
              jobId,
              actor,
              action: item.action === 'create' ? 'account_import' : 'token_update',
              targetKey: item.identityKey,
              beforeFingerprint: item._account?.tokenFingerprints?.access || null,
              afterFingerprint: item.fingerprints?.access || null,
              result: 'failed',
              details: { error: message, code: error?.code || null, sub2api: safeImportResult(error?.result) },
            });
          } catch (auditError) {
            writeLog(logger, 'error', 'import.audit_failed', {
              ...baseFields,
              error: safeErrorMessage(auditError),
            });
          }
          writeLog(logger, 'error', 'import.account_failed', {
            ...baseFields,
            durationMs: Date.now() - itemStartedAt,
            error: message,
          });
        }
      }
      if (!haltedForReconciliation) throwIfJobInterrupted(signal);
      const failed = imported.filter((item) => item.error).length;
      const runtimeSkipped = imported.filter((item) => item.skipped).length;
      const reconciliationCount = imported.filter(
        (item) => item.requiresReconciliation === true,
      ).length;
      const succeeded = imported.length - failed - runtimeSkipped;
      writeLog(logger, failed > 0 ? 'warn' : 'info', 'import.accounts_completed', {
        jobId,
        actor,
        count: plan.length,
        attempted: imported.length,
        succeeded,
        failed,
        skipped: runtimeSkipped,
        requiresReconciliation: haltedForReconciliation,
        reconciliationCount,
        notAttempted: notAttempted.length,
      });
          return {
        ...importPlanSummary(plan),
        imported,
        notAttempted,
        backupPath,
        attempted: imported.length,
        succeeded,
        failed,
        runtimeSkipped,
        notAttemptedCount: notAttempted.length,
        halted: haltedForReconciliation,
        requiresReconciliation: haltedForReconciliation,
        reconciliationCount,
          };
        }, { signal });
      } catch (error) {
        if (typeof persistFailure === 'function') {
          try {
            // Keep the durable job status in step with the protected operation.
            // The observer repeats this idempotently if local persistence is
            // temporarily unavailable.
            await persistFailure(error);
          } catch (jobError) {
            writeLog(logger, 'error', 'import.job_update_deferred', {
              jobId,
              actor,
              terminalOutcome: 'failed',
              error: safeErrorMessage(jobError),
            });
          }
        }
        throw error;
      }
      if (typeof persistResult === 'function') {
        try {
          await persistResult(lockedResult);
        } catch (jobError) {
          writeLog(logger, 'error', 'import.job_update_deferred', {
            jobId,
            actor,
            terminalOutcome: 'completed',
            error: safeErrorMessage(jobError),
          });
        }
      }
      return lockedResult;
    }, { signal });
    writeLog(logger, result.failed > 0 ? 'warn' : 'info', 'import.completed', {
      jobId,
      actor,
      durationMs: Date.now() - startedAt,
      importedCount: result.imported?.length || 0,
      failed: result.failed || 0,
      skipped: Boolean(result.skipped || result.runtimeSkipped),
      requiresReconciliation: result.requiresReconciliation === true,
      notAttempted: result.notAttemptedCount || 0,
      backupPath: result.backupPath || null,
    });
    return result;
  } catch (error) {
    writeLog(logger, 'error', 'import.failed', {
      jobId,
      actor,
      durationMs: Date.now() - startedAt,
      error: safeErrorMessage(error),
      code: error?.code || null,
    });
    throw error;
  }
}

module.exports = {
  buildSnapshot,
  buildImportPlan,
  collectCandidates,
  compareTokenRecordFreshness,
  buildOAuthUpdatePayload,
  buildCodexSessionDocument,
  buildCodexImportIdempotencyKey,
  revalidateSourceToken,
  executeImportPlanItem,
  importResultAccountId,
  executeImport,
  importPlanSummary,
  safeImportResult,
  resolveGroupIds,
  configuredForSub2Api,
  confirmedSub2ApiRead,
  snapshotVersion,
  safeErrorMessage,
  writeBackup,
};
