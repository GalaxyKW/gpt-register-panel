const fs = require('node:fs');
const path = require('node:path');
const { getAccountAvailability } = require('./accountAvailability');
const { accountTestTargetRevision, accountTestTargetDigest, matchesAccountTestTargetRevision } = require('./accountTargetRevision');
const { parseDateValue } = require('./lib/token');
const { assertAuditLogCheckpoint } = require('./logger');
const { accountInMaintenanceScope, lifecycleIdentityKeys, managementEndpointKey,
  validEndpointKey, TERMINAL_LIFECYCLE_STATES } = require('./accountLifecycle');

const BAN_CODES = new Set(['account_deactivated', 'user_deactivated', 'account_suspended', 'account_banned']);
const AUTH_CODES = new Set(['invalid_grant', 'invalid_token', 'token_expired', 'refresh_token_expired',
  'refresh_token_reused', 'refresh_token_revoked', 'token_revoked', 'session_expired']);
const QUOTA_CODES = new Set(['insufficient_quota', 'usage_limit_reached', 'rate_limit_exceeded',
  'rate_limit_error', 'quota_exceeded', 'overloaded', 'server_overloaded']);

function maintenanceError(code, message = '账号维护安全核验未通过，未继续操作') {
  const error = new Error(message);
  error.code = code;
  return error;
}

function structuredErrorCode(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 16384) return '';
  const trimmed = text.trim();
  const body = trimmed.startsWith('{') ? trimmed : /\bbody:\s*(\{[\s\S]*\})\s*$/i.exec(trimmed)?.[1];
  if (!body) return '';
  let value;
  try { value = JSON.parse(body); } catch { return ''; }
  const codes = [value?.error?.code, value?.error?.type, value?.detail?.code, value?.code]
    .filter((code) => typeof code === 'string' && /^[a-z][a-z0-9_]{1,63}$/.test(code));
  const recognized = [...new Set(codes.filter((code) => BAN_CODES.has(code) || AUTH_CODES.has(code) || QUOTA_CODES.has(code)))];
  return recognized.length === 1 ? recognized[0] : '';
}

// Raw error text only exists while parsing the management response. Return
// finite, non-secret enums; never carry raw errors, arbitrary codes or bodies
// into snapshots, task results, the browser, or lifecycle rows.
function maintenanceEvidenceFromRaw(account) {
  const messages = [account?.error_message, account?.errorMessage,
    account?.temp_unschedulable_reason, account?.tempUnschedulableReason]
    .filter((value) => typeof value === 'string' && Buffer.byteLength(value) <= 16384);
  const codes = [...new Set(messages.map(structuredErrorCode).filter(Boolean))];
  if (codes.some((code) => QUOTA_CODES.has(code)) || messages.some((message) => /(?:\b(?:429|rate[_ -]?limit|insufficient_quota|usage_limit_reached|quota[_ -]?exceeded|overload(?:ed)?)\b|额度.*(?:用完|耗尽)|限流)/i.test(message))) {
    return { category: 'quota_wait', code: 'upstream_quota_or_overload' };
  }
  if (codes.length === 1 && BAN_CODES.has(codes[0])) return { category: 'confirmed_banned', code: codes[0] };
  if (codes.length === 1 && AUTH_CODES.has(codes[0])) return { category: 'auth_invalid', code: codes[0] };
  if (codes.length > 1) return { category: 'network_unknown', code: 'conflicting_upstream_evidence' };
  // Expired/missing refresh tokens have a precise provider-generated marker;
  // arbitrary HTTP failures and provider/client configuration errors do not.
  if (messages.some((message) => message === 'openai access_token expired and refresh_token is missing')) {
    return { category: 'auth_invalid', code: 'refresh_token_missing' };
  }
  if (messages.some((message) => /^Token refresh failed \(non-retryable\):\s*(?:Error:\s*)?(?:invalid_grant|refresh_token_reused|refresh_token_expired|refresh_token_revoked)(?:\s|:|-|$)/.test(message))) {
    return { category: 'auth_invalid', code: 'refresh_reauthorization_required' };
  }
  return { category: 'network_unknown', code: messages.length ? 'unclassified_upstream_error' : 'no_error_evidence' };
}

function dateMs(value) {
  const normalized = parseDateValue(value);
  return normalized ? Date.parse(normalized) : null;
}

function classifyAccountMaintenance(account, { nowMs = Date.now() } = {}) {
  if (!Number.isFinite(nowMs) || account?.schemaValid === false
      || account?.identityConflict || account?.fingerprintConflict || account?.credentialsStatusConflict) {
    return { classification: 'network_unknown', reasonCode: 'account_schema_unknown' };
  }
  if (['inactive', 'disabled'].includes(account?.status)) {
    return { classification: 'manual_disabled', reasonCode: 'administrator_disabled' };
  }
  if (!['active', 'error'].includes(account?.status)) {
    return { classification: 'network_unknown', reasonCode: 'account_status_unknown' };
  }
  // This top-level expiry is an administrator's account lifetime, not an
  // OAuth access token deadline. Reauthorizing and restoring scheduling
  // cannot override that policy, even when a stale error also says invalid_grant.
  if (account.autoPauseOnExpired !== false && dateMs(account.expiresAt) !== null
      && dateMs(account.expiresAt) <= nowMs) {
    return { classification: 'manual_disabled', reasonCode: 'administrator_lifetime_expired' };
  }
  const evidence = account?.maintenanceEvidence;
  if (evidence?.category === 'quota_wait'
      || ['rateLimitResetAt', 'overloadUntil'].some((field) => (dateMs(account[field]) || 0) > nowMs)) {
    return { classification: 'quota_wait', reasonCode: 'quota_or_cooldown',
      retryAt: [account.rateLimitResetAt, account.overloadUntil].filter((value) => (dateMs(value) || 0) > nowMs).sort().at(-1) || null };
  }
  // A healthy live account overrides stale historical auth/ban metadata.
  if (getAccountAvailability(account, nowMs).key === 'available') {
    return { classification: 'healthy', reasonCode: 'account_available' };
  }
  if (evidence?.category === 'confirmed_banned' && BAN_CODES.has(evidence.code)
      && account.status === 'error') return { classification: 'confirmed_banned', reasonCode: evidence.code };
  if (evidence?.category === 'auth_invalid'
      && (AUTH_CODES.has(evidence.code) || ['refresh_token_missing', 'refresh_reauthorization_required'].includes(evidence.code))) {
    return { classification: 'auth_invalid', reasonCode: evidence.code };
  }
  // An access token's expiry is not enough while the account is active and
  // schedulable; Sub2API may already be refreshing it. Account lifetime expiry
  // is an administrator policy and must not be "fixed" with a new token.
  if (account.status === 'error' && dateMs(account.credentialExpiresAt) !== null
      && dateMs(account.credentialExpiresAt) <= nowMs) {
    return { classification: 'expired', reasonCode: 'credential_expired_unavailable' };
  }
  if (account.status === 'active' && account.schedulable === false
      && (!account.errorMessage || evidence?.code === 'no_error_evidence')) {
    return { classification: 'manual_disabled', reasonCode: 'administrator_unscheduled' };
  }
  return { classification: 'network_unknown', reasonCode: 'failure_requires_diagnosis' };
}

function buildMaintenancePlan({ accounts, lifecycles = [], endpointKey, nowMs = Date.now(), policy = {} }) {
  if (!Array.isArray(accounts) || accounts.length > 10000 || !Array.isArray(lifecycles)
      || !validEndpointKey(endpointKey)) throw maintenanceError('MAINTENANCE_PLAN_INVALID');
  const summary = { keep: 0, wait: 0, refresh: 0, delete: 0, review: 0, skip: 0 };
  const identityOwners = new Map();
  const idCounts = new Map();
  for (const account of accounts) {
    idCounts.set(account.id, (idCounts.get(account.id) || 0) + 1);
    for (const key of lifecycleIdentityKeys(account)) {
      const owners = identityOwners.get(key) || new Set();
      owners.add(account); identityOwners.set(key, owners);
    }
  }
  const historyByKey = new Map();
  for (const row of lifecycles) {
    if (row.endpointKey !== endpointKey) continue;
    const history = historyByKey.get(row.identityKey) || [];
    history.push(row); historyByKey.set(row.identityKey, history);
  }
  const items = accounts.map((account) => {
    const identityKeys = lifecycleIdentityKeys(account);
    const classified = classifyAccountMaintenance(account, { nowMs });
    let action = ({ healthy: 'keep', quota_wait: 'wait', auth_invalid: 'refresh', expired: 'refresh',
      confirmed_banned: 'delete', manual_disabled: 'skip', network_unknown: 'review' })[classified.classification];
    let reasonCode = classified.reasonCode;
    const overlaps = new Set(identityKeys.flatMap((key) => [...(identityOwners.get(key) || [])]));
    const lifecycle = identityKeys.flatMap((key) => historyByKey.get(key) || []);
    const revision = accountTestTargetRevision(account);
    if (!accountInMaintenanceScope(account)) { action = 'skip'; reasonCode = 'outside_free_oauth_scope'; }
    else if (identityKeys.length === 0 || overlaps.size !== 1 || !revision || idCounts.get(account.id) !== 1) {
      action = 'review'; reasonCode = 'strong_identity_ambiguous';
    } else if (lifecycle.some((row) => TERMINAL_LIFECYCLE_STATES.has(row.state) || row.sub2apiId !== account.id)) {
      action = 'review'; reasonCode = 'lifecycle_requires_reconciliation';
    } else if ((action === 'refresh' && policy.refreshInvalid === false) || (action === 'delete' && policy.deleteBanned === false)) {
      action = 'skip'; reasonCode = 'disabled_by_policy';
    }
    summary[action] += 1;
    return { accountId: account.id, accountName: account.name || '', identityKeys,
      targetRevision: revision, classification: classified.classification, action, reasonCode,
      ...(classified.retryAt ? { retryAt: classified.retryAt } : {}) };
  });
  return { items, summary };
}

async function verifyPhase3BanEvidence(db, jobId, { target, account, client }) {
  const { validateBoundRemoteTarget, remotePhase3EndpointDigest } = require('./remotePhase3');
  const job = await db.getJob(jobId);
  const result = job?.result;
  if (job?.type !== 'phase3' || job?.status !== 'failed' || !job.finishedAt
      || job.payload?.sourceMode !== 'token'
      || result?.code !== 'ACCOUNT_DEACTIVATED' || result?.accountDisposition !== 'discard'
      || result?.dispositionPersisted !== true || result?.dispositionOutcome !== 'persisted'
      || result?.requiresReconciliation === true || result?.writeOutcomeUnknown === true
      || result?.dispositionWriteOutcomeUnknown === true || job.reconciliationHold === true) {
    throw maintenanceError('MAINTENANCE_BAN_EVIDENCE_INVALID');
  }
  let binding;
  try { binding = validateBoundRemoteTarget(job.payload?.remoteTarget); }
  catch { throw maintenanceError('MAINTENANCE_BAN_EVIDENCE_INVALID'); }
  if (binding.accountId !== target.accountId || account.id !== target.accountId
      || binding.endpointDigest !== remotePhase3EndpointDigest(client)
      || binding.targetDigest !== accountTestTargetDigest(account)
      || JSON.stringify(binding.identityKeys) !== JSON.stringify(lifecycleIdentityKeys(account))) {
    throw maintenanceError('MAINTENANCE_BAN_EVIDENCE_INVALID');
  }
  return true;
}

async function assertDeletionTarget(account, target, nowMs, verifyBanEvidence) {
  if (!accountInMaintenanceScope(account) || account.id !== target.accountId
      || account.name !== target.accountName || account.status !== 'error'
      || !matchesAccountTestTargetRevision(target.targetRevision, account)
      || JSON.stringify(lifecycleIdentityKeys(account)) !== JSON.stringify(target.identityKeys)) {
    throw maintenanceError('MAINTENANCE_DELETE_TARGET_CHANGED');
  }
  const classification = classifyAccountMaintenance(account, { nowMs }).classification;
  if (classification === 'confirmed_banned') return;
  if (['quota_wait', 'healthy', 'manual_disabled'].includes(classification)
      || typeof verifyBanEvidence !== 'function' || await verifyBanEvidence(account) !== true) {
    throw maintenanceError('MAINTENANCE_DELETE_TARGET_CHANGED');
  }
}

function assertDeletionBackup(exported, account) {
  if (!exported || !Array.isArray(exported.accounts) || exported.accounts.length !== 1
      || !Array.isArray(exported.proxies) || exported.proxies.length !== 0) {
    throw maintenanceError('MAINTENANCE_DELETE_BACKUP_INVALID');
  }
  const raw = exported.accounts[0];
  if (!raw || !raw.credentials || typeof raw.credentials !== 'object' || Array.isArray(raw.credentials)
      || (raw.id !== undefined && raw.id !== account.id)
      || raw.name !== account.name || raw.platform !== account.platform || raw.type !== account.type) {
    throw maintenanceError('MAINTENANCE_DELETE_BACKUP_INVALID');
  }
  const { safeAccount } = require('./adapters/sub2apiAdmin');
  const extra = { ...raw.extra };
  const credentials = { ...raw.credentials };
  for (const key of ['access_token_sha256', 'refresh_token_sha256', 'id_token_sha256']) {
    delete extra[key]; delete credentials[key];
  }
  const safe = safeAccount({ ...raw, id: account.id, extra, credentials });
  if (!safe || safe.schemaValid === false || safe.planType !== 'free'
      || JSON.stringify(lifecycleIdentityKeys(safe)) !== JSON.stringify(lifecycleIdentityKeys(account))) {
    throw maintenanceError('MAINTENANCE_DELETE_BACKUP_INVALID');
  }
  for (const kind of ['access', 'refresh', 'id']) {
    const expectedPresence = account.credentialPresence?.[kind];
    const expected = account.tokenFingerprints?.[kind];
    const actualPresence = safe.tokenFingerprints?.[kind] ? 'present' : 'absent';
    if (actualPresence !== expectedPresence
        || (expected && safe.tokenFingerprints?.[kind] !== expected)) throw maintenanceError('MAINTENANCE_DELETE_BACKUP_INVALID');
  }
}

async function deleteConfirmedBannedAccount({ client, db, target, endpointKey, backup, signal = null,
  now = () => Date.now(), verifyBanEvidence = null, logger = null, jobId = null, actor = 'local' }) {
  if (!client || !db || typeof backup !== 'function' || !validEndpointKey(endpointKey)
      || managementEndpointKey(client.baseUrl) !== endpointKey || !target
      || target.action !== 'delete' || !Number.isSafeInteger(target.accountId)
      || !Array.isArray(target.identityKeys) || !target.identityKeys.length) {
    throw maintenanceError('MAINTENANCE_DELETE_INVALID');
  }
  const ensureNotAborted = () => { if (signal?.aborted) throw maintenanceError('MAINTENANCE_INTERRUPTED'); };
  ensureNotAborted();
  const history = await db.listAccountLifecycles(endpointKey);
  if (history.some((row) => row.endpointKey === endpointKey && target.identityKeys.includes(row.identityKey)
      && (TERMINAL_LIFECYCLE_STATES.has(row.state) || row.sub2apiId !== target.accountId))) {
    throw maintenanceError('MAINTENANCE_DELETE_ALREADY_RECORDED');
  }
  const all = await client.listAccounts({ platform: 'openai', type: 'oauth', pageSize: 200,
    requireTotal: true, requirePaginationMetadata: true, signal });
  const matches = all.filter((account) => lifecycleIdentityKeys(account).some((key) => target.identityKeys.includes(key)));
  if (matches.length !== 1 || matches[0].id !== target.accountId
      || all.filter((account) => account.id === target.accountId).length !== 1) throw maintenanceError('MAINTENANCE_DELETE_IDENTITY_AMBIGUOUS');
  await assertDeletionTarget(matches[0], target, now(), verifyBanEvidence);
  const before = await client.getAccount(target.accountId, { signal });
  await assertDeletionTarget(before, target, now(), verifyBanEvidence);
  const exported = await client.exportAccounts([target.accountId], { includeProxies: false, signal });
  assertDeletionBackup(exported, before);
  const auditFields = { jobId, actor, accountId: target.accountId, endpointKey };
  assertAuditLogCheckpoint(logger, 'maintenance.delete_backup_checkpoint', auditFields);
  const backupPath = await backup(exported, { accountId: target.accountId, endpointKey });
  if (typeof backupPath !== 'string' || !path.isAbsolute(backupPath)) throw maintenanceError('MAINTENANCE_DELETE_BACKUP_MISSING');
  const info = fs.lstatSync(backupPath);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o077) !== 0) {
    throw maintenanceError('MAINTENANCE_DELETE_BACKUP_MISSING');
  }
  ensureNotAborted();
  const afterBackup = await client.getAccount(target.accountId, { signal });
  await assertDeletionTarget(afterBackup, target, now(), verifyBanEvidence);
  const record = { endpointKey, identityKeys: target.identityKeys, sub2apiId: target.accountId,
    accountName: target.accountName, state: 'delete_pending', reasonCode: 'confirmed_ban_delete_pending' };
  // Persist before dispatch, not after the network result. A crash can never
  // leave old token files eligible for automatic re-import.
  await db.audit({ jobId, actor, action: 'account_delete_prepare', targetKey: String(target.accountId),
    result: 'prepared', details: { endpointKey, backupPath, identityKeys: target.identityKeys } });
  assertAuditLogCheckpoint(logger, 'maintenance.delete_checkpoint', auditFields);
  try {
    await db.upsertAccountLifecycle(record);
    const persisted = await db.listAccountLifecycles(endpointKey);
    if (!target.identityKeys.every((key) => persisted.some((row) => row.endpointKey === endpointKey
        && row.identityKey === key && row.sub2apiId === target.accountId && row.state === 'delete_pending'))) {
      throw maintenanceError('MAINTENANCE_DELETE_ALREADY_RECORDED');
    }
    ensureNotAborted();
    let deleteError;
    try { await client.deleteAccount(target.accountId, { signal }); } catch (error) { deleteError = error; }
    ensureNotAborted();
    let absent = false;
    try { await client.getAccount(target.accountId, { signal }); }
    catch (error) { absent = error?.code === 'SUB2API_REQUEST_REJECTED' && error?.upstreamStatus === 404; }
    if (!absent) throw maintenanceError('MAINTENANCE_DELETE_OUTCOME_UNKNOWN');
    // An HTTP failure may follow a successful deletion (lost response). The
    // exact-ID authenticated 404 is the result, never the response wording.
    await db.upsertAccountLifecycle({ ...record, state: 'deleted', reasonCode: 'confirmed_ban_deleted' });
    await db.audit({ jobId, actor, action: 'account_delete_verified', targetKey: String(target.accountId),
      result: 'deleted', details: { endpointKey, backupPath, verifiedAbsent: true } });
    return { outcome: 'deleted', accountId: target.accountId, accountName: target.accountName,
      backupPath, verifiedAbsent: true, recoveredLostResponse: Boolean(deleteError), requiresReconciliation: false };
  } catch {
    try { logger?.error('maintenance.delete_unknown', { ...auditFields, reason: 'account_delete_outcome_unknown' }); } catch {}
    const error = maintenanceError('MAINTENANCE_DELETE_OUTCOME_UNKNOWN', '删除结果尚未确认，已保留账号墓碑和待核对阻挡');
    error.requiresReconciliation = true;
    error.writeOutcomeUnknown = true;
    error.reconciliationReason = 'account_delete_outcome_unknown';
    throw error;
  }
}

module.exports = { maintenanceEvidenceFromRaw, classifyAccountMaintenance, buildMaintenancePlan,
  deleteConfirmedBannedAccount, assertDeletionBackup, verifyPhase3BanEvidence };
