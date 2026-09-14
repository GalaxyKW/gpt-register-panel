const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const initSqlJs = require('sql.js');
const { redactText, redactValue } = require('./logger');
const { acquireBakeryLease, releaseBakeryLease } = require('./lib/bakeryLock');
const { ensureDirectoryTree } = require('./lib/safeFs');
const { currentProcessOwner, isProcessOwnerAlive } = require('./taskCoordinator');
const { mutationKeyHash, normalizeIdempotencyKey } = require('./idempotency');

// /tmp keeps an unconfigured development run writable in restricted containers.
// Production should set PANEL_DB_PATH to a 0600 path under the project runtime directory.
const DEFAULT_DB_PATH = path.join('/tmp', 'gpt-register-panel', 'panel.sqlite3');
const initializationPromises = new Map();
const DB_LOCK_KIND = 'gpt-register-panel-db-lock';
const DEFAULT_DB_MAX_BYTES = 128 * 1024 * 1024;
const HARD_DB_MAX_BYTES = 512 * 1024 * 1024;
const MAX_JOB_PAYLOAD_BYTES = 1024 * 1024;
const MAX_JOB_RESULT_BYTES = 2 * 1024 * 1024;
const MAX_JOB_ERROR_BYTES = 64 * 1024;
const MAX_AUDIT_TEXT_BYTES = 16 * 1024;
const MAX_AUDIT_DETAILS_BYTES = 512 * 1024;
const MAX_JOB_CLAIM_KEYS = 1000;
const MAX_JOB_CLAIM_KEY_BYTES = 512;
const MAX_RECONCILIATION_LIST_JOBS = 100;
const MAX_MUTATION_RECEIPT_RESPONSE_BYTES = 64 * 1024;
const MAX_MUTATION_RECEIPT_JOBS = 100;
const MAX_MUTATION_RECEIPT_JOB_IDS_BYTES = 8 * 1024;
const DEFAULT_MUTATION_RECEIPT_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MIN_MUTATION_RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_MUTATION_RECEIPT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_MUTATION_RECEIPTS = 2000;
const HARD_MAX_MUTATION_RECEIPTS = 10000;
// Public history pages need only a compact operational summary. Individual
// results may legitimately approach MAX_JOB_RESULT_BYTES, so transferring,
// parsing and recursively redacting hundreds of them on every poll would let
// old jobs monopolize the event loop. Full (still bounded/redacted) results
// remain available through getJob().
const MAX_JOB_LIST_RESULT_BYTES = 16 * 1024;
const MAX_ACTIVE_JOB_LIST_JOBS = 200;
const LEGACY_GLOBAL_CLAIM_PREFIX = 'reconciliation:legacy-global:';
const RECONCILIATION_ACK_CONFIRMATION = '我已按强身份完成人工核对';
const RECONCILIATION_ACK_RESOLUTIONS = Object.freeze([
  'operation_applied',
  'operation_not_applied',
  'state_manually_reconciled',
]);
const RECONCILIATION_ACK_RESOLUTION_SET = new Set(RECONCILIATION_ACK_RESOLUTIONS);
const ACTIVE_JOB_STATUSES = new Set(['queued', 'running']);
const TERMINAL_JOB_STATUSES = new Set(['succeeded', 'partial', 'failed', 'interrupted']);
const JOB_STATUSES = new Set([...ACTIVE_JOB_STATUSES, ...TERMINAL_JOB_STATUSES]);

function sameInode(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function databaseMaximumBytes() {
  const value = Number(process.env.PANEL_DB_MAX_BYTES);
  if (!Number.isSafeInteger(value) || value < 1024 * 1024) return DEFAULT_DB_MAX_BYTES;
  return Math.min(value, HARD_DB_MAX_BYTES);
}

function readDatabaseBytes(descriptor, maximumBytes) {
  const chunks = [];
  let total = 0;
  while (total <= maximumBytes) {
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
    const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    total += bytesRead;
  }
  if (total > maximumBytes) {
    const error = new Error('SQLite 数据库文件超过安全上限');
    error.code = 'PANEL_DB_TOO_LARGE';
    throw error;
  }
  return Buffer.concat(chunks, total);
}

function storedJobOwnerIsAlive(job) {
  const verifier = currentProcessOwner();
  // Legacy rows without the identity dimensions available on this host cannot
  // prove that a reused PID still belongs to the process that queued the job.
  if (verifier.processStartId && !String(job?.owner_start_id || '').trim()) return false;
  if (verifier.processBootId && !String(job?.owner_boot_id || '').trim()) return false;
  return isProcessOwnerAlive(job?.owner_pid, job?.owner_start_id, job?.owner_boot_id);
}

function storedJobOwnerIsDefinitelyGone(job) {
  const pid = Number(job?.owner_pid);
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  const verifier = currentProcessOwner();
  const identityIncomplete = (verifier.processStartId && !String(job?.owner_start_id || '').trim())
    || (verifier.processBootId && !String(job?.owner_boot_id || '').trim());
  // Missing identity dimensions cannot distinguish the original owner from a
  // reused, currently-live PID. They may only be treated as dead once that PID
  // itself is no longer alive.
  if (identityIncomplete) return !isProcessOwnerAlive(pid);
  return !storedJobOwnerIsAlive(job);
}

function jsonString(value) {
  return JSON.stringify(value === undefined ? null : value);
}

function assertStoredByteLength(field, value, maximumBytes) {
  if (value === null || value === undefined) return value;
  const actualBytes = Buffer.byteLength(String(value), 'utf8');
  if (actualBytes <= maximumBytes) return value;
  const error = new Error('SQLite 字段超过安全字节上限');
  error.code = 'PANEL_DB_FIELD_TOO_LARGE';
  error.field = field;
  error.actualBytes = actualBytes;
  error.maximumBytes = maximumBytes;
  throw error;
}

function boundedJsonString(field, value, maximumBytes) {
  return assertStoredByteLength(field, jsonString(redactValue(value)), maximumBytes);
}

function boundedRedactedText(field, value, maximumBytes) {
  if (value === null || value === undefined) return value;
  return assertStoredByteLength(field, redactText(value), maximumBytes);
}

function randomId(prefix) {
  return prefix + '_' + crypto.randomBytes(12).toString('hex');
}

function sqlString(value) {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'boolean') return value ? '1' : '0';
  return "'" + String(value).replaceAll("'", "''") + "'";
}

function resultRows(result) {
  if (!result || result.length === 0) return [];
  const [{ columns, values }] = result;
  return values.map((row) => Object.fromEntries(columns.map((column, index) => [column, row[index]])));
}

function claimIntegrityError(message) {
  const error = new Error(message);
  error.code = 'JOB_CLAIM_INTEGRITY_INVALID';
  return error;
}

function reconciliationError(code, message, fields = {}) {
  const error = new Error(message);
  error.code = code;
  if (fields && typeof fields === 'object' && !Array.isArray(fields)) {
    Object.assign(error, fields);
  }
  return error;
}

function normalizeClaimKeys(value, { stored = false } = {}) {
  if (value === undefined && !stored) return [];
  if (!Array.isArray(value) || value.length > MAX_JOB_CLAIM_KEYS) {
    throw claimIntegrityError(stored
      ? '任务保护键元数据无效，拒绝解除并发安全屏障'
      : '任务保护键参数无效');
  }
  const normalized = [];
  const seen = new Set();
  for (const rawKey of value) {
    if (typeof rawKey !== 'string') {
      throw claimIntegrityError(stored
        ? '任务保护键元数据无效，拒绝解除并发安全屏障'
        : '任务保护键必须是字符串');
    }
    const key = rawKey.trim();
    if (!key || Buffer.byteLength(key, 'utf8') > MAX_JOB_CLAIM_KEY_BYTES) {
      throw claimIntegrityError(stored
        ? '任务保护键元数据无效，拒绝解除并发安全屏障'
        : '任务保护键为空或超过安全上限');
    }
    if (stored && key !== rawKey) {
      throw claimIntegrityError('任务保护键未按规范存储，拒绝解除并发安全屏障');
    }
    if (!stored && key.startsWith(LEGACY_GLOBAL_CLAIM_PREFIX)) {
      throw claimIntegrityError('任务保护键使用了保留命名空间');
    }
    if (seen.has(key)) {
      if (stored) {
        throw claimIntegrityError('任务保护键元数据重复，拒绝解除并发安全屏障');
      }
      continue;
    }
    seen.add(key);
    normalized.push(key);
  }
  return normalized;
}

function legacyGlobalClaimKey(jobId) {
  return LEGACY_GLOBAL_CLAIM_PREFIX
    + crypto.createHash('sha256').update(String(jobId)).digest('hex').slice(0, 32);
}

function isLegacyGlobalClaimKey(value) {
  return typeof value === 'string'
    && new RegExp('^' + LEGACY_GLOBAL_CLAIM_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      + '[a-f0-9]{32}$').test(value);
}

function parseStoredClaimKeys(job) {
  let parsed;
  try {
    parsed = JSON.parse(job?.claim_keys_json);
  } catch {
    throw claimIntegrityError('任务保护键元数据无法解析，拒绝解除并发安全屏障');
  }
  return normalizeClaimKeys(parsed, { stored: true });
}

function claimDigest(claimKeys) {
  return crypto.createHash('sha256').update(jsonString([...claimKeys].sort())).digest('hex');
}

function isCanonicalIsoTimestamp(value) {
  if (typeof value !== 'string' || value.length !== 24) return false;
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime()) && timestamp.toISOString() === value;
}

function parseStoredResult(job) {
  if (job?.result_json === null || job?.result_json === undefined) return null;
  let result;
  try {
    result = JSON.parse(job.result_json);
  } catch {
    throw claimIntegrityError('终态任务的结果元数据无法解析，拒绝处理保护键');
  }
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw claimIntegrityError('终态任务的结果元数据无效，拒绝处理保护键');
  }
  return result;
}

function resultHasReconciliationSignal(result) {
  return result?.requiresReconciliation === true
    || result?.reconciliationHold === true
    || result?.writeOutcomeUnknown === true;
}

function legacyInterruptedExecutionUnknown(job, result) {
  return job?.status === 'interrupted'
    && result === null
    && isCanonicalIsoTimestamp(job?.started_at)
    && isCanonicalIsoTimestamp(job?.finished_at);
}

function sameClaims(expected, actual) {
  return expected.size === actual.size
    && [...expected].every((claimKey) => actual.has(claimKey));
}

function recordClaimRecoveryAudit(database, job, result, details, createdAt) {
  const statement = database.prepare(`INSERT INTO audit_events
    (job_id, actor, action, target_key, before_fingerprint, after_fingerprint,
      result, details_json, created_at)
    VALUES (?, 'local', 'job_claim_recovery', NULL, NULL, NULL, ?, ?, ?)`);
  try {
    statement.run([
      job.id,
      result,
      jsonString(details),
      createdAt,
    ]);
  } finally {
    statement.free();
  }
}

function recordTerminalClaimCleanup(database, job, count, createdAt) {
  recordClaimRecoveryAudit(database, job, 'stale_terminal_claim_removed', {
    claimCount: count,
    terminalStatus: job.status,
  }, createdAt);
}

function validateAcknowledgedReconciliation(job, storedResult, expectedKeys, actual) {
  const digest = claimDigest(expectedKeys);
  const globalScope = job.reconciliation_scope === 'global';
  const claimScope = job.reconciliation_scope === 'claims';
  const hasLegacyGlobalKey = expectedKeys.length === 1
    && isLegacyGlobalClaimKey(expectedKeys[0]);
  if ((!globalScope && !claimScope)
      || expectedKeys.length === 0
      || globalScope !== hasLegacyGlobalKey
      || actual.size !== 0
      || !/^[a-f0-9]{64}$/.test(String(job.reconciliation_claim_digest || ''))
      || job.reconciliation_claim_digest !== digest
      || !isCanonicalIsoTimestamp(job.reconciliation_acknowledged_at)
      || !RECONCILIATION_ACK_RESOLUTION_SET.has(job.reconciliation_resolution)
      || job.reconciliation_acknowledged_by !== 'panel-admin'
      || storedResult?.reconciliationResolved !== true
      || storedResult?.reconciliationHold !== false
      || storedResult?.requiresReconciliation !== false
      || storedResult?.futureOperationsUnblocked !== true
      || storedResult?.doNotRetry !== true
      || storedResult?.retryAllowed !== false
      || storedResult?.reconciliationClaimDigest !== digest
      || storedResult?.reconciliationHoldScope !== (globalScope ? 'all_future_jobs' : 'claim_keys')
      || storedResult?.reconciliationBlockScope !== 'none'
      || storedResult?.reconciliationBlockScopeWas !== 'all_mutating_operations'
      || storedResult?.reconciliationResolution !== job.reconciliation_resolution
      || storedResult?.reconciliationAcknowledgedAt !== job.reconciliation_acknowledged_at
      || storedResult?.reconciliationAcknowledgedBy !== job.reconciliation_acknowledged_by) {
    throw claimIntegrityError('已确认对账任务的持久元数据不一致');
  }
}

function validateJobClaims(database, { cleanupOrdinaryTerminalClaims = false } = {}) {
  const jobs = resultRows(database.exec(`SELECT id, type, status, claim_keys_json,
      owner_pid, owner_start_id, owner_boot_id, started_at, finished_at, result_json, error,
      reconciliation_hold, reconciliation_scope, reconciliation_claim_digest, reconciliation_acknowledged_at,
      reconciliation_resolution, reconciliation_acknowledged_by
    FROM sync_jobs`));
  const jobsById = new Map();
  for (const job of jobs) {
    const id = typeof job.id === 'string' ? job.id : '';
    if (!id || jobsById.has(id)) {
      throw claimIntegrityError('任务标识无效，拒绝处理并发安全屏障');
    }
    jobsById.set(id, job);
  }

  const actualByJobId = new Map();
  const claimOwnerByKey = new Map();
  const claims = resultRows(database.exec(
    'SELECT claim_key, job_id, job_type FROM job_claims',
  ));
  for (const claim of claims) {
    const jobId = typeof claim.job_id === 'string' ? claim.job_id : '';
    const job = jobsById.get(jobId);
    if (!job) {
      throw claimIntegrityError('任务保护键指向不存在的任务，拒绝自动删除');
    }
    if (typeof claim.claim_key !== 'string'
        || claim.claim_key !== claim.claim_key.trim()
        || !claim.claim_key
        || Buffer.byteLength(claim.claim_key, 'utf8') > MAX_JOB_CLAIM_KEY_BYTES
        || claim.job_type !== job.type) {
      throw claimIntegrityError('任务保护键与任务元数据不一致，拒绝处理');
    }
    if (!actualByJobId.has(jobId)) actualByJobId.set(jobId, new Set());
    actualByJobId.get(jobId).add(claim.claim_key);
    claimOwnerByKey.set(claim.claim_key, jobId);
  }

  const activeJobs = [];
  const staleTerminalJobs = [];
  for (const job of jobs) {
    const active = ACTIVE_JOB_STATUSES.has(job.status);
    const holdValue = Number(job.reconciliation_hold);
    if (holdValue !== 0 && holdValue !== 1) {
      throw claimIntegrityError('待对账 hold 标记无效');
    }
    let hold = holdValue === 1;
    if (active && hold) {
      throw claimIntegrityError('活跃任务不得同时标记为待对账 hold');
    }
    if (!active && !TERMINAL_JOB_STATUSES.has(job.status)) {
      if (actualByJobId.has(job.id) || hold) {
        throw claimIntegrityError('任务状态无效，拒绝处理保护键');
      }
      continue;
    }
    const acknowledgementMetadataPresent = [
      job.reconciliation_scope,
      job.reconciliation_claim_digest,
      job.reconciliation_acknowledged_at,
      job.reconciliation_resolution,
      job.reconciliation_acknowledged_by,
    ].some((value) => value !== null && value !== undefined);
    let legacyTerminalResult = null;
    let legacyTerminalSignal = false;
    if (!active && !hold && !actualByJobId.has(job.id) && !acknowledgementMetadataPresent) {
      legacyTerminalResult = parseStoredResult(job);
      legacyTerminalSignal = resultHasReconciliationSignal(legacyTerminalResult);
      if (!legacyTerminalSignal && legacyInterruptedExecutionUnknown(job, legacyTerminalResult)) {
        legacyTerminalResult = {
          code: 'JOB_EXECUTION_OUTCOME_UNKNOWN',
          outcome: 'requires_reconciliation',
          executionOutcome: 'unknown',
          writeOutcomeUnknown: true,
          requiresReconciliation: true,
          reconciliationReason: 'legacy_owner_process_exited_while_running',
          retryAllowed: false,
          doNotRetry: true,
        };
        legacyTerminalSignal = true;
      }
      if (!legacyTerminalSignal) continue;
    }

    let expectedKeys;
    const claimMetadataWasMissing = job.claim_keys_json === null;
    if (claimMetadataWasMissing) {
      const recoverableKeys = [...(actualByJobId.get(job.id) || [])].sort();
      if (recoverableKeys.length > 0) {
        const repair = database.prepare('UPDATE sync_jobs SET claim_keys_json = ? WHERE id = ? AND claim_keys_json IS NULL');
        try {
          repair.run([jsonString(recoverableKeys), job.id]);
        } finally {
          repair.free();
        }
        job.claim_keys_json = jsonString(recoverableKeys);
        expectedKeys = recoverableKeys;
      } else if (active
          && job.status === 'queued'
          && !jobExecutionOutcomeUnknown(job)
          && storedJobOwnerIsDefinitelyGone(job)) {
        const repair = database.prepare("UPDATE sync_jobs SET claim_keys_json = '[]' WHERE id = ? AND claim_keys_json IS NULL");
        try {
          repair.run([job.id]);
        } finally {
          repair.free();
        }
        job.claim_keys_json = '[]';
        job.force_recovery = true;
        expectedKeys = [];
      } else if (active
          && Number.isSafeInteger(Number(job.owner_pid))
          && Number(job.owner_pid) > 0
          && !storedJobOwnerIsDefinitelyGone(job)) {
        // A live owner may still dispatch this queued task. Neither inventing
        // an empty claim list nor terminalizing the row is safe while that
        // process is active, so fail closed and leave its state untouched.
        throw claimIntegrityError('活动任务缺少可恢复的保护键元数据，拒绝并发处理');
      } else if (active) {
        // Rows created before durable claims existed cannot identify the
        // affected target after execution may have started. Convert that
        // uncertainty into an explicit global barrier. A unique synthetic key
        // makes the hold acknowledgeable without pretending it is a target key.
        const globalClaimKey = legacyGlobalClaimKey(job.id);
        const repairedAt = new Date().toISOString();
        const repair = database.prepare(`UPDATE sync_jobs
          SET claim_keys_json = ?, reconciliation_scope = 'global'
          WHERE id = ? AND claim_keys_json IS NULL`);
        const insert = database.prepare(`INSERT INTO job_claims
          (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
        try {
          repair.run([jsonString([globalClaimKey]), job.id]);
          insert.run([globalClaimKey, job.id, job.type, repairedAt]);
        } finally {
          repair.free();
          insert.free();
        }
        recordClaimRecoveryAudit(database, job, 'legacy_global_hold_created', {
          claimCount: 1,
          previousClaimMetadata: 'missing',
          scope: 'all_future_jobs',
          activeStatus: job.status,
        }, repairedAt);
        job.claim_keys_json = jsonString([globalClaimKey]);
        job.reconciliation_scope = 'global';
        job.force_recovery = true;
        expectedKeys = [globalClaimKey];
        actualByJobId.set(job.id, new Set(expectedKeys));
      } else if (!active && !hold && !acknowledgementMetadataPresent && legacyTerminalSignal) {
        // A pre-claim-schema terminal row cannot identify its original target,
        // but a trusted unknown-outcome signal still requires a durable safety
        // barrier. Let the keyless legacy migration below assign a synthetic
        // global key instead of making the whole database permanently
        // unopenable. Ordinary terminal rows without that signal were already
        // skipped above and remain untouched.
        expectedKeys = [];
      } else {
        throw claimIntegrityError('旧版任务缺少可恢复的保护键元数据，拒绝启动');
      }
    } else {
      expectedKeys = parseStoredClaimKeys(job);
    }
    const expected = new Set(expectedKeys);
    const actual = actualByJobId.get(job.id) || new Set();
    if (!active && !hold && !acknowledgementMetadataPresent) {
      if (!legacyTerminalResult) legacyTerminalResult = parseStoredResult(job);
      legacyTerminalSignal = resultHasReconciliationSignal(legacyTerminalResult);
      if (legacyTerminalSignal) {
        if (expectedKeys.length === 0) {
          if (actual.size !== 0) {
            throw claimIntegrityError('旧版终态任务声明无保护键但仍存在映射，拒绝自动迁移');
          }
          // The block policy is deliberately global until every workflow
          // shares one resource key space. A synthetic key makes even an old
          // keyless unknown outcome durable and acknowledgeable.
          const globalClaimKey = legacyGlobalClaimKey(job.id);
          const repairedAt = new Date().toISOString();
          const repair = database.prepare(`UPDATE sync_jobs
            SET claim_keys_json = ?, reconciliation_scope = 'global'
            WHERE id = ? AND reconciliation_hold = 0`);
          const insert = database.prepare(`INSERT INTO job_claims
            (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
          try {
            repair.run([jsonString([globalClaimKey]), job.id]);
            insert.run([globalClaimKey, job.id, job.type, repairedAt]);
          } finally {
            repair.free();
            insert.free();
          }
          expectedKeys.push(globalClaimKey);
          expected.add(globalClaimKey);
          actual.add(globalClaimKey);
          actualByJobId.set(job.id, actual);
          claimOwnerByKey.set(globalClaimKey, job.id);
          job.claim_keys_json = jsonString(expectedKeys);
          job.reconciliation_scope = 'global';
          recordClaimRecoveryAudit(database, job, 'legacy_terminal_global_hold_created', {
            claimCount: 1,
            terminalStatus: job.status,
            previousClaimMetadata: claimMetadataWasMissing ? 'missing' : 'empty',
            scope: 'all_future_jobs',
          }, repairedAt);
        }

        const legacyGlobal = expectedKeys.length === 1
          && expectedKeys[0] === legacyGlobalClaimKey(job.id);
        if (expectedKeys.some(isLegacyGlobalClaimKey) && !legacyGlobal) {
          throw claimIntegrityError('旧版终态任务包含无法验证归属的全局保护键');
        }
        for (const claimKey of expectedKeys) {
          const ownerJobId = claimOwnerByKey.get(claimKey);
          if (ownerJobId && ownerJobId !== job.id) {
            throw claimIntegrityError('旧版终态任务的保护键已被其他任务占用，拒绝自动迁移');
          }
        }
        if (actual.size !== 0 && !sameClaims(expected, actual)) {
          throw claimIntegrityError('旧版终态任务的保护键映射不完整，拒绝自动迁移');
        }

        const repairedAt = new Date().toISOString();
        const digest = claimDigest(expectedKeys);
        const scope = legacyGlobal ? 'global' : 'claims';
        const holdFields = {
          requiresReconciliation: true,
          reconciliationHold: true,
          reconciliationResolved: false,
          futureOperationsUnblocked: false,
          reconciliationHoldUnavailable: false,
          reconciliationHoldReason: null,
          reconciliationClaimDigest: digest,
          heldClaimCount: expectedKeys.length,
          reconciliationHoldScope: legacyGlobal ? 'all_future_jobs' : 'claim_keys',
          reconciliationBlockScope: 'all_mutating_operations',
          reconciliationResolution: null,
          reconciliationAcknowledgedAt: null,
          reconciliationAcknowledgedBy: null,
          retryAllowed: false,
          doNotRetry: true,
        };
        const boundedHold = boundedReconciliationResult(
          legacyTerminalResult,
          holdFields,
          job.result_json,
        );
        const holdResult = boundedHold.result;
        const holdResultJson = boundedHold.json;
        const repair = database.prepare(`UPDATE sync_jobs
          SET result_json = ?, reconciliation_hold = 1,
            reconciliation_scope = ?, reconciliation_claim_digest = ?
          WHERE id = ? AND reconciliation_hold = 0`);
        const insert = database.prepare(`INSERT INTO job_claims
          (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
        try {
          repair.run([
            holdResultJson,
            scope,
            digest,
            job.id,
          ]);
          for (const claimKey of expectedKeys) {
            if (!claimOwnerByKey.has(claimKey)) {
              insert.run([claimKey, job.id, job.type, repairedAt]);
              actual.add(claimKey);
              claimOwnerByKey.set(claimKey, job.id);
            }
          }
        } finally {
          repair.free();
          insert.free();
        }
        recordClaimRecoveryAudit(database, job, 'legacy_terminal_hold_rebuilt', {
          claimCount: expectedKeys.length,
          terminalStatus: job.status,
          scope: legacyGlobal ? 'all_future_jobs' : 'claim_keys',
        }, repairedAt);
        actualByJobId.set(job.id, actual);
        job.result_json = holdResultJson;
        job.reconciliation_hold = 1;
        job.reconciliation_scope = scope;
        job.reconciliation_claim_digest = digest;
        hold = true;
      }
    }
    const acknowledged = !active && !hold && Boolean(job.reconciliation_acknowledged_at);
    if (acknowledged) {
      const storedResult = parseStoredResult(job);
      validateAcknowledgedReconciliation(job, storedResult, expectedKeys, actual);
      continue;
    }
    if (!sameClaims(expected, actual)) {
      throw claimIntegrityError('任务保护键与任务内保护键列表不一致，拒绝解除安全屏障');
    }

    if (active) {
      const activeGlobal = job.reconciliation_scope === 'global';
      if (activeGlobal !== (expected.size === 1 && isLegacyGlobalClaimKey(expectedKeys[0]))) {
        throw claimIntegrityError('旧版全局保护键与任务范围不一致');
      }
      if (!activeGlobal && job.reconciliation_scope !== null) {
        throw claimIntegrityError('活跃任务的对账范围无效');
      }
      if (job.reconciliation_claim_digest !== null
          || job.reconciliation_acknowledged_at !== null
          || job.reconciliation_resolution !== null
          || job.reconciliation_acknowledged_by !== null) {
        throw claimIntegrityError('活跃任务包含非法的对账确认元数据');
      }
      activeJobs.push(job);
      continue;
    }
    const storedResult = parseStoredResult(job);
    if (hold) {
      const digest = claimDigest(expected);
      const globalScope = job.reconciliation_scope === 'global';
      const claimScope = job.reconciliation_scope === 'claims';
      const hasLegacyGlobalKey = expected.size === 1
        && isLegacyGlobalClaimKey(expectedKeys[0]);
      if ((!globalScope && !claimScope)
          || expected.size === 0
          || globalScope !== hasLegacyGlobalKey
          || !/^[a-f0-9]{64}$/.test(String(job.reconciliation_claim_digest || ''))
          || job.reconciliation_claim_digest !== digest
          || storedResult?.reconciliationHold !== true
          || storedResult?.requiresReconciliation !== true
          || storedResult?.reconciliationResolved !== false
          || storedResult?.futureOperationsUnblocked !== false
          || storedResult?.doNotRetry !== true
          || storedResult?.retryAllowed !== false
          || storedResult?.reconciliationClaimDigest !== digest
          || storedResult?.reconciliationHoldScope !== (globalScope ? 'all_future_jobs' : 'claim_keys')
          || storedResult?.reconciliationBlockScope !== 'all_mutating_operations'
          || job.reconciliation_acknowledged_at !== null
          || job.reconciliation_resolution !== null
          || job.reconciliation_acknowledged_by !== null) {
        throw claimIntegrityError('待对账任务的持久 hold 元数据不一致');
      }
    } else {
      if (acknowledgementMetadataPresent) {
        throw claimIntegrityError('非 hold 任务的对账范围与确认状态不一致');
      }
      if (resultHasReconciliationSignal(storedResult)) {
        throw claimIntegrityError('终态任务仍需对账，拒绝将其保护键当作普通残留删除');
      }
      staleTerminalJobs.push({ job, count: actual.size });
    }
  }

  if (cleanupOrdinaryTerminalClaims && staleTerminalJobs.length > 0) {
    const now = new Date().toISOString();
    const remove = database.prepare('DELETE FROM job_claims WHERE job_id = ?');
    try {
      for (const { job, count } of staleTerminalJobs) {
        recordTerminalClaimCleanup(database, job, count, now);
        remove.run([job.id]);
      }
    } finally {
      remove.free();
    }
  } else if (staleTerminalJobs.length > 0) {
    throw claimIntegrityError('检测到普通终态任务的残留保护键，需要在持久化锁内清理');
  }
  return activeJobs;
}

function jobExecutionOutcomeUnknown(job) {
  return job?.status === 'running'
    || [job?.started_at, job?.finished_at, job?.result_json, job?.error]
      .some((value) => value !== null && value !== undefined);
}

function recoveredJobResult(job) {
  if (!jobExecutionOutcomeUnknown(job)) {
    return {
      code: 'JOB_OWNER_EXITED_BEFORE_START',
      outcome: 'not_started',
      executionOutcome: 'not_started',
      retryAllowed: true,
      doNotRetry: false,
      requiresReconciliation: false,
    };
  }
  return {
    code: 'JOB_EXECUTION_OUTCOME_UNKNOWN',
    outcome: 'requires_reconciliation',
    executionOutcome: 'unknown',
    writeOutcomeUnknown: true,
    requiresReconciliation: true,
    reconciliationResolved: false,
    futureOperationsUnblocked: false,
    retryAllowed: false,
    doNotRetry: true,
    reconciliationReason: job?.status === 'running'
      ? 'owner_process_exited_while_running'
      : 'queued_state_inconsistent',
  };
}

function interruptDeadOwnerJob(database, job, interruptedAt) {
  let claimKeys = parseStoredClaimKeys(job);
  const result = recoveredJobResult(job);
  if (result.requiresReconciliation && claimKeys.length === 0) {
    const globalClaimKey = legacyGlobalClaimKey(job.id);
    const claimStatement = database.prepare(`INSERT INTO job_claims
      (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
    try {
      claimStatement.run([globalClaimKey, job.id, job.type, interruptedAt]);
    } finally {
      claimStatement.free();
    }
    claimKeys = [globalClaimKey];
    job.claim_keys_json = jsonString(claimKeys);
    job.reconciliation_scope = 'global';
  }
  const retainClaims = result.requiresReconciliation && claimKeys.length > 0;
  const globalScope = retainClaims && job?.reconciliation_scope === 'global';
  const digest = retainClaims ? claimDigest(claimKeys) : null;
  if (retainClaims) {
    result.reconciliationHold = true;
    result.reconciliationHoldUnavailable = false;
    result.reconciliationHoldReason = null;
    result.reconciliationClaimDigest = digest;
    result.heldClaimCount = claimKeys.length;
    result.reconciliationHoldScope = globalScope ? 'all_future_jobs' : 'claim_keys';
    result.reconciliationBlockScope = 'all_mutating_operations';
  } else if (result.requiresReconciliation) {
    result.reconciliationHold = false;
    result.reconciliationHoldUnavailable = true;
    result.reconciliationHoldReason = 'no_claim_keys';
    result.reconciliationBlockScope = null;
  }
  const message = retainClaims
    ? '任务所属进程退出且执行结果未知；已保留持久保护键，请先人工核对操作影响的实际状态'
    : result.requiresReconciliation
      ? '任务所属进程退出且执行结果未知；该任务未配置保护键，无法为后续操作建立持久阻挡'
    : '任务所属进程已退出，排队任务未开始执行';
  const statement = database.prepare(`UPDATE sync_jobs
    SET status = 'interrupted', result_json = ?, error = ?, finished_at = ?,
      claim_keys_json = ?, reconciliation_hold = ?, reconciliation_scope = ?,
      reconciliation_claim_digest = ?
    WHERE id = ? AND status = ?`);
  try {
    statement.run([
      jsonString(result),
      message,
      interruptedAt,
      jsonString(claimKeys),
      retainClaims ? 1 : 0,
      retainClaims ? (globalScope ? 'global' : 'claims') : null,
      digest,
      job.id,
      job.status,
    ]);
  } finally {
    statement.free();
  }
  if (!retainClaims) {
    const release = database.prepare('DELETE FROM job_claims WHERE job_id = ?');
    try {
      release.run([job.id]);
    } finally {
      release.free();
    }
  }
  return result;
}

function reconciliationHoldError(job) {
  return reconciliationError(
    'JOB_RECONCILIATION_REQUIRED',
    '上一个任务的执行结果未知，持久保护键已阻止新操作；请先人工核对操作影响的实际状态',
    {
      existingJobId: job?.id || null,
      requiresReconciliation: true,
      reconciliationHold: true,
      reconciliationHoldScope: job?.reconciliation_scope === 'global'
        ? 'all_future_jobs'
        : 'claim_keys',
      reconciliationBlockScope: 'all_mutating_operations',
      retryAllowed: false,
      doNotRetry: true,
    },
  );
}

function firstReconciliationBarrier(database) {
  return resultRows(database.exec(`SELECT id, reconciliation_scope
    FROM sync_jobs
    WHERE reconciliation_hold = 1
    ORDER BY CASE WHEN reconciliation_scope = 'global' THEN 0 ELSE 1 END,
      created_at ASC, id ASC LIMIT 1`))[0] || null;
}

function firstRunningMutation(database) {
  return resultRows(database.exec(`SELECT id, type
    FROM sync_jobs
    WHERE status = 'running'
    ORDER BY COALESCE(started_at, created_at) ASC, id ASC LIMIT 1`))[0] || null;
}

function runningMutationError(job) {
  const error = new Error('已有写任务正在执行，已保守阻止新的写操作');
  error.code = 'JOB_ALREADY_CLAIMED';
  error.existingJobId = job?.id || null;
  error.blockScope = 'all_mutating_operations';
  return error;
}

function blockedBeforeExecutionError(code, message, job) {
  const error = new Error(message);
  error.code = code;
  error.blockedBeforeStart = true;
  error.executionOutcome = 'not_started';
  error.retryAllowed = false;
  error.doNotRetry = true;
  error.existingJobId = job?.id || null;
  return error;
}

function reconciliationResultSummary(result) {
  const safeString = (value, maximum = 128) => {
    if (typeof value !== 'string') return undefined;
    const normalized = value.trim();
    return normalized && normalized.length <= maximum && /^[A-Za-z0-9_.:-]+$/.test(normalized)
      ? normalized
      : undefined;
  };
  const safeCount = (value) => {
    const number = Number(value);
    return Number.isSafeInteger(number) && number >= 0 && number <= 1_000_000
      ? number
      : undefined;
  };
  return {
    code: safeString(result?.code),
    outcome: safeString(result?.outcome),
    executionOutcome: safeString(result?.executionOutcome),
    requiresReconciliation: result?.requiresReconciliation === true,
    reconciliationHold: result?.reconciliationHold === true,
    reconciliationResolved: result?.reconciliationResolved === true,
    reconciliationHoldUnavailable: result?.reconciliationHoldUnavailable === true,
    reconciliationHoldReason: safeString(result?.reconciliationHoldReason),
    reconciliationReason: safeString(result?.reconciliationReason),
    reconciliationClaimDigest: /^[a-f0-9]{64}$/.test(String(result?.reconciliationClaimDigest || ''))
      ? result.reconciliationClaimDigest
      : undefined,
    reconciliationHoldScope: safeString(result?.reconciliationHoldScope),
    reconciliationBlockScope: safeString(result?.reconciliationBlockScope),
    reconciliationBlockScopeWas: safeString(result?.reconciliationBlockScopeWas),
    heldClaimCount: safeCount(result?.heldClaimCount),
    succeeded: safeCount(result?.succeeded),
    failed: safeCount(result?.failed),
    skipped: safeCount(result?.skipped),
    runtimeSkipped: safeCount(result?.runtimeSkipped),
    reconciliationCount: safeCount(result?.reconciliationCount),
    notAttemptedCount: safeCount(result?.notAttemptedCount),
    writeOutcomeUnknown: result?.writeOutcomeUnknown === true,
    retryAllowed: result?.retryAllowed === true,
    doNotRetry: result?.doNotRetry === true,
    futureOperationsUnblocked: result?.futureOperationsUnblocked === true,
  };
}

function boundedReconciliationResult(originalResult, requiredFields, originalSerialized = null) {
  const result = { ...originalResult, ...requiredFields };
  try {
    return {
      result,
      json: boundedJsonString('sync_jobs.result_json', result, MAX_JOB_RESULT_BYTES),
    };
  } catch (error) {
    if (error?.code !== 'PANEL_DB_FIELD_TOO_LARGE') throw error;
    const serialized = typeof originalSerialized === 'string'
      ? originalSerialized
      : jsonString(redactValue(originalResult));
    // A result that was legal in the previous schema may leave no room for
    // newly required hold metadata. Keep the operational summary plus a digest
    // of the original bounded value so the safety barrier remains durable and
    // acknowledgeable instead of making startup or terminal persistence fail.
    const compact = {
      ...reconciliationResultSummary(originalResult),
      originalResultCompacted: true,
      originalResultBytes: Buffer.byteLength(serialized, 'utf8'),
      originalResultDigest: crypto.createHash('sha256').update(serialized).digest('hex'),
      ...requiredFields,
    };
    return {
      result: compact,
      json: boundedJsonString('sync_jobs.result_json', compact, MAX_JOB_RESULT_BYTES),
    };
  }
}

function normalizedJobListLimit(limit, fallback = 50) {
  let raw;
  let parsed;
  try {
    raw = limit === null || limit === undefined ? '' : String(limit).trim();
    parsed = Number(limit);
  } catch {
    return fallback;
  }
  if (!raw || !Number.isFinite(parsed)) return fallback;
  // Clamp before truncating so even a finite value outside the safe-integer
  // range can never be interpolated into SQL as an unsafe or decimal LIMIT.
  return Math.trunc(Math.max(1, Math.min(200, parsed)));
}

function boundedJobListText(value, maximumCharacters) {
  if (value === null || value === undefined) return null;
  return redactText(String(value)).slice(0, maximumCharacters);
}

function durableReconciliationListSummary(row) {
  if (Number(row?.reconciliation_hold) !== 1) return {};
  const digest = String(row?.reconciliation_claim_digest || '');
  const holdScope = row?.reconciliation_scope === 'global'
    ? 'all_future_jobs'
    : row?.reconciliation_scope === 'claims' ? 'claim_keys' : undefined;
  return {
    requiresReconciliation: true,
    reconciliationHold: true,
    reconciliationResolved: false,
    futureOperationsUnblocked: false,
    reconciliationClaimDigest: /^[a-f0-9]{64}$/.test(digest) ? digest : undefined,
    reconciliationHoldScope: holdScope,
    reconciliationBlockScope: 'all_mutating_operations',
    retryAllowed: false,
    doNotRetry: true,
  };
}

function mutationReceiptTtlMs() {
  const value = Number(process.env.PANEL_IDEMPOTENCY_TTL_MS);
  if (!Number.isFinite(value)) return DEFAULT_MUTATION_RECEIPT_TTL_MS;
  return Math.max(
    MIN_MUTATION_RECEIPT_TTL_MS,
    Math.min(MAX_MUTATION_RECEIPT_TTL_MS, Math.floor(value)),
  );
}

function maximumMutationReceipts() {
  const value = Number(process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS);
  if (!Number.isSafeInteger(value) || value <= 0) return DEFAULT_MAX_MUTATION_RECEIPTS;
  return Math.min(value, HARD_MAX_MUTATION_RECEIPTS);
}

function normalizeMutationWorkflow(value) {
  const workflow = typeof value === 'string' ? value.trim() : '';
  if (!/^[a-z][a-z0-9_]{1,63}$/.test(workflow)) {
    const error = new Error('幂等工作流标识无效');
    error.code = 'IDEMPOTENCY_WORKFLOW_INVALID';
    throw error;
  }
  return workflow;
}

function normalizeMutationActor(value) {
  const actor = typeof value === 'string' ? value.trim() : '';
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(actor)) {
    const error = new Error('幂等请求执行者无效');
    error.code = 'IDEMPOTENCY_SCOPE_INVALID';
    throw error;
  }
  return actor;
}

function normalizeRequestDigest(value) {
  const digest = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!/^[a-f0-9]{64}$/.test(digest)) {
    const error = new Error('幂等请求摘要无效');
    error.code = 'IDEMPOTENCY_REQUEST_INVALID';
    throw error;
  }
  return digest;
}

function normalizeMutationJobSpecs(value) {
  if (!Array.isArray(value) || value.length === 0
      || value.length > MAX_MUTATION_RECEIPT_JOBS) {
    const error = new Error('幂等提交必须包含 1 至 100 个任务');
    error.code = 'IDEMPOTENCY_JOBS_INVALID';
    throw error;
  }
  return value.map((rawSpec) => {
    if (!rawSpec || typeof rawSpec !== 'object' || Array.isArray(rawSpec)) {
      const error = new Error('幂等任务定义无效');
      error.code = 'IDEMPOTENCY_JOBS_INVALID';
      throw error;
    }
    const type = typeof rawSpec.type === 'string' ? rawSpec.type.trim() : '';
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(type)) {
      const error = new Error('幂等任务类型无效');
      error.code = 'IDEMPOTENCY_JOBS_INVALID';
      throw error;
    }
    return {
      type,
      payloadJson: boundedJsonString(
        'sync_jobs.payload_json',
        rawSpec.payload === undefined ? {} : rawSpec.payload,
        MAX_JOB_PAYLOAD_BYTES,
      ),
      claimKeys: normalizeClaimKeys(rawSpec.claimKeys),
      metadata: rawSpec.metadata,
    };
  });
}

function normalizeMaximumActiveByType(value) {
  if (value === undefined || value === null) return new Map();
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    const error = new Error('幂等任务容量约束无效');
    error.code = 'IDEMPOTENCY_JOBS_INVALID';
    throw error;
  }
  const result = new Map();
  for (const [rawType, rawMaximum] of Object.entries(value)) {
    const type = typeof rawType === 'string' ? rawType.trim() : '';
    const maximum = Number(rawMaximum);
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(type)
        || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 10000) {
      const error = new Error('幂等任务容量约束无效');
      error.code = 'IDEMPOTENCY_JOBS_INVALID';
      throw error;
    }
    result.set(type, maximum);
  }
  return result;
}

function mutationReceiptError(code, message, fields = {}) {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, fields);
  return error;
}

function receiptJobIds(row) {
  let values;
  try { values = JSON.parse(row?.job_ids_json); } catch {}
  if (!Array.isArray(values) || values.length === 0
      || values.length > MAX_MUTATION_RECEIPT_JOBS
      || values.some((id) => typeof id !== 'string' || !/^job_[a-f0-9]{24}$/.test(id))
      || new Set(values).size !== values.length) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '幂等回执关联的任务标识无效，已拒绝继续写入',
    );
  }
  return values;
}

function mutationReceiptStoredBytes(row, field, measuredField) {
  if (Object.prototype.hasOwnProperty.call(row || {}, measuredField)) {
    return Number(row[measuredField]);
  }
  return Buffer.byteLength(String(row?.[field] || ''), 'utf8');
}

function validateMutationReceiptMetadata(row) {
  const responseBytes = mutationReceiptStoredBytes(row, 'response_json', 'response_bytes');
  const jobIdsBytes = mutationReceiptStoredBytes(row, 'job_ids_json', 'job_ids_bytes');
  if (!/^[a-f0-9]{64}$/.test(String(row?.key_hash || ''))
      || !/^[a-z][a-z0-9_]{1,63}$/.test(String(row?.workflow || ''))
      || !/^[a-f0-9]{64}$/.test(String(row?.request_digest || ''))
      || Number(row?.http_status) !== 202
      || !Number.isSafeInteger(responseBytes)
      || responseBytes <= 0 || responseBytes > MAX_MUTATION_RECEIPT_RESPONSE_BYTES
      || !Number.isSafeInteger(jobIdsBytes)
      || jobIdsBytes <= 0 || jobIdsBytes > MAX_MUTATION_RECEIPT_JOB_IDS_BYTES
      || !isCanonicalIsoTimestamp(row?.created_at)
      || !isCanonicalIsoTimestamp(row?.expires_at)
      || row.expires_at <= row.created_at) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '幂等回执元数据无效，已拒绝继续写入',
    );
  }
}

function readBoundStatementRows(statement, parameters, maximumRows) {
  const rows = [];
  statement.bind(parameters);
  try {
    while (statement.step()) {
      rows.push(statement.getAsObject());
      if (rows.length >= maximumRows) break;
    }
  } finally {
    statement.reset();
  }
  return rows;
}

function mutationReceiptLinkedJobs(database, keyHash, reusableStatement) {
  const statement = reusableStatement || database.prepare(`SELECT id, status, reconciliation_hold,
    submission_key_hash FROM sync_jobs WHERE submission_key_hash = ?
    ORDER BY created_at ASC, id ASC LIMIT ${MAX_MUTATION_RECEIPT_JOBS + 1}`);
  try {
    return readBoundStatementRows(statement, [keyHash], MAX_MUTATION_RECEIPT_JOBS + 1);
  } finally {
    if (!reusableStatement) statement.free();
  }
}

function validateMutationReceiptResponse(response, jobIds) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '幂等回执响应无效，已拒绝继续写入',
    );
  }
  const responseJobIds = Array.isArray(response.jobIds)
    ? response.jobIds
    : typeof response.jobId === 'string' ? [response.jobId] : [];
  if (response.status !== 'queued'
      || responseJobIds.length !== jobIds.length
      || responseJobIds.some((id, index) => id !== jobIds[index])
      || (typeof response.jobId === 'string' && response.jobId !== jobIds[0])) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '幂等回执响应与关联任务不一致，已拒绝继续写入',
    );
  }
}

function decodeMutationReceipt(database, row, expected = {}) {
  if (!row) return null;
  validateMutationReceiptMetadata(row);
  const jobIds = receiptJobIds(row);
  if (expected.workflow && row.workflow !== expected.workflow) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '幂等回执工作流不一致，已拒绝继续写入',
    );
  }
  if (expected.requestDigest && row.request_digest !== expected.requestDigest) {
    throw mutationReceiptError(
      'IDEMPOTENCY_KEY_REUSED',
      '该 Idempotency-Key 已用于不同请求，请为新操作生成新键',
    );
  }
  let response;
  try { response = JSON.parse(row.response_json); } catch {}
  validateMutationReceiptResponse(response, jobIds);
  const linkedRows = Array.isArray(expected.linkedJobs)
    ? expected.linkedJobs
    : mutationReceiptLinkedJobs(database, row.key_hash);
  const linkedIds = new Set(linkedRows.map((item) => item.id));
  if (linkedIds.size !== jobIds.length || jobIds.some((id) => !linkedIds.has(id))) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '幂等回执与任务记录不一致，已拒绝继续写入',
    );
  }
  return {
    workflow: row.workflow,
    requestDigest: row.request_digest,
    statusCode: 202,
    response: redactValue(response),
    jobIds,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

function pruneExpiredMutationReceipts(database, now) {
  // An expired receipt can be removed only after every linked task has a
  // normal terminal outcome. Active and reconciliation-held tasks retain the
  // receipt indefinitely so expiry can never authorize duplicate work.
  // Validate the complete receipt/job graph before changing any row. A
  // missing or extra linked job is evidence that the earlier operation's
  // durable boundary is corrupt; silently expiring that receipt would permit
  // a duplicate operation with an unknown prior outcome.
  const receiptCount = Number(resultRows(database.exec(
    'SELECT COUNT(*) AS count FROM mutation_receipts',
  ))[0]?.count);
  if (!Number.isSafeInteger(receiptCount) || receiptCount < 0
      || receiptCount > HARD_MAX_MUTATION_RECEIPTS) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '幂等回执数量超过完整性校验上限，已拒绝继续写入',
    );
  }

  const orphan = resultRows(database.exec(`SELECT jobs.id, jobs.submission_key_hash
    FROM sync_jobs AS jobs
    LEFT JOIN mutation_receipts AS receipts
      ON receipts.key_hash = jobs.submission_key_hash
    WHERE jobs.submission_key_hash IS NOT NULL AND receipts.key_hash IS NULL
    LIMIT 1`))[0];
  if (orphan) {
    throw mutationReceiptError(
      'IDEMPOTENCY_RECEIPT_INVALID',
      '任务指向不存在或无效的幂等回执，已拒绝继续写入',
    );
  }

  // Keep the scan bounded to one compact metadata row plus one receipt and at
  // most 101 linked jobs. Expired candidates retain only a hash and count.
  // No durable graph row is changed until the complete first pass succeeds.
  const removable = [];
  const receiptScan = database.prepare(`SELECT key_hash, workflow, request_digest,
      http_status, created_at, expires_at,
      length(CAST(response_json AS BLOB)) AS response_bytes,
      length(CAST(job_ids_json AS BLOB)) AS job_ids_bytes
    FROM mutation_receipts ORDER BY created_at ASC, key_hash ASC`);
  const receiptByHash = database.prepare(
    'SELECT * FROM mutation_receipts WHERE key_hash = ? LIMIT 1',
  );
  const jobsByHash = database.prepare(`SELECT id, status, reconciliation_hold,
      submission_key_hash FROM sync_jobs WHERE submission_key_hash = ?
      ORDER BY created_at ASC, id ASC LIMIT ${MAX_MUTATION_RECEIPT_JOBS + 1}`);
  try {
    while (receiptScan.step()) {
      const metadata = receiptScan.getAsObject();
      // Reject oversized/corrupt fields before materializing them in JS.
      validateMutationReceiptMetadata(metadata);
      const row = readBoundStatementRows(receiptByHash, [metadata.key_hash], 1)[0];
      const jobs = mutationReceiptLinkedJobs(database, metadata.key_hash, jobsByHash);
      const receipt = decodeMutationReceipt(database, row, { linkedJobs: jobs });
      for (const job of jobs) {
        if (!JOB_STATUSES.has(job.status)
            || ![0, 1].includes(Number(job.reconciliation_hold))) {
          throw mutationReceiptError(
            'IDEMPOTENCY_RECEIPT_INVALID',
            '幂等回执关联任务状态无效，已拒绝继续写入',
          );
        }
      }
      if (receipt.expiresAt <= now && jobs.every((job) => (
        TERMINAL_JOB_STATUSES.has(job.status) && Number(job.reconciliation_hold) === 0
      ))) {
        removable.push({ keyHash: metadata.key_hash, linkedCount: jobs.length });
      }
    }
  } finally {
    jobsByHash.free();
    receiptByHash.free();
    receiptScan.free();
  }

  const unlinkJob = database.prepare(`UPDATE sync_jobs SET submission_key_hash = NULL
    WHERE submission_key_hash = ?`);
  const deleteReceipt = database.prepare('DELETE FROM mutation_receipts WHERE key_hash = ?');
  try {
    for (const item of removable) {
      unlinkJob.run([item.keyHash]);
      if (database.getRowsModified() !== item.linkedCount) {
        throw mutationReceiptError(
          'IDEMPOTENCY_RECEIPT_INVALID',
          '幂等回执关联任务在清理期间发生变化，已拒绝继续写入',
        );
      }
      deleteReceipt.run([item.keyHash]);
      if (database.getRowsModified() !== 1) {
        throw mutationReceiptError(
          'IDEMPOTENCY_RECEIPT_INVALID',
          '幂等回执在清理期间发生变化，已拒绝继续写入',
        );
      }
    }
  } finally {
    deleteReceipt.free();
    unlinkJob.free();
  }
}

class PanelDb {
  constructor(dbPath = process.env.PANEL_DB_PATH || DEFAULT_DB_PATH) {
    this.dbPath = path.resolve(dbPath);
    this.lockPath = this.dbPath + '.lock';
    this.queue = Promise.resolve();
    const existingInitialization = initializationPromises.get(this.dbPath);
    if (existingInitialization) {
      // Multiple PanelDb objects in one process are used by tests and by
      // embedded consumers. Only the first object performs restart recovery;
      // later objects load the already-recovered file without resetting jobs.
      this.ready = existingInitialization.then(() => this.initializeLocalDatabase());
    } else {
      const initialization = this.initialize();
      const wrappedInitialization = initialization.then((result) => {
        return result;
      }).catch((error) => {
        throw error;
      });
      this.ready = wrappedInitialization;
      // Store the wrapped promise so a concurrent constructor waits for the
      // completion path that records initialization success/failure.
      initializationPromises.set(this.dbPath, wrappedInitialization);
      wrappedInitialization.then(
        () => { if (initializationPromises.get(this.dbPath) === wrappedInitialization) initializationPromises.delete(this.dbPath); },
        () => { if (initializationPromises.get(this.dbPath) === wrappedInitialization) initializationPromises.delete(this.dbPath); },
      );
    }
  }

  pinDatabaseDirectory() {
    const directory = path.dirname(this.dbPath);
    const realPath = fs.realpathSync(directory);
    let descriptor;
    try {
      descriptor = fs.openSync(
        realPath,
        fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0),
      );
      const stat = fs.fstatSync(descriptor);
      if (!stat.isDirectory()) throw new Error('SQLite 数据库父路径必须是目录');
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
      if ((currentUid !== null && stat.uid !== currentUid) || (stat.mode & 0o022) !== 0) {
        const error = new Error('SQLite 数据库父目录必须由当前用户持有且不可由组或其他用户写入');
        error.code = 'DB_LOCK_PATH_INVALID';
        throw error;
      }
      try {
        const descriptorRealPath = fs.realpathSync('/proc/self/fd/' + descriptor);
        if (descriptorRealPath !== realPath) throw new Error('SQLite 数据库父目录解析结果不一致');
      } catch (error) {
        if (process.platform === 'linux') throw error;
        const latest = fs.lstatSync(realPath);
        if (!latest.isDirectory() || !sameInode(latest, stat)) {
          throw new Error('SQLite 数据库父目录在固定期间发生变化');
        }
      }
      if (this.databaseDirectoryIdentity
          && (!sameInode(this.databaseDirectoryIdentity, stat)
            || this.databaseDirectoryIdentity.realPath !== realPath)) {
        throw new Error('SQLite 数据库父目录已被替换，拒绝继续读写');
      }
      this.databaseDirectoryIdentity = { realPath, dev: stat.dev, ino: stat.ino };
      this.lockPath = path.join(realPath, path.basename(this.dbPath) + '.lock');
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
    }
  }

  openPinnedDatabaseDirectory() {
    if (!this.databaseDirectoryIdentity) this.pinDatabaseDirectory();
    const identity = this.databaseDirectoryIdentity;
    const descriptor = fs.openSync(
      identity.realPath,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0),
    );
    try {
      const stat = fs.fstatSync(descriptor);
      if (!stat.isDirectory() || !sameInode(identity, stat)) {
        throw new Error('SQLite 数据库父目录已被替换，拒绝继续读写');
      }
      if (process.platform === 'linux') {
        const accessDirectory = '/proc/self/fd/' + descriptor;
        if (fs.realpathSync(accessDirectory) !== identity.realPath) {
          throw new Error('SQLite 数据库父目录 FD 校验失败');
        }
        return { descriptor, accessDirectory };
      }
      const latest = fs.lstatSync(identity.realPath);
      if (!latest.isDirectory() || !sameInode(identity, latest)) {
        throw new Error('SQLite 数据库父目录已被替换，拒绝继续读写');
      }
      return { descriptor, accessDirectory: identity.realPath };
    } catch (error) {
      try { fs.closeSync(descriptor); } catch {}
      throw error;
    }
  }

  async acquireFileLock() {
    const pinnedDirectory = this.openPinnedDatabaseDirectory();
    const timeoutMs = Math.max(1000, Math.min(120000, Number(process.env.PANEL_DB_LOCK_TIMEOUT_MS) || 30000));
    const owner = currentProcessOwner();
    try {
      const lease = await acquireBakeryLease({
        directoryDescriptor: pinnedDirectory.descriptor,
        accessDirectory: pinnedDirectory.accessDirectory,
        lockName: path.basename(this.dbPath) + '.lock',
        kind: DB_LOCK_KIND,
        owner,
        isOwnerAlive: isProcessOwnerAlive,
        timeoutMs,
        pollMs: 25,
        invalidCode: 'DB_LOCK_PATH_INVALID',
        changedCode: 'DB_LOCK_CHANGED',
        timeoutCode: 'DB_LOCK_TIMEOUT',
        releaseCode: 'DB_LOCK_RELEASE_FAILED',
        invalidMessage: 'SQLite 锁命名空间或租约记录无效，拒绝覆盖或删除',
        changedMessage: 'SQLite 锁租约在操作期间发生变化',
        timeoutMessage: 'SQLite 文件锁等待超时',
        releaseMessage: 'SQLite 锁租约释放失败，当前进程已停止使用该数据库锁命名空间',
      });
      return { ...lease, directoryDescriptor: pinnedDirectory.descriptor };
    } catch (error) {
      try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      throw error;
    }
  }

  releaseFileLock(lease) {
    try {
      releaseBakeryLease(lease);
      if (lease.directoryDescriptor !== undefined) fs.fsyncSync(lease.directoryDescriptor);
    } finally {
      if (lease?.directoryDescriptor !== undefined) {
        try { fs.closeSync(lease.directoryDescriptor); } catch {}
      }
    }
  }

  async withFileLock(callback) {
    const lease = await this.acquireFileLock();
    try {
      return await callback();
    } finally {
      this.releaseFileLock(lease);
    }
  }

  loadDatabaseFromDisk() {
    const pinnedDirectory = this.openPinnedDatabaseDirectory();
    let descriptor;
    let bytes = null;
    try {
      const pinnedPath = path.join(pinnedDirectory.accessDirectory, path.basename(this.dbPath));
      try {
        descriptor = fs.openSync(pinnedPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
      if (descriptor !== undefined) {
        const before = fs.fstatSync(descriptor);
        const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
        if (!before.isFile() || before.nlink !== 1
            || (currentUid !== null && before.uid !== currentUid)
            || (before.mode & 0o077) !== 0) {
          throw new Error('PANEL_DB_PATH 必须是当前用户持有的 0600 非硬链接普通文件');
        }
        if (before.size > databaseMaximumBytes()) {
          const error = new Error('SQLite 数据库文件超过安全上限');
          error.code = 'PANEL_DB_TOO_LARGE';
          throw error;
        }
        bytes = readDatabaseBytes(descriptor, databaseMaximumBytes());
        const after = fs.fstatSync(descriptor);
        if (!sameInode(before, after)
            || before.size !== after.size
            || before.mtimeMs !== after.mtimeMs
            || before.ctimeMs !== after.ctimeMs
            || bytes.length !== after.size) {
          throw new Error('SQLite 数据库文件在读取期间发生变化');
        }
      }
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
    }
    const next = bytes ? new this.SQL.Database(bytes) : new this.SQL.Database();
    if (this.database && typeof this.database.close === 'function') {
      try { this.database.close(); } catch {}
    }
    this.database = next;
  }

  runSchema() {
    this.database.run(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS sync_snapshots (
        id TEXT PRIMARY KEY,
        version TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sync_snapshots_created_at ON sync_snapshots(created_at DESC);
      CREATE TABLE IF NOT EXISTS sync_jobs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        result_json TEXT,
        error TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        claim_keys_json TEXT,
        owner_pid INTEGER,
        owner_start_id TEXT,
        owner_boot_id TEXT,
        reconciliation_hold INTEGER NOT NULL DEFAULT 0,
        reconciliation_scope TEXT,
        reconciliation_claim_digest TEXT,
        reconciliation_acknowledged_at TEXT,
        reconciliation_resolution TEXT,
        reconciliation_acknowledged_by TEXT,
        submission_key_hash TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_sync_jobs_created_at ON sync_jobs(created_at DESC);
      CREATE TABLE IF NOT EXISTS job_claims (
        claim_key TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        job_type TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_job_claims_job_id ON job_claims(job_id);
      CREATE TABLE IF NOT EXISTS mutation_receipts (
        key_hash TEXT PRIMARY KEY,
        workflow TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        http_status INTEGER NOT NULL,
        response_json TEXT NOT NULL,
        job_ids_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_mutation_receipts_expires_at
        ON mutation_receipts(expires_at);
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target_key TEXT,
        before_fingerprint TEXT,
        after_fingerprint TEXT,
        result TEXT NOT NULL,
        details_json TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);
      CREATE TABLE IF NOT EXISTS account_links (
        identity_key TEXT PRIMARY KEY,
        token_path TEXT,
        sub2api_id INTEGER,
        account_name TEXT,
        updated_at TEXT NOT NULL
      );
    `);
    const columns = resultRows(this.database.exec('PRAGMA table_info(sync_jobs)'))
      .map((row) => row.name);
    if (!columns.includes('claim_keys_json')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN claim_keys_json TEXT');
    }
    if (!columns.includes('owner_pid')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN owner_pid INTEGER');
    }
    if (!columns.includes('owner_start_id')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN owner_start_id TEXT');
    }
    if (!columns.includes('owner_boot_id')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN owner_boot_id TEXT');
    }
    if (!columns.includes('reconciliation_hold')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN reconciliation_hold INTEGER NOT NULL DEFAULT 0');
    }
    if (!columns.includes('reconciliation_scope')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN reconciliation_scope TEXT');
    }
    if (!columns.includes('reconciliation_claim_digest')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN reconciliation_claim_digest TEXT');
    }
    if (!columns.includes('reconciliation_acknowledged_at')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN reconciliation_acknowledged_at TEXT');
    }
    if (!columns.includes('reconciliation_resolution')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN reconciliation_resolution TEXT');
    }
    if (!columns.includes('reconciliation_acknowledged_by')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN reconciliation_acknowledged_by TEXT');
    }
    if (!columns.includes('submission_key_hash')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN submission_key_hash TEXT');
    }
    this.database.run('CREATE INDEX IF NOT EXISTS idx_sync_jobs_submission_key_hash ON sync_jobs(submission_key_hash)');
  }

  pruneRows() {
    const maxJobs = Math.max(100, Math.min(100000, Number(process.env.PANEL_MAX_JOBS) || 5000));
    const maxAudit = Math.max(100, Math.min(200000, Number(process.env.PANEL_MAX_AUDIT_EVENTS) || 20000));
    const maxSnapshots = Math.max(20, Math.min(10000, Number(process.env.PANEL_MAX_SNAPSHOTS) || 500));
    // Never prune a queued/running job: its claim is the guard that prevents
    // duplicate remote work. Terminal history is expendable; active work is
    // not, even when a burst temporarily exceeds the retention limit.
    pruneExpiredMutationReceipts(this.database, new Date().toISOString());
    this.database.run(`DELETE FROM sync_jobs WHERE id IN (
      SELECT id FROM sync_jobs
      WHERE status NOT IN ('queued', 'running') AND reconciliation_hold = 0
        AND submission_key_hash IS NULL
      ORDER BY COALESCE(reconciliation_acknowledged_at, finished_at, created_at) DESC
      LIMIT -1 OFFSET ${maxJobs}
    )`);
    this.database.run(`DELETE FROM audit_events WHERE id IN (
      SELECT id FROM audit_events ORDER BY id DESC LIMIT -1 OFFSET ${maxAudit}
    )`);
    this.database.run(`DELETE FROM sync_snapshots WHERE id IN (
      SELECT id FROM sync_snapshots ORDER BY created_at DESC LIMIT -1 OFFSET ${maxSnapshots}
    )`);
  }

  async initialize() {
    ensureDirectoryTree(path.dirname(this.dbPath), 'SQLite 数据库目录');
    this.pinDatabaseDirectory();
    const SQL = await initSqlJs({
      locateFile: (file) => path.join(path.dirname(require.resolve('sql.js')), file),
    });
    this.SQL = SQL;
    await this.withFileLock(async () => {
      this.loadDatabaseFromDisk();
      this.runSchema();
      // The worker queue lives in the process that created the job. Preserve
      // jobs owned by another still-running panel instance; only a dead owner
      // proves that queued/running work was interrupted. This also prevents a
      // second PanelDb object in the same process from releasing live claims.
      const interruptedAt = new Date().toISOString();
      // Claims are the durable barrier against duplicate remote mutations.
      // Validate both directions before recovery; attempting to "repair" an
      // incomplete mapping by deleting rows could silently remove that barrier.
      const activeJobs = validateJobClaims(this.database, {
        cleanupOrdinaryTerminalClaims: true,
      });
      const interrupted = activeJobs.filter((job) => (
        job.force_recovery === true || storedJobOwnerIsDefinitelyGone(job)
      ));
      for (const job of interrupted) interruptDeadOwnerJob(this.database, job, interruptedAt);
      this.pruneRows();
      this.persistUnlocked();
    });
  }

  async initializeLocalDatabase() {
    ensureDirectoryTree(path.dirname(this.dbPath), 'SQLite 数据库目录');
    this.pinDatabaseDirectory();
    this.SQL = await initSqlJs({
      locateFile: (file) => path.join(path.dirname(require.resolve('sql.js')), file),
    });
    this.loadDatabaseFromDisk();
    this.runSchema();
  }

  persistUnlocked() {
    const bytes = this.database.export();
    const maximumBytes = databaseMaximumBytes();
    if (bytes.byteLength > maximumBytes) {
      // Fail before opening a temporary output file. The last durable version
      // remains intact and the next operation will reload it from disk.
      const error = new Error('SQLite 数据库文件超过安全上限');
      error.code = 'PANEL_DB_TOO_LARGE';
      error.actualBytes = bytes.byteLength;
      error.maximumBytes = maximumBytes;
      throw error;
    }
    const pinnedDirectory = this.openPinnedDatabaseDirectory();
    const fileName = path.basename(this.dbPath);
    const temporaryPath = path.join(
      pinnedDirectory.accessDirectory,
      fileName + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex'),
    );
    const targetPath = path.join(pinnedDirectory.accessDirectory, fileName);
    let descriptor;
    try {
      descriptor = fs.openSync(
        temporaryPath,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
      fs.writeFileSync(descriptor, Buffer.from(bytes));
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      fs.renameSync(temporaryPath, targetPath);
      fs.fsyncSync(pinnedDirectory.descriptor);
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      try { fs.unlinkSync(temporaryPath); } catch {}
      try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
    }
  }

  async persist() {
    // Compatibility entrypoint for older embedded callers. Never export this
    // instance's cached database directly: another PanelDb/process may have
    // committed newer rows since the last local read. A no-op write reloads
    // the current file under the lease before persisting schema/pruning work.
    await this.write(() => undefined);
  }

  async write(callback) {
    await this.ready;
    const run = this.queue.then(async () => {
      return this.withFileLock(async () => {
        this.loadDatabaseFromDisk();
        this.runSchema();
        // Validate every durable idempotency boundary before an arbitrary DB
        // mutation callback runs. This makes unrelated receipt corruption a
        // fail-closed condition instead of allowing later capacity/pruning
        // work to erase evidence of an unknown prior operation.
        pruneExpiredMutationReceipts(this.database, new Date().toISOString());
        const result = await callback(this.database);
        this.pruneRows();
        this.persistUnlocked();
        return result;
      });
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async read(callback) {
    await this.ready;
    await this.queue;
    // Atomic rename makes this read safe while another process persists. A
    // fresh load also prevents a second PanelDb instance from serving stale
    // task state indefinitely. Corrupt or replaced database files must be
    // surfaced instead of silently serving an old in-memory copy.
    this.loadDatabaseFromDisk();
    return callback(this.database);
  }

  saveSnapshot(snapshot) {
    const id = randomId('snap');
    const now = new Date().toISOString();
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO sync_snapshots
        (id, version, generated_at, summary_json, created_at)
        VALUES (?, ?, ?, ?, ?)`);
      statement.run([
        id,
        snapshot.version,
        snapshot.generatedAt,
        jsonString({ counts: snapshot.diff?.counts || {}, summary: snapshot.sources?.summary || {} }),
        now,
      ]);
      statement.free();
      return id;
    });
  }

  createJob(type, payload = {}, requestedBy = 'local', options = {}) {
    const id = randomId('job');
    const now = new Date().toISOString();
    let claimKeys;
    const owner = currentProcessOwner();
    let safePayloadJson;
    try {
      claimKeys = normalizeClaimKeys(options.claimKeys);
      safePayloadJson = boundedJsonString('sync_jobs.payload_json', payload, MAX_JOB_PAYLOAD_BYTES);
    } catch (error) {
      return Promise.reject(error);
    }
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        const activeJobs = validateJobClaims(database, { cleanupOrdinaryTerminalClaims: true });
        for (const activeJob of activeJobs.filter((job) => (
          job.force_recovery === true || storedJobOwnerIsDefinitelyGone(job)
        ))) {
          interruptDeadOwnerJob(database, activeJob, now);
        }
        const reconciliationBarrier = firstReconciliationBarrier(database);
        if (reconciliationBarrier) {
          // Validation may just have migrated one or more legacy unknown jobs
          // into durable holds. Persist that fail-closed repair before returning
          // the conflict to the caller. Until resource claims span every
          // workflow, any unresolved outcome blocks every new mutation job.
          database.run('COMMIT');
          return {
            recoveryBlock: {
              jobId: reconciliationBarrier.id,
              scope: reconciliationBarrier.reconciliation_scope || 'claims',
            },
          };
        }
        const runningMutation = firstRunningMutation(database);
        if (runningMutation) {
          database.run('COMMIT');
          return { runningBlock: runningMutation };
        }
        let recoveryBlock = null;
        for (const claimKey of claimKeys) {
          let existing = resultRows(database.exec(
            'SELECT job_id FROM job_claims WHERE claim_key = ' + sqlString(claimKey) + ' LIMIT 1',
          ))[0];
          if (existing) {
            const existingJob = resultRows(database.exec(`SELECT id, type, status, claim_keys_json,
                owner_pid, owner_start_id, owner_boot_id, started_at, finished_at, result_json, error,
                reconciliation_hold, reconciliation_scope, reconciliation_claim_digest, reconciliation_acknowledged_at,
                reconciliation_resolution, reconciliation_acknowledged_by
              FROM sync_jobs WHERE id = ${sqlString(existing.job_id)} LIMIT 1`))[0];
            if (Number(existingJob?.reconciliation_hold) === 1) {
              // Validation may have rebuilt this legacy terminal hold in the
              // current transaction. Commit the repair before surfacing the
              // conflict so the hold is visible and acknowledgeable later.
              recoveryBlock = {
                jobId: existingJob.id,
                scope: existingJob.reconciliation_scope || 'claims',
              };
              break;
            }
            // An incomplete legacy owner identity is not proof that the owner
            // has exited. In particular, do not reclaim a queued claim while
            // its recorded PID is still alive: that process may still dispatch
            // the original mutation. This must use the same conservative
            // predicate as the active-job recovery pass above.
            if (storedJobOwnerIsDefinitelyGone(existingJob)) {
              const recovery = interruptDeadOwnerJob(database, existingJob, now);
              if (recovery.requiresReconciliation) {
                recoveryBlock = { jobId: existing.job_id };
                break;
              }
              existing = null;
            }
          }
          if (existing) {
            const error = new Error('该操作目标已有任务排队或运行中');
            error.code = 'JOB_ALREADY_CLAIMED';
            error.existingJobId = existing.job_id;
            error.claimKey = claimKey;
            throw error;
          }
        }
        if (recoveryBlock) {
          database.run('COMMIT');
          return { recoveryBlock };
        }
        const statement = database.prepare(`INSERT INTO sync_jobs
          (id, type, status, requested_by, payload_json, created_at, claim_keys_json,
            owner_pid, owner_start_id, owner_boot_id)
          VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)`);
        statement.run([
          id,
          type,
          requestedBy,
          safePayloadJson,
          now,
          jsonString(claimKeys),
          owner.pid,
          owner.processStartId,
          owner.processBootId,
        ]);
        statement.free();
        if (claimKeys.length > 0) {
          const claimStatement = database.prepare(`INSERT INTO job_claims
            (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
          try {
            for (const claimKey of claimKeys) claimStatement.run([claimKey, id, type, now]);
          } finally {
            claimStatement.free();
          }
        }
        database.run('COMMIT');
        return { job: { id, type, status: 'queued', requestedBy, createdAt: now } };
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    }).then((outcome) => {
      if (outcome?.recoveryBlock) {
        throw reconciliationHoldError({
          id: outcome.recoveryBlock.jobId,
          reconciliation_scope: outcome.recoveryBlock.scope || 'claims',
        });
      }
      if (outcome?.runningBlock) throw runningMutationError(outcome.runningBlock);
      return outcome.job;
    });
  }

  getMutationReceipt({ workflow, requestedBy = 'local', idempotencyKey, requestDigest } = {}) {
    let normalizedWorkflow;
    let normalizedActor;
    let normalizedDigest;
    let keyHash;
    try {
      normalizedWorkflow = normalizeMutationWorkflow(workflow);
      normalizedActor = normalizeMutationActor(requestedBy);
      normalizedDigest = normalizeRequestDigest(requestDigest);
      normalizeIdempotencyKey(idempotencyKey);
      keyHash = mutationKeyHash(normalizedWorkflow, normalizedActor, idempotencyKey);
    } catch (error) {
      return Promise.reject(error);
    }
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        const row = resultRows(database.exec(`SELECT * FROM mutation_receipts
          WHERE key_hash = ${sqlString(keyHash)} LIMIT 1`))[0];
        const receipt = decodeMutationReceipt(database, row, {
          workflow: normalizedWorkflow,
          requestDigest: normalizedDigest,
        });
        database.run('COMMIT');
        return receipt;
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    });
  }

  createMutationSubmission(options = {}) {
    let workflow;
    let requestedBy;
    let requestDigest;
    let keyHash;
    let jobSpecs;
    let maximumActiveByType;
    const allowPartial = options.allowPartial === true;
    const responseFactory = options.responseFactory;
    try {
      workflow = normalizeMutationWorkflow(options.workflow);
      requestedBy = normalizeMutationActor(options.requestedBy || 'local');
      requestDigest = normalizeRequestDigest(options.requestDigest);
      normalizeIdempotencyKey(options.idempotencyKey);
      keyHash = mutationKeyHash(workflow, requestedBy, options.idempotencyKey);
      jobSpecs = normalizeMutationJobSpecs(options.jobs);
      maximumActiveByType = normalizeMaximumActiveByType(options.maximumActiveByType);
      if (typeof responseFactory !== 'function') {
        throw mutationReceiptError('IDEMPOTENCY_RESPONSE_INVALID', '幂等提交缺少响应构造器');
      }
    } catch (error) {
      return Promise.reject(error);
    }
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.parse(now) + mutationReceiptTtlMs()).toISOString();
    const owner = currentProcessOwner();
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        // A committed receipt is authoritative before current revisions,
        // claims or process-local signing keys are consulted.
        const receiptRow = resultRows(database.exec(`SELECT * FROM mutation_receipts
          WHERE key_hash = ${sqlString(keyHash)} LIMIT 1`))[0];
        const existingReceipt = decodeMutationReceipt(database, receiptRow, {
          workflow,
          requestDigest,
        });
        if (existingReceipt) {
          database.run('COMMIT');
          return { receipt: existingReceipt, replayed: true, createdJobs: [], rejections: [] };
        }

        const receiptCount = Number(resultRows(database.exec(
          'SELECT COUNT(*) AS count FROM mutation_receipts',
        ))[0]?.count);
        if (!Number.isSafeInteger(receiptCount) || receiptCount < 0
            || receiptCount >= maximumMutationReceipts()) {
          throw mutationReceiptError(
            'IDEMPOTENCY_CAPACITY_EXCEEDED',
            '幂等回执容量已满；未执行任何新任务，请等待旧回执到期或由管理员扩容',
          );
        }

        const activeJobs = validateJobClaims(database, { cleanupOrdinaryTerminalClaims: true });
        for (const activeJob of activeJobs.filter((job) => (
          job.force_recovery === true || storedJobOwnerIsDefinitelyGone(job)
        ))) {
          interruptDeadOwnerJob(database, activeJob, now);
        }
        const reconciliationBarrier = firstReconciliationBarrier(database);
        if (reconciliationBarrier) {
          database.run('COMMIT');
          return {
            recoveryBlock: {
              jobId: reconciliationBarrier.id,
              scope: reconciliationBarrier.reconciliation_scope || 'claims',
            },
          };
        }
        const runningMutation = firstRunningMutation(database);
        if (runningMutation) {
          database.run('COMMIT');
          return { runningBlock: runningMutation };
        }

        const activeCounts = new Map();
        for (const type of maximumActiveByType.keys()) {
          const count = Number(resultRows(database.exec(`SELECT COUNT(*) AS count
            FROM sync_jobs WHERE status IN ('queued', 'running')
              AND type = ${sqlString(type)}`))[0]?.count);
          if (!Number.isSafeInteger(count) || count < 0) {
            throw mutationReceiptError(
              'IDEMPOTENCY_RECEIPT_INVALID',
              '无法安全确认活跃任务数量，已拒绝提交',
            );
          }
          activeCounts.set(type, count);
        }

        const createdJobs = [];
        const rejections = [];
        const insertJob = database.prepare(`INSERT INTO sync_jobs
          (id, type, status, requested_by, payload_json, created_at, claim_keys_json,
            owner_pid, owner_start_id, owner_boot_id, submission_key_hash)
          VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?)`);
        const insertClaim = database.prepare(`INSERT INTO job_claims
          (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
        try {
          for (const spec of jobSpecs) {
            const maximum = maximumActiveByType.get(spec.type);
            if (maximum !== undefined && (activeCounts.get(spec.type) || 0) >= maximum) {
              if (!allowPartial) {
                throw mutationReceiptError('JOB_QUEUE_FULL', '活跃任务已达到安全上限');
              }
              rejections.push({ reason: 'queue_full', metadata: spec.metadata });
              continue;
            }
            let claimConflict = null;
            for (const claimKey of spec.claimKeys) {
              claimConflict = resultRows(database.exec(`SELECT job_id FROM job_claims
                WHERE claim_key = ${sqlString(claimKey)} LIMIT 1`))[0] || null;
              if (claimConflict) break;
            }
            if (claimConflict) {
              if (!allowPartial) {
                throw Object.assign(new Error('该操作目标已有任务排队或运行中'), {
                  code: 'JOB_ALREADY_CLAIMED',
                  existingJobId: claimConflict.job_id,
                });
              }
              rejections.push({
                reason: createdJobs.some((item) => item.job.id === claimConflict.job_id)
                  ? 'duplicate_in_submission'
                  : 'claim_conflict',
                existingJobId: claimConflict.job_id,
                metadata: spec.metadata,
              });
              continue;
            }
            const id = randomId('job');
            insertJob.run([
              id,
              spec.type,
              requestedBy,
              spec.payloadJson,
              now,
              jsonString(spec.claimKeys),
              owner.pid,
              owner.processStartId,
              owner.processBootId,
              keyHash,
            ]);
            for (const claimKey of spec.claimKeys) insertClaim.run([claimKey, id, spec.type, now]);
            const job = { id, type: spec.type, status: 'queued', requestedBy, createdAt: now };
            createdJobs.push({ job, metadata: spec.metadata });
            if (maximum !== undefined) {
              activeCounts.set(spec.type, (activeCounts.get(spec.type) || 0) + 1);
            }
          }
        } finally {
          insertClaim.free();
          insertJob.free();
        }

        if (createdJobs.length === 0) {
          database.run('COMMIT');
          return { noJobs: true, createdJobs: [], rejections };
        }
        const rawResponse = responseFactory({ createdJobs, rejections });
        if (!rawResponse || typeof rawResponse !== 'object' || Array.isArray(rawResponse)) {
          throw mutationReceiptError(
            'IDEMPOTENCY_RESPONSE_INVALID',
            '幂等提交响应必须是 JSON 对象',
          );
        }
        const responseJson = boundedJsonString(
          'mutation_receipts.response_json',
          rawResponse,
          MAX_MUTATION_RECEIPT_RESPONSE_BYTES,
        );
        const response = JSON.parse(responseJson);
        const jobIds = createdJobs.map((item) => item.job.id);
        validateMutationReceiptResponse(response, jobIds);
        const jobIdsJson = boundedJsonString(
          'mutation_receipts.job_ids_json',
          jobIds,
          MAX_MUTATION_RECEIPT_JOB_IDS_BYTES,
        );
        const insertReceipt = database.prepare(`INSERT INTO mutation_receipts
          (key_hash, workflow, request_digest, http_status, response_json,
            job_ids_json, created_at, expires_at)
          VALUES (?, ?, ?, 202, ?, ?, ?, ?)`);
        try {
          insertReceipt.run([
            keyHash,
            workflow,
            requestDigest,
            responseJson,
            jobIdsJson,
            now,
            expiresAt,
          ]);
        } finally {
          insertReceipt.free();
        }
        database.run('COMMIT');
        return {
          receipt: {
            workflow,
            requestDigest,
            statusCode: 202,
            response,
            jobIds,
            createdAt: now,
            expiresAt,
          },
          replayed: false,
          createdJobs,
          rejections,
        };
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    }).then((outcome) => {
      if (outcome?.recoveryBlock) {
        throw reconciliationHoldError({
          id: outcome.recoveryBlock.jobId,
          reconciliation_scope: outcome.recoveryBlock.scope || 'claims',
        });
      }
      if (outcome?.runningBlock) throw runningMutationError(outcome.runningBlock);
      return outcome;
    });
  }

  assertNoReconciliationHold() {
    const now = new Date().toISOString();
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        const activeJobs = validateJobClaims(database, {
          cleanupOrdinaryTerminalClaims: true,
        });
        for (const activeJob of activeJobs.filter((job) => (
          job.force_recovery === true || storedJobOwnerIsDefinitelyGone(job)
        ))) {
          interruptDeadOwnerJob(database, activeJob, now);
        }
        const barrier = firstReconciliationBarrier(database);
        const runningMutation = barrier ? null : firstRunningMutation(database);
        database.run('COMMIT');
        return { barrier, runningMutation };
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    }).then(({ barrier, runningMutation }) => {
      if (barrier) throw reconciliationHoldError(barrier);
      if (runningMutation) throw runningMutationError(runningMutation);
      return { allowed: true };
    });
  }

  startMutationJob(id) {
    const jobId = typeof id === 'string' ? id.trim() : '';
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(jobId)) {
      const error = new Error('任务标识无效');
      error.code = 'JOB_ID_INVALID';
      return Promise.reject(error);
    }
    const startedAt = new Date().toISOString();
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        const activeJobs = validateJobClaims(database, {
          cleanupOrdinaryTerminalClaims: true,
        });
        for (const activeJob of activeJobs.filter((job) => (
          job.id !== jobId
            && (job.force_recovery === true || storedJobOwnerIsDefinitelyGone(job))
        ))) {
          interruptDeadOwnerJob(database, activeJob, startedAt);
        }
        const current = resultRows(database.exec(`SELECT id, status FROM sync_jobs
          WHERE id = ${sqlString(jobId)} LIMIT 1`))[0];
        if (!current) {
          const error = new Error('任务不存在');
          error.code = 'JOB_NOT_FOUND';
          throw error;
        }
        if (current.status !== 'queued') {
          const error = new Error('只有排队中的任务可以开始执行');
          error.code = 'JOB_STATUS_CONFLICT';
          error.currentStatus = current.status || null;
          error.requestedStatus = 'running';
          throw error;
        }
        const barrier = firstReconciliationBarrier(database);
        if (barrier) {
          database.run('COMMIT');
          return { barrier };
        }
        const runningMutation = firstRunningMutation(database);
        if (runningMutation) {
          database.run('COMMIT');
          return { runningMutation };
        }
        const statement = database.prepare(`UPDATE sync_jobs
          SET status = 'running', started_at = ?
          WHERE id = ? AND status = 'queued'`);
        try {
          statement.run([startedAt, jobId]);
          if (database.getRowsModified() !== 1) {
            const error = new Error('任务状态在开始执行时发生变化');
            error.code = 'JOB_STATUS_CONFLICT';
            throw error;
          }
        } finally {
          statement.free();
        }
        database.run('COMMIT');
        return { startedAt };
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    }).then(({ barrier, runningMutation, startedAt: persistedStartedAt }) => {
      if (barrier) {
        throw blockedBeforeExecutionError(
          'JOB_BLOCKED_BY_RECONCILIATION',
          '存在待人工对账的任务，本任务尚未开始且已被安全阻止',
          barrier,
        );
      }
      if (runningMutation) {
        throw blockedBeforeExecutionError(
          'JOB_BLOCKED_BY_RUNNING_MUTATION',
          '另一个写任务仍处于运行状态，本任务尚未开始且已被安全阻止',
          runningMutation,
        );
      }
      return { status: 'running', startedAt: persistedStartedAt };
    });
  }

  acknowledgeJobReconciliation(id, acknowledgement = {}) {
    const jobId = typeof id === 'string' ? id.trim() : '';
    const actor = acknowledgement?.actor;
    const confirmation = acknowledgement?.confirmation;
    const resolution = acknowledgement?.resolution;
    const expectedDigest = typeof acknowledgement?.claimDigest === 'string'
      ? acknowledgement.claimDigest.trim().toLowerCase()
      : '';
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(jobId)) {
      return Promise.reject(reconciliationError(
        'JOB_RECONCILIATION_JOB_ID_INVALID',
        '待对账任务标识无效',
      ));
    }
    if (actor !== 'panel-admin') {
      return Promise.reject(reconciliationError(
        'JOB_RECONCILIATION_ADMIN_REQUIRED',
        '只允许经过认证的面板管理员解除待对账阻挡',
      ));
    }
    if (confirmation !== RECONCILIATION_ACK_CONFIRMATION) {
      return Promise.reject(reconciliationError(
        'JOB_RECONCILIATION_CONFIRMATION_INVALID',
        '人工对账确认语不正确',
      ));
    }
    if (!RECONCILIATION_ACK_RESOLUTION_SET.has(resolution)) {
      return Promise.reject(reconciliationError(
        'JOB_RECONCILIATION_RESOLUTION_INVALID',
        '人工对账结论无效',
      ));
    }
    if (!/^[a-f0-9]{64}$/.test(expectedDigest)) {
      return Promise.reject(reconciliationError(
        'JOB_RECONCILIATION_DIGEST_INVALID',
        '任务保护键摘要无效',
      ));
    }

    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        validateJobClaims(database, { cleanupOrdinaryTerminalClaims: true });
        const job = resultRows(database.exec(`SELECT id, type, status, claim_keys_json,
            result_json, reconciliation_hold, reconciliation_scope, reconciliation_claim_digest,
            reconciliation_acknowledged_at, reconciliation_resolution,
            reconciliation_acknowledged_by
          FROM sync_jobs WHERE id = ${sqlString(jobId)} LIMIT 1`))[0];
        if (!job) {
          throw reconciliationError(
            'JOB_RECONCILIATION_NOT_FOUND',
            '待对账任务不存在',
          );
        }
        if (Number(job.reconciliation_hold) !== 1) {
          const idempotent = job.reconciliation_acknowledged_at
            && job.reconciliation_claim_digest === expectedDigest
            && job.reconciliation_resolution === resolution
            && job.reconciliation_acknowledged_by === actor;
          if (!idempotent) {
            throw reconciliationError(
              job.reconciliation_acknowledged_at
                ? 'JOB_RECONCILIATION_ACK_CONFLICT'
                : 'JOB_RECONCILIATION_NOT_HELD',
              job.reconciliation_acknowledged_at
                ? '该任务已使用不同结论完成人工对账'
                : '该任务当前没有待解除的持久阻挡',
            );
          }
          database.run('COMMIT');
          return {
            jobId,
            status: 'acknowledged',
            resolution,
            claimDigest: expectedDigest,
            acknowledgedAt: job.reconciliation_acknowledged_at,
            releasedClaimCount: 0,
            idempotent: true,
          };
        }
        if (!TERMINAL_JOB_STATUSES.has(job.status)) {
          throw claimIntegrityError('待对账 hold 所属任务不是可确认的终态');
        }
        const claimKeys = parseStoredClaimKeys(job);
        const currentDigest = claimDigest(claimKeys);
        if (job.reconciliation_claim_digest !== currentDigest
            || expectedDigest !== currentDigest) {
          throw reconciliationError(
            'JOB_RECONCILIATION_DIGEST_MISMATCH',
            '待对账任务的保护键已变化，请刷新后重新核对',
          );
        }
        const previousResult = parseStoredResult(job);
        if (!resultHasReconciliationSignal(previousResult)
            || previousResult.reconciliationHold !== true
            || previousResult.reconciliationClaimDigest !== currentDigest) {
          throw claimIntegrityError('待对账任务的结果与持久 hold 不一致');
        }
        const acknowledgedAt = new Date().toISOString();
        const nextResult = {
          ...previousResult,
          writeOutcomeWasUnknown: previousResult.writeOutcomeUnknown === true,
          writeOutcomeUnknown: false,
          requiresReconciliation: false,
          reconciliationHold: false,
          reconciliationResolved: true,
          futureOperationsUnblocked: true,
          reconciliationResolution: resolution,
          reconciliationAcknowledgedAt: acknowledgedAt,
          reconciliationAcknowledgedBy: actor,
          reconciliationBlockScope: 'none',
          reconciliationBlockScopeWas: 'all_mutating_operations',
          // These fields continue to describe the original ambiguous
          // operation. Releasing its claim permits future work; it never turns
          // the old request itself into a safe retry.
          retryAllowed: false,
          doNotRetry: true,
        };
        let nextResultJson;
        try {
          nextResultJson = boundedJsonString(
            'sync_jobs.result_json',
            nextResult,
            MAX_JOB_RESULT_BYTES,
          );
        } catch (error) {
          if (error?.code !== 'PANEL_DB_FIELD_TOO_LARGE') throw error;
          // Older versions could persist a hold whose result consumed almost
          // the entire field budget. Never make such a safety barrier
          // impossible to acknowledge merely because confirmation metadata
          // needs a few more bytes. Preserve a digest and the bounded
          // operational summary while dropping only oversized detail.
          const compactResult = {
            ...reconciliationResultSummary(previousResult),
            originalResultCompacted: true,
            originalResultBytes: Buffer.byteLength(String(job.result_json || ''), 'utf8'),
            originalResultDigest: crypto.createHash('sha256')
              .update(String(job.result_json || ''))
              .digest('hex'),
            writeOutcomeWasUnknown: previousResult.writeOutcomeUnknown === true,
            writeOutcomeUnknown: false,
            requiresReconciliation: false,
            reconciliationHold: false,
            reconciliationResolved: true,
            futureOperationsUnblocked: true,
            reconciliationResolution: resolution,
            reconciliationAcknowledgedAt: acknowledgedAt,
            reconciliationAcknowledgedBy: actor,
            reconciliationBlockScope: 'none',
            reconciliationBlockScopeWas: 'all_mutating_operations',
            retryAllowed: false,
            doNotRetry: true,
          };
          nextResultJson = boundedJsonString(
            'sync_jobs.result_json',
            compactResult,
            MAX_JOB_RESULT_BYTES,
          );
        }
        const auditDetails = boundedJsonString(
          'audit_events.details_json',
          {
            resolution,
            claimDigest: currentDigest,
            holdScope: job.reconciliation_scope,
            releasedClaimCount: claimKeys.length,
          },
          MAX_AUDIT_DETAILS_BYTES,
        );

        if (typeof acknowledgement.beforeRelease === 'function') {
          acknowledgement.beforeRelease({
            jobId,
            resolution,
            claimDigest: currentDigest,
            holdScope: job.reconciliation_scope,
            releasedClaimCount: claimKeys.length,
          });
        }

        // The intent audit and hold release are part of one SQLite export.
        // A failed audit insert aborts before either the job row or claims are
        // changed; a persist failure leaves the previous durable hold intact.
        const audit = database.prepare(`INSERT INTO audit_events
          (job_id, actor, action, target_key, before_fingerprint,
            after_fingerprint, result, details_json, created_at)
          VALUES (?, ?, 'job_reconciliation_acknowledge', NULL, NULL, NULL,
            'acknowledged', ?, ?)`);
        try {
          audit.run([jobId, actor, auditDetails, acknowledgedAt]);
        } finally {
          audit.free();
        }
        const update = database.prepare(`UPDATE sync_jobs
          SET reconciliation_hold = 0,
            reconciliation_acknowledged_at = ?, reconciliation_resolution = ?,
            reconciliation_acknowledged_by = ?, result_json = ?
          WHERE id = ? AND status IN ('succeeded', 'partial', 'failed', 'interrupted')
            AND reconciliation_hold = 1
            AND reconciliation_claim_digest = ?`);
        try {
          update.run([
            acknowledgedAt,
            resolution,
            actor,
            nextResultJson,
            jobId,
            currentDigest,
          ]);
          if (database.getRowsModified() !== 1) {
            throw reconciliationError(
              'JOB_RECONCILIATION_ACK_CONFLICT',
              '待对账任务在确认期间已变化',
            );
          }
        } finally {
          update.free();
        }
        const release = database.prepare('DELETE FROM job_claims WHERE job_id = ?');
        try {
          release.run([jobId]);
          if (database.getRowsModified() !== claimKeys.length) {
            throw claimIntegrityError('待对账任务的保护键释放数量不一致');
          }
        } finally {
          release.free();
        }
        database.run('COMMIT');
        return {
          jobId,
          status: 'acknowledged',
          resolution,
          claimDigest: currentDigest,
          acknowledgedAt,
          releasedClaimCount: claimKeys.length,
          idempotent: false,
        };
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    });
  }

  updateJob(id, patch = {}) {
    let safeResult = patch.result;
    let safeResultJson;
    let safeError;
    try {
      if (patch.result !== undefined) safeResult = redactValue(patch.result);
      safeResultJson = patch.result === undefined
        ? undefined
        : boundedJsonString('sync_jobs.result_json', safeResult, MAX_JOB_RESULT_BYTES);
      safeError = patch.error === undefined
        ? undefined
        : patch.error === null
          ? null
          : assertStoredByteLength(
            'sync_jobs.error',
            redactText(String(patch.error)),
            MAX_JOB_ERROR_BYTES,
          );
    } catch (error) {
      return Promise.reject(error);
    }
    const hasRequestedStatus = patch.status !== undefined;
    const requestedStatus = hasRequestedStatus ? patch.status : null;
    if (hasRequestedStatus && !JOB_STATUSES.has(requestedStatus)) {
      const error = new Error('任务状态无效');
      error.code = 'JOB_STATUS_INVALID';
      return Promise.reject(error);
    }
    const terminalStatus = TERMINAL_JOB_STATUSES.has(requestedStatus)
      ? requestedStatus
      : null;
    if (patch.status === undefined
        && patch.result === undefined
        && patch.error === undefined
        && patch.startedAt === undefined
        && patch.finishedAt === undefined) return Promise.resolve();
    return this.write((database) => {
      if (terminalStatus) {
        validateJobClaims(database, { cleanupOrdinaryTerminalClaims: true });
      }
      const row = resultRows(database.exec(`SELECT type, status, claim_keys_json, result_json,
          reconciliation_hold, reconciliation_scope, reconciliation_claim_digest
        FROM sync_jobs WHERE id = ${sqlString(id)} LIMIT 1`))[0];
      if (!row) {
        const error = new Error('任务不存在');
        error.code = 'JOB_NOT_FOUND';
        throw error;
      }
      const currentStatus = String(row.status || '');
      if (!JOB_STATUSES.has(currentStatus)) {
        const error = new Error('数据库中的任务状态无效');
        error.code = 'JOB_STORED_STATUS_INVALID';
        error.currentStatus = currentStatus || null;
        throw error;
      }
      if (TERMINAL_JOB_STATUSES.has(currentStatus)) {
        if (terminalStatus === currentStatus) {
          // A retry after an ambiguous local persistence response may replay
          // the same terminal state. Confirm it without replacing the first
          // terminal result, error, or timestamp.
          return {
            applied: false,
            idempotent: true,
            previousStatus: currentStatus,
            currentStatus,
          };
        }
        const error = new Error('任务已经结束，拒绝重新打开或覆盖终态');
        error.code = 'JOB_STATUS_CONFLICT';
        error.currentStatus = currentStatus;
        error.requestedStatus = requestedStatus;
        throw error;
      }
      const transitionAllowed = !hasRequestedStatus
        || (currentStatus === 'queued'
          && (requestedStatus === 'running' || terminalStatus !== null))
        || (currentStatus === 'running'
          && (requestedStatus === 'running' || terminalStatus !== null));
      if (!transitionAllowed) {
        const error = new Error('任务状态转换无效');
        error.code = 'JOB_STATUS_CONFLICT';
        error.currentStatus = currentStatus;
        error.requestedStatus = requestedStatus;
        throw error;
      }
      let retainClaims = false;
      let holdDigest = null;
      let holdClaimKeys = null;
      let holdGlobalScope = false;
      const terminalResult = terminalStatus && patch.result === undefined
        ? parseStoredResult(row)
        : safeResult;
      if (terminalStatus && resultHasReconciliationSignal(terminalResult)) {
        holdClaimKeys = parseStoredClaimKeys(row);
        if (holdClaimKeys.length === 0) {
          holdClaimKeys = [legacyGlobalClaimKey(id)];
          holdGlobalScope = true;
        } else if (holdClaimKeys.some(isLegacyGlobalClaimKey)) {
          holdGlobalScope = holdClaimKeys.length === 1
            && row.reconciliation_scope === 'global';
          if (!holdGlobalScope) {
            throw claimIntegrityError('任务包含无法验证归属的全局保护键');
          }
        }
        retainClaims = true;
        holdDigest = claimDigest(holdClaimKeys);
        const holdFields = {
          requiresReconciliation: true,
          reconciliationHold: true,
          reconciliationResolved: false,
          futureOperationsUnblocked: false,
          reconciliationHoldUnavailable: false,
          reconciliationHoldReason: null,
          reconciliationClaimDigest: holdDigest,
          heldClaimCount: holdClaimKeys.length,
          reconciliationHoldScope: holdGlobalScope ? 'all_future_jobs' : 'claim_keys',
          reconciliationBlockScope: 'all_mutating_operations',
          reconciliationResolution: null,
          reconciliationAcknowledgedAt: null,
          reconciliationAcknowledgedBy: null,
          retryAllowed: false,
          doNotRetry: true,
        };
        const boundedHold = boundedReconciliationResult(
          terminalResult,
          holdFields,
          patch.result === undefined ? row.result_json : safeResultJson,
        );
        safeResult = boundedHold.result;
        safeResultJson = boundedHold.json;
      }
      const fields = [];
      const values = [];
      const add = (column, value) => {
        if (value === undefined) return;
        fields.push(column + ' = ?');
        values.push(value);
      };
      add('status', patch.status);
      add('result_json', safeResultJson);
      add('error', safeError);
      add('started_at', patch.startedAt);
      add('finished_at', patch.finishedAt);
      if (terminalStatus) {
        if (holdGlobalScope) add('claim_keys_json', jsonString(holdClaimKeys));
        add('reconciliation_hold', retainClaims ? 1 : 0);
        add('reconciliation_scope', retainClaims ? (holdGlobalScope ? 'global' : 'claims') : null);
        add('reconciliation_claim_digest', holdDigest);
        add('reconciliation_acknowledged_at', null);
        add('reconciliation_resolution', null);
        add('reconciliation_acknowledged_by', null);
      }
      const statement = database.prepare(
        'UPDATE sync_jobs SET ' + fields.join(', ') + ' WHERE id = ? AND status = ?',
      );
      statement.run([...values, id, currentStatus]);
      const applied = database.getRowsModified() > 0;
      statement.free();
      if (!applied) {
        const latestStatus = resultRows(database.exec(
          'SELECT status FROM sync_jobs WHERE id = ' + sqlString(id) + ' LIMIT 1',
        ))[0]?.status || null;
        const error = new Error('任务状态在更新期间发生变化');
        error.code = latestStatus ? 'JOB_STATUS_CONFLICT' : 'JOB_NOT_FOUND';
        error.currentStatus = latestStatus;
        error.requestedStatus = requestedStatus;
        throw error;
      }
      if (terminalStatus && applied && !retainClaims) {
        const claimStatement = database.prepare('DELETE FROM job_claims WHERE job_id = ?');
        claimStatement.run([id]);
        claimStatement.free();
      } else if (terminalStatus && applied && holdGlobalScope) {
        const claimStatement = database.prepare(`INSERT INTO job_claims
          (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
        try {
          claimStatement.run([
            holdClaimKeys[0],
            id,
            row.type,
            patch.finishedAt || new Date().toISOString(),
          ]);
        } finally {
          claimStatement.free();
        }
      }
      return {
        applied: true,
        idempotent: false,
        previousStatus: currentStatus,
        currentStatus: hasRequestedStatus ? requestedStatus : currentStatus,
      };
    });
  }

  interruptOwnedActiveJobs(reason = '面板服务停止，任务已安全中断', options = {}) {
    const owner = currentProcessOwner();
    const finishedAt = new Date().toISOString();
    const safeReason = redactText(String(reason || '面板服务停止，任务已安全中断'));
    const excludedJobIds = new Set(
      (Array.isArray(options?.excludeJobIds) ? options.excludeJobIds : [])
        .map((id) => String(id || '').trim())
        .filter(Boolean),
    );
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        validateJobClaims(database, { cleanupOrdinaryTerminalClaims: true });
        const startCondition = owner.processStartId
          ? 'owner_start_id = ' + sqlString(owner.processStartId)
          : 'owner_start_id IS NULL';
        const bootCondition = owner.processBootId
          ? 'owner_boot_id = ' + sqlString(owner.processBootId)
          : 'owner_boot_id IS NULL';
        const rows = resultRows(database.exec(`SELECT id, type, status, claim_keys_json,
            owner_pid, owner_start_id, owner_boot_id, started_at, finished_at, result_json, error,
            reconciliation_hold, reconciliation_scope, reconciliation_claim_digest, reconciliation_acknowledged_at,
            reconciliation_resolution, reconciliation_acknowledged_by
          FROM sync_jobs
          WHERE status IN ('queued', 'running')
            AND owner_pid = ${sqlString(owner.pid)}
            AND ${startCondition}
            AND ${bootCondition}`))
          .filter((row) => !excludedJobIds.has(String(row.id)));
        for (const row of rows) {
          const result = interruptDeadOwnerJob(database, row, finishedAt);
          if (!result.requiresReconciliation && safeReason) {
            const statement = database.prepare(`UPDATE sync_jobs SET error = ?
              WHERE id = ? AND status = 'interrupted'`);
            try {
              statement.run([safeReason, row.id]);
            } finally {
              statement.free();
            }
          }
        }
        database.run('COMMIT');
        return rows.map((row) => row.id);
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    });
  }

  decodeJob(row, options = {}) {
    if (!row) return null;
    const listSummary = options.listSummary === true || options.reconciliationSummary === true;
    let payload = null;
    let result = null;
    if (!listSummary) {
      try { payload = redactValue(JSON.parse(row.payload_json)); } catch {}
    }
    const resultSummaryOmitted = listSummary && Number(row.result_summary_omitted) === 1;
    if (!resultSummaryOmitted) {
      try { result = row.result_json ? redactValue(JSON.parse(row.result_json)) : null; } catch {}
    }
    if (listSummary) {
      result = result !== null ? reconciliationResultSummary(result) : null;
      const durableHold = durableReconciliationListSummary(row);
      if (resultSummaryOmitted) {
        const resultBytes = Number(row.result_bytes);
        result = {
          summaryUnavailable: true,
          summaryReason: 'result_too_large',
          resultBytes: Number.isSafeInteger(resultBytes) && resultBytes >= 0
            && resultBytes <= MAX_JOB_RESULT_BYTES ? resultBytes : undefined,
          ...durableHold,
        };
      } else if (durableHold.reconciliationHold === true) {
        // The dedicated columns are the authoritative public-list contract.
        // Do not let a stale or partially migrated JSON summary hide a durable
        // safety barrier from the administrator.
        result = { ...(result || {}), ...durableHold };
      }
    }
    return {
      id: listSummary ? boundedJobListText(row.id, 128) : row.id,
      type: listSummary ? boundedJobListText(row.type, 64) : row.type,
      status: listSummary ? boundedJobListText(row.status, 32) : row.status,
      requestedBy: listSummary ? boundedJobListText(row.requested_by, 32) : row.requested_by,
      payload,
      result,
      error: row.error
        ? redactText(String(row.error)).slice(0, listSummary ? 1000 : MAX_JOB_ERROR_BYTES)
        : null,
      createdAt: listSummary ? boundedJobListText(row.created_at, 64) : row.created_at,
      startedAt: listSummary
        ? boundedJobListText(row.started_at, 64)
        : row.started_at || null,
      finishedAt: listSummary
        ? boundedJobListText(row.finished_at, 64)
        : row.finished_at || null,
    };
  }

  async getJob(id) {
    const rows = await this.read((database) => resultRows(database.exec(
      'SELECT * FROM sync_jobs WHERE id = ' + sqlString(id) + ' LIMIT 1',
    )));
    return this.decodeJob(rows[0]);
  }

  async listJobsPage(limit = 50) {
    const safeLimit = normalizedJobListLimit(limit);
    const rows = await this.read((database) => {
      const heldTotal = Number(resultRows(database.exec(`SELECT COUNT(*) AS count
        FROM sync_jobs WHERE reconciliation_hold = 1`))[0]?.count) || 0;
      const activeTotal = Number(resultRows(database.exec(`SELECT COUNT(*) AS count
        FROM sync_jobs WHERE status IN ('queued', 'running')`))[0]?.count) || 0;
      // A normal history limit must never hide a durable hold. Bound the
      // exceptional set separately and report truncation rather than silently
      // implying that the returned list is complete. Global upgrade barriers
      // and oldest holds come first so the blocking path remains actionable.
      const held = resultRows(database.exec(`SELECT id, type, status, requested_by,
          CASE WHEN length(CAST(result_json AS BLOB)) <= ${MAX_JOB_LIST_RESULT_BYTES}
            THEN result_json ELSE NULL END AS result_json,
          CASE WHEN result_json IS NOT NULL
              AND length(CAST(result_json AS BLOB)) > ${MAX_JOB_LIST_RESULT_BYTES}
            THEN 1 ELSE 0 END AS result_summary_omitted,
          length(CAST(result_json AS BLOB)) AS result_bytes,
          reconciliation_hold, reconciliation_scope, reconciliation_claim_digest,
          error, created_at, started_at, finished_at
        FROM sync_jobs
        WHERE reconciliation_hold = 1
        ORDER BY CASE WHEN reconciliation_scope = 'global' THEN 0 ELSE 1 END,
          created_at ASC, id ASC
        LIMIT ${MAX_RECONCILIATION_LIST_JOBS}`));
      // Active work is operational state, not history. Query it independently
      // so a burst of newer terminal rows can never make the UI conclude that
      // an older queued/running mutation disappeared. Oldest work comes first;
      // if the defensive cap is ever reached the response says so explicitly.
      const active = resultRows(database.exec(`SELECT id, type, status, requested_by,
          CASE WHEN length(CAST(result_json AS BLOB)) <= ${MAX_JOB_LIST_RESULT_BYTES}
            THEN result_json ELSE NULL END AS result_json,
          CASE WHEN result_json IS NOT NULL
              AND length(CAST(result_json AS BLOB)) > ${MAX_JOB_LIST_RESULT_BYTES}
            THEN 1 ELSE 0 END AS result_summary_omitted,
          length(CAST(result_json AS BLOB)) AS result_bytes,
          reconciliation_hold, reconciliation_scope, reconciliation_claim_digest,
          error, created_at, started_at, finished_at
        FROM sync_jobs
        WHERE status IN ('queued', 'running')
        ORDER BY created_at ASC, id ASC
        LIMIT ${MAX_ACTIVE_JOB_LIST_JOBS}`));
      const ordinary = resultRows(database.exec(`SELECT id, type, status, requested_by,
          CASE WHEN length(CAST(result_json AS BLOB)) <= ${MAX_JOB_LIST_RESULT_BYTES}
            THEN result_json ELSE NULL END AS result_json,
          CASE WHEN result_json IS NOT NULL
              AND length(CAST(result_json AS BLOB)) > ${MAX_JOB_LIST_RESULT_BYTES}
            THEN 1 ELSE 0 END AS result_summary_omitted,
          length(CAST(result_json AS BLOB)) AS result_bytes,
          reconciliation_hold, reconciliation_scope, reconciliation_claim_digest,
          error, created_at, started_at, finished_at
        FROM sync_jobs
        WHERE reconciliation_hold = 0
          AND status NOT IN ('queued', 'running')
        ORDER BY created_at DESC LIMIT ${safeLimit}`));
      return { held, heldTotal, active, activeTotal, ordinary };
    });
    const seen = new Set();
    const jobs = [];
    for (const row of [...rows.held, ...rows.active, ...rows.ordinary]) {
      if (seen.has(row.id)) continue;
      seen.add(row.id);
      jobs.push(this.decodeJob(row, { listSummary: true }));
    }
    return {
      jobs,
      reconciliationHolds: {
        total: rows.heldTotal,
        returned: rows.held.length,
        truncated: rows.heldTotal > rows.held.length,
        maximumReturned: MAX_RECONCILIATION_LIST_JOBS,
      },
      activeJobs: {
        total: rows.activeTotal,
        returned: rows.active.length,
        truncated: rows.activeTotal > rows.active.length,
        maximumReturned: MAX_ACTIVE_JOB_LIST_JOBS,
      },
      history: {
        limit: safeLimit,
        returned: rows.ordinary.length,
      },
    };
  }

  async listJobs(limit = 50) {
    const safeLimit = normalizedJobListLimit(limit);
    const rows = await this.read((database) => resultRows(database.exec(
      `SELECT * FROM sync_jobs ORDER BY created_at DESC LIMIT ${safeLimit}`,
    )));
    return rows.map((row) => this.decodeJob(row));
  }

  async countActiveJobs(type = null) {
    const normalizedType = typeof type === 'string' ? type.trim() : '';
    const condition = normalizedType
      ? ' AND type = ' + sqlString(normalizedType)
      : '';
    const rows = await this.read((database) => resultRows(database.exec(
      `SELECT COUNT(*) AS count FROM sync_jobs
        WHERE status IN ('queued', 'running')${condition}`,
    )));
    const count = Number(rows[0]?.count);
    return Number.isSafeInteger(count) && count >= 0 ? count : 0;
  }

  audit(event = {}) {
    const now = new Date().toISOString();
    let values;
    try {
      values = [
        event.jobId || null,
        event.actor || 'local',
        event.action || 'unknown',
        event.targetKey || null,
        event.beforeFingerprint || null,
        event.afterFingerprint || null,
        event.result || 'ok',
      ];
      const fields = [
        'audit_events.job_id',
        'audit_events.actor',
        'audit_events.action',
        'audit_events.target_key',
        'audit_events.before_fingerprint',
        'audit_events.after_fingerprint',
        'audit_events.result',
      ];
      values = values.map((value, index) => (
        boundedRedactedText(fields[index], value, MAX_AUDIT_TEXT_BYTES)
      ));
      values.push(boundedJsonString(
        'audit_events.details_json',
        event.details || {},
        MAX_AUDIT_DETAILS_BYTES,
      ));
    } catch (error) {
      return Promise.reject(error);
    }
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO audit_events
        (job_id, actor, action, target_key, before_fingerprint, after_fingerprint, result, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      statement.run([...values, now]);
      statement.free();
    });
  }

  async listAudit(limit = 100) {
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    const rows = await this.read((database) => resultRows(database.exec(
      'SELECT * FROM audit_events ORDER BY id DESC LIMIT ' + safeLimit,
    )));
    return rows.map((row) => {
      let details = {};
      try { details = redactValue(JSON.parse(row.details_json || '{}')); } catch {}
      return {
        id: row.id,
        jobId: row.job_id ? redactText(row.job_id) : null,
        actor: redactText(row.actor),
        action: redactText(row.action),
        targetKey: row.target_key ? redactText(row.target_key) : null,
        beforeFingerprint: row.before_fingerprint ? redactText(row.before_fingerprint) : null,
        afterFingerprint: row.after_fingerprint ? redactText(row.after_fingerprint) : null,
        result: redactText(row.result),
        details,
        createdAt: row.created_at,
      };
    });
  }

  saveLink(link = {}) {
    if (!link.identityKey) return Promise.resolve();
    const now = new Date().toISOString();
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO account_links
        (identity_key, token_path, sub2api_id, account_name, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(identity_key) DO UPDATE SET
          token_path=excluded.token_path, sub2api_id=excluded.sub2api_id,
          account_name=excluded.account_name, updated_at=excluded.updated_at`);
      statement.run([
        link.identityKey,
        link.tokenPath || null,
        link.sub2apiId ?? null,
        link.accountName || null,
        now,
      ]);
      statement.free();
    });
  }
}

module.exports = {
  PanelDb,
  DEFAULT_DB_PATH,
  RECONCILIATION_ACK_CONFIRMATION,
  RECONCILIATION_ACK_RESOLUTIONS,
};
