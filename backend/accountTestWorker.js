const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');

const { Sub2ApiAdminClient, safeModelId } = require('./adapters/sub2apiAdmin');
const { getAccountAvailability } = require('./accountAvailability');
const {
  REVISION_PATTERN,
  accountTestOwnershipDigest,
  accountTestTargetDigest,
  matchesAccountTestTargetRevision,
} = require('./accountTargetRevision');
const { accountKeys, hasStrongIdentity, identitiesStronglyCompatible } = require('./diff');
const { normalizeIdentityValue } = require('./lib/token');
const { assertAuditLogCheckpoint, redactText } = require('./logger');
const { withControlPlaneLock } = require('./taskCoordinator');
const { throwIfJobInterrupted } = require('./jobLifecycle');

let submissionQueue = Promise.resolve();

const ACCOUNT_TEST_STATUSES = new Set(['active', 'inactive', 'disabled', 'error']);

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Logging must never change the outcome of a remote account test.
  }
}

function safeErrorMessage(error) {
  let detail = 'unknown error';
  try {
    let message;
    try { message = error?.message; } catch {}
    if (typeof message === 'string' && message) detail = message;
    else if (error !== undefined && error !== null) detail = String(error);
  } catch {
    detail = 'unknown error';
  }
  try {
    return redactText(detail).slice(0, 1000);
  } catch {
    return 'unknown error';
  }
}

function writeRequiresReconciliation(error) {
  return error?.writeOutcomeUnknown === true || error?.requiresReconciliation === true;
}

function normalizedReconciliationReason(value, fallback = 'scheduler_write_unknown') {
  const reason = String(value || '').trim().toLowerCase();
  if (/^[a-z0-9_]{1,64}$/.test(reason)) return reason;
  return fallback;
}

function schedulerReconciliationError(error, reason = 'scheduler_write_unknown', options = {}) {
  const target = error instanceof Error
    ? error
    : new Error('Sub2API 调度设置写入结果无法确认');
  if (options.writeOutcomeUnknown === true || target.writeOutcomeUnknown === true) {
    target.writeOutcomeUnknown = true;
  }
  target.requiresReconciliation = true;
  if (target.reconciliationScope !== 'test') target.reconciliationScope = 'scheduler';
  target.reconciliationReason = normalizedReconciliationReason(
    target.reconciliationReason || target.writeOutcomeReason || reason,
    reason,
  );
  return target;
}

function accountTestReconciliationError(error, reason = 'account_test_state_unknown', options = {}) {
  const target = error instanceof Error
    ? error
    : new Error('账号测试后状态无法确认');
  target.requiresReconciliation = true;
  target.reconciliationScope = 'test';
  if (options.testOutcomeUnknown === true || target.testOutcomeUnknown === true) {
    target.testOutcomeUnknown = true;
  }
  if (typeof options.testSuccess === 'boolean') {
    target.testSuccess = options.testSuccess;
    target.testSuccessKnown = true;
  }
  target.reconciliationReason = normalizedReconciliationReason(
    target.reconciliationReason || reason,
    reason,
  );
  return target;
}

function withAccountTestSubmissionLock(callback) {
  const run = submissionQueue.then(callback);
  submissionQueue = run.catch(() => {});
  return run;
}

function normalizePositiveAccountId(value) {
  let id;
  if (typeof value === 'number') id = value;
  else if (typeof value === 'string' && /^[1-9]\d*$/.test(value)) id = Number(value);
  else return null;
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function elapsedMilliseconds(startedAt) {
  const elapsed = performance.now() - startedAt;
  return Number.isFinite(elapsed) ? Math.max(0, Math.floor(elapsed)) : 0;
}

function normalizeAccountTestModelId(value) {
  if (value === undefined || value === null || value === '') return '';
  if (typeof value !== 'string') {
    const error = new Error('modelId 必须是字符串');
    error.code = 'ACCOUNT_TEST_MODEL_INVALID';
    throw error;
  }
  const model = safeModelId(value);
  if (!model) {
    const error = new Error('modelId 包含无效或敏感内容');
    error.code = 'ACCOUNT_TEST_MODEL_INVALID';
    throw error;
  }
  return model.toLowerCase() === '5.6-luna' ? 'gpt-5.6-luna' : model;
}

function normalizeAccountTestPrompt(value) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string' || value.length > 2000) {
    const error = new Error('prompt 必须是长度不超过 2000 的字符串');
    error.code = 'ACCOUNT_TEST_PROMPT_INVALID';
    throw error;
  }
  return value.trim();
}

function normalizeAccountTestJobAccountIds(values) {
  if (!Array.isArray(values) || values.length > 100) {
    const error = new Error('账号测试任务的账号 ID 列表无效');
    error.code = 'ACCOUNT_TEST_SELECTION_INVALID';
    throw error;
  }
  const result = [];
  const seen = new Set();
  for (const value of values) {
    const id = normalizePositiveAccountId(value);
    if (!id) {
      const error = new Error('账号测试任务的 accountId 必须是规范正整数');
      error.code = 'ACCOUNT_TEST_ACCOUNT_ID_INVALID';
      throw error;
    }
    if (seen.has(id)) {
      const error = new Error('账号测试任务不能包含重复 accountId');
      error.code = 'ACCOUNT_TEST_TARGET_DUPLICATE';
      throw error;
    }
    seen.add(id);
    result.push(id);
  }
  return result;
}

function boundedJobDuration(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return 30 * 60 * 1000;
  return Math.max(60 * 1000, Math.min(2 * 60 * 60 * 1000, Math.floor(number)));
}

function accountTestStopError(reason) {
  const timedOut = reason === 'timeout';
  const error = new Error(timedOut
    ? '账号测试任务达到总时限'
    : '面板正在停止，账号测试任务已中断');
  error.code = timedOut ? 'ACCOUNT_TEST_JOB_TIMEOUT' : 'JOB_INTERRUPTED';
  return error;
}

function createAccountTestJobSignal(externalSignal, timeoutMs, startedAt = performance.now()) {
  const controller = new AbortController();
  const deadline = startedAt + timeoutMs;
  let stopReason = null;
  let timer = null;

  const stop = (reason) => {
    if (stopReason) return;
    stopReason = reason;
    // The job deadline is the only handle guaranteed to wake a client that is
    // waiting exclusively on AbortSignal. Keep it referenced until the first
    // stop, then release it immediately (especially on external shutdown).
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    controller.abort(accountTestStopError(reason));
  };
  const onExternalAbort = () => stop('interrupted');
  if (externalSignal && typeof externalSignal.addEventListener === 'function') {
    externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    if (externalSignal.aborted) onExternalAbort();
  }
  if (!stopReason) {
    timer = setTimeout(() => stop('timeout'), Math.max(1, deadline - performance.now()));
  }

  return {
    signal: controller.signal,
    reason() {
      // Do not depend solely on timer scheduling: a synchronous boundary may
      // observe the deadline before the timer callback gets a turn.
      if (!stopReason && performance.now() >= deadline) stop('timeout');
      return stopReason;
    },
    dispose() {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (externalSignal && typeof externalSignal.removeEventListener === 'function') {
        try { externalSignal.removeEventListener('abort', onExternalAbort); } catch {}
      }
    },
  };
}

function throwIfAccountTestStopped(signal, stopReason) {
  const reason = typeof stopReason === 'function' ? stopReason() : null;
  // A synchronous checkpoint can cross the absolute deadline before the
  // timeout callback gets an event-loop turn. Consult the clock-backed reason
  // at every dispatch boundary instead of relying on AbortSignal alone.
  if (reason) throw accountTestStopError(reason);
  throwIfJobInterrupted(signal);
}

function accountTestJobStatus(result = {}) {
  const requested = Number.isSafeInteger(result.requested) && result.requested >= 0
    ? result.requested
    : 0;
  const succeeded = Number.isSafeInteger(result.succeeded) && result.succeeded >= 0
    ? result.succeeded
    : 0;
  const failed = Number.isSafeInteger(result.failed) && result.failed >= 0
    ? result.failed
    : 0;
  const skipped = Number.isSafeInteger(result.skipped) && result.skipped >= 0
    ? result.skipped
    : 0;
  const notAttempted = Number.isSafeInteger(result.notAttemptedCount)
    && result.notAttemptedCount >= 0
    ? result.notAttemptedCount
    : 0;
  const attempted = Number.isSafeInteger(result.attemptedCount) && result.attemptedCount >= 0
    ? result.attemptedCount
    : Math.max(0, requested - notAttempted);
  if (result.stopReason === 'interrupted' && attempted === 0) return 'interrupted';
  if (notAttempted > 0 && attempted > 0) return 'partial';
  if (failed > 0) return succeeded > 0 ? 'partial' : 'failed';
  if (skipped > 0) return succeeded > 0 ? 'partial' : 'failed';
  return requested === succeeded ? 'succeeded' : 'failed';
}

function normalizeAccountTestRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    const error = new Error('请求体必须是 JSON 对象');
    error.code = 'ACCOUNT_TEST_REQUEST_INVALID';
    throw error;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'accountIds')
      || Object.prototype.hasOwnProperty.call(body, 'account_ids')) {
    const error = new Error('账号测试请求缺少当前快照的目标 revision，请刷新页面后重新选择');
    error.code = 'ACCOUNT_TEST_TARGET_REVISION_REQUIRED';
    throw error;
  }
  const rawTargets = body.targets;
  if (!Array.isArray(rawTargets) || rawTargets.length === 0 || rawTargets.length > 100) {
    const error = new Error('至少选择一个带当前 revision 的上游账号，单次最多测试 100 个账号');
    error.code = 'ACCOUNT_TEST_SELECTION_INVALID';
    throw error;
  }
  const accountIds = [];
  const targets = [];
  const seen = new Set();
  for (const target of rawTargets) {
    if (!target || typeof target !== 'object' || Array.isArray(target)
        || Object.keys(target).length !== 2
        || !Object.prototype.hasOwnProperty.call(target, 'accountId')
        || !Object.prototype.hasOwnProperty.call(target, 'targetRevision')) {
      const error = new Error('每个账号测试目标必须只包含 accountId 和 targetRevision');
      error.code = 'ACCOUNT_TEST_TARGET_INVALID';
      throw error;
    }
    const id = normalizePositiveAccountId(target.accountId);
    if (!id) {
      const error = new Error('账号测试目标的 accountId 必须是正整数');
      error.code = 'ACCOUNT_TEST_ACCOUNT_ID_INVALID';
      throw error;
    }
    if (seen.has(id)) {
      const error = new Error('同一账号 ID 不能重复提交；请刷新后重新选择唯一账号行');
      error.code = 'ACCOUNT_TEST_TARGET_DUPLICATE';
      throw error;
    }
    if (typeof target.targetRevision !== 'string'
        || !REVISION_PATTERN.test(target.targetRevision)) {
      const error = new Error('账号测试目标 revision 缺失或格式无效，请刷新页面后重试');
      error.code = 'ACCOUNT_TEST_TARGET_REVISION_INVALID';
      throw error;
    }
    seen.add(id);
    accountIds.push(id);
    targets.push({ accountId: id, targetRevision: target.targetRevision });
  }
  const modelAliases = ['modelId', 'model_id']
    .filter((key) => Object.prototype.hasOwnProperty.call(body, key)
      && body[key] !== undefined && body[key] !== null);
  const normalizedModels = modelAliases.length > 0
    ? modelAliases.map((key) => normalizeAccountTestModelId(body[key]))
    : [''];
  if (new Set(normalizedModels).size !== 1) {
    const error = new Error('modelId 与 model_id 不一致');
    error.code = 'ACCOUNT_TEST_MODEL_INVALID';
    throw error;
  }
  return {
    targets,
    accountIds,
    modelId: normalizedModels[0],
    prompt: normalizeAccountTestPrompt(body.prompt),
  };
}

function assertAccountTestTargetRevisions(accountRows, targets) {
  const accountsById = new Map();
  for (const account of accountRows || []) {
    const id = normalizePositiveAccountId(account?.id);
    if (!id) continue;
    const bucket = accountsById.get(id) || [];
    bucket.push(account);
    accountsById.set(id, bucket);
  }
  for (const target of targets || []) {
    const matches = accountsById.get(target.accountId) || [];
    if (matches.length !== 1
        || !matchesAccountTestTargetRevision(target.targetRevision, matches[0])) {
      const error = new Error('账号身份、凭据或状态已变化，旧 revision 已失效；请刷新页面后重新选择');
      error.code = 'ACCOUNT_TEST_TARGET_REVISION_STALE';
      throw error;
    }
  }
}

function accountStatus(account) {
  return String(account?.status || '').trim().toLowerCase();
}

function accountTestState(account) {
  const status = accountStatus(account);
  const recognizedStatus = ACCOUNT_TEST_STATUSES.has(status);
  return {
    status,
    statusKnown: account?.statusKnown === undefined
      ? recognizedStatus
      : account.statusKnown === true && recognizedStatus,
    schedulable: typeof account?.schedulable === 'boolean'
      ? account.schedulable
      : null,
    schedulableKnown: account?.schedulableKnown === undefined
      ? typeof account?.schedulable === 'boolean'
      : account.schedulableKnown === true && typeof account?.schedulable === 'boolean',
  };
}

function accountIdentityKeys(account) {
  return Array.isArray(account?.identityKeys) && account.identityKeys.length > 0
    ? account.identityKeys
    : accountKeys(account);
}

function canonicalStrongIdentityKeys(account) {
  const keys = [];
  for (const value of accountIdentityKeys(account)) {
    const raw = String(value || '').trim();
    const separator = raw.indexOf(':');
    if (separator <= 0) continue;
    const prefix = raw.slice(0, separator).toLowerCase() + ':';
    if (prefix !== 'account:' && prefix !== 'user:') continue;
    const normalized = normalizeIdentityValue(prefix, raw.slice(separator + 1));
    if (normalized) keys.push(prefix + normalized);
  }
  return [...new Set(keys)].sort();
}

function accountTestTargetError(account) {
  if (!account) return 'account_not_found';
  if (account.schemaValid === false) return 'account_schema_invalid';
  if (String(account.platform || '').trim().toLowerCase() !== 'openai'
      || String(account.type || '').trim().toLowerCase() !== 'oauth') {
    return 'account_kind_invalid';
  }
  const { statusKnown, schedulableKnown } = accountTestState(account);
  if (!statusKnown || !schedulableKnown) return 'account_state_unknown';
  if (!hasStrongIdentity(accountIdentityKeys(account))) return 'account_identity_missing';
  return null;
}

function accountTestTargetBaseline(account) {
  const accountId = normalizePositiveAccountId(account?.id);
  if (!accountId || accountTestTargetError(account)) return null;
  const strongIdentityKeys = canonicalStrongIdentityKeys(account);
  if (strongIdentityKeys.length === 0) return null;
  const state = accountTestState(account);
  const targetDigest = accountTestTargetDigest(account);
  if (!targetDigest) return null;
  return {
    accountId,
    // Persist only a one-way digest. Raw account/user IDs and credentials do
    // not need to become part of the job history exposed by the jobs API.
    identityDigest: crypto.createHash('sha256')
      .update(JSON.stringify(strongIdentityKeys))
      .digest('hex'),
    // The full reviewed target (credential fingerprints/presence and every
    // recovery-relevant state field) is also persisted only as a one-way
    // digest, closing the admission-to-worker queue window.
    targetDigest,
    // Bind the decision to probe/recover to the state that was reviewed at
    // submission time. These normalized fields are safe to persist and stop a
    // queued healthy test from becoming an implicit recovery operation.
    status: state.status,
    statusKnown: state.statusKnown,
    schedulable: state.schedulable,
    schedulableKnown: state.schedulableKnown,
  };
}

function accountTestBaselineMap(targetBaselines, accountIds) {
  const expectedIds = new Set((accountIds || []).map(normalizePositiveAccountId).filter(Boolean));
  if (!Array.isArray(targetBaselines) || expectedIds.size !== (accountIds || []).length) {
    const error = new Error('账号测试任务缺少提交时的目标身份基线');
    error.code = 'ACCOUNT_TEST_BASELINE_INVALID';
    throw error;
  }
  const baselines = new Map();
  for (const baseline of targetBaselines) {
    const accountId = normalizePositiveAccountId(baseline?.accountId);
    const identityDigest = typeof baseline?.identityDigest === 'string'
      ? baseline.identityDigest.trim().toLowerCase()
      : '';
    const targetDigest = typeof baseline?.targetDigest === 'string'
      ? baseline.targetDigest.trim().toLowerCase()
      : '';
    const status = typeof baseline?.status === 'string'
      ? baseline.status.trim().toLowerCase()
      : '';
    if (!accountId || !expectedIds.has(accountId) || baselines.has(accountId)
        || !/^[a-f0-9]{64}$/.test(identityDigest)
        || !/^[a-f0-9]{64}$/.test(targetDigest)
        || baseline?.statusKnown !== true
        || !ACCOUNT_TEST_STATUSES.has(status)
        || baseline?.schedulableKnown !== true
        || typeof baseline?.schedulable !== 'boolean') {
      const error = new Error('账号测试任务的目标身份基线无效');
      error.code = 'ACCOUNT_TEST_BASELINE_INVALID';
      throw error;
    }
    baselines.set(accountId, {
      accountId,
      identityDigest,
      targetDigest,
      status,
      statusKnown: true,
      schedulable: baseline.schedulable,
      schedulableKnown: true,
    });
  }
  if (baselines.size !== expectedIds.size) {
    const error = new Error('账号测试任务的目标身份基线不完整');
    error.code = 'ACCOUNT_TEST_BASELINE_INVALID';
    throw error;
  }
  return baselines;
}

function matchesAccountTestTargetDigest(baseline, account) {
  const actualDigest = accountTestTargetDigest(account);
  if (!baseline || !actualDigest) return false;
  const expected = Buffer.from(baseline.targetDigest, 'hex');
  const actual = Buffer.from(actualDigest, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function matchesAccountTestIdentityBaseline(baseline, account) {
  const accountId = normalizePositiveAccountId(account?.id);
  const strongIdentityKeys = canonicalStrongIdentityKeys(account);
  if (!baseline || accountId !== baseline.accountId || strongIdentityKeys.length === 0) return false;
  const actualDigest = crypto.createHash('sha256')
    .update(JSON.stringify(strongIdentityKeys))
    .digest('hex');
  const expectedDigest = Buffer.from(baseline.identityDigest, 'hex');
  const actualDigestBuffer = Buffer.from(actualDigest, 'hex');
  return expectedDigest.length === actualDigestBuffer.length
    && crypto.timingSafeEqual(expectedDigest, actualDigestBuffer);
}

function matchesAccountTestStateBaseline(baseline, account) {
  if (!baseline) return false;
  const actual = accountTestState(account);
  return actual.status === baseline.status
    && actual.statusKnown === baseline.statusKnown
    && actual.schedulable === baseline.schedulable
    && actual.schedulableKnown === baseline.schedulableKnown;
}

function assertAccountTestSubmittedBaseline(baseline, account) {
  if (!matchesAccountTestIdentityBaseline(baseline, account)) {
    const error = new Error('账号强身份自测试任务提交后已变化，拒绝测试复用的数字 ID');
    error.code = 'ACCOUNT_TEST_SUBMITTED_TARGET_CHANGED';
    throw error;
  }
  if (!matchesAccountTestStateBaseline(baseline, account)) {
    const error = new Error('账号状态或调度设置自测试任务提交后已变化，已拒绝执行');
    error.code = 'ACCOUNT_TEST_SUBMITTED_STATE_CHANGED';
    throw error;
  }
  if (!matchesAccountTestTargetDigest(baseline, account)) {
    const error = new Error('账号凭据或恢复状态自测试任务提交后已变化，已拒绝执行');
    error.code = 'ACCOUNT_TEST_SUBMITTED_TARGET_CHANGED';
    throw error;
  }
}

function sameAccountTarget(expected, actual) {
  const expectedId = normalizePositiveAccountId(expected?.id);
  const actualId = normalizePositiveAccountId(actual?.id);
  return !accountTestTargetError(expected)
    && !accountTestTargetError(actual)
    && expectedId !== null
    && expectedId === actualId
    && identitiesStronglyCompatible(accountIdentityKeys(expected), accountIdentityKeys(actual))
    && JSON.stringify(canonicalStrongIdentityKeys(expected))
      === JSON.stringify(canonicalStrongIdentityKeys(actual));
}

function sameAccountOwnership(expected, actual) {
  if (!sameAccountTarget(expected, actual)) return false;
  const expectedDigest = accountTestOwnershipDigest(expected);
  const actualDigest = accountTestOwnershipDigest(actual);
  if (!expectedDigest || !actualDigest) return false;
  const expectedBuffer = Buffer.from(expectedDigest, 'hex');
  const actualBuffer = Buffer.from(actualDigest, 'hex');
  return expectedBuffer.length === actualBuffer.length
    && crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

function accountStateVersion(account) {
  return accountTestTargetDigest(account);
}

function sameAccountStateVersion(expected, actual) {
  const expectedVersion = accountStateVersion(expected);
  const actualVersion = accountStateVersion(actual);
  if (!expectedVersion || !actualVersion) return false;
  const expectedBuffer = Buffer.from(expectedVersion, 'hex');
  const actualBuffer = Buffer.from(actualVersion, 'hex');
  return expectedBuffer.length === actualBuffer.length
    && crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

function activeAccountTestJobs(jobs = []) {
  const result = new Map();
  for (const job of jobs || []) {
    if (job?.type !== 'account_test' || !['queued', 'running'].includes(job.status)) continue;
    const ids = Array.isArray(job.payload?.accountIds) ? job.payload.accountIds : [];
    for (const id of ids) {
      const normalized = normalizePositiveAccountId(id);
      if (normalized && !result.has(String(normalized))) result.set(String(normalized), job);
    }
  }
  return result;
}

function classifyAccountTestTargets(accountRows, accountIds, activeJobs = new Map()) {
  const rows = new Map((accountRows || []).map((account) => [String(account.id), account]));
  const eligible = [];
  const rejected = [];
  for (const id of accountIds || []) {
    const key = String(id);
    const activeJob = activeJobs.get(key);
    if (activeJob) {
      rejected.push({
        accountId: id,
        code: 'account_test_already_running',
        message: '该账号已有测试任务排队或运行中',
        jobId: activeJob.id,
      });
      continue;
    }
    const account = rows.get(key);
    if (!account) {
      rejected.push({ accountId: id, code: 'account_not_found', message: 'Sub2API 中不存在该账号' });
      continue;
    }
    const targetError = accountTestTargetError(account);
    if (targetError) {
      rejected.push({
        accountId: id,
        accountName: account.name || null,
        code: targetError,
        message: '账号身份、类型或状态无法安全确认，已跳过测试',
      });
      continue;
    }
    eligible.push({ id, account });
  }
  return { eligible, rejected };
}

function resultForRejected(item) {
  return {
    accountId: item.accountId,
    accountName: item.accountName || null,
    status: 'skipped',
    code: item.code,
    message: item.message,
    durationMs: 0,
  };
}

async function auditResult(db, logger, result, actor, jobId, modelId) {
  if (!db) return;
  const testSuccessKnown = result.testSuccessKnown === false
    ? false
    : typeof result.testSuccess === 'boolean';
  const enabledKnown = result.enabledKnown === false
    ? false
    : typeof result.enabled === 'boolean';
  const statusAfterKnown = result.statusAfterKnown === false
    ? false
    : typeof result.statusAfter === 'string' && result.statusAfter.length > 0;
  try {
    await db.audit({
      jobId,
      actor,
      action: 'account_test',
      targetKey: 'account:' + result.accountId,
      result: result.status === 'succeeded' ? 'ok' : result.status === 'skipped' ? 'skipped' : 'failed',
      details: {
        model: modelId || null,
        accountName: result.accountName || null,
        status: result.status,
        code: result.code || null,
        message: result.message || null,
        durationMs: result.durationMs || 0,
        attempted: result.attempted !== false,
        interruptionReason: result.interruptionReason || null,
        testSuccess: testSuccessKnown ? result.testSuccess : null,
        testSuccessKnown,
        enabled: enabledKnown ? result.enabled : null,
        enabledKnown,
        statusAfterKnown,
        requiresReconciliation: result.requiresReconciliation === true,
        writeOutcomeUnknown: result.writeOutcomeUnknown === true,
        testOutcomeUnknown: result.testOutcomeUnknown === true,
        reconciliationScope: result.reconciliationScope || null,
        reconciliationReason: result.reconciliationReason || null,
        statusBefore: result.statusBefore || null,
        statusAfter: statusAfterKnown ? result.statusAfter : null,
      },
    });
  } catch (error) {
    writeLog(logger, 'error', 'account_test.audit_failed', {
      jobId,
      actor,
      accountId: result.accountId,
      error: safeErrorMessage(error),
    });
  }
}

async function rollbackOwnedSchedulableMutation(client, id, mutation, options = {}) {
  if (!mutation?.after || mutation.original === mutation.written) {
    return { attempted: false, succeeded: false, state: null, reason: 'rollback_not_owned' };
  }
  let current;
  try { current = await client.getAccount(id, { signal: options.signal }); } catch (error) {
    if (error?.code === 'JOB_INTERRUPTED' || options.signal?.aborted) throw error;
    return { attempted: false, succeeded: false, state: null, reason: 'rollback_state_unavailable' };
  }
  if (!sameAccountOwnership(mutation.after, current)
      || !sameAccountStateVersion(current, mutation.after)
      || current.schedulable !== mutation.written) {
    return { attempted: false, succeeded: false, state: current, reason: 'rollback_state_changed' };
  }
  assertAuditLogCheckpoint(options.logger, 'account_test.scheduler_rollback_checkpoint', {
    jobId: options.jobId || null,
    actor: options.actor || 'local',
    accountId: id,
    expectedSchedulable: mutation.original,
  });
  throwIfAccountTestStopped(options.signal, options.stopReason);
  let writeResponse;
  try {
    writeResponse = await client.setSchedulable(
      id,
      mutation.original,
      { signal: options.signal },
    );
  } catch (error) {
    if (options.signal?.aborted && !writeRequiresReconciliation(error)) {
      const stopReason = typeof options.stopReason === 'function'
        ? options.stopReason()
        : 'interrupted';
      throw schedulerReconciliationError(
        error,
        stopReason === 'timeout'
          ? 'rollback_not_dispatched_timeout'
          : 'rollback_not_dispatched_interrupted',
      );
    }
    throw error;
  }
  if (!writeResponse
      || !sameAccountOwnership(mutation.after, writeResponse)
      || writeResponse.schedulable !== mutation.original) {
    return {
      attempted: true,
      succeeded: false,
      state: writeResponse || current,
      reason: 'rollback_response_mismatch',
      writeOutcomeUnknown: true,
    };
  }
  const verified = await client.getAccount(id, { signal: options.signal });
  const succeeded = sameAccountOwnership(writeResponse, verified)
    && sameAccountStateVersion(verified, writeResponse)
    && verified.schedulable === mutation.original;
  return {
    attempted: true,
    succeeded,
    state: verified,
    reason: succeeded ? null : 'rollback_verification_mismatch',
  };
}

async function runAccountTestJobNow({
  accountIds,
  targetBaselines,
  modelId = '',
  prompt = '',
  actor = 'local',
  db,
  jobId,
  logger = null,
  client: providedClient = null,
  jobTimeoutMs: requestedJobTimeoutMs = null,
  signal: externalSignal = null,
  persistResult = null,
}) {
  throwIfJobInterrupted(externalSignal);
  accountIds = normalizeAccountTestJobAccountIds(accountIds);
  const startedAt = performance.now();
  const timeoutStartedAt = startedAt;
  const jobTimeoutMs = Number.isFinite(Number(requestedJobTimeoutMs))
    && Number(requestedJobTimeoutMs) > 0
    ? Math.floor(Number(requestedJobTimeoutMs))
    : boundedJobDuration(process.env.PANEL_ACCOUNT_TEST_JOB_TIMEOUT_MS);
  const deadline = timeoutStartedAt + jobTimeoutMs;
  const jobSignal = createAccountTestJobSignal(externalSignal, jobTimeoutMs, timeoutStartedAt);
  const signal = jobSignal.signal;
  try {
    const normalizedModelId = normalizeAccountTestModelId(modelId);
    const normalizedPrompt = normalizeAccountTestPrompt(prompt);
    const baselineByAccountId = accountTestBaselineMap(targetBaselines, accountIds);
  if (db && jobId) {
    if (typeof db.startMutationJob !== 'function') {
      const error = new Error('任务执行安全检查不可用，尚未开始账号测试');
      error.code = 'JOB_RECONCILIATION_GUARD_UNAVAILABLE';
      throw error;
    }
    await db.startMutationJob(jobId);
  }
  writeLog(logger, 'info', 'account_test.started', {
    jobId,
    actor,
    accountCount: accountIds.length,
    model: normalizedModelId || null,
  });

    const client = providedClient || new Sub2ApiAdminClient({ logger, logContext: { jobId, actor } });
    const results = [];
    const appendReconciliationResult = async ({
      error,
      accountId,
      account,
      statusBefore,
      testSucceeded,
      itemStartedAt,
    }) => {
      const scope = error.reconciliationScope === 'test' ? 'test' : 'scheduler';
      const testOutcomeUnknown = scope === 'test' && error.testOutcomeUnknown === true;
      const reconciledTestSuccess = error.testSuccessKnown === true
        && typeof error.testSuccess === 'boolean'
        ? error.testSuccess
        : testSucceeded;
      const causeCode = typeof error.code === 'string' && /^[A-Z0-9_]{1,96}$/.test(error.code)
        ? error.code
        : null;
      const result = {
        accountId,
        accountName: account?.name || null,
        status: 'failed',
        code: scope === 'test'
          ? 'account_test_reconciliation_required'
          : 'account_scheduler_reconciliation_required',
        causeCode,
        message: scope === 'test'
          ? (testOutcomeUnknown
            ? '账号测试请求已发出，但结果无法确认；已停止后续测试，请人工核对该账号状态'
            : '账号测试已完成，但恢复状态或后续调度流程未能安全确认；已停止后续测试，请人工核对')
          : '测试成功，但调度设置写入或回滚结果无法确认；已停止后续测试，请人工核对该账号调度状态',
        testSuccess: testOutcomeUnknown ? null : reconciledTestSuccess,
        testSuccessKnown: !testOutcomeUnknown,
        enabled: null,
        enabledKnown: false,
        requiresReconciliation: true,
        writeOutcomeUnknown: error.writeOutcomeUnknown === true,
        testOutcomeUnknown,
        reconciliationScope: scope,
        reconciliationReason: normalizedReconciliationReason(
          error.reconciliationReason || error.writeOutcomeReason,
        ),
        interruptionReason: stopReason,
        statusBefore,
        statusAfter: null,
        statusAfterKnown: false,
        durationMs: elapsedMilliseconds(itemStartedAt),
      };
      results.push(result);
      await auditResult(db, logger, result, actor, jobId, normalizedModelId);
      writeLog(logger, 'error', scope === 'test'
        ? 'account_test.test_reconciliation_required'
        : 'account_test.scheduler_reconciliation_required', {
        jobId,
        actor,
        accountId,
        accountName: account?.name || null,
        code: causeCode,
        reconciliationScope: scope,
        reconciliationReason: result.reconciliationReason,
        durationMs: result.durationMs,
      });
      return result;
    };
    let initialAccounts = [];
    let stopReason = null;
    let executionStopIndex = null;
    try {
      initialAccounts = await client.listAccounts({
        platform: 'openai',
        type: 'oauth',
        pageSize: 200,
        requireTotal: true,
        requirePaginationMetadata: true,
        signal,
      });
    } catch (error) {
      stopReason = jobSignal.reason();
      if (!stopReason) throw error;
      executionStopIndex = 0;
    }
    let reconciliationStopIndex = null;
    if (!stopReason) {
  for (let itemIndex = 0; itemIndex < accountIds.length; itemIndex += 1) {
    const id = accountIds[itemIndex];
    const boundaryStopReason = jobSignal.reason();
    if (boundaryStopReason) {
      stopReason = boundaryStopReason;
      executionStopIndex = itemIndex;
      break;
    }
    const itemStartedAt = performance.now();
    const listedAccount = initialAccounts.find((candidate) => candidate.id === id) || null;
    const submittedBaseline = baselineByAccountId.get(id);
    let account = listedAccount;
    let statusBefore = submittedBaseline?.status || account?.status || null;
    let schedulableBefore = submittedBaseline?.schedulableKnown === true
      ? submittedBaseline.schedulable
      : (typeof account?.schedulable === 'boolean' ? account.schedulable : null);
    let recoveryAttempted = false;
    let recoveryMutation = null;
    let testAttempted = false;
    let testSucceeded = false;
    let testSuccessKnown = false;
    let confirmedPostTestState = null;
    let schedulerEnablePending = false;
    try {
      if (listedAccount) assertAccountTestSubmittedBaseline(submittedBaseline, listedAccount);
      // Re-read immediately before testing so a deleted account or concurrent
      // admin change cannot turn this into a probe of the wrong account.
      const current = await client.getAccount(id, { signal });
      if (!current) {
        const result = {
          accountId: id,
          status: 'skipped',
          code: 'account_not_found',
          message: 'Sub2API 中不存在该账号',
          attempted: false,
          testSuccess: null,
          testSuccessKnown: false,
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        continue;
      }
      const targetError = accountTestTargetError(current);
      assertAccountTestSubmittedBaseline(submittedBaseline, current);
      if (targetError || (listedAccount && !sameAccountTarget(listedAccount, current))) {
        const error = new Error('账号身份、类型或状态在测试前无法安全确认');
        error.code = targetError || 'ACCOUNT_TEST_SUBMITTED_TARGET_CHANGED';
        throw error;
      }
      account = current;
      statusBefore = current.status || statusBefore;
      schedulableBefore = current.schedulable;
      const shouldRecover = accountStatus(account) === 'error';

      assertAuditLogCheckpoint(logger, 'account_test.test_mutation_checkpoint', {
        jobId,
        actor,
        accountId: id,
        model: normalizedModelId || null,
      });
      throwIfAccountTestStopped(signal, () => jobSignal.reason());
      const test = await client.testAccount(id, {
        modelId: normalizedModelId,
        prompt: normalizedPrompt,
        timeoutMs: Math.max(1, deadline - performance.now()),
        signal,
      });
      // A returned terminal response proves that the adapter dispatched the
      // probe. Thrown adapter errors carry their own reconciliation marker
      // when dispatch occurred; a plain exception is a pre-dispatch failure
      // and must not inflate attempted/execution counters.
      testAttempted = true;
      let returnedTestSuccess;
      try {
        returnedTestSuccess = test?.success;
      } catch {
        // Treat hostile/invalid response objects exactly like a missing
        // success field and never copy a thrown remote value into logs.
        returnedTestSuccess = undefined;
      }
      if (typeof returnedTestSuccess !== 'boolean') {
        const error = new Error('Sub2API 账号测试结果结构无效');
        error.code = 'ACCOUNT_TEST_RESULT_INVALID';
        throw accountTestReconciliationError(
          error,
          'test_response_invalid',
          { testOutcomeUnknown: true },
        );
      }
      testSuccessKnown = true;
      testSucceeded = returnedTestSuccess;
      // Any dispatched test can change Sub2API runtime state, including a
      // test whose terminal result is a known failure. If shutdown wins before
      // postflight verification, persist the unfinished chain rather than
      // silently relabelling it as an ordinary interrupted job.
      const postTestStopReason = jobSignal.reason();
      if (postTestStopReason && testSuccessKnown) {
        throw accountTestReconciliationError(
          accountTestStopError(postTestStopReason),
          postTestStopReason === 'timeout' ? 'post_test_timeout' : 'post_test_interrupted',
          { testSuccess: testSucceeded },
        );
      }
      throwIfAccountTestStopped(signal, () => postTestStopReason);
      if (!returnedTestSuccess) {
        let afterFailure = null;
        let afterFailureReadError = null;
        try {
          afterFailure = await client.getAccount(id, { signal });
        } catch (readError) {
          if (readError?.code === 'JOB_INTERRUPTED' || signal?.aborted) {
            throw accountTestReconciliationError(
              readError,
              jobSignal.reason() === 'timeout' ? 'post_test_timeout' : 'post_test_interrupted',
              { testSuccess: false },
            );
          }
          afterFailureReadError = readError;
        }
        if (!afterFailure) {
          writeLog(logger, 'error', 'account_test.failed_state_unavailable', {
            jobId,
            actor,
            accountId: id,
            error: safeErrorMessage(afterFailureReadError || 'account state unavailable'),
          });
          const error = new Error('账号测试失败后无法确认账号当前状态');
          error.code = 'ACCOUNT_TEST_POSTFLIGHT_UNAVAILABLE';
          throw accountTestReconciliationError(
            error,
            'post_test_state_unconfirmed',
            { testSuccess: false },
          );
        }
        if (!sameAccountOwnership(account, afterFailure)) {
          const error = new Error('账号测试后身份、凭据或所属组已变化');
          error.code = 'ACCOUNT_TEST_TARGET_CHANGED';
          throw accountTestReconciliationError(
            error,
            'post_test_target_changed',
            { testSuccess: false },
          );
        }
        const result = {
          accountId: id,
          accountName: account.name || null,
          status: 'failed',
          code: 'upstream_test_failed',
          // Keep the worker boundary defensive even though the production
          // adapter currently emits a fixed failure message. Injected clients
          // and future adapters must not be able to persist or log credentials.
          message: safeErrorMessage(test.message || '常规请求失败'),
          testSuccess: false,
          statusBefore,
          enabled: afterFailure.schedulable === true,
          enabledKnown: true,
          statusAfter: afterFailure.status || null,
          statusAfterKnown: true,
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'warn', 'account_test.item_failed', {
          jobId,
          actor,
          accountId: id,
          accountName: account.name || null,
          code: result.code,
          durationMs: result.durationMs,
          error: result.message,
        });
        continue;
      }
      // Sub2API's test endpoint already clears recoverable runtime state. The
      // panel only changes schedulable for accounts that started in error;
      // healthy or intentionally disabled accounts must keep their setting.
      if (!shouldRecover) {
        const after = await client.getAccount(id, { signal });
        const targetUnchanged = sameAccountOwnership(account, after);
        if (!targetUnchanged) {
          const error = new Error('账号测试后身份、凭据或所属组已变化');
          error.code = 'ACCOUNT_TEST_TARGET_CHANGED';
          throw accountTestReconciliationError(
            error,
            'post_test_target_changed',
            { testSuccess: true },
          );
        }
        const statusUnchanged = targetUnchanged && accountStatus(after) === accountStatus(account);
        const schedulableUnchanged = targetUnchanged && after.schedulable === schedulableBefore;
        if (!statusUnchanged || !schedulableUnchanged) {
          const result = {
            accountId: id,
            accountName: after?.name || account.name || null,
            status: 'failed',
            code: 'account_state_changed_after_test',
            message: '测试请求成功，但账号状态或调度设置发生变化，未标记为成功',
            testSuccess: true,
            enabled: targetUnchanged ? after.schedulable === true : null,
            enabledKnown: targetUnchanged,
            statusBefore,
            statusAfter: targetUnchanged ? after?.status || null : null,
            statusAfterKnown: targetUnchanged,
            durationMs: elapsedMilliseconds(itemStartedAt),
          };
          results.push(result);
          await auditResult(db, logger, result, actor, jobId, normalizedModelId);
          writeLog(logger, 'error', 'account_test.state_changed_after_test', {
            jobId,
            actor,
            accountId: id,
            accountName: result.accountName,
            statusBefore,
            statusAfter: result.statusAfter,
            schedulableBefore,
            schedulableAfter: result.enabled,
            durationMs: result.durationMs,
          });
          continue;
        }
        const result = {
          accountId: id,
          accountName: account.name || null,
          status: 'succeeded',
          code: 'account_test_succeeded',
          message: '测试请求成功，账号状态和调度设置未修改',
          testSuccess: true,
          enabled: after.schedulable === true,
          statusBefore,
          statusAfter: after?.status || statusBefore,
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'info', 'account_test.item_succeeded', {
          jobId,
          actor,
          accountId: id,
          accountName: account.name || null,
          stateChanged: false,
          durationMs: result.durationMs,
        });
        continue;
      }

      const afterTest = await client.getAccount(id, { signal });
      if (!sameAccountOwnership(account, afterTest)) {
        const error = new Error('测试后账号身份、凭据或所属组已变化，拒绝修改调度设置');
        error.code = 'ACCOUNT_TEST_TARGET_CHANGED';
        throw error;
      }
      confirmedPostTestState = afterTest;
      const availabilityAfterTest = getAccountAvailability(afterTest);
      if (availabilityAfterTest.key === 'available') {
        const result = {
          accountId: id,
          accountName: afterTest.name || account.name || null,
          status: 'succeeded',
          code: 'account_recovered',
          message: '测试成功，账号已恢复并启用调度',
          testSuccess: true,
          enabled: true,
          statusBefore,
          statusAfter: afterTest.status || 'active',
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'info', 'account_test.item_succeeded', {
          jobId,
          actor,
          accountId: id,
          accountName: result.accountName,
          stateChanged: false,
          durationMs: result.durationMs,
        });
        continue;
      }
      if (schedulableBefore === true
          && afterTest.schedulable === true
          && ['active', 'error'].includes(accountStatus(afterTest))) {
        const result = {
          accountId: id,
          accountName: afterTest.name || account.name || null,
          status: 'failed',
          code: 'account_recovery_not_confirmed',
          message: '测试成功，但账号仍不可用；原调度设置已保持不变',
          testSuccess: true,
          enabled: true,
          statusBefore,
          statusAfter: afterTest.status || statusBefore,
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'error', 'account_test.recovery_unconfirmed', {
          jobId,
          actor,
          accountId: id,
          accountName: result.accountName,
          availability: availabilityAfterTest.reason,
          schedulerPreserved: true,
          durationMs: result.durationMs,
        });
        continue;
      }
      if (afterTest.schedulable !== schedulableBefore
          || schedulableBefore !== false) {
        const error = new Error('测试后账号状态已变化或不允许自动启用调度');
        error.code = 'ACCOUNT_TEST_STATE_CHANGED';
        throw error;
      }
      // Evaluate the state that would exist after enabling scheduling before
      // issuing any write. Enabling cannot repair an error/inactive status
      // (including the legacy disabled spelling), expiry, rate limit,
      // temporary pause, overload, or malformed runtime
      // metadata; toggling true and then rolling back only adds an avoidable
      // mutation window and can overwrite a concurrent administrator change.
      const availabilityIfEnabled = getAccountAvailability({
        ...afterTest,
        schedulable: true,
        schedulableKnown: true,
      });
      if (availabilityIfEnabled.key !== 'available') {
        const result = {
          accountId: id,
          accountName: afterTest.name || account.name || null,
          status: 'failed',
          code: 'account_recovery_not_confirmed',
          message: availabilityIfEnabled.key === 'unknown'
            ? '测试成功，但账号恢复后的可用性无法确认；未修改调度设置'
            : '测试成功，但账号仍存在其他不可用状态；未修改调度设置',
          testSuccess: true,
          enabled: false,
          enabledKnown: true,
          statusBefore,
          statusAfter: afterTest.status || null,
          statusAfterKnown: true,
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'error', 'account_test.recovery_unconfirmed', {
          jobId,
          actor,
          accountId: id,
          accountName: result.accountName,
          availability: availabilityIfEnabled.reason,
          schedulerPreserved: true,
          durationMs: result.durationMs,
        });
        continue;
      }
      schedulerEnablePending = true;

      assertAuditLogCheckpoint(logger, 'account_test.scheduler_enable_checkpoint', {
        jobId,
        actor,
        accountId: id,
        expectedSchedulable: true,
      });
      throwIfAccountTestStopped(signal, () => jobSignal.reason());
      recoveryAttempted = true;
      recoveryMutation = {
        original: schedulableBefore,
        written: true,
        before: afterTest,
        after: null,
      };
      let writeResponse;
      try {
        writeResponse = await client.setSchedulable(id, true, { signal });
      } catch (error) {
        // The adapter marks dispatched writes whose outcome is unknown. A
        // plain interruption is therefore a confirmed pre-dispatch stop and
        // must not be promoted to an unknown scheduler mutation here.
        if (!writeRequiresReconciliation(error)) recoveryMutation = null;
        throw error;
      }
      if (!writeResponse
          || typeof writeResponse !== 'object'
          || !sameAccountOwnership(afterTest, writeResponse)
          || writeResponse.schedulable !== true) {
        // The write may have raced a delete/recreate. Its response is not
        // an account we can safely treat as our mutation or roll back.
        recoveryMutation = null;
        const error = new Error('启用调度响应与预检账号不一致');
        error.code = 'ACCOUNT_TEST_TARGET_CHANGED';
        throw schedulerReconciliationError(error, 'enable_response_mismatch', {
          writeOutcomeUnknown: true,
        });
      }
      recoveryMutation.after = writeResponse;
      const after = await client.getAccount(id, { signal });
      if (!sameAccountOwnership(afterTest, after)) {
        const error = new Error('启用调度后账号身份、凭据或所属组已变化');
        error.code = 'ACCOUNT_TEST_TARGET_CHANGED';
        throw error;
      }
      if (!sameAccountStateVersion(after, writeResponse)) {
        // Keep the immediate mutation response as the ownership boundary.
        // A later GET may include a concurrent administrator change; treating
        // that newer state as ours could make rollback undo their scheduler.
        const error = new Error('启用调度后账号状态被并发修改');
        error.code = 'ACCOUNT_TEST_STATE_CHANGED';
        throw error;
      }
      const enabled = after.schedulable === true;
      const availability = getAccountAvailability(after);
      const recovered = availability.key === 'available';
      if (!enabled || !recovered) {
        let rollback;
        try {
          rollback = await rollbackOwnedSchedulableMutation(
            client,
            id,
            recoveryMutation,
            { signal, logger, jobId, actor, stopReason: () => jobSignal.reason() },
          );
        } catch (rollbackError) {
          writeLog(logger, 'error', 'account_test.recovery_rollback_failed', {
            jobId,
            actor,
            accountId: id,
            error: safeErrorMessage(rollbackError),
          });
          recoveryMutation = null;
          throw schedulerReconciliationError(rollbackError, 'rollback_failed');
        }
        recoveryMutation = null;
        if (!rollback.succeeded) {
          const rollbackError = new Error('账号调度设置回滚未能安全确认');
          rollbackError.code = 'ACCOUNT_TEST_ROLLBACK_UNCONFIRMED';
          throw schedulerReconciliationError(
            rollbackError,
            rollback.reason || 'rollback_unconfirmed',
            { writeOutcomeUnknown: rollback.writeOutcomeUnknown === true },
          );
        }
        const rollbackState = rollback.state || after;
        const result = {
          accountId: id,
          accountName: account.name || null,
          status: 'failed',
          code: 'account_recovery_not_confirmed',
          message: '测试成功，但恢复状态或启用调度未确认，未标记为成功',
          testSuccess: true,
          enabled: sameAccountOwnership(account, rollbackState) && rollbackState.schedulable === true,
          statusBefore,
          statusAfter: rollbackState?.status || after?.status || null,
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'error', 'account_test.recovery_unconfirmed', {
          jobId,
          actor,
          accountId: id,
          accountName: account.name || null,
          enabled,
          recovered,
          availability: availability.reason,
          rollbackSucceeded: true,
          rollbackReason: null,
          durationMs: result.durationMs,
        });
        continue;
      }

      const result = {
        accountId: id,
        accountName: account.name || null,
        status: 'succeeded',
        code: 'account_recovered',
        message: '测试成功，账号已恢复并启用调度',
        testSuccess: true,
        enabled: true,
        statusBefore,
        statusAfter: after?.status || 'active',
        durationMs: elapsedMilliseconds(itemStartedAt),
      };
      results.push(result);
      await auditResult(db, logger, result, actor, jobId, normalizedModelId);
      writeLog(logger, 'info', 'account_test.item_succeeded', {
        jobId,
        actor,
        accountId: id,
        accountName: account.name || null,
        durationMs: result.durationMs,
      });
    } catch (error) {
      const caughtStopReason = jobSignal.reason();
      if (caughtStopReason) stopReason = caughtStopReason;
      let reconciliationError = writeRequiresReconciliation(error)
        ? schedulerReconciliationError(error)
        : null;
      if (reconciliationError && caughtStopReason === 'timeout') {
        if (reconciliationError.reconciliationScope === 'test') {
          reconciliationError.reconciliationReason = 'job_timeout';
        } else if (reconciliationError.writeOutcomeUnknown === true) {
          reconciliationError.reconciliationReason = 'job_timeout';
          reconciliationError.writeOutcomeReason = 'job_timeout';
        }
      }
      if (!reconciliationError
          && caughtStopReason
          && testSuccessKnown
          && confirmedPostTestState
          && schedulerEnablePending
          && !recoveryMutation) {
        const result = {
          accountId: id,
          accountName: confirmedPostTestState.name || account?.name || null,
          status: 'failed',
          code: caughtStopReason === 'timeout'
            ? 'account_scheduler_enable_not_attempted_timeout'
            : 'account_scheduler_enable_not_attempted_interrupted',
          message: caughtStopReason === 'timeout'
            ? '账号测试已完成且测试后状态已确认，但总时限到达前未发送调度启用请求'
            : '账号测试已完成且测试后状态已确认，但面板停止前未发送调度启用请求',
          attempted: true,
          interruptionReason: caughtStopReason,
          testSuccess: testSucceeded,
          testSuccessKnown: true,
          enabled: confirmedPostTestState.schedulable === true,
          enabledKnown: true,
          statusBefore,
          statusAfter: confirmedPostTestState.status || null,
          statusAfterKnown: true,
          durationMs: elapsedMilliseconds(itemStartedAt),
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'warn', 'account_test.scheduler_enable_not_attempted', {
          jobId,
          actor,
          accountId: id,
          accountName: result.accountName,
          interruptionReason: caughtStopReason,
          durationMs: result.durationMs,
        });
        executionStopIndex = itemIndex + 1;
        break;
      }
      if (!reconciliationError
          && testSuccessKnown
          && !recoveryMutation) {
        reconciliationError = accountTestReconciliationError(
          error,
          error?.code === 'JOB_INTERRUPTED' || signal?.aborted
            ? (caughtStopReason === 'timeout' ? 'post_test_timeout' : 'post_test_interrupted')
            : 'post_test_state_unconfirmed',
          { testSuccess: testSucceeded },
        );
      }
      if (recoveryMutation && !reconciliationError) {
        try {
          const rollback = await rollbackOwnedSchedulableMutation(
            client,
            id,
            recoveryMutation,
            { signal, logger, jobId, actor, stopReason: () => jobSignal.reason() },
          );
          if (rollback.succeeded) {
            writeLog(logger, 'warn', 'account_test.recovery_rolled_back', {
              jobId,
              actor,
              accountId: id,
              reason: safeErrorMessage(error),
            });
          } else {
            writeLog(logger, 'error', 'account_test.recovery_rollback_skipped', {
              jobId,
              actor,
              accountId: id,
              reason: rollback.reason,
            });
            const rollbackError = new Error('账号调度设置回滚未能安全确认');
            rollbackError.code = 'ACCOUNT_TEST_ROLLBACK_UNCONFIRMED';
            reconciliationError = schedulerReconciliationError(
              rollbackError,
              rollback.reason || 'rollback_unconfirmed',
              { writeOutcomeUnknown: rollback.writeOutcomeUnknown === true },
            );
          }
        } catch (rollbackError) {
          writeLog(logger, 'error', 'account_test.recovery_rollback_failed', {
            jobId,
            actor,
            accountId: id,
            error: safeErrorMessage(rollbackError),
          });
          reconciliationError = schedulerReconciliationError(rollbackError, 'rollback_failed');
        }
      }
      recoveryMutation = null;
      if (reconciliationError) {
        await appendReconciliationResult({
          error: reconciliationError,
          accountId: id,
          account,
          statusBefore,
          testSucceeded,
          itemStartedAt,
        });
        reconciliationStopIndex = itemIndex;
        break;
      }
      // Cancellation is a job-level terminal outcome when no scheduler state
      // is ambiguous. A confirmed mutation that could not be safely rolled
      // back has already been converted into a persisted reconciliation result.
      if (caughtStopReason) {
        executionStopIndex = itemIndex;
        break;
      }
      let afterFailure = null;
      try {
        afterFailure = await client.getAccount(id, { signal });
      } catch (readError) {
        const diagnosticStopReason = jobSignal.reason();
        if (diagnosticStopReason) {
          stopReason = diagnosticStopReason;
          // A plain test error carries no adapter evidence that the request
          // was dispatched. If its diagnostic read is then cancelled, keep
          // the current account in the not-attempted set instead of inventing
          // an unknown remote test outcome.
          executionStopIndex = itemIndex;
          break;
        }
      }
      const afterFailureOwned = sameAccountOwnership(account, afterFailure);
      const result = {
        accountId: id,
        accountName: account?.name || null,
        status: 'failed',
        code: ['ACCOUNT_TEST_SUBMITTED_STATE_CHANGED', 'ACCOUNT_TEST_SUBMITTED_TARGET_CHANGED']
          .includes(error?.code)
          ? error.code
          : (recoveryAttempted ? 'account_recovery_failed' : 'account_test_failed'),
        message: safeErrorMessage(error),
        attempted: testAttempted,
        testSuccess: testSuccessKnown ? testSucceeded : null,
        testSuccessKnown,
        enabled: afterFailureOwned ? afterFailure.schedulable === true : null,
        enabledKnown: afterFailureOwned,
        statusBefore,
        statusAfter: afterFailureOwned ? afterFailure.status || null : null,
        statusAfterKnown: afterFailureOwned,
        durationMs: elapsedMilliseconds(itemStartedAt),
      };
      results.push(result);
      await auditResult(db, logger, result, actor, jobId, normalizedModelId);
      writeLog(logger, 'error', 'account_test.item_failed', {
        jobId,
        actor,
        accountId: id,
        accountName: account?.name || null,
        code: result.code,
        durationMs: result.durationMs,
        error: result.message,
      });
    }
  }
    }

  if (reconciliationStopIndex !== null) {
    for (let index = reconciliationStopIndex + 1; index < accountIds.length; index += 1) {
      const accountId = accountIds[index];
      const listedAccount = initialAccounts.find((candidate) => candidate.id === accountId) || null;
      const result = {
        accountId,
        accountName: listedAccount?.name || null,
        status: 'skipped',
        code: 'account_test_not_attempted_reconciliation',
        message: '前一账号需要人工核对，本账号未执行测试',
        attempted: false,
        interruptionReason: stopReason,
        durationMs: 0,
      };
      results.push(result);
      await auditResult(db, logger, result, actor, jobId, normalizedModelId);
    }
  }
  if (reconciliationStopIndex === null && executionStopIndex !== null) {
    const interruptionCode = stopReason === 'timeout'
      ? 'account_test_job_timeout'
      : 'account_test_not_attempted_interrupted';
    const interruptionMessage = stopReason === 'timeout'
      ? '账号测试任务达到总时限，本账号未执行'
      : '面板停机中断了批量任务，本账号未执行测试';
    for (let index = executionStopIndex; index < accountIds.length; index += 1) {
      const accountId = accountIds[index];
      const listedAccount = initialAccounts.find((candidate) => candidate.id === accountId) || null;
      const result = {
        accountId,
        accountName: listedAccount?.name || null,
        status: 'skipped',
        code: interruptionCode,
        message: interruptionMessage,
        attempted: false,
        interruptionReason: stopReason,
        durationMs: 0,
      };
      results.push(result);
      await auditResult(db, logger, result, actor, jobId, normalizedModelId);
    }
  }

  if (results.length !== accountIds.length) {
    const error = new Error('账号测试结果数量与请求数量不一致');
    error.code = 'ACCOUNT_TEST_RESULT_COUNT_MISMATCH';
    throw error;
  }

  const succeeded = results.filter((item) => item.status === 'succeeded').length;
  const failed = results.filter((item) => item.status === 'failed').length;
  const skipped = results.filter((item) => item.status === 'skipped').length;
  const reconciliationCount = results.filter(
    (item) => item.requiresReconciliation === true,
  ).length;
  const attemptedCount = results.filter((item) => item.attempted !== false).length;
  const notAttemptedCount = results.length - attemptedCount;
  const reconciliationNotAttemptedCount = results.filter(
    (item) => item.code === 'account_test_not_attempted_reconciliation',
  ).length;
  const timeoutCount = results.filter((item) => item.interruptionReason === 'timeout').length;
  const interruptedCount = results.filter(
    (item) => item.interruptionReason === 'interrupted',
  ).length;
  const result = {
    model: normalizedModelId || null,
    requested: accountIds.length,
    succeeded,
    failed,
    skipped,
    requiresReconciliation: reconciliationCount > 0,
    reconciliationCount,
    attemptedCount,
    notAttemptedCount,
    reconciliationNotAttemptedCount,
    timeoutCount,
    interruptedCount,
    stopReason,
    executionStarted: attemptedCount > 0,
    executionComplete: notAttemptedCount === 0,
    durationMs: elapsedMilliseconds(startedAt),
    results,
  };
  result.jobStatus = accountTestJobStatus(result);
  writeLog(logger, result.jobStatus === 'succeeded' ? 'info' : 'warn', 'account_test.completed', {
    jobId,
    actor,
    requested: result.requested,
    succeeded,
    failed,
    skipped,
    requiresReconciliation: result.requiresReconciliation,
    reconciliationCount,
    attemptedCount,
    notAttemptedCount,
    timeoutCount,
    interruptedCount,
    stopReason,
    jobStatus: result.jobStatus,
    durationMs: result.durationMs,
  });
  if (typeof persistResult === 'function') {
    try {
      await persistResult(result);
    } catch (error) {
      // The observer repeats this bounded, idempotent terminal write. Do not
      // reinterpret a completed remote test as a failed test because the
      // first local persistence attempt was unavailable.
      writeLog(logger, 'error', 'account_test.job_update_deferred', {
        jobId,
        actor,
        error: safeErrorMessage(error),
      });
    }
  }
  return result;
  } finally {
    jobSignal.dispose();
  }
}

function runAccountTestJob(args = {}) {
  return withControlPlaneLock(
    async () => {
      try {
        return await runAccountTestJobNow(args);
      } catch (error) {
        if (typeof args.persistFailure === 'function') {
          try {
            // As with normal result persistence, settle the durable job row
            // while the control-plane lease is still held. The observer is an
            // idempotent fallback for temporary persistence failures only.
            await args.persistFailure(error);
          } catch (jobError) {
            writeLog(args.logger, 'error', 'account_test.job_update_deferred', {
              jobId: args.jobId || null,
              actor: args.actor || 'local',
              terminalOutcome: 'failed',
              error: safeErrorMessage(jobError),
            });
          }
        }
        throw error;
      }
    },
    { signal: args.signal },
  );
}

module.exports = {
  accountTestJobStatus,
  accountTestTargetBaseline,
  activeAccountTestJobs,
  assertAccountTestTargetRevisions,
  classifyAccountTestTargets,
  normalizeAccountTestModelId,
  normalizeAccountTestRequest,
  resultForRejected,
  runAccountTestJob,
  runAccountTestJobNow,
  safeErrorMessage,
  withAccountTestSubmissionLock,
};
