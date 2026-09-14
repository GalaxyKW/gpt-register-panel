const crypto = require('node:crypto');

const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
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

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Logging must never change the outcome of a remote account test.
  }
}

function safeErrorMessage(error) {
  return redactText(String(error?.message || error || 'unknown error')).slice(0, 1000);
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
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text)) return null;
  const id = Number(text);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function normalizeAccountTestModelId(value) {
  const model = String(value ?? '').trim();
  if (model.toLowerCase() === '5.6-luna') return 'gpt-5.6-luna';
  return model;
}

function boundedJobDuration(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return 30 * 60 * 1000;
  return Math.max(60 * 1000, Math.min(2 * 60 * 60 * 1000, Math.floor(number)));
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
  const modelValue = body.modelId ?? body.model_id ?? '';
  if (typeof modelValue !== 'string' || modelValue.length > 256) {
    const error = new Error('modelId 必须是长度不超过 256 的字符串');
    error.code = 'ACCOUNT_TEST_MODEL_INVALID';
    throw error;
  }
  const promptValue = body.prompt ?? '';
  if (typeof promptValue !== 'string' || promptValue.length > 2000) {
    const error = new Error('prompt 必须是长度不超过 2000 的字符串');
    error.code = 'ACCOUNT_TEST_PROMPT_INVALID';
    throw error;
  }
  return {
    targets,
    accountIds,
    modelId: normalizeAccountTestModelId(modelValue),
    prompt: promptValue.trim(),
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
  return {
    status,
    statusKnown: account?.statusKnown === undefined
      ? ['active', 'disabled', 'error'].includes(status)
      : account.statusKnown === true,
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
        || !['active', 'disabled', 'error'].includes(status)
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
  return !accountTestTargetError(expected)
    && !accountTestTargetError(actual)
    && Number(expected.id) === Number(actual.id)
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
  throwIfJobInterrupted(options.signal);
  const writeResponse = await client.setSchedulable(
    id,
    mutation.original,
    { signal: options.signal },
  );
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
  signal = null,
  persistResult = null,
}) {
  throwIfJobInterrupted(signal);
  const startedAt = Date.now();
  const jobTimeoutMs = Number.isFinite(Number(requestedJobTimeoutMs))
    && Number(requestedJobTimeoutMs) > 0
    ? Math.floor(Number(requestedJobTimeoutMs))
    : boundedJobDuration(process.env.PANEL_ACCOUNT_TEST_JOB_TIMEOUT_MS);
  const deadline = startedAt + jobTimeoutMs;
  const normalizedModelId = normalizeAccountTestModelId(modelId);
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
  const initialAccounts = await client.listAccounts({
    platform: 'openai',
    type: 'oauth',
    pageSize: 200,
    requireTotal: true,
    requirePaginationMetadata: true,
    signal,
  });
  const results = [];
  let reconciliationStopIndex = null;
  for (let itemIndex = 0; itemIndex < accountIds.length; itemIndex += 1) {
    const id = accountIds[itemIndex];
    throwIfJobInterrupted(signal);
    const itemStartedAt = Date.now();
    const listedAccount = initialAccounts.find((candidate) => candidate.id === id) || null;
    const submittedBaseline = baselineByAccountId.get(id);
    if (itemStartedAt >= deadline) {
      const result = {
        accountId: id,
        accountName: listedAccount?.name || null,
        status: 'skipped',
        code: 'account_test_job_timeout',
        message: '账号测试任务达到总时限，剩余账号已跳过',
        durationMs: 0,
      };
      results.push(result);
      await auditResult(db, logger, result, actor, jobId, normalizedModelId);
      continue;
    }
    let account = listedAccount;
    let statusBefore = submittedBaseline?.status || account?.status || null;
    let schedulableBefore = submittedBaseline?.schedulableKnown === true
      ? submittedBaseline.schedulable
      : (typeof account?.schedulable === 'boolean' ? account.schedulable : null);
    let recoveryAttempted = false;
    let recoveryMutation = null;
    let testSucceeded = false;
    let testSuccessKnown = false;
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
          durationMs: Date.now() - itemStartedAt,
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
      throwIfJobInterrupted(signal);
      const test = await client.testAccount(id, {
        modelId: normalizedModelId,
        prompt,
        timeoutMs: Math.max(1, deadline - Date.now()),
        signal,
      });
      testSuccessKnown = typeof test?.success === 'boolean';
      testSucceeded = test?.success === true;
      // Any dispatched test can change Sub2API runtime state, including a
      // test whose terminal result is a known failure. If shutdown wins before
      // postflight verification, persist the unfinished chain rather than
      // silently relabelling it as an ordinary interrupted job.
      if (signal?.aborted && testSuccessKnown) {
        throw accountTestReconciliationError(
          new Error('账号测试后状态确认流程因面板停机中断'),
          'post_test_interrupted',
          { testSuccess: testSucceeded },
        );
      }
      throwIfJobInterrupted(signal);
      if (!test.success) {
        let afterFailure = null;
        let afterFailureReadError = null;
        try {
          afterFailure = await client.getAccount(id, { signal });
        } catch (readError) {
          if (readError?.code === 'JOB_INTERRUPTED' || signal?.aborted) {
            throw accountTestReconciliationError(
              readError,
              'post_test_interrupted',
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
          message: test.message || '常规请求失败',
          testSuccess: false,
          statusBefore,
          enabled: afterFailure.schedulable === true,
          enabledKnown: true,
          statusAfter: afterFailure.status || null,
          statusAfterKnown: true,
          durationMs: Date.now() - itemStartedAt,
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
            durationMs: Date.now() - itemStartedAt,
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
          durationMs: Date.now() - itemStartedAt,
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
          durationMs: Date.now() - itemStartedAt,
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
          durationMs: Date.now() - itemStartedAt,
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
          || !['active', 'error'].includes(accountStatus(afterTest))
          || schedulableBefore !== false) {
        const error = new Error('测试后账号状态已变化或不允许自动启用调度');
        error.code = 'ACCOUNT_TEST_STATE_CHANGED';
        throw error;
      }

      assertAuditLogCheckpoint(logger, 'account_test.scheduler_enable_checkpoint', {
        jobId,
        actor,
        accountId: id,
        expectedSchedulable: true,
      });
      throwIfJobInterrupted(signal);
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
        // A pre-dispatch interruption is safe: no scheduler write occurred.
        // Once dispatched, however, retrying or rolling back an unconfirmed
        // enable could race the original write, so persist it for reconciliation.
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
            { signal, logger, jobId, actor },
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
          durationMs: Date.now() - itemStartedAt,
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
        durationMs: Date.now() - itemStartedAt,
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
      let reconciliationError = writeRequiresReconciliation(error)
        ? schedulerReconciliationError(error)
        : null;
      if (!reconciliationError
          && testSuccessKnown
          && !recoveryMutation) {
        reconciliationError = accountTestReconciliationError(
          error,
          error?.code === 'JOB_INTERRUPTED' || signal?.aborted
            ? 'post_test_interrupted'
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
            { signal, logger, jobId, actor },
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
        const scope = reconciliationError.reconciliationScope === 'test'
          ? 'test'
          : 'scheduler';
        const testOutcomeUnknown = scope === 'test'
          && reconciliationError.testOutcomeUnknown === true;
        const reconciledTestSuccess = reconciliationError.testSuccessKnown === true
          && typeof reconciliationError.testSuccess === 'boolean'
          ? reconciliationError.testSuccess
          : testSucceeded;
        const causeCode = typeof reconciliationError.code === 'string'
          && /^[A-Z0-9_]{1,96}$/.test(reconciliationError.code)
          ? reconciliationError.code
          : null;
        const result = {
          accountId: id,
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
          writeOutcomeUnknown: reconciliationError.writeOutcomeUnknown === true,
          testOutcomeUnknown,
          reconciliationScope: scope,
          reconciliationReason: normalizedReconciliationReason(
            reconciliationError.reconciliationReason
              || reconciliationError.writeOutcomeReason,
          ),
          statusBefore,
          statusAfter: null,
          statusAfterKnown: false,
          durationMs: Date.now() - itemStartedAt,
        };
        results.push(result);
        await auditResult(db, logger, result, actor, jobId, normalizedModelId);
        writeLog(logger, 'error', scope === 'test'
          ? 'account_test.test_reconciliation_required'
          : 'account_test.scheduler_reconciliation_required', {
          jobId,
          actor,
          accountId: id,
          accountName: account?.name || null,
          code: causeCode,
          reconciliationScope: scope,
          reconciliationReason: result.reconciliationReason,
          durationMs: result.durationMs,
        });
        reconciliationStopIndex = itemIndex;
        break;
      }
      // Cancellation is a job-level terminal outcome when no scheduler state
      // is ambiguous. A confirmed mutation that could not be safely rolled
      // back has already been converted into a persisted reconciliation result.
      if (error?.code === 'JOB_INTERRUPTED' || signal?.aborted) {
        throwIfJobInterrupted(signal);
        throw error;
      }
      let afterFailure = null;
      try {
        afterFailure = await client.getAccount(id, { signal });
      } catch (readError) {
        if (readError?.code === 'JOB_INTERRUPTED' || signal?.aborted) {
          throwIfJobInterrupted(signal);
          throw readError;
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
        testSuccess: testSucceeded,
        enabled: afterFailureOwned ? afterFailure.schedulable === true : null,
        enabledKnown: afterFailureOwned,
        statusBefore,
        statusAfter: afterFailureOwned ? afterFailure.status || null : null,
        statusAfterKnown: afterFailureOwned,
        durationMs: Date.now() - itemStartedAt,
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
        durationMs: 0,
      };
      results.push(result);
      await auditResult(db, logger, result, actor, jobId, normalizedModelId);
    }
  }

  const succeeded = results.filter((item) => item.status === 'succeeded').length;
  const failed = results.filter((item) => item.status === 'failed').length;
  const skipped = results.filter((item) => item.status === 'skipped').length;
  const reconciliationCount = results.filter(
    (item) => item.requiresReconciliation === true,
  ).length;
  const notAttemptedCount = results.filter(
    (item) => item.code === 'account_test_not_attempted_reconciliation',
  ).length;
  const result = {
    model: normalizedModelId || null,
    requested: accountIds.length,
    succeeded,
    failed,
    skipped,
    requiresReconciliation: reconciliationCount > 0,
    reconciliationCount,
    notAttemptedCount,
    durationMs: Date.now() - startedAt,
    results,
  };
  writeLog(logger, failed > 0 ? 'warn' : 'info', 'account_test.completed', {
    jobId,
    actor,
    requested: result.requested,
    succeeded,
    failed,
    skipped,
    requiresReconciliation: result.requiresReconciliation,
    reconciliationCount,
    notAttemptedCount,
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
