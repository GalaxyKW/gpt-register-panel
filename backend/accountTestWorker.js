const crypto = require('node:crypto');

const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const { getAccountAvailability } = require('./accountAvailability');
const { accountKeys, hasStrongIdentity, identitiesStronglyCompatible } = require('./diff');
const { normalizeIdentityValue } = require('./lib/token');
const { redactText } = require('./logger');
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
  const rawIds = body.accountIds ?? body.account_ids;
  if (!Array.isArray(rawIds) || rawIds.length === 0 || rawIds.length > 100) {
    const error = new Error('至少选择一个已导入的上游账号，单次最多测试 100 个账号');
    error.code = 'ACCOUNT_TEST_SELECTION_INVALID';
    throw error;
  }
  const accountIds = [];
  const seen = new Set();
  for (const value of rawIds) {
    const id = normalizePositiveAccountId(value);
    if (!id) {
      const error = new Error('accountIds 必须是正整数 ID 数组');
      error.code = 'ACCOUNT_TEST_ACCOUNT_ID_INVALID';
      throw error;
    }
    if (!seen.has(id)) {
      seen.add(id);
      accountIds.push(id);
    }
  }
  if (accountIds.length === 0) {
    const error = new Error('没有有效的账号 ID');
    error.code = 'ACCOUNT_TEST_SELECTION_INVALID';
    throw error;
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
    accountIds,
    modelId: normalizeAccountTestModelId(modelValue),
    prompt: promptValue.trim(),
  };
}

function accountStatus(account) {
  return String(account?.status || '').trim().toLowerCase();
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
  const status = accountStatus(account);
  const statusKnown = account.statusKnown === undefined
    ? ['active', 'disabled', 'error'].includes(status)
    : account.statusKnown === true;
  const schedulableKnown = account.schedulableKnown === undefined
    ? typeof account.schedulable === 'boolean'
    : account.schedulableKnown === true && typeof account.schedulable === 'boolean';
  if (!statusKnown || !schedulableKnown) return 'account_state_unknown';
  if (!hasStrongIdentity(accountIdentityKeys(account))) return 'account_identity_missing';
  return null;
}

function accountTestTargetBaseline(account) {
  const accountId = normalizePositiveAccountId(account?.id);
  if (!accountId || accountTestTargetError(account)) return null;
  const strongIdentityKeys = canonicalStrongIdentityKeys(account);
  if (strongIdentityKeys.length === 0) return null;
  return {
    accountId,
    // Persist only a one-way digest. Raw account/user IDs and credentials do
    // not need to become part of the job history exposed by the jobs API.
    identityDigest: crypto.createHash('sha256')
      .update(JSON.stringify(strongIdentityKeys))
      .digest('hex'),
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
    if (!accountId || !expectedIds.has(accountId) || baselines.has(accountId)
        || !/^[a-f0-9]{64}$/.test(identityDigest)) {
      const error = new Error('账号测试任务的目标身份基线无效');
      error.code = 'ACCOUNT_TEST_BASELINE_INVALID';
      throw error;
    }
    baselines.set(accountId, { accountId, identityDigest });
  }
  if (baselines.size !== expectedIds.size) {
    const error = new Error('账号测试任务的目标身份基线不完整');
    error.code = 'ACCOUNT_TEST_BASELINE_INVALID';
    throw error;
  }
  return baselines;
}

function matchesAccountTestTargetBaseline(baseline, account) {
  const actual = accountTestTargetBaseline(account);
  if (!baseline || !actual || actual.accountId !== baseline.accountId) return false;
  const expectedDigest = Buffer.from(baseline.identityDigest, 'hex');
  const actualDigest = Buffer.from(actual.identityDigest, 'hex');
  return expectedDigest.length === actualDigest.length
    && crypto.timingSafeEqual(expectedDigest, actualDigest);
}

function sameAccountTarget(expected, actual) {
  return !accountTestTargetError(expected)
    && !accountTestTargetError(actual)
    && Number(expected.id) === Number(actual.id)
    && identitiesStronglyCompatible(accountIdentityKeys(expected), accountIdentityKeys(actual))
    && JSON.stringify(canonicalStrongIdentityKeys(expected))
      === JSON.stringify(canonicalStrongIdentityKeys(actual));
}

function accountStateVersion(account) {
  return JSON.stringify({
    id: account?.id ?? null,
    status: accountStatus(account),
    schedulable: account?.schedulable,
    identityKeys: [...accountIdentityKeys(account)].sort(),
    accessFingerprint: account?.tokenFingerprints?.access || null,
    tempUnschedulableUntil: account?.tempUnschedulableUntil || null,
    rateLimitResetAt: account?.rateLimitResetAt || null,
    overloadUntil: account?.overloadUntil || null,
    expiresAt: account?.expiresAt || null,
    autoPauseOnExpired: account?.autoPauseOnExpired,
  });
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
        testSuccess: result.testSuccess === true,
        enabled: result.enabled === true,
        statusBefore: result.statusBefore || null,
        statusAfter: result.statusAfter || null,
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

async function rollbackOwnedSchedulableMutation(client, id, mutation) {
  if (!mutation?.after || mutation.original === mutation.written) {
    return { attempted: false, succeeded: false, state: null, reason: 'rollback_not_owned' };
  }
  let current;
  try { current = await client.getAccount(id); } catch {
    return { attempted: false, succeeded: false, state: null, reason: 'rollback_state_unavailable' };
  }
  if (!sameAccountTarget(mutation.after, current)
      || accountStateVersion(current) !== accountStateVersion(mutation.after)
      || current.schedulable !== mutation.written) {
    return { attempted: false, succeeded: false, state: current, reason: 'rollback_state_changed' };
  }
  const writeResponse = await client.setSchedulable(id, mutation.original);
  if (!writeResponse
      || !sameAccountTarget(mutation.after, writeResponse)
      || writeResponse.schedulable !== mutation.original) {
    return {
      attempted: true,
      succeeded: false,
      state: writeResponse || current,
      reason: 'rollback_response_mismatch',
    };
  }
  const verified = await client.getAccount(id);
  return {
    attempted: true,
    succeeded: sameAccountTarget(writeResponse, verified)
      && verified.schedulable === mutation.original,
    state: verified,
    reason: null,
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
  await db?.updateJob(jobId, { status: 'running', startedAt: new Date().toISOString() });
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
    signal,
  });
  const results = [];
  for (const id of accountIds) {
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
    let statusBefore = account?.status || null;
    let schedulableBefore = typeof account?.schedulable === 'boolean' ? account.schedulable : null;
    let recoveryAttempted = false;
    let recoveryMutation = null;
    let testSucceeded = false;
    try {
      if (listedAccount && !matchesAccountTestTargetBaseline(submittedBaseline, listedAccount)) {
        const error = new Error('账号强身份自测试任务提交后已变化，拒绝测试复用的数字 ID');
        error.code = 'ACCOUNT_TEST_SUBMITTED_TARGET_CHANGED';
        throw error;
      }
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
      if (targetError
          || !matchesAccountTestTargetBaseline(submittedBaseline, current)
          || (listedAccount && !sameAccountTarget(listedAccount, current))) {
        const error = new Error('账号身份、类型或状态在测试前无法安全确认');
        error.code = targetError || 'ACCOUNT_TEST_SUBMITTED_TARGET_CHANGED';
        throw error;
      }
      account = current;
      statusBefore = current.status || statusBefore;
      schedulableBefore = current.schedulable;
      const shouldRecover = accountStatus(account) === 'error';

      const test = await client.testAccount(id, {
        modelId: normalizedModelId,
        prompt,
        timeoutMs: Math.max(1, deadline - Date.now()),
        signal,
      });
      // A successful response can race SIGTERM. Do not start any new reads or
      // scheduler mutation after the job has been cancelled.
      throwIfJobInterrupted(signal);
      if (!test.success) {
        let afterFailure = account;
        try { afterFailure = await client.getAccount(id); } catch {}
        const result = {
          accountId: id,
          accountName: account.name || null,
          status: 'failed',
          code: 'upstream_test_failed',
          message: test.message || '常规请求失败，账号保持当前状态',
          testSuccess: false,
          statusBefore,
          enabled: sameAccountTarget(account, afterFailure) ? afterFailure.schedulable === true : false,
          statusAfter: afterFailure?.status || account.status || statusBefore,
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
      testSucceeded = true;

      // Sub2API's test endpoint already clears recoverable runtime state. The
      // panel only changes schedulable for accounts that started in error;
      // healthy or intentionally disabled accounts must keep their setting.
      if (!shouldRecover) {
        const after = await client.getAccount(id, { signal });
        const targetUnchanged = sameAccountTarget(account, after);
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
            enabled: targetUnchanged && after.schedulable === true,
            statusBefore,
            statusAfter: after?.status || null,
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
      if (!sameAccountTarget(account, afterTest)) {
        const error = new Error('测试后账号身份或结构已变化，拒绝修改调度设置');
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

      recoveryAttempted = true;
      recoveryMutation = {
        original: schedulableBefore,
        written: true,
        before: afterTest,
        after: null,
      };
      throwIfJobInterrupted(signal);
      const writeResponse = await client.setSchedulable(id, true);
      if (!writeResponse
          || typeof writeResponse !== 'object'
          || !sameAccountTarget(afterTest, writeResponse)
          || writeResponse.schedulable !== true) {
        // The write may have raced a delete/recreate. Its response is not
        // an account we can safely treat as our mutation or roll back.
        recoveryMutation = null;
        const error = new Error('启用调度响应与预检账号不一致');
        error.code = 'ACCOUNT_TEST_TARGET_CHANGED';
        throw error;
      }
      recoveryMutation.after = writeResponse;
      const after = await client.getAccount(id);
      if (!sameAccountTarget(afterTest, after)) {
        const error = new Error('启用调度后账号身份或结构已变化');
        error.code = 'ACCOUNT_TEST_TARGET_CHANGED';
        throw error;
      }
      if (accountStateVersion(after) !== accountStateVersion(writeResponse)) {
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
        let rollbackState = after;
        let rollbackSucceeded = false;
        let rollbackReason = null;
        try {
          const rollback = await rollbackOwnedSchedulableMutation(client, id, recoveryMutation);
          rollbackState = rollback.state || rollbackState;
          rollbackSucceeded = rollback.succeeded;
          rollbackReason = rollback.reason;
        } catch (rollbackError) {
          rollbackReason = safeErrorMessage(rollbackError);
          writeLog(logger, 'error', 'account_test.recovery_rollback_failed', {
            jobId,
            actor,
            accountId: id,
            error: rollbackReason,
          });
        }
        recoveryMutation = null;
        const result = {
          accountId: id,
          accountName: account.name || null,
          status: 'failed',
          code: 'account_recovery_not_confirmed',
          message: '测试成功，但恢复状态或启用调度未确认，未标记为成功',
          testSuccess: true,
          enabled: sameAccountTarget(account, rollbackState) && rollbackState.schedulable === true,
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
          rollbackSucceeded,
          rollbackReason,
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
      if (recoveryMutation) {
        try {
          const rollback = await rollbackOwnedSchedulableMutation(client, id, recoveryMutation);
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
          }
        } catch (rollbackError) {
          writeLog(logger, 'error', 'account_test.recovery_rollback_failed', {
            jobId,
            actor,
            accountId: id,
            error: safeErrorMessage(rollbackError),
          });
        }
      }
      // Cancellation is a job-level terminal outcome, not a failed account
      // test. Any owned scheduler mutation has been rolled back above before
      // the interruption escapes to the observer.
      if (error?.code === 'JOB_INTERRUPTED' || signal?.aborted) {
        throwIfJobInterrupted(signal);
        throw error;
      }
      let afterFailure = account;
      try { afterFailure = await client.getAccount(id); } catch {}
      const result = {
        accountId: id,
        accountName: account?.name || null,
        status: 'failed',
        code: recoveryAttempted ? 'account_recovery_failed' : 'account_test_failed',
        message: safeErrorMessage(error),
        testSuccess: testSucceeded,
        enabled: sameAccountTarget(account, afterFailure) && afterFailure.schedulable === true,
        statusBefore,
        statusAfter: afterFailure?.status || account?.status || statusBefore,
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

  const succeeded = results.filter((item) => item.status === 'succeeded').length;
  const failed = results.filter((item) => item.status === 'failed').length;
  const skipped = results.filter((item) => item.status === 'skipped').length;
  const result = {
    model: normalizedModelId || null,
    requested: accountIds.length,
    succeeded,
    failed,
    skipped,
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
  return withControlPlaneLock(() => runAccountTestJobNow(args));
}

module.exports = {
  accountTestTargetBaseline,
  activeAccountTestJobs,
  classifyAccountTestTargets,
  normalizeAccountTestModelId,
  normalizeAccountTestRequest,
  resultForRejected,
  runAccountTestJob,
  runAccountTestJobNow,
  safeErrorMessage,
  withAccountTestSubmissionLock,
};
