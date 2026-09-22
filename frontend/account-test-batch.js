(function exposeAccountTestBatch(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PanelAccountTestBatch = api;
}(globalThis, function createAccountTestBatch() {
  'use strict';

  const MAXIMUM_TARGETS = 1000;
  const MAXIMUM_BATCH_SIZE = 100;
  const REVISION = /^account-test-v1\.[A-Za-z0-9_-]{43}$/;
  const JOB_ID = /^job_[a-f0-9]{24}$/;
  const JOB_STATUSES = new Set(['queued', 'running', 'succeeded', 'partial', 'failed', 'interrupted']);
  const ACCOUNT_STATUSES = new Set(['active', 'inactive', 'disabled', 'error']);
  let running = false;

  function fail(code, message) {
    const error = new Error(message);
    error.code = 'ACCOUNT_TEST_BATCH_' + code;
    throw error;
  }

  function object(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function accountId(value) {
    return Number.isSafeInteger(value) && value > 0;
  }

  function assertNotAborted(signal) {
    if (signal?.aborted) {
      fail('ABORTED', '已停止后续批次；已经提交的任务不会被取消，请核对任务清单。');
    }
  }

  // Callers own networking and idempotency. An abort only stops this local
  // coordinator; it never sends a cancellation request for an accepted job.
  async function boundary(callback, argument, signal, code, message) {
    assertNotAborted(signal);
    let removeAbort = () => {};
    const aborted = new Promise((resolve, reject) => {
      if (!signal) return;
      const listener = () => {
        try { assertNotAborted(signal); } catch (error) { reject(error); }
      };
      signal.addEventListener('abort', listener, { once: true });
      removeAbort = () => signal.removeEventListener('abort', listener);
    });
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => {
          assertNotAborted(signal);
          return callback(argument);
        }),
        aborted,
      ]);
      assertNotAborted(signal);
      return result;
    } catch (error) {
      assertNotAborted(signal);
      // Do not echo adapter/network diagnostics: they may contain credentials
      // or arbitrary remote account text. Preserve only our own static code.
      fail(code, message);
    } finally {
      removeAbort();
    }
  }

  function normalizeOptions(options) {
    if (!object(options)) fail('OPTIONS_INVALID', '账号分批测试配置无效。');
    const maximumTargets = options.maximumTargets ?? MAXIMUM_TARGETS;
    const batchSize = options.batchSize ?? MAXIMUM_BATCH_SIZE;
    if (!Number.isSafeInteger(maximumTargets) || maximumTargets < 1
        || maximumTargets > MAXIMUM_TARGETS
        || !Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > MAXIMUM_BATCH_SIZE) {
      fail('LIMIT_INVALID', '账号分批测试总量最多 1000，每批最多 100。');
    }
    if (!Array.isArray(options.targets) || options.targets.length === 0
        || options.targets.length > maximumTargets) {
      fail('TARGET_LIMIT', '所选账号数量为空或超过本次分批测试上限。');
    }
    const seen = new Set();
    const targets = options.targets.map((target) => {
      if (!object(target) || Object.keys(target).length !== 2
          || !Object.hasOwn(target, 'accountId') || !Object.hasOwn(target, 'targetRevision')
          || !accountId(target.accountId) || typeof target.targetRevision !== 'string'
          || !REVISION.test(target.targetRevision)) {
        fail('TARGET_INVALID', '所选账号缺少有效 ID 或当前快照凭证，请重新选择。');
      }
      if (seen.has(target.accountId)) fail('TARGET_DUPLICATE', '不能重复选择同一 Sub2API 账号 ID。');
      seen.add(target.accountId);
      return Object.freeze({ accountId: target.accountId, targetRevision: target.targetRevision });
    });
    if (typeof options.modelId !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(options.modelId)) {
      fail('MODEL_INVALID', '请选择有效的账号测试模型。');
    }
    for (const name of ['loadInventory', 'loadSnapshot', 'submitBatch', 'waitForTerminal']) {
      if (typeof options[name] !== 'function') fail('OPTIONS_INVALID', '缺少账号分批测试接口。');
    }
    if (options.onProgress !== undefined && typeof options.onProgress !== 'function') {
      fail('OPTIONS_INVALID', '账号分批测试进度接口无效。');
    }
    if (options.signal !== undefined && (!object(options.signal)
        || typeof options.signal.aborted !== 'boolean'
        || typeof options.signal.addEventListener !== 'function'
        || typeof options.signal.removeEventListener !== 'function')) {
      fail('OPTIONS_INVALID', '账号分批测试取消信号无效。');
    }
    return { ...options, targets: Object.freeze(targets), maximumTargets, batchSize };
  }

  function assertInventory(inventory) {
    if (!object(inventory) || !Array.isArray(inventory.jobs)
        || inventory.jobs.length > 1000
        || inventory.jobs.some((job) => !object(job) || !JOB_STATUSES.has(job.status))) {
      fail('INVENTORY_INVALID', '后台任务清单无效，已停止后续测试。');
    }
    for (const field of ['activeJobs', 'reconciliationHolds']) {
      const listing = inventory[field];
      if (!object(listing) || !Number.isSafeInteger(listing.total) || listing.total < 0
          || !Number.isSafeInteger(listing.returned) || listing.returned < 0
          || listing.total !== listing.returned || listing.truncated !== false) {
        fail('INVENTORY_INCOMPLETE', '后台任务或待对账清单不完整，已停止后续测试。');
      }
    }
    const active = inventory.jobs.filter((job) => ['queued', 'running'].includes(job.status));
    const holds = inventory.jobs.filter((job) => (
      job.reconciliationHold === true || job.result?.reconciliationHold === true
    ));
    if (inventory.activeJobs.returned !== active.length
        || inventory.reconciliationHolds.returned !== holds.length) {
      fail('INVENTORY_INCOMPLETE', '后台任务清单与完整性统计不一致，已停止后续测试。');
    }
    if (active.length > 0 || holds.length > 0) {
      fail('INVENTORY_BLOCKED', '后台仍有活动任务或待人工对账项，已停止后续测试。');
    }
  }

  function assertSnapshot(snapshot, remaining) {
    if (!object(snapshot) || snapshot.readOnly !== false
        || snapshot.sub2api?.readStatus !== 'ok' || snapshot.sub2api?.apiError
        || snapshot.diff?.comparisonStatus !== 'complete' || !Array.isArray(snapshot.rows)) {
      fail('SNAPSHOT_UNAVAILABLE', '当前快照不可写或 Sub2API 未完整读取，已停止后续测试。');
    }
    const approved = new Map(remaining.map((target) => [target.accountId, target.targetRevision]));
    const found = new Set();
    for (const row of snapshot.rows) {
      if (!approved.has(row?.accountId)) continue;
      if (row.platform !== 'openai' || row.type !== 'oauth'
          || !ACCOUNT_STATUSES.has(row.status) || row.accountTestEligible === false
          || typeof row.targetRevision !== 'string' || !REVISION.test(row.targetRevision)) {
        fail('TARGET_INELIGIBLE', '尚未执行的所选账号已不具备测试资格，请重新核对并确认。');
      }
      if (row.targetRevision !== approved.get(row.accountId)) {
        fail('TARGET_CHANGED', '尚未执行的所选账号已变化，已停止；请刷新并重新确认，不会自动替换目标。');
      }
      found.add(row.accountId);
    }
    if (found.size !== approved.size) {
      fail('TARGET_MISSING', '尚未执行的所选账号已不在当前快照中，已停止后续测试。');
    }
  }

  function exactAccountIds(actual, expected) {
    if (!Array.isArray(actual) || actual.length !== expected.length
        || actual.some((id) => !accountId(id))) return false;
    const ids = new Set(actual);
    return ids.size === actual.length && expected.every((id) => ids.has(id));
  }

  function hasUncertainOutcome(value) {
    if (!object(value)) return false;
    for (const field of ['reconciliationHold', 'requiresReconciliation', 'writeOutcomeUnknown',
      'schedulerStateUnknown', 'outcomeUnknown', 'doNotRetry']) {
      if (Object.hasOwn(value, field) && value[field] !== false) return true;
    }
    return value.retryAllowed === false || value.attempted === false
      || value.outcome === 'unknown' || value.outcome === 'not_attempted'
      || value.executionOutcome === 'unknown' || value.status === 'unknown'
      || Boolean(value.reconciliationReason) || Boolean(value.reconciliationScope);
  }

  function assertSubmission(body, ids) {
    if (!object(body) || typeof body.jobId !== 'string' || !JOB_ID.test(body.jobId)
        || body.status !== 'queued' || !Array.isArray(body.rejected) || body.rejected.length !== 0
        || !exactAccountIds(body.accountIds, ids) || hasUncertainOutcome(body)) {
      fail('SUBMISSION_INCOMPLETE', '本批未被完整准确接受；已停止后续提交，请核对可能已创建的任务。');
    }
  }

  function assertTerminal(job, jobId, ids, modelId) {
    const result = job?.result;
    if (!object(job) || job.id !== jobId || job.type !== 'account_test'
        || job.status !== 'succeeded' || job.error || hasUncertainOutcome(job)
        || !object(job.payload) || !exactAccountIds(job.payload.accountIds, ids)
        || job.payload.modelId !== modelId || !object(result)
        || result.jobStatus !== 'succeeded' || result.model !== modelId
        || result.requiresReconciliation !== false || hasUncertainOutcome(result)
        || result.executionComplete !== true || result.executionStarted !== true
        || result.stopReason !== null || result.requested !== ids.length
        || result.succeeded !== ids.length || result.attemptedCount !== ids.length
        || ['failed', 'skipped', 'reconciliationCount', 'notAttemptedCount',
          'reconciliationNotAttemptedCount', 'timeoutCount', 'interruptedCount']
          .some((field) => result[field] !== 0)
        || !Array.isArray(result.results)
        || !exactAccountIds(result.results.map((item) => item?.accountId), ids)
        || result.results.some((item) => !object(item) || item.status !== 'succeeded'
          || item.testSuccess !== true || hasUncertainOutcome(item)
          || !['account_test_succeeded', 'account_recovered'].includes(item.code))) {
      fail('RESULT_UNCONFIRMED', '本批没有获得逐项完整成功结果，已停止后续测试；请查看任务详情。');
    }
  }

  // The caller obtains one explicit confirmation for these exact targets and
  // model before calling run(). Nothing is persisted or resumed automatically.
  async function run(rawOptions) {
    const options = normalizeOptions(rawOptions);
    if (running) fail('ALREADY_RUNNING', '当前页面已有账号分批测试正在执行。');
    running = true;
    const { targets, modelId, batchSize, signal } = options;
    const batchCount = Math.ceil(targets.length / batchSize);
    const submittedJobIds = [];
    let completed = 0;
    let batchIndex = 0;
    let jobId;
    const progress = async (phase) => {
      if (!options.onProgress) return;
      const event = Object.freeze({ phase, batchIndex, batchCount, total: targets.length,
        completed, ...(jobId ? { jobId } : {}) });
      await boundary(options.onProgress, event, signal, 'PROGRESS_FAILED', '分批测试界面状态无法确认，已停止后续提交。');
    };
    try {
      for (let offset = 0; offset < targets.length; offset += batchSize) {
        batchIndex += 1;
        jobId = undefined;
        assertNotAborted(signal);
        await progress('checking');
        const inventory = await boundary(options.loadInventory, { signal }, signal,
          'INVENTORY_UNAVAILABLE', '后台任务清单读取失败，已停止后续测试。');
        assertInventory(inventory);
        const snapshot = await boundary(options.loadSnapshot, { signal }, signal,
          'SNAPSHOT_UNAVAILABLE', '账号快照读取失败，已停止后续测试。');
        assertSnapshot(snapshot, targets.slice(offset));
        const batch = Object.freeze(targets.slice(offset, offset + batchSize));
        const ids = Object.freeze(batch.map((target) => target.accountId));
        await progress('submitting');
        const body = await boundary(options.submitBatch, Object.freeze({ targets: batch, modelId,
          signal, batchIndex, batchCount }), signal, 'SUBMISSION_UNCONFIRMED',
        '本批提交结果无法确认，已停止后续提交；请核对后台任务，勿直接重新测试。');
        if (typeof body?.jobId === 'string' && JOB_ID.test(body.jobId)) {
          jobId = body.jobId;
          if (submittedJobIds.includes(jobId)) {
            fail('JOB_REUSED', '不同测试批次返回同一任务 ID，已停止后续提交。');
          }
          submittedJobIds.push(jobId);
        }
        assertSubmission(body, ids);
        await progress('submitted');
        const job = await boundary(options.waitForTerminal, Object.freeze({ jobId, accountIds: ids,
          signal, batchIndex, batchCount }), signal, 'RESULT_UNAVAILABLE',
        '本批任务结果无法确认，已停止后续测试；已提交任务可能仍在执行。');
        assertTerminal(job, jobId, ids, modelId);
        completed += batch.length;
        await progress('completed');
      }
      return Object.freeze({ status: 'succeeded', requested: targets.length, completed,
        batches: batchCount, jobIds: Object.freeze([...submittedJobIds]) });
    } catch (error) {
      error.completed = completed;
      error.submittedJobIds = Object.freeze([...submittedJobIds]);
      throw error;
    } finally {
      running = false;
    }
  }

  return Object.freeze({ run, MAXIMUM_TARGETS, MAXIMUM_BATCH_SIZE });
}));
