const TERMINAL_JOB_STATUSES = new Set(['succeeded', 'partial', 'failed', 'interrupted']);
const MAX_ADMISSION_DISPATCH_JOBS = 100;
const FOREGROUND_ADMISSION_RECOVERY_ATTEMPTS = 4;
const BACKGROUND_ADMISSION_RECOVERY_ATTEMPTS = 8;

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function detachedDelay(milliseconds) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref?.();
  });
}

function interruptedJobError(message = '面板正在停止，任务已中断') {
  const error = new Error(message);
  error.code = 'JOB_INTERRUPTED';
  return error;
}

function throwIfJobInterrupted(signal) {
  if (!signal?.aborted) return;
  throw interruptedJobError();
}

function safeAdmissionFailureCode(value, fallback = 'JOB_ADMISSION_DISPATCH_FAILED') {
  let code = '';
  try { code = String(value || '').trim().toUpperCase(); } catch {}
  return /^[A-Z0-9_]{1,96}$/.test(code) ? code : fallback;
}

function admissionDispatchError(code, message, fields = {}) {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, fields);
  return error;
}

function recordHasTrackedPromise(record) {
  return Boolean(record?.promise && typeof record.promise.then === 'function');
}

function createAdmissionDispatchGuard({ db, jobManager, onRetry, onInterrupted } = {}) {
  const committed = new Map();
  let finalized = false;
  let backgroundRecoveryScheduled = false;

  function stateFor(job) {
    const id = typeof job?.id === 'string' ? job.id.trim() : '';
    if (!id || !committed.has(id)) {
      throw admissionDispatchError(
        'JOB_ADMISSION_TRACKING_INVALID',
        '任务派发守卫未找到已提交的任务',
      );
    }
    return committed.get(id);
  }

  function recordCommitted(createdJobs) {
    if (finalized) {
      throw admissionDispatchError(
        'JOB_ADMISSION_TRACKING_INVALID',
        '任务派发守卫已经结束，拒绝追加任务',
      );
    }
    if (!Array.isArray(createdJobs)
        || committed.size + createdJobs.length > MAX_ADMISSION_DISPATCH_JOBS) {
      throw admissionDispatchError(
        'JOB_ADMISSION_TRACKING_INVALID',
        '已提交任务清单超过派发守卫的安全上限',
      );
    }
    const pendingBatch = [];
    const pendingIds = new Set();
    for (const item of createdJobs) {
      const job = item?.job || item;
      const id = typeof job?.id === 'string' ? job.id.trim() : '';
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)
          || committed.has(id)
          || pendingIds.has(id)) {
        throw admissionDispatchError(
          'JOB_ADMISSION_TRACKING_INVALID',
          '已提交任务清单包含无效或重复的任务标识',
        );
      }
      pendingIds.add(id);
      pendingBatch.push({ id, job });
    }
    // Do not leave a partially tracked durable batch when a later item is
    // malformed. Validation above is deliberately completed before mutation.
    for (const { id, job } of pendingBatch) {
      committed.set(id, {
        id,
        job,
        record: null,
        observerRegistered: false,
        interrupted: false,
      });
    }
  }

  function dispatch(job, type, actor, registerObserver) {
    if (typeof registerObserver !== 'function') {
      throw admissionDispatchError(
        'JOB_ADMISSION_TRACKING_INVALID',
        '任务派发缺少 observer 注册器',
      );
    }
    const state = stateFor(job);
    if (state.observerRegistered || state.record) {
      throw admissionDispatchError(
        'JOB_ADMISSION_TRACKING_INVALID',
        '同一任务被重复派发',
      );
    }
    const record = jobManager?.begin(job, type, actor);
    if (!record) {
      throw admissionDispatchError(
        'JOB_ADMISSION_TRACKING_INVALID',
        '后台任务管理器未返回任务记录',
      );
    }
    state.record = record;
    try {
      const observation = registerObserver(record);
      if (!recordHasTrackedPromise(record)) {
        throw admissionDispatchError(
          'JOB_ADMISSION_OBSERVER_UNTRACKED',
          'observer 注册器返回时未通过后台任务管理器跟踪执行结果',
        );
      }
      state.observerRegistered = true;
      return observation;
    } catch (error) {
      // A custom observer may have registered work and then thrown. A standard
      // manager exposes that fact through record.promise; never relabel such a
      // task as not-started.
      if (recordHasTrackedPromise(record)) state.observerRegistered = true;
      else {
        // Standard observers defer worker execution to a promise turn and
        // check this signal before crossing their mutation boundary.
        try { record.controller?.abort(interruptedJobError()); } catch {}
      }
      throw error;
    }
  }

  function pendingStates() {
    return [...committed.values()].filter((state) => (
      !state.interrupted && !state.observerRegistered && !recordHasTrackedPromise(state.record)
    ));
  }

  function applyRecoveryResult(result, pending, ids, code) {
    const rawInterruptedIds = Array.isArray(result?.interrupted) ? result.interrupted : [];
    const skippedItems = Array.isArray(result?.skipped) ? result.skipped : [];
    const safeSkippedStatuses = new Set([
      'running',
      'succeeded',
      'partial',
      'failed',
      'interrupted',
    ]);
    const skippedIds = skippedItems.map((item) => item?.id);
    const resultInvalid = rawInterruptedIds.some((id) => !ids.includes(id))
      || new Set(rawInterruptedIds).size !== rawInterruptedIds.length
      || new Set(skippedIds).size !== skippedIds.length
      || skippedIds.some((id) => rawInterruptedIds.includes(id))
      || skippedItems.some((item) => (
        !ids.includes(item?.id)
        || !safeSkippedStatuses.has(item?.status)
        || typeof item?.safeNotStarted !== 'boolean'
        || (item.safeNotStarted && item.status !== 'interrupted')
      ));
    if (resultInvalid) {
      throw admissionDispatchError(
        'JOB_ADMISSION_RECOVERY_INVALID',
        '任务派发恢复结果无效；保护键已保留',
      );
    }
    const interruptedIds = rawInterruptedIds;
    const accounted = new Set([...interruptedIds, ...skippedIds]);
    if (accounted.size !== ids.length) {
      throw admissionDispatchError(
        'JOB_ADMISSION_RECOVERY_INVALID',
        '任务派发恢复结果不完整；保护键已保留',
      );
    }
    const safelyInterrupted = new Set([
      ...interruptedIds,
      ...skippedItems
        .filter((item) => item.safeNotStarted === true)
        .map((item) => item.id),
    ]);
    for (const state of pending) {
      state.interrupted = safelyInterrupted.has(state.id);
    }
    if (safelyInterrupted.size > 0) {
      try {
        onInterrupted?.({ code, jobIds: [...safelyInterrupted], result });
      } catch {}
    }
    const unsafeSkipped = skippedItems.filter((item) => item.safeNotStarted !== true);
    if (unsafeSkipped.length > 0) {
      // A running or previously-started terminal row proves that this guard can
      // no longer certify the operation as undispatched. Keep the write fuse
      // engaged instead of treating a syntactically complete DB reply as a
      // successful admission recovery.
      throw admissionDispatchError(
        'JOB_ADMISSION_RECOVERY_UNCERTAIN',
        '任务派发恢复发现可能已执行的任务；保护键与写入熔断已保留',
      );
    }
    return result;
  }

  async function persistPendingOnce(pending, code) {
    const ids = pending.map((state) => state.id);
    const result = await db.interruptOwnedQueuedJobsBeforeDispatch(ids, { code });
    return applyRecoveryResult(result, pending, ids, code);
  }

  function scheduleBackgroundRecovery(cause) {
    if (backgroundRecoveryScheduled || pendingStates().length === 0) return;
    backgroundRecoveryScheduled = true;
    const code = safeAdmissionFailureCode(cause?.code);
    let releaseAdmissionHold = null;
    try {
      releaseAdmissionHold = jobManager?.holdAdmissions?.({ code }) || null;
    } catch {}
    const recovery = (async () => {
      for (let attempt = 1; attempt <= BACKGROUND_ADMISSION_RECOVERY_ATTEMPTS; attempt += 1) {
        await detachedDelay(Math.min(2000, 50 * (2 ** (attempt - 1))));
        const pending = pendingStates();
        if (pending.length === 0) {
          try { releaseAdmissionHold?.(); } catch {}
          return;
        }
        try {
          await persistPendingOnce(pending, code);
          try { releaseAdmissionHold?.(); } catch {}
          return;
        } catch (error) {
          try {
            onRetry?.(error, FOREGROUND_ADMISSION_RECOVERY_ATTEMPTS + attempt, {
              code,
              jobIds: pending.map((state) => state.id),
              background: true,
            });
          } catch {}
        }
      }
      // Keep the admission hold after bounded recovery is exhausted. Reads
      // remain available, while new mutations fail closed until restart can
      // run normal orphan recovery against the now-dead owner identity.
    })();
    recovery.catch(() => {});
  }

  async function interruptPending(cause) {
    const pending = pendingStates();
    if (pending.length === 0) return { interrupted: [], skipped: [] };
    if (!db || typeof db.interruptOwnedQueuedJobsBeforeDispatch !== 'function') {
      scheduleBackgroundRecovery(cause);
      throw admissionDispatchError(
        'JOB_ADMISSION_RECOVERY_FAILED',
        '任务已入队但派发失败，且安全中断持久化不可用；保护键已保留',
        { retryAllowed: false, doNotRetry: true },
      );
    }
    const code = safeAdmissionFailureCode(cause?.code);
    const ids = pending.map((state) => state.id);
    let lastError;
    for (let attempt = 1; attempt <= FOREGROUND_ADMISSION_RECOVERY_ATTEMPTS; attempt += 1) {
      try {
        return await persistPendingOnce(pending, code);
      } catch (error) {
        lastError = error;
        try { onRetry?.(error, attempt, { code, jobIds: ids }); } catch {}
        if (attempt < FOREGROUND_ADMISSION_RECOVERY_ATTEMPTS) {
          await delay(Math.min(1000, 25 * (3 ** (attempt - 1))));
        }
      }
    }
    scheduleBackgroundRecovery(cause);
    throw admissionDispatchError(
      'JOB_ADMISSION_RECOVERY_FAILED',
      '任务已入队但派发失败，且安全中断未能持久化；保护键已保留',
      {
        admissionFailureCode: code,
        persistenceFailureCode: safeAdmissionFailureCode(lastError?.code, 'JOB_PERSISTENCE_FAILED'),
        retryAllowed: false,
        doNotRetry: true,
      },
    );
  }

  async function run(callback) {
    if (typeof callback !== 'function' || finalized) {
      throw admissionDispatchError(
        'JOB_ADMISSION_TRACKING_INVALID',
        '任务派发守卫调用无效',
      );
    }
    try {
      const result = await callback({ recordCommitted, dispatch });
      if (pendingStates().length > 0) {
        throw admissionDispatchError(
          'JOB_ADMISSION_DISPATCH_INCOMPLETE',
          '已提交任务未全部注册 observer，已安全中断未派发任务',
        );
      }
      finalized = true;
      return result;
    } catch (error) {
      try {
        await interruptPending(error);
      } finally {
        // A record without a tracked promise cannot produce a real worker
        // outcome. Remove it even when persistence failed so a later shutdown
        // can still find the retained queued claim instead of excluding it as
        // an active observer.
        for (const state of committed.values()) {
          if (!state.observerRegistered && !recordHasTrackedPromise(state.record) && state.record) {
            try { jobManager?.abandon?.(state.record); } catch {}
          }
        }
        finalized = true;
      }
      if (committed.size > 0
          && [...committed.values()].every((state) => state.interrupted)) {
        const code = safeAdmissionFailureCode(error?.code);
        throw admissionDispatchError(
          code,
          '任务已持久入队，但未交给执行器；已确认未开始并安全中断',
          {
            blockedBeforeStart: true,
            executionOutcome: 'not_started',
            requiresReconciliation: false,
            retryAllowed: true,
            doNotRetry: false,
            controlPlaneLeaseReleaseFailed:
              error?.controlPlaneLeaseReleaseFailed === true || undefined,
            interruptedJobCount: [...committed.values()]
              .filter((state) => state.interrupted).length,
          },
        );
      }
      throw error;
    }
  }

  return {
    dispatch,
    recordCommitted,
    run,
    get committedCount() { return committed.size; },
    get pendingCount() { return pendingStates().length; },
  };
}

async function updateTerminalJob(db, jobId, patch = {}, options = {}) {
  if (!db || typeof db.updateJob !== 'function') return;
  if (!TERMINAL_JOB_STATUSES.has(patch.status)) {
    const error = new Error('任务终态更新必须提供有效的终态 status');
    error.code = 'JOB_TERMINAL_STATUS_INVALID';
    throw error;
  }
  const attempts = boundedInteger(options.attempts, 4, 1, 6);
  const initialDelayMs = boundedInteger(options.initialDelayMs, 25, 0, 1000);
  const terminalPatch = {
    ...patch,
    // Reuse one timestamp across retries so replaying an update is idempotent.
    finishedAt: patch.finishedAt || new Date().toISOString(),
  };
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const result = await db.updateJob(jobId, terminalPatch);
      const alreadyPersisted = result?.applied === false
        && result?.idempotent === true
        && result?.currentStatus === patch.status;
      if (result?.applied === false && !alreadyPersisted) {
        const error = new Error('任务终态已由其他执行路径写入，拒绝覆盖');
        error.code = 'JOB_TERMINAL_STATUS_CONFLICT';
        error.jobId = jobId;
        error.requestedStatus = patch.status;
        error.currentStatus = result.currentStatus || null;
        throw error;
      }
      return result;
    } catch (error) {
      lastError = error;
      if (attempt >= attempts || [
        'JOB_NOT_FOUND',
        'JOB_STATUS_CONFLICT',
        'JOB_STATUS_INVALID',
        'JOB_STORED_STATUS_INVALID',
        'JOB_TERMINAL_STATUS_CONFLICT',
      ].includes(error?.code)) break;
      if (typeof options.onRetry === 'function') {
        try { options.onRetry(error, attempt); } catch {}
      }
      const waitMs = Math.min(1000, initialDelayMs * (3 ** (attempt - 1)));
      if (waitMs > 0) await delay(waitMs);
    }
  }
  throw lastError;
}

function createBackgroundJobManager({ db } = {}) {
  const active = new Map();
  const pendingAdmissions = new Set();
  const admissionHolds = new Set();
  let shuttingDown = false;
  let admissions = 0;

  function admissionRecoveryPendingError() {
    return admissionDispatchError(
      'JOB_ADMISSION_RECOVERY_FAILED',
      '此前任务的派发恢复仍在进行，新的写任务已被临时阻止',
      { recoveryPending: true, retryAllowed: false, doNotRetry: true },
    );
  }

  function begin(job, type, actor = 'local') {
    if (shuttingDown) throw interruptedJobError();
    if (admissionHolds.size > 0) throw admissionRecoveryPendingError();
    const controller = new AbortController();
    const record = {
      id: String(job?.id || ''),
      type: String(type || job?.type || 'unknown'),
      actor,
      controller,
      promise: null,
    };
    if (!record.id) throw new Error('后台任务缺少 job id');
    active.set(record.id, record);
    return record;
  }

  function track(record, promise) {
    const tracked = Promise.resolve(promise).finally(() => {
      if (active.get(record.id) === record) active.delete(record.id);
    });
    // Observers normally handle their own rejection. Keep a handler attached
    // here too so a shutdown racing observer setup cannot create an unhandled
    // rejection.
    tracked.catch(() => {});
    record.promise = tracked;
    return tracked;
  }

  function abandon(record) {
    if (!record || active.get(record.id) !== record || recordHasTrackedPromise(record)) return false;
    try { record.controller.abort(interruptedJobError()); } catch {}
    active.delete(record.id);
    return true;
  }

  function holdAdmissions() {
    const hold = Object.freeze({});
    admissionHolds.add(hold);
    let released = false;
    return () => {
      if (released) return false;
      released = true;
      return admissionHolds.delete(hold);
    };
  }

  async function withAdmission(callback) {
    if (shuttingDown) throw interruptedJobError();
    if (admissionHolds.size > 0) throw admissionRecoveryPendingError();
    admissions += 1;
    const controller = new AbortController();
    pendingAdmissions.add(controller);
    const signal = controller.signal;
    const operation = Promise.resolve().then(() => {
      throwIfJobInterrupted(signal);
      return callback(signal);
    });
    operation.then(() => {
      admissions -= 1;
      pendingAdmissions.delete(controller);
    }, () => {
      admissions -= 1;
      pendingAdmissions.delete(controller);
    });
    // The HTTP caller should receive a deterministic interruption immediately,
    // while `admissions` continues tracking the underlying callback until it
    // has unwound. This keeps shutdown from closing persistence underneath an
    // admission that was already inside a non-cancellable operation.
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (callbackFn, value) => {
        if (settled) return;
        settled = true;
        try { signal.removeEventListener('abort', onAbort); } catch {}
        callbackFn(value);
      };
      const onAbort = () => finish(reject, interruptedJobError());
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
      operation.then(
        (value) => finish(resolve, value),
        (error) => finish(reject, error),
      );
    });
  }

  async function waitForIdle(timeoutMs) {
    const deadline = Date.now() + Math.max(0, Number(timeoutMs) || 0);
    while ((active.size > 0 || admissions > 0) && Date.now() < deadline) {
      const pending = [...active.values()]
        .filter(recordHasTrackedPromise)
        .map((record) => record.promise);
      const remaining = Math.max(0, deadline - Date.now());
      let timer;
      const waits = [new Promise((resolve) => {
          timer = setTimeout(resolve, Math.min(25, remaining));
      })];
      if (pending.length > 0) waits.push(Promise.allSettled(pending));
      await Promise.race(waits);
      if (timer) clearTimeout(timer);
    }
    return active.size;
  }

  async function shutdown(options = {}) {
    shuttingDown = true;
    const reason = interruptedJobError();
    for (const controller of pendingAdmissions) controller.abort(reason);
    for (const record of active.values()) record.controller.abort(reason);
    // Phase3's TERM + KILL process-tree cleanup has a five-second hard limit.
    // Keep the drain below twelve seconds, leaving the rest of systemd's
    // 45-second stop budget for a contended SQLite lock and final connection
    // closure.
    const timeoutMs = boundedInteger(options.timeoutMs, 10_000, 0, 12_000);
    const remaining = await waitForIdle(timeoutMs);
    // Only a record with a tracked promise has an observer that can still
    // persist the real worker outcome. begin() temporarily registers a record
    // before observer setup; excluding that untracked record would let a
    // shutdown race strand its queued claim if admission recovery also fails.
    const excludedJobIds = [...active.values()]
      .filter(recordHasTrackedPromise)
      .map((record) => record.id);
    const outstandingAdmissions = admissions;
    // A worker still registered here has not finished unwinding and may yet
    // persist its real terminal outcome. Retain its claim until that happens;
    // only owned jobs with no active observer (for example, an admission
    // interrupted between durable creation and begin()) may be interrupted.
    const interrupted = db && typeof db.interruptOwnedActiveJobs === 'function'
      ? await db.interruptOwnedActiveJobs('面板服务停止，任务已安全中断', {
        excludeJobIds: excludedJobIds,
      })
      : [];
    return {
      remaining,
      active: active.size,
      outstandingAdmissions,
      interrupted,
    };
  }

  return {
    abandon,
    begin,
    get activeCount() { return active.size; },
    get admissionCount() { return admissions; },
    get admissionHoldCount() { return admissionHolds.size; },
    get shuttingDown() { return shuttingDown; },
    holdAdmissions,
    shutdown,
    track,
    withAdmission,
  };
}

module.exports = {
  TERMINAL_JOB_STATUSES,
  createAdmissionDispatchGuard,
  createBackgroundJobManager,
  interruptedJobError,
  throwIfJobInterrupted,
  updateTerminalJob,
};
