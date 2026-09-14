const TERMINAL_JOB_STATUSES = new Set(['succeeded', 'partial', 'failed', 'interrupted']);

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
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
  let shuttingDown = false;
  let admissions = 0;

  function begin(job, type, actor = 'local') {
    if (shuttingDown) throw interruptedJobError();
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

  async function withAdmission(callback) {
    if (shuttingDown) throw interruptedJobError();
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
      const pending = [...active.values()].map((record) => record.promise).filter(Boolean);
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
    const excludedJobIds = [...active.keys()];
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
    begin,
    get activeCount() { return active.size; },
    get admissionCount() { return admissions; },
    get shuttingDown() { return shuttingDown; },
    shutdown,
    track,
    withAdmission,
  };
}

module.exports = {
  TERMINAL_JOB_STATUSES,
  createBackgroundJobManager,
  interruptedJobError,
  throwIfJobInterrupted,
  updateTerminalJob,
};
