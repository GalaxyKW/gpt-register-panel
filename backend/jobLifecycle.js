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
      return await db.updateJob(jobId, terminalPatch);
    } catch (error) {
      lastError = error;
      if (attempt >= attempts) break;
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
  let shuttingDown = false;
  let admissions = 0;

  function begin(job, type, actor = 'local') {
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
    if (shuttingDown) controller.abort(interruptedJobError());
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
    try {
      return await callback();
    } finally {
      admissions -= 1;
    }
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
    for (const record of active.values()) record.controller.abort(reason);
    // Phase3's default TERM + KILL deadlines total ten seconds. Keep the drain
    // below twelve seconds, leaving the rest of systemd's 45-second stop
    // budget for a contended SQLite lock and final connection closure.
    const timeoutMs = boundedInteger(options.timeoutMs, 10_000, 0, 12_000);
    const remaining = await waitForIdle(timeoutMs);
    // Give a worker that completed concurrently with SIGTERM a chance to
    // persist success first. Only work still queued/running after the bounded
    // drain is labelled interrupted and has its claims released.
    const interrupted = db && typeof db.interruptOwnedActiveJobs === 'function'
      ? await db.interruptOwnedActiveJobs('面板服务停止，任务已安全中断')
      : [];
    return { remaining, active: active.size, interrupted };
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
