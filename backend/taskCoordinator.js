const fs = require('node:fs');
const path = require('node:path');

const { acquireBakeryLease, releaseBakeryLease } = require('./lib/bakeryLock');
const { ensureDirectoryTree } = require('./lib/safeFs');
const { interruptedJobError, throwIfJobInterrupted } = require('./jobLifecycle');
const { redactText, redactValue } = require('./logger');

const CONTROL_LOCK_KIND = 'gpt-register-panel-control-lock';
const CONTROL_LOCK_RELEASE_CODE = 'CONTROL_PLANE_LOCK_RELEASE_FAILED';
const CRITICAL_SECTION_RESULT_MAX_BYTES = 512 * 1024;
const PROCESS_START_ID_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/;
const PROCESS_BOOT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Keep FIFO ordering inside one process, then take a filesystem lease for the
// whole callback so independently started panel processes cannot overlap work
// against gpt_register or the shared Sub2API account pool.
let queue = Promise.resolve();

function processInformation(pid) {
  if (!Number.isSafeInteger(Number(pid)) || Number(pid) <= 0 || process.platform !== 'linux') return null;
  try {
    const value = fs.readFileSync('/proc/' + String(pid) + '/stat', 'utf8');
    const commandEnd = value.lastIndexOf(')');
    if (commandEnd < 0) return null;
    // Fields after comm start at proc field 3 (state); starttime is field 22.
    const fields = value.slice(commandEnd + 2).trim().split(/\s+/);
    return {
      state: fields[0] || '',
      startId: fields[19] || '',
    };
  } catch {
    return null;
  }
}

const RAW_PROCESS_START_ID = processInformation(process.pid)?.startId || '';
const PROCESS_START_ID = PROCESS_START_ID_PATTERN.test(RAW_PROCESS_START_ID)
  ? RAW_PROCESS_START_ID
  : '';
const PROCESS_BOOT_ID = (() => {
  if (process.platform !== 'linux') return '';
  try {
    const value = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
    return PROCESS_BOOT_ID_PATTERN.test(value) ? value.toLowerCase() : '';
  } catch {
    return '';
  }
})();

function currentProcessOwner() {
  return {
    pid: process.pid,
    processStartId: PROCESS_START_ID || null,
    processBootId: PROCESS_BOOT_ID || null,
  };
}

function isProcessOwnerAlive(pid, expectedStartId = '', expectedBootId = '') {
  const normalizedPid = Number(pid);
  if (!Number.isSafeInteger(normalizedPid) || normalizedPid <= 0) return false;
  try {
    process.kill(normalizedPid, 0);
  } catch (error) {
    if (error?.code === 'EPERM') return true;
    return false;
  }
  const information = processInformation(normalizedPid);
  if (information && ['Z', 'X'].includes(information.state)) return false;
  // A malformed persisted identity is not evidence that a live PID belongs to
  // a different process. Treat it as unverifiable and keep its lease. Only a
  // canonical boot/start mismatch can safely authorize stale-entry cleanup.
  if (expectedBootId && (typeof expectedBootId !== 'string'
      || !PROCESS_BOOT_ID_PATTERN.test(expectedBootId))) return true;
  if (expectedStartId && (typeof expectedStartId !== 'string'
      || !PROCESS_START_ID_PATTERN.test(expectedStartId))) return true;
  if (expectedBootId && PROCESS_BOOT_ID
      && expectedBootId.toLowerCase() !== PROCESS_BOOT_ID) return false;
  if (expectedStartId && information?.startId && information.startId !== String(expectedStartId)) return false;
  return true;
}

function controlPlaneLockPath() {
  if (String(process.env.PANEL_CONTROL_LOCK_PATH || '').trim()) {
    return path.resolve(String(process.env.PANEL_CONTROL_LOCK_PATH).trim());
  }
  if (String(process.env.PANEL_DB_PATH || '').trim()) {
    return path.resolve(String(process.env.PANEL_DB_PATH).trim()) + '.control.lock';
  }
  return path.join('/tmp', 'gpt-register-panel', 'control-plane.lock');
}

function boundedMilliseconds(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}

function sameFile(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function openControlPlaneDirectory(lockPath) {
  const directory = ensureDirectoryTree(path.dirname(lockPath), '控制面锁目录');
  const realDirectory = fs.realpathSync(directory);
  let descriptor;
  try {
    descriptor = fs.openSync(
      realDirectory,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor);
    const latest = fs.lstatSync(realDirectory);
    if (!opened.isDirectory() || latest.isSymbolicLink() || !latest.isDirectory()
        || !sameFile(opened, latest)) {
      throw new Error('控制面锁父目录在固定期间发生变化');
    }
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if ((currentUid !== null && opened.uid !== currentUid) || (opened.mode & 0o022) !== 0) {
      const error = new Error('控制面锁父目录必须由当前用户持有且不可由组或其他用户写入');
      error.code = 'CONTROL_PLANE_LOCK_PATH_INVALID';
      throw error;
    }
    const accessDirectory = process.platform === 'linux'
      ? '/proc/self/fd/' + descriptor
      : realDirectory;
    if (process.platform === 'linux' && fs.realpathSync(accessDirectory) !== realDirectory) {
      throw new Error('控制面锁父目录 FD 校验失败');
    }
    return { descriptor, accessDirectory, lockName: path.basename(lockPath) };
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    throw error;
  }
}

async function acquireControlPlaneLease(options = {}) {
  const lockPath = controlPlaneLockPath();
  const timeoutMs = boundedMilliseconds(
    process.env.PANEL_CONTROL_LOCK_TIMEOUT_MS,
    6 * 60 * 60 * 1000,
    1000,
    24 * 60 * 60 * 1000,
  );
  const pollMs = boundedMilliseconds(process.env.PANEL_CONTROL_LOCK_POLL_MS, 50, 10, 1000);
  const pinnedDirectory = openControlPlaneDirectory(lockPath);
  try {
    const lease = await acquireBakeryLease({
      directoryDescriptor: pinnedDirectory.descriptor,
      accessDirectory: pinnedDirectory.accessDirectory,
      lockName: pinnedDirectory.lockName,
      kind: CONTROL_LOCK_KIND,
      owner: currentProcessOwner(),
      isOwnerAlive: isProcessOwnerAlive,
      timeoutMs,
      pollMs,
      invalidCode: 'CONTROL_PLANE_LOCK_PATH_INVALID',
      changedCode: 'CONTROL_PLANE_LOCK_CHANGED',
      timeoutCode: 'CONTROL_PLANE_LOCK_TIMEOUT',
      releaseCode: 'CONTROL_PLANE_LOCK_RELEASE_FAILED',
      invalidMessage: '控制面锁命名空间或租约记录无效，拒绝覆盖或删除',
      changedMessage: '控制面锁租约在操作期间发生变化',
      timeoutMessage: '等待控制面全局锁超时',
      releaseMessage: '控制面锁租约释放失败，当前进程已停止接受新的全局锁任务',
      signal: options.signal,
    });
    return { ...lease, directoryDescriptor: pinnedDirectory.descriptor };
  } catch (error) {
    try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
    throw error;
  }
}

function releaseControlPlaneLease(lease) {
  try {
    releaseBakeryLease(lease);
  } finally {
    if (lease?.directoryDescriptor !== undefined) {
      try { fs.closeSync(lease.directoryDescriptor); } catch {}
    }
  }
}

function safeErrorCode(value, fallback) {
  let candidate = '';
  try { candidate = String(value || '').trim(); } catch {}
  return /^[A-Za-z0-9_.-]{1,100}$/.test(candidate) ? candidate : fallback;
}

function errorProperty(error, key) {
  try { return error?.[key]; } catch { return undefined; }
}

function safeErrorMessage(error, fallback) {
  try {
    return redactText(String(error?.message || error || fallback)).slice(0, 1000) || fallback;
  } catch {
    return fallback;
  }
}

function safeReleaseFailure(error) {
  return {
    code: safeErrorCode(errorProperty(error, 'code'), CONTROL_LOCK_RELEASE_CODE),
    message: safeErrorMessage(error, '控制面全局锁释放失败'),
  };
}

function safeCriticalSectionResult(value) {
  try {
    // A cloned value can retain an enumerable `toJSON` function. Parse and
    // redact its serialized form once more so custom serialization cannot
    // reintroduce credentials after the first structured redaction pass.
    const initialSerialized = JSON.stringify(redactValue(value));
    if (initialSerialized === undefined) {
      return { available: false, reason: 'not_json_serializable' };
    }
    const initialByteLength = Buffer.byteLength(initialSerialized, 'utf8');
    if (initialByteLength > CRITICAL_SECTION_RESULT_MAX_BYTES) {
      return { available: false, reason: 'result_too_large', byteLength: initialByteLength };
    }
    const serialized = JSON.stringify(redactValue(JSON.parse(initialSerialized)));
    const byteLength = Buffer.byteLength(serialized, 'utf8');
    if (byteLength > CRITICAL_SECTION_RESULT_MAX_BYTES) {
      return { available: false, reason: 'result_too_large', byteLength };
    }
    return { available: true, value: JSON.parse(serialized) };
  } catch {
    return { available: false, reason: 'result_unavailable' };
  }
}

function completedCriticalSectionReleaseError(releaseError, result) {
  const error = new Error(
    '控制面操作已经完成，但全局锁释放失败；执行结果需要人工对账，禁止自动重试',
  );
  const safeResult = safeCriticalSectionResult(result);
  error.code = CONTROL_LOCK_RELEASE_CODE;
  error.criticalSectionCompleted = true;
  error.controlPlaneLeaseReleaseFailed = true;
  error.requiresReconciliation = true;
  error.retryAllowed = false;
  error.doNotRetry = true;
  error.releaseFailure = safeReleaseFailure(releaseError);
  error.criticalSectionResultAvailable = safeResult.available;
  if (safeResult.available) error.criticalSectionResult = safeResult.value;
  else error.criticalSectionResultOmittedReason = safeResult.reason;
  if (safeResult.byteLength !== undefined) {
    error.criticalSectionResultByteLength = safeResult.byteLength;
  }
  return error;
}

function callbackFailureSummary(error) {
  return {
    code: safeErrorCode(errorProperty(error, 'code'), 'CONTROL_PLANE_CALLBACK_FAILED'),
    message: safeErrorMessage(error, '控制面操作失败'),
  };
}

function callbackErrorWithReleaseFailure(callbackError, releaseError) {
  const releaseFailure = safeReleaseFailure(releaseError);
  const annotations = {
    controlPlaneLeaseReleaseFailed: true,
    releaseFailure,
  };
  if (errorProperty(callbackError, 'criticalSectionCompleted') !== true) {
    annotations.criticalSectionCompleted = false;
  }
  try {
    if (callbackError && (typeof callbackError === 'object' || typeof callbackError === 'function')) {
      Object.assign(callbackError, annotations);
      if (errorProperty(callbackError, 'controlPlaneLeaseReleaseFailed') === true) {
        return callbackError;
      }
    }
  } catch {
    // Frozen or otherwise non-extensible thrown values are represented below
    // without retaining an unsafe raw cause.
  }

  const callbackFailure = callbackFailureSummary(callbackError);
  const error = new Error(callbackFailure.message);
  error.code = callbackFailure.code;
  error.callbackFailure = callbackFailure;
  Object.assign(error, annotations);
  if (errorProperty(callbackError, 'criticalSectionCompleted') === true) {
    error.criticalSectionCompleted = true;
  }
  if (errorProperty(callbackError, 'requiresReconciliation') === true) {
    error.requiresReconciliation = true;
  }
  if (errorProperty(callbackError, 'doNotRetry') === true) error.doNotRetry = true;
  if (errorProperty(callbackError, 'retryAllowed') === false) error.retryAllowed = false;
  return error;
}

async function runWithGlobalLease(callback, options = {}) {
  const lease = await acquireControlPlaneLease(options);
  let callbackCompleted = false;
  let callbackFailed = false;
  let callbackResult;
  let callbackError;
  try {
    throwIfJobInterrupted(options.signal);
    callbackResult = await callback();
    callbackCompleted = true;
  } catch (error) {
    callbackFailed = true;
    callbackError = error;
  }

  let releaseError;
  try {
    releaseControlPlaneLease(lease);
  } catch (error) {
    releaseError = error;
  }

  if (releaseError) {
    if (callbackCompleted) {
      throw completedCriticalSectionReleaseError(releaseError, callbackResult);
    }
    throw callbackErrorWithReleaseFailure(callbackError, releaseError);
  }
  if (callbackFailed) throw callbackError;
  return callbackResult;
}

function queueCancelableRun(predecessor, callback, options = {}) {
  const signal = options.signal;
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

function withControlPlaneLock(callback, options = {}) {
  const queued = queueCancelableRun(
    queue,
    () => runWithGlobalLease(callback, options),
    options,
  );
  const run = queued.run;
  queue = run.catch(() => {});
  return queued.result;
}

module.exports = {
  controlPlaneLockPath,
  currentProcessOwner,
  isProcessOwnerAlive,
  queueCancelableRun,
  withControlPlaneLock,
};
