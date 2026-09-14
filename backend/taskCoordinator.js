const fs = require('node:fs');
const path = require('node:path');

const { acquireBakeryLease, releaseBakeryLease } = require('./lib/bakeryLock');
const { ensureDirectoryTree } = require('./lib/safeFs');

const CONTROL_LOCK_KIND = 'gpt-register-panel-control-lock';

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

const PROCESS_START_ID = processInformation(process.pid)?.startId || '';
const PROCESS_BOOT_ID = (() => {
  if (process.platform !== 'linux') return '';
  try {
    const value = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
    return /^[a-f0-9-]{36}$/i.test(value) ? value.toLowerCase() : '';
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
  if (expectedBootId && PROCESS_BOOT_ID
      && String(expectedBootId).toLowerCase() !== PROCESS_BOOT_ID) return false;
  try {
    process.kill(normalizedPid, 0);
  } catch (error) {
    if (error?.code === 'EPERM') return true;
    return false;
  }
  const information = processInformation(normalizedPid);
  if (information && ['Z', 'X'].includes(information.state)) return false;
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

async function acquireControlPlaneLease() {
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
    if (lease?.directoryDescriptor !== undefined) fs.fsyncSync(lease.directoryDescriptor);
  } finally {
    if (lease?.directoryDescriptor !== undefined) {
      try { fs.closeSync(lease.directoryDescriptor); } catch {}
    }
  }
}

async function runWithGlobalLease(callback) {
  const lease = await acquireControlPlaneLease();
  try {
    return await callback();
  } finally {
    releaseControlPlaneLease(lease);
  }
}

function withControlPlaneLock(callback) {
  const run = queue.then(() => runWithGlobalLease(callback));
  queue = run.catch(() => {});
  return run;
}

module.exports = {
  controlPlaneLockPath,
  currentProcessOwner,
  isProcessOwnerAlive,
  withControlPlaneLock,
};
