const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const {
  closeDirectoryHandle,
  openRootDirectory,
  readGptRegisterSources,
  usernameRecordLimit,
} = require('./adapters/gptRegisterFs');
const { normalizeEmail } = require('./lib/token');
const { redactText } = require('./logger');
const { withControlPlaneLock } = require('./taskCoordinator');
const { assertDirectoryTree, syncDirectory } = require('./lib/safeFs');
const { interruptedJobError, throwIfJobInterrupted } = require('./jobLifecycle');

// Phase 3 drives a real browser and gpt_register uses a shared profile. Only
// one process may run at a time; jobs for different accounts wait in order.
let phase3Queue = Promise.resolve();
const activePhase3Jobs = new Map();
const TERMINAL_ACCOUNT_STATUSES = new Set([
  'account_deactivated',
  'account_deleted',
  'account_disabled',
]);
const PHASE3_CHILD_MUTABLE_FIELDS = new Set([
  'status',
  'phase3LastAttemptAt',
  'phase3LastErrorCode',
  'phase3LastError',
  'phase3Retryable',
  'phase3RetryCount',
  'phase3Screenshot',
  'phase3RequestId',
  'phase3Disposition',
]);
const PHASE3_ENV_NAMES = new Set([
  'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TZ', 'NODE_ENV',
  'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY',
  'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR',
]);
const activePhase3Children = new Set();
let phase3ExitHookInstalled = false;
// Phase3 reads credentials from this file, so callers may lower the limit but
// cannot configure away the process-level allocation bound.
const PHASE3_USERNAME_DEFAULT_MAX_BYTES = 32 * 1024 * 1024;
const PHASE3_USERNAME_HARD_MAX_BYTES = 32 * 1024 * 1024;
const PHASE3_FINAL_KILL_WAIT_MS = 5000;
const PHASE3_DESCENDANT_LIMIT = 4096;
const PHASE3_SCRIPT_CHILD_FD = 3;
const READ_ONLY_NOFOLLOW = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);

function registerRoot() {
  return path.resolve(process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register');
}

function linuxProcessIdentity(pid) {
  const numericPid = Number(pid);
  if (process.platform !== 'linux' || !Number.isSafeInteger(numericPid) || numericPid <= 1) {
    return null;
  }
  try {
    const stat = fs.readFileSync('/proc/' + String(numericPid) + '/stat', 'utf8');
    const commandEnd = stat.lastIndexOf(')');
    if (commandEnd < 0) return null;
    const fields = stat.slice(commandEnd + 2).trim().split(/\s+/);
    if (fields.length < 20) return null;
    const cgroup = fs.readFileSync('/proc/' + String(numericPid) + '/cgroup', 'utf8').trim();
    return {
      pid: numericPid,
      state: fields[0] || '',
      parentPid: Number(fields[1]),
      processGroupId: Number(fields[2]),
      startId: fields[19] || '',
      cgroup,
    };
  } catch {
    return null;
  }
}

function linuxChildPids(pid) {
  const taskRoot = '/proc/' + String(pid) + '/task';
  let taskIds;
  try {
    taskIds = fs.readdirSync(taskRoot).filter((value) => /^\d+$/.test(value)).slice(
      0,
      PHASE3_DESCENDANT_LIMIT,
    );
  } catch {
    return [];
  }
  const children = new Set();
  for (const taskId of taskIds) {
    try {
      const values = fs.readFileSync(taskRoot + '/' + taskId + '/children', 'utf8')
        .trim().split(/\s+/).filter(Boolean).map(Number);
      for (const value of values) {
        if (Number.isSafeInteger(value) && value > 1) children.add(value);
      }
    } catch {}
  }
  return [...children];
}

function captureLinuxDescendants(rootPid, tracked, expectedCgroup = '') {
  if (process.platform !== 'linux') return expectedCgroup;
  const root = linuxProcessIdentity(rootPid);
  const cgroup = expectedCgroup || root?.cgroup || '';
  if (!root || !cgroup || root.cgroup !== cgroup) return cgroup;
  const queue = [{ pid: root.pid, depth: 0 }];
  const visited = new Set();
  while (queue.length > 0 && tracked.size < PHASE3_DESCENDANT_LIMIT) {
    const current = queue.shift();
    if (visited.has(current.pid)) continue;
    visited.add(current.pid);
    for (const childPid of linuxChildPids(current.pid)) {
      if (tracked.size >= PHASE3_DESCENDANT_LIMIT) break;
      const identity = linuxProcessIdentity(childPid);
      if (!identity || identity.parentPid !== current.pid || identity.cgroup !== cgroup) continue;
      const existing = tracked.get(childPid);
      if (!existing) tracked.set(childPid, { ...identity, depth: current.depth + 1 });
      queue.push({ pid: childPid, depth: current.depth + 1 });
    }
  }
  return cgroup;
}

function activeTrackedDescendants(tracked) {
  const active = [];
  for (const expected of tracked.values()) {
    const current = linuxProcessIdentity(expected.pid);
    if (!current || ['Z', 'X'].includes(current.state)
        || current.startId !== expected.startId || current.cgroup !== expected.cgroup) continue;
    active.push({ ...expected, processGroupId: current.processGroupId });
  }
  return active;
}

function signalTrackedDescendants(tracked, signal, excludedProcessGroups = new Set()) {
  const active = activeTrackedDescendants(tracked)
    .sort((left, right) => right.depth - left.depth || right.pid - left.pid);
  const signalledGroups = new Set(excludedProcessGroups);
  for (const processInfo of active) {
    const groupId = processInfo.processGroupId;
    if (Number.isSafeInteger(groupId) && groupId > 1 && !signalledGroups.has(groupId)) {
      signalledGroups.add(groupId);
      try { process.kill(-groupId, signal); } catch {}
    }
    try { process.kill(processInfo.pid, signal); } catch {}
  }
}

function sameFileIdentity(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function assertTrustedPhase3Object(stat, label, options = {}) {
  const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  const trustedOwner = effectiveUid === null || stat.uid === 0 || stat.uid === effectiveUid;
  if (!trustedOwner || (stat.mode & 0o022) !== 0) {
    const error = new Error(label + ' 的所有者或写权限不安全');
    error.code = 'PHASE3_PATH_PERMISSIONS_INVALID';
    throw error;
  }
  if (options.executable === true && (stat.mode & 0o111) === 0) {
    const error = new Error(label + ' 不可执行');
    error.code = 'PHASE3_PATH_INVALID';
    throw error;
  }
}

function openPinnedRegularFile(filePath, label, options = {}) {
  if (options.parentPinned !== true) {
    try { assertDirectoryTree(path.dirname(filePath), label + ' 父目录'); } catch (error) {
      const wrapped = new Error(label + ' 父目录不存在、不可读取或包含符号链接');
      wrapped.code = 'PHASE3_PATH_INVALID';
      wrapped.cause = error;
      throw wrapped;
    }
  }
  let descriptor;
  try {
    const initial = fs.lstatSync(filePath);
    if (initial.isSymbolicLink() || !initial.isFile()) {
      throw new Error(label + ' 必须是非符号链接普通文件');
    }
    descriptor = fs.openSync(filePath, READ_ONLY_NOFOLLOW);
    const opened = fs.fstatSync(descriptor);
    const latest = fs.lstatSync(filePath);
    if (!opened.isFile() || latest.isSymbolicLink() || !latest.isFile()
        || !sameFileIdentity(initial, opened) || !sameFileIdentity(opened, latest)) {
      throw new Error(label + ' 在打开期间发生变化');
    }
    assertTrustedPhase3Object(opened, label, options);
    return { descriptor, stat: opened };
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (['PHASE3_PATH_INVALID', 'PHASE3_PATH_PERMISSIONS_INVALID'].includes(error?.code)) throw error;
    const wrapped = new Error(label + ' 不存在、不可读取、已变化或不安全');
    wrapped.code = 'PHASE3_PATH_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
}

function closeRegularFileHandle(handle) {
  if (handle?.descriptor !== undefined) {
    try { fs.closeSync(handle.descriptor); } catch {}
  }
}

function openPinnedPhase3Root(root) {
  let handle;
  try {
    handle = openRootDirectory(root, 'GPT_REGISTER_ROOT');
    const sharedTraversalPath = '/proc/' + process.pid + '/fd/' + handle.descriptor;
    let sharedStat;
    try { sharedStat = fs.statSync(sharedTraversalPath); } catch {}
    if (!handle.procPinned || !/^\/proc\/self\/fd\/\d+$/.test(handle.traversalPath || '')
        || !sameFileIdentity(handle.stat, sharedStat)) {
      const error = new Error('当前平台无法固定 GPT_REGISTER_ROOT，拒绝执行 Phase3');
      error.code = 'PHASE3_PATH_PIN_UNAVAILABLE';
      throw error;
    }
    handle.sharedTraversalPath = sharedTraversalPath;
    assertTrustedPhase3Object(fs.fstatSync(handle.descriptor), 'GPT_REGISTER_ROOT');
    return handle;
  } catch (error) {
    closeDirectoryHandle(handle);
    if (['PHASE3_PATH_PIN_UNAVAILABLE', 'PHASE3_PATH_PERMISSIONS_INVALID'].includes(error?.code)) {
      throw error;
    }
    const wrapped = new Error('GPT_REGISTER_ROOT 不存在、不可读取、已变化或不安全');
    wrapped.code = 'PHASE3_ROOT_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
}

function sharedDescriptorPath(descriptor) {
  return '/proc/' + process.pid + '/fd/' + descriptor;
}

// This launcher is deliberately constant. The verified index.js is inherited
// as a descriptor instead of putting its source in argv/environment. Compile
// that descriptor-backed source as the real main module so gpt_register's
// `require.main === module` entrypoint runs normally.
const PHASE3_LAUNCHER_SOURCE = [
  `'use strict';`,
  "const fs = require('node:fs');",
  "const Module = require('node:module');",
  'const [root, ...forwarded] = process.argv.slice(1);',
  "if (!/^\\/proc\\/[1-9][0-9]*\\/fd\\/[0-9]+$/.test(root || '')) {",
  "  throw new Error('invalid pinned Phase3 root');",
  '}',
  `const source = fs.readFileSync(${PHASE3_SCRIPT_CHILD_FD}, 'utf8');`,
  "const script = root + '/index.js';",
  'process.cwd = () => root;',
  'process.argv = [process.execPath, script, ...forwarded];',
  "const main = new Module('.', null);",
  'main.filename = script;',
  'main.path = root;',
  'main.paths = Module._nodeModulePaths(root);',
  'process.mainModule = main;',
  'Module._cache[script] = main;',
  'try {',
  '  main._compile(source, script);',
  '  main.loaded = true;',
  '} catch (error) {',
  '  delete Module._cache[script];',
  '  throw error;',
  '}',
].join('\n');

function phase3LauncherSource() {
  return PHASE3_LAUNCHER_SOURCE;
}

function phase3Environment() {
  const environment = {};
  for (const name of PHASE3_ENV_NAMES) {
    if (process.env[name] !== undefined) environment[name] = process.env[name];
  }
  environment.NODE_ENV = process.env.NODE_ENV || 'production';
  return environment;
}

function normalizePhone(value) {
  return String(value || '').trim().replace(/[^0-9]/g, '');
}

function recordFingerprint(record) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(record === undefined ? null : record))
    .digest('hex');
}

function phase3TransitionBaseFingerprint(record) {
  const stable = {};
  for (const [key, value] of Object.entries(record || {})) {
    if (!PHASE3_CHILD_MUTABLE_FIELDS.has(key)) stable[key] = value;
  }
  return recordFingerprint(stable);
}

function phase3UsernameMaxBytes() {
  const configured = Number(process.env.GPT_REGISTER_USERNAME_MAX_BYTES);
  if (!Number.isSafeInteger(configured) || configured < 1024) {
    return PHASE3_USERNAME_DEFAULT_MAX_BYTES;
  }
  return Math.min(configured, PHASE3_USERNAME_HARD_MAX_BYTES);
}

function readDescriptorBounded(descriptor, maximumBytes, label) {
  const chunks = [];
  let total = 0;
  while (true) {
    const remainingWithSentinel = maximumBytes - total + 1;
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, remainingWithSentinel));
    const count = fs.readSync(descriptor, chunk, 0, chunk.length, null);
    if (count === 0) break;
    total += count;
    if (total > maximumBytes) {
      const error = new Error(label + ' 超过 Phase3 允许的大小上限');
      error.code = 'PHASE3_USERNAME_TOO_LARGE';
      throw error;
    }
    chunks.push(chunk.subarray(0, count));
  }
  return Buffer.concat(chunks, total);
}

function readRegularJsonArraySnapshot(filePath, label, options = {}) {
  let descriptor;
  try {
    if (options.parentPinned !== true) {
      assertDirectoryTree(path.dirname(filePath), label + ' 父目录');
    }
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0)
      | (fs.constants.O_NONBLOCK || 0));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile()) throw new Error(label + ' 必须是普通文件');
    assertTrustedPhase3Object(before, label);
    const maximumBytes = phase3UsernameMaxBytes();
    if (before.size > maximumBytes) {
      const error = new Error(label + ' 超过 Phase3 允许的大小上限');
      error.code = 'PHASE3_USERNAME_TOO_LARGE';
      throw error;
    }
    const bytes = readDescriptorBounded(descriptor, maximumBytes, label);
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino
        || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs) {
      throw new Error(label + ' 在读取期间发生变化');
    }
    const value = JSON.parse(bytes.toString('utf8'));
    const records = Array.isArray(value)
      ? value
      : value && typeof value === 'object' ? [value] : [];
    if (records.length > usernameRecordLimit()) {
      const error = new Error('username.json 账号记录数超过允许上限');
      error.code = 'GPT_REGISTER_USERNAME_RECORD_LIMIT';
      throw error;
    }
    return {
      records,
      dev: after.dev,
      ino: after.ino,
      size: after.size,
      mtimeMs: after.mtimeMs,
      contentHash: crypto.createHash('sha256').update(bytes).digest('hex'),
    };
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function sameFileSnapshot(left, right) {
  return Boolean(left && right
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.contentHash === right.contentHash);
}

function usernameFilePath(rootHandle = null) {
  return path.join(rootHandle?.traversalPath || registerRoot(), 'username.json');
}

function findUsernameEntry({ email, phone } = {}, rootHandle = null) {
  const records = readRegularJsonArraySnapshot(
    usernameFilePath(rootHandle),
    'username.json',
    { parentPinned: Boolean(rootHandle) },
  ).records;
  const normalizedEmail = normalizeEmail(email);
  const normalizedPhone = normalizePhone(phone);
  const eligible = records.map((record, index) => ({ record, index })).filter(({ record }) => {
    if (!record || !record.password) return false;
    const emailMatches = normalizedEmail && record.email
      && normalizeEmail(record.email) === normalizedEmail;
    const phoneMatches = normalizedPhone && normalizePhone(record.phone) === normalizedPhone;
    // When both identifiers are supplied they must identify the same row.
    // Matching email from one account and phone from another is ambiguous.
    if (normalizedEmail && normalizedPhone) return emailMatches && phoneMatches;
    return emailMatches || phoneMatches;
  });
  if (eligible.length !== 1) {
    const error = new Error(eligible.length > 1
      ? 'username.json 中存在多个匹配的 phase3 账号'
      : 'username.json 中未找到可用于 phase3 的账号');
    error.code = eligible.length > 1 ? 'PHASE3_ACCOUNT_AMBIGUOUS' : 'PHASE3_ACCOUNT_NOT_FOUND';
    throw error;
  }
  const { record, index } = eligible[0];
  const status = String(record.status || '').trim().toLowerCase();
  if (TERMINAL_ACCOUNT_STATUSES.has(status)) {
    const error = new Error(`账号已标记为 ${record.status}，跳过 Phase3`);
    error.code = 'PHASE3_ACCOUNT_TERMINAL';
    error.accountStatus = status;
    throw error;
  }
  return {
    index,
    email: normalizeEmail(record.email),
    phone: normalizePhone(record.phone),
    createdAt: record.createdAt || null,
    recordFingerprint: recordFingerprint(record),
    transitionBaseFingerprint: phase3TransitionBaseFingerprint(record),
    resolvedAtMs: Date.now(),
  };
}

function persistAccountDispositionWithHandle(entry, code, rootHandle) {
  const filePath = path.join(rootHandle.traversalPath, 'username.json');
  let snapshot;
  try { snapshot = readRegularJsonArraySnapshot(filePath, 'username.json', { parentPinned: true }); } catch (error) {
    const wrapped = new Error('username.json 不存在、不可读取、不是普通文件或内容无效');
    wrapped.cause = error;
    throw wrapped;
  }
  const records = snapshot.records;
  if (!Array.isArray(records) || !records[entry.index]) {
    throw new Error('username.json 账号记录已变化，无法持久化处置状态');
  }
  const current = records[entry.index];
  if (normalizeEmail(current?.email) !== entry.email || normalizePhone(current?.phone) !== entry.phone) {
    throw new Error('username.json 账号索引已变化，拒绝覆盖错误记录');
  }
  if (entry.recordFingerprint && recordFingerprint(current) !== entry.recordFingerprint) {
    const currentStatus = String(current?.status || '').trim().toLowerCase();
    const attemptAtMs = Date.parse(String(current?.phase3LastAttemptAt || ''));
    const childRecordedDiscard = TERMINAL_ACCOUNT_STATUSES.has(currentStatus)
      && String(current?.phase3Disposition || '').trim().toLowerCase() === 'discard'
      && String(current?.phase3LastErrorCode || '').trim() === String(code || 'ACCOUNT_DEACTIVATED')
      && current?.phase3Retryable === false
      && Number.isFinite(attemptAtMs)
      && attemptAtMs >= Number(entry.resolvedAtMs || 0) - 1000
      && phase3TransitionBaseFingerprint(current) === entry.transitionBaseFingerprint;
    // gpt_register records a terminal Phase3 failure before the child exits.
    // Accept that one expected transition and preserve all of its diagnostic
    // fields, while still rejecting unrelated/manual concurrent changes.
    if (!childRecordedDiscard) {
      throw new Error('username.json 账号记录在 Phase3 期间发生变化，拒绝覆盖');
    }
  }
  records[entry.index] = {
    ...current,
    status: 'account_deleted',
    phase3Disposition: 'discard',
    phase3DispositionAt: new Date().toISOString(),
    phase3ErrorCode: code || 'ACCOUNT_DEACTIVATED',
  };
  const temporaryPath = filePath + '.tmp-' + process.pid + '-' + crypto.randomBytes(8).toString('hex');
  let descriptor;
  try {
    descriptor = fs.openSync(temporaryPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    const content = Buffer.from(JSON.stringify(records, null, 2) + '\n', 'utf8');
    fs.writeFileSync(descriptor, content);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    // Recheck inode, metadata and the complete content before the replace.
    // This catches same-size writes and timestamp-preserving rewrites as well
    // as ordinary editor updates while the temporary file is being flushed.
    const latest = readRegularJsonArraySnapshot(filePath, 'username.json', { parentPinned: true });
    if (!sameFileSnapshot(latest, snapshot)) {
      throw new Error('username.json 在写入前发生变化，拒绝覆盖');
    }
    fs.renameSync(temporaryPath, filePath);
    syncDirectory(path.dirname(filePath));
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    try { fs.unlinkSync(temporaryPath); } catch {}
  }
}

function persistAccountDisposition(entry, code, suppliedRootHandle = null) {
  const rootHandle = suppliedRootHandle || openPinnedPhase3Root(registerRoot());
  try {
    return persistAccountDispositionWithHandle(entry, code, rootHandle);
  } finally {
    if (!suppliedRootHandle) closeDirectoryHandle(rootHandle);
  }
}

function boundedByteCount(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) return 0;
  return number;
}

function phase3ProcessSummary(details = {}) {
  const value = details && typeof details === 'object' ? details : {};
  const stdout = typeof value.stdout === 'string' ? value.stdout : '';
  const stderr = typeof value.stderr === 'string' ? value.stderr : '';
  return {
    code: Number.isSafeInteger(value.code) ? value.code : null,
    signal: typeof value.signal === 'string' && /^[A-Z0-9]{1,32}$/.test(value.signal)
      ? value.signal
      : null,
    forcedClose: value.forcedClose === true,
    outputTruncated: value.outputTruncated === true,
    stdoutBytes: boundedByteCount(value.stdoutBytes) || Buffer.byteLength(stdout, 'utf8'),
    stderrBytes: boundedByteCount(value.stderrBytes) || Buffer.byteLength(stderr, 'utf8'),
  };
}

function classifyPhase3ProcessError(error, entry = null, rootHandle = null) {
  const details = error?.details || {};
  const hasProcessDetails = details && typeof details === 'object'
    && ['code', 'signal', 'stdout', 'stderr', 'forcedClose', 'outputTruncated',
      'stdoutBytes', 'stderrBytes'].some((key) => Object.hasOwn(details, key));
  const combined = [details.stdout, details.stderr, error?.message]
    .filter(Boolean)
    .join('\n');
  let childRecordedTerminal = false;
  if (entry) {
    try {
      const snapshot = readRegularJsonArraySnapshot(
        usernameFilePath(rootHandle),
        'username.json',
        { parentPinned: Boolean(rootHandle) },
      );
      const current = snapshot.records[entry.index];
      childRecordedTerminal = normalizeEmail(current?.email) === entry.email
        && normalizePhone(current?.phone) === entry.phone
        && TERMINAL_ACCOUNT_STATUSES.has(String(current?.status || '').trim().toLowerCase())
        && String(current?.phase3Disposition || '').trim().toLowerCase() === 'discard'
        && String(current?.phase3LastErrorCode || '').trim() === 'ACCOUNT_DEACTIVATED';
    } catch {}
  }
  // Only trust the structured state transition written by gpt_register for
  // this exact username row. Browser text and dependency diagnostics are
  // untrusted prose and can contain phrases such as "account disabled"
  // without proving that this account was permanently deactivated.
  if (childRecordedTerminal) {
    error.code = 'ACCOUNT_DEACTIVATED';
    error.retryable = false;
    error.accountDisposition = 'discard';
    error.message = 'OpenAI 账号已删除或停用';
    const screenshot = combined.match(/(?:截图|screenshot)\s*:\s*(\S+\.png)/i)?.[1] || '';
    const safeScreenshot = /^[A-Za-z0-9._/-]{1,240}$/.test(screenshot)
      ? path.basename(screenshot)
      : null;
    const requestId = combined.match(
      /(?:request[_ ]?id|请求\s*ID)\s*[:：]?\s*([A-Za-z0-9-]{1,128})/i,
    )?.[1] || null;
    error.details = {
      ...phase3ProcessSummary(details),
      phase3: {
        code: 'ACCOUNT_DEACTIVATED',
        screenshot: safeScreenshot,
        requestId,
      },
    };
  } else if (hasProcessDetails) {
    // Child output can contain arbitrary unlabelled credentials. It is used
    // above for the in-memory classifier only and must never escape through a
    // job error, API response, audit record, or persistent logger.
    error.details = phase3ProcessSummary(details);
  }
  return error;
}

function sanitizeLog(value) {
  return redactText(String(value || '')).slice(-12000);
}

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Logging must never change the outcome of a Phase 3 task.
  }
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const maxOutputBytes = Number.isSafeInteger(Number(options.maxOutputBytes))
      ? Math.max(1024, Math.min(Number(options.maxOutputBytes), 1024 * 1024))
      : 256 * 1024;
    const output = { stdout: [], stderr: [] };
    const observedBytes = { stdout: 0, stderr: 0 };
    let retainedBytes = 0;
    let outputTruncated = false;
    let child;
    let settled = false;
    let timer;
    let killTimer;
    let forceSettleTimer;
    let descendantSampler;
    let terminationError = null;
    let closeResult = null;
    const externalSignal = options.signal;
    let stopForwardingAbort = () => {};
    const trackedDescendants = new Map();
    let descendantCgroup = '';
    const captureDescendants = () => {
      if (!child?.pid) return;
      descendantCgroup = captureLinuxDescendants(
        child.pid,
        trackedDescendants,
        descendantCgroup,
      );
    };
    const terminate = (signal) => {
      if (!child?.pid) return;
      captureDescendants();
      if (process.platform !== 'win32') {
        const ownGroup = linuxProcessIdentity(process.pid)?.processGroupId;
        signalTrackedDescendants(
          trackedDescendants,
          signal,
          new Set([child.pid, ownGroup].filter(Number.isSafeInteger)),
        );
        try { process.kill(-child.pid, signal); } catch {}
      }
      try { child.kill(signal); } catch {}
    };
    const readOutput = (streamName) => {
      const value = Buffer.concat(output[streamName]).toString('utf8');
      return sanitizeLog(value) + (outputTruncated ? '\n[phase3 output truncated]' : '');
    };
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      if (forceSettleTimer) clearTimeout(forceSettleTimer);
      if (descendantSampler) clearInterval(descendantSampler);
      stopForwardingAbort();
      if (child) activePhase3Children.delete(child);
    };
    const destroyOutputPipes = () => {
      for (const stream of [child?.stdout, child?.stderr]) {
        if (!stream) continue;
        try { stream.removeAllListeners('data'); } catch {}
        try { stream.destroy(); } catch {}
      }
    };
    const terminationResult = (forcedClose) => ({
      code: closeResult?.code ?? child?.exitCode ?? null,
      signal: closeResult?.signal || child?.signalCode || 'SIGKILL',
      stdout: readOutput('stdout'),
      stderr: readOutput('stderr'),
      forcedClose,
      outputTruncated,
      stdoutBytes: observedBytes.stdout,
      stderrBytes: observedBytes.stderr,
    });
    const settleTerminatedCommand = (forcedClose = false) => {
      if (settled || !terminationError) return false;
      captureDescendants();
      if (!forcedClose && (!closeResult || activeTrackedDescendants(trackedDescendants).length > 0)) {
        return false;
      }
      settled = true;
      if (forcedClose) destroyOutputPipes();
      terminationError.details = terminationResult(forcedClose);
      cleanup();
      reject(terminationError);
      return true;
    };
    const forceTerminationSettlement = () => {
      if (settled || !terminationError) return;
      terminate('SIGKILL');
      settleTerminatedCommand(true);
    };
    const requestTermination = (error) => {
      if (settled || terminationError) return;
      terminationError = error;
      terminate('SIGTERM');
      const configuredGraceMs = Number(options.terminationGraceMs);
      const graceMs = Number.isFinite(configuredGraceMs) && configuredGraceMs > 0
        ? Math.min(Math.max(configuredGraceMs, 100), 30000)
        : 5000;
      killTimer = setTimeout(() => {
        // The leader can exit on SIGTERM while a descendant keeps the process
        // group (and stdout/stderr pipes) alive. Keep targeting the PGID until
        // `close` confirms all inherited stdio handles are gone.
        if (settled) return;
        terminate('SIGKILL');
        const configuredFinalWaitMs = Number(options.terminationHardDeadlineMs);
        const finalWaitMs = Number.isFinite(configuredFinalWaitMs) && configuredFinalWaitMs > 0
          ? Math.min(Math.max(configuredFinalWaitMs, 100), 30000)
          : PHASE3_FINAL_KILL_WAIT_MS;
        // A detached descendant can escape the original process group while
        // retaining its stdout/stderr descriptors. Do not let those inherited
        // pipes keep the job Promise and cross-process lock alive forever.
        const hardDeadline = Date.now() + finalWaitMs;
        const checkDescendants = () => {
          if (settled || settleTerminatedCommand(false)) return;
          if (Date.now() >= hardDeadline) {
            forceTerminationSettlement();
            return;
          }
          forceSettleTimer = setTimeout(
            checkDescendants,
            Math.min(50, Math.max(1, hardDeadline - Date.now())),
          );
        };
        forceSettleTimer = setTimeout(checkDescendants, Math.min(50, finalWaitMs));
      }, graceMs);
      killTimer.unref();
    };
    if (externalSignal?.aborted) {
      reject(interruptedJobError());
      return;
    }
    const extraFileDescriptors = Array.isArray(options.extraFileDescriptors)
      ? options.extraFileDescriptors
      : [];
    if (extraFileDescriptors.length > 8 || extraFileDescriptors.some(
      (descriptor) => !Number.isSafeInteger(descriptor) || descriptor < 0,
    )) {
      const error = new Error('phase3 继承文件描述符无效');
      error.code = 'PHASE3_DESCRIPTOR_INVALID';
      reject(error);
      return;
    }
    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        env: options.env,
        shell: false,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe', ...extraFileDescriptors],
      });
    } catch (error) {
      cleanup();
      reject(error);
      return;
    }
    activePhase3Children.add(child);
    if (process.platform === 'linux') {
      // A browser helper can leave the original process group before timeout
      // or shutdown. Retain only descendants proven by pid/start-id/cgroup
      // while the parent relationship still exists, then target that bounded
      // set if termination becomes necessary.
      captureDescendants();
      descendantSampler = setInterval(captureDescendants, 100);
      descendantSampler.unref();
    }
    if (externalSignal && typeof externalSignal.addEventListener === 'function') {
      const abort = () => requestTermination(interruptedJobError());
      externalSignal.addEventListener('abort', abort, { once: true });
      stopForwardingAbort = () => {
        try { externalSignal.removeEventListener('abort', abort); } catch {}
      };
      if (externalSignal.aborted) abort();
    }
    const collectOutput = (streamName, chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      observedBytes[streamName] = Math.min(
        Number.MAX_SAFE_INTEGER,
        observedBytes[streamName] + bytes.length,
      );
      const remaining = Math.max(0, maxOutputBytes - retainedBytes);
      if (remaining > 0) {
        const retained = bytes.length > remaining ? bytes.subarray(0, remaining) : bytes;
        output[streamName].push(Buffer.from(retained));
        retainedBytes += retained.length;
      }
      if (bytes.length > remaining && !terminationError) {
        outputTruncated = true;
        const error = new Error('phase3 输出超过安全上限');
        error.code = 'PHASE3_OUTPUT_LIMIT';
        requestTermination(error);
      }
    };
    child.stdout.on('data', (chunk) => collectOutput('stdout', chunk));
    child.stderr.on('data', (chunk) => collectOutput('stderr', chunk));
    if (!phase3ExitHookInstalled) {
      phase3ExitHookInstalled = true;
      process.once('exit', () => {
        for (const running of activePhase3Children) {
          if (process.platform !== 'win32') {
            try { process.kill(-running.pid, 'SIGTERM'); } catch {}
          }
        }
      });
    }
    const configuredTimeoutMs = Number(options.timeoutMs);
    const timeoutMs = Number.isFinite(configuredTimeoutMs) && configuredTimeoutMs > 0
      ? Math.min(Math.max(configuredTimeoutMs, 1_000), 2 * 60 * 60 * 1_000)
      : 30 * 60 * 1_000;
    timer = setTimeout(() => {
      if (settled) return;
      const error = new Error('phase3 超时');
      error.code = 'PHASE3_TIMEOUT';
      requestTermination(error);
    }, timeoutMs);
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      error.details = {
        code: null,
        signal: null,
        stdout: readOutput('stdout'),
        stderr: readOutput('stderr'),
        outputTruncated,
        stdoutBytes: observedBytes.stdout,
        stderrBytes: observedBytes.stderr,
      };
      cleanup();
      reject(error);
    });
    // `exit` can fire before stdout/stderr have emitted their final chunks.
    // Wait for `close` so account-deactivation markers are available to the
    // classifier before the job is rejected.
    child.once('close', (code, signal) => {
      if (settled) return;
      clearTimeout(timer);
      const result = {
        code,
        signal,
        stdout: readOutput('stdout'),
        stderr: readOutput('stderr'),
        outputTruncated,
        stdoutBytes: observedBytes.stdout,
        stderrBytes: observedBytes.stderr,
      };
      if (terminationError) {
        closeResult = result;
        settleTerminatedCommand(false);
        return;
      }
      settled = true;
      cleanup();
      if (code !== 0) {
        const error = new Error('phase3 进程失败（退出码 ' + String(code) + '）');
        error.details = result;
        reject(error);
      } else resolve(result);
    });
  });
}

async function runPhase3JobNow({
  email,
  phone,
  actor = 'local',
  db,
  jobId,
  logger = null,
  signal = null,
  persistSuccess = null,
}) {
  throwIfJobInterrupted(signal);
  const startedAt = Date.now();
  let entry = null;
  let rootHandle = null;
  let scriptHandle = null;
  let nodeHandle = null;
  writeLog(logger, 'info', 'phase3.started', {
    jobId,
    actor,
    email: email || null,
    phone: phone || null,
  });
  try {
    if (process.env.PANEL_PHASE3_ENABLED !== '1') {
      const error = new Error('Phase 3 未启用，请设置 PANEL_PHASE3_ENABLED=1 后重启面板');
      error.code = 'PHASE3_DISABLED';
      throw error;
    }
    const root = registerRoot();
    rootHandle = openPinnedPhase3Root(root);
    entry = findUsernameEntry({ email, phone }, rootHandle);
    const scriptPath = path.join(rootHandle.traversalPath, 'index.js');
    scriptHandle = openPinnedRegularFile(scriptPath, 'gpt_register/index.js', { parentPinned: true });
    const nodePath = path.resolve(process.env.GPT_REGISTER_NODE_PATH || process.execPath);
    nodeHandle = openPinnedRegularFile(nodePath, 'GPT_REGISTER_NODE_PATH', { executable: true });
    const beforeSources = readGptRegisterSources({ rootDirectory: root, rootHandle });
    const beforeTokens = beforeSources.tokens
      .filter((item) => item.historical !== true && item.parseStatus === 'ok' && item.email === entry.email)
      .map((item) => ({
        relativePath: item.relativePath,
        mtimeMs: item.mtimeMs,
        access: item.fingerprints?.access || null,
        refresh: item.fingerprints?.refresh || null,
      }));
    writeLog(logger, 'info', 'phase3.account_resolved', {
      jobId,
      actor,
      email: entry.email,
      createdAt: entry.createdAt,
    });
    const processStartedAt = Date.now();
    writeLog(logger, 'info', 'phase3.process_started', {
      jobId,
      actor,
      email: entry.email,
      command: path.basename(nodePath),
      script: 'index.js',
    });
    let result;
    let interruptionError = null;
    try {
      throwIfJobInterrupted(signal);
      const phase3Argument = phone && entry.phone
        ? '--phone=' + entry.phone
        : '--email=' + entry.email;
      const pinnedRootPath = rootHandle.sharedTraversalPath;
      result = await runCommand(sharedDescriptorPath(nodeHandle.descriptor), [
        '--preserve-symlinks',
        '--preserve-symlinks-main',
        '-e',
        phase3LauncherSource(),
        '--',
        pinnedRootPath,
        '--phase3',
        phase3Argument,
      ], {
        cwd: pinnedRootPath,
        env: phase3Environment(),
        timeoutMs: process.env.PANEL_PHASE3_TIMEOUT_MS,
        maxOutputBytes: process.env.PANEL_PHASE3_MAX_OUTPUT_BYTES,
        terminationGraceMs: process.env.PANEL_PHASE3_KILL_GRACE_MS,
        extraFileDescriptors: [scriptHandle.descriptor],
        signal,
      });
    } catch (error) {
      const shutdownInterruption = error?.code === 'JOB_INTERRUPTED';
      classifyPhase3ProcessError(error, entry, rootHandle);
      const processSummary = phase3ProcessSummary(error?.details);
      writeLog(logger, shutdownInterruption ? 'warn' : 'error', shutdownInterruption
        ? 'phase3.process_interrupted'
        : 'phase3.process_failed', {
        jobId,
        actor,
        email: entry.email,
        durationMs: Date.now() - processStartedAt,
        ...processSummary,
        error: redactText(String(error?.message || error)),
      });
      if (!shutdownInterruption || error?.accountDisposition === 'discard') throw error;
      // The child may have atomically published a valid token immediately
      // before SIGTERM. Preserve the interruption while checking that
      // irreversible output below; only a confirmed changed token can turn
      // this race into success.
      interruptionError = error;
      result = error?.details || {};
    }
    const processSummary = phase3ProcessSummary(result);
    if (!interruptionError) {
      writeLog(logger, 'info', 'phase3.process_completed', {
        jobId,
        actor,
        email: entry.email,
        durationMs: Date.now() - processStartedAt,
        ...processSummary,
      });
      const processMarker = new Error('phase3 进程报告了账号状态异常');
      processMarker.details = result;
      classifyPhase3ProcessError(processMarker, entry, rootHandle);
      if (processMarker.accountDisposition === 'discard') throw processMarker;
    }
    const sources = readGptRegisterSources({ rootDirectory: root, rootHandle });
    const beforeByPath = new Map(beforeTokens.map((item) => [item.relativePath, item]));
    const changedTokens = sources.tokens
      .filter((item) => item.historical !== true && item.parseStatus === 'ok' && item.email === entry.email)
      .filter((item) => {
        const before = beforeByPath.get(item.relativePath);
        if (!before) return true;
        const fingerprintChanged = before.access !== item.fingerprints?.access
          || before.refresh !== item.fingerprints?.refresh;
        const mtimeChangedWithoutFingerprint = !before.access
          && Number(item.mtimeMs) > Number(before.mtimeMs || 0)
          && Number(item.mtimeMs) >= startedAt;
        return fingerprintChanged || mtimeChangedWithoutFingerprint;
      })
      .sort((left, right) => right.mtimeMs - left.mtimeMs);
    const token = changedTokens[0];
    if (!token) {
      if (interruptionError) throw interruptionError;
      const error = new Error('phase3 已退出，但没有检测到对应的 token 变化');
      error.code = 'PHASE3_TOKEN_UNCHANGED';
      throw error;
    }
    writeLog(logger, 'info', 'phase3.token_detected', {
      jobId,
      actor,
      email: entry.email,
      tokenFile: token.relativePath,
      fingerprint: token.fingerprints?.access || null,
    });
    const output = {
      email: entry.email,
      tokenFile: token.relativePath,
      fingerprint: token.fingerprints?.access || null,
      process: processSummary,
    };
    if (interruptionError) output.interruptedAfterToken = true;
    if (typeof persistSuccess === 'function') {
      try {
        // Token creation is the irreversible Phase3 side effect. Persist its
        // terminal result before secondary audit/log writes to minimize the
        // window in which a process crash could make completed work look
        // retryable.
        await persistSuccess(output);
      } catch (jobError) {
        // The observer immediately repeats this bounded, idempotent write.
        // Never turn an already-created token into a retryable Phase3 failure
        // solely because the first local terminal update was unavailable.
        writeLog(logger, 'error', 'phase3.job_update_deferred', {
          jobId,
          actor,
          email: entry.email,
          error: redactText(String(jobError?.message || jobError)),
        });
      }
    }
    try {
      await db?.audit({
        jobId,
        actor,
        action: 'phase3',
        targetKey: 'email:' + entry.email,
        afterFingerprint: token.fingerprints?.access || null,
        result: 'ok',
        details: { tokenFile: token.relativePath },
      });
    } catch (auditError) {
      // The browser flow and token write are already complete. Audit storage
      // failure must not turn success into a retry that repeats Phase3.
      writeLog(logger, 'error', 'phase3.audit_failed_after_success', {
        jobId,
        actor,
        email: entry.email,
        error: redactText(String(auditError?.message || auditError)),
      });
    }
    writeLog(logger, 'info', 'phase3.completed', {
      jobId,
      actor,
      email: entry.email,
      tokenFile: token.relativePath,
      fingerprint: token.fingerprints?.access || null,
      durationMs: Date.now() - startedAt,
    });
    return output;
  } catch (error) {
    classifyPhase3ProcessError(error, entry, rootHandle);
    if (entry && error?.accountDisposition === 'discard') {
      try {
        persistAccountDisposition(entry, error.code, rootHandle);
        writeLog(logger, 'warn', 'phase3.account_discarded', {
          jobId,
          actor,
          email: entry.email,
          status: 'account_deleted',
          code: error.code || null,
        });
      } catch (dispositionError) {
        writeLog(logger, 'error', 'phase3.account_disposition_failed', {
          jobId,
          actor,
          email: entry.email,
          error: redactText(String(dispositionError?.message || dispositionError)),
        });
      }
    }
    writeLog(logger, 'error', 'phase3.failed', {
      jobId,
      actor,
      email: email || null,
      durationMs: Date.now() - startedAt,
      error: redactText(String(error?.message || error)),
      code: error?.code || null,
    });
    throw error;
  } finally {
    closeRegularFileHandle(scriptHandle);
    closeRegularFileHandle(nodeHandle);
    closeDirectoryHandle(rootHandle);
  }
}

function phase3Key({ email, phone } = {}) {
  const normalizedEmail = normalizeEmail(email);
  if (normalizedEmail) return 'email:' + normalizedEmail;
  const normalizedPhone = normalizePhone(phone);
  return normalizedPhone ? 'phone:' + normalizedPhone : null;
}

function phase3Keys({ email, phone } = {}) {
  return [
    normalizeEmail(email) ? 'email:' + normalizeEmail(email) : null,
    normalizePhone(phone) ? 'phone:' + normalizePhone(phone) : null,
  ].filter(Boolean);
}

function safeProvidedCanonicalKeys(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 2) return null;
  const keys = value
    .map((key) => String(key || '').trim().toLowerCase())
    .filter((key) => /^(?:email:[^\s]{1,320}|phone:\d{1,80})$/.test(key));
  return keys.length > 0 ? [...new Set(keys)].sort() : null;
}

function resolvePhase3Requests(requests = []) {
  const root = registerRoot();
  const sources = readGptRegisterSources({
    rootDirectory: root,
    requireValidUsername: true,
    usernameMaxBytes: phase3UsernameMaxBytes(),
    usernameMaxRecords: usernameRecordLimit(),
  });
  const records = sources.usernames || [];
  const eligible = [];
  const rejected = [];
  for (const request of requests) {
    const email = normalizeEmail(request?.email);
    const phone = normalizePhone(request?.phone);
    const matches = records.filter((record) => {
      const emailMatches = email && normalizeEmail(record?.email) === email;
      const phoneMatches = phone && normalizePhone(record?.phone) === phone;
      if (email && phone) return emailMatches && phoneMatches;
      return emailMatches || phoneMatches;
    });
    let code = null;
    let message = null;
    const record = matches.length === 1 ? matches[0] : null;
    if (matches.length === 0) {
      code = 'phase3_account_not_found';
      message = 'username.json 中未找到该账号';
    } else if (matches.length > 1) {
      code = 'phase3_account_ambiguous';
      message = 'username.json 中存在多个匹配账号';
    } else if (!record.hasPassword) {
      code = 'phase3_password_missing';
      message = '该账号缺少可用于 Phase 3 的密码';
    } else if (TERMINAL_ACCOUNT_STATUSES.has(String(record.status || '').trim().toLowerCase())) {
      code = 'phase3_account_terminal';
      message = '该账号已是终态，不能再次执行 Phase 3';
    }
    if (code) {
      rejected.push({
        index: request?.originalIndex,
        email: email || null,
        phone: phone || null,
        error: code,
        message,
      });
      continue;
    }
    const resolvedEmail = normalizeEmail(record.email) || email;
    const resolvedPhone = normalizePhone(record.phone) || phone;
    const canonicalKeys = phase3Keys({ email: resolvedEmail, phone: resolvedPhone }).sort();
    eligible.push({
      ...request,
      email: resolvedEmail,
      phone: resolvedPhone || null,
      canonicalKeys,
    });
  }
  return { eligible, rejected };
}

function canonicalPhase3Keys(args = {}) {
  const provided = safeProvidedCanonicalKeys(args.canonicalKeys);
  if (provided) return provided;
  const keys = new Set(phase3Keys(args));
  try {
    const records = readRegularJsonArraySnapshot(
      path.join(registerRoot(), 'username.json'),
      'username.json',
    ).records;
    const normalizedEmail = normalizeEmail(args.email);
    const normalizedPhone = normalizePhone(args.phone);
    const matches = records.filter((item) => {
      const emailMatches = normalizedEmail && normalizeEmail(item?.email) === normalizedEmail;
      const phoneMatches = normalizedPhone && normalizePhone(item?.phone) === normalizedPhone;
      if (normalizedEmail && normalizedPhone) return emailMatches && phoneMatches;
      return emailMatches || phoneMatches;
    });
    const record = matches.length === 1 ? matches[0] : null;
    if (record) {
      if (normalizeEmail(record.email)) keys.add('email:' + normalizeEmail(record.email));
      if (normalizePhone(record.phone)) keys.add('phone:' + normalizePhone(record.phone));
    }
  } catch {
    // The definitive username/password validation happens when the worker runs.
  }
  return [...keys];
}

function getActivePhase3Job({ email, phone } = {}) {
  for (const key of canonicalPhase3Keys({ email, phone })) {
    const active = activePhase3Jobs.get(key);
    if (active) return active;
  }
  return null;
}

function runPhase3Job(args = {}) {
  const keys = canonicalPhase3Keys(args);
  const key = keys[0] || null;
  if (!key) return Promise.reject(new Error('email 或 phone 必须提供一个'));
  const duplicate = keys.map((item) => activePhase3Jobs.get(item)).find(Boolean);
  if (duplicate) {
    const error = new Error('该账号已有 Phase 3 任务排队或运行中');
    error.code = 'PHASE3_DUPLICATE';
    error.existingJobId = duplicate.jobId || null;
    return Promise.reject(error);
  }
  const queuedAt = Date.now();
  const activeRecord = {
    jobId: args.jobId || null,
    email: normalizeEmail(args.email),
    phone: normalizePhone(args.phone) || null,
    queuedAt,
  };
  for (const activeKey of keys) activePhase3Jobs.set(activeKey, activeRecord);
  writeLog(args.logger, 'info', 'phase3.queued', {
    jobId: args.jobId || null,
    actor: args.actor || 'local',
    email: normalizeEmail(args.email) || null,
    phone: String(args.phone || '').trim() || null,
    queueWaitMs: null,
  });
  const run = phase3Queue.then(async () => {
    throwIfJobInterrupted(args.signal);
    const queueWaitMs = Date.now() - queuedAt;
    writeLog(args.logger, 'info', 'phase3.started_after_queue', {
      jobId: args.jobId || null,
      actor: args.actor || 'local',
      email: normalizeEmail(args.email) || null,
      phone: String(args.phone || '').trim() || null,
      queueWaitMs,
    });
    return withControlPlaneLock(async () => {
      throwIfJobInterrupted(args.signal);
      // A job waiting behind another panel process is still queued. Mark it
      // running only after the cross-process lease has actually been acquired.
      if (args.db && args.jobId) {
        await args.db.updateJob(args.jobId, {
          status: 'running',
          startedAt: new Date().toISOString(),
        });
      }
      throwIfJobInterrupted(args.signal);
      return runPhase3JobNow(args);
    });
  }).finally(() => {
    for (const activeKey of keys) {
      if (activePhase3Jobs.get(activeKey) === activeRecord) activePhase3Jobs.delete(activeKey);
    }
  });
  phase3Queue = run.catch(() => {});
  return run;
}

module.exports = {
  findUsernameEntry,
  canonicalPhase3Keys,
  resolvePhase3Requests,
  persistAccountDisposition,
  getActivePhase3Job,
  runCommand,
  runPhase3Job,
  sanitizeLog,
};
