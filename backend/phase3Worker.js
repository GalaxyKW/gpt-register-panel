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
const { isExpired, isExpiryInvalid } = require('./diff');
const { normalizeEmail } = require('./lib/token');
const { phase3TargetRevisionMatches } = require('./phase3TargetRevision');
const { assertAuditLogCheckpoint, redactText } = require('./logger');
const { queueCancelableRun, withControlPlaneLock } = require('./taskCoordinator');
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
let phase3ProcessTreeUnsafe = false;
// Phase3 reads credentials from this file, so callers may lower the limit but
// cannot configure away the process-level allocation bound.
const PHASE3_USERNAME_DEFAULT_MAX_BYTES = 32 * 1024 * 1024;
const PHASE3_USERNAME_HARD_MAX_BYTES = 32 * 1024 * 1024;
// Keep the complete TERM -> KILL -> verification path below the server's
// default ten-second shutdown drain so token reconciliation and terminal job
// persistence retain their own bounded window.
const PHASE3_TERMINATION_GRACE_DEFAULT_MS = 4000;
const PHASE3_TERMINATION_GRACE_MAX_MS = 4000;
const PHASE3_FINAL_KILL_WAIT_MS = 1000;
const PHASE3_FINAL_KILL_WAIT_MAX_MS = 1000;
const PHASE3_TERMINATION_MAX_TOTAL_MS = PHASE3_TERMINATION_GRACE_MAX_MS
  + PHASE3_FINAL_KILL_WAIT_MAX_MS;
const PHASE3_DESCENDANT_LIMIT = 4096;
const PHASE3_PROC_ENV_MAX_BYTES = 64 * 1024;
const PHASE3_PROC_ENV_SCAN_MAX_BYTES = 8 * 1024 * 1024;
const PHASE3_SUPERVISION_ENV_NAME = 'GPT_REGISTER_PANEL_SUPERVISION_ID';
const PHASE3_SCRIPT_CHILD_FD = 3;
const PHASE3_NODE_CHILD_FD = 4;
const PHASE3_ROOT_CHILD_FD = 5;
// Phase3 admission baselines may cover passwords and complete token files.
// Keep their authentication key process-local so neither a persisted job nor
// an API response exposes a reusable/offline-guessable content digest.
const PHASE3_EXECUTION_BINDING_SECRET = crypto.randomBytes(32);
const READ_ONLY_NOFOLLOW = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);

function registerRoot() {
  return path.resolve(process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register');
}

function phase3SupervisionError() {
  const error = new Error('此前 Phase3 子进程树未能确认退出；重启并核对账号状态前禁止继续执行');
  error.code = 'PHASE3_SUPERVISION_UNSAFE';
  return error;
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

function sameLinuxProcess(left, right) {
  return Boolean(left && right
    && left.pid === right.pid
    && left.startId === right.startId
    && left.cgroup === right.cgroup);
}

function procEnvironmentContains(pid, name, value, scanBudget) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      '/proc/' + String(pid) + '/environ',
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const marker = Buffer.from(String(name) + '=' + String(value) + '\0');
    const chunks = [];
    let total = 0;
    while (total < PHASE3_PROC_ENV_MAX_BYTES && scanBudget.remaining > 0) {
      const buffer = Buffer.allocUnsafe(Math.min(
        8 * 1024,
        PHASE3_PROC_ENV_MAX_BYTES - total,
        scanBudget.remaining,
      ));
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead <= 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
      scanBudget.remaining -= bytesRead;
    }
    const environment = Buffer.concat(chunks, total);
    let offset = environment.indexOf(marker);
    while (offset >= 0) {
      if (offset === 0 || environment[offset - 1] === 0) return true;
      offset = environment.indexOf(marker, offset + 1);
    }
    return false;
  } catch {
    return false;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function captureLinuxSupervisedProcesses({
  supervisionId,
  expectedCgroup,
  excludedPids = new Set(),
  tracked,
}) {
  if (process.platform !== 'linux' || !supervisionId || !expectedCgroup) return;
  let processIds;
  try {
    processIds = fs.readdirSync('/proc')
      .filter((value) => /^\d+$/.test(value))
      .map(Number)
      .filter((value) => Number.isSafeInteger(value) && value > 1)
      // Newly spawned descendants normally have the highest PIDs. Scan them
      // first so the aggregate environ-read ceiling cannot be consumed by
      // unrelated long-running processes in a shared development cgroup.
      .sort((left, right) => right - left);
  } catch {
    return;
  }
  const scanBudget = { remaining: PHASE3_PROC_ENV_SCAN_MAX_BYTES };
  for (const pid of processIds) {
    if (scanBudget.remaining <= 0) break;
    if (tracked.size >= PHASE3_DESCENDANT_LIMIT || excludedPids.has(pid)) continue;
    const before = linuxProcessIdentity(pid);
    if (!before || before.cgroup !== expectedCgroup || ['Z', 'X'].includes(before.state)) continue;
    if (!procEnvironmentContains(
      pid,
      PHASE3_SUPERVISION_ENV_NAME,
      supervisionId,
      scanBudget,
    )) continue;
    // `/proc` enumeration and environ reads are not atomic. Re-read the
    // immutable process start id before retaining or signalling this PID so a
    // recycled PID can never turn into an unrelated kill target.
    const after = linuxProcessIdentity(pid);
    if (!sameLinuxProcess(before, after) || ['Z', 'X'].includes(after.state)) continue;
    if (!tracked.has(pid)) tracked.set(pid, { ...after, depth: PHASE3_DESCENDANT_LIMIT });
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
        || current.startId !== expected.startId || current.cgroup !== expected.cgroup) {
      tracked.delete(expected.pid);
      continue;
    }
    active.push({ ...expected, processGroupId: current.processGroupId });
  }
  return active;
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
    let pinnedStat;
    try { pinnedStat = fs.statSync(handle.traversalPath); } catch {}
    if (!handle.procPinned || !/^\/proc\/self\/fd\/\d+$/.test(handle.traversalPath || '')
        || !sameFileIdentity(handle.stat, pinnedStat)) {
      const error = new Error('当前平台无法固定 GPT_REGISTER_ROOT，拒绝执行 Phase3');
      error.code = 'PHASE3_PATH_PIN_UNAVAILABLE';
      throw error;
    }
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

// This launcher is deliberately constant. The verified index.js, Node binary
// and source root are inherited directly as child descriptors instead of
// resolving descriptors from the parent process. Compile the descriptor-
// backed source as the real main module so gpt_register's
// `require.main === module` entrypoint runs normally.
const PHASE3_LAUNCHER_SOURCE = [
  `'use strict';`,
  "const fs = require('node:fs');",
  "const Module = require('node:module');",
  `const root = '/proc/self/fd/${PHASE3_ROOT_CHILD_FD}';`,
  'const forwarded = process.argv.slice(1);',
  `if (!fs.fstatSync(${PHASE3_SCRIPT_CHILD_FD}).isFile()`,
  `    || !fs.fstatSync(${PHASE3_NODE_CHILD_FD}).isFile()`,
  `    || !fs.fstatSync(${PHASE3_ROOT_CHILD_FD}).isDirectory()) {`,
  "  throw new Error('invalid inherited Phase3 descriptors');",
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

function phase3ExecutionDigest(scope, value) {
  return crypto.createHmac('sha256', PHASE3_EXECUTION_BINDING_SECRET)
    .update(String(scope))
    .update('\0')
    .update(JSON.stringify(value === undefined ? null : value))
    .digest('hex');
}

function executionDigestsEqual(left, right) {
  if (!/^[a-f0-9]{64}$/.test(String(left || ''))
      || !/^[a-f0-9]{64}$/.test(String(right || ''))) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function phase3BindingError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function usernameExecutionDigest(index, record) {
  return phase3ExecutionDigest('phase3-username-record-v1', [index, record]);
}

function tokenSelectionKey(token) {
  return 'token:' + String(token?.source || '') + ':' + String(token?.relativePath || '');
}

function tokenExecutionDigest(token) {
  return phase3ExecutionDigest('phase3-token-record-v1', [
    token?.source || null,
    token?.relativePath || null,
    token?.contentHash || null,
    token?.parseStatus || null,
    token?.historical === true,
    normalizeEmail(token?.email) || null,
    token?.accountId || null,
    token?.userId || null,
  ]);
}

function createTokenExecutionBinding(token, selectedKey) {
  return Object.freeze({
    version: 1,
    selectedKey,
    source: token.source,
    relativePath: token.relativePath,
    digest: tokenExecutionDigest(token),
  });
}

function assertTokenExecutionBinding(binding, sources, entry, request = {}) {
  if (!binding || binding.version !== 1
      || !['tokens', 'use_token'].includes(binding.source)
      || typeof binding.relativePath !== 'string'
      || tokenSelectionKey(binding) !== binding.selectedKey
      || !/^[a-f0-9]{64}$/.test(String(binding.digest || ''))) {
    throw phase3BindingError(
      'PHASE3_SOURCE_BINDING_INVALID',
      'Phase3 本地 token 执行绑定无效，拒绝启动',
    );
  }
  const matches = (sources?.tokens || []).filter((token) => (
    tokenSelectionKey(token) === binding.selectedKey
  ));
  const token = matches.length === 1 ? matches[0] : null;
  const tokenEmail = normalizeEmail(token?.email);
  const requestEmail = normalizeEmail(request.email);
  const requestPhone = normalizePhone(request.phone);
  if (!token || token.historical === true || token.parseStatus !== 'ok'
      || !executionDigestsEqual(binding.digest, tokenExecutionDigest(token))
      || !tokenEmail || tokenEmail !== entry.email
      || (requestEmail && requestEmail !== tokenEmail)
      || (requestPhone && requestPhone !== entry.phone)) {
    throw phase3BindingError(
      'PHASE3_SOURCE_BINDING_CHANGED',
      '所选本地 token 在排队期间已变化，拒绝启动 Phase3',
    );
  }
  return token;
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

function findUsernameEntry({
  email,
  phone,
  expectedFileContentHash = null,
  createExecutionBinding = false,
  expectedExecutionBinding = null,
} = {}, rootHandle = null) {
  const snapshot = readRegularJsonArraySnapshot(
    usernameFilePath(rootHandle),
    'username.json',
    { parentPinned: Boolean(rootHandle) },
  );
  if (expectedFileContentHash !== null
      && snapshot.contentHash !== expectedFileContentHash) {
    throw phase3BindingError(
      'PHASE3_USERNAME_CHANGED_DURING_ADMISSION',
      'username.json 在 Phase3 入队检查期间发生变化',
    );
  }
  const records = snapshot.records;
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
  const entry = {
    index,
    email: normalizeEmail(record.email),
    phone: normalizePhone(record.phone),
    createdAt: record.createdAt || null,
    recordFingerprint: recordFingerprint(record),
    transitionBaseFingerprint: phase3TransitionBaseFingerprint(record),
    resolvedAtMs: Date.now(),
  };
  const currentExecutionDigest = usernameExecutionDigest(index, record);
  if (expectedExecutionBinding) {
    const validBinding = expectedExecutionBinding.version === 1
      && Number.isSafeInteger(expectedExecutionBinding.index)
      && expectedExecutionBinding.index >= 0
      && typeof expectedExecutionBinding.email === 'string'
      && typeof expectedExecutionBinding.phone === 'string'
      && /^[a-f0-9]{64}$/.test(String(expectedExecutionBinding.digest || ''));
    if (!validBinding
        || expectedExecutionBinding.index !== index
        || expectedExecutionBinding.email !== entry.email
        || expectedExecutionBinding.phone !== entry.phone
        || !executionDigestsEqual(expectedExecutionBinding.digest, currentExecutionDigest)) {
      throw phase3BindingError(
        'PHASE3_USERNAME_BINDING_CHANGED',
        'username.json 目标账号在排队期间已变化，拒绝启动 Phase3',
      );
    }
  }
  if (createExecutionBinding) {
    Object.defineProperty(entry, 'executionBinding', {
      value: Object.freeze({
        version: 1,
        index,
        email: entry.email,
        phone: entry.phone,
        digest: currentExecutionDigest,
      }),
      enumerable: false,
      configurable: false,
      writable: false,
    });
  }
  return entry;
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
  let replacementStarted = false;
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
    // Once rename has been dispatched, a thrown error can no longer prove
    // whether the new disposition is visible (or durable). Callers must
    // reconcile the pinned username row and must never retry Phase3.
    replacementStarted = true;
    fs.renameSync(temporaryPath, filePath);
    syncDirectory(path.dirname(filePath));
  } catch (error) {
    if (!replacementStarted) throw error;
    const target = error instanceof Error
      ? error
      : new Error('账号处置写入结果无法确认');
    try {
      Object.assign(target, {
        writeOutcomeUnknown: true,
        requiresReconciliation: true,
        retryAllowed: false,
        doNotRetry: true,
        reconciliationScope: 'phase3_account_disposition',
        reconciliationReason: 'account_disposition_write_unknown',
      });
    } catch {
      const wrapped = new Error('账号处置写入结果无法确认');
      wrapped.code = 'PHASE3_ACCOUNT_DISPOSITION_WRITE_UNKNOWN';
      wrapped.writeOutcomeUnknown = true;
      wrapped.requiresReconciliation = true;
      wrapped.retryAllowed = false;
      wrapped.doNotRetry = true;
      wrapped.reconciliationScope = 'phase3_account_disposition';
      wrapped.reconciliationReason = 'account_disposition_write_unknown';
      throw wrapped;
    }
    throw target;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    try { fs.unlinkSync(temporaryPath); } catch {}
  }
}

function safePhase3ErrorCode(value, fallback) {
  const code = String(value || '').trim().toUpperCase();
  return /^[A-Z0-9_]{1,96}$/.test(code) ? code : fallback;
}

function phase3DispositionFailure(primaryError, dispositionError) {
  const writeOutcomeUnknown = dispositionError?.writeOutcomeUnknown === true;
  const checkpointUnavailable = dispositionError?.code === 'AUDIT_LOG_UNAVAILABLE';
  const annotations = {
    requiresReconciliation: true,
    retryAllowed: false,
    doNotRetry: true,
    reconciliationScope: 'phase3_account_disposition',
    reconciliationReason: writeOutcomeUnknown
      ? 'account_disposition_write_unknown'
      : checkpointUnavailable
        ? 'account_disposition_checkpoint_unavailable'
        : 'account_disposition_not_persisted',
    dispositionPersisted: writeOutcomeUnknown ? null : false,
    dispositionOutcome: writeOutcomeUnknown ? 'unknown' : 'not_persisted',
    dispositionWriteOutcomeUnknown: writeOutcomeUnknown,
    dispositionErrorCode: safePhase3ErrorCode(
      dispositionError?.code,
      checkpointUnavailable
        ? 'AUDIT_LOG_UNAVAILABLE'
        : 'PHASE3_ACCOUNT_DISPOSITION_WRITE_FAILED',
    ),
  };
  if (writeOutcomeUnknown) annotations.writeOutcomeUnknown = true;

  const target = primaryError instanceof Error
    ? primaryError
    : new Error('Phase3 失败，且账号处置状态需要人工对账');
  try {
    Object.assign(target, annotations);
    return target;
  } catch {
    // Preserve the primary safety code even for a frozen or non-extensible
    // thrown value. Never attach the raw secondary error or its filesystem
    // diagnostics to the replacement error.
    const message = redactText(String(primaryError?.message || '账号处置状态需要人工对账'))
      .slice(0, 1000);
    const wrapped = new Error(message || '账号处置状态需要人工对账');
    wrapped.code = safePhase3ErrorCode(primaryError?.code, 'PHASE3_FAILED');
    if (primaryError?.accountDisposition === 'discard') wrapped.accountDisposition = 'discard';
    if (primaryError?.dispositionCode) {
      wrapped.dispositionCode = safePhase3ErrorCode(
        primaryError.dispositionCode,
        'ACCOUNT_DEACTIVATED',
      );
    }
    Object.assign(wrapped, annotations);
    return wrapped;
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
  const safeSignal = (signal) => typeof signal === 'string' && /^[A-Z0-9]{1,32}$/.test(signal)
    ? signal
    : null;
  return {
    code: Number.isSafeInteger(value.code) ? value.code : null,
    signal: safeSignal(value.observedSignal || value.signal),
    requestedSignal: safeSignal(value.requestedSignal),
    observedSignal: safeSignal(value.observedSignal || value.signal),
    terminationConfirmed: value.terminationConfirmed === true,
    remainingDescendantCount: Number.isSafeInteger(value.remainingDescendantCount)
      ? Math.max(0, Math.min(PHASE3_DESCENDANT_LIMIT, value.remainingDescendantCount))
      : 0,
    rootProcessRemaining: value.rootProcessRemaining === true,
    forcedClose: value.forcedClose === true,
    outputTruncated: value.outputTruncated === true,
    stdoutBytes: boundedByteCount(value.stdoutBytes) || Buffer.byteLength(stdout, 'utf8'),
    stderrBytes: boundedByteCount(value.stderrBytes) || Buffer.byteLength(stderr, 'utf8'),
  };
}

function phase3TokenPostflightError(cause) {
  const error = new Error('Phase 3 已执行，但无法确认 token 输出；必须人工对账，禁止直接重试');
  error.code = 'PHASE3_TOKEN_POSTFLIGHT_UNKNOWN';
  error.writeOutcomeUnknown = true;
  error.requiresReconciliation = true;
  error.retryAllowed = false;
  error.doNotRetry = true;
  error.reconciliationScope = 'phase3_token_output';
  error.reconciliationReason = 'phase3_postflight_source_unavailable';
  if (cause) error.cause = cause;
  return error;
}

function classifyPhase3ProcessError(error, entry = null, rootHandle = null) {
  const details = error?.details || {};
  const hasProcessDetails = details && typeof details === 'object'
    && ['code', 'signal', 'requestedSignal', 'observedSignal', 'terminationConfirmed',
      'remainingDescendantCount', 'rootProcessRemaining', 'stdout', 'stderr', 'forcedClose',
      'outputTruncated', 'stdoutBytes', 'stderrBytes'].some((key) => Object.hasOwn(details, key));
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
    const supervisionFailure = error?.code === 'PHASE3_TERMINATION_UNCONFIRMED';
    // A leaked process tree is the primary safety failure even when the child
    // also wrote a terminal account disposition. Preserve that supervision
    // code so callers keep Phase3 poisoned, while recording the independent
    // account disposition under its own code.
    error.dispositionCode = 'ACCOUNT_DEACTIVATED';
    if (!supervisionFailure) error.code = 'ACCOUNT_DEACTIVATED';
    error.retryable = false;
    error.accountDisposition = 'discard';
    if (!supervisionFailure) error.message = 'OpenAI 账号已删除或停用';
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
  if (error?.code === 'PHASE3_TERMINATION_UNCONFIRMED') {
    // A still-running supervised process can continue changing token or
    // username state after the panel has stopped observing it. Preserve this
    // primary error and prohibit both disposition writes and automatic retry.
    error.writeOutcomeUnknown = true;
    error.requiresReconciliation = true;
    error.retryAllowed = false;
    error.doNotRetry = true;
    error.reconciliationScope = 'phase3_process_tree';
    error.reconciliationReason = 'phase3_process_tree_unconfirmed';
    if (error.accountDisposition === 'discard') {
      error.dispositionPersisted = false;
      error.dispositionOutcome = 'not_attempted';
      error.dispositionWriteOutcomeUnknown = false;
    }
  }
  return error;
}

function sanitizeLog(value) {
  return redactText(String(value || '')).slice(-12000);
}

function phase3TokenDateMilliseconds(value) {
  const parsed = Date.parse(String(value || ''));
  return Number.isFinite(parsed) ? parsed : 0;
}

function comparePhase3TokenFreshness(left, right, nowMs = Date.now()) {
  const leftExpired = isExpired(left, nowMs);
  const rightExpired = isExpired(right, nowMs);
  if (leftExpired !== rightExpired) return leftExpired ? 1 : -1;
  for (const field of ['expiresAt', 'lastRefresh']) {
    const leftValue = phase3TokenDateMilliseconds(left?.[field]);
    const rightValue = phase3TokenDateMilliseconds(right?.[field]);
    if (leftValue !== rightValue) return leftValue > rightValue ? -1 : 1;
  }
  const leftMtime = Number(left?.mtimeMs) || 0;
  const rightMtime = Number(right?.mtimeMs) || 0;
  if (leftMtime !== rightMtime) return leftMtime > rightMtime ? -1 : 1;
  for (const field of ['access', 'refresh']) {
    const leftPresent = Boolean(left?.fingerprints?.[field]);
    const rightPresent = Boolean(right?.fingerprints?.[field]);
    if (leftPresent !== rightPresent) return leftPresent ? -1 : 1;
  }
  const leftSourcePriority = left?.source === 'tokens' ? 1 : 0;
  const rightSourcePriority = right?.source === 'tokens' ? 1 : 0;
  if (leftSourcePriority !== rightSourcePriority) {
    return leftSourcePriority > rightSourcePriority ? -1 : 1;
  }
  const leftPath = String(left?.relativePath || '');
  const rightPath = String(right?.relativePath || '');
  const naturalOrder = leftPath.localeCompare(
    rightPath,
    'en',
    { numeric: true, sensitivity: 'base' },
  );
  if (naturalOrder !== 0) return naturalOrder;
  if (leftPath === rightPath) return 0;
  const byteOrder = Buffer.compare(Buffer.from(leftPath, 'utf8'), Buffer.from(rightPath, 'utf8'));
  if (byteOrder !== 0) return byteOrder;
  return leftPath < rightPath ? -1 : 1;
}

function isUsablePhase3Token(token, nowMs = Date.now()) {
  return token?.historical !== true
    && token?.parseStatus === 'ok'
    && token?.disabled !== true
    && !isExpiryInvalid(token)
    && !isExpired(token, nowMs);
}

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Logging must never change the outcome of a Phase 3 task.
  }
}

function phase3TerminationBudget(options = {}) {
  const configuredGraceMs = Number(options.terminationGraceMs);
  const graceMs = Number.isFinite(configuredGraceMs) && configuredGraceMs > 0
    ? Math.min(Math.max(Math.floor(configuredGraceMs), 100), PHASE3_TERMINATION_GRACE_MAX_MS)
    : PHASE3_TERMINATION_GRACE_DEFAULT_MS;
  const configuredFinalWaitMs = Number(options.terminationHardDeadlineMs);
  const finalWaitMs = Number.isFinite(configuredFinalWaitMs) && configuredFinalWaitMs > 0
    ? Math.min(Math.max(Math.floor(configuredFinalWaitMs), 100), PHASE3_FINAL_KILL_WAIT_MAX_MS)
    : PHASE3_FINAL_KILL_WAIT_MS;
  return { graceMs, finalWaitMs, totalMs: graceMs + finalWaitMs };
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
    let treeCleanupTimer;
    let descendantSampler;
    let terminationError = null;
    let closeResult = null;
    let cleanupStarted = false;
    let requestedSignal = null;
    let rootIdentity = null;
    let supervisionRecord = null;
    const externalSignal = options.signal;
    let stopForwardingAbort = () => {};
    const trackedDescendants = new Map();
    const supervisionId = crypto.randomBytes(24).toString('hex');
    let descendantCgroup = linuxProcessIdentity(process.pid)?.cgroup || '';
    const captureProcesses = (scanSupervision = false) => {
      if (!child?.pid) return;
      // Sequential browser helpers must not permanently consume the bounded
      // tracking table after they have exited.
      activeTrackedDescendants(trackedDescendants);
      const currentRoot = linuxProcessIdentity(child.pid);
      if (currentRoot && !rootIdentity) rootIdentity = currentRoot;
      descendantCgroup = captureLinuxDescendants(
        child.pid,
        trackedDescendants,
        descendantCgroup,
      );
      if (scanSupervision) {
        captureLinuxSupervisedProcesses({
          supervisionId,
          expectedCgroup: descendantCgroup,
          excludedPids: new Set([process.pid, child.pid]),
          tracked: trackedDescendants,
        });
      }
    };
    const currentRootProcess = () => {
      if (!rootIdentity) return null;
      const current = linuxProcessIdentity(rootIdentity.pid);
      if (!sameLinuxProcess(rootIdentity, current) || ['Z', 'X'].includes(current.state)) return null;
      return current;
    };
    const activeProcessState = () => {
      captureProcesses(true);
      return {
        root: currentRootProcess(),
        descendants: activeTrackedDescendants(trackedDescendants),
      };
    };
    const signalProcessTree = (signal) => {
      if (!child?.pid) return;
      requestedSignal = signal;
      if (process.platform !== 'linux') {
        try { child.kill(signal); } catch {}
        return;
      }
      const state = activeProcessState();
      const processes = [state.root, ...state.descendants].filter(Boolean);
      const ownGroup = linuxProcessIdentity(process.pid)?.processGroupId;
      const grouped = new Map();
      for (const processInfo of processes) {
        const groupId = processInfo.processGroupId;
        if (!grouped.has(groupId)) grouped.set(groupId, []);
        grouped.get(groupId).push(processInfo);
      }
      for (const [groupId, members] of grouped) {
        let groupSignalled = false;
        if (Number.isSafeInteger(groupId) && groupId > 1 && groupId !== ownGroup) {
          try {
            process.kill(-groupId, signal);
            groupSignalled = true;
          } catch {}
        }
        if (groupSignalled) continue;
        for (const expected of members) {
          const latest = linuxProcessIdentity(expected.pid);
          if (!sameLinuxProcess(expected, latest) || ['Z', 'X'].includes(latest.state)) continue;
          try { process.kill(expected.pid, signal); } catch {}
        }
      }
      // A successfully spawned ChildProcess handle cannot refer to a recycled
      // PID before it has been reaped. This fallback covers the very small
      // window in which `/proc/<pid>/stat` is not readable yet.
      if (!state.root && child.exitCode === null && child.signalCode === null) {
        try { child.kill(signal); } catch {}
      }
    };
    const readOutput = (streamName) => {
      const value = Buffer.concat(output[streamName]).toString('utf8')
        .replaceAll(supervisionId, '[REDACTED]');
      return sanitizeLog(value) + (outputTruncated ? '\n[phase3 output truncated]' : '');
    };
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      if (treeCleanupTimer) clearTimeout(treeCleanupTimer);
      if (descendantSampler) clearInterval(descendantSampler);
      stopForwardingAbort();
      if (supervisionRecord) activePhase3Children.delete(supervisionRecord);
    };
    const destroyOutputPipes = () => {
      for (const stream of [child?.stdout, child?.stderr]) {
        if (!stream) continue;
        try { stream.removeAllListeners('data'); } catch {}
        try { stream.destroy(); } catch {}
      }
    };
    const processResult = ({ forcedClose = false, terminationConfirmed = true, state = null } = {}) => ({
      code: closeResult?.code ?? child?.exitCode ?? null,
      // `signal` remains as a compatibility alias, but now means an observed
      // exit signal only. A requested SIGKILL is never reported as observed.
      signal: closeResult?.signal || child?.signalCode || null,
      requestedSignal,
      observedSignal: closeResult?.signal || child?.signalCode || null,
      terminationConfirmed,
      remainingDescendantCount: state?.descendants?.length || 0,
      rootProcessRemaining: Boolean(state?.root),
      stdout: readOutput('stdout'),
      stderr: readOutput('stderr'),
      forcedClose,
      outputTruncated,
      stdoutBytes: observedBytes.stdout,
      stderrBytes: observedBytes.stderr,
    });
    const settleConfirmedCommand = () => {
      if (settled || !closeResult) return false;
      const state = activeProcessState();
      if (state.root || state.descendants.length > 0) return false;
      settled = true;
      const result = processResult({ terminationConfirmed: true, state });
      cleanup();
      if (terminationError) {
        terminationError.details = result;
        reject(terminationError);
      } else if (closeResult.code !== 0) {
        const error = new Error('phase3 进程失败（退出码 ' + String(closeResult.code) + '）');
        error.details = result;
        reject(error);
      } else {
        resolve(result);
      }
      return true;
    };
    const forceUnconfirmedSettlement = () => {
      if (settled) return;
      signalProcessTree('SIGKILL');
      const state = activeProcessState();
      if (settleConfirmedCommand()) return;
      settled = true;
      phase3ProcessTreeUnsafe = true;
      destroyOutputPipes();
      const originalCode = terminationError?.code || null;
      const error = new Error('Phase3 子进程树未能在安全期限内确认退出，已禁止继续执行 Phase3');
      error.code = 'PHASE3_TERMINATION_UNCONFIRMED';
      error.causeCode = originalCode;
      error.details = {
        ...processResult({ forcedClose: true, terminationConfirmed: false, state }),
        causeCode: originalCode,
      };
      // Retain the verified termination callback for the process exit hook.
      if (timer) clearTimeout(timer);
      if (treeCleanupTimer) clearTimeout(treeCleanupTimer);
      if (descendantSampler) clearInterval(descendantSampler);
      stopForwardingAbort();
      reject(error);
    };
    const beginTreeCleanup = () => {
      if (settled || cleanupStarted) return;
      cleanupStarted = true;
      const budget = phase3TerminationBudget(options);
      const killAt = Date.now() + budget.graceMs;
      const hardDeadline = killAt + budget.finalWaitMs;
      let killSent = false;
      signalProcessTree('SIGTERM');
      const check = () => {
        if (settled || settleConfirmedCommand()) return;
        const now = Date.now();
        if (!killSent && now >= killAt) {
          killSent = true;
          signalProcessTree('SIGKILL');
        }
        if (now >= hardDeadline) {
          forceUnconfirmedSettlement();
          return;
        }
        const nextBoundary = killSent ? hardDeadline : killAt;
        treeCleanupTimer = setTimeout(check, Math.min(50, Math.max(1, nextBoundary - now)));
      };
      treeCleanupTimer = setTimeout(check, Math.min(50, budget.graceMs));
    };
    const requestTermination = (error) => {
      if (settled || terminationError) return;
      terminationError = error;
      beginTreeCleanup();
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
    const childEnvironment = { [PHASE3_SUPERVISION_ENV_NAME]: supervisionId };
    for (const [name, value] of Object.entries(options.env || process.env)) {
      if (name !== PHASE3_SUPERVISION_ENV_NAME) childEnvironment[name] = value;
    }
    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        env: childEnvironment,
        shell: false,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe', ...extraFileDescriptors],
      });
    } catch (error) {
      cleanup();
      reject(error);
      return;
    }
    child.once('spawn', () => {
      try {
        if (typeof options.onSpawn === 'function') options.onSpawn();
      } catch {
        // Spawn observers are diagnostic only and must not affect the child.
      }
    });
    supervisionRecord = { terminate: () => signalProcessTree('SIGKILL') };
    activePhase3Children.add(supervisionRecord);
    if (process.platform === 'linux') {
      // A browser helper can leave the original process group before timeout
      // or shutdown. Retain only descendants proven by pid/start-id/cgroup
      // while the parent relationship still exists, then target that bounded
      // set if termination becomes necessary.
      captureProcesses();
      descendantSampler = setInterval(() => captureProcesses(false), 100);
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
          try { running.terminate(); } catch {}
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
      if (terminationError) return;
      if (child?.pid) {
        requestTermination(error);
        return;
      }
      settled = true;
      error.details = processResult({ terminationConfirmed: true });
      cleanup();
      reject(error);
    });
    // `close` waits for every inherited stdio descriptor, so a daemonized
    // helper can keep it pending after the Phase3 leader has already exited.
    // Detect that case at `exit`, terminate only the verified supervised
    // descendants, and still wait for `close` to drain the final output.
    child.once('exit', () => {
      if (settled || cleanupStarted) return;
      const state = activeProcessState();
      if (state.descendants.length > 0) beginTreeCleanup();
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
      closeResult = result;
      // A command can exit while a daemonized browser/helper remains alive
      // with redirected stdio. Resolve/reject only after that supervised tree
      // has also terminated.
      if (!settleConfirmedCommand()) beginTreeCleanup();
    });
  });
}

async function runPhase3JobNow({
  email,
  phone,
  executionBinding = null,
  requireExecutionBinding = false,
  actor = 'local',
  db,
  jobId,
  logger = null,
  signal = null,
  persistSuccess = null,
}) {
  throwIfJobInterrupted(signal);
  if (phase3ProcessTreeUnsafe) throw phase3SupervisionError();
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
    if ((requireExecutionBinding && !executionBinding)
        || (executionBinding && (executionBinding.version !== 1
          || !executionBinding.token || !executionBinding.username))) {
      throw phase3BindingError(
        'PHASE3_EXECUTION_BINDING_INVALID',
        'Phase3 执行目标绑定缺失或无效，拒绝启动',
      );
    }
    const root = registerRoot();
    rootHandle = openPinnedPhase3Root(root);
    const scriptPath = path.join(rootHandle.traversalPath, 'index.js');
    scriptHandle = openPinnedRegularFile(scriptPath, 'gpt_register/index.js', { parentPinned: true });
    const nodePath = path.resolve(process.env.GPT_REGISTER_NODE_PATH || process.execPath);
    nodeHandle = openPinnedRegularFile(nodePath, 'GPT_REGISTER_NODE_PATH', { executable: true });
    const beforeSources = readGptRegisterSources({
      rootDirectory: root,
      rootHandle,
      strictCompleteSnapshot: true,
    });
    entry = findUsernameEntry({
      email,
      phone,
      expectedExecutionBinding: executionBinding?.username || null,
    }, rootHandle);
    if (executionBinding) {
      assertTokenExecutionBinding(executionBinding.token, beforeSources, entry, { email, phone });
    }
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
    let result;
    let processError = null;
    try {
      throwIfJobInterrupted(signal);
      const phase3Argument = phone && entry.phone
        ? '--phone=' + entry.phone
        : '--email=' + entry.email;
      const pinnedRootPath = '/proc/self/fd/' + PHASE3_ROOT_CHILD_FD;
      const command = '/proc/self/fd/' + PHASE3_NODE_CHILD_FD;
      const commandArguments = [
        '--preserve-symlinks',
        '--preserve-symlinks-main',
        '-e',
        phase3LauncherSource(),
        '--',
        '--phase3',
        phase3Argument,
      ];
      const processLogFields = {
        jobId,
        actor,
        email: entry.email,
        command: path.basename(nodePath),
        script: 'index.js',
      };
      const commandOptions = {
        cwd: pinnedRootPath,
        env: phase3Environment(),
        timeoutMs: process.env.PANEL_PHASE3_TIMEOUT_MS,
        maxOutputBytes: process.env.PANEL_PHASE3_MAX_OUTPUT_BYTES,
        terminationGraceMs: process.env.PANEL_PHASE3_KILL_GRACE_MS,
        extraFileDescriptors: [
          scriptHandle.descriptor,
          nodeHandle.descriptor,
          rootHandle.descriptor,
        ],
        signal,
        onSpawn: () => writeLog(logger, 'info', 'phase3.process_started', processLogFields),
      };
      writeLog(logger, 'info', 'phase3.process_starting', processLogFields);
      assertAuditLogCheckpoint(logger, 'phase3.process_spawn_checkpoint', processLogFields);
      result = await runCommand(command, commandArguments, commandOptions);
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
      if (error?.accountDisposition === 'discard'
          || error?.details?.terminationConfirmed !== true) throw error;
      // The child may have atomically published a valid token immediately
      // before a non-zero exit, timeout, output-limit termination or SIGTERM.
      // Only after the complete process tree is confirmed stopped can that
      // irreversible output safely turn the task into success.
      processError = error;
      result = error?.details || {};
    }
    const processSummary = phase3ProcessSummary(result);
    if (!processError) {
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
    let sources;
    try {
      sources = readGptRegisterSources({
        rootDirectory: root,
        rootHandle,
        strictCompleteSnapshot: true,
      });
    } catch (error) {
      throw phase3TokenPostflightError(error);
    }
    const tokenObservedAt = Date.now();
    const beforeByPath = new Map(beforeTokens.map((item) => [item.relativePath, item]));
    const changedTokens = sources.tokens
      .filter((item) => isUsablePhase3Token(item, tokenObservedAt) && item.email === entry.email)
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
      .sort((left, right) => comparePhase3TokenFreshness(left, right, tokenObservedAt));
    const token = changedTokens[0];
    if (!token) {
      if (processError) throw processError;
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
    if (processError) {
      output.processEndedWithError = true;
      output.processErrorCode = /^[A-Z0-9_]{1,96}$/.test(String(processError.code || ''))
        ? processError.code
        : 'PHASE3_PROCESS_FAILED';
      if (processError.code === 'JOB_INTERRUPTED') output.interruptedAfterToken = true;
    }
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
        details: {
          tokenFile: token.relativePath,
          processEndedWithError: output.processEndedWithError === true,
          processErrorCode: output.processErrorCode || null,
        },
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
      processEndedWithError: output.processEndedWithError === true,
      processErrorCode: output.processErrorCode || null,
      durationMs: Date.now() - startedAt,
    });
    return output;
  } catch (error) {
    classifyPhase3ProcessError(error, entry, rootHandle);
    if (entry && error?.accountDisposition === 'discard') {
      if (error?.details?.terminationConfirmed !== true) {
        // The child tree may still be mutating the pinned file. Even an atomic
        // replace here could race a late child write, so leave the row untouched
        // and make the supervision failure the durable reconciliation signal.
        error.dispositionPersisted = false;
        error.dispositionOutcome = 'not_attempted';
        error.dispositionWriteOutcomeUnknown = false;
        writeLog(logger, 'error', 'phase3.account_disposition_deferred', {
          jobId,
          actor,
          email: entry.email,
          code: error.code || null,
          reason: 'phase3_process_tree_unconfirmed',
        });
      } else {
        try {
          const dispositionCode = error.dispositionCode || error.code || 'ACCOUNT_DEACTIVATED';
          assertAuditLogCheckpoint(logger, 'phase3.account_disposition_checkpoint', {
            jobId,
            actor,
            email: entry.email,
            disposition: 'discard',
            status: 'account_deleted',
            code: safePhase3ErrorCode(dispositionCode, 'ACCOUNT_DEACTIVATED'),
          });
          persistAccountDisposition(entry, dispositionCode, rootHandle);
          error.dispositionPersisted = true;
          error.dispositionOutcome = 'persisted';
          error.dispositionWriteOutcomeUnknown = false;
          writeLog(logger, 'warn', 'phase3.account_discarded', {
            jobId,
            actor,
            email: entry.email,
            status: 'account_deleted',
            code: error.code || null,
          });
        } catch (dispositionError) {
          error = phase3DispositionFailure(error, dispositionError);
          writeLog(logger, 'error', 'phase3.account_disposition_failed', {
            jobId,
            actor,
            email: entry.email,
            error: redactText(String(dispositionError?.message || dispositionError)),
            errorCode: error.dispositionErrorCode,
            dispositionOutcome: error.dispositionOutcome,
            writeOutcomeUnknown: error.dispositionWriteOutcomeUnknown === true,
            requiresReconciliation: true,
            doNotRetry: true,
          });
        }
      }
    }
    writeLog(logger, 'error', 'phase3.failed', {
      jobId,
      actor,
      email: email || null,
      durationMs: Date.now() - startedAt,
      error: redactText(String(error?.message || error)),
      code: error?.code || null,
      dispositionOutcome: error?.dispositionOutcome || null,
      writeOutcomeUnknown: error?.writeOutcomeUnknown === true,
      requiresReconciliation: error?.requiresReconciliation === true,
      doNotRetry: error?.doNotRetry === true,
      reconciliationReason: error?.reconciliationReason || null,
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
    strictCompleteSnapshot: true,
    usernameMaxBytes: phase3UsernameMaxBytes(),
    usernameMaxRecords: usernameRecordLimit(),
  });
  const records = sources.usernames || [];
  const eligible = [];
  const rejected = [];
  for (const request of requests) {
    const email = normalizeEmail(request?.email);
    const phone = normalizePhone(request?.phone);
    const selectedKey = typeof request?.selectedKey === 'string'
      ? request.selectedKey.trim()
      : '';
    const selectedTokenMatches = sources.tokens.filter((token) => (
      tokenSelectionKey(token) === selectedKey
    ));
    const selectedToken = selectedTokenMatches.length === 1
      ? selectedTokenMatches[0]
      : null;
    const matches = records.filter((record) => {
      const emailMatches = email && normalizeEmail(record?.email) === email;
      const phoneMatches = phone && normalizePhone(record?.phone) === phone;
      if (email && phone) return emailMatches && phoneMatches;
      return emailMatches || phoneMatches;
    });
    let code = null;
    let message = null;
    const record = matches.length === 1 ? matches[0] : null;
    const revisionEvidence = selectedToken && record ? {
      token: selectedToken,
      username: record,
      usernameContentHash: sources.usernameContentHash,
    } : null;
    if (!phase3TargetRevisionMatches(request?.phase3TargetRevision, revisionEvidence)) {
      code = 'phase3_target_revision_changed';
      message = '所选 Phase 3 目标已变化或快照凭证无效，请刷新后重新选择';
    } else if (!selectedKey || selectedTokenMatches.length !== 1) {
      code = 'phase3_source_not_found';
      message = '所选本地 token 不存在或选择键无效';
    } else if (selectedToken.historical === true) {
      code = 'phase3_source_historical';
      message = '历史 token 不能用于 Phase 3';
    } else if (selectedToken.parseStatus !== 'ok'
        || !/^[a-f0-9]{64}$/.test(String(selectedToken.contentHash || ''))) {
      code = 'phase3_source_invalid';
      message = '所选本地 token 无效，不能用于 Phase 3';
    } else if (email && normalizeEmail(selectedToken.email) !== email) {
      code = 'phase3_source_identity_mismatch';
      message = '所选本地 token 与提交账号不一致';
    } else if (matches.length === 0) {
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
    if (!resolvedEmail || normalizeEmail(selectedToken.email) !== resolvedEmail) {
      rejected.push({
        index: request?.originalIndex,
        email: email || null,
        phone: phone || null,
        error: 'phase3_source_identity_mismatch',
        message: '所选本地 token 与 username.json 目标账号不一致',
      });
      continue;
    }
    const rawEntry = findUsernameEntry({
      email: resolvedEmail,
      phone: resolvedPhone,
      expectedFileContentHash: sources.usernameContentHash,
      createExecutionBinding: true,
    });
    if (rawEntry.index !== record.index
        || rawEntry.email !== resolvedEmail
        || rawEntry.phone !== resolvedPhone) {
      throw phase3BindingError(
        'PHASE3_USERNAME_CHANGED_DURING_ADMISSION',
        'username.json 在 Phase3 入队检查期间发生变化',
      );
    }
    const canonicalKeys = phase3Keys({ email: resolvedEmail, phone: resolvedPhone }).sort();
    const resolvedRequest = {
      ...request,
      email: resolvedEmail,
      phone: resolvedPhone || null,
      canonicalKeys,
      phase3TargetRevision: request.phase3TargetRevision,
    };
    Object.defineProperty(resolvedRequest, 'executionBinding', {
      value: Object.freeze({
        version: 1,
        token: createTokenExecutionBinding(selectedToken, selectedKey),
        username: rawEntry.executionBinding,
      }),
      enumerable: false,
      configurable: false,
      writable: false,
    });
    eligible.push(resolvedRequest);
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
  if (phase3ProcessTreeUnsafe) return Promise.reject(phase3SupervisionError());
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
  const queued = queueCancelableRun(phase3Queue, async () => {
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
        if (typeof args.db.startMutationJob !== 'function') {
          const error = new Error('任务执行安全检查不可用，尚未开始 Phase 3');
          error.code = 'JOB_RECONCILIATION_GUARD_UNAVAILABLE';
          throw error;
        }
        await args.db.startMutationJob(args.jobId);
      }
      throwIfJobInterrupted(args.signal);
      try {
        return await runPhase3JobNow(args);
      } catch (error) {
        if (typeof args.persistFailure === 'function') {
          try {
            // Persist the terminal failure before releasing the global lease.
            // This prevents the next queued worker from mistaking a completed
            // predecessor for a still-running mutation.
            await args.persistFailure(error);
          } catch (jobError) {
            writeLog(args.logger, 'error', 'phase3.job_update_deferred', {
              jobId: args.jobId || null,
              actor: args.actor || 'local',
              terminalOutcome: 'failed',
              error: redactText(String(jobError?.message || jobError)),
            });
          }
        }
        throw error;
      }
    }, { signal: args.signal });
  }, { signal: args.signal });
  phase3Queue = queued.run.catch(() => {});
  return queued.result.finally(() => {
    for (const activeKey of keys) {
      if (activePhase3Jobs.get(activeKey) === activeRecord) activePhase3Jobs.delete(activeKey);
    }
  });
}

module.exports = {
  PHASE3_TERMINATION_MAX_TOTAL_MS,
  classifyPhase3ProcessError,
  comparePhase3TokenFreshness,
  findUsernameEntry,
  canonicalPhase3Keys,
  resolvePhase3Requests,
  persistAccountDisposition,
  getActivePhase3Job,
  runCommand,
  runPhase3Job,
  sanitizeLog,
  phase3TerminationBudget,
};
