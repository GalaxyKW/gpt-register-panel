const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { TextDecoder } = require('node:util');
const {
  normalizeTokenDocument,
  toSafeTokenSummary,
  normalizeEmail,
  parseDateValue,
} = require('../lib/token');
const { assertDirectoryTree } = require('../lib/safeFs');
const { compareNaturalStrings } = require('../lib/stableOrder');
const {
  PHASE3_PHONE_USERNAME_MAX_BYTES,
  normalizePhase3Phone,
} = require('../lib/phase3Identity');
const { redactText } = require('../logger');

const READ_ONLY_FLAGS = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);
const DEFAULT_TOKEN_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_USERNAME_MAX_BYTES = 32 * 1024 * 1024;
const DEFAULT_USERNAME_MAX_RECORDS = 10_000;
const HARD_TOKEN_MAX_BYTES = 16 * 1024 * 1024;
const HARD_USERNAME_MAX_BYTES = 64 * 1024 * 1024;
const HARD_USERNAME_MAX_RECORDS = 100_000;
const DEFAULT_TOKEN_MAX_FILES = 10_000;
const HARD_TOKEN_MAX_FILES = 100_000;
const DEFAULT_TOKEN_MAX_DIRECTORY_ENTRIES = 20_000;
const HARD_TOKEN_MAX_DIRECTORY_ENTRIES = 200_000;
const DEFAULT_TOKEN_TOTAL_MAX_BYTES = 256 * 1024 * 1024;
const HARD_TOKEN_TOTAL_MAX_BYTES = 1024 * 1024 * 1024;
const REQUIRED_SOURCE_NAMES = Object.freeze(['tokens', 'use_token', 'username.json']);
const TOKEN_ONLY_SOURCE_READ = Symbol('token-only-source-read');
const C0_OR_DEL = /[\u0000-\u001f\u007f]/;
const CREDENTIAL_LINE_CONTROL = /[\u0000\u000a\u000d]/;
const UNSAFE_TOKEN_FILE_NAME = /[\\\p{Cc}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
const RESERVED_TOKEN_FILE_PREFIX = '.panel-token-cleanup-claim-';

function decodeUtf8Json(bytes) {
  // Buffer#toString silently replaces malformed byte sequences with U+FFFD.
  // That can turn a damaged credential or identity into a different, yet
  // syntactically valid, JSON value. Source bytes must therefore decode
  // losslessly before they can participate in a snapshot or write plan.
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function gptPathError(label, cause) {
  const error = new Error(label + ' 不存在、不可读取、已变化或包含符号链接');
  error.code = 'GPT_REGISTER_PATH_INVALID';
  if (cause) error.cause = cause;
  return error;
}

function sourceSizeError(label) {
  const error = new Error(label + ' 超过允许的大小上限');
  error.code = 'GPT_REGISTER_FILE_TOO_LARGE';
  return error;
}

function allowlistedMissingSources(values) {
  const requested = new Set(Array.isArray(values) ? values : [values]);
  return REQUIRED_SOURCE_NAMES.filter((source) => requested.has(source));
}

function incompleteSourceError(
  label,
  cause,
  code = 'GPT_REGISTER_SOURCE_INCOMPLETE',
  missingSources = [],
) {
  const error = new Error(label + ' 无法形成完整可信快照');
  error.code = code;
  if (code === 'GPT_REGISTER_SOURCE_MISSING') {
    error.missingSources = Object.freeze(allowlistedMissingSources(missingSources));
  }
  if (cause) error.cause = cause;
  return error;
}

function sourceChangedError(label, cause) {
  return incompleteSourceError(label, cause, 'GPT_REGISTER_SOURCE_CHANGED');
}

function configuredByteLimit(value, fallback, hardMaximum) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1024) return fallback;
  return Math.min(number, hardMaximum);
}

function configuredCountLimit(value, fallback, hardMaximum) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) return fallback;
  return Math.min(number, hardMaximum);
}

function usernameRecordLimit(value = process.env.GPT_REGISTER_USERNAME_MAX_RECORDS) {
  return configuredCountLimit(
    value,
    DEFAULT_USERNAME_MAX_RECORDS,
    HARD_USERNAME_MAX_RECORDS,
  );
}

function tokenDirectoryEntryLimit(value = process.env.GPT_REGISTER_TOKEN_MAX_DIRECTORY_ENTRIES) {
  return configuredCountLimit(
    value,
    DEFAULT_TOKEN_MAX_DIRECTORY_ENTRIES,
    HARD_TOKEN_MAX_DIRECTORY_ENTRIES,
  );
}

function usernameInvalidError(message = 'username.json 账号记录字段无效') {
  const error = new Error(message);
  error.code = 'GPT_REGISTER_USERNAME_INVALID';
  return error;
}

function validateUsernameRecords(records) {
  for (const record of records) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw usernameInvalidError();
    }
    const email = record.email;
    if (typeof email !== 'string'
        || !normalizeEmail(email)) {
      throw usernameInvalidError();
    }
    if (record.password !== undefined && record.password !== null
        && (typeof record.password !== 'string'
          || CREDENTIAL_LINE_CONTROL.test(record.password))) {
      throw usernameInvalidError();
    }
    if (record.status !== undefined && record.status !== null) {
      if (typeof record.status !== 'string'
          || C0_OR_DEL.test(record.status)
          || !/^[a-z0-9_-]{1,64}$/i.test(record.status.trim())) {
        throw usernameInvalidError();
      }
    }
    if (record.phone !== undefined && record.phone !== null) {
      const phone = normalizePhase3Phone(record.phone, {
        maximumBytes: PHASE3_PHONE_USERNAME_MAX_BYTES,
        allowNumber: true,
      });
      if (!phone) {
        throw usernameInvalidError();
      }
    }
    if (record.name !== undefined && record.name !== null
        && (typeof record.name !== 'string'
          || record.name.length > 200
          || C0_OR_DEL.test(record.name))) {
      throw usernameInvalidError();
    }
  }
}

function sameFileIdentity(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function sameStableFileState(left, right) {
  return sameFileIdentity(left, right)
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function assertTrustedOwnerAndMode(stat, label) {
  const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if ((effectiveUid !== null && stat.uid !== effectiveUid) || (stat.mode & 0o022) !== 0) {
    const error = new Error(label + ' 必须由面板进程用户持有，且不可被组或其他用户写入');
    error.code = 'GPT_REGISTER_PATH_PERMISSIONS_INVALID';
    throw error;
  }
}

function nativeRealpath(value) {
  return typeof fs.realpathSync.native === 'function'
    ? fs.realpathSync.native(value)
    : fs.realpathSync(value);
}

function pathIsWithin(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..' + path.sep)
    && relative !== '..' && !path.isAbsolute(relative));
}

function assertWithinRoot(rootRealPath, targetRealPath, label) {
  if (!rootRealPath || !targetRealPath || !pathIsWithin(rootRealPath, targetRealPath)) {
    throw gptPathError(label);
  }
}

function descriptorRealPath(descriptor, label) {
  let procAvailable = false;
  try { procAvailable = fs.statSync('/proc/self/fd').isDirectory(); } catch {}
  if (!procAvailable) return null;
  try {
    return nativeRealpath('/proc/self/fd/' + descriptor);
  } catch (error) {
    // On platforms with /proc, an unresolved descriptor normally means the
    // opened path was renamed or removed during verification. Fail closed.
    throw gptPathError(label, error);
  }
}

function verifyPathStillReferences(openPath, initialStat, descriptorStat, expectedParentReal, label) {
  let latest;
  let current;
  try {
    latest = fs.lstatSync(openPath);
    current = fs.statSync(openPath);
    if (latest.isSymbolicLink()
        || !sameFileIdentity(initialStat, latest)
        || !sameFileIdentity(descriptorStat, current)
        || nativeRealpath(path.dirname(openPath)) !== expectedParentReal) {
      throw gptPathError(label);
    }
  } catch (error) {
    if (['GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID'].includes(error?.code)) {
      throw error;
    }
    throw gptPathError(label, error);
  }
}

function openVerifiedDirectory(logicalPath, options = {}) {
  const label = options.label || 'gpt_register 目录';
  const openPath = options.openPath || logicalPath;
  let initialStat;
  let expectedParentReal;
  let descriptor;
  try {
    initialStat = fs.lstatSync(openPath);
    if (initialStat.isSymbolicLink() || !initialStat.isDirectory()) throw gptPathError(label);
    expectedParentReal = nativeRealpath(path.dirname(openPath));
    descriptor = fs.openSync(openPath, READ_ONLY_FLAGS | (fs.constants.O_DIRECTORY || 0));
    const descriptorStat = fs.fstatSync(descriptor);
    if (!descriptorStat.isDirectory() || !sameFileIdentity(initialStat, descriptorStat)) {
      throw gptPathError(label);
    }
    assertTrustedOwnerAndMode(descriptorStat, label);
    const procTarget = descriptorRealPath(descriptor, label);
    const realPath = procTarget || nativeRealpath(openPath);
    if (options.expectedRealPath && realPath !== options.expectedRealPath) throw gptPathError(label);
    if (options.rootRealPath) assertWithinRoot(options.rootRealPath, realPath, label);
    verifyPathStillReferences(openPath, initialStat, descriptorStat, expectedParentReal, label);
    return {
      descriptor,
      logicalPath: path.resolve(logicalPath),
      realPath,
      stat: descriptorStat,
      traversalPath: procTarget ? '/proc/self/fd/' + descriptor : openPath,
      procPinned: Boolean(procTarget),
      expectedParentReal,
      openPath,
    };
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (['GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID'].includes(error?.code)) {
      throw error;
    }
    throw gptPathError(label, error);
  }
}

function closeDirectoryHandle(handle) {
  if (handle?.descriptor !== undefined) {
    try { fs.closeSync(handle.descriptor); } catch {}
  }
}

function assertDirectoryHandleCurrent(handle, label) {
  if (!handle) throw gptPathError(label);
  let descriptorStat;
  try { descriptorStat = fs.fstatSync(handle.descriptor); } catch (error) {
    throw gptPathError(label, error);
  }
  if (!descriptorStat.isDirectory() || !sameFileIdentity(handle.stat, descriptorStat)) {
    throw gptPathError(label);
  }
  assertTrustedOwnerAndMode(descriptorStat, label);
  if (handle.procPinned) return;
  verifyPathStillReferences(
    handle.openPath,
    handle.stat,
    descriptorStat,
    handle.expectedParentReal,
    label,
  );
}

function openRootDirectory(directory, label) {
  assertDirectoryTree(directory, label);
  let initialStat;
  let expectedRealPath;
  try {
    initialStat = fs.lstatSync(directory);
    expectedRealPath = nativeRealpath(directory);
    const latest = fs.lstatSync(directory);
    if (initialStat.isSymbolicLink() || !initialStat.isDirectory()
        || !sameFileIdentity(initialStat, latest)) throw gptPathError(label);
  } catch (error) {
    if (error?.code === 'GPT_REGISTER_PATH_INVALID') throw error;
    throw gptPathError(label, error);
  }
  return openVerifiedDirectory(directory, {
    label,
    expectedRealPath,
    rootRealPath: expectedRealPath,
  });
}

function childPathContext(rootHandle, rootDirectory, targetPath, label) {
  assertDirectoryHandleCurrent(rootHandle, label);
  const logicalTarget = path.resolve(targetPath);
  const relative = path.relative(path.resolve(rootDirectory), logicalTarget);
  if (relative.startsWith('..' + path.sep) || relative === '..' || path.isAbsolute(relative)) {
    throw gptPathError(label);
  }
  // A caller can intentionally keep a directory descriptor open while the
  // configured pathname is renamed. Resolve child identities from that live
  // descriptor instead of the stale original pathname; traversal remains
  // rooted at the same directory inode throughout the operation.
  const rootRealPath = rootHandle.procPinned
    ? descriptorRealPath(rootHandle.descriptor, label)
    : rootHandle.realPath;
  return {
    logicalPath: logicalTarget,
    openPath: relative ? path.join(rootHandle.traversalPath, relative) : rootHandle.traversalPath,
    expectedRealPath: relative ? path.join(rootRealPath, relative) : rootRealPath,
    rootRealPath,
  };
}

function readDescriptorBounded(descriptor, maximumBytes, label) {
  const chunks = [];
  let total = 0;
  while (true) {
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes - total + 1));
    const count = fs.readSync(descriptor, chunk, 0, chunk.length, null);
    if (count === 0) break;
    total += count;
    if (total > maximumBytes) throw sourceSizeError(label);
    chunks.push(chunk.subarray(0, count));
  }
  return Buffer.concat(chunks, total);
}

function readVerifiedRegularFile(context, label, maximumBytes) {
  let initialStat;
  let expectedParentReal;
  let descriptor;
  try {
    initialStat = fs.lstatSync(context.openPath);
    if (initialStat.isSymbolicLink() || !initialStat.isFile() || initialStat.nlink !== 1) {
      throw gptPathError(label);
    }
    expectedParentReal = nativeRealpath(path.dirname(context.openPath));
    descriptor = fs.openSync(context.openPath, READ_ONLY_FLAGS);
    const descriptorStat = fs.fstatSync(descriptor);
    if (!descriptorStat.isFile() || descriptorStat.nlink !== 1
        || !sameFileIdentity(initialStat, descriptorStat)) {
      throw gptPathError(label);
    }
    assertTrustedOwnerAndMode(descriptorStat, label);
    if (descriptorStat.size > maximumBytes) throw sourceSizeError(label);
    const procTarget = descriptorRealPath(descriptor, label);
    if (procTarget && procTarget !== context.expectedRealPath) throw gptPathError(label);
    if (procTarget) assertWithinRoot(context.rootRealPath, procTarget, label);
    else {
      const realPath = nativeRealpath(context.openPath);
      if (realPath !== context.expectedRealPath) throw gptPathError(label);
      assertWithinRoot(context.rootRealPath, realPath, label);
    }
    verifyPathStillReferences(
      context.openPath,
      initialStat,
      descriptorStat,
      expectedParentReal,
      label,
    );
    const bytes = readDescriptorBounded(descriptor, maximumBytes, label);
    const finalDescriptorStat = fs.fstatSync(descriptor);
    if (finalDescriptorStat.nlink !== 1
        || !sameStableFileState(descriptorStat, finalDescriptorStat)) throw gptPathError(label);
    verifyPathStillReferences(
      context.openPath,
      initialStat,
      finalDescriptorStat,
      expectedParentReal,
      label,
    );
    return { bytes, stat: finalDescriptorStat };
  } catch (error) {
    if (['GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID', 'GPT_REGISTER_FILE_TOO_LARGE']
      .includes(error?.code)) throw error;
    throw gptPathError(label, error);
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function assertReadableDirectory(directory, label) {
  try {
    assertDirectoryTree(directory, label);
    return true;
  } catch (error) {
    // A missing source directory is a valid first-run state. Symlinks,
    // regular files, and other path errors must fail closed instead of
    // silently presenting an empty account pool.
    if (error?.cause?.code === 'ENOENT') return false;
    const wrapped = new Error(label + ' 不存在、不可读取或包含符号链接');
    wrapped.code = 'GPT_REGISTER_PATH_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
}

function assertReadableFileParent(filePath, label) {
  assertReadableDirectory(path.dirname(filePath), label + ' 父目录');
  let stat;
  try { stat = fs.lstatSync(filePath); } catch (error) {
    if (error?.code === 'ENOENT') return false;
    const wrapped = new Error(label + ' 不存在或不可读取');
    wrapped.code = 'GPT_REGISTER_PATH_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    const error = new Error(label + ' 必须是非符号链接普通文件');
    error.code = 'GPT_REGISTER_PATH_INVALID';
    throw error;
  }
  return true;
}

function readJsonArraySnapshot(filePath, options = {}) {
  const fallback = {
    records: [], contentHash: null, mtimeMs: 0, size: 0, present: false, fileState: null,
  };
  const maximumBytes = configuredByteLimit(
    options.maxBytes ?? process.env.GPT_REGISTER_USERNAME_MAX_BYTES,
    DEFAULT_USERNAME_MAX_BYTES,
    HARD_USERNAME_MAX_BYTES,
  );
  let rootHandle = options.rootHandle || null;
  let ownedRootHandle = false;
  try {
    if (!rootHandle) {
      const parent = path.dirname(path.resolve(filePath));
      rootHandle = openRootDirectory(parent, 'JSON 父目录');
      ownedRootHandle = true;
    }
    const rootDirectory = options.rootDirectory || rootHandle.logicalPath;
    const context = childPathContext(rootHandle, rootDirectory, filePath, 'JSON 文件');
    let observed;
    try {
      observed = fs.lstatSync(context.openPath);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        if (options.requireCompleteSnapshot === true) {
          throw incompleteSourceError(
            'gpt_register/username.json',
            error,
            'GPT_REGISTER_SOURCE_MISSING',
            ['username.json'],
          );
        }
        return fallback;
      }
      throw error;
    }
    if (observed.isSymbolicLink() || !observed.isFile()) {
      if (options.strict === true || options.requireCompleteSnapshot === true) {
        throw gptPathError('JSON 文件');
      }
      return { ...fallback, mtimeMs: observed.mtimeMs, size: observed.size };
    }
    const { bytes, stat } = readVerifiedRegularFile(context, 'JSON 文件', maximumBytes);
    assertDirectoryHandleCurrent(rootHandle, 'JSON 父目录');
    const contentHash = crypto.createHash('sha256').update(bytes).digest('hex');
    try {
      const value = JSON.parse(decodeUtf8Json(bytes));
      if (options.requireValidJson === true
          && !Array.isArray(value)
          && (!value || typeof value !== 'object')) {
        const error = new Error('username.json 必须包含账号对象或账号数组');
        error.code = 'GPT_REGISTER_USERNAME_INVALID';
        throw error;
      }
      const records = Array.isArray(value)
        ? value
        : value && typeof value === 'object' ? [value] : [];
      if (records.length > usernameRecordLimit(options.maxRecords)) {
        const error = new Error('username.json 账号记录数超过允许上限');
        error.code = 'GPT_REGISTER_USERNAME_RECORD_LIMIT';
        throw error;
      }
      if (options.requireValidRecords === true) validateUsernameRecords(records);
      return {
        records,
        contentHash,
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        present: true,
        fileState: stat,
      };
    } catch (error) {
      if (error?.code === 'GPT_REGISTER_USERNAME_RECORD_LIMIT') throw error;
      if (options.requireValidJson === true) {
        if (error?.code === 'GPT_REGISTER_USERNAME_INVALID') throw error;
        const invalid = new Error('username.json 不是有效 JSON');
        invalid.code = 'GPT_REGISTER_USERNAME_INVALID';
        invalid.cause = error;
        throw invalid;
      }
      // Malformed JSON remains an empty record set, but its exact bytes still
      // participate in snapshot versioning.
      return {
        records: [],
        contentHash,
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        present: true,
        fileState: stat,
      };
    }
  } catch (error) {
    if (['GPT_REGISTER_PATH_PERMISSIONS_INVALID', 'GPT_REGISTER_USERNAME_RECORD_LIMIT']
      .includes(error?.code)) throw error;
    if (options.strict === true) {
      if (['GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
        'GPT_REGISTER_FILE_TOO_LARGE', 'GPT_REGISTER_USERNAME_INVALID',
        'GPT_REGISTER_SOURCE_MISSING', 'GPT_REGISTER_SOURCE_INCOMPLETE',
        'GPT_REGISTER_SOURCE_CHANGED']
        .includes(error?.code)) throw error;
      throw gptPathError('JSON 文件', error);
    }
    return fallback;
  } finally {
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
  }
}

function readJsonArray(filePath) {
  return readJsonArraySnapshot(filePath).records;
}

function sortFileNames(left, right) {
  return compareNaturalStrings(left, right);
}

function isSafeTokenFileName(fileName) {
  const value = typeof fileName === 'string' ? fileName : '';
  return Boolean(value)
    && value === value.trim()
    && value.normalize('NFC') === value
    && path.basename(value) === value
    && value.toLowerCase().endsWith('.json')
    && !value.startsWith(RESERVED_TOKEN_FILE_PREFIX)
    && !UNSAFE_TOKEN_FILE_NAME.test(value);
}

function isHistoricalTokenFile(fileName) {
  return /^old_codex[-_]/i.test(String(fileName || ''));
}

function errorHasCode(error, code) {
  const visited = new Set();
  let current = error;
  while (current && !visited.has(current)) {
    if (current.code === code) return true;
    visited.add(current);
    current = current.cause;
  }
  return false;
}

function readBoundedManifestNames(directoryHandle, limits) {
  const maximumJsonFiles = Math.max(0, Number(limits?.maximumJsonFiles) || 0);
  const maximumEntries = Math.max(0, Number(limits?.maximumEntries) || 0);
  const names = [];
  let entryCount = 0;
  let directory;
  try {
    directory = fs.opendirSync(directoryHandle.traversalPath);
  } catch (error) {
    throw sourceChangedError('token 目录', error);
  }
  let failure = null;
  try {
    while (true) {
      const entry = directory.readSync();
      if (!entry) break;
      entryCount += 1;
      if (entryCount > maximumEntries) {
        const error = new Error('token 目录项数量超过安全上限');
        error.code = 'GPT_REGISTER_SOURCE_LIMIT';
        throw error;
      }
      if (!entry.name.toLowerCase().endsWith('.json')) continue;
      // File names become row/selection identifiers in the UI and API. Bidi,
      // invisible/control characters or a POSIX-valid backslash can make the
      // reviewed path look different from the path that a mutation targets.
      // Reject the source instead of returning a confusable operational key.
      if (!isSafeTokenFileName(entry.name)) {
        throw gptPathError('token 文件名');
      }
      names.push(entry.name);
      if (names.length > maximumJsonFiles) {
        const error = new Error('token 文件数量超过安全上限');
        error.code = 'GPT_REGISTER_SOURCE_LIMIT';
        throw error;
      }
    }
  } catch (error) {
    failure = ['GPT_REGISTER_SOURCE_LIMIT', 'GPT_REGISTER_SOURCE_CHANGED',
      'GPT_REGISTER_PATH_INVALID']
      .includes(error?.code)
      ? error
      : sourceChangedError('token 目录', error);
  }
  try {
    directory.closeSync();
  } catch (error) {
    if (!failure) failure = sourceChangedError('token 目录', error);
  }
  if (failure) throw failure;
  return { names: names.sort(sortFileNames), entryCount };
}

function captureTokenDirectoryManifest(
  rootHandle,
  rootDirectory,
  directory,
  source,
  budget,
) {
  let directoryHandle = null;
  const label = 'gpt_register/' + source;
  try {
    const context = childPathContext(rootHandle, rootDirectory, directory, label);
    try {
      const observed = fs.lstatSync(context.openPath);
      if (observed.isSymbolicLink() || !observed.isDirectory()) throw gptPathError(label);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        throw incompleteSourceError(label, error, 'GPT_REGISTER_SOURCE_MISSING', [source]);
      }
      throw error;
    }
    directoryHandle = openVerifiedDirectory(context.logicalPath, {
      label,
      openPath: context.openPath,
      expectedRealPath: context.expectedRealPath,
      rootRealPath: context.rootRealPath,
    });
    const enumerationLimits = {
      maximumJsonFiles: Math.max(0, budget.maximumFiles - budget.files),
      maximumEntries: Math.max(0, budget.maximumEntries - budget.entries),
    };
    const enumeration = readBoundedManifestNames(directoryHandle, enumerationLimits);
    const { names, entryCount } = enumeration;
    budget.files += names.length;
    budget.entries += entryCount;
    const fileStats = new Map();
    for (const name of names) {
      let stat;
      try {
        stat = fs.lstatSync(path.join(directoryHandle.traversalPath, name));
      } catch (error) {
        throw sourceChangedError(label, error);
      }
      if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
        throw gptPathError('token 文件');
      }
      assertTrustedOwnerAndMode(stat, 'token 文件');
      fileStats.set(name, stat);
    }
    assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
    assertDirectoryHandleCurrent(directoryHandle, label);
    const directoryStat = fs.fstatSync(directoryHandle.descriptor);
    if (!sameStableFileState(directoryHandle.stat, directoryStat)) {
      throw sourceChangedError(label);
    }
    return {
      directory,
      source,
      directoryStat,
      names,
      entryCount,
      fileStats,
    };
  } catch (error) {
    if (['GPT_REGISTER_SOURCE_MISSING', 'GPT_REGISTER_SOURCE_LIMIT',
      'GPT_REGISTER_SOURCE_CHANGED',
      'GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
      'GPT_REGISTER_FILE_TOO_LARGE', 'GPT_REGISTER_SOURCE_INCOMPLETE']
      .includes(error?.code)) throw error;
    throw incompleteSourceError(
      label,
      error,
      'GPT_REGISTER_SOURCE_INCOMPLETE',
      [source],
    );
  } finally {
    closeDirectoryHandle(directoryHandle);
  }
}

function captureRegularFileManifest(rootHandle, rootDirectory, filePath, label) {
  try {
    const context = childPathContext(rootHandle, rootDirectory, filePath, label);
    const stat = fs.lstatSync(context.openPath);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
      throw gptPathError(label);
    }
    assertTrustedOwnerAndMode(stat, label);
    assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
    return stat;
  } catch (error) {
    if (['GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
      'GPT_REGISTER_SOURCE_INCOMPLETE']
      .includes(error?.code)) throw error;
    throw incompleteSourceError(
      label,
      error,
      errorHasCode(error, 'ENOENT')
        ? 'GPT_REGISTER_SOURCE_MISSING'
        : 'GPT_REGISTER_SOURCE_INCOMPLETE',
      ['username.json'],
    );
  }
}

function assertTokenManifestMatches(expected, current) {
  const label = 'gpt_register/' + expected.source;
  if (!current
      || expected.directory !== current.directory
      || expected.source !== current.source
      || !sameStableFileState(expected.directoryStat, current.directoryStat)
      || expected.entryCount !== current.entryCount
      || expected.names.length !== current.names.length
      || expected.names.some((name, index) => name !== current.names[index])) {
    throw sourceChangedError(label);
  }
  for (const name of expected.names) {
    if (!sameStableFileState(expected.fileStats.get(name), current.fileStats.get(name))) {
      throw sourceChangedError(label);
    }
  }
}

function verifyTokenDirectoryManifest(rootHandle, rootDirectory, manifest, budget) {
  let directoryHandle = null;
  const label = 'gpt_register/' + manifest.source;
  try {
    const context = childPathContext(
      rootHandle,
      rootDirectory,
      manifest.directory,
      label,
    );
    directoryHandle = openVerifiedDirectory(context.logicalPath, {
      label,
      openPath: context.openPath,
      expectedRealPath: context.expectedRealPath,
      rootRealPath: context.rootRealPath,
    });
    if (!sameStableFileState(manifest.directoryStat, directoryHandle.stat)) {
      throw sourceChangedError(label);
    }
    const enumeration = readBoundedManifestNames(directoryHandle, {
      maximumJsonFiles: Math.max(0, budget.maximumFiles - budget.files),
      maximumEntries: Math.max(0, budget.maximumEntries - budget.entries),
    });
    budget.files += enumeration.names.length;
    budget.entries += enumeration.entryCount;
    if (enumeration.entryCount !== manifest.entryCount
        || enumeration.names.length !== manifest.names.length
        || enumeration.names.some((name, index) => name !== manifest.names[index])) {
      throw sourceChangedError(label);
    }
    const { names } = enumeration;
    for (const name of names) {
      const expected = manifest.fileStats.get(name);
      const current = fs.lstatSync(path.join(directoryHandle.traversalPath, name));
      if (!expected || current.isSymbolicLink() || !current.isFile() || current.nlink !== 1
          || !sameStableFileState(expected, current)) {
        throw sourceChangedError(label);
      }
      assertTrustedOwnerAndMode(current, 'token 文件');
    }
    assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
    assertDirectoryHandleCurrent(directoryHandle, label);
  } catch (error) {
    if (['GPT_REGISTER_SOURCE_CHANGED', 'GPT_REGISTER_SOURCE_LIMIT',
      'GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
      'GPT_REGISTER_FILE_TOO_LARGE']
      .includes(error?.code)) throw error;
    throw sourceChangedError(label, error);
  } finally {
    closeDirectoryHandle(directoryHandle);
  }
}

function verifyRegularFileManifest(rootHandle, rootDirectory, filePath, expected, label) {
  try {
    const context = childPathContext(rootHandle, rootDirectory, filePath, label);
    const current = fs.lstatSync(context.openPath);
    if (!expected || current.isSymbolicLink() || !current.isFile() || current.nlink !== 1
        || !sameStableFileState(expected, current)) {
      throw sourceChangedError(label);
    }
    assertTrustedOwnerAndMode(current, label);
    assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
  } catch (error) {
    if (['GPT_REGISTER_SOURCE_CHANGED', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID']
      .includes(error?.code)) throw error;
    throw sourceChangedError(label, error);
  }
}

function readTokenDirectory(directory, source, rootDirectory, includeRaw = false, options = {}) {
  const records = [];
  const observedFiles = new Map();
  const initialFiles = new Map();
  const maximumBytes = configuredByteLimit(
    options.maxBytes ?? process.env.GPT_REGISTER_TOKEN_MAX_BYTES,
    DEFAULT_TOKEN_MAX_BYTES,
    HARD_TOKEN_MAX_BYTES,
  );
  const budget = options.budget || {
    files: 0,
    entries: 0,
    bytes: 0,
    maximumFiles: configuredCountLimit(
      options.maxFiles ?? process.env.GPT_REGISTER_TOKEN_MAX_FILES,
      DEFAULT_TOKEN_MAX_FILES,
      HARD_TOKEN_MAX_FILES,
    ),
    maximumEntries: tokenDirectoryEntryLimit(options.maxDirectoryEntries),
    maximumBytes: configuredByteLimit(
      options.totalMaxBytes ?? process.env.GPT_REGISTER_TOKEN_TOTAL_MAX_BYTES,
      DEFAULT_TOKEN_TOTAL_MAX_BYTES,
      HARD_TOKEN_TOTAL_MAX_BYTES,
    ),
  };
  if (!Number.isSafeInteger(budget.entries) || budget.entries < 0) budget.entries = 0;
  budget.maximumEntries = configuredCountLimit(
    budget.maximumEntries ?? options.maxDirectoryEntries
      ?? process.env.GPT_REGISTER_TOKEN_MAX_DIRECTORY_ENTRIES,
    DEFAULT_TOKEN_MAX_DIRECTORY_ENTRIES,
    HARD_TOKEN_MAX_DIRECTORY_ENTRIES,
  );
  let rootHandle = options.rootHandle || null;
  let ownedRootHandle = false;
  let directoryHandle = null;
  let pinnedRootRealPath = null;
  try {
    if (!rootHandle) {
      const rootPresent = assertReadableDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
      if (!rootPresent) {
        if (options.requireCompleteSnapshot === true) {
          throw incompleteSourceError(
            'gpt_register/' + source,
            null,
            'GPT_REGISTER_SOURCE_MISSING',
            [source],
          );
        }
        return records;
      }
      rootHandle = openRootDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
      ownedRootHandle = true;
    }
    const directoryContext = childPathContext(
      rootHandle,
      rootDirectory,
      directory,
      'gpt_register/' + source,
    );
    pinnedRootRealPath = directoryContext.rootRealPath;
    try {
      const observed = fs.lstatSync(directoryContext.openPath);
      if (observed.isSymbolicLink() || !observed.isDirectory()) {
        throw gptPathError('gpt_register/' + source);
      }
    } catch (error) {
      if (error?.code === 'ENOENT') {
        if (options.requireCompleteSnapshot === true) {
          throw incompleteSourceError(
            'gpt_register/' + source,
            error,
            'GPT_REGISTER_SOURCE_MISSING',
            [source],
          );
        }
        if (ownedRootHandle) closeDirectoryHandle(rootHandle);
        return records;
      }
      throw error;
    }
    directoryHandle = openVerifiedDirectory(directoryContext.logicalPath, {
      label: 'gpt_register/' + source,
      openPath: directoryContext.openPath,
      expectedRealPath: directoryContext.expectedRealPath,
      rootRealPath: directoryContext.rootRealPath,
    });
  } catch (error) {
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
    if (error?.code === 'GPT_REGISTER_SOURCE_MISSING') {
      if (options.requireCompleteSnapshot === true) throw error;
      return records;
    }
    if (['GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
      'GPT_REGISTER_FILE_TOO_LARGE', 'GPT_REGISTER_SOURCE_CHANGED',
      'GPT_REGISTER_SOURCE_LIMIT'].includes(error?.code)) throw error;
    if (options.requireCompleteSnapshot === true) {
      throw incompleteSourceError(
        'gpt_register/' + source,
        error,
        'GPT_REGISTER_SOURCE_INCOMPLETE',
      );
    }
    if (options.strict === true && error?.cause?.code !== 'ENOENT') throw error;
    return records;
  }
  let names = [];
  let initialEntryCount = 0;
  let enumerationLimits = null;
  try {
    assertDirectoryHandleCurrent(directoryHandle, 'gpt_register/' + source);
    enumerationLimits = {
      maximumJsonFiles: Math.max(0, budget.maximumFiles - budget.files),
      maximumEntries: Math.max(0, budget.maximumEntries - budget.entries),
    };
    const enumeration = readBoundedManifestNames(directoryHandle, enumerationLimits);
    names = enumeration.names;
    initialEntryCount = enumeration.entryCount;
    budget.files += names.length;
    budget.entries += initialEntryCount;
    if (options.requireCompleteSnapshot === true) {
      for (const name of names) {
        let stat;
        try {
          stat = fs.lstatSync(path.join(directoryHandle.traversalPath, name));
        } catch (error) {
          throw sourceChangedError('gpt_register/' + source, error);
        }
        if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
          throw gptPathError('token 文件');
        }
        assertTrustedOwnerAndMode(stat, 'token 文件');
        initialFiles.set(name, stat);
      }
      const enumeratedDirectoryStat = fs.fstatSync(directoryHandle.descriptor);
      if (!sameStableFileState(directoryHandle.stat, enumeratedDirectoryStat)) {
        throw sourceChangedError('gpt_register/' + source);
      }
    }
  } catch (error) {
    closeDirectoryHandle(directoryHandle);
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
    if (options.strict === true) {
      if (['GPT_REGISTER_SOURCE_LIMIT', 'GPT_REGISTER_SOURCE_CHANGED',
        'GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
        'GPT_REGISTER_FILE_TOO_LARGE'].includes(error?.code)) throw error;
      throw gptPathError('gpt_register/' + source, error);
    }
    return records;
  }

  try {
    for (const fileName of names) {
      assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
      assertDirectoryHandleCurrent(directoryHandle, 'gpt_register/' + source);
      const absolutePath = path.join(directory, fileName);
      const context = {
        logicalPath: absolutePath,
        openPath: path.join(directoryHandle.traversalPath, fileName),
        expectedRealPath: path.join(directoryHandle.realPath, fileName),
        rootRealPath: pinnedRootRealPath,
      };
      let stat;
      let bytes;
      try {
        const opened = readVerifiedRegularFile(context, 'token 文件', maximumBytes);
        stat = opened.stat;
        bytes = opened.bytes;
        if (options.requireCompleteSnapshot === true
            && !sameStableFileState(initialFiles.get(fileName), stat)) {
          throw sourceChangedError('gpt_register/' + source);
        }
        if (budget.bytes + bytes.length > budget.maximumBytes) {
          const limitError = new Error('token 文件总大小超过安全上限');
          limitError.code = 'GPT_REGISTER_SOURCE_LIMIT';
          throw limitError;
        }
        budget.bytes += bytes.length;
        assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
        assertDirectoryHandleCurrent(directoryHandle, 'gpt_register/' + source);
        observedFiles.set(fileName, stat);
      } catch (error) {
        if (['GPT_REGISTER_SOURCE_LIMIT', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
          'GPT_REGISTER_SOURCE_CHANGED']
          .includes(error?.code)) throw error;
        if (options.requireCompleteSnapshot === true) {
          if (error?.code === 'GPT_REGISTER_FILE_TOO_LARGE') throw error;
          if (error?.code === 'GPT_REGISTER_PATH_INVALID' && initialFiles.has(fileName)) {
            throw sourceChangedError('gpt_register/' + source, error);
          }
          if (error?.code === 'GPT_REGISTER_PATH_INVALID') throw error;
          throw incompleteSourceError('token 文件', error);
        }
        records.push(normalizeTokenDocument({
          source,
          relativePath: path.relative(rootDirectory, absolutePath),
          fileName,
          mtimeMs: 0,
          historical: isHistoricalTokenFile(fileName),
          parseError: error,
          includeRaw,
        }));
        continue;
      }

      const contentHash = crypto.createHash('sha256').update(bytes).digest('hex');
      let data;
      let parseError = null;
      try { data = JSON.parse(decodeUtf8Json(bytes)); } catch {
        parseError = new Error('token JSON 无效');
        parseError.code = 'TOKEN_JSON_INVALID';
      }

      records.push(normalizeTokenDocument({
        source,
        relativePath: path.relative(rootDirectory, absolutePath),
        fileName,
        mtimeMs: stat.mtimeMs,
        data,
        parseError,
        contentHash,
        historical: isHistoricalTokenFile(fileName),
        includeRaw,
      }));
    }
    if (options.requireCompleteSnapshot === true) {
      try {
        assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
        assertDirectoryHandleCurrent(directoryHandle, 'gpt_register/' + source);
        const latestEnumeration = readBoundedManifestNames(directoryHandle, enumerationLimits);
        const latestNames = latestEnumeration.names;
        if (latestEnumeration.entryCount !== initialEntryCount
            || latestNames.length !== names.length
            || latestNames.some((name, index) => name !== names[index])) {
          throw sourceChangedError('gpt_register/' + source);
        }
        for (const [fileName, expectedStat] of observedFiles) {
          const current = fs.lstatSync(path.join(directoryHandle.traversalPath, fileName));
          if (current.isSymbolicLink() || !current.isFile() || current.nlink !== 1
              || !sameStableFileState(expectedStat, current)) {
            throw sourceChangedError('gpt_register/' + source);
          }
          assertTrustedOwnerAndMode(current, 'token 文件');
        }
        const latestDirectoryStat = fs.fstatSync(directoryHandle.descriptor);
        if (!sameStableFileState(directoryHandle.stat, latestDirectoryStat)) {
          throw sourceChangedError('gpt_register/' + source);
        }
        if (Array.isArray(options.manifestCollector)) {
          options.manifestCollector.push({
            directory,
            source,
            directoryStat: latestDirectoryStat,
            names: [...names],
            entryCount: latestEnumeration.entryCount,
            fileStats: new Map(observedFiles),
          });
        }
      } catch (error) {
        if (['GPT_REGISTER_SOURCE_CHANGED', 'GPT_REGISTER_SOURCE_LIMIT',
          'GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
          'GPT_REGISTER_FILE_TOO_LARGE']
          .includes(error?.code)) throw error;
        throw sourceChangedError('gpt_register/' + source, error);
      }
    }
  } finally {
    closeDirectoryHandle(directoryHandle);
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
  }
  return records;
}

function safeUsernameRecords(records) {
  return records.map((item, index) => {
    const rawEmail = typeof item?.email === 'string' ? item.email : '';
    const email = normalizeEmail(rawEmail);
    const rawPhoneValue = typeof item?.phone === 'string' || typeof item?.phone === 'number'
      ? String(item.phone)
      : '';
    const normalizedPhone = normalizePhase3Phone(item?.phone, {
      maximumBytes: PHASE3_PHONE_USERNAME_MAX_BYTES,
      allowNumber: true,
      allowNull: true,
    });
    const phoneValid = normalizedPhone !== null;
    const phone = phoneValid ? rawPhoneValue.trim() : '';
    const rawName = typeof item?.name === 'string' ? item.name : '';
    const name = redactText(rawName.replace(/[\u0000-\u001f\u007f]/g, ' ')).slice(0, 200);
    const rawStatus = typeof item?.status === 'string' ? item.status.trim() : '';
    const status = /^[a-z0-9_-]{1,64}$/i.test(rawStatus) ? rawStatus : '';
    return {
      index,
      email,
      phone,
      phoneValid,
      name,
      createdAt: parseDateValue(item?.createdAt),
      status,
      hasPassword: typeof item?.password === 'string'
        && !CREDENTIAL_LINE_CONTROL.test(item.password)
        && item.password.trim().length > 0,
    };
  });
}

function readGptRegisterSources(options = {}) {
  const tokenOnly = options[TOKEN_ONLY_SOURCE_READ] === true;
  const rootDirectory = path.resolve(
    options.rootDirectory
      || process.env.GPT_REGISTER_ROOT
      || '/mnt/nvme/gpt_register',
  );
  const tokensDirectory = path.resolve(
    options.tokensDirectory || path.join(rootDirectory, 'tokens'),
  );
  const useTokenDirectory = path.resolve(
    options.useTokenDirectory || path.join(rootDirectory, 'use_token'),
  );
  const usernameFile = path.resolve(
    options.usernameFile || path.join(rootDirectory, 'username.json'),
  );
  const suppliedRootHandle = options.rootHandle || null;
  if (suppliedRootHandle
      && path.resolve(suppliedRootHandle.logicalPath || '') !== rootDirectory) {
    throw gptPathError('GPT_REGISTER_ROOT');
  }
  if (!suppliedRootHandle) {
    const rootPresent = assertReadableDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
    const tokensPresent = assertReadableDirectory(tokensDirectory, 'gpt_register/tokens');
    const useTokenPresent = assertReadableDirectory(useTokenDirectory, 'gpt_register/use_token');
    const usernamePresent = tokenOnly
      ? true
      : assertReadableFileParent(usernameFile, 'gpt_register/username.json');
    if (options.strictCompleteSnapshot === true) {
      const missing = [
        tokensPresent ? null : 'tokens',
        useTokenPresent ? null : 'use_token',
        tokenOnly || usernamePresent ? null : 'username.json',
      ].filter(Boolean);
      if (missing.length > 0) {
        throw incompleteSourceError(
          'gpt_register 来源',
          null,
          'GPT_REGISTER_SOURCE_MISSING',
          rootPresent ? missing : REQUIRED_SOURCE_NAMES,
        );
      }
    }
  }
  const rootHandle = suppliedRootHandle
    || openRootDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
  const ownedRootHandle = !suppliedRootHandle;
  assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
  const snapshotRootStat = fs.fstatSync(rootHandle.descriptor);
  let tokenRecords;
  let usernameSnapshot;
  const tokenBudget = {
    files: 0,
    entries: 0,
    bytes: 0,
    maximumFiles: configuredCountLimit(
      options.tokenMaxFiles ?? process.env.GPT_REGISTER_TOKEN_MAX_FILES,
      DEFAULT_TOKEN_MAX_FILES,
      HARD_TOKEN_MAX_FILES,
    ),
    maximumEntries: tokenDirectoryEntryLimit(options.tokenMaxDirectoryEntries),
    maximumBytes: configuredByteLimit(
      options.tokenTotalMaxBytes ?? process.env.GPT_REGISTER_TOKEN_TOTAL_MAX_BYTES,
      DEFAULT_TOKEN_TOTAL_MAX_BYTES,
      HARD_TOKEN_TOTAL_MAX_BYTES,
    ),
  };
  const tokenManifests = [];
  try {
    let initialTokenManifests = [];
    let initialUsernameState = null;
    if (options.strictCompleteSnapshot === true) {
      const manifestBudget = {
        files: 0,
        entries: 0,
        maximumFiles: tokenBudget.maximumFiles,
        maximumEntries: tokenBudget.maximumEntries,
      };
      initialTokenManifests = [
        captureTokenDirectoryManifest(
          rootHandle,
          rootDirectory,
          tokensDirectory,
          'tokens',
          manifestBudget,
        ),
        captureTokenDirectoryManifest(
          rootHandle,
          rootDirectory,
          useTokenDirectory,
          'use_token',
          manifestBudget,
        ),
      ];
      if (!tokenOnly) {
        initialUsernameState = captureRegularFileManifest(
          rootHandle,
          rootDirectory,
          usernameFile,
          'gpt_register/username.json',
        );
      }
    }
    tokenRecords = [
      ...readTokenDirectory(tokensDirectory, 'tokens', rootDirectory, options.includeRaw === true, {
        rootHandle,
        strict: true,
        requireCompleteSnapshot: options.strictCompleteSnapshot === true,
        manifestCollector: tokenManifests,
        maxBytes: options.tokenMaxBytes,
        budget: tokenBudget,
      }),
      ...readTokenDirectory(useTokenDirectory, 'use_token', rootDirectory, options.includeRaw === true, {
        rootHandle,
        strict: true,
        requireCompleteSnapshot: options.strictCompleteSnapshot === true,
        manifestCollector: tokenManifests,
        maxBytes: options.tokenMaxBytes,
        budget: tokenBudget,
      }),
    ];
    usernameSnapshot = tokenOnly
      ? {
          records: [],
          contentHash: null,
          mtimeMs: 0,
          size: 0,
          present: false,
          fileState: null,
        }
      : readJsonArraySnapshot(usernameFile, {
          rootHandle,
          rootDirectory,
          strict: true,
          requireCompleteSnapshot: options.strictCompleteSnapshot === true,
          // Raw token reads are used to build or execute a write plan. Losing a
          // terminal username status because the JSON is corrupt must stop that
          // plan instead of treating the file as an empty account list.
          requireValidJson: options.requireValidUsername === true
            || options.strictCompleteSnapshot === true,
          requireValidRecords: options.requireValidUsername === true
            || options.strictCompleteSnapshot === true,
          maxBytes: options.usernameMaxBytes,
          maxRecords: options.usernameMaxRecords,
        });
    if (options.strictCompleteSnapshot === true) {
      const verificationBudget = {
        files: 0,
        entries: 0,
        maximumFiles: tokenBudget.maximumFiles,
        maximumEntries: tokenBudget.maximumEntries,
      };
      for (const initialManifest of initialTokenManifests) {
        const readManifest = tokenManifests.find(
          (manifest) => manifest.source === initialManifest.source,
        );
        assertTokenManifestMatches(initialManifest, readManifest);
        verifyTokenDirectoryManifest(
          rootHandle,
          rootDirectory,
          initialManifest,
          verificationBudget,
        );
      }
      if (!tokenOnly) {
        if (!sameStableFileState(initialUsernameState, usernameSnapshot.fileState)) {
          throw sourceChangedError('gpt_register/username.json');
        }
        verifyRegularFileManifest(
          rootHandle,
          rootDirectory,
          usernameFile,
          initialUsernameState,
          'gpt_register/username.json',
        );
      }
      assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
      const latestRootStat = fs.fstatSync(rootHandle.descriptor);
      if (!sameStableFileState(snapshotRootStat, latestRootStat)) {
        throw sourceChangedError('GPT_REGISTER_ROOT');
      }
    }
  } finally {
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
  }
  const historicalTokenCount = tokenRecords.filter((item) => item.historical === true).length;
  const activeTokenRecords = tokenRecords.filter((item) => item.historical !== true);
  return {
    generatedAt: new Date().toISOString(),
    rootDirectory,
    tokensDirectory,
    useTokenDirectory,
    usernameFile,
    tokens: tokenRecords,
    usernames: safeUsernameRecords(usernameSnapshot.records),
    usernameContentHash: usernameSnapshot.contentHash,
    usernameMtimeMs: usernameSnapshot.mtimeMs,
    usernameSize: usernameSnapshot.size,
    summary: {
      tokenCount: tokenRecords.length,
      validTokenCount: tokenRecords.filter((item) => item.parseStatus === 'ok').length,
      invalidTokenCount: tokenRecords.filter((item) => item.parseStatus !== 'ok').length,
      activeTokenCount: activeTokenRecords.length,
      activeValidTokenCount: activeTokenRecords.filter((item) => item.parseStatus === 'ok').length,
      activeInvalidTokenCount: activeTokenRecords.filter((item) => item.parseStatus !== 'ok').length,
      historicalTokenCount,
      usernameCount: usernameSnapshot.records.length,
    },
  };
}

function readGptRegisterTokenSources(options = {}) {
  return readGptRegisterSources({
    ...options,
    [TOKEN_ONLY_SOURCE_READ]: true,
  });
}

function toSafeSources(sources) {
  return {
    generatedAt: sources.generatedAt,
    rootDirectory: sources.rootDirectory,
    tokensDirectory: sources.tokensDirectory,
    useTokenDirectory: sources.useTokenDirectory,
    usernameFile: sources.usernameFile,
    tokens: sources.tokens.map(toSafeTokenSummary),
    usernames: sources.usernames,
    summary: sources.summary,
  };
}

module.exports = {
  closeDirectoryHandle,
  isSafeTokenFileName,
  isHistoricalTokenFile,
  openRootDirectory,
  readJsonArray,
  readTokenDirectory,
  readGptRegisterSources,
  readGptRegisterTokenSources,
  toSafeSources,
  usernameRecordLimit,
};
