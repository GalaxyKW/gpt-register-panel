const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  normalizeTokenDocument,
  toSafeTokenSummary,
  normalizeEmail,
  parseDateValue,
} = require('../lib/token');
const { assertDirectoryTree } = require('../lib/safeFs');
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
const DEFAULT_TOKEN_TOTAL_MAX_BYTES = 256 * 1024 * 1024;
const HARD_TOKEN_TOTAL_MAX_BYTES = 1024 * 1024 * 1024;

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
  const fallback = { records: [], contentHash: null, mtimeMs: 0, size: 0 };
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
      if (error?.code === 'ENOENT') return fallback;
      throw error;
    }
    if (observed.isSymbolicLink() || !observed.isFile()) {
      if (options.strict === true) throw gptPathError('JSON 文件');
      return { ...fallback, mtimeMs: observed.mtimeMs, size: observed.size };
    }
    const { bytes, stat } = readVerifiedRegularFile(context, 'JSON 文件', maximumBytes);
    assertDirectoryHandleCurrent(rootHandle, 'JSON 父目录');
    const contentHash = crypto.createHash('sha256').update(bytes).digest('hex');
    try {
      const value = JSON.parse(bytes.toString('utf8'));
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
      return { records, contentHash, mtimeMs: stat.mtimeMs, size: stat.size };
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
      return { records: [], contentHash, mtimeMs: stat.mtimeMs, size: stat.size };
    }
  } catch (error) {
    if (['GPT_REGISTER_PATH_PERMISSIONS_INVALID', 'GPT_REGISTER_USERNAME_RECORD_LIMIT']
      .includes(error?.code)) throw error;
    if (options.strict === true) {
      if (['GPT_REGISTER_PATH_INVALID', 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
        'GPT_REGISTER_FILE_TOO_LARGE', 'GPT_REGISTER_USERNAME_INVALID']
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
  return left.localeCompare(right, 'en', {
    numeric: true,
    sensitivity: 'base',
  });
}

function isHistoricalTokenFile(fileName) {
  return /^old_codex[-_]/i.test(String(fileName || ''));
}

function readTokenDirectory(directory, source, rootDirectory, includeRaw = false, options = {}) {
  const records = [];
  const maximumBytes = configuredByteLimit(
    options.maxBytes ?? process.env.GPT_REGISTER_TOKEN_MAX_BYTES,
    DEFAULT_TOKEN_MAX_BYTES,
    HARD_TOKEN_MAX_BYTES,
  );
  const budget = options.budget || {
    files: 0,
    bytes: 0,
    maximumFiles: configuredCountLimit(
      options.maxFiles ?? process.env.GPT_REGISTER_TOKEN_MAX_FILES,
      DEFAULT_TOKEN_MAX_FILES,
      HARD_TOKEN_MAX_FILES,
    ),
    maximumBytes: configuredByteLimit(
      options.totalMaxBytes ?? process.env.GPT_REGISTER_TOKEN_TOTAL_MAX_BYTES,
      DEFAULT_TOKEN_TOTAL_MAX_BYTES,
      HARD_TOKEN_TOTAL_MAX_BYTES,
    ),
  };
  let rootHandle = options.rootHandle || null;
  let ownedRootHandle = false;
  let directoryHandle = null;
  let pinnedRootRealPath = null;
  try {
    if (!rootHandle) {
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
    directoryHandle = openVerifiedDirectory(directoryContext.logicalPath, {
      label: 'gpt_register/' + source,
      openPath: directoryContext.openPath,
      expectedRealPath: directoryContext.expectedRealPath,
      rootRealPath: directoryContext.rootRealPath,
    });
  } catch (error) {
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
    if (error?.code === 'GPT_REGISTER_PATH_PERMISSIONS_INVALID') throw error;
    if (options.strict === true && error?.cause?.code !== 'ENOENT') throw error;
    return records;
  }
  let names = [];
  try {
    assertDirectoryHandleCurrent(directoryHandle, 'gpt_register/' + source);
    names = fs.readdirSync(directoryHandle.traversalPath)
      .filter((name) => name.toLowerCase().endsWith('.json'))
      .sort(sortFileNames);
    if (budget.files + names.length > budget.maximumFiles) {
      const error = new Error('token 文件数量超过安全上限');
      error.code = 'GPT_REGISTER_SOURCE_LIMIT';
      throw error;
    }
    budget.files += names.length;
  } catch (error) {
    closeDirectoryHandle(directoryHandle);
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
    if (options.strict === true) {
      if (error?.code === 'GPT_REGISTER_SOURCE_LIMIT') throw error;
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
        if (budget.bytes + bytes.length > budget.maximumBytes) {
          const limitError = new Error('token 文件总大小超过安全上限');
          limitError.code = 'GPT_REGISTER_SOURCE_LIMIT';
          throw limitError;
        }
        budget.bytes += bytes.length;
        assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
        assertDirectoryHandleCurrent(directoryHandle, 'gpt_register/' + source);
      } catch (error) {
        if (error?.code === 'GPT_REGISTER_SOURCE_LIMIT') throw error;
        if (error?.code === 'GPT_REGISTER_PATH_PERMISSIONS_INVALID') throw error;
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
      try { data = JSON.parse(bytes.toString('utf8')); } catch {
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
  } finally {
    closeDirectoryHandle(directoryHandle);
    if (ownedRootHandle) closeDirectoryHandle(rootHandle);
  }
  return records;
}

function safeUsernameRecords(records) {
  return records.map((item, index) => {
    const rawEmail = typeof item?.email === 'string' ? item.email : '';
    const email = rawEmail.length <= 320 && /^[^\s@]+@[^\s@]+$/.test(rawEmail.trim())
      ? normalizeEmail(rawEmail)
      : '';
    const rawPhone = typeof item?.phone === 'string' || typeof item?.phone === 'number'
      ? String(item.phone).trim()
      : '';
    const phone = rawPhone.length <= 64 && /^[+\d\s().-]*$/.test(rawPhone) ? rawPhone : '';
    const rawName = typeof item?.name === 'string' ? item.name : '';
    const name = redactText(rawName.replace(/[\u0000-\u001f\u007f]/g, ' ')).slice(0, 200);
    const rawStatus = typeof item?.status === 'string' ? item.status.trim() : '';
    const status = /^[a-z0-9_-]{1,64}$/i.test(rawStatus) ? rawStatus : '';
    return {
      index,
      email,
      phone,
      name,
      createdAt: parseDateValue(item?.createdAt),
      status,
      hasPassword: typeof item?.password === 'string' && item.password.trim().length > 0,
    };
  });
}

function readGptRegisterSources(options = {}) {
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
    assertReadableDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
    assertReadableDirectory(tokensDirectory, 'gpt_register/tokens');
    assertReadableDirectory(useTokenDirectory, 'gpt_register/use_token');
    assertReadableFileParent(usernameFile, 'gpt_register/username.json');
  }
  const rootHandle = suppliedRootHandle
    || openRootDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
  const ownedRootHandle = !suppliedRootHandle;
  assertDirectoryHandleCurrent(rootHandle, 'GPT_REGISTER_ROOT');
  let tokenRecords;
  let usernameSnapshot;
  const tokenBudget = {
    files: 0,
    bytes: 0,
    maximumFiles: configuredCountLimit(
      options.tokenMaxFiles ?? process.env.GPT_REGISTER_TOKEN_MAX_FILES,
      DEFAULT_TOKEN_MAX_FILES,
      HARD_TOKEN_MAX_FILES,
    ),
    maximumBytes: configuredByteLimit(
      options.tokenTotalMaxBytes ?? process.env.GPT_REGISTER_TOKEN_TOTAL_MAX_BYTES,
      DEFAULT_TOKEN_TOTAL_MAX_BYTES,
      HARD_TOKEN_TOTAL_MAX_BYTES,
    ),
  };
  try {
    tokenRecords = [
      ...readTokenDirectory(tokensDirectory, 'tokens', rootDirectory, options.includeRaw === true, {
        rootHandle,
        strict: true,
        maxBytes: options.tokenMaxBytes,
        budget: tokenBudget,
      }),
      ...readTokenDirectory(useTokenDirectory, 'use_token', rootDirectory, options.includeRaw === true, {
        rootHandle,
        strict: true,
        maxBytes: options.tokenMaxBytes,
        budget: tokenBudget,
      }),
    ];
    usernameSnapshot = readJsonArraySnapshot(usernameFile, {
      rootHandle,
      rootDirectory,
      strict: true,
      // Raw token reads are used to build or execute a write plan. Losing a
      // terminal username status because the JSON is corrupt must stop that
      // plan instead of treating the file as an empty account list.
      requireValidJson: options.requireValidUsername === true || options.includeRaw === true,
      maxBytes: options.usernameMaxBytes,
      maxRecords: options.usernameMaxRecords,
    });
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
  isHistoricalTokenFile,
  openRootDirectory,
  readJsonArray,
  readTokenDirectory,
  readGptRegisterSources,
  toSafeSources,
  usernameRecordLimit,
};
