const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { readGptRegisterSources } = require('./adapters/gptRegisterFs');
const { throwIfJobInterrupted } = require('./jobLifecycle');
const { assertDirectoryTree } = require('./lib/safeFs');
const { compareNaturalStrings } = require('./lib/stableOrder');
const { currentProcessOwner, isProcessOwnerAlive } = require('./taskCoordinator');

const CONFIRMATION = 'DELETE_EXPIRED_TOKENS';
const SOURCES = new Set(['tokens', 'use_token']);
const CLAIM_PREFIX = '.panel-token-cleanup-claim-';
const CLAIM_PREFIX_V1 = '.panel-token-cleanup-claim-v1-';
const CLAIM_PREFIX_V2 = '.panel-token-cleanup-claim-v2-';
const MAX_REPORTED_CLEANUP_CLAIMS = 1000;
const MAX_RECOVERABLE_CLEANUP_CLAIMS = 1000;
const DEFAULT_CLEANUP_DIRECTORY_ENTRIES = 20_000;
const HARD_CLEANUP_DIRECTORY_ENTRIES = 200_000;
const DEFAULT_TOKEN_MAX_BYTES = 4 * 1024 * 1024;
const HARD_TOKEN_MAX_BYTES = 16 * 1024 * 1024;

function cleanupDirectoryEntryLimit() {
  const value = Number(process.env.GPT_REGISTER_TOKEN_MAX_DIRECTORY_ENTRIES);
  if (!Number.isSafeInteger(value) || value < 1) return DEFAULT_CLEANUP_DIRECTORY_ENTRIES;
  return Math.min(value, HARD_CLEANUP_DIRECTORY_ENTRIES);
}

function cleanupClaimScanLimitExceeded(reason) {
  const error = new Error('token 清理 claim 扫描超过安全上限；无法证明目录中不存在未完成操作，请人工核验');
  error.code = 'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT';
  error.recoveryRequired = true;
  error.requiresReconciliation = true;
  error.reconciliationScope = 'expired_token_cleanup';
  error.reconciliationReason = reason;
  error.blockedBeforeStart = true;
  error.executionOutcome = 'not_started';
  error.retryAllowed = false;
  error.doNotRetry = true;
  return error;
}

function forEachBoundedCleanupDirectoryEntry(directoryPath, visitor) {
  const maximumEntries = cleanupDirectoryEntryLimit();
  let directory;
  let failure = null;
  try {
    directory = fs.opendirSync(directoryPath);
    let entryCount = 0;
    while (true) {
      const entry = directory.readSync();
      if (!entry) break;
      entryCount += 1;
      if (entryCount > maximumEntries) {
        throw cleanupClaimScanLimitExceeded('directory_entry_limit_exceeded');
      }
      visitor(String(entry.name));
    }
  } catch (error) {
    failure = error;
  }
  if (directory) {
    try { directory.closeSync(); } catch (error) {
      if (!failure) failure = error;
    }
  }
  if (failure) throw failure;
}

function cleanupTokenMaximumBytes() {
  const value = Number(process.env.GPT_REGISTER_TOKEN_MAX_BYTES);
  if (!Number.isSafeInteger(value) || value < 1024) return DEFAULT_TOKEN_MAX_BYTES;
  return Math.min(value, HARD_TOKEN_MAX_BYTES);
}

function copyBoundedFile(sourceDescriptor, targetDescriptor, expectedSize) {
  const maximumBytes = cleanupTokenMaximumBytes();
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || expectedSize > maximumBytes) {
    const error = new Error('token 文件超过清理安全上限');
    error.code = 'TOKEN_CLEANUP_FILE_TOO_LARGE';
    throw error;
  }
  const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, Math.max(1, expectedSize)));
  let total = 0;
  while (total < expectedSize) {
    const bytesRead = fs.readSync(
      sourceDescriptor,
      buffer,
      0,
      Math.min(buffer.length, expectedSize - total),
      null,
    );
    if (bytesRead <= 0) throw new Error('token 文件在复制期间被截断');
    let written = 0;
    while (written < bytesRead) {
      const count = fs.writeSync(targetDescriptor, buffer, written, bytesRead - written, null);
      if (count <= 0) throw new Error('token 隔离目标写入失败');
      written += count;
    }
    total += bytesRead;
  }
  const trailing = Buffer.allocUnsafe(1);
  if (fs.readSync(sourceDescriptor, trailing, 0, 1, null) !== 0) {
    throw new Error('token 文件在复制期间增长');
  }
}

function sameInode(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function syncCleanupDirectory(directory) {
  let descriptor;
  let operationError;
  try {
    descriptor = fs.openSync(
      directory,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0),
    );
    try { fs.fsyncSync(descriptor); } catch (error) { operationError = error; }
  } catch (error) {
    operationError = error;
  }
  if (descriptor !== undefined) {
    try { fs.closeSync(descriptor); } catch (error) {
      if (!operationError) operationError = error;
    }
  }
  if (operationError) throw operationError;
}

function safeCleanupErrorCode(value) {
  const code = String(value || '').trim().toUpperCase();
  return /^[A-Z0-9_]{1,96}$/.test(code) ? code : null;
}

function cleanupWriteOutcomeUnknown(error, { code, message, reason }) {
  // Do not retain the original message or cause: filesystem diagnostics can
  // contain deployment paths. The fixed code and reconciliation fields are
  // sufficient for callers to stop and inspect the two pinned locations.
  const wrapped = new Error(message);
  wrapped.code = code;
  wrapped.writeOutcomeUnknown = true;
  wrapped.requiresReconciliation = true;
  wrapped.retryAllowed = false;
  wrapped.doNotRetry = true;
  wrapped.reconciliationScope = 'expired_token_cleanup';
  wrapped.reconciliationReason = reason;
  wrapped.outcome = 'unknown';
  const causeCode = safeCleanupErrorCode(error?.code);
  if (causeCode) wrapped.causeCode = causeCode;
  return wrapped;
}

function boundedCleanupCount(value) {
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0) return 0;
  return count;
}

function attachCleanupProgress(error, item, deletedCount, skippedCount, options = {}) {
  error.requiresReconciliation = true;
  error.writeOutcomeUnknown = true;
  error.retryAllowed = false;
  error.doNotRetry = true;
  error.outcome = 'unknown';
  error.reconciliationScope = 'expired_token_cleanup';
  error.currentItem = {
    source: SOURCES.has(item?.source) ? item.source : 'unknown',
    relativePath: String(item?.relativePath || '')
      .replace(/[\u0000-\u001f\u007f]/g, '?')
      .slice(0, 512),
  };
  error.completedCount = boundedCleanupCount(deletedCount);
  error.skippedCount = boundedCleanupCount(skippedCount);
  if (options.quarantinePath) {
    error.quarantinePath = String(options.quarantinePath)
      .replace(/[\u0000-\u001f\u007f]/g, '?')
      .slice(0, 1024);
  }
  return error;
}

function cleanupClaimRecoveryOutcomeUnknown(error) {
  if (error?.writeOutcomeUnknown === true) return error;
  return cleanupWriteOutcomeUnknown(error, {
    code: 'TOKEN_CLEANUP_CLAIM_RECOVERY_OUTCOME_UNKNOWN',
    message: 'token claim 无法确认已恢复或隔离；请人工对账，禁止自动重试',
    reason: 'token_claim_recovery_outcome_unknown',
  });
}

function assertCleanupClaimResolved(claimPath) {
  try {
    fs.lstatSync(claimPath);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw cleanupWriteOutcomeUnknown(error, {
      code: 'TOKEN_CLEANUP_CLAIM_RESOLUTION_UNKNOWN',
      message: 'token claim 的最终清理结果无法确认；请人工对账，禁止自动重试',
      reason: 'token_claim_resolution_unknown',
    });
  }
  throw cleanupWriteOutcomeUnknown(null, {
    code: 'TOKEN_CLEANUP_CLAIM_RESOLUTION_UNKNOWN',
    message: 'token claim 在操作结束后仍然存在；请人工对账，禁止自动重试',
    reason: 'token_claim_residual_present',
  });
}

function cleanupRecoveryInvalid(reason) {
  const error = new Error('检测到无法安全验证的过期 token 清理 claim；请人工核验，禁止自动重试');
  error.code = 'TOKEN_CLEANUP_RECOVERY_INVALID_CLAIM';
  error.recoveryReason = reason;
  error.recoveryRequired = true;
  error.requiresReconciliation = true;
  error.retryAllowed = false;
  error.doNotRetry = true;
  error.blockedBeforeStart = true;
  error.executionOutcome = 'not_started';
  error.reconciliationScope = 'expired_token_cleanup';
  error.reconciliationReason = reason;
  return error;
}

function compareCleanupPaths(left, right) {
  const leftPath = String(left?.relativePath ?? left ?? '');
  const rightPath = String(right?.relativePath ?? right ?? '');
  return compareNaturalStrings(leftPath, rightPath);
}

function pathEntryExists(filePath) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function unlinkIfSameInode(filePath, expectedStat) {
  try {
    const latest = fs.lstatSync(filePath);
    if (sameInode(latest, expectedStat)) fs.unlinkSync(filePath);
  } catch {}
}

function rollbackOwnedPath(filePath, expectedStat) {
  if (!expectedStat) return false;
  let latest;
  try {
    latest = fs.lstatSync(filePath);
  } catch (error) {
    if (error?.code !== 'ENOENT') return false;
    // A previous unlink may have succeeded before reporting an error. Flush
    // even an already-absent entry so that retrying this confirmation can
    // establish durability instead of silently accepting an unflushed rename.
    try {
      syncCleanupDirectory(path.dirname(filePath));
      return true;
    } catch {
      return false;
    }
  }
  if (!sameInode(latest, expectedStat)) return false;
  try {
    fs.unlinkSync(filePath);
    syncCleanupDirectory(path.dirname(filePath));
  } catch {
    return false;
  }
  try {
    latest = fs.lstatSync(filePath);
    return !sameInode(latest, expectedStat);
  } catch (error) {
    return error?.code === 'ENOENT';
  }
}

function cleanupRoot(options = {}) {
  return path.resolve(
    options.rootDirectory
      || process.env.GPT_REGISTER_ROOT
      || '/mnt/nvme/gpt_register',
  );
}

function sourceDirectory(sources, source) {
  return source === 'tokens' ? sources.tokensDirectory : sources.useTokenDirectory;
}

function quarantineDirectory(options = {}) {
  return path.resolve(
    options.quarantineDirectory
      || process.env.PANEL_TOKEN_QUARANTINE_DIR
      || path.join(cleanupRoot(options), '.panel-quarantine', 'expired-tokens'),
  );
}

function ensureDirectory(directory, label) {
  try {
    return assertDirectoryTree(directory, label);
  } catch (error) {
    const wrapped = new Error(label + ' 不存在、不可读取或包含符号链接');
    wrapped.code = 'TOKEN_CLEANUP_PATH_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
}

const CLEANUP_FD_ROOT = '/proc/self/fd';
const UNSUPPORTED_CLEANUP_FSYNC = new Set(['EINVAL', 'ENOSYS', 'ENOTSUP', 'EOPNOTSUPP']);

function cleanupDirectoryError(error, label, syncing = false) {
  const unsupported = syncing && UNSUPPORTED_CLEANUP_FSYNC.has(error?.code);
  const wrapped = new Error(unsupported
    ? label + ' 所在文件系统不支持目录 fsync，拒绝开始 token 清理'
    : label + ' 无法安全验证或持久化，拒绝开始 token 清理');
  wrapped.code = unsupported
    ? 'TOKEN_CLEANUP_DIRECTORY_FSYNC_UNSUPPORTED'
    : 'TOKEN_CLEANUP_PATH_INVALID';
  wrapped.cleanupInfrastructureInvalid = true;
  const causeCode = safeCleanupErrorCode(error?.code);
  if (causeCode) wrapped.causeCode = causeCode;
  return wrapped;
}

function cleanupProcessUid() {
  if (typeof process.geteuid === 'function') return process.geteuid();
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function verifyCleanupDirectory(stat, label, privateRequired) {
  const currentUid = cleanupProcessUid();
  if (!stat?.isDirectory() || stat.isSymbolicLink()
      || (currentUid !== null && stat.uid !== currentUid)
      || (stat.mode & 0o022) !== 0
      || (privateRequired && (stat.mode & 0o077) !== 0)) {
    throw cleanupDirectoryError(null, label);
  }
}

function assertCleanupDirectoryPin(pin) {
  try {
    const opened = fs.fstatSync(pin.fd);
    const linked = fs.lstatSync(pin.displayPath);
    verifyCleanupDirectory(opened, pin.label, pin.privateRequired);
    verifyCleanupDirectory(linked, pin.label, pin.privateRequired);
    if (!sameInode(opened, pin.identity) || !sameInode(linked, pin.identity)) {
      throw cleanupDirectoryError(null, pin.label);
    }
  } catch (error) {
    if (error?.cleanupInfrastructureInvalid === true) throw error;
    throw cleanupDirectoryError(error, pin.label);
  }
}

function openCleanupDirectory(operationPath, displayPath, label, privateRequired = false) {
  let fd;
  try {
    fd = fs.openSync(
      operationPath,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0),
    );
    const identity = fs.fstatSync(fd);
    verifyCleanupDirectory(identity, label, privateRequired);
    const pin = { fd, displayPath: path.resolve(displayPath), identity, label, privateRequired };
    assertCleanupDirectoryPin(pin);
    return pin;
  } catch (error) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    if (error?.cleanupInfrastructureInvalid === true) throw error;
    throw cleanupDirectoryError(error, label);
  }
}

function cleanupFdPath(pin, fileName = '') {
  return path.join(CLEANUP_FD_ROOT, String(pin.fd), fileName);
}

function strictFsyncCleanupDirectory(pin) {
  assertCleanupDirectoryPin(pin);
  try { fs.fsyncSync(pin.fd); } catch (error) {
    throw cleanupDirectoryError(error, pin.label, true);
  }
  assertCleanupDirectoryPin(pin);
}

function createPrivateCleanupChild(parentPin, name, label) {
  if (!name || name === '.' || name === '..' || path.basename(name) !== name) {
    throw cleanupDirectoryError(null, label);
  }
  assertCleanupDirectoryPin(parentPin);
  const operationPath = cleanupFdPath(parentPin, name);
  const displayPath = path.join(parentPin.displayPath, name);
  let created = false;
  try {
    fs.mkdirSync(operationPath, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (error?.code !== 'EEXIST') throw cleanupDirectoryError(error, label);
  }
  const pin = openCleanupDirectory(operationPath, displayPath, label, true);
  try {
    if (created) strictFsyncCleanupDirectory(parentPin);
    assertCleanupDirectoryPin(pin);
    return { pin, created };
  } catch (error) {
    try { fs.closeSync(pin.fd); } catch {}
    throw error;
  }
}

function closeCleanupDirectoryPins(pins) {
  for (const pin of [...pins].reverse()) try { fs.closeSync(pin.fd); } catch {}
}

function prepareCleanupSourceDirectories(rootDirectory, options = {}) {
  const pins = [];
  const sourcePins = new Map();
  try {
    const rootPin = openCleanupDirectory(rootDirectory, rootDirectory, 'GPT_REGISTER_ROOT');
    pins.push(rootPin);
    for (const source of SOURCES) {
      const displayPath = path.join(rootDirectory, source);
      const pin = openCleanupDirectory(cleanupFdPath(rootPin, source), displayPath, source + ' 目录');
      if (options.sync === true) strictFsyncCleanupDirectory(pin);
      pins.push(pin);
      sourcePins.set(source, pin);
    }
    return { pins, sourcePins };
  } catch (error) {
    closeCleanupDirectoryPins(pins);
    throw error;
  }
}

function inspectTokenCleanupClaims(preparedSources) {
  let claimCount = 0;
  let claimCountTruncated = false;
  assertPreparedCleanupDirectories(preparedSources);
  for (const source of SOURCES) {
    const pin = preparedSources.sourcePins.get(source);
    if (!pin) throw cleanupDirectoryError(null, source + ' 目录');
    try {
      forEachBoundedCleanupDirectoryEntry(cleanupFdPath(pin), (name) => {
        // Unknown or malformed claim generations are deliberately included.
        // Treating an unparseable staging name as ordinary input could strand or
        // overwrite the only recoverable copy of a token.
        if (!name.startsWith(CLAIM_PREFIX)) return;
        if (claimCount < MAX_REPORTED_CLEANUP_CLAIMS) claimCount += 1;
        else claimCountTruncated = true;
      });
    } catch (error) {
      if (error?.code === 'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT') throw error;
      throw cleanupDirectoryError(error, source + ' 目录');
    }
    assertCleanupDirectoryPin(pin);
  }
  assertPreparedCleanupDirectories(preparedSources);
  return {
    recoveryRequired: claimCount > 0 || claimCountTruncated,
    claimCount,
    claimCountTruncated,
  };
}

function assertTokenCleanupRecoveryNotRequired(status) {
  if (status?.recoveryRequired !== true) return;
  const error = new Error('检测到未完成的 token 清理 claim；普通清理已阻断且不会自动恢复，请由管理员核验后处理');
  error.code = 'TOKEN_CLEANUP_RECOVERY_REQUIRED';
  error.recoveryRequired = true;
  error.claimCount = boundedCleanupCount(status.claimCount);
  error.claimCountTruncated = status.claimCountTruncated === true;
  error.blockedBeforeStart = true;
  error.executionOutcome = 'not_started';
  error.retryAllowed = false;
  error.doNotRetry = true;
  throw error;
}

function prepareQuarantineDirectories(rootDirectory, quarantineRoot, sources) {
  const pins = [];
  try {
    const resolvedQuarantine = path.resolve(quarantineRoot);
    let boundary = resolvedQuarantine.startsWith(rootDirectory + path.sep)
      ? rootDirectory
      : path.dirname(resolvedQuarantine);
    while (!pathEntryExists(boundary)) boundary = path.dirname(boundary);
    let quarantinePin = openCleanupDirectory(boundary, boundary, 'token 隔离目录边界');
    pins.push(quarantinePin);
    const relative = path.relative(boundary, resolvedQuarantine);
    if (!relative || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
      throw cleanupDirectoryError(null, '过期 token 隔离目录');
    }
    for (const component of relative.split(path.sep).filter(Boolean)) {
      const created = createPrivateCleanupChild(quarantinePin, component, '过期 token 隔离目录');
      quarantinePin = created.pin;
      pins.push(quarantinePin);
    }
    strictFsyncCleanupDirectory(quarantinePin);

    let batch;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const batchName = new Date().toISOString().replace(/[:.]/g, '-')
        + '-' + process.pid + '-' + crypto.randomBytes(4).toString('hex');
      const created = createPrivateCleanupChild(quarantinePin, batchName, 'token 隔离批次目录');
      if (created.created) {
        batch = created.pin;
        pins.push(batch);
        break;
      }
      try { fs.closeSync(created.pin.fd); } catch {}
    }
    if (!batch) throw cleanupDirectoryError(null, 'token 隔离批次目录');

    const quarantineSourcePins = new Map();
    for (const source of [...sources].sort(compareCleanupPaths)) {
      if (!SOURCES.has(source)) throw cleanupDirectoryError(null, 'token 隔离子目录');
      const created = createPrivateCleanupChild(batch, source, 'token 隔离子目录');
      if (!created.created) {
        try { fs.closeSync(created.pin.fd); } catch {}
        throw cleanupDirectoryError(null, 'token 隔离子目录');
      }
      pins.push(created.pin);
      quarantineSourcePins.set(source, created.pin);
    }
    for (const pin of pins) assertCleanupDirectoryPin(pin);
    return { pins, quarantinePin, batch, quarantineSourcePins };
  } catch (error) {
    closeCleanupDirectoryPins(pins);
    throw error;
  }
}

function assertPreparedCleanupDirectories(prepared) {
  for (const pin of prepared.pins) assertCleanupDirectoryPin(pin);
}

function assertPublishedCleanupTarget(targetPath, targetDescriptor, expectedStat) {
  const linked = fs.lstatSync(targetPath);
  const opened = fs.fstatSync(targetDescriptor);
  const currentUid = cleanupProcessUid();
  if (linked.isSymbolicLink() || !linked.isFile() || !opened.isFile()
      || !sameInode(linked, expectedStat) || !sameInode(opened, expectedStat)
      || linked.nlink !== 1 || opened.nlink !== 1
      || (currentUid !== null && (linked.uid !== currentUid || opened.uid !== currentUid))
      || (linked.mode & 0o022) !== 0 || (opened.mode & 0o022) !== 0) {
    throw new Error('隔离目标在持久化确认期间发生变化');
  }
}

function assertCleanupMoveSource(stat, expectedSnapshot = null) {
  const currentUid = cleanupProcessUid();
  if (!stat?.isFile() || stat.isSymbolicLink()
      || stat.nlink !== 1
      || (currentUid !== null && stat.uid !== currentUid)
      || (stat.mode & 0o022) !== 0
      || (expectedSnapshot && !sameClaimSnapshot(stat, expectedSnapshot))) {
    throw new Error('隔离来源与已验证的普通文件快照不一致');
  }
}

function moveToQuarantine(sourcePath, targetPath, options = {}) {
  let targetLinked = false;
  let linkedTargetDescriptor;
  let targetIdentity = null;
  let sourceRemoved = false;
  let sourceIdentityBeforeLink = null;
  try {
    // Hard-link + unlink is a no-overwrite move on one filesystem. If the
    // process crashes between the two operations, both names still reference
    // the same recoverable inode instead of losing the only copy.
    const sourceBeforeLink = fs.lstatSync(sourcePath);
    assertCleanupMoveSource(sourceBeforeLink, options.expectedSourceSnapshot);
    sourceIdentityBeforeLink = sourceBeforeLink;
    targetIdentity = sourceBeforeLink;
    fs.linkSync(sourcePath, targetPath);
    targetLinked = true;
    const sourceStat = fs.lstatSync(sourcePath);
    const targetStat = fs.lstatSync(targetPath);
    targetIdentity = targetStat;
    if (sourceStat.isSymbolicLink() || targetStat.isSymbolicLink()
        || !sourceStat.isFile() || !targetStat.isFile()
        || !sameInode(sourceStat, sourceBeforeLink)
        || sourceStat.nlink !== 2 || targetStat.nlink !== 2
        || sourceStat.dev !== targetStat.dev || sourceStat.ino !== targetStat.ino) {
      throw new Error('隔离目标不是来源文件的预期硬链接');
    }
    linkedTargetDescriptor = fs.openSync(targetPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const openedTarget = fs.fstatSync(linkedTargetDescriptor);
    if (!openedTarget.isFile() || !sameInode(openedTarget, targetStat)) {
      throw new Error('隔离目标在权限收紧前发生变化');
    }
    fs.fchmodSync(linkedTargetDescriptor, 0o600);
    // The target name must never become the only name of an inode whose data or
    // tightened permissions have not reached stable storage yet.
    fs.fsyncSync(linkedTargetDescriptor);
    syncCleanupDirectory(path.dirname(targetPath));
    const latestSource = fs.lstatSync(sourcePath);
    const latestTarget = fs.lstatSync(targetPath);
    const finalOpenedTarget = fs.fstatSync(linkedTargetDescriptor);
    if (latestSource.isSymbolicLink() || !latestSource.isFile()
        || latestTarget.isSymbolicLink() || !latestTarget.isFile()
        || !sameInode(latestSource, targetStat)
        || !sameInode(latestTarget, targetStat)
        || !sameInode(finalOpenedTarget, targetStat)
        || latestSource.nlink !== 2 || latestTarget.nlink !== 2
        || finalOpenedTarget.nlink !== 2) {
      throw new Error('隔离来源或目标在发布后发生变化');
    }
    if (typeof options.beforeSourceUnlink === 'function') options.beforeSourceUnlink();
    fs.unlinkSync(sourcePath);
    sourceRemoved = true;
    syncCleanupDirectory(path.dirname(sourcePath));
    fs.fsyncSync(linkedTargetDescriptor);
    assertPublishedCleanupTarget(targetPath, linkedTargetDescriptor, targetStat);
    if (typeof options.afterSourceUnlink === 'function') options.afterSourceUnlink();
    assertPublishedCleanupTarget(targetPath, linkedTargetDescriptor, targetStat);
    fs.closeSync(linkedTargetDescriptor);
    linkedTargetDescriptor = undefined;
    return;
  } catch (error) {
    if (linkedTargetDescriptor !== undefined) {
      try { fs.closeSync(linkedTargetDescriptor); } catch {}
      linkedTargetDescriptor = undefined;
    }
    if (sourceRemoved) {
      throw cleanupWriteOutcomeUnknown(error, {
        code: 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN',
        message: 'token 已从原路径移除，但隔离持久化结果无法确认；请人工对账，禁止自动重试',
        reason: 'quarantine_move_outcome_unknown',
      });
    }
    if (error?.code !== 'EXDEV' || targetLinked) {
      if (targetLinked && !rollbackOwnedPath(targetPath, targetIdentity)) {
        throw cleanupWriteOutcomeUnknown(error, {
          code: 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN',
          message: 'token 隔离失败后的目标回滚无法确认；请人工对账，禁止自动重试',
          reason: 'quarantine_rollback_outcome_unknown',
        });
      }
      throw error;
    }
  }
  // A custom quarantine directory may be on another filesystem. Copy into a
  // private temporary file through an already-open regular-file descriptor,
  // flush it, publish without overwrite, then remove only the random staging
  // path owned by this cleanup operation.
  const temporaryPath = targetPath + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex');
  let sourceDescriptor;
  let targetDescriptor;
  let published = false;
  let publishedIdentity = null;
  let temporaryIdentity = null;
  let copiedSourceRemoved = false;
  try {
    sourceDescriptor = fs.openSync(
      sourcePath,
      fs.constants.O_RDONLY
        | (fs.constants.O_NOFOLLOW || 0)
        | (fs.constants.O_NONBLOCK || 0),
    );
    const before = fs.fstatSync(sourceDescriptor);
    assertCleanupMoveSource(before, options.expectedSourceSnapshot);
    if (!sourceIdentityBeforeLink || !sameClaimSnapshot(before, sourceIdentityBeforeLink)) {
      throw new Error('隔离来源在跨文件系统回退前发生变化');
    }
    targetDescriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    temporaryIdentity = fs.fstatSync(targetDescriptor);
    copyBoundedFile(sourceDescriptor, targetDescriptor, before.size);
    const after = fs.fstatSync(sourceDescriptor);
    if (before.dev !== after.dev || before.ino !== after.ino
        || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs) {
      throw new Error('隔离来源在复制期间发生变化');
    }
    fs.fsyncSync(targetDescriptor);
    const temporaryStat = fs.fstatSync(targetDescriptor);
    temporaryIdentity = temporaryStat;
    fs.linkSync(temporaryPath, targetPath);
    published = true;
    publishedIdentity = temporaryStat;
    const publishedStat = fs.lstatSync(targetPath);
    if (!publishedStat.isFile() || publishedStat.isSymbolicLink()
        || !sameInode(publishedStat, temporaryStat)) {
      throw new Error('跨文件系统隔离目标发布后身份校验失败');
    }
    publishedIdentity = publishedStat;
    if (!rollbackOwnedPath(temporaryPath, temporaryIdentity)) {
      const error = new Error('跨文件系统隔离临时文件回滚失败');
      error.code = 'TOKEN_CLEANUP_ROLLBACK_FAILED';
      throw error;
    }
    syncCleanupDirectory(path.dirname(targetPath));
    const finalSource = fs.fstatSync(sourceDescriptor);
    const latest = fs.lstatSync(sourcePath);
    const latestTarget = fs.lstatSync(targetPath);
    const finalTarget = fs.fstatSync(targetDescriptor);
    if (latest.isSymbolicLink() || !latest.isFile()
        || latestTarget.isSymbolicLink() || !latestTarget.isFile()
        || latest.dev !== after.dev || latest.ino !== after.ino
        || !sameInode(finalSource, after)
        || !sameInode(latestTarget, publishedIdentity)
        || !sameInode(finalTarget, publishedIdentity)
        || finalSource.size !== after.size || finalSource.mtimeMs !== after.mtimeMs
        || finalSource.ctimeMs !== after.ctimeMs) {
      throw new Error('隔离来源在发布前发生变化');
    }
    assertPublishedCleanupTarget(targetPath, targetDescriptor, publishedIdentity);
    if (typeof options.beforeSourceUnlink === 'function') options.beforeSourceUnlink();
    fs.unlinkSync(sourcePath);
    copiedSourceRemoved = true;
    syncCleanupDirectory(path.dirname(sourcePath));
    fs.fsyncSync(targetDescriptor);
    assertPublishedCleanupTarget(targetPath, targetDescriptor, publishedIdentity);
    if (typeof options.afterSourceUnlink === 'function') options.afterSourceUnlink();
    assertPublishedCleanupTarget(targetPath, targetDescriptor, publishedIdentity);
  } catch (error) {
    let rollbackUnconfirmed = temporaryIdentity
      ? !rollbackOwnedPath(temporaryPath, temporaryIdentity)
      : false;
    if (copiedSourceRemoved) {
      throw cleanupWriteOutcomeUnknown(error, {
        code: 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN',
        message: 'token 已从原路径移除，但跨文件系统隔离持久化结果无法确认；请人工对账，禁止自动重试',
        reason: 'quarantine_move_outcome_unknown',
      });
    }
    if (published
        && (!publishedIdentity || !rollbackOwnedPath(targetPath, publishedIdentity))) {
      rollbackUnconfirmed = true;
    }
    if (rollbackUnconfirmed) {
      throw cleanupWriteOutcomeUnknown(error, {
        code: 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN',
        message: 'token 隔离失败后的跨文件系统回滚无法确认；请人工对账，禁止自动重试',
        reason: 'quarantine_rollback_outcome_unknown',
      });
    }
    throw error;
  } finally {
    if (sourceDescriptor !== undefined) {
      try { fs.closeSync(sourceDescriptor); } catch {}
    }
    if (targetDescriptor !== undefined) {
      try { fs.closeSync(targetDescriptor); } catch {}
    }
  }
}

function claimSourcePath(sourcePath, expectedHash) {
  const directory = path.dirname(sourcePath);
  const fileName = path.basename(sourcePath);
  const owner = currentProcessOwner();
  const encodedName = Buffer.from(fileName, 'utf8').toString('base64url');
  const normalizedHash = String(expectedHash || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(normalizedHash)) throw new Error('token claim 缺少有效内容摘要');
  const normalizedBootId = String(owner.processBootId || '').replace(/-/g, '').toLowerCase();
  const encodedBootId = /^[a-f0-9]{32}$/.test(normalizedBootId)
    ? Buffer.from(normalizedBootId, 'hex').toString('base64url')
    : '0';
  const encodedHash = Buffer.from(normalizedHash, 'hex').toString('base64url');
  for (let attempt = 0; attempt < 20; attempt += 1) {
    // Dot separators are outside base64url, so the compact metadata remains
    // unambiguous while leaving enough room for ordinary token filenames.
    const claimName = CLAIM_PREFIX_V2 + [
      String(owner.pid),
      String(owner.processStartId || '0'),
      encodedBootId,
      encodedHash,
      encodedName,
      crypto.randomBytes(8).toString('base64url'),
    ].join('.');
    // Filesystems generally cap one path component at 255 bytes. Fail before
    // hiding a source whose basename cannot be represented recoverably.
    if (Buffer.byteLength(claimName) > 240) {
      const error = new Error('token 文件名过长，无法创建可恢复的清理 claim');
      error.code = 'TOKEN_CLEANUP_FILENAME_TOO_LONG';
      throw error;
    }
    const claimPath = path.join(directory, claimName);
    if (fs.existsSync(claimPath)) continue;
    let replacementStarted = false;
    try {
      replacementStarted = true;
      fs.renameSync(sourcePath, claimPath);
      syncCleanupDirectory(directory);
    } catch (error) {
      if (replacementStarted) {
        throw cleanupWriteOutcomeUnknown(error, {
          code: 'TOKEN_CLEANUP_CLAIM_OUTCOME_UNKNOWN',
          message: 'token claim 创建结果无法确认；请人工对账，禁止自动重试',
          reason: 'token_claim_outcome_unknown',
        });
      }
      throw error;
    }
    return claimPath;
  }
  throw new Error('无法创建唯一的 token 隔离暂存路径');
}

function parseClaimName(fileName) {
  const value = String(fileName);
  if (value.startsWith(CLAIM_PREFIX_V2)) {
    const body = value.slice(CLAIM_PREFIX_V2.length);
    const match = body.match(/^([1-9]\d*)\.(0|[1-9]\d*)\.([A-Za-z0-9_-]{22}|0)\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{11})$/);
    if (!match) return null;
    let bootBytes;
    let hashBytes;
    let originalFileName;
    let nonceBytes;
    try {
      bootBytes = match[3] === '0' ? null : Buffer.from(match[3], 'base64url');
      hashBytes = Buffer.from(match[4], 'base64url');
      originalFileName = Buffer.from(match[5], 'base64url').toString('utf8');
      nonceBytes = Buffer.from(match[6], 'base64url');
    } catch { return null; }
    if ((bootBytes && (bootBytes.length !== 16 || bootBytes.toString('base64url') !== match[3]))
        || hashBytes.length !== 32 || hashBytes.toString('base64url') !== match[4]
        || Buffer.from(originalFileName, 'utf8').toString('base64url') !== match[5]
        || nonceBytes.length !== 8 || nonceBytes.toString('base64url') !== match[6]) return null;
    if (!originalFileName
        || path.basename(originalFileName) !== originalFileName
        || !originalFileName.toLowerCase().endsWith('.json')) return null;
    const pid = Number(match[1]);
    if (!Number.isSafeInteger(pid) || pid <= 0) return null;
    const bootHex = bootBytes?.toString('hex') || '';
    return {
      pid,
      processStartId: match[2] === '0' ? null : match[2],
      processBootId: bootHex
        ? bootHex.slice(0, 8) + '-' + bootHex.slice(8, 12) + '-' + bootHex.slice(12, 16)
          + '-' + bootHex.slice(16, 20) + '-' + bootHex.slice(20)
        : null,
      contentHash: hashBytes.toString('hex'),
      originalFileName,
    };
  }

  if (!value.startsWith(CLAIM_PREFIX_V1)) return null;
  const body = value.slice(CLAIM_PREFIX_V1.length);
  const match = body.match(/^([1-9]\d*)-(0|[1-9]\d*)-([a-f0-9]{64})-([A-Za-z0-9_-]+)-([a-f0-9]{16})$/);
  if (!match) return null;
  let originalFileName = '';
  try { originalFileName = Buffer.from(match[4], 'base64url').toString('utf8'); } catch { return null; }
  if (!originalFileName
      || path.basename(originalFileName) !== originalFileName
      || !originalFileName.toLowerCase().endsWith('.json')
      || Buffer.from(originalFileName, 'utf8').toString('base64url') !== match[4]) return null;
  const pid = Number(match[1]);
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  return {
    pid,
    processStartId: match[2] === '0' ? null : match[2],
    processBootId: null,
    contentHash: match[3].toLowerCase(),
    originalFileName,
  };
}

function sameClaimSnapshot(stat, snapshot) {
  if (!snapshot) return true;
  return Boolean(stat
    && stat.dev === snapshot.dev
    && stat.ino === snapshot.ino
    && stat.size === snapshot.size
    && stat.mtimeMs === snapshot.mtimeMs
    && stat.ctimeMs === snapshot.ctimeMs
    && stat.nlink === snapshot.nlink
    && stat.uid === snapshot.uid
    && stat.mode === snapshot.mode);
}

function cleanupCreatedRestoreLink(sourcePath, claimPath, claimStat) {
  try {
    const latestClaim = fs.lstatSync(claimPath);
    if (!sameInode(latestClaim, claimStat)) return false;
    let latestSource;
    try { latestSource = fs.lstatSync(sourcePath); } catch (error) {
      return error?.code === 'ENOENT';
    }
    if (!sameInode(latestSource, claimStat)) return false;
    fs.unlinkSync(sourcePath);
    syncCleanupDirectory(path.dirname(sourcePath));
    try {
      const after = fs.lstatSync(sourcePath);
      return !sameInode(after, claimStat);
    } catch (error) {
      return error?.code === 'ENOENT';
    }
  } catch {
    // If the claim itself disappeared or changed identity, the source link may
    // be its last remaining name. Leave it for reconciliation instead of
    // risking deletion of the only recoverable copy.
    return false;
  }
}

function restoreOutcomeUnknown(error) {
  return cleanupWriteOutcomeUnknown(error, {
    code: 'TOKEN_CLEANUP_RESTORE_OUTCOME_UNKNOWN',
    message: 'token claim 恢复的命名空间结果无法确认；请人工对账，禁止自动重试',
    reason: 'token_claim_restore_outcome_unknown',
  });
}

function restoreClaimedPath(claimPath, sourcePath, expectedSnapshot = null) {
  let claimStat = null;
  let sourceLinkCreated = false;
  let claimRemoved = false;
  try {
    // linkSync refuses to overwrite a fresh token recreated at the original
    // path while cleanup was validating the claimed inode.
    claimStat = fs.lstatSync(claimPath);
    if (claimStat.isSymbolicLink() || !claimStat.isFile()
        || !sameClaimSnapshot(claimStat, expectedSnapshot)) return false;
    fs.linkSync(claimPath, sourcePath);
    sourceLinkCreated = true;
    const restoredStat = fs.lstatSync(sourcePath);
    if (restoredStat.isSymbolicLink() || !restoredStat.isFile()
        || !sameInode(restoredStat, claimStat)) {
      if (cleanupCreatedRestoreLink(sourcePath, claimPath, claimStat)) {
        sourceLinkCreated = false;
        return false;
      }
      throw restoreOutcomeUnknown();
    }
    syncCleanupDirectory(path.dirname(sourcePath));
    const latestSource = fs.lstatSync(sourcePath);
    if (latestSource.isSymbolicLink() || !latestSource.isFile()
        || !sameInode(latestSource, claimStat)) {
      if (cleanupCreatedRestoreLink(sourcePath, claimPath, claimStat)) {
        sourceLinkCreated = false;
        return false;
      }
      throw restoreOutcomeUnknown();
    }
    unlinkIfSameInode(claimPath, claimStat);
    try {
      const latestClaim = fs.lstatSync(claimPath);
      if (sameInode(latestClaim, claimStat)) {
        if (cleanupCreatedRestoreLink(sourcePath, claimPath, claimStat)) {
          sourceLinkCreated = false;
          return false;
        }
      }
      throw restoreOutcomeUnknown();
    } catch (error) {
      if (error?.writeOutcomeUnknown === true) throw error;
      if (error?.code !== 'ENOENT') {
        if (cleanupCreatedRestoreLink(sourcePath, claimPath, claimStat)) {
          sourceLinkCreated = false;
          return false;
        }
        throw restoreOutcomeUnknown(error);
      }
      claimRemoved = true;
    }
    syncCleanupDirectory(path.dirname(claimPath));
    sourceLinkCreated = false;
    return true;
  } catch (error) {
    if (error?.writeOutcomeUnknown === true) throw error;
    if (claimRemoved) {
      throw restoreOutcomeUnknown(error);
    }
    if (sourceLinkCreated && claimStat) {
      if (!cleanupCreatedRestoreLink(sourcePath, claimPath, claimStat)) {
        throw restoreOutcomeUnknown(error);
      }
    }
    return false;
  }
}

function safeAbsolutePath(directory, fileName) {
  const absoluteDirectory = path.resolve(directory);
  const absolutePath = path.resolve(absoluteDirectory, String(fileName || ''));
  if (absolutePath === absoluteDirectory || !absolutePath.startsWith(absoluteDirectory + path.sep)) return null;
  return absolutePath;
}

function regularFileSnapshot(filePath) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY
        | (fs.constants.O_NOFOLLOW || 0)
        | (fs.constants.O_NONBLOCK || 0),
    );
    const before = fs.fstatSync(descriptor);
    const currentUid = cleanupProcessUid();
    if (!before.isFile() || before.nlink !== 1
        || (currentUid !== null && before.uid !== currentUid)
        || (before.mode & 0o022) !== 0) {
      throw new Error('token 来源必须是当前用户持有、不可被其他用户修改的非硬链接普通文件');
    }
    const maximumBytes = cleanupTokenMaximumBytes();
    if (before.size < 0 || before.size > maximumBytes) {
      const error = new Error('token 文件超过清理安全上限');
      error.code = 'TOKEN_CLEANUP_FILE_TOO_LARGE';
      throw error;
    }
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    while (total <= maximumBytes) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      total += bytesRead;
      if (total > maximumBytes) {
        const error = new Error('token 文件超过清理安全上限');
        error.code = 'TOKEN_CLEANUP_FILE_TOO_LARGE';
        throw error;
      }
    }
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino
        || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs || total !== after.size
        || after.nlink !== 1
        || (currentUid !== null && after.uid !== currentUid)
        || (after.mode & 0o022) !== 0) {
      throw new Error('token 文件在读取期间发生变化');
    }
    return {
      dev: after.dev,
      ino: after.ino,
      size: after.size,
      mtimeMs: after.mtimeMs,
      ctimeMs: after.ctimeMs,
      nlink: after.nlink,
      uid: after.uid,
      mode: after.mode,
      contentHash: hash.digest('hex'),
    };
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function safeItem(record, snapshot) {
  return {
    source: record.source,
    relativePath: record.relativePath,
    email: record.email || '',
    expiresAt: record.expiresAt || null,
    fingerprint: record.fingerprints?.access || null,
    mtimeMs: Number(snapshot.mtimeMs) || 0,
    size: Number(snapshot.size) || 0,
    contentHash: snapshot.contentHash,
  };
}

function recoverTokenCleanupClaimsFromDirectories(rootDirectory, options = {}) {
  const discovered = [];
  // Discovery and validation are deliberately separated from restoration.
  // A conflict in the last directory must not be able to surface only after
  // an earlier claim has already been moved back into the producer namespace.
  for (const source of SOURCES) {
    const pinnedDirectory = options.sourceDirectories?.get?.(source);
    const directory = pinnedDirectory || path.join(rootDirectory, source);
    if (!pinnedDirectory) ensureDirectory(directory, source + ' 目录');
    try {
      forEachBoundedCleanupDirectoryEntry(directory, (fileName) => {
        if (!fileName.startsWith(CLAIM_PREFIX)) return;
        const claim = parseClaimName(fileName);
        if (!claim) throw cleanupRecoveryInvalid('claim_name_invalid');
        const claimPath = safeAbsolutePath(directory, fileName);
        const sourcePath = safeAbsolutePath(directory, claim.originalFileName);
        if (!claimPath || !sourcePath) throw cleanupRecoveryInvalid('claim_path_invalid');
        if (discovered.length >= MAX_RECOVERABLE_CLEANUP_CLAIMS) {
          throw cleanupClaimScanLimitExceeded('recoverable_claim_limit_exceeded');
        }
        discovered.push({
          source,
          claim,
          claimPath,
          sourcePath,
          relativePath: path.join(source, claim.originalFileName),
        });
      });
    } catch (cause) {
      if (cause?.code === 'TOKEN_CLEANUP_RECOVERY_INVALID_CLAIM'
          || cause?.code === 'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT') throw cause;
      const error = new Error('无法完整预检 token 清理 claim');
      error.code = 'TOKEN_CLEANUP_RECOVERY_FAILED';
      throw error;
    }
  }
  discovered.sort((left, right) => compareCleanupPaths(left.relativePath, right.relativePath)
    || compareCleanupPaths(left.claimPath, right.claimPath));

  const claimsByOriginal = new Map();
  for (const item of discovered) {
    const key = item.sourcePath;
    const count = (claimsByOriginal.get(key) || 0) + 1;
    claimsByOriginal.set(key, count);
    if (count > 1) {
      const error = new Error('检测到多个 token 清理 claim 指向同一原路径，需要人工核验');
      error.code = 'TOKEN_CLEANUP_RECOVERY_CONFLICT';
      error.recoveryReason = 'duplicate_claims';
      throw error;
    }
  }

  const planned = [];
  for (const item of discovered) {
    if (isProcessOwnerAlive(
      item.claim.pid,
      item.claim.processStartId,
      item.claim.processBootId,
    )) continue;
    let snapshot;
    try {
      snapshot = regularFileSnapshot(item.claimPath);
    } catch {
      throw cleanupRecoveryInvalid('claim_snapshot_unavailable');
    }
    if (snapshot.contentHash !== item.claim.contentHash) {
      throw cleanupRecoveryInvalid('claim_content_hash_mismatch');
    }
    let sourceExists;
    try { sourceExists = pathEntryExists(item.sourcePath); } catch {
      const error = new Error('无法完整预检 token 清理 claim 的原路径');
      error.code = 'TOKEN_CLEANUP_RECOVERY_FAILED';
      throw error;
    }
    if (sourceExists) {
      const error = new Error('检测到过期 token 清理 claim 与新文件冲突，需要人工核验');
      error.code = 'TOKEN_CLEANUP_RECOVERY_CONFLICT';
      error.recoveryReason = 'original_path_occupied';
      throw error;
    }
    planned.push({ ...item, snapshot });
  }

  // Revalidate the complete plan once more after discovery. No mutation is
  // allowed until every recoverable claim and every destination passes this
  // final read-only barrier.
  for (const item of planned) {
    let latest;
    try { latest = regularFileSnapshot(item.claimPath); } catch {
      const error = new Error('token 清理 claim 在恢复预检期间发生变化');
      error.code = 'TOKEN_CLEANUP_RECOVERY_CHANGED';
      throw error;
    }
    if (latest.contentHash !== item.snapshot.contentHash
        || !sameClaimSnapshot(latest, item.snapshot)) {
      const error = new Error('token 清理 claim 在恢复预检期间发生变化');
      error.code = 'TOKEN_CLEANUP_RECOVERY_CHANGED';
      throw error;
    }
    let sourceExists;
    try { sourceExists = pathEntryExists(item.sourcePath); } catch {
      const error = new Error('无法完整确认 token 清理 claim 的恢复目标');
      error.code = 'TOKEN_CLEANUP_RECOVERY_FAILED';
      throw error;
    }
    if (sourceExists) {
      const error = new Error('检测到过期 token 清理 claim 与新文件冲突，需要人工核验');
      error.code = 'TOKEN_CLEANUP_RECOVERY_CONFLICT';
      error.recoveryReason = 'original_path_occupied';
      throw error;
    }
  }

  const recovered = [];
  for (const item of planned) {
    if (!restoreClaimedPath(item.claimPath, item.sourcePath, item.snapshot)) {
      const error = new Error('无法恢复上次中断的 token 清理 claim');
      error.code = 'TOKEN_CLEANUP_RECOVERY_FAILED';
      if (recovered.length > 0) {
        error.requiresReconciliation = true;
        error.retryAllowed = false;
        error.doNotRetry = true;
        error.reconciliationScope = 'expired_token_cleanup';
        error.reconciliationReason = 'claim_recovery_partially_completed';
        error.recoveredCount = recovered.length;
      }
      throw error;
    }
    recovered.push(item.relativePath);
  }
  return recovered;
}

function recoverTokenCleanupClaims(rootDirectory, options = {}) {
  const resolvedRoot = ensureDirectory(rootDirectory || cleanupRoot(options), 'GPT_REGISTER_ROOT');
  if (options.sourceDirectories?.get) {
    return recoverTokenCleanupClaimsFromDirectories(resolvedRoot, options);
  }
  const preparedSources = prepareCleanupSourceDirectories(resolvedRoot, { sync: true });
  try {
    return recoverTokenCleanupClaimsFromDirectories(resolvedRoot, {
      ...options,
      sourceDirectories: new Map([...preparedSources.sourcePins].map(
        ([source, pin]) => [source, cleanupFdPath(pin)],
      )),
    });
  } finally {
    closeCleanupDirectoryPins(preparedSources.pins);
  }
}

function versionForItems(items) {
  return crypto.createHash('sha256')
    .update(JSON.stringify([...items].sort(compareCleanupPaths).map((item) => ({
      source: item.source,
      relativePath: item.relativePath,
      email: item.email,
      expiresAt: item.expiresAt,
      fingerprint: item.fingerprint,
      mtimeMs: item.mtimeMs,
      size: item.size,
      contentHash: item.contentHash,
    }))))
    .digest('hex');
}

function publicExpiredTokenItem(item) {
  const output = {
    source: item.source,
    relativePath: item.relativePath,
    email: item.email || '',
    expiresAt: item.expiresAt || null,
    fingerprint: item.fingerprint || null,
    mtimeMs: item.mtimeMs || 0,
  };
  if (item.quarantinePath) output.quarantinePath = item.quarantinePath;
  if (item.reason) output.reason = item.reason;
  return output;
}

function listExpiredTokens(options = {}) {
  const rootDirectory = ensureDirectory(cleanupRoot(options), 'GPT_REGISTER_ROOT');
  const preparedSources = prepareCleanupSourceDirectories(rootDirectory);
  try {
    const claimsBefore = inspectTokenCleanupClaims(preparedSources);
    const nowMs = Number(options.nowMs || Date.now());
    const sources = readGptRegisterSources({ rootDirectory });
    const items = [];
    for (const record of sources.tokens || []) {
      if (!SOURCES.has(record.source)
          || record.historical === true
          || record.parseStatus !== 'ok'
          || record.expiryStatus === 'invalid'
          || !record.expiresAt) continue;
      const expiresAtMs = Date.parse(record.expiresAt);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs > nowMs) continue;
      const directory = sourceDirectory(sources, record.source);
      const absolutePath = safeAbsolutePath(directory, record.fileName);
      if (!absolutePath) continue;
      try {
        const snapshot = regularFileSnapshot(absolutePath);
        // `record` was parsed from the adapter's verified FD snapshot. If the
        // path now names different bytes, never combine old expiry metadata with
        // a new token's hash and accidentally classify the replacement expired.
        if (!/^[a-f0-9]{64}$/i.test(String(record.contentHash || ''))
            || snapshot.contentHash !== String(record.contentHash).toLowerCase()) continue;
        items.push(safeItem(record, snapshot));
      } catch {
        // Files that disappear or cannot be read are left untouched.
      }
    }
    const claimsAfter = inspectTokenCleanupClaims(preparedSources);
    const claimStatus = {
      recoveryRequired: claimsBefore.recoveryRequired || claimsAfter.recoveryRequired,
      claimCount: Math.max(claimsBefore.claimCount, claimsAfter.claimCount),
      claimCountTruncated: claimsBefore.claimCountTruncated || claimsAfter.claimCountTruncated,
    };
    items.sort(compareCleanupPaths);
    const listing = {
      generatedAt: new Date(nowMs).toISOString(),
      rootDirectory,
      version: versionForItems(items),
      count: items.length,
      items: items.map(publicExpiredTokenItem),
      ...claimStatus,
    };
    Object.defineProperty(listing, '_internalItems', {
      value: items,
      enumerable: false,
    });
    return listing;
  } finally {
    closeCleanupDirectoryPins(preparedSources.pins);
  }
}

function deleteExpiredTokens(options = {}) {
  if (String(options.confirmation || '') !== CONFIRMATION) {
    const error = new Error('缺少明确的过期 token 删除确认');
    error.code = 'TOKEN_CLEANUP_CONFIRMATION_REQUIRED';
    throw error;
  }
  throwIfJobInterrupted(options.signal);
  const rootDirectory = ensureDirectory(cleanupRoot(options), 'GPT_REGISTER_ROOT');
  const preparedSources = prepareCleanupSourceDirectories(rootDirectory, { sync: true });
  let preparedQuarantine = null;
  let cleanupResult = null;
  let quarantineRoot = null;
  let batchDirectory = null;
  try {
    assertPreparedCleanupDirectories(preparedSources);
    const current = listExpiredTokens({ ...options, rootDirectory });
    assertPreparedCleanupDirectories(preparedSources);
    if (!/^[a-f0-9]{64}$/i.test(String(options.expectedVersion || ''))
        || String(options.expectedVersion).toLowerCase() !== current.version.toLowerCase()) {
      const error = new Error('过期 token 清单已变化，请重新扫描后再删除');
      error.code = 'TOKEN_CLEANUP_STALE';
      error.currentVersion = current.version;
      throw error;
    }
    const latestClaimStatus = inspectTokenCleanupClaims(preparedSources);
    assertTokenCleanupRecoveryNotRequired({
      recoveryRequired: current.recoveryRequired || latestClaimStatus.recoveryRequired,
      claimCount: Math.max(current.claimCount, latestClaimStatus.claimCount),
      claimCountTruncated: current.claimCountTruncated || latestClaimStatus.claimCountTruncated,
    });
    const deleted = [];
    const skipped = [];
    if ((current._internalItems || []).length === 0) {
      return { version: current.version, deleted, skipped, count: 0 };
    }
    throwIfJobInterrupted(options.signal);
    if (typeof options.beforeMutation === 'function') options.beforeMutation();
    throwIfJobInterrupted(options.signal);
    const plannedSources = new Set(
      (current._internalItems || []).map((item) => item.source).filter((source) => SOURCES.has(source)),
    );
    preparedQuarantine = prepareQuarantineDirectories(
      rootDirectory,
      quarantineDirectory(options),
      plannedSources,
    );
    quarantineRoot = preparedQuarantine.quarantinePin.displayPath;
    batchDirectory = preparedQuarantine.batch.displayPath;
    // All quarantine components, the batch and every required source folder are
    // durable and pinned before the first producer-visible rename.
    assertPreparedCleanupDirectories(preparedQuarantine);
    assertPreparedCleanupDirectories(preparedSources);
    for (const item of current._internalItems || []) {
      let absolutePath = null;
      let sourceFolder = null;
      let operationSourceFolder = null;
      let claimPath = null;
      let claimedSnapshot = null;
      let quarantinedPath = null;
      let quarantinedDisplayPath = null;
      try {
        const sourcePin = preparedSources.sourcePins.get(item.source);
        const quarantineSourcePin = preparedQuarantine.quarantineSourcePins.get(item.source);
        if (!sourcePin || !quarantineSourcePin) {
          throw cleanupDirectoryError(null, 'token 清理目录');
        }
        assertPreparedCleanupDirectories(preparedSources);
        assertPreparedCleanupDirectories(preparedQuarantine);
        const fileName = path.basename(item.relativePath);
        absolutePath = cleanupFdPath(sourcePin, fileName);
        sourceFolder = quarantineSourcePin.displayPath;
        operationSourceFolder = cleanupFdPath(quarantineSourcePin);
        const assertAllDirectoryPins = () => {
          assertPreparedCleanupDirectories(preparedSources);
          assertPreparedCleanupDirectories(preparedQuarantine);
        };
        const sourceSnapshot = regularFileSnapshot(absolutePath);
        if (sourceSnapshot.contentHash !== item.contentHash) {
          skipped.push({ ...item, reason: 'file_changed' });
          continue;
        }
        quarantinedPath = path.join(operationSourceFolder, fileName);
        quarantinedDisplayPath = path.join(sourceFolder, fileName);
        // A rename is recoverable and stays on the same filesystem in normal
        // deployments. Never overwrite an existing quarantine file.
        if (fs.existsSync(quarantinedPath)) {
          skipped.push({ ...item, reason: 'quarantine_target_exists' });
          continue;
        }
        // First atomically remove the path from the producer-visible namespace.
        // Every subsequent digest/copy/unlink uses this unguessable staging name,
        // never the original path where a fresh token may be recreated.
        assertPreparedCleanupDirectories(preparedSources);
        assertPreparedCleanupDirectories(preparedQuarantine);
        claimPath = claimSourcePath(absolutePath, item.contentHash);
        claimedSnapshot = regularFileSnapshot(claimPath);
        assertPreparedCleanupDirectories(preparedSources);
        assertPreparedCleanupDirectories(preparedQuarantine);
        if (claimedSnapshot.contentHash !== item.contentHash) {
          if (!restoreClaimedPath(claimPath, absolutePath, claimedSnapshot)) {
            const changedPath = path.join(
              operationSourceFolder,
              'changed-' + crypto.randomBytes(6).toString('hex') + '-' + path.basename(item.relativePath),
            );
            moveToQuarantine(claimPath, changedPath, {
              expectedSourceSnapshot: claimedSnapshot,
              beforeSourceUnlink: assertAllDirectoryPins,
              afterSourceUnlink: assertAllDirectoryPins,
            });
            assertCleanupClaimResolved(claimPath);
            claimPath = null;
            skipped.push({
              ...item,
              reason: 'file_changed_quarantined',
              quarantinePath: path.join(
                path.basename(batchDirectory),
                item.source,
                path.basename(changedPath),
              ),
            });
          } else {
            claimPath = null;
            skipped.push({ ...item, reason: 'file_changed' });
          }
          continue;
        }
        moveToQuarantine(claimPath, quarantinedPath, {
          expectedSourceSnapshot: claimedSnapshot,
          beforeSourceUnlink: assertAllDirectoryPins,
          afterSourceUnlink: assertAllDirectoryPins,
        });
        assertCleanupClaimResolved(claimPath);
        claimPath = null;
        deleted.push({
          source: item.source,
          relativePath: item.relativePath,
          email: item.email,
          expiresAt: item.expiresAt,
          fingerprint: item.fingerprint,
          mtimeMs: item.mtimeMs,
          quarantinePath: path.relative(quarantineRoot, quarantinedDisplayPath),
        });
      } catch (error) {
        if (error?.writeOutcomeUnknown === true
            || error?.requiresReconciliation === true
            || error?.doNotRetry === true) {
          const failure = attachCleanupProgress(
            error,
            item,
            deleted.length,
            skipped.length,
            {
              quarantinePath: error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN' && quarantinedDisplayPath
                ? path.relative(quarantineRoot, quarantinedDisplayPath)
                : null,
            },
          );
          throw failure;
        }
        if (error?.cleanupInfrastructureInvalid === true && !claimPath) {
          if (deleted.length > 0 || skipped.length > 0) {
            throw attachCleanupProgress(error, item, deleted.length, skipped.length);
          }
          throw error;
        }
        if (claimPath) {
          // A successful rename only proves that some directory entry now has
          // the random claim name. If its first verified snapshot failed, no
          // trusted inode/content baseline exists for either restoration or
          // quarantine. Leave the claim untouched for manual reconciliation.
          if (!claimedSnapshot) {
            throw attachCleanupProgress(
              cleanupClaimRecoveryOutcomeUnknown(error),
              item,
              deleted.length,
              skipped.length,
            );
          }
          if (error?.cleanupInfrastructureInvalid === true) {
            try {
              // Restoring a claimed token is itself a namespace mutation. A
              // source/root pin that has become foreign-owned or writable by
              // other users must remain untouched for manual reconciliation.
              assertPreparedCleanupDirectories(preparedSources);
            } catch (sourcePinError) {
              throw attachCleanupProgress(
                cleanupClaimRecoveryOutcomeUnknown(sourcePinError),
                item,
                deleted.length,
                skipped.length,
              );
            }
          }
          let restored = false;
          try {
            restored = restoreClaimedPath(claimPath, absolutePath, claimedSnapshot);
          } catch (recoveryError) {
            throw attachCleanupProgress(
              cleanupClaimRecoveryOutcomeUnknown(recoveryError),
              item,
              deleted.length,
              skipped.length,
            );
          }
          if (restored) {
            claimPath = null;
            if (error?.cleanupInfrastructureInvalid === true) {
              if (deleted.length > 0 || skipped.length > 0) {
                throw attachCleanupProgress(error, item, deleted.length, skipped.length);
              }
              throw error;
            }
          } else {
            if (error?.cleanupInfrastructureInvalid === true) {
              throw attachCleanupProgress(
                cleanupClaimRecoveryOutcomeUnknown(error),
                item,
                deleted.length,
                skipped.length,
              );
            }
            let recoveryPath = null;
            let recoveryDisplayPath = null;
            try {
              recoveryPath = path.join(
                operationSourceFolder,
                'recovery-' + crypto.randomBytes(6).toString('hex') + '-' + path.basename(item.relativePath),
              );
              recoveryDisplayPath = path.join(sourceFolder, path.basename(recoveryPath));
              moveToQuarantine(claimPath, recoveryPath, {
                expectedSourceSnapshot: claimedSnapshot,
                beforeSourceUnlink: () => {
                  assertPreparedCleanupDirectories(preparedSources);
                  assertPreparedCleanupDirectories(preparedQuarantine);
                },
                afterSourceUnlink: () => {
                  assertPreparedCleanupDirectories(preparedSources);
                  assertPreparedCleanupDirectories(preparedQuarantine);
                },
              });
              assertCleanupClaimResolved(claimPath);
              claimPath = null;
              skipped.push({
                ...item,
                reason: 'file_unavailable_quarantined',
                quarantinePath: path.relative(quarantineRoot, recoveryDisplayPath),
              });
              continue;
            } catch (recoveryError) {
              throw attachCleanupProgress(
                cleanupClaimRecoveryOutcomeUnknown(recoveryError),
                item,
                deleted.length,
                skipped.length,
                {
                  quarantinePath: recoveryError?.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
                    && recoveryDisplayPath
                    ? path.relative(quarantineRoot, recoveryDisplayPath)
                    : null,
                },
              );
            }
          }
        }
        if (error?.cleanupInfrastructureInvalid === true) {
          if (deleted.length > 0 || skipped.length > 0) {
            throw attachCleanupProgress(error, item, deleted.length, skipped.length);
          }
          throw error;
        }
        skipped.push({ ...item, reason: 'file_unavailable' });
      }
    }
    cleanupResult = {
      version: current.version,
      deleted,
      skipped: skipped.map(publicExpiredTokenItem),
      count: deleted.length,
    };
  } finally {
    if (preparedQuarantine) closeCleanupDirectoryPins(preparedQuarantine.pins);
    closeCleanupDirectoryPins(preparedSources.pins);
  }
  return cleanupResult;
}

module.exports = {
  CONFIRMATION,
  listExpiredTokens,
  deleteExpiredTokens,
  compareCleanupPaths,
  moveToQuarantine,
  claimSourcePath,
  recoverTokenCleanupClaims,
  assertTokenCleanupRecoveryNotRequired,
  restoreClaimedPath,
  quarantineDirectory,
  versionForItems,
};
