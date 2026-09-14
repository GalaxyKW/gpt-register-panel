const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { readGptRegisterSources } = require('./adapters/gptRegisterFs');
const { ensureDirectoryTree, assertDirectoryTree, syncDirectory } = require('./lib/safeFs');
const { currentProcessOwner, isProcessOwnerAlive } = require('./taskCoordinator');

const CONFIRMATION = 'DELETE_EXPIRED_TOKENS';
const SOURCES = new Set(['tokens', 'use_token']);
const CLAIM_PREFIX_V1 = '.panel-token-cleanup-claim-v1-';
const CLAIM_PREFIX_V2 = '.panel-token-cleanup-claim-v2-';
const DEFAULT_TOKEN_MAX_BYTES = 4 * 1024 * 1024;
const HARD_TOKEN_MAX_BYTES = 16 * 1024 * 1024;

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

function unlinkIfSameInode(filePath, expectedStat) {
  try {
    const latest = fs.lstatSync(filePath);
    if (sameInode(latest, expectedStat)) fs.unlinkSync(filePath);
  } catch {}
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

function ensureDirectory(directory, label, create = false) {
  try {
    return create
      ? ensureDirectoryTree(directory, label)
      : assertDirectoryTree(directory, label);
  } catch (error) {
    const wrapped = new Error(label + ' 不存在、不可读取或包含符号链接');
    wrapped.code = 'TOKEN_CLEANUP_PATH_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
}

function ensurePrivateDirectory(directory, label, create = false) {
  const resolved = ensureDirectory(directory, label, create);
  const stat = fs.lstatSync(resolved);
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
  if (!stat.isDirectory() || stat.isSymbolicLink()
      || (currentUid !== null && stat.uid !== currentUid)
      || (stat.mode & 0o077) !== 0) {
    const error = new Error(label + ' 必须由当前用户持有且权限为 0700 或更严格');
    error.code = 'TOKEN_CLEANUP_PATH_INVALID';
    throw error;
  }
  return resolved;
}

function moveToQuarantine(sourcePath, targetPath) {
  let targetLinked = false;
  let linkedTargetDescriptor;
  let targetIdentity = null;
  let sourceRemoved = false;
  try {
    // Hard-link + unlink is a no-overwrite move on one filesystem. If the
    // process crashes between the two operations, both names still reference
    // the same recoverable inode instead of losing the only copy.
    fs.linkSync(sourcePath, targetPath);
    targetLinked = true;
    const sourceStat = fs.lstatSync(sourcePath);
    const targetStat = fs.lstatSync(targetPath);
    targetIdentity = targetStat;
    if (sourceStat.isSymbolicLink() || targetStat.isSymbolicLink()
        || !sourceStat.isFile() || !targetStat.isFile()
        || sourceStat.dev !== targetStat.dev || sourceStat.ino !== targetStat.ino) {
      throw new Error('隔离目标不是来源文件的预期硬链接');
    }
    linkedTargetDescriptor = fs.openSync(targetPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const openedTarget = fs.fstatSync(linkedTargetDescriptor);
    if (!openedTarget.isFile() || !sameInode(openedTarget, targetStat)) {
      throw new Error('隔离目标在权限收紧前发生变化');
    }
    fs.fchmodSync(linkedTargetDescriptor, 0o600);
    syncDirectory(path.dirname(targetPath));
    const latestSource = fs.lstatSync(sourcePath);
    const latestTarget = fs.lstatSync(targetPath);
    const finalOpenedTarget = fs.fstatSync(linkedTargetDescriptor);
    if (latestSource.isSymbolicLink() || !latestSource.isFile()
        || latestTarget.isSymbolicLink() || !latestTarget.isFile()
        || !sameInode(latestSource, targetStat)
        || !sameInode(latestTarget, targetStat)
        || !sameInode(finalOpenedTarget, targetStat)) {
      throw new Error('隔离来源或目标在发布后发生变化');
    }
    fs.unlinkSync(sourcePath);
    sourceRemoved = true;
    syncDirectory(path.dirname(sourcePath));
    fs.closeSync(linkedTargetDescriptor);
    linkedTargetDescriptor = undefined;
    return;
  } catch (error) {
    if (linkedTargetDescriptor !== undefined) {
      try { fs.closeSync(linkedTargetDescriptor); } catch {}
      linkedTargetDescriptor = undefined;
    }
    if (error?.code !== 'EXDEV' || targetLinked) {
      if (!sourceRemoved && targetLinked && targetIdentity) unlinkIfSameInode(targetPath, targetIdentity);
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
    sourceDescriptor = fs.openSync(sourcePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const before = fs.fstatSync(sourceDescriptor);
    if (!before.isFile()) throw new Error('隔离来源必须是普通文件');
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
    const publishedStat = fs.lstatSync(targetPath);
    if (!publishedStat.isFile() || publishedStat.isSymbolicLink()
        || !sameInode(publishedStat, temporaryStat)) {
      throw new Error('跨文件系统隔离目标发布后身份校验失败');
    }
    publishedIdentity = publishedStat;
    published = true;
    unlinkIfSameInode(temporaryPath, temporaryIdentity);
    syncDirectory(path.dirname(targetPath));
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
    fs.unlinkSync(sourcePath);
    copiedSourceRemoved = true;
    syncDirectory(path.dirname(sourcePath));
  } catch (error) {
    if (temporaryIdentity) unlinkIfSameInode(temporaryPath, temporaryIdentity);
    if (published && !copiedSourceRemoved) {
      unlinkIfSameInode(targetPath, publishedIdentity);
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
    fs.renameSync(sourcePath, claimPath);
    syncDirectory(directory);
    return claimPath;
  }
  throw new Error('无法创建唯一的 token 隔离暂存路径');
}

function parseClaimName(fileName) {
  const value = String(fileName);
  if (value.startsWith(CLAIM_PREFIX_V2)) {
    const body = value.slice(CLAIM_PREFIX_V2.length);
    const match = body.match(/^(\d+)\.(\d+)\.([A-Za-z0-9_-]{22}|0)\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{11})$/);
    if (!match) return null;
    let bootBytes;
    let hashBytes;
    let originalFileName;
    try {
      bootBytes = match[3] === '0' ? null : Buffer.from(match[3], 'base64url');
      hashBytes = Buffer.from(match[4], 'base64url');
      originalFileName = Buffer.from(match[5], 'base64url').toString('utf8');
    } catch { return null; }
    if ((bootBytes && (bootBytes.length !== 16 || bootBytes.toString('base64url') !== match[3]))
        || hashBytes.length !== 32 || hashBytes.toString('base64url') !== match[4]
        || Buffer.from(originalFileName, 'utf8').toString('base64url') !== match[5]) return null;
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
  const match = body.match(/^(\d+)-([0-9]+)-([a-f0-9]{64})-([A-Za-z0-9_-]+)-([a-f0-9]{16})$/i);
  if (!match) return null;
  let originalFileName = '';
  try { originalFileName = Buffer.from(match[4], 'base64url').toString('utf8'); } catch { return null; }
  if (!originalFileName
      || path.basename(originalFileName) !== originalFileName
      || !originalFileName.toLowerCase().endsWith('.json')) return null;
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

function restoreClaimedPath(claimPath, sourcePath) {
  try {
    // linkSync refuses to overwrite a fresh token recreated at the original
    // path while cleanup was validating the claimed inode.
    const claimStat = fs.lstatSync(claimPath);
    if (claimStat.isSymbolicLink() || !claimStat.isFile()) return false;
    fs.linkSync(claimPath, sourcePath);
    const restoredStat = fs.lstatSync(sourcePath);
    if (restoredStat.isSymbolicLink() || !restoredStat.isFile()
        || !sameInode(restoredStat, claimStat)) return false;
    syncDirectory(path.dirname(sourcePath));
    unlinkIfSameInode(claimPath, claimStat);
    try {
      const latestClaim = fs.lstatSync(claimPath);
      if (sameInode(latestClaim, claimStat)) return false;
    } catch (error) {
      if (error?.code !== 'ENOENT') return false;
    }
    syncDirectory(path.dirname(claimPath));
    return true;
  } catch {
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
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
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

function recoverTokenCleanupClaims(rootDirectory) {
  const recovered = [];
  for (const source of SOURCES) {
    const directory = path.join(rootDirectory, source);
    ensureDirectory(directory, source + ' 目录');
    let names;
    try { names = fs.readdirSync(directory); } catch { continue; }
    for (const fileName of names) {
      const claim = parseClaimName(fileName);
      if (!claim || isProcessOwnerAlive(
        claim.pid,
        claim.processStartId,
        claim.processBootId,
      )) continue;
      const claimPath = safeAbsolutePath(directory, fileName);
      const sourcePath = safeAbsolutePath(directory, claim.originalFileName);
      if (!claimPath || !sourcePath) continue;
      let snapshot;
      try { snapshot = regularFileSnapshot(claimPath); } catch { continue; }
      if (snapshot.contentHash !== claim.contentHash) continue;
      if (fs.existsSync(sourcePath)) {
        const error = new Error('检测到过期 token 清理 claim 与新文件冲突，需要人工核验');
        error.code = 'TOKEN_CLEANUP_RECOVERY_CONFLICT';
        throw error;
      }
      if (!restoreClaimedPath(claimPath, sourcePath)) {
        const error = new Error('无法恢复上次中断的 token 清理 claim');
        error.code = 'TOKEN_CLEANUP_RECOVERY_FAILED';
        throw error;
      }
      recovered.push(path.join(source, claim.originalFileName));
    }
  }
  return recovered;
}

function versionForItems(items) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(items.map((item) => ({
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
  items.sort((left, right) => String(left.relativePath).localeCompare(
    String(right.relativePath), 'en', { numeric: true, sensitivity: 'base' },
  ));
  const listing = {
    generatedAt: new Date(nowMs).toISOString(),
    rootDirectory,
    version: versionForItems(items),
    count: items.length,
    items: items.map(publicExpiredTokenItem),
  };
  Object.defineProperty(listing, '_internalItems', {
    value: items,
    enumerable: false,
  });
  return listing;
}

function deleteExpiredTokens(options = {}) {
  if (String(options.confirmation || '') !== CONFIRMATION) {
    const error = new Error('缺少明确的过期 token 删除确认');
    error.code = 'TOKEN_CLEANUP_CONFIRMATION_REQUIRED';
    throw error;
  }
  recoverTokenCleanupClaims(cleanupRoot(options));
  const current = listExpiredTokens(options);
  if (!/^[a-f0-9]{64}$/i.test(String(options.expectedVersion || ''))
      || String(options.expectedVersion).toLowerCase() !== current.version.toLowerCase()) {
    const error = new Error('过期 token 清单已变化，请重新扫描后再删除');
    error.code = 'TOKEN_CLEANUP_STALE';
    error.currentVersion = current.version;
    throw error;
  }
  const deleted = [];
  const skipped = [];
  const quarantineRoot = ensurePrivateDirectory(
    quarantineDirectory(options),
    '过期 token 隔离目录',
    true,
  );
  const batchDirectory = path.join(
    quarantineRoot,
    new Date().toISOString().replace(/[:.]/g, '-') + '-' + process.pid + '-' + crypto.randomBytes(4).toString('hex'),
  );
  let batchCreated = false;
  const createdSourceFolders = new Set();
  for (const item of current._internalItems || []) {
    const directory = item.source === 'tokens'
      ? path.join(current.rootDirectory, 'tokens')
      : path.join(current.rootDirectory, 'use_token');
    try { ensureDirectory(directory, item.source + ' 目录'); } catch {
      skipped.push({ ...item, reason: 'source_directory_unavailable' });
      continue;
    }
    const absolutePath = safeAbsolutePath(directory, path.basename(item.relativePath));
    if (!absolutePath) {
      skipped.push({ ...item, reason: 'unsafe_path' });
      continue;
    }
    let claimPath = null;
    try {
      const sourceSnapshot = regularFileSnapshot(absolutePath);
      if (sourceSnapshot.contentHash !== item.contentHash) {
        skipped.push({ ...item, reason: 'file_changed' });
        continue;
      }
      const sourceFolder = path.join(batchDirectory, item.source);
      ensurePrivateDirectory(sourceFolder, 'token 隔离子目录', true);
      createdSourceFolders.add(sourceFolder);
      const quarantinedPath = path.join(sourceFolder, path.basename(item.relativePath));
      // A rename is recoverable and stays on the same filesystem in normal
      // deployments. Never overwrite an existing quarantine file.
      if (fs.existsSync(quarantinedPath)) {
        skipped.push({ ...item, reason: 'quarantine_target_exists' });
        continue;
      }
      // First atomically remove the path from the producer-visible namespace.
      // Every subsequent digest/copy/unlink uses this unguessable staging name,
      // never the original path where a fresh token may be recreated.
      claimPath = claimSourcePath(absolutePath, item.contentHash);
      const claimedSnapshot = regularFileSnapshot(claimPath);
      if (claimedSnapshot.contentHash !== item.contentHash) {
        if (!restoreClaimedPath(claimPath, absolutePath)) {
          const changedPath = path.join(
            sourceFolder,
            'changed-' + crypto.randomBytes(6).toString('hex') + '-' + path.basename(item.relativePath),
          );
          moveToQuarantine(claimPath, changedPath);
          claimPath = null;
          batchCreated = true;
          skipped.push({
            ...item,
            reason: 'file_changed_quarantined',
            quarantinePath: path.relative(quarantineRoot, changedPath),
          });
        } else {
          claimPath = null;
          skipped.push({ ...item, reason: 'file_changed' });
        }
        continue;
      }
      moveToQuarantine(claimPath, quarantinedPath);
      claimPath = null;
      batchCreated = true;
      deleted.push({
        source: item.source,
        relativePath: item.relativePath,
        email: item.email,
        expiresAt: item.expiresAt,
        fingerprint: item.fingerprint,
        mtimeMs: item.mtimeMs,
        quarantinePath: path.relative(quarantineRoot, quarantinedPath),
      });
    } catch {
      if (claimPath && !restoreClaimedPath(claimPath, absolutePath)) {
        try {
          const sourceFolder = path.join(batchDirectory, item.source);
          ensurePrivateDirectory(sourceFolder, 'token 隔离子目录', true);
          createdSourceFolders.add(sourceFolder);
          const recoveryPath = path.join(
            sourceFolder,
            'recovery-' + crypto.randomBytes(6).toString('hex') + '-' + path.basename(item.relativePath),
          );
          moveToQuarantine(claimPath, recoveryPath);
          batchCreated = true;
          skipped.push({
            ...item,
            reason: 'file_unavailable_quarantined',
            quarantinePath: path.relative(quarantineRoot, recoveryPath),
          });
          continue;
        } catch {}
      }
      skipped.push({ ...item, reason: 'file_unavailable' });
    }
  }
  if (!batchCreated) {
    for (const sourceFolder of createdSourceFolders) {
      try { fs.rmdirSync(sourceFolder); } catch {}
    }
    try { fs.rmdirSync(batchDirectory); } catch {}
  }
  return {
    version: current.version,
    deleted,
    skipped: skipped.map(publicExpiredTokenItem),
    count: deleted.length,
  };
}

module.exports = {
  CONFIRMATION,
  listExpiredTokens,
  deleteExpiredTokens,
  moveToQuarantine,
  claimSourcePath,
  recoverTokenCleanupClaims,
  quarantineDirectory,
  versionForItems,
};
