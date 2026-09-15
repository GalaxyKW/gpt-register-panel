const fs = require('node:fs');
const path = require('node:path');

function pathError(label, detail) {
  const error = new Error(label + ' 必须是非符号链接目录');
  error.code = 'SAFE_FS_PATH_INVALID';
  if (detail) error.cause = detail;
  return error;
}

function directoryParts(directory) {
  const absolute = path.resolve(directory);
  const parsed = path.parse(absolute);
  const parts = absolute.slice(parsed.root.length).split(path.sep).filter(Boolean);
  return { absolute, root: parsed.root, parts };
}

function verifyDirectory(stat, label) {
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw pathError(label);
}

function openDirectoryComponent(candidate, label) {
  let initial;
  try {
    initial = fs.lstatSync(candidate);
  } catch (error) {
    throw pathError(label, error);
  }
  verifyDirectory(initial, label);
  let descriptor;
  try {
    descriptor = fs.openSync(
      candidate,
      fs.constants.O_RDONLY
        | (fs.constants.O_DIRECTORY || 0)
        | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor);
    const latest = fs.lstatSync(candidate);
    verifyDirectory(latest, label);
    if (!opened.isDirectory() || !sameFileIdentity(initial, opened)
        || !sameFileIdentity(opened, latest)) {
      throw pathError(label);
    }
    return { descriptor, stat: opened };
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (error?.code === 'SAFE_FS_PATH_INVALID') throw error;
    // ENOENT here is not an ordinary missing directory: lstat already
    // succeeded, so the pathname changed during the verified open window.
    throw pathError(label, directorySyncError(error));
  }
}

function pinnedDirectoryAccessPath(handle, fallback, label) {
  if (process.platform !== 'linux') return fallback;
  const candidate = '/proc/self/fd/' + handle.descriptor;
  try {
    const stat = fs.statSync(candidate);
    if (stat.isDirectory() && sameFileIdentity(stat, handle.stat)) return candidate;
  } catch (error) {
    throw pathError(label, directorySyncError(error));
  }
  // Silently falling back to the pathname here would reintroduce the exact
  // ancestor-swap window that descriptor-backed creation is meant to close.
  throw pathError(label, directorySyncError());
}

function syncDirectoryDescriptor(descriptor) {
  try { fs.fsyncSync(descriptor); } catch (error) {
    if (!isUnsupportedDirectoryFsyncError(error)) throw error;
  }
}

function walkDirectoryTree(directory, label, options = {}) {
  const { absolute, root, parts } = directoryParts(directory);
  let handle;
  let logical = root;
  try {
    handle = openDirectoryComponent(root, label);
    let accessPath = pinnedDirectoryAccessPath(handle, root, label);
    for (const part of parts) {
      const candidate = path.join(accessPath, part);
      let creationObserved = false;
      try {
        fs.lstatSync(candidate);
      } catch (error) {
        if (error?.code !== 'ENOENT' || options.create !== true) throw pathError(label, error);
        try {
          fs.mkdirSync(candidate, { mode: options.mode });
          creationObserved = true;
        } catch (mkdirError) {
          if (mkdirError?.code !== 'EEXIST') throw pathError(label, mkdirError);
          creationObserved = true;
        }
      }
      const child = openDirectoryComponent(candidate, label);
      try {
        if (creationObserved) syncDirectoryDescriptor(handle.descriptor);
        logical = path.join(logical, part);
        const logicalStat = fs.lstatSync(logical);
        verifyDirectory(logicalStat, label);
        if (!sameFileIdentity(logicalStat, child.stat)) throw pathError(label);
      } catch (error) {
        try { fs.closeSync(child.descriptor); } catch {}
        if (error?.code === 'SAFE_FS_PATH_INVALID') throw error;
        throw pathError(label, error);
      }
      const previous = handle;
      handle = null;
      try {
        fs.closeSync(previous.descriptor);
      } catch (closeError) {
        try { fs.closeSync(child.descriptor); } catch {}
        throw pathError(label, closeError);
      }
      handle = child;
      accessPath = pinnedDirectoryAccessPath(handle, logical, label);
    }
    // Recheck every configured component after descriptor-backed traversal;
    // a stable ancestor replacement must never be hidden by the pinned view.
    let latestPath = root;
    for (const part of parts) {
      latestPath = path.join(latestPath, part);
      verifyDirectory(fs.lstatSync(latestPath), label);
    }
    const finalStat = fs.lstatSync(absolute);
    if (!sameFileIdentity(finalStat, handle.stat)) throw pathError(label);
    const completed = handle;
    handle = null;
    try { fs.closeSync(completed.descriptor); } catch (closeError) {
      throw pathError(label, closeError);
    }
    return absolute;
  } catch (error) {
    if (error?.code === 'SAFE_FS_PATH_INVALID') throw error;
    throw pathError(label, error);
  } finally {
    if (handle?.descriptor !== undefined) {
      try { fs.closeSync(handle.descriptor); } catch {}
    }
  }
}

// Traverse through pinned directory descriptors. Recursive mkdir and ordinary
// pathname-only loops can follow a parent symlink introduced after validation.
function ensureDirectoryTree(directory, label = '目录', mode = 0o700) {
  return walkDirectoryTree(directory, label, { create: true, mode });
}

function assertDirectoryTree(directory, label = '目录') {
  return walkDirectoryTree(directory, label);
}

const UNSUPPORTED_DIRECTORY_FSYNC_CODES = new Set([
  'EINVAL',
  'ENOSYS',
  'ENOTSUP',
  'EOPNOTSUPP',
]);

function isUnsupportedDirectoryFsyncError(error) {
  return UNSUPPORTED_DIRECTORY_FSYNC_CODES.has(error?.code);
}

function sameFileIdentity(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function directorySyncError(detail) {
  const error = new Error('目录在刷盘期间发生变化或不是安全目录');
  error.code = 'SAFE_FS_DIRECTORY_CHANGED';
  if (detail) error.cause = detail;
  return error;
}

function isPinnedProcDirectoryPath(directory) {
  return process.platform === 'linux'
    && /^\/proc\/self\/fd\/\d+$/.test(path.resolve(String(directory)));
}

function syncDirectory(directory, fsApi = fs) {
  let descriptor;
  let operationError;

  try {
    // Most callers pass a normal path, which must never be allowed to turn
    // into a symlink between a mutation and its durability check. Phase3 is
    // the sole exception: it deliberately passes an inherited, already
    // pinned `/proc/self/fd/N` directory descriptor.
    const procPinned = isPinnedProcDirectoryPath(directory);
    const before = procPinned
      ? fsApi.statSync(directory)
      : fsApi.lstatSync(directory);
    if (!before.isDirectory() || (!procPinned && before.isSymbolicLink())) {
      throw directorySyncError();
    }
    descriptor = fsApi.openSync(
      directory,
      fsApi.constants.O_RDONLY
        | (fsApi.constants.O_DIRECTORY || 0)
        | (procPinned ? 0 : (fsApi.constants.O_NOFOLLOW || 0)),
    );
    const opened = fsApi.fstatSync(descriptor);
    if (!opened.isDirectory() || !sameFileIdentity(before, opened)) {
      throw directorySyncError();
    }
    try {
      fsApi.fsyncSync(descriptor);
    } catch (error) {
      if (!isUnsupportedDirectoryFsyncError(error)) operationError = error;
    }
    if (!operationError) {
      const after = procPinned
        ? fsApi.statSync(directory)
        : fsApi.lstatSync(directory);
      if (!after.isDirectory() || (!procPinned && after.isSymbolicLink())
          || !sameFileIdentity(opened, after)) {
        operationError = directorySyncError();
      }
    }
  } catch (error) {
    operationError = error;
  }

  if (descriptor !== undefined) {
    try {
      fsApi.closeSync(descriptor);
    } catch (error) {
      if (!operationError) operationError = error;
    }
  }

  if (operationError) throw operationError;
}

module.exports = {
  ensureDirectoryTree,
  assertDirectoryTree,
  isUnsupportedDirectoryFsyncError,
  syncDirectory,
};
