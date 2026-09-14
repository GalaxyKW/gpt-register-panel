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

// Check every existing path component. Recursive mkdir otherwise follows a
// symlink in a parent component before the final directory can be validated.
function ensureDirectoryTree(directory, label = '目录', mode = 0o700) {
  const { absolute, root, parts } = directoryParts(directory);
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw pathError(label, error);
      try { fs.mkdirSync(current, { mode }); } catch (mkdirError) {
        if (mkdirError?.code !== 'EEXIST') throw pathError(label, mkdirError);
      }
      try { stat = fs.lstatSync(current); } catch (statError) { throw pathError(label, statError); }
    }
    verifyDirectory(stat, label);
  }
  return absolute;
}

function assertDirectoryTree(directory, label = '目录') {
  const { absolute, root, parts } = directoryParts(directory);
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    let stat;
    try { stat = fs.lstatSync(current); } catch (error) { throw pathError(label, error); }
    verifyDirectory(stat, label);
  }
  return absolute;
}

function syncDirectory(directory) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0));
    fs.fsyncSync(descriptor);
  } catch {
    // Some filesystems (notably certain mounted user-space filesystems) do not
    // support fsync on directories. The file operation itself remains valid.
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

module.exports = {
  ensureDirectoryTree,
  assertDirectoryTree,
  syncDirectory,
};
