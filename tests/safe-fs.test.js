const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const {
  ensureDirectoryTree,
  isUnsupportedDirectoryFsyncError,
  syncDirectory,
} = require('../backend/lib/safeFs');

function codedError(code) {
  return Object.assign(new Error('simulated filesystem error'), { code });
}

function fakeDirectoryStat(dev = 1, ino = 2, options = {}) {
  return {
    dev,
    ino,
    isDirectory() { return options.directory !== false; },
    isSymbolicLink() { return options.symlink === true; },
  };
}

function fakeFs({ openError, fsyncError, closeError, before, opened, after } = {}) {
  const calls = [];
  let pathChecks = 0;
  return {
    calls,
    constants: { O_RDONLY: 0, O_DIRECTORY: 0x10000, O_NOFOLLOW: 0x20000 },
    lstatSync(directory) {
      calls.push(['lstat', directory]);
      pathChecks += 1;
      return pathChecks === 1
        ? (before || fakeDirectoryStat())
        : (after || before || fakeDirectoryStat());
    },
    openSync(directory, flags) {
      calls.push(['open', directory, flags]);
      if (openError) throw openError;
      return 42;
    },
    fstatSync(descriptor) {
      calls.push(['fstat', descriptor]);
      return opened || before || fakeDirectoryStat();
    },
    fsyncSync(descriptor) {
      calls.push(['fsync', descriptor]);
      if (fsyncError) throw fsyncError;
    },
    closeSync(descriptor) {
      calls.push(['close', descriptor]);
      if (closeError) throw closeError;
    },
  };
}

test('syncDirectory ignores only explicit unsupported directory-fsync errors', () => {
  for (const code of ['EINVAL', 'ENOSYS', 'ENOTSUP', 'EOPNOTSUPP']) {
    const fsApi = fakeFs({ fsyncError: codedError(code) });
    assert.doesNotThrow(() => syncDirectory('/safe-directory', fsApi), code);
    assert.deepEqual(fsApi.calls.map(([name]) => name), [
      'lstat', 'open', 'fstat', 'fsync', 'lstat', 'close',
    ]);
    assert.equal(isUnsupportedDirectoryFsyncError(codedError(code)), true);
  }
});

test('syncDirectory propagates real fsync failures and still closes the descriptor', () => {
  for (const code of ['EIO', 'ENOSPC', 'EROFS', 'EACCES', 'EPERM']) {
    const expected = codedError(code);
    const fsApi = fakeFs({ fsyncError: expected });
    assert.throws(() => syncDirectory('/safe-directory', fsApi), (error) => error === expected);
    assert.deepEqual(fsApi.calls.map(([name]) => name), ['lstat', 'open', 'fstat', 'fsync', 'close']);
    assert.equal(isUnsupportedDirectoryFsyncError(expected), false);
  }
});

test('syncDirectory propagates open and close failures without leaking descriptors', () => {
  const openError = codedError('EACCES');
  const openFailure = fakeFs({ openError });
  assert.throws(() => syncDirectory('/safe-directory', openFailure), (error) => error === openError);
  assert.deepEqual(openFailure.calls.map(([name]) => name), ['lstat', 'open']);

  const closeError = codedError('EIO');
  const closeFailure = fakeFs({ closeError });
  assert.throws(() => syncDirectory('/safe-directory', closeFailure), (error) => error === closeError);
  assert.deepEqual(closeFailure.calls.map(([name]) => name), [
    'lstat', 'open', 'fstat', 'fsync', 'lstat', 'close',
  ]);
});

test('syncDirectory rejects ordinary symlinks and directory identity changes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-safe-fs-'));
  const target = path.join(root, 'target');
  const linked = path.join(root, 'linked');
  fs.mkdirSync(target);
  fs.symlinkSync(target, linked, 'dir');
  assert.throws(
    () => syncDirectory(linked),
    (error) => error?.code === 'SAFE_FS_DIRECTORY_CHANGED',
  );

  const changedDuringOpen = fakeFs({
    before: fakeDirectoryStat(1, 2),
    opened: fakeDirectoryStat(1, 3),
  });
  assert.throws(
    () => syncDirectory('/safe-directory', changedDuringOpen),
    (error) => error?.code === 'SAFE_FS_DIRECTORY_CHANGED',
  );
  assert.equal(changedDuringOpen.calls.some(([name]) => name === 'fsync'), false);
  assert.equal(changedDuringOpen.calls.some(([name]) => name === 'close'), true);

  const changedAfterFsync = fakeFs({
    before: fakeDirectoryStat(1, 2),
    opened: fakeDirectoryStat(1, 2),
    after: fakeDirectoryStat(1, 4),
  });
  assert.throws(
    () => syncDirectory('/safe-directory', changedAfterFsync),
    (error) => error?.code === 'SAFE_FS_DIRECTORY_CHANGED',
  );
});

test('syncDirectory accepts an explicitly pinned Linux proc descriptor', {
  skip: process.platform !== 'linux' || !fs.existsSync('/proc/self/fd'),
}, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-safe-fs-proc-'));
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    assert.doesNotThrow(() => syncDirectory('/proc/self/fd/' + descriptor));
  } finally {
    fs.closeSync(descriptor);
  }
});

test('ensureDirectoryTree fsyncs each parent that receives a new directory entry', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-safe-mkdir-'));
  const first = path.join(root, 'first');
  const second = path.join(first, 'second');
  const rootStat = fs.statSync(root);
  const originalFsyncSync = fs.fsyncSync;
  const syncedDirectories = [];
  fs.fsyncSync = function trackedDirectorySync(descriptor) {
    const stat = fs.fstatSync(descriptor);
    if (stat.isDirectory()) syncedDirectories.push({ dev: stat.dev, ino: stat.ino });
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    assert.equal(ensureDirectoryTree(second), second);
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }
  const firstStat = fs.statSync(first);
  assert.equal(syncedDirectories.some((item) => (
    item.dev === rootStat.dev && item.ino === rootStat.ino
  )), true);
  assert.equal(syncedDirectories.some((item) => (
    item.dev === firstStat.dev && item.ino === firstStat.ino
  )), true);
});

test('ensureDirectoryTree reports a real parent fsync failure', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-safe-mkdir-fail-'));
  const target = path.join(root, 'created');
  const rootStat = fs.statSync(root);
  const originalFsyncSync = fs.fsyncSync;
  fs.fsyncSync = function failTargetParentSync(descriptor) {
    const stat = fs.fstatSync(descriptor);
    if (stat.isDirectory() && stat.dev === rootStat.dev && stat.ino === rootStat.ino) {
      throw codedError('EIO');
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    assert.throws(
      () => ensureDirectoryTree(target),
      (error) => error?.code === 'SAFE_FS_PATH_INVALID' && error?.cause?.code === 'EIO',
    );
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }
});

test('ensureDirectoryTree never creates through a parent path swapped after pinning', {
  skip: process.platform !== 'linux' || !fs.existsSync('/proc/self/fd'),
}, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-safe-race-'));
  const parent = path.join(root, 'parent');
  const movedParent = path.join(root, 'parent-pinned');
  const outside = path.join(root, 'outside');
  fs.mkdirSync(parent, { mode: 0o700 });
  fs.mkdirSync(outside, { mode: 0o700 });
  const originalMkdirSync = fs.mkdirSync;
  let swapped = false;
  fs.mkdirSync = function swapParentBeforeCreate(target, ...args) {
    if (!swapped && path.basename(String(target)) === 'child') {
      swapped = true;
      fs.renameSync(parent, movedParent);
      fs.symlinkSync(outside, parent, 'dir');
    }
    return originalMkdirSync.call(fs, target, ...args);
  };
  try {
    assert.throws(
      () => ensureDirectoryTree(path.join(parent, 'child')),
      (error) => error?.code === 'SAFE_FS_PATH_INVALID',
    );
  } finally {
    fs.mkdirSync = originalMkdirSync;
  }
  assert.equal(swapped, true);
  assert.equal(fs.existsSync(path.join(outside, 'child')), false);
  assert.equal(fs.statSync(path.join(movedParent, 'child')).isDirectory(), true);
});

test('ensureDirectoryTree fails closed when Linux cannot use its pinned proc descriptor', {
  skip: process.platform !== 'linux' || !fs.existsSync('/proc/self/fd'),
}, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-safe-proc-fail-'));
  const target = path.join(root, 'must-not-exist');
  const originalStatSync = fs.statSync;
  fs.statSync = function failProcDescriptor(candidate, ...args) {
    if (/^\/proc\/self\/fd\/\d+$/.test(String(candidate))) throw codedError('EACCES');
    return originalStatSync.call(fs, candidate, ...args);
  };
  try {
    assert.throws(
      () => ensureDirectoryTree(target),
      (error) => error?.code === 'SAFE_FS_PATH_INVALID'
        && error?.cause?.code === 'SAFE_FS_DIRECTORY_CHANGED',
    );
  } finally {
    fs.statSync = originalStatSync;
  }
  assert.equal(fs.existsSync(target), false);
});
