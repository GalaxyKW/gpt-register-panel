const assert = require('node:assert/strict');
const test = require('node:test');

require('./test-isolation');

const {
  isUnsupportedDirectoryFsyncError,
  syncDirectory,
} = require('../backend/lib/safeFs');

function codedError(code) {
  return Object.assign(new Error('simulated filesystem error'), { code });
}

function fakeFs({ openError, fsyncError, closeError } = {}) {
  const calls = [];
  return {
    calls,
    constants: { O_RDONLY: 0, O_DIRECTORY: 0x10000 },
    openSync(directory, flags) {
      calls.push(['open', directory, flags]);
      if (openError) throw openError;
      return 42;
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
    assert.deepEqual(fsApi.calls.map(([name]) => name), ['open', 'fsync', 'close']);
    assert.equal(isUnsupportedDirectoryFsyncError(codedError(code)), true);
  }
});

test('syncDirectory propagates real fsync failures and still closes the descriptor', () => {
  for (const code of ['EIO', 'ENOSPC', 'EROFS', 'EACCES', 'EPERM']) {
    const expected = codedError(code);
    const fsApi = fakeFs({ fsyncError: expected });
    assert.throws(() => syncDirectory('/safe-directory', fsApi), (error) => error === expected);
    assert.deepEqual(fsApi.calls.map(([name]) => name), ['open', 'fsync', 'close']);
    assert.equal(isUnsupportedDirectoryFsyncError(expected), false);
  }
});

test('syncDirectory propagates open and close failures without leaking descriptors', () => {
  const openError = codedError('EACCES');
  const openFailure = fakeFs({ openError });
  assert.throws(() => syncDirectory('/safe-directory', openFailure), (error) => error === openError);
  assert.deepEqual(openFailure.calls.map(([name]) => name), ['open']);

  const closeError = codedError('EIO');
  const closeFailure = fakeFs({ closeError });
  assert.throws(() => syncDirectory('/safe-directory', closeFailure), (error) => error === closeError);
  assert.deepEqual(closeFailure.calls.map(([name]) => name), ['open', 'fsync', 'close']);
});
