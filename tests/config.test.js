const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { loadEnv, readEnvFile } = require('../backend/config');

test('loadEnv reads a regular file without overwriting existing environment values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-'));
  const filePath = path.join(directory, '.env');
  fs.writeFileSync(filePath, 'PANEL_CONFIG_TEST_NEW=loaded\nPANEL_CONFIG_TEST_EXISTING=replaced\n');
  const previousNew = process.env.PANEL_CONFIG_TEST_NEW;
  const previousExisting = process.env.PANEL_CONFIG_TEST_EXISTING;
  delete process.env.PANEL_CONFIG_TEST_NEW;
  process.env.PANEL_CONFIG_TEST_EXISTING = 'kept';
  try {
    assert.equal(loadEnv(filePath), true);
    assert.equal(process.env.PANEL_CONFIG_TEST_NEW, 'loaded');
    assert.equal(process.env.PANEL_CONFIG_TEST_EXISTING, 'kept');
  } finally {
    if (previousNew === undefined) delete process.env.PANEL_CONFIG_TEST_NEW;
    else process.env.PANEL_CONFIG_TEST_NEW = previousNew;
    if (previousExisting === undefined) delete process.env.PANEL_CONFIG_TEST_EXISTING;
    else process.env.PANEL_CONFIG_TEST_EXISTING = previousExisting;
  }
});

test('readEnvFile rejects final and parent-directory symlinks', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-'));
  const realDirectory = path.join(directory, 'real');
  fs.mkdirSync(realDirectory);
  const realFile = path.join(realDirectory, '.env');
  fs.writeFileSync(realFile, 'PANEL_CONFIG_TEST_VALUE=fake\n');
  const fileLink = path.join(directory, 'linked.env');
  const directoryLink = path.join(directory, 'linked-directory');
  fs.symlinkSync(realFile, fileLink);
  fs.symlinkSync(realDirectory, directoryLink, 'dir');

  assert.throws(
    () => readEnvFile(fileLink),
    (error) => error.code === 'ENV_PATH_INVALID',
  );
  assert.throws(
    () => readEnvFile(path.join(directoryLink, '.env')),
    (error) => error.code === 'ENV_PATH_INVALID',
  );
  assert.equal(readEnvFile(path.join(directory, 'missing.env')), null);
});

test('readEnvFile pins the verified parent before opening the file', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-race-'));
  const trustedDirectory = path.join(directory, 'trusted');
  const savedDirectory = path.join(directory, 'trusted-original');
  const outsideDirectory = path.join(directory, 'outside');
  fs.mkdirSync(trustedDirectory);
  fs.mkdirSync(outsideDirectory);
  const filePath = path.join(trustedDirectory, '.env');
  fs.writeFileSync(filePath, 'PANEL_CONFIG_TEST_VALUE=trusted\n');
  fs.writeFileSync(path.join(outsideDirectory, '.env'), 'PANEL_CONFIG_TEST_VALUE=outside\n');

  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = function guardedOpen(target, ...args) {
    if (!swapped && target === filePath) {
      swapped = true;
      fs.renameSync(trustedDirectory, savedDirectory);
      fs.symlinkSync(outsideDirectory, trustedDirectory, 'dir');
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    assert.throws(
      () => readEnvFile(filePath),
      (error) => error.code === 'ENV_PATH_INVALID',
    );
  } finally {
    fs.openSync = originalOpenSync;
    if (swapped) {
      fs.unlinkSync(trustedDirectory);
      fs.renameSync(savedDirectory, trustedDirectory);
    }
  }
});

test('readEnvFile rejects oversized and concurrently modified environment files', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-env-'));
  const oversized = path.join(directory, 'oversized.env');
  fs.writeFileSync(oversized, Buffer.alloc(1024 * 1024 + 1, 0x78));
  assert.throws(
    () => readEnvFile(oversized),
    (error) => error.code === 'ENV_PATH_INVALID',
  );

  const changing = path.join(directory, 'changing.env');
  fs.writeFileSync(changing, 'SAFE_VALUE=fake\n');
  const originalReadSync = fs.readSync;
  let modified = false;
  fs.readSync = function guardedRead(descriptor, ...args) {
    const bytesRead = originalReadSync.call(fs, descriptor, ...args);
    if (!modified && bytesRead > 0) {
      modified = true;
      fs.appendFileSync(changing, 'CHANGED_DURING_READ=1\n');
    }
    return bytesRead;
  };
  try {
    assert.throws(
      () => readEnvFile(changing),
      (error) => error.code === 'ENV_PATH_INVALID',
    );
  } finally {
    fs.readSync = originalReadSync;
  }
});

test('readEnvFile rejects writable-by-others and multiply linked secret files', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-env-permissions-'));
  const writable = path.join(directory, 'writable.env');
  fs.writeFileSync(writable, 'SAFE_VALUE=fake\n', { mode: 0o600 });
  fs.chmodSync(writable, 0o666);
  assert.throws(
    () => readEnvFile(writable),
    (error) => error.code === 'ENV_PATH_INVALID',
  );

  const linked = path.join(directory, 'linked.env');
  const secondName = path.join(directory, 'linked-copy.env');
  fs.writeFileSync(linked, 'SAFE_VALUE=fake\n', { mode: 0o600 });
  fs.linkSync(linked, secondName);
  assert.throws(
    () => readEnvFile(linked),
    (error) => error.code === 'ENV_PATH_INVALID',
  );
});
