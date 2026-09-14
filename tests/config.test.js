const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const {
  BOOLEAN_ENV_NAMES,
  configuredEnvFile,
  loadEnv,
  parseEnvContent,
  readEnvFile,
  validateBooleanEnvironment,
} = require('../backend/config');

test('loadEnv reads a regular file without overwriting existing environment values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-'));
  const filePath = path.join(directory, '.env');
  fs.writeFileSync(
    filePath,
    'PANEL_CONFIG_TEST_NEW=loaded\nPANEL_CONFIG_TEST_EXISTING=replaced\n',
    { mode: 0o600 },
  );
  const environment = { PANEL_CONFIG_TEST_EXISTING: 'kept' };
  assert.equal(loadEnv(filePath, environment), true);
  assert.equal(environment.PANEL_CONFIG_TEST_NEW, 'loaded');
  assert.equal(environment.PANEL_CONFIG_TEST_EXISTING, 'kept');
});

test('loadEnv rejects duplicate keys without partially applying earlier values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-atomic-'));
  const filePath = path.join(directory, '.env');
  fs.writeFileSync(filePath, [
    'PANEL_CONFIG_TEST_ATOMIC=must-not-apply',
    'PANEL_CONFIG_TEST_DUPLICATE=first',
    'PANEL_CONFIG_TEST_DUPLICATE=second',
    '',
  ].join('\n'), { mode: 0o600 });
  // Duplicate detection must not be bypassed just because the parent process
  // already supplied the same key and would otherwise win precedence.
  const environment = { PANEL_CONFIG_TEST_DUPLICATE: 'parent-value' };
  let duplicateError;
  assert.throws(
    () => loadEnv(filePath, environment),
    (error) => {
      duplicateError = error;
      return error.code === 'ENV_DUPLICATE_KEY';
    },
  );
  assert.match(duplicateError.message, /PANEL_CONFIG_TEST_DUPLICATE/);
  assert.match(duplicateError.message, /第 2 行和第 3 行/);
  assert.equal(duplicateError.message.includes('first'), false);
  assert.equal(duplicateError.message.includes('second'), false);
  assert.equal(environment.PANEL_CONFIG_TEST_ATOMIC, undefined);
  assert.equal(environment.PANEL_CONFIG_TEST_DUPLICATE, 'parent-value');
});

test('loadEnv validates boolean settings before applying any values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-boolean-'));
  const filePath = path.join(directory, '.env');
  fs.writeFileSync(filePath, [
    'PANEL_CONFIG_TEST_ATOMIC=must-not-apply',
    'PANEL_WRITE_ENABLED=true',
    '',
  ].join('\n'), { mode: 0o600 });
  const environment = {};
  assert.throws(
    () => loadEnv(filePath, environment),
    (error) => error.code === 'ENV_BOOLEAN_INVALID',
  );
  assert.equal(environment.PANEL_CONFIG_TEST_ATOMIC, undefined);
  assert.equal(environment.PANEL_WRITE_ENABLED, undefined);
});

test('loadEnv rejects NUL bytes and unterminated quotes before applying any values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-syntax-'));
  const filePath = path.join(directory, '.env');
  const environment = {};

  fs.writeFileSync(filePath, 'PANEL_CONFIG_TEST_ATOMIC=must-not-apply\nBROKEN=value\0hidden\n', {
    mode: 0o600,
  });
  assert.throws(
    () => loadEnv(filePath, environment),
    (error) => error.code === 'ENV_SYNTAX_INVALID' && !error.message.includes('hidden'),
  );
  assert.equal(environment.PANEL_CONFIG_TEST_ATOMIC, undefined);

  fs.writeFileSync(filePath, 'PANEL_CONFIG_TEST_ATOMIC=must-not-apply\nBROKEN="unterminated\n', {
    mode: 0o600,
  });
  assert.throws(
    () => loadEnv(filePath, environment),
    (error) => error.code === 'ENV_SYNTAX_INVALID' && /第 2 行/.test(error.message),
  );
  assert.equal(environment.PANEL_CONFIG_TEST_ATOMIC, undefined);
});

test('environment parser handles bare CR as a line ending and rejects other controls', () => {
  assert.deepEqual(parseEnvContent('FIRST=value\rSECOND=other\r'), [
    ['FIRST', 'value'],
    ['SECOND', 'other'],
  ]);
  assert.throws(
    () => parseEnvContent('BROKEN=value\u000bhidden'),
    (error) => error.code === 'ENV_SYNTAX_INVALID' && !error.message.includes('hidden'),
  );
});

test('environment parser bounds individual lines and the number of entries', () => {
  assert.throws(
    () => parseEnvContent('TOO_LONG=' + 'x'.repeat(64 * 1024)),
    (error) => error.code === 'ENV_LINE_TOO_LONG',
  );
  const entries = Array.from({ length: 4097 }, (_, index) => `SAFE_${index}=1`).join('\n');
  assert.throws(
    () => parseEnvContent(entries),
    (error) => error.code === 'ENV_ENTRY_LIMIT_EXCEEDED',
  );
});

test('readEnvFile rejects malformed UTF-8 without substituting credential bytes', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-encoding-'));
  const filePath = path.join(directory, '.env');
  fs.writeFileSync(filePath, Buffer.from([
    ...Buffer.from('SUB2API_ADMIN_API_KEY=', 'utf8'),
    0xc3,
    0x28,
    0x0a,
  ]), { mode: 0o600 });
  assert.throws(
    () => readEnvFile(filePath),
    (error) => error.code === 'ENV_FILE_ENCODING_INVALID'
      && !error.message.includes('SUB2API_ADMIN_API_KEY'),
  );
});

test('every declared boolean environment setting accepts only 0 or 1', () => {
  const invalidValues = ['', 'true', 'false', 'TRUE', 'yes', ' 1', '1 ', '2'];
  for (const name of BOOLEAN_ENV_NAMES) {
    assert.doesNotThrow(() => validateBooleanEnvironment({ [name]: '0' }));
    assert.doesNotThrow(() => validateBooleanEnvironment({ [name]: '1' }));
    for (const invalidValue of invalidValues) {
      assert.throws(
        () => validateBooleanEnvironment({ [name]: invalidValue }),
        (error) => error.code === 'ENV_BOOLEAN_INVALID'
          && error.message === name + ' 必须严格设置为 0 或 1',
      );
    }
  }
});

test('configured environment file must be an explicit absolute path', () => {
  const selected = path.join(os.tmpdir(), 'panel.env');
  assert.equal(configuredEnvFile({ PANEL_ENV_FILE: selected }), selected);
  assert.throws(
    () => configuredEnvFile({ PANEL_ENV_FILE: 'relative.env' }),
    (error) => error.code === 'ENV_FILE_PATH_INVALID',
  );
  assert.throws(
    () => configuredEnvFile({ PANEL_ENV_FILE: '' }),
    (error) => error.code === 'ENV_FILE_PATH_INVALID',
  );
  assert.throws(
    () => readEnvFile('relative.env'),
    (error) => error.code === 'ENV_FILE_PATH_INVALID',
  );
});

test('loadEnv uses PANEL_ENV_FILE without exposing or copying its values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-external-env-'));
  const filePath = path.join(directory, 'panel.env');
  fs.writeFileSync(filePath, 'PANEL_CONFIG_EXTERNAL=loaded\n', { mode: 0o600 });
  const environment = { PANEL_ENV_FILE: filePath };
  assert.equal(loadEnv(undefined, environment), true);
  assert.equal(environment.PANEL_CONFIG_EXTERNAL, 'loaded');
  assert.equal(environment.PANEL_ENV_FILE, filePath);
});

test('loadEnv fails closed when an explicitly selected environment file is missing', () => {
  const missing = path.join(os.tmpdir(), 'missing-panel-env-' + process.pid + '.env');
  assert.equal(fs.existsSync(missing), false);
  assert.throws(
    () => loadEnv(undefined, { PANEL_ENV_FILE: missing }),
    (error) => error.code === 'ENV_FILE_MISSING',
  );
  assert.throws(
    () => loadEnv(missing, {}),
    (error) => error.code === 'ENV_FILE_MISSING',
  );
});

test('readEnvFile rejects final and parent-directory symlinks', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-config-'));
  const realDirectory = path.join(directory, 'real');
  fs.mkdirSync(realDirectory);
  const realFile = path.join(realDirectory, '.env');
  fs.writeFileSync(realFile, 'PANEL_CONFIG_TEST_VALUE=fake\n', { mode: 0o600 });
  const fileLink = path.join(directory, 'linked.env');
  const directoryLink = path.join(directory, 'linked-directory');
  fs.symlinkSync(realFile, fileLink);
  fs.symlinkSync(realDirectory, directoryLink, 'dir');

  assert.throws(
    () => readEnvFile(fileLink),
    (error) => error.code === 'ENV_FILE_TYPE_INVALID',
  );
  assert.throws(
    () => readEnvFile(path.join(directoryLink, '.env')),
    (error) => error.code === 'ENV_PARENT_INVALID',
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
  fs.writeFileSync(filePath, 'PANEL_CONFIG_TEST_VALUE=trusted\n', { mode: 0o600 });
  fs.writeFileSync(
    path.join(outsideDirectory, '.env'),
    'PANEL_CONFIG_TEST_VALUE=outside\n',
    { mode: 0o600 },
  );

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
      (error) => error.code === 'ENV_FILE_CHANGED',
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
  fs.writeFileSync(oversized, Buffer.alloc(1024 * 1024 + 1, 0x78), { mode: 0o600 });
  assert.throws(
    () => readEnvFile(oversized),
    (error) => error.code === 'ENV_FILE_TOO_LARGE',
  );

  const changing = path.join(directory, 'changing.env');
  fs.writeFileSync(changing, 'SAFE_VALUE=fake\n', { mode: 0o600 });
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
      (error) => error.code === 'ENV_FILE_CHANGED',
    );
  } finally {
    fs.readSync = originalReadSync;
  }
});

test('readEnvFile rejects any group or other access and multiply linked secret files', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-env-permissions-'));
  const writable = path.join(directory, 'writable.env');
  fs.writeFileSync(writable, 'SAFE_VALUE=fake\n', { mode: 0o600 });
  fs.chmodSync(writable, 0o666);
  assert.throws(
    () => readEnvFile(writable),
    (error) => error.code === 'ENV_FILE_PERMISSIONS_INVALID',
  );

  const readable = path.join(directory, 'readable.env');
  fs.writeFileSync(readable, 'SAFE_VALUE=fake\n', { mode: 0o600 });
  fs.chmodSync(readable, 0o644);
  assert.throws(
    () => readEnvFile(readable),
    (error) => error.code === 'ENV_FILE_PERMISSIONS_INVALID',
  );

  const executable = path.join(directory, 'executable.env');
  fs.writeFileSync(executable, 'SAFE_VALUE=fake\n', { mode: 0o600 });
  fs.chmodSync(executable, 0o700);
  assert.throws(
    () => readEnvFile(executable),
    (error) => error.code === 'ENV_FILE_PERMISSIONS_INVALID',
  );

  const linked = path.join(directory, 'linked.env');
  const secondName = path.join(directory, 'linked-copy.env');
  fs.writeFileSync(linked, 'SAFE_VALUE=fake\n', { mode: 0o600 });
  fs.linkSync(linked, secondName);
  assert.throws(
    () => readEnvFile(linked),
    (error) => error.code === 'ENV_FILE_LINK_INVALID',
  );
});

test('readEnvFile rejects a private file beneath a replaceable parent directory', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-env-parent-'));
  const unsafeDirectory = path.join(root, 'replaceable');
  fs.mkdirSync(unsafeDirectory, { mode: 0o700 });
  const filePath = path.join(unsafeDirectory, 'panel.env');
  fs.writeFileSync(filePath, 'SAFE_VALUE=fake\n', { mode: 0o600 });
  fs.chmodSync(unsafeDirectory, 0o777);
  try {
    assert.throws(
      () => readEnvFile(filePath),
      (error) => error.code === 'ENV_PARENT_PERMISSIONS_INVALID',
    );
  } finally {
    fs.chmodSync(unsafeDirectory, 0o700);
  }
});
