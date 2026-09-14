const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

require('./test-isolation');

const { PanelLogger, redactText, redactValue } = require('../backend/logger');

test('structured logger redacts token-like fields and process output', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false, level: 'debug' });
  logger.info('test.sensitive', {
    access_token: 'access-secret-value',
    refreshToken: 'refresh-secret-value',
    id_token: 'id-secret-value',
    token: 'opaque-secret-value',
    authorization: 'Bearer bearer-secret-value',
    jwt: 'eyJheader.secret.payload',
    apiKey: 'sk-secret-api-key-value',
    nested: { password: 'password-secret-value' },
    message: '{"access_token":"quoted-secret-value"}',
    processOutput: '{"token":"quoted-token-secret-value","credential":"quoted-credential-secret-value"}',
  });
  const text = fs.readFileSync(filePath, 'utf8');
  for (const secret of [
    'access-secret-value',
    'refresh-secret-value',
    'id-secret-value',
    'opaque-secret-value',
    'bearer-secret-value',
    'secret-api-key-value',
    'password-secret-value',
    'quoted-secret-value',
    'quoted-token-secret-value',
    'quoted-credential-secret-value',
  ]) assert.equal(text.includes(secret), false, secret + ' leaked');
  assert.match(text, /\[redacted\]/);
  assert.equal(redactText('Authorization: Bearer abc.def.ghi').includes('abc.def.ghi'), false);
});

test('free-text redaction covers compound headers, structured values, and opaque JWT fields', () => {
  const cases = [
    ['Authorization: Basic ZmFrZTpmYWtl', 'ZmFrZTpmYWtl'],
    ['Cookie: first=fake-cookie-one; second=fake-cookie-two', 'fake-cookie-two'],
    ['{"tokens":["fake-token-one","fake-token-two"]}', 'fake-token-two'],
    ['prefix {"credential":{"value":"fake-credential"}} suffix', 'fake-credential'],
    ['prefix credential payload: {\n"primary":"fake-multiline-credential"\n} suffix', 'fake-multiline-credential'],
    ['oauth_code: "fake-code with-spaces"', 'with-spaces'],
    ['eyJfake.one.two.three.four', 'three.four'],
    ['SUB2API_JWT=opaque-all-caps-value', 'opaque-all-caps-value'],
  ];
  for (const [input, secret] of cases) {
    assert.equal(redactText(input).includes(secret), false, input + ' leaked');
  }
  assert.equal(redactValue({ nested: [{ jwt: 'opaque-fake-jwt' }] }).nested[0].jwt, '[redacted]');
  const keyed = redactValue({
    SUB2API_JWT: 'all-caps-jwt',
    APIKey: 'camel-api-key',
    credentialPayload: { value: 'nested-credential-value' },
    tokenValue: 'opaque-token-value',
    accessTokens: ['access-token-list-value'],
    refreshTokens: ['refresh-token-list-value'],
    apiKeys: ['api-key-list-value'],
    tokenList: ['generic-token-list-value'],
    credentialMap: { primary: 'credential-map-value' },
    prompt: 'unlabelled-prompt-secret',
    tokenCount: 12,
    tokenFingerprint: 'safe-fingerprint',
    accessTokenCount: 2,
    refreshTokenExpiry: 'safe-expiry',
    credentialStatus: 'safe-status',
    apiKeyFingerprint: 'safe-key-fingerprint',
  });
  assert.equal(keyed.SUB2API_JWT, '[redacted]');
  assert.equal(keyed.APIKey, '[redacted]');
  assert.equal(keyed.credentialPayload, '[redacted]');
  assert.equal(keyed.tokenValue, '[redacted]');
  assert.equal(keyed.accessTokens, '[redacted]');
  assert.equal(keyed.refreshTokens, '[redacted]');
  assert.equal(keyed.apiKeys, '[redacted]');
  assert.equal(keyed.tokenList, '[redacted]');
  assert.equal(keyed.credentialMap, '[redacted]');
  assert.equal(keyed.prompt, '[redacted]');
  assert.equal(keyed.tokenCount, 12);
  assert.equal(keyed.tokenFingerprint, 'safe-fingerprint');
  assert.equal(keyed.accessTokenCount, 2);
  assert.equal(keyed.refreshTokenExpiry, 'safe-expiry');
  assert.equal(keyed.credentialStatus, 'safe-status');
  assert.equal(keyed.apiKeyFingerprint, 'safe-key-fingerprint');

  const sentence = redactText(
    'access token: fake-access-value request failed; API key = "fake api key value" retry later',
  );
  assert.equal(sentence.includes('fake-access-value'), false);
  assert.equal(sentence.includes('fake api key value'), false);
  assert.match(sentence, /request failed/);
  assert.match(sentence, /retry later/);

  const spaceSeparated = redactText([
    'access token fake-access-space completed',
    'refresh token fake-refresh-space retried',
    'password fake-password-space handled',
    'credential fake-credential-space retained',
    'API key fake-api-space rotated',
  ].join('; '));
  for (const secret of [
    'fake-access-space',
    'fake-refresh-space',
    'fake-password-space',
    'fake-credential-space',
    'fake-api-space',
  ]) assert.equal(spaceSeparated.includes(secret), false, secret + ' leaked');
  assert.match(spaceSeparated, /completed/);
  assert.match(spaceSeparated, /retried/);
  assert.match(spaceSeparated, /handled/);
  assert.match(spaceSeparated, /retained/);
  assert.match(spaceSeparated, /rotated/);

  const metadata = [
    'access token expiry future',
    'token count 3',
    'token fingerprint safe-fingerprint',
    'token status active',
    'tokenCount 4',
  ].join('; ');
  assert.equal(redactText(metadata), metadata);

  const url = redactText('request failed at https://fake-user:fake-password@host.example/path?q=1');
  assert.equal(url.includes('fake-user'), false);
  assert.equal(url.includes('fake-password'), false);
  assert.match(url, /https:\/\/\[redacted\]@host\.example\/path\?q=1/);

  const longUserinfoSecret = 'x'.repeat(4097) + '-long-userinfo-secret';
  const longUrl = redactText(
    'https://fake-user:' + longUserinfoSecret + '@host.example/path',
  );
  assert.equal(longUrl.includes(longUserinfoSecret), false);
  assert.equal(longUrl, 'https://[redacted]@host.example/path');
});

test('structured logger rotates files, supports tail, and uses restrictive permissions', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'nested', 'panel.log');
  const logger = new PanelLogger({ filePath, console: false, maxBytes: 1024, rotations: 2 });
  for (let index = 0; index < 30; index += 1) {
    logger.info('test.rotation', { index, padding: 'x'.repeat(180) });
  }
  assert.equal(fs.statSync(directory + '/nested').mode & 0o077, 0);
  assert.equal(fs.statSync(filePath).mode & 0o077, 0);
  assert.equal(fs.existsSync(filePath + '.1'), true);
  const entries = logger.tail(3);
  assert.equal(entries.length, 3);
  assert.equal(entries[2].event, 'test.rotation');

  const bounded = new PanelLogger({
    filePath: path.join(directory, 'bounded.log'),
    console: false,
    maxBytes: Number.MAX_VALUE,
    rotations: 1_000_000,
  });
  assert.equal(bounded.maxBytes, 128 * 1024 * 1024);
  assert.equal(bounded.rotations, 100);
});

test('logger fails closed when its destination cannot be initialized', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const blockingPath = path.join(directory, 'not-a-directory');
  fs.writeFileSync(blockingPath, 'x');
  assert.throws(
    () => new PanelLogger({ filePath: path.join(blockingPath, 'panel.log'), console: false }),
    (error) => error?.code === 'PANEL_LOG_INITIALIZATION_FAILED'
      && !String(error.message).includes(blockingPath),
  );
});

test('logger handles circular and bigint fields without throwing', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const fields = { count: 12n };
  fields.self = fields;
  assert.doesNotThrow(() => logger.info('test.circular', fields));
  const entry = logger.tail(1)[0];
  assert.equal(entry.count, '12');
  assert.equal(entry.self, '[circular]');
});

test('logger fields cannot override fixed metadata or leak through a dynamic event', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const entry = logger.info('Authorization: Bearer fake-event-secret', {
    timestamp: 'spoofed-time',
    level: 'debug',
    event: 'spoofed-event',
    pid: -1,
  });
  assert.notEqual(entry.timestamp, 'spoofed-time');
  assert.equal(entry.level, 'info');
  assert.equal(entry.pid, process.pid);
  assert.equal(entry.event, 'Authorization: [redacted]');
  assert.equal(JSON.stringify(entry).includes('fake-event-secret'), false);
});

test('logger tail re-redacts valid legacy JSON lines before returning them', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  fs.writeFileSync(filePath, JSON.stringify({
    level: 'info',
    event: 'legacy.entry',
    jwt: 'opaque-legacy-jwt',
    message: '{"tokens":["legacy-one","legacy-two"]}',
    detail: 'access token legacy-space-secret at https://legacy-user:legacy-pass@host.example/path',
  }) + '\n');
  const logger = new PanelLogger({ filePath, console: false });
  const serialized = JSON.stringify(logger.tail(1));
  assert.equal(serialized.includes('opaque-legacy-jwt'), false);
  assert.equal(serialized.includes('legacy-one'), false);
  assert.equal(serialized.includes('legacy-two'), false);
  assert.equal(serialized.includes('legacy-space-secret'), false);
  assert.equal(serialized.includes('legacy-user'), false);
  assert.equal(serialized.includes('legacy-pass'), false);
  assert.match(serialized, /\[redacted\]/);
});

test('logger tail reads bounded blocks from the end and drops a truncated first line', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const hardReadLimit = 4 * 1024 * 1024;
  const hugeEntry = JSON.stringify({
    event: 'huge.entry',
    padding: 'x'.repeat(hardReadLimit + 1024),
  }) + '\n';
  fs.writeFileSync(filePath, hugeEntry
    + JSON.stringify({ event: 'tail.one' }) + '\n'
    + JSON.stringify({ event: 'tail.two' }) + '\n');
  const logger = new PanelLogger({ filePath, console: false });

  const originalReadSync = fs.readSync;
  let requestedBytes = 0;
  fs.readSync = function trackedRead(descriptor, buffer, offset, length, position) {
    requestedBytes += length;
    return originalReadSync.call(fs, descriptor, buffer, offset, length, position);
  };
  try {
    assert.deepEqual(logger.tail(2).map((entry) => entry.event), ['tail.one', 'tail.two']);
    assert.ok(requestedBytes <= hardReadLimit);
    assert.ok(requestedBytes < fs.statSync(filePath).size);

    fs.writeFileSync(filePath,
      JSON.stringify({ event: 'outside.window' }) + '\n' + 'x'.repeat(hardReadLimit + 1024));
    requestedBytes = 0;
    assert.deepEqual(logger.tail(2), []);
    assert.ok(requestedBytes <= hardReadLimit);
  } finally {
    fs.readSync = originalReadSync;
  }
});

test('logger tail does not follow a file swapped to a symbolic link before open', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const outsidePath = path.join(directory, 'outside-secret');
  fs.writeFileSync(filePath, JSON.stringify({ event: 'safe.entry' }) + '\n');
  fs.writeFileSync(outsidePath, 'outside-secret-value\n');
  const logger = new PanelLogger({ filePath, console: false });
  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = function guardedOpen(target, ...args) {
    if (!swapped && target === filePath) {
      swapped = true;
      fs.renameSync(filePath, filePath + '.original');
      fs.symlinkSync(outsidePath, filePath);
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    assert.deepEqual(logger.tail(10), []);
  } finally {
    fs.openSync = originalOpenSync;
  }
});

test('logger writes do not follow a file swapped to a symbolic link before open', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const outsidePath = path.join(directory, 'outside-target');
  fs.writeFileSync(filePath, 'original-log\n');
  fs.writeFileSync(outsidePath, 'outside-original\n');
  const logger = new PanelLogger({ filePath, console: false });
  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = function guardedOpen(target, ...args) {
    if (!swapped && target === filePath) {
      swapped = true;
      fs.renameSync(filePath, filePath + '.original');
      fs.symlinkSync(outsidePath, filePath);
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    assert.doesNotThrow(() => logger.info('unsafe.swap', { value: 'not-written' }));
  } finally {
    fs.openSync = originalOpenSync;
  }
  assert.equal(logger.health().healthy, false);
  assert.equal(logger.health().consecutiveWriteFailures, 1);
  assert.equal(fs.readFileSync(outsidePath, 'utf8'), 'outside-original\n');
});

test('logger refuses unsafe directories and multiply linked log files', () => {
  const unsafeDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-unsafe-'));
  fs.chmodSync(unsafeDirectory, 0o777);
  const unsafePath = path.join(unsafeDirectory, 'panel.log');
  assert.throws(
    () => new PanelLogger({ filePath: unsafePath, console: false }),
    { code: 'PANEL_LOG_INITIALIZATION_FAILED' },
  );
  assert.equal(fs.existsSync(unsafePath), false);

  const linkedDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-link-'));
  const linkedPath = path.join(linkedDirectory, 'panel.log');
  fs.writeFileSync(linkedPath, 'original\n', { mode: 0o600 });
  fs.linkSync(linkedPath, linkedPath + '.alias');
  assert.throws(
    () => new PanelLogger({ filePath: linkedPath, console: false }),
    { code: 'PANEL_LOG_INITIALIZATION_FAILED' },
  );
  assert.equal(fs.readFileSync(linkedPath, 'utf8'), 'original\n');
});

test('fatal stderr formatting preserves a bounded stack without exposing credentials', () => {
  const script = [
    "const { safeErrorText } = require('./backend/logger');",
    "const error = new Error('Authorization: Basic ZmFrZTpmYWtl');",
    "error.code = 'FAKE_START_FAILURE';",
    "error.stack += '\\ncredentialPayload=fake-stderr-credential';",
    "process.stderr.write(safeErrorText(error, 512) + '\\n');",
  ].join('\n');
  const child = spawnSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stderr, /code=FAKE_START_FAILURE/);
  assert.match(child.stderr, /Error:/);
  assert.equal(child.stderr.includes('ZmFrZTpmYWtl'), false);
  assert.equal(child.stderr.includes('fake-stderr-credential'), false);
  assert.ok(child.stderr.length <= 513);
});
