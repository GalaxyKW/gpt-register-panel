const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

require('./test-isolation');

const {
  PanelLogger,
  assertAuditLogCheckpoint,
  redactText,
  redactValue,
  safeErrorText,
} = require('../backend/logger');

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
    'password is fake-password-copula handled-again',
    'API key is "fake api copula" rotated-again',
    'JWT was fake-jwt-copula rejected',
    'apikey=fake-api-alias',
    'pwd=fake-password-alias',
  ].join('; '));
  for (const secret of [
    'fake-access-space',
    'fake-refresh-space',
    'fake-password-space',
    'fake-credential-space',
    'fake-api-space',
    'fake-password-copula',
    'fake api copula',
    'fake-jwt-copula',
    'fake-api-alias',
    'fake-password-alias',
  ]) assert.equal(spaceSeparated.includes(secret), false, secret + ' leaked');
  assert.match(spaceSeparated, /completed/);
  assert.match(spaceSeparated, /retried/);
  assert.match(spaceSeparated, /rotated/);
  assert.match(spaceSeparated, /rotated-again/);
  assert.match(spaceSeparated, /rejected/);

  const metadata = [
    'access token expiry future',
    'token count 3',
    'token fingerprint safe-fingerprint',
    'token status active',
    'tokenCount 4',
    'token is count 5',
    'JWT was fingerprint safe-jwt-fingerprint',
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

test('redaction covers localized, composite, and URL-encoded credential forms', () => {
  const marker = 'fake-localized-credential-marker';
  const secondPart = 'fake-localized-secret-second-part';
  const cases = [
    [`密码：${marker} ${secondPart}；状态=失败`, '状态=失败'],
    [`password ${marker} ${secondPart}; status=failed`, 'status=failed'],
    [`credential payload ${marker} ${secondPart}; status=failed`, 'status=failed'],
    [`Bearer "${marker} ${secondPart}" rejected`, 'rejected'],
    [`token => ${marker}`, 'token =>'],
    [`API key -> ${marker}`, 'API key ->'],
    [`client.credentials.raw.value=${marker}&status=failed`, 'status=failed'],
    [`https%3A%2F%2Fhost.test%2Fcb%3Faccess%5Ftoken%3D${marker}%26status%3Dfailed`,
      'status%3Dfailed'],
    [`rt_${marker}`, '[redacted]'],
  ];
  for (const [input, retained] of cases) {
    const output = redactText(input);
    assert.equal(output.includes(marker), false, input + ' leaked its first secret segment');
    assert.equal(output.includes(secondPart), false, input + ' leaked its remaining secret segment');
    assert.ok(output.includes(retained), input + ' lost its non-secret diagnostic context');
  }

  const structured = redactValue({
    credentialBody: marker,
    credentialPayloadRawValue: marker,
    cookieJar: marker,
    OAuthCode: marker,
    OAuth凭据响应: marker,
    访问令牌: marker,
    API密钥: marker,
    tokenCount: 3,
    tokenFingerprint: 'safe-fingerprint',
  });
  for (const key of [
    'credentialBody',
    'credentialPayloadRawValue',
    'cookieJar',
    'OAuthCode',
    'OAuth凭据响应',
    '访问令牌',
    'API密钥',
  ]) assert.equal(structured[key], '[redacted]', key + ' was not redacted');
  assert.equal(structured.tokenCount, 3);
  assert.equal(structured.tokenFingerprint, 'safe-fingerprint');
});

test('redaction covers private-key material and common cloud signing credentials', () => {
  const pemSecret = [
    '-----BEGIN PRIVATE KEY-----',
    'fake-private-pem-material',
    '-----END PRIVATE KEY-----',
  ].join('\n');
  const structured = redactValue({
    privateKey: 'fake-structured-private-key',
    secretAccessKey: 'fake-cloud-secret-access-key',
    accessKeyId: 'fake-cloud-access-key-id',
    signingKey: 'fake-signing-key',
    keyMaterial: 'fake-key-material',
    diagnostic: pemSecret,
    privateKeyFingerprint: 'safe-private-key-fingerprint',
  });
  for (const key of [
    'privateKey',
    'secretAccessKey',
    'accessKeyId',
    'signingKey',
    'keyMaterial',
  ]) assert.equal(structured[key], '[redacted]');
  assert.equal(structured.diagnostic.includes('fake-private-pem-material'), false);
  assert.equal(structured.privateKeyFingerprint, 'safe-private-key-fingerprint');

  const freeText = redactText([
    'private_key=fake-assigned-private-key',
    'secret access key fake-space-cloud-key accepted',
    'signing key: "fake signing key value"',
    pemSecret,
  ].join('; '));
  for (const secret of [
    'fake-assigned-private-key',
    'fake-space-cloud-key',
    'fake signing key value',
    'fake-private-pem-material',
  ]) assert.equal(freeText.includes(secret), false, secret + ' leaked');

  const incompletePem = redactText(
    'failure: -----BEGIN OPENSSH PRIVATE KEY-----\nfake-incomplete-private-material',
  );
  assert.equal(incompletePem.includes('fake-incomplete-private-material'), false);
});

test('redaction fails closed for encoded labels, opaque schemes, passphrases, and unsafe object shapes', () => {
  const bearer = redactText('retry received Bearer opaque:value-with-colon');
  assert.equal(bearer.includes('opaque:value-with-colon'), false);
  const encoded = redactText('access%5Ftoken=fake-percent-encoded-secret&status=failed');
  assert.equal(encoded.includes('fake-percent-encoded-secret'), false);
  assert.match(encoded, /status=failed/);
  const passphrase = redactText('password: correct horse battery staple; status=failed');
  assert.equal(passphrase.includes('correct horse battery staple'), false);
  assert.match(passphrase, /status=failed/);
  const recoveryCode = redactText('recovery_code: alpha beta gamma; status=used');
  assert.equal(recoveryCode.includes('alpha beta gamma'), false);
  assert.match(recoveryCode, /status=used/);

  let getterCalls = 0;
  const hostile = {
    buffer: Buffer.from('fake-buffer-secret'),
    typed: new Uint8Array(Buffer.from('fake-typed-secret')),
    'Authorization: Bearer fake-key-secret': 'fake-key-value',
  };
  Object.defineProperty(hostile, 'dynamic', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'fake-getter-secret';
    },
  });
  const safe = redactValue(hostile);
  const serialized = JSON.stringify(safe);
  assert.equal(getterCalls, 0);
  for (const secret of [
    'fake-buffer-secret',
    'fake-typed-secret',
    'fake-key-secret',
    'fake-key-value',
    'fake-getter-secret',
  ]) assert.equal(serialized.includes(secret), false, secret + ' leaked');
  assert.equal(safe.buffer, '[binary redacted]');
  assert.equal(safe.typed, '[binary redacted]');
  assert.equal(safe.dynamic, '[accessor omitted]');

  let errorGetterCalls = 0;
  const hostileError = {};
  for (const property of ['stack', 'message', 'code']) {
    Object.defineProperty(hostileError, property, {
      get() {
        errorGetterCalls += 1;
        return 'fake-error-getter-secret';
      },
    });
  }
  assert.equal(safeErrorText(hostileError), 'unknown error');
  assert.equal(errorGetterCalls, 0);
});

test('redaction and log serialization are bounded for deep, sparse, and oversized input', () => {
  let deep = { safe: true };
  for (let index = 0; index < 20_000; index += 1) deep = { child: deep };
  assert.doesNotThrow(() => redactValue(deep));
  assert.match(JSON.stringify(redactValue(deep)), /redaction depth reached/);

  const sparse = [];
  sparse.length = 0xffffffff;
  sparse[0xfffffffe] = 'last';
  const startedAt = Date.now();
  const safeSparse = redactValue(sparse);
  assert.ok(Date.now() - startedAt < 1000);
  assert.ok(safeSparse.length <= 2);
  assert.match(JSON.stringify(safeSparse), /truncated/);

  const storedArray = Array.from({ length: 2_000 }, (_, index) => ({ index }));
  assert.equal(redactValue(storedArray).length, storedArray.length);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-bounded-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false, maxBytes: 1024 });
  let eventStringCalls = 0;
  const entry = logger.info({
    toString() {
      eventStringCalls += 1;
      return 'fake-event-secret';
    },
  }, {
    message: 'x'.repeat(2 * 1024 * 1024),
    many: Array.from({ length: 10_000 }, (_, index) => 'value-' + index),
  });
  assert.equal(eventStringCalls, 0);
  assert.equal(entry.event, 'event');
  assert.ok(Buffer.byteLength(JSON.stringify(entry)) <= logger.maxBytes);
  assert.ok(fs.statSync(filePath).size <= logger.maxBytes);
});

test('logger startup writes and fsyncs one valid JSONL preflight record', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const originalFsyncSync = fs.fsyncSync;
  let fileFsyncCalls = 0;
  fs.fsyncSync = function trackedFsync(descriptor) {
    if (fs.fstatSync(descriptor).isFile()) fileFsyncCalls += 1;
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    const logger = new PanelLogger({ filePath, console: false });
    assert.equal(logger.health().healthy, true);
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }

  const lines = fs.readFileSync(filePath, 'utf8').trimEnd().split('\n');
  assert.equal(lines.length, 1);
  const entry = JSON.parse(lines[0]);
  assert.equal(entry.event, 'logger.write_preflight');
  assert.equal(entry.level, 'info');
  assert.equal(entry.pid, process.pid);
  assert.ok(Number.isFinite(Date.parse(entry.timestamp)));
  assert.ok(fileFsyncCalls >= 1);
});

test('audit checkpoints are contextual, redacted, and fsynced before returning success', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const originalFsyncSync = fs.fsyncSync;
  let checkpointFsyncs = 0;
  fs.fsyncSync = function trackedFsync(descriptor) {
    if (fs.fstatSync(descriptor).isFile()) checkpointFsyncs += 1;
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    assert.equal(assertAuditLogCheckpoint(logger, 'token_cleanup.mutation_checkpoint', {
      requestId: 'checkpoint-request',
      credential: 'checkpoint-secret-value',
      event: 'spoofed-event',
      pid: -1,
    }), true);
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }

  const entry = logger.tail(1)[0];
  assert.equal(entry.event, 'token_cleanup.mutation_checkpoint');
  assert.equal(entry.requestId, 'checkpoint-request');
  assert.equal(entry.credential, '[redacted]');
  assert.equal(entry.pid, process.pid);
  assert.equal(JSON.stringify(entry).includes('checkpoint-secret-value'), false);
  assert.ok(checkpointFsyncs >= 1);
});

test('custom log directory is fsynced after rotation and current-log recreation', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-durable-'));
  const dbDirectory = path.join(root, 'db');
  const logDirectory = path.join(root, 'custom-log');
  fs.mkdirSync(dbDirectory, { mode: 0o700 });
  fs.mkdirSync(logDirectory, { mode: 0o700 });
  const filePath = path.join(logDirectory, 'panel.log');
  const logDirectoryStat = fs.statSync(logDirectory);
  const dbDirectoryStat = fs.statSync(dbDirectory);
  const originalFsyncSync = fs.fsyncSync;
  const fsyncTargets = [];
  let logger;
  fs.fsyncSync = function trackedCustomDirectoryFsync(descriptor) {
    const stat = fs.fstatSync(descriptor);
    fsyncTargets.push({
      kind: stat.isDirectory() ? 'directory' : 'file',
      dev: stat.dev,
      ino: stat.ino,
    });
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    logger = new PanelLogger({
      dbPath: path.join(dbDirectory, 'panel.sqlite3'),
      filePath,
      console: false,
      maxBytes: 1024,
      rotations: 2,
    });
    assert.ok(fsyncTargets.some((target) => target.kind === 'directory'
      && target.dev === logDirectoryStat.dev && target.ino === logDirectoryStat.ino));
    assert.equal(fsyncTargets.some((target) => target.kind === 'directory'
      && target.dev === dbDirectoryStat.dev && target.ino === dbDirectoryStat.ino), false);

    fs.appendFileSync(filePath, JSON.stringify({
      event: 'existing.large',
      padding: 'x'.repeat(1100),
    }) + '\n');
    fsyncTargets.length = 0;
    assert.equal(logger.checkpoint('test.custom_log_rotation'), true);
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }

  assert.equal(fs.existsSync(filePath + '.1'), true);
  assert.equal(logger.tail(1)[0].event, 'test.custom_log_rotation');
  assert.ok(fsyncTargets.some((target) => target.kind === 'directory'
    && target.dev === logDirectoryStat.dev && target.ino === logDirectoryStat.ino));
  assert.equal(fsyncTargets.some((target) => target.kind === 'directory'
    && target.dev === dbDirectoryStat.dev && target.ino === dbDirectoryStat.ino), false);
  assert.deepEqual(fsyncTargets.slice(-2).map((target) => target.kind), ['file', 'directory']);
});

test('audit checkpoint assertion fails closed for missing, rejected, or throwing sinks', () => {
  for (const logger of [
    null,
    { checkpoint() { return false; } },
    { checkpoint() { throw new Error('simulated checkpoint failure'); } },
    { probe() { return false; } },
  ]) {
    assert.throws(
      () => assertAuditLogCheckpoint(logger, 'test.checkpoint'),
      (error) => error?.code === 'AUDIT_LOG_UNAVAILABLE'
        && !String(error.message).includes('simulated checkpoint failure'),
    );
  }
  assert.equal(assertAuditLogCheckpoint({ probe() { return true; } }, 'test.compatibility'), true);
});

test('a checkpoint fsync failure marks the logger unhealthy and fails closed', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const originalFsyncSync = fs.fsyncSync;
  fs.fsyncSync = function failingCheckpointFsync(descriptor) {
    if (fs.fstatSync(descriptor).isFile()) throw new Error('simulated checkpoint fsync failure');
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    assert.throws(
      () => assertAuditLogCheckpoint(logger, 'test.fsync_failure'),
      (error) => error?.code === 'AUDIT_LOG_UNAVAILABLE'
        && !String(error.message).includes('simulated checkpoint fsync failure'),
    );
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(logger.health().healthy, false);
  assert.equal(logger.health().consecutiveWriteFailures, 1);
});

test('a custom log directory fsync failure makes an audit checkpoint fail closed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-dir-fsync-'));
  const logDirectory = path.join(root, 'custom-log');
  fs.mkdirSync(logDirectory, { mode: 0o700 });
  const filePath = path.join(logDirectory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false, maxBytes: 1024, rotations: 2 });
  fs.appendFileSync(filePath, JSON.stringify({
    event: 'existing.large',
    padding: 'x'.repeat(1100),
  }) + '\n');

  const logDirectoryStat = fs.statSync(logDirectory);
  const originalFsyncSync = fs.fsyncSync;
  fs.fsyncSync = function failingCustomDirectoryFsync(descriptor) {
    const stat = fs.fstatSync(descriptor);
    if (stat.isDirectory() && stat.dev === logDirectoryStat.dev && stat.ino === logDirectoryStat.ino) {
      const error = new Error('simulated custom log directory fsync failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    assert.throws(
      () => assertAuditLogCheckpoint(logger, 'test.directory_fsync_failure'),
      (error) => error?.code === 'AUDIT_LOG_UNAVAILABLE'
        && !String(error.message).includes('simulated custom log directory fsync failure'),
    );
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(logger.health().healthy, false);
  assert.equal(logger.health().consecutiveWriteFailures, 1);
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
  assert.equal(bounded.rotations, 3);
  assert.ok(bounded.maxBytes * (bounded.rotations + 1) <= 512 * 1024 * 1024);
});

test('logger treats rotation failure as a failed write until rotation recovers', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false, maxBytes: 1024, rotations: 2 });
  fs.appendFileSync(filePath, JSON.stringify({
    event: 'existing.large',
    padding: 'x'.repeat(1100),
  }) + '\n');

  const originalRenameSync = fs.renameSync;
  fs.renameSync = function failingRotation(from, to) {
    if (path.basename(String(from)) === path.basename(filePath)) {
      const error = new Error('forced rotation failure');
      error.code = 'EACCES';
      throw error;
    }
    return originalRenameSync.call(fs, from, to);
  };
  try {
    logger.info('test.rotation.failure.one');
    logger.info('test.rotation.failure.two');
  } finally {
    fs.renameSync = originalRenameSync;
  }

  assert.equal(logger.health().healthy, false);
  assert.equal(logger.health().failedWrites, 2);
  assert.equal(logger.health().consecutiveWriteFailures, 2);
  const failedText = fs.readFileSync(filePath, 'utf8');
  assert.equal(failedText.includes('test.rotation.failure.one'), false);
  assert.equal(failedText.includes('test.rotation.failure.two'), false);

  logger.info('test.rotation.recovered');
  assert.equal(logger.health().healthy, true);
  assert.equal(logger.health().consecutiveWriteFailures, 0);
  assert.equal(logger.tail(1)[0].event, 'test.rotation.recovered');
});

test('logger write failure fallback never invokes hostile error accessors', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const originalWriteFileSync = fs.writeFileSync;
  let getterCalls = 0;
  const hostileError = {};
  Object.defineProperty(hostileError, 'message', {
    get() {
      getterCalls += 1;
      throw new Error('fake-hostile-error-getter-secret');
    },
  });
  fs.writeFileSync = function failingLogWrite() {
    throw hostileError;
  };
  try {
    assert.doesNotThrow(() => logger.info('test.hostile_write_failure'));
  } finally {
    fs.writeFileSync = originalWriteFileSync;
  }
  assert.equal(getterCalls, 0);
  assert.equal(logger.health().healthy, false);
  assert.equal(logger.health().consecutiveWriteFailures, 1);
  assert.equal(fs.readFileSync(filePath, 'utf8').includes('fake-hostile-error-getter-secret'), false);
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

test('redacted values cannot reintroduce secrets through JSON serialization hooks', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const marker = 'opaque-serialization-hook-secret-marker';
  let hookCalls = 0;
  const prototypePayload = Object.create(null);
  Object.defineProperty(prototypePayload, '__proto__', {
    value: {
      toJSON() {
        hookCalls += 1;
        return { note: marker };
      },
    },
    enumerable: true,
  });
  const fields = {
    ordinary: 'safe',
    custom: {
      toJSON() {
        hookCalls += 1;
        return { note: marker };
      },
    },
    prototypePayload,
  };

  const safe = redactValue(fields);
  const serialized = JSON.stringify(safe);
  assert.equal(hookCalls, 0);
  assert.equal(serialized.includes(marker), false);
  assert.equal(Object.getPrototypeOf(safe.prototypePayload), Object.prototype);
  assert.equal(Object.prototype.hasOwnProperty.call(safe.prototypePayload, '__proto__'), true);
  logger.info('test.serialization_hook', fields);
  const logText = fs.readFileSync(filePath, 'utf8');
  assert.equal(hookCalls, 0);
  assert.equal(logText.includes(marker), false);
  assert.equal(logger.tail(1)[0].custom.toJSON, '[redacted]');
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
  const serialized = JSON.stringify(logger.tail(2));
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
    assert.deepEqual(
      logger.tail(3).map((entry) => entry.event),
      ['tail.one', 'tail.two', 'logger.write_preflight'],
    );
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
    if (!swapped && path.basename(String(target)) === path.basename(filePath)) {
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
    if (!swapped && path.basename(String(target)) === path.basename(filePath)) {
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

test('logger secures the full rotated namespace and refuses unsafe rotation targets', () => {
  const normalizedDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-old-'));
  const normalizedPath = path.join(normalizedDirectory, 'panel.log');
  fs.writeFileSync(normalizedPath, 'current\n', { mode: 0o600 });
  fs.writeFileSync(normalizedPath + '.999', 'legacy\n', { mode: 0o644 });
  new PanelLogger({ filePath: normalizedPath, console: false, rotations: 2 });
  assert.equal(fs.statSync(normalizedPath + '.999').mode & 0o077, 0);

  for (const kind of ['hardlink', 'symlink']) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-unsafe-old-'));
    const filePath = path.join(directory, 'panel.log');
    const outsidePath = path.join(directory, 'outside');
    fs.writeFileSync(filePath, 'current\n', { mode: 0o600 });
    fs.writeFileSync(outsidePath, 'outside\n', { mode: 0o600 });
    if (kind === 'hardlink') fs.linkSync(outsidePath, filePath + '.1');
    else fs.symlinkSync(outsidePath, filePath + '.1');
    assert.throws(
      () => new PanelLogger({ filePath, console: false }),
      { code: 'PANEL_LOG_INITIALIZATION_FAILED' },
    );
    assert.equal(fs.readFileSync(outsidePath, 'utf8'), 'outside\n');
  }

  const runtimeDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-target-'));
  const runtimePath = path.join(runtimeDirectory, 'panel.log');
  const runtimeOutside = path.join(runtimeDirectory, 'outside');
  const logger = new PanelLogger({ filePath: runtimePath, console: false, maxBytes: 1024, rotations: 2 });
  fs.appendFileSync(runtimePath, 'x'.repeat(1100));
  fs.writeFileSync(runtimeOutside, 'outside-original\n', { mode: 0o600 });
  fs.linkSync(runtimeOutside, runtimePath + '.1');
  logger.info('test.unsafe.rotation.target');
  assert.equal(logger.health().healthy, false);
  assert.equal(fs.readFileSync(runtimeOutside, 'utf8'), 'outside-original\n');
});

test('logger scans its directory with a bounded stream instead of an unbounded readdir', () => {
  const streamingDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-stream-'));
  const streamingPath = path.join(streamingDirectory, 'panel.log');
  const originalReaddirSync = fs.readdirSync;
  fs.readdirSync = function rejectUnboundedLoggerRead() {
    throw new Error('logger must not materialize the complete directory');
  };
  try {
    const logger = new PanelLogger({ filePath: streamingPath, console: false });
    assert.equal(logger.health().healthy, true);
  } finally {
    fs.readdirSync = originalReaddirSync;
  }

  const oversizedDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-scan-limit-'));
  const oversizedPath = path.join(oversizedDirectory, 'panel.log');
  const originalOpenDirectory = fs.opendirSync;
  let closed = false;
  fs.opendirSync = function syntheticOversizedDirectory(target, ...args) {
    if (!String(target).startsWith('/proc/self/fd/') && path.resolve(String(target)) !== oversizedDirectory) {
      return originalOpenDirectory.call(fs, target, ...args);
    }
    let index = 0;
    return {
      readSync() {
        index += 1;
        return index <= 20_001 ? { name: 'unrelated-' + String(index) } : null;
      },
      closeSync() { closed = true; },
    };
  };
  try {
    assert.throws(
      () => new PanelLogger({ filePath: oversizedPath, console: false }),
      { code: 'PANEL_LOG_INITIALIZATION_FAILED' },
    );
  } finally {
    fs.opendirSync = originalOpenDirectory;
  }
  assert.equal(closed, true);
  assert.equal(fs.existsSync(oversizedPath), false);
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
