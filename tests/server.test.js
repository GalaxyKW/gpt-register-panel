const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { EventEmitter } = require('node:events');
const test = require('node:test');

require('./test-isolation');

const {
  authFailureBucketCount,
  authorizationError,
  configuredListenHost,
  configuredListenPort,
  createServer,
  openVerifiedStaticFile,
  phase3ClaimKeys,
  phase3FailureMetadata,
  mutationFailureMetadata,
  reconciliationReviewDetail,
  readJsonBody,
  resetAuthFailureBuckets,
  safeStaticPath,
  shutdownServer,
  startServer,
  validateRuntimeConfiguration,
} = require('../backend/server');
const { listExpiredTokens } = require('../backend/tokenCleanup');
const { PanelDb } = require('../backend/db');
const { withControlPlaneLock } = require('../backend/taskCoordinator');
const configuredPanelToken = process.env.PANEL_ADMIN_TOKEN || '';

test('static routing exposes only the three declared frontend assets', () => {
  assert.equal(path.basename(safeStaticPath('/')), 'index.html');
  assert.equal(path.basename(safeStaticPath('/app.js')), 'app.js');
  assert.equal(path.basename(safeStaticPath('/styles.css')), 'styles.css');
  assert.equal(safeStaticPath('/debug.json'), null);
  assert.equal(safeStaticPath('/nested/asset.js'), null);
});

test('Phase3 failures persist only bounded reconciliation metadata', () => {
  const metadata = phase3FailureMetadata({
    code: 'account_deactivated',
    accountDisposition: 'discard',
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationScope: 'phase3_account_disposition',
    reconciliationReason: 'account_disposition_write_unknown',
    dispositionPersisted: null,
    dispositionOutcome: 'unknown',
    dispositionWriteOutcomeUnknown: true,
    dispositionCode: 'account_deactivated',
    dispositionErrorCode: 'eio',
    message: 'Bearer must-not-persist',
    details: { credential: 'must-not-persist' },
    cause: new Error('must-not-persist'),
  });
  assert.deepEqual(metadata, {
    code: 'ACCOUNT_DEACTIVATED',
    accountDisposition: 'discard',
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationScope: 'phase3_account_disposition',
    reconciliationReason: 'account_disposition_write_unknown',
    dispositionPersisted: null,
    dispositionOutcome: 'unknown',
    dispositionWriteOutcomeUnknown: true,
    dispositionCode: 'ACCOUNT_DEACTIVATED',
    dispositionErrorCode: 'EIO',
  });
  assert.equal(JSON.stringify(metadata).includes('must-not-persist'), false);

  assert.deepEqual(phase3FailureMetadata({
    code: 'invalid-code!',
    accountDisposition: 'delete_everything',
    reconciliationScope: 'untrusted',
    reconciliationReason: 'untrusted',
    dispositionOutcome: 'untrusted',
    dispositionErrorCode: 'x'.repeat(97),
  }), { code: null, accountDisposition: null });

  assert.deepEqual(phase3FailureMetadata({
    code: 'PHASE3_TOKEN_POSTFLIGHT_UNKNOWN',
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationScope: 'phase3_token_output',
    reconciliationReason: 'phase3_postflight_source_unavailable',
  }), {
    code: 'PHASE3_TOKEN_POSTFLIGHT_UNKNOWN',
    accountDisposition: null,
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationScope: 'phase3_token_output',
    reconciliationReason: 'phase3_postflight_source_unavailable',
  });
});

test('generic worker failures preserve only bounded reconciliation signals', () => {
  const metadata = mutationFailureMetadata({
    code: 'sub2api_write_reconciliation_required',
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationReason: 'post_write_verification',
    message: 'Bearer must-not-persist',
    credential: 'must-not-persist',
  });
  assert.deepEqual(metadata, {
    code: 'SUB2API_WRITE_RECONCILIATION_REQUIRED',
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationReason: 'post_write_verification',
  });
  assert.equal(JSON.stringify(metadata).includes('must-not-persist'), false);
});

test('a running token cleanup owned by a dead process recovers as an actionable hold', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-dead-owner-'));
  const file = path.join(root, 'panel.sqlite3');
  const db = new PanelDb(file);
  const expectedVersion = 'a'.repeat(64);
  const contentHash = 'b'.repeat(64);
  const job = await db.createJob('token_cleanup', {
    expectedVersion,
    targetCount: 1,
    reviewTargets: [{
      sourcePath: 'tokens/expired.json',
      contentHash,
    }],
    reviewTargetsTruncated: false,
  }, 'panel-admin', { claimKeys: ['token_cleanup:expired_tokens'] });
  await db.startMutationJob(job.id);
  await db.write((database) => {
    const statement = database.prepare(
      'UPDATE sync_jobs SET owner_pid = ?, owner_start_id = ? WHERE id = ?',
    );
    statement.run([2147483647, 'definitely-not-live', job.id]);
    statement.free();
  });

  const restarted = new PanelDb(file);
  const recovered = await restarted.getJob(job.id);
  assert.equal(recovered.status, 'interrupted');
  assert.equal(recovered.result.executionOutcome, 'unknown');
  assert.equal(recovered.result.requiresReconciliation, true);
  assert.equal(recovered.result.reconciliationHold, true);
  assert.equal(recovered.result.retryAllowed, false);
  assert.equal(recovered.result.doNotRetry, true);
  const detail = reconciliationReviewDetail(recovered);
  assert.equal(detail.targetContext.truncated, false);
  assert.deepEqual(detail.targetContext.targets[1], {
    sourcePath: 'tokens/expired.json',
    contentHash,
    accessFingerprint: undefined,
  });
  await assert.rejects(
    restarted.createJob('token_cleanup', {}, 'panel-admin', {
      claimKeys: ['token_cleanup:expired_tokens'],
    }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === job.id,
  );
});

test('HTTP server applies bounded slow-request and connection limits', () => {
  const logger = {
    requestId: () => 'bounded-http-test',
    info() {},
    warn() {},
    error() {},
  };
  const server = createServer({ db: { dbPath: '/tmp/unused-panel-test.sqlite3' }, logger });
  assert.equal(server.requestTimeout, 30_000);
  assert.equal(server.headersTimeout, 15_000);
  assert.equal(server.keepAliveTimeout, 5_000);
  assert.equal(server.maxHeadersCount, 100);
  assert.equal(server.maxRequestsPerSocket, 100);
});

test('HTTP limits treat blank values as defaults and clamp explicit bounds', () => {
  const names = [
    'PANEL_HTTP_REQUEST_TIMEOUT_MS',
    'PANEL_HTTP_HEADERS_TIMEOUT_MS',
    'PANEL_HTTP_KEEP_ALIVE_TIMEOUT_MS',
    'PANEL_HTTP_MAX_HEADERS',
    'PANEL_HTTP_MAX_REQUESTS_PER_SOCKET',
  ];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  const logger = {
    requestId: () => 'bounded-http-config-test',
    info() {},
    warn() {},
    error() {},
  };
  try {
    process.env.PANEL_HTTP_REQUEST_TIMEOUT_MS = '   ';
    process.env.PANEL_HTTP_HEADERS_TIMEOUT_MS = '999999';
    process.env.PANEL_HTTP_KEEP_ALIVE_TIMEOUT_MS = '-1';
    process.env.PANEL_HTTP_MAX_HEADERS = 'not-a-number';
    process.env.PANEL_HTTP_MAX_REQUESTS_PER_SOCKET = '0';
    const server = createServer({ db: { dbPath: '/tmp/unused-panel-config-test.sqlite3' }, logger });
    assert.equal(server.requestTimeout, 30_000);
    assert.equal(server.headersTimeout, 30_000);
    assert.equal(server.keepAliveTimeout, 1_000);
    assert.equal(server.maxHeadersCount, 100);
    assert.equal(server.maxRequestsPerSocket, 1);
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  }
});

test('listen host and port reject ambiguous deployment values', () => {
  assert.equal(configuredListenHost(undefined, {}), '127.0.0.1');
  assert.equal(configuredListenHost(undefined, { PANEL_HOST: ' 127.0.0.1 ' }), '127.0.0.1');
  assert.throws(
    () => configuredListenHost(undefined, { PANEL_HOST: '   ' }),
    (error) => error.code === 'PANEL_HOST_INVALID',
  );

  assert.equal(configuredListenPort(undefined, {}), 4170);
  assert.equal(configuredListenPort(undefined, { PANEL_PORT: '   ' }), 4170);
  assert.equal(configuredListenPort(undefined, { PANEL_PORT: '4171' }), 4171);
  assert.equal(configuredListenPort(0, { PANEL_PORT: '4171' }), 0);
  for (const invalid of ['0', '-1', '1e3', '0x1050', '65536', 'port']) {
    assert.throws(
      () => configuredListenPort(undefined, { PANEL_PORT: invalid }),
      (error) => error.code === 'PANEL_PORT_INVALID',
    );
  }
});

test('JSON request bodies account for bytes incrementally and reject aborted streams', async () => {
  const requestStream = new EventEmitter();
  requestStream.setEncoding = () => {};
  requestStream.resume = () => {};
  const originalByteLength = Buffer.byteLength;
  const measuredLengths = [];
  Buffer.byteLength = function measuredByteLength(value, ...args) {
    measuredLengths.push(String(value).length);
    return originalByteLength.call(Buffer, value, ...args);
  };
  try {
    const parsedPromise = readJsonBody(requestStream, 64);
    requestStream.emit('data', '{"part":');
    requestStream.emit('data', '"value"}');
    requestStream.emit('end');
    assert.deepEqual(await parsedPromise, { part: 'value' });
    assert.deepEqual(measuredLengths, [8, 8]);
  } finally {
    Buffer.byteLength = originalByteLength;
  }

  const abortedStream = new EventEmitter();
  abortedStream.setEncoding = () => {};
  abortedStream.resume = () => {};
  const abortedPromise = readJsonBody(abortedStream, 64);
  abortedStream.emit('data', '{"partial":');
  abortedStream.emit('aborted');
  await assert.rejects(abortedPromise, (error) => error.code === 'REQUEST_ABORTED');
});

test('server startup waits for database initialization before listening', async () => {
  const sentinel = new Error('database initialization failed');
  const db = { dbPath: '/tmp/unused-panel-ready-test.sqlite3' };
  Object.defineProperty(db, 'ready', {
    get() { return Promise.reject(sentinel); },
  });
  const logger = {
    requestId: () => 'db-ready-test',
    info() {},
    warn() {},
    error() {},
    tail() { return []; },
  };
  await assert.rejects(
    startServer({ host: '127.0.0.1', port: 0, db, logger }),
    (error) => error === sentinel,
  );
});

test('authentication defaults to enabled and startup validates before database access', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
  };
  delete process.env.PANEL_ADMIN_TOKEN;
  delete process.env.PANEL_REQUIRE_AUTH;
  resetAuthFailureBuckets();
  let databaseAccessed = false;
  const db = { dbPath: '/tmp/unused-panel-default-auth-test.sqlite3' };
  Object.defineProperty(db, 'ready', {
    get() {
      databaseAccessed = true;
      return Promise.resolve();
    },
  });
  try {
    assert.equal(authorizationError({
      headers: {},
      socket: { remoteAddress: '127.0.0.1' },
    }).status, 401);
    await assert.rejects(
      startServer({
        host: '127.0.0.1',
        port: 0,
        db,
        logger: { info() {}, warn() {}, error() {} },
      }),
      (error) => error.code === 'PANEL_AUTH_CONFIG_REQUIRED',
    );
    assert.equal(databaseAccessed, false);
  } finally {
    resetAuthFailureBuckets();
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
  }
});

test('startup rejects invalid booleans before database access', async () => {
  const previous = {
    phase3: process.env.PANEL_PHASE3_ENABLED,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    token: process.env.PANEL_ADMIN_TOKEN,
  };
  process.env.PANEL_REQUIRE_AUTH = '0';
  delete process.env.PANEL_ADMIN_TOKEN;
  process.env.PANEL_PHASE3_ENABLED = 'true';
  let databaseAccessed = false;
  const db = { dbPath: '/tmp/unused-panel-invalid-boolean-test.sqlite3' };
  Object.defineProperty(db, 'ready', {
    get() {
      databaseAccessed = true;
      return Promise.resolve();
    },
  });
  try {
    await assert.rejects(
      startServer({ host: '127.0.0.1', port: 0, db }),
      (error) => error.code === 'ENV_BOOLEAN_INVALID',
    );
    assert.equal(databaseAccessed, false);
  } finally {
    if (previous.phase3 === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.phase3;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
  }
});

test('Phase3 startup rejects a shutdown budget shorter than process-tree cleanup', () => {
  const previous = {
    enabled: process.env.PANEL_PHASE3_ENABLED,
    shutdown: process.env.PANEL_SHUTDOWN_TIMEOUT_MS,
  };
  try {
    process.env.PANEL_PHASE3_ENABLED = '1';
    process.env.PANEL_SHUTDOWN_TIMEOUT_MS = '5999';
    assert.throws(
      () => validateRuntimeConfiguration(),
      (error) => error?.code === 'PANEL_SHUTDOWN_BUDGET_TOO_SMALL'
        && /6000/.test(error.message),
    );
    process.env.PANEL_SHUTDOWN_TIMEOUT_MS = '6000';
    assert.doesNotThrow(() => validateRuntimeConfiguration());
    delete process.env.PANEL_SHUTDOWN_TIMEOUT_MS;
    assert.doesNotThrow(() => validateRuntimeConfiguration());
  } finally {
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
    if (previous.shutdown === undefined) delete process.env.PANEL_SHUTDOWN_TIMEOUT_MS;
    else process.env.PANEL_SHUTDOWN_TIMEOUT_MS = previous.shutdown;
  }
});

test('configured administrator tokens must be bounded printable ASCII without whitespace', () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
  };
  process.env.PANEL_REQUIRE_AUTH = '1';
  const invalidTokens = [
    'short-token',
    'sixteen chars ok ',
    'sixteen\tchars-ok',
    'non-ascii-token-密钥',
    'x'.repeat(4097),
  ];
  try {
    for (const token of invalidTokens) {
      process.env.PANEL_ADMIN_TOKEN = token;
      let validationError;
      assert.throws(
        () => validateRuntimeConfiguration(),
        (caught) => {
          validationError = caught;
          return caught.code === 'PANEL_ADMIN_TOKEN_INVALID';
        },
      );
      assert.equal(validationError.message.includes(token), false);
      assert.equal(validationError.message.includes(String(token.length)), false);
    }
    process.env.PANEL_ADMIN_TOKEN = '0123456789abcdef';
    assert.doesNotThrow(() => validateRuntimeConfiguration());
    process.env.PANEL_ADMIN_TOKEN = '!'.repeat(4096);
    assert.doesNotThrow(() => validateRuntimeConfiguration());
  } finally {
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
  }
});

test('write endpoints fail closed when the audit log becomes unavailable', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let server;
  try {
    const logger = {
      requestId: () => 'audit-log-unavailable-test',
      info() {},
      warn() {},
      error() {},
      probe() { return false; },
      health() { return { healthy: false, failedWrites: 1 }; },
    };
    server = createServer({
      db: { dbPath: '/tmp/unused-panel-audit-log-test.sqlite3' },
      logger,
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    const response = await postJson(baseUrl, '/api/phase3', {
      accounts: [{ email: 'must-not-queue@example.test' }],
    });
    assert.equal(response.status, 503);
    assert.equal(JSON.parse(response.body).error, 'audit_log_unavailable');
    const health = await request(baseUrl, '/api/health');
    assert.equal(JSON.parse(health.body).auditLog.healthy, false);
  } finally {
    await closeHttpServer(server);
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

function request(baseUrl, pathname) {
  return new Promise((resolve, reject) => {
    const requestObject = http.get(baseUrl + pathname, configuredPanelToken
      ? { headers: { 'x-panel-token': configuredPanelToken } }
      : {}, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body,
      }));
    });
    requestObject.on('error', reject);
  });
}

function postJson(baseUrl, pathname, body) {
  return new Promise((resolve, reject) => {
    const requestObject = http.request(baseUrl + pathname, {
      method: 'POST',
      headers: {
        ...(configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {}),
        'content-type': 'application/json',
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body: responseBody }));
    });
    requestObject.on('error', reject);
    requestObject.end(JSON.stringify(body));
  });
}

function postBody(baseUrl, pathname, body, contentType) {
  return new Promise((resolve, reject) => {
    const requestObject = http.request(baseUrl + pathname, {
      method: 'POST',
      headers: {
        ...(configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {}),
        ...(contentType ? { 'content-type': contentType } : {}),
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body: responseBody }));
    });
    requestObject.on('error', reject);
    requestObject.end(body);
  });
}

async function closeHttpServer(server) {
  if (!server || !server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function waitForTerminalJob(baseUrl, jobId) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const response = await request(baseUrl, '/api/jobs/' + encodeURIComponent(jobId));
    assert.equal(response.status, 200);
    const job = JSON.parse(response.body);
    if (['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('timed out waiting for test job ' + jobId);
}

async function waitForAdmission(server) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (server?.panelJobManager?.admissionCount > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('timed out waiting for request admission');
}

test('importing the server does not load deployment environment files', () => {
  const script = [
    "const configPath = require.resolve('./backend/config');",
    'let called = false;',
    'require.cache[configPath] = {',
    '  id: configPath,',
    '  filename: configPath,',
    '  loaded: true,',
    '  exports: { loadEnv() { called = true; } },',
    '};',
    "require('./backend/server');",
    "process.stdout.write(called ? 'called' : 'not-called');",
  ].join('\n');
  const child = spawnSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'not-called');
});

test('test isolation removes inherited Sub2API credentials before snapshot code loads', () => {
  const isolationModule = path.resolve(__dirname, 'test-isolation.js');
  const script = [
    'let fetchCalls = 0;',
    "global.fetch = async () => { fetchCalls += 1; throw new Error('unexpected network'); };",
    "const { buildSnapshot, configuredForSub2Api } = require('./backend/sync');",
    '(async () => {',
    '  const snapshot = await buildSnapshot(new URLSearchParams());',
    '  process.stdout.write(JSON.stringify({',
    '    configured: configuredForSub2Api(),',
    '    fetchCalls,',
    '    readStatus: snapshot.sub2api.readStatus,',
    '    accountCount: snapshot.sub2api.accountCount,',
    '    comparisonStatus: snapshot.diff.comparisonStatus,',
    '  }));',
    '})().catch(() => { process.exitCode = 1; });',
  ].join('\n');
  const child = spawnSync(process.execPath, ['--require', isolationModule, '-e', script], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    env: {
      ...process.env,
      SUB2API_BASE_URL: 'http://127.0.0.1:9',
      SUB2API_ADMIN_API_KEY: 'inherited-test-api-key',
      SUB2API_JWT: 'inherited-test-jwt',
    },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), {
    configured: false,
    fetchCalls: 0,
    readStatus: 'omitted',
    accountCount: null,
    comparisonStatus: 'unavailable',
  });
});

test('executable entrypoints redact fatal stderr instead of printing raw stacks', () => {
  const serverSource = fs.readFileSync(path.resolve(__dirname, '..', 'backend', 'server.js'), 'utf8');
  const snapshotSource = fs.readFileSync(
    path.resolve(__dirname, '..', 'backend', 'cli', 'snapshot.js'),
    'utf8',
  );
  for (const entrypoint of [serverSource, snapshotSource]) {
    assert.doesNotMatch(entrypoint, /process\.stderr\.write\(error\.stack/);
    assert.match(entrypoint, /process\.stderr\.write\(safeErrorText\(error\)/);
  }
  assert.match(snapshotSource, /async function main\(\) \{\s*loadEnv\(\);/);
});

test('verified static opener rejects final and intermediate symlinks', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-static-'));
  const root = path.join(directory, 'frontend');
  const outside = path.join(directory, 'outside');
  fs.mkdirSync(root);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(root, 'regular.txt'), 'regular');
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside');
  fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(root, 'file-link'));
  fs.symlinkSync(outside, path.join(root, 'directory-link'), 'dir');

  const opened = openVerifiedStaticFile(path.join(root, 'regular.txt'), root);
  try {
    assert.equal(fs.readFileSync(opened.descriptor, 'utf8'), 'regular');
  } finally {
    fs.closeSync(opened.descriptor);
  }
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'file-link'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'directory-link', 'secret.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  assert.throws(
    () => openVerifiedStaticFile(path.join(outside, 'secret.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  fs.chmodSync(path.join(root, 'regular.txt'), 0o666);
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'regular.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  fs.chmodSync(path.join(root, 'regular.txt'), 0o644);
  fs.chmodSync(root, 0o777);
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'regular.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  fs.chmodSync(root, 0o755);
  fs.writeFileSync(path.join(root, 'linked.txt'), 'linked');
  fs.linkSync(path.join(root, 'linked.txt'), path.join(root, 'linked-copy.txt'));
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'linked.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );

  const raceRoot = path.join(directory, 'race-frontend');
  const savedRoot = path.join(directory, 'race-frontend-original');
  fs.mkdirSync(raceRoot);
  const raceFile = path.join(raceRoot, 'app.js');
  fs.writeFileSync(raceFile, 'trusted');
  fs.writeFileSync(path.join(outside, 'app.js'), 'outside');
  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = function guardedOpen(target, ...args) {
    if (!swapped && target === raceFile) {
      swapped = true;
      fs.renameSync(raceRoot, savedRoot);
      fs.symlinkSync(outside, raceRoot, 'dir');
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    assert.throws(
      () => openVerifiedStaticFile(raceFile, raceRoot),
      (error) => error.code === 'STATIC_PATH_INVALID',
    );
  } finally {
    fs.openSync = originalOpenSync;
    if (swapped) {
      fs.unlinkSync(raceRoot);
      fs.renameSync(savedRoot, raceRoot);
    }
  }
});

test('authentication failure buckets remain strictly bounded for unique sources', () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    maxFailures: process.env.PANEL_AUTH_MAX_FAILURES,
  };
  process.env.PANEL_ADMIN_TOKEN = 'bounded-test-admin-token';
  process.env.PANEL_REQUIRE_AUTH = '1';
  process.env.PANEL_AUTH_MAX_FAILURES = '10';
  resetAuthFailureBuckets();
  try {
    for (let index = 0; index < 10_025; index += 1) {
      const result = authorizationError({
        headers: { authorization: 'Bearer incorrect' },
        socket: { remoteAddress: 'unique-test-source-' + index },
      });
      assert.equal(result.status, 401);
    }
    assert.equal(authFailureBucketCount(), 10_000);

    resetAuthFailureBuckets();
    process.env.PANEL_AUTH_MAX_FAILURES = '1';
    const sharedSource = { remoteAddress: '198.51.100.20' };
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer incorrect' },
      socket: sharedSource,
    }).status, 401);
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer incorrect' },
      socket: sharedSource,
    }).status, 429);
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer bounded-test-admin-token' },
      socket: sharedSource,
    }), null);
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer incorrect' },
      socket: sharedSource,
    }).status, 401);
  } finally {
    resetAuthFailureBuckets();
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.maxFailures === undefined) delete process.env.PANEL_AUTH_MAX_FAILURES;
    else process.env.PANEL_AUTH_MAX_FAILURES = previous.maxFailures;
  }
});

test('Phase3 claim keys include every canonical email and phone identity', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-identity-'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
    email: 'canonical@example.test',
    phone: '15550000002',
    password: 'fake-password',
  }]));
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    const expected = [
      'phase3:email:canonical@example.test',
      'phase3:phone:15550000002',
    ];
    assert.deepEqual(phase3ClaimKeys({ email: 'canonical@example.test' }), expected);
    assert.deepEqual(phase3ClaimKeys({ phone: '15550000002' }), expected);
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('serves a read-only health endpoint and safe source snapshot', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-server-'));
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
    phase3Enabled: process.env.PANEL_PHASE3_ENABLED,
    registerRoot: process.env.GPT_REGISTER_ROOT,
  };
  let server = null;
  process.env.PANEL_WRITE_ENABLED = '0';
  process.env.GPT_REGISTER_ROOT = root;
  try {
    fs.mkdirSync(path.join(root, 'tokens'));
    fs.mkdirSync(path.join(root, 'use_token'));
    fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
      {
        email: 'server@example.test',
        phone: '15550000001',
        password: 'hidden-password',
        status: 'oauth_done',
      },
      {
        email: 'second@example.test',
        password: 'second-hidden-password',
        status: 'oauth_done',
      },
    ]));
    fs.writeFileSync(path.join(root, 'tokens', 'token.json'), JSON.stringify({
      access_token: 'not-a-jwt',
      refresh_token: 'refresh-hidden',
      email: 'server@example.test',
      expired: '2099-01-01T00:00:00.000Z',
    }));
    fs.writeFileSync(path.join(root, 'tokens', 'token-duplicate.json'), JSON.stringify({
      access_token: 'not-a-jwt-duplicate',
      email: 'server@example.test',
    }));
    fs.writeFileSync(path.join(root, 'tokens', 'second.json'), JSON.stringify({
      access_token: 'not-a-jwt-second',
      email: 'second@example.test',
    }));
    fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify({
      access_token: 'expired-access',
      refresh_token: 'expired-refresh-hidden',
      email: 'expired@example.test',
      expired: '2020-01-01T00:00:00.000Z',
    }));
    server = createServer({
      dbPath: path.join(root, 'panel.sqlite3'),
      logger: {
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint() { return true; },
        requestId(value) { return value || 'test-request'; },
        tail() { return []; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });
    const address = server.address();
    const baseUrl = 'http://127.0.0.1:' + address.port;
    const health = await request(baseUrl, '/api/health');
    assert.equal(health.status, 200);
    assert.match(health.body, /"readOnly":true/);
    assert.match(health.headers['content-security-policy'], /base-uri 'none'/);
    assert.match(health.headers['content-security-policy'], /object-src 'none'/);
    assert.match(health.headers['content-security-policy'], /form-action 'none'/);
    assert.equal(health.headers['referrer-policy'], 'no-referrer');
    assert.equal(health.headers['x-frame-options'], 'DENY');

    const healthWrite = await postJson(baseUrl, '/api/health', {});
    assert.equal(healthWrite.status, 405);

    const page = await request(baseUrl, '/');
    assert.equal(page.status, 200);
    assert.match(page.body, /账号管理/);
    assert.match(page.headers['content-security-policy'], /base-uri 'none'/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    const app = await request(baseUrl, '/app.js');
    assert.equal(app.status, 200);
    assert.match(app.body, /resumeActiveJob/);

    const staticWrite = await new Promise((resolve, reject) => {
      const req = http.request(baseUrl + '/', { method: 'POST' }, (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      });
      req.on('error', reject);
      req.end('ignored');
    });
    assert.equal(staticWrite, 405);

    const snapshot = await request(baseUrl, '/api/snapshot');
    assert.equal(snapshot.status, 200);
    assert.match(snapshot.body, /server@example.test/);
    assert.equal(snapshot.body.includes('hidden-password'), false);
    assert.equal(snapshot.body.includes('refresh-hidden'), false);

    fs.renameSync(path.join(root, 'use_token'), path.join(root, 'use_token-missing'));
    const incompleteSourcePreview = await postJson(baseUrl, '/api/sync/preview', {
      selectedKeys: [],
    });
    assert.equal(incompleteSourcePreview.status, 400);
    assert.equal(
      JSON.parse(incompleteSourcePreview.body).error,
      'GPT_REGISTER_SOURCE_MISSING',
    );
    fs.renameSync(path.join(root, 'use_token-missing'), path.join(root, 'use_token'));

    const incompletePreview = await postJson(baseUrl, '/api/sync/preview', {
      selectedKeys: [],
    });
    assert.equal(incompletePreview.status, 502);
    assert.equal(JSON.parse(incompletePreview.body).error, 'SUB2API_READ_FAILED');

    const writeAttempt = await new Promise((resolve, reject) => {
      const req = http.request(baseUrl + '/api/snapshot', {
        method: 'POST',
        headers: configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {},
      }, (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(writeAttempt, 405);

    process.env.PANEL_WRITE_ENABLED = '1';
    process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
    process.env.PANEL_PHASE3_ENABLED = '0';
    const crossSiteStylePost = await postBody(
      baseUrl,
      '/api/phase3',
      JSON.stringify({ accounts: [{ email: 'server@example.test' }] }),
      'text/plain',
    );
    assert.equal(crossSiteStylePost.status, 415);
    assert.equal(JSON.parse(crossSiteStylePost.body).error, 'json_content_type_required');

    const batchPhase3 = await postJson(baseUrl, '/api/phase3', {
      accounts: [
        {
          email: 'server@example.test',
          selectedKey: 'token:tokens:tokens/token.json',
        },
        {
          phone: '15550000001',
          selectedKey: 'token:tokens:tokens/token-duplicate.json',
        },
        {
          email: 'second@example.test',
          selectedKey: 'token:tokens:tokens/second.json',
        },
      ],
      selectedKeys: [
        'token:tokens:tokens/token.json',
        'token:tokens:tokens/token-duplicate.json',
        'token:tokens:tokens/second.json',
      ],
    });
    assert.equal(batchPhase3.status, 202);
    const batchBody = JSON.parse(batchPhase3.body);
    assert.equal(batchBody.batch, true);
    assert.equal(batchBody.jobIds.length, 2);
    assert.equal(batchBody.rejected.length, 1);
    assert.equal(batchBody.rejected[0].error, 'duplicate_in_request');
    const phase3Jobs = await Promise.all(
      batchBody.jobIds.map((jobId) => waitForTerminalJob(baseUrl, jobId)),
    );
    assert.equal(phase3Jobs.every((job) => job.status === 'failed'), true);
    assert.equal(phase3Jobs.every((job) => job.result?.code === 'PHASE3_DISABLED'), true);

    const expiredListing = await request(baseUrl, '/api/tokens/expired');
    assert.equal(expiredListing.status, 200);
    const expiredBody = JSON.parse(expiredListing.body);
    assert.equal(expiredBody.count, 1);
    assert.equal(expiredListing.body.includes('expired-refresh-hidden'), false);
    const expiredDelete = await postJson(baseUrl, '/api/tokens/expired/delete', {
      version: expiredBody.version,
      confirmation: 'DELETE_EXPIRED_TOKENS',
    });
    assert.equal(expiredDelete.status, 202);
    const cleanupSubmission = JSON.parse(expiredDelete.body);
    const cleanupJob = await waitForTerminalJob(baseUrl, cleanupSubmission.jobId);
    assert.equal(cleanupJob.type, 'token_cleanup');
    assert.equal(cleanupJob.status, 'succeeded');
    assert.equal(cleanupJob.result.deletedCount, 1);
    assert.equal(cleanupJob.result.skippedCount, 0);
    assert.equal(cleanupJob.result.deleted, undefined);
    assert.equal(cleanupJob.payload.reviewTargets[0].sourcePath, 'tokens/expired.json');
    assert.match(cleanupJob.payload.reviewTargets[0].contentHash, /^[a-f0-9]{64}$/);
    assert.equal(JSON.stringify(cleanupJob).includes('expired-refresh-hidden'), false);
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'expired.json')), false);
  } finally {
    try {
      await closeHttpServer(server);
    } finally {
      const names = {
        writeEnabled: 'PANEL_WRITE_ENABLED',
        allowInsecureWrite: 'PANEL_ALLOW_INSECURE_WRITE',
        phase3Enabled: 'PANEL_PHASE3_ENABLED',
        registerRoot: 'GPT_REGISTER_ROOT',
      };
      for (const [key, environmentName] of Object.entries(names)) {
        if (previous[key] === undefined) delete process.env[environmentName];
        else process.env[environmentName] = previous[key];
      }
    }
  }
});

test('expired token deletion fails closed when its durable audit intent cannot be stored', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-intent-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: 'expired-access',
    email: 'intent@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let server;
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  let checkpoints = 0;
  try {
    await db.ready;
    db.audit = async () => { throw new Error('simulated audit storage failure'); };
    const listing = listExpiredTokens();
    assert.equal(listing.count, 1);
    server = createServer({
      db,
      logger: {
        requestId: () => 'cleanup-intent-failure',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint() { checkpoints += 1; return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const response = await postJson(
      'http://127.0.0.1:' + server.address().port,
      '/api/tokens/expired/delete',
      { version: listing.version, confirmation: 'DELETE_EXPIRED_TOKENS' },
    );
    assert.equal(response.status, 202);
    const job = await waitForTerminalJob(
      'http://127.0.0.1:' + server.address().port,
      JSON.parse(response.body).jobId,
    );
    assert.equal(job.status, 'failed');
    assert.equal(job.result.code, 'TOKEN_CLEANUP_AUDIT_INTENT_FAILED');
    assert.notEqual(job.result.requiresReconciliation, true);
    assert.equal(checkpoints, 0);
    assert.equal(fs.existsSync(sourcePath), true);
    assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
  } finally {
    await closeHttpServer(server);
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('expired token deletion reports reconciliation and forbids retry when completion audit fails', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-audit-result-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: 'expired-access',
    email: 'completion@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let server;
  const audits = [];
  const checkpoints = [];
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  try {
    await db.ready;
    const persistAudit = db.audit.bind(db);
    db.audit = async (entry) => {
      if (entry?.action === 'expired_token_cleanup') {
        audits.push(entry);
        if (audits.length === 2) throw new Error('simulated completion audit failure');
      }
      return persistAudit(entry);
    };
    const listing = listExpiredTokens();
    server = createServer({
      db,
      logger: {
        requestId: () => 'cleanup-completion-failure',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint(event) { checkpoints.push(event); return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const response = await postJson(
      'http://127.0.0.1:' + server.address().port,
      '/api/tokens/expired/delete',
      { version: listing.version, confirmation: 'DELETE_EXPIRED_TOKENS' },
    );
    assert.equal(response.status, 202);
    const job = await waitForTerminalJob(
      'http://127.0.0.1:' + server.address().port,
      JSON.parse(response.body).jobId,
    );
    assert.equal(job.status, 'partial');
    assert.equal(job.result.code, 'TOKEN_CLEANUP_AUDIT_RECONCILIATION_REQUIRED');
    assert.equal(job.result.outcome, 'requires_reconciliation');
    assert.equal(job.result.requiresReconciliation, true);
    assert.equal(job.result.reconciliationHold, true);
    assert.equal(job.result.retryAllowed, false);
    assert.equal(job.result.doNotRetry, true);
    assert.equal(job.result.completedCount, 1);
    assert.equal(fs.existsSync(sourcePath), false);
    assert.equal(audits[0].result, 'intent');
    assert.deepEqual(checkpoints, [
      'token_cleanup.mutation_checkpoint',
      'token_cleanup.mutation_completed',
    ]);
  } finally {
    await closeHttpServer(server);
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('token cleanup retains a durable hold when claim recovery is followed by a stale listing', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-boundary-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  const sourceContent = JSON.stringify({
    access_token: 'expired-access',
    email: 'boundary@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  });
  fs.writeFileSync(sourcePath, sourceContent, { mode: 0o600 });
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  let server;
  try {
    await db.ready;
    const listing = listExpiredTokens();
    const createJob = db.createJob.bind(db);
    let injected = false;
    db.createJob = async (...args) => {
      const job = await createJob(...args);
      if (!injected && args[0] === 'token_cleanup') {
        injected = true;
        const contentHash = crypto.createHash('sha256').update(sourceContent).digest('hex');
        const encodedName = Buffer.from(path.basename(sourcePath), 'utf8').toString('base64url');
        const claimPath = path.join(
          path.dirname(sourcePath),
          '.panel-token-cleanup-claim-v1-999999-0-' + contentHash + '-'
            + encodedName + '-0123456789abcdef',
        );
        fs.renameSync(sourcePath, claimPath);
        fs.writeFileSync(path.join(root, 'use_token', 'new-expired.json'), JSON.stringify({
          access_token: 'second-expired-access',
          email: 'second-boundary@example.test',
          expired: '2020-01-01T00:00:00.000Z',
        }), { mode: 0o600 });
      }
      return job;
    };
    server = createServer({
      db,
      logger: {
        requestId: () => 'cleanup-boundary-stale',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint() { return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    const response = await postJson(baseUrl, '/api/tokens/expired/delete', {
      version: listing.version,
      confirmation: 'DELETE_EXPIRED_TOKENS',
    });
    assert.equal(response.status, 202);
    const job = await waitForTerminalJob(baseUrl, JSON.parse(response.body).jobId);
    assert.equal(job.status, 'failed');
    assert.equal(job.result.code, 'TOKEN_CLEANUP_OUTCOME_UNKNOWN');
    assert.equal(job.result.causeCode, 'TOKEN_CLEANUP_STALE');
    assert.equal(job.result.reconciliationReason, 'mutation_boundary_failure');
    assert.equal(job.result.requiresReconciliation, true);
    assert.equal(job.result.reconciliationHold, true);
    assert.equal(job.result.retryAllowed, false);
    assert.equal(job.result.doNotRetry, true);
    assert.equal(fs.existsSync(sourcePath), true);
    assert.equal(fs.existsSync(path.join(root, 'use_token', 'new-expired.json')), true);
    const detail = reconciliationReviewDetail(job);
    assert.equal(detail.type, 'token_cleanup');
    assert.equal(detail.targetContext.truncated, false);
    assert.equal(detail.targetContext.targets[1].sourcePath, 'tokens/expired.json');
    assert.match(detail.targetContext.targets[1].contentHash, /^[a-f0-9]{64}$/);
    assert.equal(JSON.stringify(detail).includes('expired-access'), false);
    const blocked = await postJson(baseUrl, '/api/tokens/expired/delete', {
      version: listExpiredTokens().version,
      confirmation: 'DELETE_EXPIRED_TOKENS',
    });
    assert.equal(blocked.status, 409);
    assert.equal(JSON.parse(blocked.body).error, 'JOB_RECONCILIATION_REQUIRED');
  } finally {
    await closeHttpServer(server);
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('expired token deletion rechecks its log checkpoint after waiting for the control lock', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-checkpoint-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: 'expired-access',
    email: 'checkpoint@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let releaseBlocker;
  let markBlockerEntered;
  const blockerEntered = new Promise((resolve) => { markBlockerEntered = resolve; });
  const blocker = withControlPlaneLock(async () => {
    markBlockerEntered();
    await new Promise((resolve) => { releaseBlocker = resolve; });
  });
  let server;
  let checkpointHealthy = true;
  const audits = [];
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  try {
    await blockerEntered;
    await db.ready;
    const persistAudit = db.audit.bind(db);
    db.audit = async (entry) => {
      if (entry?.action === 'expired_token_cleanup') audits.push(entry);
      return persistAudit(entry);
    };
    const listing = listExpiredTokens();
    server = createServer({
      db,
      logger: {
        requestId: () => 'cleanup-checkpoint-after-queue',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint() { return checkpointHealthy; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const responsePromise = postJson(
      'http://127.0.0.1:' + server.address().port,
      '/api/tokens/expired/delete',
      { version: listing.version, confirmation: 'DELETE_EXPIRED_TOKENS' },
    );
    await waitForAdmission(server);
    checkpointHealthy = false;
    releaseBlocker();
    releaseBlocker = null;
    await blocker;
    const response = await responsePromise;
    assert.equal(response.status, 202);
    const job = await waitForTerminalJob(
      'http://127.0.0.1:' + server.address().port,
      JSON.parse(response.body).jobId,
    );
    assert.equal(job.status, 'failed');
    assert.equal(job.result.code, 'AUDIT_LOG_UNAVAILABLE');
    assert.notEqual(job.result.requiresReconciliation, true);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].result, 'intent');
    assert.equal(fs.existsSync(sourcePath), true);
    assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
  } finally {
    if (releaseBlocker) releaseBlocker();
    await Promise.allSettled([blocker]);
    await withControlPlaneLock(async () => {});
    await closeHttpServer(server);
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('shutdown cancels a queued expired token deletion before any audit or file mutation', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-shutdown-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: 'expired-access',
    email: 'shutdown@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let releaseBlocker;
  let markBlockerEntered;
  const blockerEntered = new Promise((resolve) => { markBlockerEntered = resolve; });
  const blocker = withControlPlaneLock(async () => {
    markBlockerEntered();
    await new Promise((resolve) => { releaseBlocker = resolve; });
  });
  let server;
  let auditCalls = 0;
  let checkpointCalls = 0;
  let shutdownPromise = null;
  try {
    await blockerEntered;
    const listing = listExpiredTokens();
    server = createServer({
      db: {
        dbPath: path.join(root, 'unused.sqlite3'),
        async assertNoReconciliationHold() {},
        async audit() { auditCalls += 1; },
        async interruptOwnedActiveJobs() { return []; },
      },
      logger: {
        requestId: () => 'cleanup-shutdown-queued',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint() { checkpointCalls += 1; return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const responsePromise = postJson(
      'http://127.0.0.1:' + server.address().port,
      '/api/tokens/expired/delete',
      { version: listing.version, confirmation: 'DELETE_EXPIRED_TOKENS' },
    );
    await waitForAdmission(server);
    shutdownPromise = shutdownServer(server, { signal: 'test', timeoutMs: 500 });
    const response = await responsePromise;
    assert.equal(response.status, 503);
    assert.equal(JSON.parse(response.body).error, 'JOB_INTERRUPTED');
    releaseBlocker();
    releaseBlocker = null;
    await blocker;
    await shutdownPromise;
    await withControlPlaneLock(async () => {});
    assert.equal(auditCalls, 0);
    assert.equal(checkpointCalls, 0);
    assert.equal(fs.existsSync(sourcePath), true);
    assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
  } finally {
    if (releaseBlocker) releaseBlocker();
    await Promise.allSettled([blocker]);
    if (shutdownPromise) await Promise.allSettled([shutdownPromise]);
    await withControlPlaneLock(async () => {});
    await closeHttpServer(server);
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('shutdown drains a tracked token cleanup after its file mutation', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-shutdown-after-mutation-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: 'expired-access',
    email: 'shutdown-after-mutation@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let markCompletionAuditEntered;
  let releaseCompletionAudit;
  const completionAuditEntered = new Promise((resolve) => { markCompletionAuditEntered = resolve; });
  const completionAuditBlocker = new Promise((resolve) => { releaseCompletionAudit = resolve; });
  let server;
  let shutdownPromise = null;
  let auditCalls = 0;
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  try {
    await db.ready;
    const persistAudit = db.audit.bind(db);
    db.audit = async (entry) => {
      if (entry?.action === 'expired_token_cleanup') {
        auditCalls += 1;
        if (auditCalls === 2) {
          markCompletionAuditEntered();
          await completionAuditBlocker;
        }
      }
      return persistAudit(entry);
    };
    const listing = listExpiredTokens();
    server = createServer({
      db,
      logger: {
        requestId: () => 'cleanup-shutdown-after-mutation',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint() { return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const responsePromise = postJson(
      'http://127.0.0.1:' + server.address().port,
      '/api/tokens/expired/delete',
      { version: listing.version, confirmation: 'DELETE_EXPIRED_TOKENS' },
    );
    const response = await responsePromise;
    assert.equal(response.status, 202);
    const jobId = JSON.parse(response.body).jobId;
    await completionAuditEntered;
    assert.equal(fs.existsSync(sourcePath), false);
    shutdownPromise = shutdownServer(server, { signal: 'test', timeoutMs: 1000 });
    releaseCompletionAudit();
    releaseCompletionAudit = null;
    await shutdownPromise;
    const job = await db.getJob(jobId);
    assert.equal(job.status, 'succeeded');
    assert.equal(job.result.deletedCount, 1);
    assert.equal(auditCalls, 2);
  } finally {
    if (releaseCompletionAudit) releaseCompletionAudit();
    if (shutdownPromise) await Promise.allSettled([shutdownPromise]);
    await closeHttpServer(server);
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});
