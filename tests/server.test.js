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
  publicApiError,
  publicTokenCleanupErrorFields,
  reconciliationReviewDetail,
  readJsonBody,
  requestLogPath,
  resetAuthFailureBuckets,
  safeStaticPath,
  shutdownServer,
  startServer,
  validateListenConfiguration,
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

test('public API errors expose only fixed codes, messages, and statuses', () => {
  const mappings = new Map([
    [400, [
      'INVALID_JSON_BODY',
      'INVALID_REQUEST_BODY',
      'IDEMPOTENCY_KEY_REQUIRED',
      'IDEMPOTENCY_KEY_INVALID',
      'SNAPSHOT_VERSION_REQUIRED',
      'IMPORT_SELECTION_REQUIRED',
      'IMPORT_SELECTION_INVALID',
      'IMPORT_SELECTION_MISMATCH',
      'PHASE3_BATCH_INVALID',
      'PHASE3_SELECTION_INVALID',
      'PHASE3_ACCOUNT_INVALID',
      'PHASE3_TARGET_REVISION_INVALID',
      'PHASE3_BATCH_EMPTY',
      'ACCOUNT_TEST_REQUEST_INVALID',
      'ACCOUNT_TEST_TARGET_REVISION_REQUIRED',
      'ACCOUNT_TEST_SELECTION_INVALID',
      'ACCOUNT_TEST_TARGET_INVALID',
      'ACCOUNT_TEST_ACCOUNT_ID_INVALID',
      'ACCOUNT_TEST_TARGET_DUPLICATE',
      'ACCOUNT_TEST_TARGET_REVISION_INVALID',
      'ACCOUNT_TEST_MODEL_INVALID',
      'ACCOUNT_TEST_PROMPT_INVALID',
      'TOKEN_CLEANUP_CONFIRMATION_REQUIRED',
      'TOKEN_CLEANUP_VERSION_REQUIRED',
      'JOB_RECONCILIATION_JOB_ID_INVALID',
      'JOB_RECONCILIATION_REQUEST_INVALID',
      'JOB_RECONCILIATION_JOB_ID_MISMATCH',
      'JOB_RECONCILIATION_CONFIRMATION_INVALID',
      'JOB_RECONCILIATION_RESOLUTION_INVALID',
      'JOB_RECONCILIATION_DIGEST_INVALID',
    ]],
    [403, [
      'JOB_RECONCILIATION_ADMIN_REQUIRED',
      'PHASE3_DISABLED',
      'WRITE_DISABLED',
    ]],
    [404, ['JOB_RECONCILIATION_NOT_FOUND']],
    [409, [
      'IDEMPOTENCY_KEY_REUSED',
      'PHASE3_DUPLICATE',
      'JOB_ALREADY_CLAIMED',
      'JOB_QUEUE_FULL',
      'JOB_RECONCILIATION_REQUIRED',
      'JOB_BLOCKED_BY_RECONCILIATION',
      'JOB_BLOCKED_BY_RUNNING_MUTATION',
      'ACCOUNT_TEST_TARGET_REVISION_STALE',
      'ACCOUNT_TEST_NO_ELIGIBLE_ACCOUNTS',
      'TOKEN_CLEANUP_STALE',
      'TOKEN_CLEANUP_RECOVERY_REQUIRED',
      'JOB_RECONCILIATION_NOT_HELD',
      'JOB_RECONCILIATION_ACK_CONFLICT',
      'JOB_RECONCILIATION_DIGEST_MISMATCH',
      'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
    ]],
    [413, ['REQUEST_BODY_TOO_LARGE']],
    [502, [
      'SUB2API_READ_FAILED',
      'SUB2API_ACCOUNTS_TOTAL_REQUIRED',
      'SUB2API_ACCOUNTS_PAGINATION_REQUIRED',
      'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    ]],
    [503, [
      'REQUEST_ABORTED',
      'JOB_INTERRUPTED',
      'IDEMPOTENCY_REQUEST_INVALID',
      'IDEMPOTENCY_WORKFLOW_INVALID',
      'IDEMPOTENCY_SCOPE_INVALID',
      'IDEMPOTENCY_RESPONSE_INVALID',
      'IDEMPOTENCY_JOBS_INVALID',
      'IDEMPOTENCY_CAPACITY_EXCEEDED',
      'IDEMPOTENCY_RECEIPT_INVALID',
      'IDEMPOTENCY_STORE_UNAVAILABLE',
      'CONTROL_PLANE_LOCK_RELEASE_FAILED',
      'JOB_ADMISSION_RECOVERY_FAILED',
      'JOB_RECONCILIATION_GUARD_UNAVAILABLE',
      'JOB_CLAIM_INTEGRITY_INVALID',
      'AUDIT_LOG_UNAVAILABLE',
      'TOKEN_CLEANUP_AUDIT_INTENT_FAILED',
      'ACCOUNT_TEST_BASELINE_INVALID',
      'GPT_REGISTER_SOURCE_MISSING',
    ]],
  ]);
  for (const [expectedStatus, codes] of mappings) {
    for (const code of codes) {
      const privateMarker = 'private-error-message-' + code;
      const error = new Error(privateMarker);
      error.code = code;
      const output = publicApiError(error, { write: true });
      assert.equal(output.statusCode, expectedStatus, code);
      assert.equal(output.body.error, code);
      assert.equal(JSON.stringify(output.body).includes(privateMarker), false, code);
    }
  }

  const malicious = new Error('private-message-must-not-escape');
  malicious.code = 'MALICIOUS_PUBLIC_CODE';
  const readFailure = publicApiError(malicious, {
    fallbackCode: 'preview_failed',
    fallbackMessage: '差异预览未能安全完成，请稍后重试',
  });
  assert.equal(readFailure.statusCode, 500);
  assert.equal(readFailure.body.error, 'preview_failed');
  assert.equal(JSON.stringify(readFailure.body).includes('MALICIOUS_PUBLIC_CODE'), false);
  assert.equal(JSON.stringify(readFailure.body).includes('private-message-must-not-escape'), false);

  const writeFailure = publicApiError(malicious, {
    write: true,
    fallbackCode: 'import_failed',
    fallbackMessage: '导入请求未能安全完成，请稍后重试',
  });
  assert.equal(writeFailure.statusCode, 503);
  assert.equal(writeFailure.body.error, 'import_failed');
  assert.equal(JSON.stringify(writeFailure.body).includes('MALICIOUS_PUBLIC_CODE'), false);
  assert.equal(JSON.stringify(writeFailure.body).includes('private-message-must-not-escape'), false);

  const hostileError = {};
  Object.defineProperty(hostileError, 'code', {
    get() { throw new Error('private-code-getter-marker'); },
  });
  Object.defineProperty(hostileError, 'message', {
    get() { throw new Error('private-message-getter-marker'); },
  });
  assert.deepEqual(publicApiError(hostileError), {
    statusCode: 500,
    body: {
      error: 'internal_error',
      message: '请求处理失败，请稍后重试',
    },
  });
});

test('cleanup public fields expose only a strict current version and bounded recovery counts', () => {
  const currentVersion = 'a'.repeat(64);
  assert.deepEqual(publicTokenCleanupErrorFields('TOKEN_CLEANUP_STALE', {
    currentVersion,
  }), { currentVersion });
  for (const invalid of [
    'A'.repeat(64),
    'a'.repeat(63),
    'a'.repeat(65),
    ' ' + 'a'.repeat(64),
    'private-current-version',
    123,
  ]) {
    assert.deepEqual(publicTokenCleanupErrorFields('TOKEN_CLEANUP_STALE', {
      currentVersion: invalid,
    }), {});
  }
  assert.deepEqual(publicTokenCleanupErrorFields('unknown_cleanup_failure', {
    currentVersion,
  }), {});
  const hostileVersion = {};
  Object.defineProperty(hostileVersion, 'currentVersion', {
    get() { throw new Error('private-version-getter-marker'); },
  });
  assert.deepEqual(publicTokenCleanupErrorFields('TOKEN_CLEANUP_STALE', hostileVersion), {});
  assert.deepEqual(publicTokenCleanupErrorFields('TOKEN_CLEANUP_RECOVERY_REQUIRED', {
    recoveryRequired: true,
    claimCount: 7,
    claimCountTruncated: true,
    currentVersion,
  }), {
    recoveryRequired: true,
    claimCount: 7,
    claimCountTruncated: true,
  });
});

test('request log paths use fixed templates without raw dynamic or unknown segments', () => {
  assert.equal(requestLogPath('/api/health'), '/api/health');
  assert.equal(requestLogPath('/api/jobs/job_' + 'a'.repeat(24)), '/api/jobs/:jobId');
  assert.equal(
    requestLogPath('/api/jobs/%65ncoded-private/reconciliation'),
    '/api/jobs/:jobId/reconciliation',
  );
  assert.equal(
    requestLogPath('/api/jobs/%65ncoded-private/reconciliation/acknowledge'),
    '/api/jobs/:jobId/reconciliation/acknowledge',
  );
  assert.equal(requestLogPath('/api/%65ncoded-private'), '/api/<unknown>');
  assert.equal(requestLogPath('/%65ncoded-private'), '<unknown-path>');
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
      'UPDATE sync_jobs SET owner_pid = ? WHERE id = ?',
    );
    // Preserve the valid boot/start identity written by createJob. A missing
    // PID is positive evidence that the original owner exited; malformed
    // identity metadata is intentionally handled as unverifiable instead.
    statement.run([2147483647, job.id]);
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

test('HTTP responses hide unknown exceptions and lifecycle logs template request paths', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  const records = [];
  const readMarker = 'private-read-exception-marker';
  const writeMarker = 'private-write-exception-marker';
  const encodedPathMarker = '%2565ncoded-route-private';
  const queryMarker = 'query-private-marker';
  const logger = {
    requestId: () => 'public-error-boundary-test',
    info(event, fields) { records.push({ event, ...fields }); },
    warn(event, fields) { records.push({ event, ...fields }); },
    error(event, fields) { records.push({ event, ...fields }); },
    probe() { return true; },
  };
  const db = {
    dbPath: '/tmp/unused-public-error-boundary.sqlite3',
    async getJob() { return null; },
    async listJobsPage() {
      const hostileError = {};
      Object.defineProperty(hostileError, 'code', {
        get() { throw new Error('MALICIOUS_READ_ERROR_CODE'); },
      });
      Object.defineProperty(hostileError, 'message', {
        get() { throw new Error(readMarker); },
      });
      throw hostileError;
    },
    async getMutationReceipt() {
      const error = new Error(writeMarker);
      error.code = 'MALICIOUS_WRITE_ERROR_CODE';
      throw error;
    },
  };
  let server;
  try {
    process.env.PANEL_WRITE_ENABLED = '1';
    process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
    server = createServer({ db, logger });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;

    assert.equal((await request(
      baseUrl,
      '/api/' + encodedPathMarker + '?credential=' + queryMarker,
    )).status, 404);
    assert.equal((await request(
      baseUrl,
      '/api/jobs/' + encodedPathMarker,
    )).status, 404);

    const readFailure = await request(baseUrl, '/api/jobs');
    assert.equal(readFailure.status, 500);
    assert.deepEqual(JSON.parse(readFailure.body), {
      error: 'internal_error',
      message: '请求处理失败，请稍后重试',
    });
    assert.equal(readFailure.body.includes(readMarker), false);
    assert.equal(readFailure.body.includes('MALICIOUS_READ_ERROR_CODE'), false);

    const writeFailure = await postJson(baseUrl, '/api/sync/import', {
      snapshotVersion: 'a'.repeat(64),
      selectedKeys: ['token:tokens:tokens/example.json'],
    });
    assert.equal(writeFailure.status, 503);
    assert.deepEqual(JSON.parse(writeFailure.body), {
      error: 'import_failed',
      message: '导入请求未能安全完成，请稍后重试',
    });
    assert.equal(writeFailure.body.includes(writeMarker), false);
    assert.equal(writeFailure.body.includes('MALICIOUS_WRITE_ERROR_CODE'), false);

    const serializedPaths = JSON.stringify(records.map((record) => record.path));
    assert.equal(serializedPaths.includes(encodedPathMarker), false);
    assert.equal(serializedPaths.includes(queryMarker), false);
    assert.ok(records.some((record) => record.path === '/api/<unknown>'));
    assert.ok(records.some((record) => record.path === '/api/jobs/:jobId'));
  } finally {
    await closeHttpServer(server);
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
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

test('listen loopback exemption requires an unbracketed numeric loopback address', () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    allowRemote: process.env.PANEL_ALLOW_INSECURE_REMOTE,
  };
  process.env.PANEL_REQUIRE_AUTH = '0';
  delete process.env.PANEL_ADMIN_TOKEN;
  delete process.env.PANEL_ALLOW_INSECURE_REMOTE;
  try {
    for (const host of ['127.0.0.1', '127.255.255.254', '::1', '0:0:0:0:0:0:0:1']) {
      assert.doesNotThrow(() => validateListenConfiguration(host));
    }
    for (const host of [
      'localhost',
      'LOCALHOST',
      '[::1]',
      '127.example.invalid',
      '::ffff:127.0.0.1',
    ]) {
      assert.throws(
        () => validateListenConfiguration(host),
        (error) => error.code === 'PANEL_REMOTE_AUTH_REQUIRED',
      );
    }

    process.env.PANEL_ADMIN_TOKEN = 'test-admin-token-123456';
    for (const host of ['localhost', '[::1]']) {
      assert.throws(
        () => validateListenConfiguration(host),
        (error) => error.code === 'PANEL_REMOTE_HTTP_CONFIRMATION_REQUIRED',
      );
    }
    process.env.PANEL_ALLOW_INSECURE_REMOTE = '1';
    assert.doesNotThrow(() => validateListenConfiguration('localhost'));
  } finally {
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.allowRemote === undefined) delete process.env.PANEL_ALLOW_INSECURE_REMOTE;
    else process.env.PANEL_ALLOW_INSECURE_REMOTE = previous.allowRemote;
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

test('tokenless loopback writes require a literal loopback Host and same-origin Origin', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  delete process.env.PANEL_ADMIN_TOKEN;
  process.env.PANEL_REQUIRE_AUTH = '0';
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let server;
  try {
    const localRequest = (host, origin, rawHeaders) => ({
      headers: {
        host,
        ...(origin === undefined ? {} : { origin }),
      },
      ...(rawHeaders === undefined ? {} : { rawHeaders }),
      socket: { remoteAddress: '127.0.0.1' },
    });
    assert.equal(authorizationError(localRequest('127.0.0.1:4170'), true), null);
    assert.equal(
      authorizationError(localRequest('[::1]:4170', 'http://[::1]:4170'), true),
      null,
    );
    assert.equal(authorizationError(localRequest('localhost:4170'), true).error,
      'write_loopback_host_required');
    assert.equal(authorizationError(localRequest('127.0.0.1:4170', 'null'), true).error,
      'write_origin_forbidden');
    assert.equal(
      authorizationError(localRequest('127.0.0.1:4170', 'http://127.0.0.2:4170'), true).error,
      'write_origin_forbidden',
    );
    assert.equal(
      authorizationError(localRequest('127.0.0.1:4170', undefined, [
        'Host', '127.0.0.1:4170', 'Host', 'attacker.example',
      ]), true).error,
      'write_loopback_host_required',
    );
    assert.equal(authorizationError({
      headers: { host: '127.0.0.1:4170' },
      socket: { remoteAddress: '198.51.100.12' },
    }, true).error, 'write_loopback_required');
    // The Host/Origin hardening is intentionally limited to tokenless writes.
    // Reads remain available in the explicitly unauthenticated configuration.
    assert.equal(authorizationError({
      headers: { host: 'attacker.example' },
      socket: { remoteAddress: '127.0.0.1' },
    }), null);

    server = createServer({
      db: { dbPath: '/tmp/unused-panel-local-origin-test.sqlite3' },
      logger: {
        requestId: () => 'local-origin-test',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const baseUrl = 'http://127.0.0.1:' + port;
    const hostileHost = await postBody(baseUrl, '/api/phase3', '{}', 'text/plain', {
      host: 'attacker.example',
      'x-forwarded-host': '127.0.0.1:' + port,
    });
    assert.equal(hostileHost.status, 403);
    assert.equal(JSON.parse(hostileHost.body).error, 'write_loopback_host_required');

    const hostileOrigin = await postBody(baseUrl, '/api/phase3', '{}', 'text/plain', {
      host: '127.0.0.1:' + port,
      origin: 'https://127.0.0.1:' + port,
      'x-forwarded-host': '127.0.0.1:' + port,
    });
    assert.equal(hostileOrigin.status, 403);
    assert.equal(JSON.parse(hostileOrigin.body).error, 'write_origin_forbidden');

    const sameOrigin = await postBody(baseUrl, '/api/phase3', '{}', 'text/plain', {
      host: '127.0.0.1:' + port,
      origin: 'http://127.0.0.1:' + port,
    });
    assert.equal(sameOrigin.status, 415);
    const cliWithoutOrigin = await postBody(baseUrl, '/api/phase3', '{}', 'text/plain', {
      host: '127.0.0.1:' + port,
    });
    assert.equal(cliWithoutOrigin.status, 415);

    process.env.PANEL_ADMIN_TOKEN = 'local-origin-test-admin-token';
    process.env.PANEL_REQUIRE_AUTH = '1';
    assert.equal(authorizationError({
      headers: {
        host: 'attacker.example',
        origin: 'https://attacker.example',
        'x-panel-token': 'local-origin-test-admin-token',
      },
      socket: { remoteAddress: '198.51.100.12' },
    }, true), null);
  } finally {
    await closeHttpServer(server);
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
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

test('all mutation routes require one strict key and replay before live validation', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  const receiptCalls = [];
  let admissions = 0;
  let server;
  const responseJobId = 'job_' + '1'.repeat(24);
  try {
    server = createServer({
      db: {
        dbPath: '/tmp/unused-panel-idempotency-replay.sqlite3',
        async getMutationReceipt(context) {
          receiptCalls.push(context);
          return {
            statusCode: 202,
            response: { jobId: responseJobId, status: 'queued' },
          };
        },
      },
      jobManager: {
        shuttingDown: false,
        activeCount: 0,
        async withAdmission() {
          admissions += 1;
          throw new Error('receipt replay must not enter admission');
        },
        async shutdown() { return { active: 0, interrupted: [] }; },
      },
      logger: {
        requestId: () => 'idempotency-route-test',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    const key = 'idem_v1_route_replay_12345678901234567890';
    const requests = [
      ['/api/sync/import', {
        snapshotVersion: 'a'.repeat(64),
        selectedKeys: ['token:tokens:tokens/missing.json'],
      }],
      ['/api/phase3', {
        accounts: [{
          email: 'missing@example.test',
          selectedKey: 'token:tokens:tokens/missing.json',
          phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
        }],
        selectedKeys: ['token:tokens:tokens/missing.json'],
      }],
      ['/api/account-tests', {
        targets: [{
          accountId: 999,
          targetRevision: 'account-test-v1.' + 'A'.repeat(43),
        }],
        modelId: 'gpt-5.6-luna',
      }],
      ['/api/tokens/expired/delete', {
        version: 'b'.repeat(64),
        confirmation: 'DELETE_EXPIRED_TOKENS',
      }],
    ];
    for (const [pathname, body] of requests) {
      const replay = await postJson(baseUrl, pathname, body, { 'idempotency-key': key });
      assert.equal(replay.status, 202, pathname);
      assert.equal(replay.headers['idempotency-replayed'], 'true');
      assert.deepEqual(JSON.parse(replay.body), { jobId: responseJobId, status: 'queued' });
    }
    assert.equal(admissions, 0);
    assert.deepEqual(receiptCalls.map((item) => item.workflow), [
      'token_import', 'phase3', 'account_test', 'token_cleanup',
    ]);
    assert.equal(receiptCalls.every((item) => /^[a-f0-9]{64}$/.test(item.requestDigest)), true);
    assert.equal(JSON.stringify(receiptCalls).includes(key), true);

    const validPhaseBody = JSON.stringify(requests[1][1]);
    const missing = await postBody(baseUrl, '/api/phase3', validPhaseBody, 'application/json');
    assert.equal(missing.status, 400);
    assert.equal(JSON.parse(missing.body).error, 'IDEMPOTENCY_KEY_REQUIRED');
    const invalid = await postBody(baseUrl, '/api/phase3', validPhaseBody, 'application/json', {
      'idempotency-key': 'short',
    });
    assert.equal(invalid.status, 400);
    assert.equal(JSON.parse(invalid.body).error, 'IDEMPOTENCY_KEY_INVALID');
    const duplicate = await postBody(baseUrl, '/api/phase3', validPhaseBody, 'application/json', {
      'idempotency-key': [key, key],
    });
    assert.equal(duplicate.status, 400);
    assert.equal(JSON.parse(duplicate.body).error, 'IDEMPOTENCY_KEY_INVALID');
  } finally {
    await closeHttpServer(server);
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('the locked receipt recheck wins before every mutable live validator', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  const receiptCalls = new Map();
  const liveCalls = { phase3: 0, accountTest: 0, cleanup: 0, create: 0 };
  let admissions = 0;
  let server;
  const responseJobId = 'job_' + '2'.repeat(24);
  try {
    server = createServer({
      db: {
        dbPath: '/tmp/unused-panel-idempotency-locked-replay.sqlite3',
        async getMutationReceipt(context) {
          const calls = (receiptCalls.get(context.workflow) || 0) + 1;
          receiptCalls.set(context.workflow, calls);
          if (calls === 1) return null;
          return {
            statusCode: 202,
            response: { jobId: responseJobId, status: 'queued' },
          };
        },
        async createMutationSubmission() {
          liveCalls.create += 1;
          throw new Error('job creation must not follow a locked receipt replay');
        },
      },
      phase3RequestResolver() {
        liveCalls.phase3 += 1;
        throw new Error('Phase3 live resolution must not run after a locked replay');
      },
      accountTestClientFactory() {
        liveCalls.accountTest += 1;
        throw new Error('Sub2API live read must not run after a locked replay');
      },
      expiredTokenLister() {
        liveCalls.cleanup += 1;
        throw new Error('expired-token scan must not run after a locked replay');
      },
      jobManager: {
        shuttingDown: false,
        activeCount: 0,
        async withAdmission(callback) {
          admissions += 1;
          return callback(new AbortController().signal);
        },
        begin() { throw new Error('worker must not start after a locked receipt replay'); },
        async shutdown() { return { active: 0, interrupted: [] }; },
      },
      logger: {
        requestId: () => 'idempotency-locked-replay-test',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    const requests = [
      ['/api/sync/import', {
        snapshotVersion: 'a'.repeat(64),
        selectedKeys: ['token:tokens:tokens/not-present.json'],
      }],
      ['/api/phase3', {
        accounts: [{
          email: 'not-present@example.test',
          selectedKey: 'token:tokens:tokens/not-present.json',
          phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
        }],
        selectedKeys: ['token:tokens:tokens/not-present.json'],
      }],
      ['/api/account-tests', {
        targets: [{
          accountId: 999,
          targetRevision: 'account-test-v1.' + 'A'.repeat(43),
        }],
        modelId: 'gpt-5.6-luna',
      }],
      ['/api/tokens/expired/delete', {
        version: 'b'.repeat(64),
        confirmation: 'DELETE_EXPIRED_TOKENS',
      }],
    ];
    for (const [index, [pathname, body]] of requests.entries()) {
      const replay = await postJson(baseUrl, pathname, body, {
        'idempotency-key': 'idem_v1_locked_replay_' + String(index).padStart(24, '0'),
      });
      assert.equal(replay.status, 202, pathname);
      assert.equal(replay.headers['idempotency-replayed'], 'true');
      assert.deepEqual(JSON.parse(replay.body), { jobId: responseJobId, status: 'queued' });
    }
    assert.equal(admissions, 4);
    assert.deepEqual(Object.fromEntries(receiptCalls), {
      token_import: 2,
      phase3: 2,
      account_test: 2,
      token_cleanup: 2,
    });
    assert.deepEqual(liveCalls, { phase3: 0, accountTest: 0, cleanup: 0, create: 0 });
  } finally {
    await closeHttpServer(server);
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('concurrent requests that both miss initially create and dispatch only once', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  const job = {
    id: 'job_' + '3'.repeat(24),
    type: 'token_import',
    status: 'queued',
    requestedBy: 'anonymous',
    createdAt: new Date().toISOString(),
  };
  const receipt = { statusCode: 202, response: { jobId: job.id, status: 'queued' } };
  let lookupCalls = 0;
  let initialLookups = 0;
  let releaseInitialLookups;
  const bothInitialLookups = new Promise((resolve) => { releaseInitialLookups = resolve; });
  let committedReceipt = null;
  let creates = 0;
  let begins = 0;
  let server;
  try {
    server = createServer({
      db: {
        dbPath: '/tmp/unused-panel-idempotency-concurrent-route.sqlite3',
        async getMutationReceipt() {
          lookupCalls += 1;
          if (initialLookups < 2) {
            initialLookups += 1;
            if (initialLookups === 2) releaseInitialLookups();
            await bothInitialLookups;
            return null;
          }
          return committedReceipt;
        },
        async createMutationSubmission() {
          creates += 1;
          committedReceipt = receipt;
          return {
            receipt,
            replayed: false,
            createdJobs: [{ job }],
            rejections: [],
          };
        },
        async updateJob() { return { applied: true }; },
        async audit() {},
      },
      jobManager: {
        shuttingDown: false,
        activeCount: 0,
        async withAdmission(callback) { return callback(new AbortController().signal); },
        begin() {
          begins += 1;
          const controller = new AbortController();
          controller.abort();
          return { controller };
        },
        track(record, observation) {
          const tracked = Promise.resolve(observation);
          tracked.catch(() => {});
          record.promise = tracked;
          return tracked;
        },
        async shutdown() { return { active: 0, interrupted: [] }; },
      },
      logger: {
        requestId: () => 'idempotency-concurrent-route-test',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    const body = {
      snapshotVersion: 'a'.repeat(64),
      selectedKeys: ['token:tokens:tokens/concurrent.json'],
    };
    const key = 'idem_v1_concurrent_route_123456789012345';
    const responses = await Promise.all([
      postJson(baseUrl, '/api/sync/import', body, { 'idempotency-key': key }),
      postJson(baseUrl, '/api/sync/import', body, { 'idempotency-key': key }),
    ]);
    assert.equal(initialLookups, 2);
    assert.equal(lookupCalls, 4);
    assert.equal(creates, 1);
    assert.equal(begins, 1);
    assert.equal(responses.every((item) => item.status === 202), true);
    assert.equal(responses[0].body, responses[1].body);
    assert.deepEqual(
      responses.map((item) => item.headers['idempotency-replayed']).sort(),
      ['false', 'true'],
    );
  } finally {
    releaseInitialLookups?.();
    await closeHttpServer(server);
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

test('a completed cleanup replays its original 202 without rescanning or starting another worker', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-replay-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify({
    access_token: 'expired-placeholder',
    email: 'replay@example.test',
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
  const db = new PanelDb(path.join(root, 'panel.sqlite3'));
  let server;
  try {
    const listing = listExpiredTokens();
    const requestBody = {
      version: listing.version,
      confirmation: 'DELETE_EXPIRED_TOKENS',
    };
    const key = 'idem_v1_cleanup_replay_12345678901234567';
    server = createServer({
      db,
      logger: {
        requestId: () => 'cleanup-replay-test',
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
    const first = await postJson(baseUrl, '/api/tokens/expired/delete', requestBody, {
      'idempotency-key': key,
    });
    assert.equal(first.status, 202);
    assert.equal(first.headers['idempotency-replayed'], 'false');
    const firstBody = JSON.parse(first.body);
    const terminal = await waitForTerminalJob(baseUrl, firstBody.jobId);
    assert.equal(terminal.status, 'succeeded');

    const replay = await postJson(baseUrl, '/api/tokens/expired/delete', requestBody, {
      'idempotency-key': key,
    });
    assert.equal(replay.status, 202);
    assert.equal(replay.headers['idempotency-replayed'], 'true');
    assert.equal(replay.body, first.body);
    assert.equal((await db.listJobs()).filter((job) => job.type === 'token_cleanup').length, 1);

    const changed = await postJson(baseUrl, '/api/tokens/expired/delete', {
      ...requestBody,
      version: 'c'.repeat(64),
    }, { 'idempotency-key': key });
    assert.equal(changed.status, 409);
    assert.equal(JSON.parse(changed.body).error, 'IDEMPOTENCY_KEY_REUSED');
    assert.equal((await db.listJobs()).filter((job) => job.type === 'token_cleanup').length, 1);
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

function postJson(baseUrl, pathname, body, extraHeaders = {}) {
  const mutationPath = ['/api/sync/import', '/api/phase3', '/api/account-tests',
    '/api/tokens/expired/delete'].includes(pathname);
  return new Promise((resolve, reject) => {
    const requestObject = http.request(baseUrl + pathname, {
      method: 'POST',
      headers: {
        ...(configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {}),
        'content-type': 'application/json',
        ...(mutationPath ? { 'idempotency-key': 'test-idem-' + crypto.randomUUID() } : {}),
        ...extraHeaders,
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: responseBody,
      }));
    });
    requestObject.on('error', reject);
    requestObject.end(JSON.stringify(body));
  });
}

function postBody(baseUrl, pathname, body, contentType, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const requestObject = http.request(baseUrl + pathname, {
      method: 'POST',
      headers: {
        ...(configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {}),
        ...(contentType ? { 'content-type': contentType } : {}),
        ...extraHeaders,
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
    assert.deepEqual(phase3ClaimKeys({
      email: 'canonical@example.test',
      phone: '15550000002',
      canonicalKeys: [
        'phone:15550000002',
        'email:canonical@example.test',
      ],
    }), expected);
    assert.throws(
      () => phase3ClaimKeys({
        email: 'canonical@example.test',
        canonicalKeys: ['email:canonical@example.test'],
      }),
      (error) => error.code === 'PHASE3_CANONICAL_KEYS_INVALID',
    );
    assert.throws(
      () => phase3ClaimKeys({
        email: 'canonical@example.test',
        canonicalKeys: [
          'email:canonical@example.test',
          'phone:19999999999',
        ],
      }),
      (error) => error.code === 'PHASE3_CANONICAL_KEYS_INVALID',
    );
    assert.throws(
      () => phase3ClaimKeys({
        email: 'canonical@example.test',
        phone: '1555letters0002',
      }),
      (error) => error.code === 'PHASE3_IDENTITY_INVALID',
    );
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
    const snapshotRows = JSON.parse(snapshot.body).rows;
    const phase3RevisionFor = (relativePath) => snapshotRows.find(
      (row) => row.relativePath === relativePath,
    )?.phase3TargetRevision;

    fs.renameSync(path.join(root, 'use_token'), path.join(root, 'use_token-missing'));
    const incompleteSourcePreview = await postJson(baseUrl, '/api/sync/preview', {
      selectedKeys: [],
    });
    assert.equal(incompleteSourcePreview.status, 503);
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

    const selectedTokenKey = 'token:tokens:tokens/token.json';
    const currentPhase3Revision = phase3RevisionFor('tokens/token.json');
    const forgedPhase3Revision = currentPhase3Revision.slice(0, -1)
      + (currentPhase3Revision.endsWith('A') ? 'B' : 'A');
    const forgedPhase3 = await postJson(baseUrl, '/api/phase3', {
      accounts: [{
        email: 'server@example.test',
        selectedKey: selectedTokenKey,
        phase3TargetRevision: forgedPhase3Revision,
      }],
      selectedKeys: [selectedTokenKey],
    });
    assert.equal(forgedPhase3.status, 409);
    const forgedPhase3Body = JSON.parse(forgedPhase3.body);
    assert.deepEqual(forgedPhase3Body.jobIds, []);
    assert.equal(forgedPhase3Body.rejected[0].error, 'phase3_target_revision_changed');

    const batchPhase3 = await postJson(baseUrl, '/api/phase3', {
      accounts: [
        {
          email: 'server@example.test',
          selectedKey: 'token:tokens:tokens/token.json',
          phase3TargetRevision: phase3RevisionFor('tokens/token.json'),
        },
        {
          phone: '15550000001',
          selectedKey: 'token:tokens:tokens/token-duplicate.json',
          phase3TargetRevision: phase3RevisionFor('tokens/token-duplicate.json'),
        },
        {
          email: 'second@example.test',
          selectedKey: 'token:tokens:tokens/second.json',
          phase3TargetRevision: phase3RevisionFor('tokens/second.json'),
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
    assert.equal(expiredBody.recoveryRequired, false);
    assert.equal(expiredBody.claimCount, 0);
    assert.equal(expiredBody.claimCountTruncated, false);
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

test('token cleanup never recovers a claim from a stale ordinary delete and reports recovery required', async () => {
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
    const createMutationSubmission = db.createMutationSubmission.bind(db);
    let injected = false;
    let injectedClaimPath = null;
    let cleanupJobCreates = 0;
    db.createMutationSubmission = async (options) => {
      const isCleanup = options?.jobs?.some((item) => item?.type === 'token_cleanup');
      if (isCleanup) cleanupJobCreates += 1;
      const submission = await createMutationSubmission(options);
      if (!injected && isCleanup && !submission.replayed) {
        injected = true;
        const contentHash = crypto.createHash('sha256').update(sourceContent).digest('hex');
        const encodedName = Buffer.from(path.basename(sourcePath), 'utf8').toString('base64url');
        const claimPath = path.join(
          path.dirname(sourcePath),
          '.panel-token-cleanup-claim-v1-999999-0-' + contentHash + '-'
            + encodedName + '-0123456789abcdef',
        );
        fs.renameSync(sourcePath, claimPath);
        injectedClaimPath = claimPath;
        fs.writeFileSync(path.join(root, 'use_token', 'new-expired.json'), JSON.stringify({
          access_token: 'second-expired-access',
          email: 'second-boundary@example.test',
          expired: '2020-01-01T00:00:00.000Z',
        }), { mode: 0o600 });
      }
      return submission;
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
    assert.equal(job.result.code, 'TOKEN_CLEANUP_STALE');
    assert.equal(job.result.requiresReconciliation, undefined);
    assert.equal(job.result.reconciliationHold, undefined);
    assert.equal(fs.existsSync(sourcePath), false);
    assert.equal(fs.existsSync(injectedClaimPath), true);
    assert.equal(fs.existsSync(path.join(root, 'use_token', 'new-expired.json')), true);
    assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
    const recoveryScan = await request(baseUrl, '/api/tokens/expired');
    assert.equal(recoveryScan.status, 200);
    const recoveryBody = JSON.parse(recoveryScan.body);
    assert.equal(recoveryBody.recoveryRequired, true);
    assert.equal(recoveryBody.claimCount, 1);
    assert.equal(recoveryBody.claimCountTruncated, false);
    assert.equal(recoveryScan.body.includes(path.basename(injectedClaimPath)), false);
    const blocked = await postJson(baseUrl, '/api/tokens/expired/delete', {
      version: recoveryBody.version,
      confirmation: 'DELETE_EXPIRED_TOKENS',
    });
    assert.equal(blocked.status, 409);
    const blockedBody = JSON.parse(blocked.body);
    assert.equal(blockedBody.error, 'TOKEN_CLEANUP_RECOVERY_REQUIRED');
    assert.equal(blockedBody.recoveryRequired, true);
    assert.equal(blockedBody.claimCount, 1);
    assert.equal(blockedBody.claimCountTruncated, false);
    assert.equal(cleanupJobCreates, 1);
    assert.equal(fs.existsSync(sourcePath), false);
    assert.equal(fs.existsSync(injectedClaimPath), true);
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
        async getMutationReceipt() { return null; },
        async createMutationSubmission() { throw new Error('unexpected task creation'); },
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
