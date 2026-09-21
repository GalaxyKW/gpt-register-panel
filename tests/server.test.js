const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
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
  hasJsonContentType,
  openVerifiedStaticFile,
  parseRequestTarget,
  phase3ClaimKeys,
  phase3FailureMetadata,
  mutationFailureMetadata,
  normalizedSelectedKeys,
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
const {
  PHASE3_RECONCILIATION_REASON,
  PHASE3_RECONCILIATION_SCOPE,
} = require('../backend/phase3Worker');
const { listExpiredTokens } = require('../backend/tokenCleanup');
const { PanelDb } = require('../backend/db');
const { withControlPlaneLock } = require('../backend/taskCoordinator');
const configuredPanelToken = process.env.PANEL_ADMIN_TOKEN || '';
const validImportPlanIntentVersion = 'sync-plan-v1.' + 'A'.repeat(43);

test('static routing exposes only the three declared frontend assets', () => {
  assert.equal(path.basename(safeStaticPath('/')), 'index.html');
  assert.equal(path.basename(safeStaticPath('/app.js')), 'app.js');
  assert.equal(path.basename(safeStaticPath('/styles.css')), 'styles.css');
  assert.equal(safeStaticPath('/debug.json'), null);
  assert.equal(safeStaticPath('/nested/asset.js'), null);
});

test('sync selectedKeys validation is exact and never trims or deduplicates input', () => {
  const key = 'token:tokens:tokens/example.json';
  assert.deepEqual(normalizedSelectedKeys([key]), [key]);
  assert.deepEqual(normalizedSelectedKeys([], { allowEmpty: true }), []);
  for (const invalid of [
    [],
    [' ' + key],
    [key + ' '],
    ['', key],
    [key, key],
  ]) {
    assert.equal(normalizedSelectedKeys(invalid), null);
  }
  assert.equal(normalizedSelectedKeys([''], { allowEmpty: true }), null);
});

test('public API errors expose only fixed codes, messages, and statuses', () => {
  const mappings = new Map([
    [400, [
      'INVALID_JSON_BODY',
      'INVALID_REQUEST_BODY',
      'INVALID_REQUEST_TARGET',
      'IDEMPOTENCY_KEY_REQUIRED',
      'IDEMPOTENCY_KEY_INVALID',
      'SNAPSHOT_VERSION_REQUIRED',
      'IMPORT_PLAN_VERSION_REQUIRED',
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
      'JOB_RECONCILIATION_CONTEXT_DIGEST_INVALID',
    ]],
    [403, [
      'JOB_RECONCILIATION_ADMIN_REQUIRED',
      'PHASE3_DISABLED',
      'WRITE_DISABLED',
    ]],
    [404, ['JOB_RECONCILIATION_NOT_FOUND']],
    [409, [
      'IDEMPOTENCY_KEY_REUSED',
      'IMPORT_PLAN_STALE',
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
      'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT',
      'JOB_RECONCILIATION_NOT_HELD',
      'JOB_RECONCILIATION_ACK_CONFLICT',
      'JOB_RECONCILIATION_DIGEST_MISMATCH',
      'JOB_RECONCILIATION_CONTEXT_DIGEST_MISMATCH',
      'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
      'JOB_RECONCILIATION_CONTEXT_INCOMPLETE',
    ]],
    [413, ['REQUEST_BODY_TOO_LARGE']],
    [502, [
      'SUB2API_READ_FAILED',
      'SUB2API_ACCOUNTS_TOTAL_REQUIRED',
      'SUB2API_ACCOUNTS_PAGINATION_REQUIRED',
      'SUB2API_ACCOUNTS_PAGINATION_INVALID',
      'SUB2API_GROUP_RESOLVE_FAILED',
      'SUB2API_GROUP_NOT_FOUND',
      'SUB2API_GROUP_AMBIGUOUS',
      'SUB2API_GROUP_NOT_ACTIVE',
      'SUB2API_GROUP_PLATFORM_MISMATCH',
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
      'GPT_REGISTER_PATH_INVALID',
      'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
      'GPT_REGISTER_FILE_TOO_LARGE',
      'GPT_REGISTER_SOURCE_LIMIT',
      'GPT_REGISTER_SOURCE_MISSING',
      'GPT_REGISTER_SOURCE_INCOMPLETE',
      'GPT_REGISTER_SOURCE_CHANGED',
      'GPT_REGISTER_USERNAME_INVALID',
      'GPT_REGISTER_USERNAME_RECORD_LIMIT',
      'SUB2API_GROUP_CONFIG_INVALID',
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
  let hostileVersionReads = 0;
  Object.defineProperty(hostileVersion, 'currentVersion', {
    get() {
      hostileVersionReads += 1;
      return hostileVersionReads < 3 ? currentVersion : 'private-version-getter-marker';
    },
  });
  assert.deepEqual(publicTokenCleanupErrorFields('TOKEN_CLEANUP_STALE', hostileVersion), {});
  assert.equal(hostileVersionReads, 0);
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
  assert.deepEqual(publicTokenCleanupErrorFields('TOKEN_CLEANUP_CLAIM_SCAN_LIMIT', {
    recoveryRequired: true,
  }), {
    recoveryRequired: true,
    claimCount: 0,
    claimCountTruncated: false,
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

test('request targets reject forms that can be normalized onto a different route', () => {
  const jobId = 'job_' + 'a'.repeat(24);
  for (const [target, pathname, query] of [
    ['/', '/', ''],
    ['/api/health', '/api/health', ''],
    ['/api/snapshot?withSub2api=1&search=a%2Fb', '/api/snapshot', 'withSub2api=1&search=a%2Fb'],
    ['/api/jobs/' + jobId, '/api/jobs/' + jobId, ''],
    ['/%E8%B4%A6%E5%8F%B7?q=%E6%B5%8B%E8%AF%95', '/%E8%B4%A6%E5%8F%B7',
      'q=%E6%B5%8B%E8%AF%95'],
    ['/api/snapshot?literal=%252e%252e', '/api/snapshot', 'literal=%252e%252e'],
  ]) {
    const parsed = parseRequestTarget(target);
    assert.equal(parsed.pathname, pathname, target);
    assert.equal(parsed.search.slice(1), query, target);
  }

  for (const target of [
    '',
    '*',
    'http://attacker.invalid/api/phase3',
    '//attacker.invalid/api/phase3',
    '/api//phase3',
    '/api\\phase3',
    '/api/./phase3',
    '/api/ignored/../phase3',
    '/api/%2e/phase3',
    '/api/%2E%2E/api/phase3',
    '/api/%252e%252e/api/phase3',
    '/api/%25252e%25252e/api/phase3',
    '/api/%2fphase3',
    '/api/%255cphase3',
    '/api/phase3#fragment',
    '/api/%00phase3',
    '/api/%ZZphase3',
    '/api/phase3?bad=%',
    '/api/phase3?bad=%0d%0aInjected',
    '/api/phase3?bad=%c2%80',
  ]) {
    assert.throws(
      () => parseRequestTarget(target),
      (error) => error?.code === 'INVALID_REQUEST_TARGET'
        && error.message === '请求目标必须是无歧义的 origin-form',
      target,
    );
  }
});

test('HTTP routing rejects ambiguous raw targets before audit or business dispatch', async () => {
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
  let probes = 0;
  let businessCalls = 0;
  const server = createServer({
    db: {
      dbPath: '/tmp/unused-request-target-test.sqlite3',
      async getMutationReceipt() { businessCalls += 1; return null; },
    },
    logger: {
      requestId: () => 'request-target-test',
      info() {},
      warn() {},
      error() {},
      probe() { probes += 1; return true; },
    },
  });
  const issue = (target, method = 'GET') => new Promise((resolve, reject) => {
    const requestObject = http.request({
      host: '127.0.0.1',
      port: server.address().port,
      path: target,
      method,
      headers: method === 'POST' ? { 'content-type': 'application/json' } : {},
    }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body }));
    });
    requestObject.on('error', reject);
    requestObject.end(method === 'POST' ? '{}' : undefined);
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    for (const response of [
      await issue('//attacker.invalid/api/health'),
      await issue('/api//phase3', 'POST'),
      await issue('/api/ignored/../phase3', 'POST'),
    ]) {
      assert.equal(response.status, 400);
      assert.equal(JSON.parse(response.body).error, 'INVALID_REQUEST_TARGET');
    }
    assert.equal(probes, 0);
    assert.equal(businessCalls, 0);
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

  let hostileReads = 0;
  const hostile = {};
  for (const key of [
    'code',
    'accountDisposition',
    'requiresReconciliation',
    'writeOutcomeUnknown',
    'doNotRetry',
    'retryAllowed',
    'reconciliationScope',
    'reconciliationReason',
    'dispositionPersisted',
    'dispositionOutcome',
    'dispositionWriteOutcomeUnknown',
    'dispositionCode',
    'dispositionErrorCode',
  ]) {
    Object.defineProperty(hostile, key, {
      get() {
        hostileReads += 1;
        return 'credential-hostile-phase3-marker';
      },
    });
  }
  assert.deepEqual(phase3FailureMetadata(hostile), {
    code: null,
    accountDisposition: null,
  });
  assert.equal(hostileReads, 0);

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

  assert.deepEqual(phase3FailureMetadata({
    code: 'PHASE3_TOKEN_IDENTITY_MISMATCH',
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationScope: 'phase3_token_output',
    reconciliationReason: 'phase3_token_identity_mismatch',
  }), {
    code: 'PHASE3_TOKEN_IDENTITY_MISMATCH',
    accountDisposition: null,
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    doNotRetry: true,
    retryAllowed: false,
    reconciliationScope: 'phase3_token_output',
    reconciliationReason: 'phase3_token_identity_mismatch',
  });
});

test('Phase3 worker and terminal persistence share every reconciliation value', () => {
  assert.equal(Object.isFrozen(PHASE3_RECONCILIATION_SCOPE), true);
  assert.equal(Object.isFrozen(PHASE3_RECONCILIATION_REASON), true);
  for (const reconciliationScope of Object.values(PHASE3_RECONCILIATION_SCOPE)) {
    assert.deepEqual(phase3FailureMetadata({ reconciliationScope }), {
      code: null,
      accountDisposition: null,
      reconciliationScope,
    });
  }
  for (const reconciliationReason of Object.values(PHASE3_RECONCILIATION_REASON)) {
    assert.deepEqual(phase3FailureMetadata({ reconciliationReason }), {
      code: null,
      accountDisposition: null,
      reconciliationReason,
    });
  }
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

  let hostileReads = 0;
  const hostile = {};
  for (const key of [
    'code',
    'requiresReconciliation',
    'writeOutcomeUnknown',
    'doNotRetry',
    'retryAllowed',
    'blockedBeforeStart',
    'executionOutcome',
    'reconciliationReason',
    'criticalSectionCompleted',
    'controlPlaneLeaseReleaseFailed',
  ]) {
    Object.defineProperty(hostile, key, {
      get() {
        hostileReads += 1;
        return 'credential-hostile-mutation-marker';
      },
    });
  }
  assert.deepEqual(mutationFailureMetadata(hostile), { code: null });
  assert.equal(hostileReads, 0);
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
      accessFingerprint: 'c'.repeat(16),
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
    accessFingerprint: 'c'.repeat(16),
  });
  await assert.rejects(
    restarted.createJob('token_cleanup', {}, 'panel-admin', {
      claimKeys: ['token_cleanup:expired_tokens'],
    }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === job.id,
  );
});

test('reconciliation review never coerces ambiguous stored account IDs', () => {
  const digest = 'c'.repeat(64);
  assert.throws(
    () => reconciliationReviewDetail({
      id: 'job_' + 'd'.repeat(24),
      type: 'account_test',
      status: 'failed',
      payload: {
        accountIds: ['01', '1e0', '2', 3],
        targetBaselines: [
          { accountId: '01', identityDigest: '1'.repeat(64) },
          { accountId: '1e0', identityDigest: '2'.repeat(64) },
          { accountId: '2', identityDigest: '3'.repeat(64) },
          { accountId: 3, identityDigest: '4'.repeat(64) },
        ],
      },
      result: {
        requiresReconciliation: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: digest,
        results: [],
      },
    }),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
  );
});

test('reconciliation review rejects a partial token-import target set', () => {
  assert.throws(
    () => reconciliationReviewDetail({
      id: 'job_' + 'a'.repeat(24),
      type: 'token_import',
      status: 'failed',
      payload: { selectedSourcePaths: ['tokens/first.json', 'tokens/second.json'] },
      result: {
        requiresReconciliation: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: 'b'.repeat(64),
        reconciliationCount: 2,
        imported: [{
          source: 'tokens',
          relativePath: 'first.json',
          action: 'create',
          accountName: 'free00001',
          fingerprints: { access: 'a'.repeat(16) },
          sourceIdentityKeys: ['account:strong-one'],
          requiresReconciliation: true,
        }, {
          source: 'tokens',
          relativePath: 'second.json',
          action: 'update',
          fingerprints: { access: 'b'.repeat(16) },
          sourceIdentityKeys: ['account:strong-two'],
          requiresReconciliation: true,
        }],
      },
    }),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
  );
});

test('reconciliation review enforces the exact token-import producer matrix', () => {
  const baseItem = {
    source: 'tokens',
    relativePath: 'new-account.json',
    accountId: null,
    accountName: 'free00001',
    email: '',
    action: 'create',
    fingerprints: { access: 'a'.repeat(16) },
    sourceIdentityKeys: [
      'account:11111111-1111-4111-8111-111111111111',
    ],
    availability: 'not_present',
    availabilityReason: 'not_in_sub2api',
    requiresReconciliation: true,
  };
  const review = (item) => reconciliationReviewDetail({
    id: 'job_' + 'a'.repeat(24),
    type: 'token_import',
    status: 'failed',
    payload: {},
    result: {
      requiresReconciliation: true,
      reconciliationHold: true,
      reconciliationResolved: false,
      reconciliationClaimDigest: 'b'.repeat(64),
      reconciliationCount: 1,
      imported: [item],
    },
  });
  const detail = review(baseItem);
  assert.deepEqual(detail.targetContext.targets[0], {
    sourcePath: 'tokens/new-account.json',
    remoteAccountId: undefined,
    accountName: 'free00001',
    email: undefined,
    action: 'create',
    accessFingerprint: 'a'.repeat(16),
    strongIdentityKeys: ['account:11111111-1111-4111-8111-111111111111'],
    availability: 'not_present',
    availabilityReason: 'not_in_sub2api',
  });

  const updateItem = {
    ...baseItem,
    relativePath: 'existing-account.json',
    accountId: 266,
    accountName: '',
    action: 'update',
    availability: 'unavailable',
    availabilityReason: 'sub2api_status_error',
  };
  assert.equal(review(updateItem).targetContext.targets[0].remoteAccountId, 266);

  const invalidItems = [
    { ...baseItem, accountId: 266 },
    { ...baseItem, availability: 'unknown', availabilityReason: 'panel_clock_invalid' },
    { ...updateItem, accountId: '266' },
    { ...updateItem, availability: 'available', availabilityReason: 'sub2api_available' },
    { ...updateItem, availabilityReason: 'sub2api_expiry_invalid' },
    { ...baseItem, sourceIdentityKeys: ['account:one', 'account:two'] },
    { ...baseItem, sourceIdentityKeys: ['account:one', 'credential:ignored-before'] },
    { ...baseItem, sourceIdentityKeys: ['account:[redacted]'] },
    {
      ...baseItem,
      email: 'first@example.test',
      sourceIdentityKeys: ['account:one', 'email:second@example.test'],
    },
    { ...baseItem, relativePath: '[redacted].json' },
    { ...baseItem, relativePath: '[unsupported].json' },
    { ...baseItem, accountName: '[redaction limit reached]' },
    { ...baseItem, sourceIdentityKeys: ['account:[circular]'] },
    { ...baseItem, relativePath: 'vis\u00adible.json' },
    { ...baseItem, sourceIdentityKeys: ['account:visible\u061cvalue'] },
    { ...baseItem, accountName: 'free00001\ufe0f' },
  ];
  for (const item of invalidItems) {
    assert.throws(
      () => review(item),
      (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
    );
  }
});

test('reconciliation review requires the complete account-test result identity set', () => {
  assert.throws(() => reconciliationReviewDetail({
    id: 'job_' + 'c'.repeat(24),
    type: 'account_test',
    status: 'failed',
    payload: {
      accountIds: [1, 2],
      targetBaselines: [1, 2].map((accountId) => ({
        accountId,
        identityDigest: String(accountId).repeat(64),
        targetDigest: String(accountId + 2).repeat(64),
        status: 'inactive',
        statusKnown: true,
        schedulable: false,
        schedulableKnown: true,
      })),
    },
    result: {
      requiresReconciliation: true,
      reconciliationHold: true,
      reconciliationResolved: false,
      reconciliationClaimDigest: 'd'.repeat(64),
      reconciliationCount: 1,
      results: [{ accountId: 1, requiresReconciliation: true }],
    },
  }), (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE');
});

test('reconciliation review rejects selected paths without strong import evidence', () => {
  assert.throws(
    () => reconciliationReviewDetail({
      id: 'job_' + 'f'.repeat(24),
      type: 'token_import',
      status: 'interrupted',
      payload: { selectedSourcePaths: ['tokens/legacy.json'] },
      result: {
        requiresReconciliation: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: '1'.repeat(64),
      },
    }),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
  );
});

test('reconciliation review requires a complete Phase3 target revision', () => {
  assert.throws(
    () => reconciliationReviewDetail({
      id: 'job_' + '2'.repeat(24),
      type: 'phase3',
      status: 'failed',
      payload: {
        email: 'phase3@example.test',
        phone: null,
        canonicalKeys: ['email:phase3@example.test'],
        sourcePath: 'tokens/phase3.json',
      },
      result: {
        requiresReconciliation: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: '3'.repeat(64),
      },
    }),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
  );
});

test('reconciliation review binds a Phase3 source path to its selected key', () => {
  const selectedKeyDigest = crypto.createHash('sha256')
    .update('gpt-register-panel/phase3-selected-key/v1\0')
    .update('token:tokens:tokens/other.json')
    .digest('hex');
  assert.throws(
    () => reconciliationReviewDetail({
      id: 'job_' + '9'.repeat(24),
      type: 'phase3',
      status: 'failed',
      payload: {
        email: 'phase3@example.test',
        phone: null,
        canonicalKeys: ['email:phase3@example.test'],
        sourcePath: 'tokens/phase3.json',
        selectedKeyDigest,
        phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
      },
      result: {
        requiresReconciliation: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: 'a'.repeat(64),
      },
    }),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
  );
});

test('reconciliation review requires the persisted Phase3 canonical-key order', () => {
  const selectedKey = 'token:tokens:tokens/phase3.json';
  const selectedKeyDigest = crypto.createHash('sha256')
    .update('gpt-register-panel/phase3-selected-key/v1\0')
    .update(selectedKey)
    .digest('hex');
  assert.throws(
    () => reconciliationReviewDetail({
      id: 'job_' + '7'.repeat(24),
      type: 'phase3',
      status: 'failed',
      payload: {
        email: 'phase3@example.test',
        phone: '15550000002',
        canonicalKeys: [
          'phone:15550000002',
          'email:phase3@example.test',
        ],
        sourcePath: 'tokens/phase3.json',
        selectedKeyDigest,
        phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
      },
      result: {
        requiresReconciliation: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: '7'.repeat(64),
      },
    }),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
  );
});

test('reconciliation review rejects duplicate token-cleanup targets', () => {
  assert.throws(
    () => reconciliationReviewDetail({
      id: 'job_' + '4'.repeat(24),
      type: 'token_cleanup',
      status: 'failed',
      payload: {
        expectedVersion: '5'.repeat(64),
        targetCount: 2,
        reviewTargetsTruncated: false,
        reviewTargets: [{
          sourcePath: 'tokens/expired.json',
          contentHash: '6'.repeat(64),
          accessFingerprint: 'a'.repeat(16),
        }, {
          sourcePath: 'tokens/expired.json',
          contentHash: '7'.repeat(64),
          accessFingerprint: 'b'.repeat(16),
        }],
      },
      result: {
        requiresReconciliation: true,
        reconciliationHold: true,
        reconciliationResolved: false,
        reconciliationClaimDigest: '8'.repeat(64),
      },
    }),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
  );
});

test('reconciliation review requires an exact cleanup access fingerprint', () => {
  const review = (accessFingerprint) => reconciliationReviewDetail({
    id: 'job_' + '5'.repeat(24),
    type: 'token_cleanup',
    status: 'failed',
    payload: {
      expectedVersion: '6'.repeat(64),
      targetCount: 1,
      reviewTargetsTruncated: false,
      reviewTargets: [{
        sourcePath: 'tokens/expired.json',
        contentHash: '7'.repeat(64),
        ...(accessFingerprint === undefined ? {} : { accessFingerprint }),
      }],
    },
    result: {
      requiresReconciliation: true,
      reconciliationHold: true,
      reconciliationResolved: false,
      reconciliationClaimDigest: '8'.repeat(64),
    },
  });
  assert.equal(review('9'.repeat(16)).targetContext.targets[1].accessFingerprint,
    '9'.repeat(16));
  for (const value of [undefined, '9'.repeat(15), '9'.repeat(17), 'A'.repeat(16)]) {
    assert.throws(
      () => review(value),
      (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
    );
  }
});

test('reconciliation review rejects redacted Phase3 identity placeholders', () => {
  const selectedKey = 'token:tokens:tokens/phase3.json';
  const selectedKeyDigest = crypto.createHash('sha256')
    .update('gpt-register-panel/phase3-selected-key/v1\0')
    .update(selectedKey)
    .digest('hex');
  assert.throws(() => reconciliationReviewDetail({
    id: 'job_' + '9'.repeat(24),
    type: 'phase3',
    status: 'failed',
    payload: {
      email: '[redacted]@example.test',
      phone: null,
      canonicalKeys: ['email:[redacted]@example.test'],
      sourcePath: 'tokens/phase3.json',
      selectedKeyDigest,
      phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
    },
    result: {
      requiresReconciliation: true,
      reconciliationHold: true,
      reconciliationResolved: false,
      reconciliationClaimDigest: 'a'.repeat(64),
    },
  }), (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE');
});

test('reconciliation review rejects impossible create availability metadata', () => {
  assert.throws(() => reconciliationReviewDetail({
    id: 'job_' + 'e'.repeat(24),
    type: 'token_import',
    status: 'failed',
    payload: {},
    result: {
      requiresReconciliation: true,
      reconciliationHold: true,
      reconciliationResolved: false,
      reconciliationClaimDigest: 'f'.repeat(64),
      reconciliationCount: 1,
      imported: [{
        source: 'tokens',
        relativePath: 'clock-invalid.json',
        action: 'create',
        accountId: null,
        accountName: 'free00001',
        fingerprints: { access: 'a'.repeat(16) },
        sourceIdentityKeys: ['account:clock-account'],
        availability: 'unknown',
        availabilityReason: 'panel_clock_invalid',
        requiresReconciliation: true,
      }],
    },
  }), (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE');
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
  assert.equal(server.connectionsCheckingInterval, 1_000);
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
    assert.equal(server.connectionsCheckingInterval, 1_000);
    assert.equal(server.maxHeadersCount, 100);
    assert.equal(server.maxRequestsPerSocket, 1);
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  }
});

test('minimum slow-header timeout is enforced by a bounded connection sweep', async () => {
  const previous = {
    requestTimeout: process.env.PANEL_HTTP_REQUEST_TIMEOUT_MS,
    headersTimeout: process.env.PANEL_HTTP_HEADERS_TIMEOUT_MS,
  };
  process.env.PANEL_HTTP_REQUEST_TIMEOUT_MS = '1000';
  process.env.PANEL_HTTP_HEADERS_TIMEOUT_MS = '1000';
  let server;
  let socket;
  try {
    server = createServer({
      db: { dbPath: '/tmp/unused-panel-slow-header-test.sqlite3' },
      logger: {
        requestId: () => 'slow-header-test',
        info() {},
        warn() {},
        error() {},
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const responseText = await new Promise((resolve, reject) => {
      let received = '';
      const timer = setTimeout(() => {
        socket?.destroy();
        reject(new Error('slow header connection outlived configured timeout sweep'));
      }, 5_000);
      socket = net.connect(server.address().port, '127.0.0.1', () => {
        socket.write('GET /api/health HTTP/1.1\r\nHost: 127.0.0.1');
      });
      socket.setEncoding('utf8');
      socket.on('data', (chunk) => { received += chunk; });
      socket.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      socket.once('close', () => {
        clearTimeout(timer);
        resolve(received);
      });
    });
    assert.match(responseText, /^HTTP\/1\.1 408 Request Timeout\r\n/);
  } finally {
    socket?.destroy();
    await closeHttpServer(server);
    if (previous.requestTimeout === undefined) delete process.env.PANEL_HTTP_REQUEST_TIMEOUT_MS;
    else process.env.PANEL_HTTP_REQUEST_TIMEOUT_MS = previous.requestTimeout;
    if (previous.headersTimeout === undefined) delete process.env.PANEL_HTTP_HEADERS_TIMEOUT_MS;
    else process.env.PANEL_HTTP_HEADERS_TIMEOUT_MS = previous.headersTimeout;
  }
});

test('known routes return an exact Allow method while unknown targets remain 404', async () => {
  let server;
  try {
    server = createServer({
      db: { dbPath: '/tmp/unused-panel-method-routing-test.sqlite3' },
      logger: {
        requestId: () => 'method-routing-test',
        info() {},
        warn() {},
        error() {},
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const issue = (method, pathname) => new Promise((resolve, reject) => {
      const requestObject = http.request({
        host: '127.0.0.1',
        port: server.address().port,
        method,
        path: pathname,
      }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve({
          status: response.statusCode,
          allow: response.headers.allow,
          body,
        }));
      });
      requestObject.once('error', reject);
      requestObject.end();
    });
    const jobId = 'job_' + 'a'.repeat(24);
    for (const [method, pathname, allow] of [
      ['GET', '/api/phase3', 'POST'],
      ['PUT', '/api/phase3', 'POST'],
      ['POST', '/api/health', 'GET'],
      ['POST', '/api/jobs', 'GET'],
      ['POST', '/api/account-tests/models?accountId=1', 'GET'],
      ['POST', '/api/jobs/' + jobId + '/reconciliation', 'GET'],
      ['GET', '/api/jobs/' + jobId + '/reconciliation/acknowledge', 'POST'],
      ['POST', '/app.js', 'GET'],
    ]) {
      const response = await issue(method, pathname);
      assert.equal(response.status, 405, method + ' ' + pathname);
      assert.equal(response.allow, allow, method + ' ' + pathname);
      assert.equal(JSON.parse(response.body).error, 'method_not_allowed');
    }
    const unknown = await issue('PATCH', '/api/not-a-route');
    assert.equal(unknown.status, 404);
    assert.equal(unknown.allow, undefined);
  } finally {
    await closeHttpServer(server);
  }
});

test('API authentication remains authoritative while the server is draining', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
  };
  const token = 'shutdown-auth-test-token';
  let server;
  resetAuthFailureBuckets();
  try {
    process.env.PANEL_ADMIN_TOKEN = token;
    process.env.PANEL_REQUIRE_AUTH = '1';
    server = createServer({
      db: { dbPath: '/tmp/unused-panel-shutdown-auth.sqlite3' },
      jobManager: { shuttingDown: true },
      logger: {
        requestId: () => 'shutdown-auth-test',
        info() {},
        warn() {},
        error() {},
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const issue = (headers = {}) => new Promise((resolve, reject) => {
      const requestObject = http.get({
        host: '127.0.0.1',
        port: server.address().port,
        path: '/api/health',
        headers,
      }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve({ status: response.statusCode, body }));
      });
      requestObject.once('error', reject);
    });

    const unauthorized = await issue();
    assert.equal(unauthorized.status, 401);
    assert.equal(JSON.parse(unauthorized.body).error, 'panel_auth_required');
    assert.equal(authFailureBucketCount(), 1);

    const authorized = await issue({ 'x-panel-token': token });
    assert.equal(authorized.status, 503);
    assert.equal(JSON.parse(authorized.body).error, 'JOB_INTERRUPTED');
    assert.equal(authFailureBucketCount(), 0);
  } finally {
    await closeHttpServer(server);
    resetAuthFailureBuckets();
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
  }
});

test('HTTP lifecycle durations use a monotonic clock', async () => {
  const originalDateNow = Date.now;
  const records = [];
  let server;
  try {
    server = createServer({
      db: { dbPath: '/tmp/unused-panel-http-duration.sqlite3' },
      logger: {
        requestId: () => 'http-duration-test',
        info(event, fields) { records.push({ event, ...fields }); },
        warn() {},
        error() {},
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    let calls = 0;
    Date.now = () => calls++ === 0 ? 60_000 : 0;
    await new Promise((resolve, reject) => {
      const requestObject = http.get({
        host: '127.0.0.1',
        port: server.address().port,
        path: '/',
      }, (response) => {
        response.resume();
        response.once('end', resolve);
      });
      requestObject.once('error', reject);
    });
    const completed = records.find((entry) => entry.event === 'http.request_completed');
    assert.ok(completed);
    assert.equal(Number.isFinite(completed.durationMs), true);
    assert.ok(completed.durationMs >= 0);
  } finally {
    Date.now = originalDateNow;
    await closeHttpServer(server);
  }
});

test('account-test model lookup rejects ambiguous and non-canonical account IDs', async () => {
  const previous = {
    baseUrl: process.env.SUB2API_BASE_URL,
    apiKey: process.env.SUB2API_ADMIN_API_KEY,
    jwt: process.env.SUB2API_JWT,
  };
  let server;
  try {
    delete process.env.SUB2API_BASE_URL;
    delete process.env.SUB2API_ADMIN_API_KEY;
    delete process.env.SUB2API_JWT;
    server = createServer({
      db: { dbPath: '/tmp/unused-panel-model-query-test.sqlite3' },
      logger: {
        requestId: () => 'model-query-test',
        info() {},
        warn() {},
        error() {},
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    for (const query of [
      'accountId=01',
      'accountId=1e0',
      'accountId=1.0',
      'accountId=%201',
      'accountId=%2B1',
      'accountId=1&accountId=2',
      'accountId=1&account_id=1',
      'accountId=1&account_id=2',
      'account_id=01',
      'accountId=9007199254740992',
    ]) {
      const result = await request(baseUrl, '/api/account-tests/models?' + query);
      assert.equal(result.status, 400, query);
      assert.deepEqual(JSON.parse(result.body), {
        error: 'ACCOUNT_TEST_ACCOUNT_ID_INVALID',
        message: '需要有效的 Sub2API 账号 ID',
      }, query);
    }
  } finally {
    await closeHttpServer(server);
    if (previous.baseUrl === undefined) delete process.env.SUB2API_BASE_URL;
    else process.env.SUB2API_BASE_URL = previous.baseUrl;
    if (previous.apiKey === undefined) delete process.env.SUB2API_ADMIN_API_KEY;
    else process.env.SUB2API_ADMIN_API_KEY = previous.apiKey;
    if (previous.jwt === undefined) delete process.env.SUB2API_JWT;
    else process.env.SUB2API_JWT = previous.jwt;
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
      planIntentVersion: validImportPlanIntentVersion,
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

test('JSON request bodies preserve raw bytes, decode UTF-8 strictly, and reject aborted streams', async () => {
  const assertBodyListenersReleased = (stream) => {
    for (const event of ['data', 'end', 'aborted', 'error', 'close']) {
      assert.equal(stream.listenerCount(event), 0, event + ' listener was not released');
    }
  };
  const requestStream = new EventEmitter();
  requestStream.setEncoding = () => { throw new Error('must retain raw request bytes'); };
  requestStream.resume = () => {};
  const parsedPromise = readJsonBody(requestStream, 64);
  requestStream.emit('data', Buffer.from('{"part":'));
  requestStream.emit('data', Buffer.from('"value"}'));
  requestStream.emit('end');
  assert.deepEqual(await parsedPromise, { part: 'value' });
  assertBodyListenersReleased(requestStream);

  const splitUtf8Stream = new EventEmitter();
  splitUtf8Stream.resume = () => {};
  const splitUtf8Promise = readJsonBody(splitUtf8Stream, 64);
  const splitUtf8Body = Buffer.from('{"part":"值"}');
  const characterStart = splitUtf8Body.indexOf(Buffer.from('值'));
  splitUtf8Stream.emit('data', splitUtf8Body.subarray(0, characterStart + 1));
  splitUtf8Stream.emit('data', splitUtf8Body.subarray(characterStart + 1));
  splitUtf8Stream.emit('end');
  assert.deepEqual(await splitUtf8Promise, { part: '值' });
  assertBodyListenersReleased(splitUtf8Stream);

  const invalidUtf8Stream = new EventEmitter();
  invalidUtf8Stream.resume = () => {};
  const invalidUtf8Promise = readJsonBody(invalidUtf8Stream, 64);
  invalidUtf8Stream.emit('data', Buffer.from('{"part":"'));
  invalidUtf8Stream.emit('data', Buffer.from([0xc3]));
  invalidUtf8Stream.emit('data', Buffer.from('"}'));
  invalidUtf8Stream.emit('end');
  await assert.rejects(invalidUtf8Promise, (error) => error.code === 'INVALID_JSON_BODY');
  assertBodyListenersReleased(invalidUtf8Stream);

  const byteLimitStream = new EventEmitter();
  byteLimitStream.resume = () => {};
  const byteLimitPromise = readJsonBody(byteLimitStream, 3);
  byteLimitStream.emit('data', Buffer.from('值'));
  byteLimitStream.emit('data', Buffer.from('a'));
  await assert.rejects(byteLimitPromise, (error) => error.code === 'REQUEST_BODY_TOO_LARGE');
  assert.equal(byteLimitStream.listenerCount('data'), 0);
  byteLimitStream.emit('end');
  assertBodyListenersReleased(byteLimitStream);

  const abortedStream = new EventEmitter();
  abortedStream.resume = () => {};
  const abortedPromise = readJsonBody(abortedStream, 64);
  abortedStream.emit('data', '{"partial":');
  abortedStream.emit('aborted');
  await assert.rejects(abortedPromise, (error) => error.code === 'REQUEST_ABORTED');
  assert.equal(abortedStream.listenerCount('data'), 0);
  abortedStream.emit('close');
  assertBodyListenersReleased(abortedStream);

  const streamError = new Error('request stream failed');
  const failedStream = new EventEmitter();
  failedStream.resume = () => {};
  const failedPromise = readJsonBody(failedStream, 64);
  failedStream.emit('error', streamError);
  await assert.rejects(failedPromise, (error) => error === streamError);
  assertBodyListenersReleased(failedStream);
});

test('client disconnect aborts an admitted mutation before durable enqueue or dispatch', async () => {
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
  let releaseControlLock;
  let requestObject;
  let createCalls = 0;
  let dispatchCalls = 0;
  let observedSignal = null;
  const controlLockRelease = new Promise((resolve) => { releaseControlLock = resolve; });
  let markControlLockEntered;
  const controlLockEntered = new Promise((resolve) => { markControlLockEntered = resolve; });
  try {
    server = createServer({
      db: {
        dbPath: '/tmp/unused-panel-client-disconnect-test.sqlite3',
        async getMutationReceipt() { return null; },
        async createMutationSubmission() {
          createCalls += 1;
          throw new Error('disconnected request reached durable enqueue');
        },
      },
      jobManager: undefined,
      admissionControlPlaneLock: async (callback, options = {}) => {
        observedSignal = options.signal;
        markControlLockEntered();
        await Promise.race([
          controlLockRelease,
          new Promise((resolve) => observedSignal.addEventListener('abort', resolve, { once: true })),
        ]);
        if (observedSignal.aborted) {
          const error = new Error('request admission interrupted');
          error.code = 'JOB_INTERRUPTED';
          throw error;
        }
        return callback();
      },
      logger: {
        requestId: () => 'client-disconnect-test',
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
      },
    });
    const originalBegin = server.panelJobManager.begin;
    server.panelJobManager.begin = (...args) => {
      dispatchCalls += 1;
      return originalBegin(...args);
    };
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const body = JSON.stringify({
      snapshotVersion: 'a'.repeat(64),
      planIntentVersion: validImportPlanIntentVersion,
      selectedKeys: ['token:tokens:tokens/disconnect.json'],
    });
    const clientSettled = new Promise((resolve) => {
      requestObject = http.request({
        host: '127.0.0.1',
        port: server.address().port,
        path: '/api/sync/import',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          'idempotency-key': 'test-client-disconnect-before-dispatch',
        },
      }, (response) => {
        response.resume();
        response.once('end', resolve);
      });
      requestObject.once('error', resolve);
      requestObject.end(body);
    });
    await controlLockEntered;
    requestObject.destroy();
    for (let attempt = 0; attempt < 100 && !observedSignal?.aborted; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(observedSignal?.aborted, true);
    releaseControlLock();
    releaseControlLock = null;
    await clientSettled;
    for (let attempt = 0; attempt < 100 && server.panelJobManager.admissionCount > 0; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(server.panelJobManager.admissionCount, 0);
    assert.equal(createCalls, 0);
    assert.equal(dispatchCalls, 0);
  } finally {
    if (releaseControlLock) releaseControlLock();
    if (requestObject && !requestObject.destroyed) requestObject.destroy();
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

test('client disconnect aborts snapshot-backed reads before preview persistence', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-preview-disconnect-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]\n');
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    registerRoot: process.env.GPT_REGISTER_ROOT,
  };
  delete process.env.PANEL_ADMIN_TOKEN;
  process.env.PANEL_REQUIRE_AUTH = '0';
  process.env.GPT_REGISTER_ROOT = root;
  let server;
  let requestObject;
  let observedSignal = null;
  let snapshotSaves = 0;
  let markAccountReadStarted;
  let markRouteSettled;
  const accountReadStarted = new Promise((resolve) => { markAccountReadStarted = resolve; });
  const routeSettled = new Promise((resolve) => { markRouteSettled = resolve; });
  try {
    server = createServer({
      db: {
        dbPath: '/tmp/unused-panel-preview-disconnect.sqlite3',
        async saveSnapshot() {
          snapshotSaves += 1;
          return 'unexpected-snapshot';
        },
      },
      syncClientFactory() {
        return {
          async listAccounts(options = {}) {
            observedSignal = options.signal;
            markAccountReadStarted();
            return new Promise((resolve) => {
              const finish = () => resolve([]);
              if (observedSignal?.aborted) finish();
              else observedSignal?.addEventListener('abort', finish, { once: true });
            });
          },
        };
      },
      logger: {
        requestId: () => 'preview-disconnect-test',
        info() {},
        warn() {},
        error(event) {
          if (event === 'preview.failed') markRouteSettled();
        },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const body = JSON.stringify({ selectedKeys: [] });
    const clientSettled = new Promise((resolve) => {
      requestObject = http.request({
        host: '127.0.0.1',
        port: server.address().port,
        path: '/api/sync/preview',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      }, (response) => {
        response.resume();
        response.once('end', resolve);
      });
      requestObject.once('error', resolve);
      requestObject.end(body);
    });
    await accountReadStarted;
    requestObject.destroy();
    await clientSettled;
    await routeSettled;
    assert.equal(observedSignal?.aborted, true);
    assert.equal(snapshotSaves, 0);
  } finally {
    if (requestObject && !requestObject.destroyed) requestObject.destroy();
    await closeHttpServer(server);
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.registerRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.registerRoot;
  }
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

test('successful startup removes the promise-only error listener', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
  };
  process.env.PANEL_REQUIRE_AUTH = '0';
  delete process.env.PANEL_ADMIN_TOKEN;
  let server;
  try {
    server = await startServer({
      host: '127.0.0.1',
      port: 0,
      db: {
        dbPath: '/tmp/unused-panel-start-listener-test.sqlite3',
        ready: Promise.resolve(),
      },
      logger: {
        info() {},
        warn() {},
        error() {},
      },
    });
    assert.equal(server.listenerCount('error'), 0);
  } finally {
    await closeHttpServer(server);
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
  }
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

test('authentication rejects conflicting, duplicated, and ambiguous credential headers', () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
  };
  const token = 'credential-source-test-token';
  process.env.PANEL_ADMIN_TOKEN = token;
  process.env.PANEL_REQUIRE_AUTH = '1';
  resetAuthFailureBuckets();
  const requestWith = (headers, rawHeaders) => ({
    headers,
    rawHeaders,
    socket: { remoteAddress: '198.51.100.42' },
  });
  try {
    assert.equal(authorizationError(requestWith(
      { authorization: 'Bearer ' + token, 'x-panel-token': token },
      ['Authorization', 'Bearer ' + token, 'X-Panel-Token', token],
    )), null);

    for (const requestObject of [
      requestWith(
        { authorization: 'Bearer ' + token, 'x-panel-token': 'conflicting-token' },
        ['Authorization', 'Bearer ' + token, 'X-Panel-Token', 'conflicting-token'],
      ),
      requestWith(
        { authorization: 'Bearer ' + token },
        ['Authorization', 'Bearer ' + token, 'Authorization', 'Bearer conflicting-token'],
      ),
      requestWith(
        { 'x-panel-token': token },
        ['X-Panel-Token', token, 'X-Panel-Token', 'conflicting-token'],
      ),
      requestWith(
        { authorization: 'Basic ignored-value', 'x-panel-token': token },
        ['Authorization', 'Basic ignored-value', 'X-Panel-Token', token],
      ),
      requestWith(
        { authorization: ['Bearer ' + token] },
        ['Authorization', 'Bearer ' + token],
      ),
    ]) assert.equal(authorizationError(requestObject).status, 401);
  } finally {
    resetAuthFailureBuckets();
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
  }
});

test('JSON content type must be represented by exactly one request header', () => {
  assert.equal(hasJsonContentType({
    headers: { 'content-type': 'application/json; charset=utf-8' },
    rawHeaders: ['Content-Type', 'application/json; charset=utf-8'],
  }), true);
  assert.equal(hasJsonContentType({
    headers: { 'content-type': 'application/json' },
    rawHeaders: ['Content-Type', 'application/json', 'Content-Type', 'text/plain'],
  }), false);
  assert.equal(hasJsonContentType({
    headers: { 'content-type': ['application/json', 'text/plain'] },
    rawHeaders: ['Content-Type', 'application/json', 'Content-Type', 'text/plain'],
  }), false);
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
        planIntentVersion: validImportPlanIntentVersion,
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

test('disabled Phase3 rejects before admission but still replays an existing receipt', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
    phase3Enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  process.env.PANEL_PHASE3_ENABLED = '0';
  const replayKey = 'idem_v1_phase3_disabled_replay';
  const responseJobId = 'job_' + '6'.repeat(24);
  let admissions = 0;
  let resolutions = 0;
  let server;
  try {
    server = createServer({
      db: {
        dbPath: '/tmp/unused-panel-phase3-disabled.sqlite3',
        async getMutationReceipt(context) {
          return context.idempotencyKey === replayKey
            ? { statusCode: 202, response: { jobId: responseJobId, status: 'queued' } }
            : null;
        },
      },
      phase3RequestResolver() {
        resolutions += 1;
        throw new Error('disabled Phase3 must not resolve mutable targets');
      },
      jobManager: {
        shuttingDown: false,
        activeCount: 0,
        async withAdmission() {
          admissions += 1;
          throw new Error('disabled Phase3 must not wait for admission');
        },
      },
      logger: {
        requestId: () => 'phase3-disabled-gate-test',
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
      accounts: [{
        email: 'disabled@example.test',
        selectedKey: 'token:tokens:tokens/disabled.json',
        phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
      }],
      selectedKeys: ['token:tokens:tokens/disabled.json'],
    };
    const rejected = await postJson(baseUrl, '/api/phase3', body, {
      'idempotency-key': 'idem_v1_phase3_disabled_new',
    });
    assert.equal(rejected.status, 403);
    assert.equal(JSON.parse(rejected.body).error, 'PHASE3_DISABLED');
    assert.equal(admissions, 0);
    assert.equal(resolutions, 0);

    const replayed = await postJson(baseUrl, '/api/phase3', body, {
      'idempotency-key': replayKey,
    });
    assert.equal(replayed.status, 202);
    assert.equal(replayed.headers['idempotency-replayed'], 'true');
    assert.deepEqual(JSON.parse(replayed.body), { jobId: responseJobId, status: 'queued' });
    assert.equal(admissions, 0);
    assert.equal(resolutions, 0);
  } finally {
    await closeHttpServer(server);
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
    if (previous.phase3Enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.phase3Enabled;
  }
});

test('the locked receipt recheck wins before every mutable live validator', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
    phase3Enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  process.env.PANEL_PHASE3_ENABLED = '1';
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
        planIntentVersion: validImportPlanIntentVersion,
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
    if (previous.phase3Enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.phase3Enabled;
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
      planIntentVersion: validImportPlanIntentVersion,
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
  assert.match(snapshotSource, /async function main\(\) \{\s*const flags = parseFlags\(\);\s*loadEnv\(\);/);
});

test('snapshot CLI refuses to publish an incomplete local source tree', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cli-source-'));
  const incompleteSource = path.join(root, 'gpt-register');
  const envFile = path.join(root, 'panel.env');
  fs.mkdirSync(incompleteSource, { mode: 0o700 });
  fs.mkdirSync(path.join(incompleteSource, 'tokens'), { mode: 0o700 });
  fs.writeFileSync(envFile, '# test environment\n', { mode: 0o600 });

  const child = spawnSync(process.execPath, [
    path.resolve(__dirname, '..', 'backend', 'cli', 'snapshot.js'),
    '--summary',
  ], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    env: {
      ...process.env,
      PANEL_ENV_FILE: envFile,
      GPT_REGISTER_ROOT: incompleteSource,
    },
  });
  assert.equal(child.status, 1, child.stderr);
  assert.equal(child.stdout, '');
  assert.match(child.stderr, /GPT_REGISTER_SOURCE_MISSING/);
  assert.match(child.stderr, /无法形成完整可信快照/);
});

test('snapshot CLI rejects unknown and duplicate flags instead of changing scope silently', () => {
  const snapshotCli = path.resolve(__dirname, '..', 'backend', 'cli', 'snapshot.js');
  for (const args of [
    ['--with-sub2api=1'],
    ['--with-sub2ap'],
    ['--summary', '--summary'],
    ['summary'],
  ]) {
    const child = spawnSync(process.execPath, [snapshotCli, ...args], {
      cwd: path.resolve(__dirname, '..'),
      encoding: 'utf8',
      env: { ...process.env },
    });
    assert.equal(child.status, 1, JSON.stringify(args));
    assert.equal(child.stdout, '');
    assert.match(child.stderr, /CLI_ARGUMENT_INVALID/);
    assert.match(child.stderr, /只接受不重复的/);
  }
});

test('snapshot CLI accepts the exact summary flag without enabling Sub2API', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cli-summary-'));
  const envFile = path.join(root, 'panel.env');
  fs.writeFileSync(envFile, '# test environment\n', { mode: 0o600 });
  const child = spawnSync(process.execPath, [
    path.resolve(__dirname, '..', 'backend', 'cli', 'snapshot.js'),
    '--summary',
  ], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    env: { ...process.env, PANEL_ENV_FILE: envFile },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stderr, '');
  const summary = JSON.parse(child.stdout);
  assert.equal(summary.sub2api.readStatus, 'omitted');
  assert.equal(summary.sub2api.accountCount, null);
  assert.equal(summary.comparisonStatus, 'unavailable');
});

test('snapshot CLI returns failure when an explicitly requested Sub2API read fails', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cli-remote-'));
  const envFile = path.join(root, 'panel.env');
  fs.writeFileSync(envFile, '# test environment\n', { mode: 0o600 });
  const child = spawnSync(process.execPath, [
    path.resolve(__dirname, '..', 'backend', 'cli', 'snapshot.js'),
    '--with-sub2api',
    '--summary',
  ], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    env: {
      ...process.env,
      PANEL_ENV_FILE: envFile,
      SUB2API_BASE_URL: 'http://127.0.0.1:1',
      SUB2API_ADMIN_API_KEY: 'isolated-test-api-key',
      SUB2API_ALLOW_INSECURE_HTTP: '1',
      SUB2API_TIMEOUT_MS: '250',
    },
  });
  assert.equal(child.status, 1, child.stderr);
  assert.equal(child.stdout, '');
  assert.match(child.stderr, /SUB2API_SNAPSHOT_UNAVAILABLE/);
  assert.match(child.stderr, /不能输出远端对比快照/);
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

    const clockJumpSource = { remoteAddress: '198.51.100.21' };
    const originalDateNow = Date.now;
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer incorrect' },
      socket: clockJumpSource,
    }).status, 401);
    try {
      Date.now = () => originalDateNow() + 60 * 60 * 1000;
      assert.equal(authorizationError({
        headers: { authorization: 'Bearer incorrect' },
        socket: clockJumpSource,
      }).status, 429);
    } finally {
      Date.now = originalDateNow;
    }

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

test('sync preview binds the resolved create group IDs with one consistent client', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-group-preview-'));
  const previous = new Map([
    ['GPT_REGISTER_ROOT', process.env.GPT_REGISTER_ROOT],
    ['PANEL_WRITE_ENABLED', process.env.PANEL_WRITE_ENABLED],
    ['SUB2API_BASE_URL', process.env.SUB2API_BASE_URL],
    ['SUB2API_ADMIN_API_KEY', process.env.SUB2API_ADMIN_API_KEY],
    ['SUB2API_GROUP_IDS', process.env.SUB2API_GROUP_IDS],
    ['SUB2API_GROUP_NAME', process.env.SUB2API_GROUP_NAME],
  ]);
  let server = null;
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '0';
  process.env.SUB2API_BASE_URL = 'http://127.0.0.1:18080';
  process.env.SUB2API_ADMIN_API_KEY = 'test-only-key';
  delete process.env.SUB2API_GROUP_IDS;
  process.env.SUB2API_GROUP_NAME = 'share';
  try {
    fs.mkdirSync(path.join(root, 'tokens'));
    fs.mkdirSync(path.join(root, 'use_token'));
    fs.writeFileSync(path.join(root, 'username.json'), '[]');
    const accessToken = [
      'header',
      Buffer.from(JSON.stringify({
        sub: 'preview-user',
        'https://api.openai.com/auth': {
          chatgpt_account_id: 'preview-account',
          chatgpt_user_id: 'preview-user',
        },
      })).toString('base64url'),
      'signature',
    ].join('.');
    fs.writeFileSync(path.join(root, 'tokens', 'preview.json'), JSON.stringify({
      access_token: accessToken,
      expires_at: '2099-01-01T00:00:00.000Z',
    }));

    let factoryCalls = 0;
    let accountReads = 0;
    let groupReads = 0;
    const client = {
      baseUrl: 'http://127.0.0.1:18080',
      async listAccounts() { accountReads += 1; return []; },
      async listGroups() {
        groupReads += 1;
        return [{ id: 17, name: 'share', platform: 'openai', status: 'active' }];
      },
    };
    server = createServer({
      dbPath: path.join(root, 'panel.sqlite3'),
      syncClientFactory() {
        factoryCalls += 1;
        return client;
      },
      logger: {
        info() {},
        warn() {},
        error() {},
        probe() { return true; },
        checkpoint() { return true; },
        requestId() { return 'group-preview-request'; },
        tail() { return []; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const response = await postJson(
      'http://127.0.0.1:' + server.address().port,
      '/api/sync/preview',
      { selectedKeys: [] },
    );
    assert.equal(response.status, 200);
    const body = JSON.parse(response.body);
    assert.deepEqual(body.groupBinding, { mode: 'explicit', groupIds: [17] });
    assert.match(body.planIntentVersion, /^sync-plan-v1\.[A-Za-z0-9_-]{43}$/);
    assert.equal(body.items[0].action, 'create');
    assert.equal(factoryCalls, 1);
    assert.equal(accountReads, 1);
    assert.equal(groupReads, 1);
  } finally {
    await closeHttpServer(server);
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
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
  process.env.PANEL_PHASE3_ENABLED = '0';
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
    const snapshotBody = JSON.parse(snapshot.body);
    assert.deepEqual(snapshotBody.capabilities, { phase3Enabled: false });
    const snapshotRows = snapshotBody.rows;
    const phase3RevisionFor = (relativePath) => snapshotRows.find(
      (row) => row.relativePath === relativePath,
    )?.phase3TargetRevision;

    fs.renameSync(path.join(root, 'use_token'), path.join(root, 'use_token-missing'));
    const incompleteSourceSnapshot = await request(baseUrl, '/api/snapshot');
    assert.equal(incompleteSourceSnapshot.status, 503);
    assert.equal(
      JSON.parse(incompleteSourceSnapshot.body).error,
      'GPT_REGISTER_SOURCE_MISSING',
    );
    const incompleteSourcePreview = await postJson(baseUrl, '/api/sync/preview', {
      selectedKeys: [],
    });
    assert.equal(incompleteSourcePreview.status, 503);
    assert.equal(
      JSON.parse(incompleteSourcePreview.body).error,
      'GPT_REGISTER_SOURCE_MISSING',
    );
    fs.renameSync(path.join(root, 'use_token-missing'), path.join(root, 'use_token'));

    const usernamePath = path.join(root, 'username.json');
    const validUsernameContent = fs.readFileSync(usernamePath);
    fs.writeFileSync(usernamePath, '{not-valid-json');
    const invalidUsernameSnapshot = await request(baseUrl, '/api/snapshot');
    assert.equal(invalidUsernameSnapshot.status, 503);
    assert.equal(
      JSON.parse(invalidUsernameSnapshot.body).error,
      'GPT_REGISTER_USERNAME_INVALID',
    );
    fs.writeFileSync(usernamePath, validUsernameContent);

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
    const disabledPhase3 = await postJson(baseUrl, '/api/phase3', {
      accounts: [{
        email: 'server@example.test',
        selectedKey: selectedTokenKey,
        phase3TargetRevision: currentPhase3Revision,
      }],
      selectedKeys: [selectedTokenKey],
    });
    assert.equal(disabledPhase3.status, 403);
    assert.equal(JSON.parse(disabledPhase3.body).error, 'PHASE3_DISABLED');
    const jobsAfterDisabledRequest = await request(baseUrl, '/api/jobs?limit=200');
    assert.equal(jobsAfterDisabledRequest.status, 200);
    assert.equal(JSON.parse(jobsAfterDisabledRequest.body).jobs.some(
      (job) => job.type === 'phase3',
    ), false);

    // The remaining assertions exercise revision and batch admission with the
    // feature enabled. The temporary test root has no runnable index.js, so
    // accepted jobs terminate without invoking the real registration project.
    process.env.PANEL_PHASE3_ENABLED = '1';
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
    assert.equal(phase3Jobs.some((job) => job.result?.code === 'PHASE3_DISABLED'), false);

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
