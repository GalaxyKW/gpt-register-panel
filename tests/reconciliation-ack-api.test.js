const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const {
  PanelDb,
  RECONCILIATION_ACK_CONFIRMATION,
} = require('../backend/db');
const { createServer, sourcePathFromSelectionKey } = require('../backend/server');
const { CONFIRMATION: TOKEN_CLEANUP_CONFIRMATION } = require('../backend/tokenCleanup');

const ADMIN_TOKEN = 'panel-test-token-16-chars';

function requestJson(baseUrl, pathname, options = {}) {
  return new Promise((resolve, reject) => {
    const body = options.rawBody !== undefined
      ? String(options.rawBody)
      : options.body === undefined ? '' : JSON.stringify(options.body);
    const request = http.request(baseUrl + pathname, {
      method: options.method || 'GET',
      headers: {
        ...(options.token ? { 'x-panel-token': options.token } : {}),
        ...(options.contentType === false ? {} : body ? { 'content-type': 'application/json' } : {}),
        ...(options.method === 'POST' && pathname === '/api/tokens/expired/delete'
          ? { 'idempotency-key': 'test-idem-' + crypto.randomUUID() }
          : {}),
        'content-length': Buffer.byteLength(body),
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => {
        let json = null;
        try { json = responseBody ? JSON.parse(responseBody) : null; } catch {}
        resolve({ status: response.statusCode, body: responseBody, json });
      });
    });
    request.on('error', reject);
    request.end(body);
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(
      'http://127.0.0.1:' + server.address().port,
    ));
  });
}

function close(server) {
  return new Promise((resolve) => {
    if (!server?.listening) return resolve();
    server.close(() => resolve());
  });
}

function testDbPath(label) {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'panel-ack-api-' + label + '-')), 'panel.sqlite3');
}

async function heldJob(db, claimKey) {
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, {
    status: 'failed',
    result: { writeOutcomeUnknown: true },
    finishedAt: new Date().toISOString(),
  });
  return db.getJob(job.id);
}

test('review source paths accept only exact source-bound selection keys', () => {
  assert.equal(
    sourcePathFromSelectionKey('token:tokens:tokens/free-account.json'),
    'tokens/free-account.json',
  );
  assert.equal(
    sourcePathFromSelectionKey('token:use_token:phase3-account.json'),
    null,
  );
  assert.equal(
    sourcePathFromSelectionKey('token:tokens:use_token/wrong-source.json'),
    null,
  );
});

function acknowledgementBody(job, resolution = 'state_manually_reconciled') {
  return {
    jobId: job.id,
    confirmation: RECONCILIATION_ACK_CONFIRMATION,
    resolution,
    claimDigest: job.result.reconciliationClaimDigest,
  };
}

test('acknowledgement route requires an authenticated administrator and a durable audit checkpoint', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    insecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_ADMIN_TOKEN = ADMIN_TOKEN;
  process.env.PANEL_REQUIRE_AUTH = '1';
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '0';
  const db = new PanelDb(testDbPath('authenticated'));
  const held = await heldJob(db, 'phase3:api-auth');
  let checkpointAllowed = false;
  const logRecords = [];
  const logger = {
    requestId: () => 'ack-api-request',
    probe: () => true,
    checkpoint(event, fields) {
      logRecords.push({ event, fields });
      return checkpointAllowed;
    },
    info(event, fields) { logRecords.push({ event, fields }); },
    warn(event, fields) { logRecords.push({ event, fields }); },
    error(event, fields) { logRecords.push({ event, fields }); },
  };
  const server = createServer({ db, logger });
  let baseUrl;
  try {
    baseUrl = await listen(server);
    const route = '/api/jobs/' + encodeURIComponent(held.id) + '/reconciliation/acknowledge';
    assert.equal((await requestJson(baseUrl, route, {
      method: 'POST', body: acknowledgementBody(held),
    })).status, 401);

    const mismatch = await requestJson(baseUrl, route, {
      method: 'POST',
      token: ADMIN_TOKEN,
      body: { ...acknowledgementBody(held), jobId: 'job_' + '0'.repeat(24) },
    });
    assert.equal(mismatch.status, 400);
    assert.equal(mismatch.json.error, 'JOB_RECONCILIATION_JOB_ID_MISMATCH');

    const invalidResolution = await requestJson(baseUrl, route, {
      method: 'POST',
      token: ADMIN_TOKEN,
      body: { ...acknowledgementBody(held), resolution: 'remote_applied' },
    });
    assert.equal(invalidResolution.status, 400);
    assert.equal(invalidResolution.json.error, 'JOB_RECONCILIATION_RESOLUTION_INVALID');

    const missingJobId = 'job_' + '0'.repeat(24);
    const notFound = await requestJson(
      baseUrl,
      '/api/jobs/' + missingJobId + '/reconciliation/acknowledge',
      {
        method: 'POST',
        token: ADMIN_TOKEN,
        body: {
          ...acknowledgementBody(held),
          jobId: missingJobId,
        },
      },
    );
    assert.equal(notFound.status, 404);
    assert.equal(notFound.json.error, 'JOB_RECONCILIATION_NOT_FOUND');
    assert.equal(notFound.json.message, '待对账任务不存在');
    assert.deepEqual(Object.keys(notFound.json).sort(), ['error', 'message']);

    const originalAcknowledge = db.acknowledgeJobReconciliation.bind(db);
    db.acknowledgeJobReconciliation = async () => {
      const error = new Error('database persistence unavailable');
      error.code = 'SIMULATED_DATABASE_PERSISTENCE_FAILURE';
      throw error;
    };
    const persistenceFailure = await requestJson(baseUrl, route, {
      method: 'POST', token: ADMIN_TOKEN, body: acknowledgementBody(held),
    });
    db.acknowledgeJobReconciliation = originalAcknowledge;
    assert.equal(persistenceFailure.status, 503);
    assert.equal(persistenceFailure.json.error, 'JOB_RECONCILIATION_ACKNOWLEDGE_FAILED');
    assert.equal(persistenceFailure.body.includes('database persistence unavailable'), false);
    assert.equal(persistenceFailure.body.includes('SIMULATED_DATABASE_PERSISTENCE_FAILURE'), false);
    assert.equal((await db.getJob(held.id)).result.reconciliationHold, true);

    const unavailable = await requestJson(baseUrl, route, {
      method: 'POST', token: ADMIN_TOKEN, body: acknowledgementBody(held),
    });
    assert.equal(unavailable.status, 503);
    assert.equal(unavailable.json.error, 'AUDIT_LOG_UNAVAILABLE');
    assert.equal((await db.getJob(held.id)).result.reconciliationHold, true);
    await assert.rejects(
      db.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:api-auth'] }),
      (error) => error.code === 'JOB_RECONCILIATION_REQUIRED',
    );

    checkpointAllowed = true;
    const acknowledged = await requestJson(baseUrl, route, {
      method: 'POST', token: ADMIN_TOKEN, body: acknowledgementBody(held),
    });
    assert.equal(acknowledged.status, 200);
    assert.equal(acknowledged.json.idempotent, false);
    assert.equal(acknowledged.json.resolution, 'state_manually_reconciled');
    assert.match(acknowledged.json.message, /原任务仍不可重试/);
    const resolved = await db.getJob(held.id);
    assert.equal(resolved.result.futureOperationsUnblocked, true);
    assert.equal(resolved.result.retryAllowed, false);
    assert.equal(resolved.result.doNotRetry, true);

    const replay = await requestJson(baseUrl, route, {
      method: 'POST', token: ADMIN_TOKEN, body: acknowledgementBody(held),
    });
    assert.equal(replay.status, 200);
    assert.equal(replay.json.idempotent, true);
    const conflict = await requestJson(baseUrl, route, {
      method: 'POST', token: ADMIN_TOKEN, body: acknowledgementBody(held, 'operation_applied'),
    });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.json.error, 'JOB_RECONCILIATION_ACK_CONFLICT');

    const serializedLogs = JSON.stringify(logRecords);
    assert.equal(serializedLogs.includes(RECONCILIATION_ACK_CONFIRMATION), false);
    assert.equal(serializedLogs.includes('phase3:api-auth'), false);
    assert.ok(logRecords.some((record) => record.event === 'job.reconciliation_acknowledge_checkpoint'));
  } finally {
    await close(server);
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.insecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.insecureWrite;
  }
});

test('reconciliation detail is path-bound and exposes only bounded workflow target context', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    insecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_ADMIN_TOKEN = ADMIN_TOKEN;
  process.env.PANEL_REQUIRE_AUTH = '1';
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '0';
  const db = new PanelDb(testDbPath('safe-detail'));
  const secretCanary = 'must-not-leak-review-payload';
  const job = await db.createJob('token_import', {
    snapshotVersion: 'a'.repeat(64),
    selectedKeys: ['token:tokens:tokens/free-account.json'],
    unrelatedNote: secretCanary,
  }, 'tester', { claimKeys: ['token_import'] });
  const accountJob = await db.createJob('account_test', {
    accountIds: [381],
    targetBaselines: [{
      accountId: 381,
      identityDigest: 'd'.repeat(64),
      status: 'error',
      statusKnown: true,
      schedulable: false,
      schedulableKnown: true,
    }],
    prompt: secretCanary,
  }, 'tester', { claimKeys: ['account_test:381'] });
  const phase3Job = await db.createJob('phase3', {
    email: 'phase3@example.test',
    phone: '13800138000',
    selectedKey: 'token:use_token:use_token/phase3-account.json',
    sourcePath: 'use_token/phase3-account.json',
    canonicalKeys: ['email:phase3@example.test', 'credential:' + secretCanary],
  }, 'tester', { claimKeys: ['phase3:email:phase3@example.test'] });
  await db.updateJob(job.id, {
    status: 'failed',
    result: {
      writeOutcomeUnknown: true,
      unrelatedResult: secretCanary,
      imported: [{
        source: 'tokens',
        relativePath: 'tokens/free-account.json',
        accountId: 266,
        accountName: 'free00006',
        email: 'account@example.test',
        action: 'update',
        fingerprints: { access: 'b'.repeat(16) },
        sourceIdentityKeys: [
          'account:11111111-1111-4111-8111-111111111111',
          'user:22222222-2222-4222-8222-222222222222',
          'email:account@example.test',
          'credential:' + secretCanary,
        ],
        availability: 'unavailable',
        availabilityReason: 'sub2api_status_error',
        requiresReconciliation: true,
        writeOutcomeUnknown: true,
        outcome: 'requires_reconciliation',
        credentials: { access_token: 'raw-access-token-canary' },
      }],
    },
    error: secretCanary,
    finishedAt: new Date().toISOString(),
  });
  await db.updateJob(accountJob.id, {
    status: 'failed',
    result: {
      writeOutcomeUnknown: true,
      results: [{ accountId: 381, requiresReconciliation: true }],
    },
    finishedAt: new Date().toISOString(),
  });
  await db.updateJob(phase3Job.id, {
    status: 'failed',
    result: { writeOutcomeUnknown: true },
    finishedAt: new Date().toISOString(),
  });
  const held = await db.getJob(job.id);
  const logger = {
    requestId: () => 'ack-detail-request',
    probe: () => true,
    checkpoint: () => true,
    info() {}, warn() {}, error() {},
  };
  const server = createServer({ db, logger });
  try {
    const baseUrl = await listen(server);
    const route = '/api/jobs/' + encodeURIComponent(job.id) + '/reconciliation';
    assert.equal((await requestJson(baseUrl, route)).status, 401);

    const response = await requestJson(baseUrl, route, { token: ADMIN_TOKEN });
    assert.equal(response.status, 200);
    assert.equal(response.json.version, 1);
    assert.equal(response.json.id, job.id);
    assert.equal(response.json.type, 'token_import');
    assert.equal(response.json.reconciliationClaimDigest,
      held.result.reconciliationClaimDigest);
    assert.deepEqual(response.json.targetContext, {
      available: true,
      total: 1,
      returned: 1,
      truncated: false,
      targets: [{
        sourcePath: 'tokens/free-account.json',
        remoteAccountId: 266,
        accountName: 'free00006',
        email: 'account@example.test',
        action: 'update',
        accessFingerprint: 'b'.repeat(16),
        strongIdentityKeys: [
          'account:11111111-1111-4111-8111-111111111111',
          'user:22222222-2222-4222-8222-222222222222',
        ],
        availability: 'unavailable',
        availabilityReason: 'sub2api_status_error',
      }],
    });
    const serialized = JSON.stringify(response.json);
    assert.equal(serialized.includes(secretCanary), false);
    assert.equal(serialized.includes('raw-access-token-canary'), false);
    assert.equal(Object.hasOwn(response.json, 'payload'), false);
    assert.equal(Object.hasOwn(response.json, 'result'), false);
    assert.equal(Object.hasOwn(response.json, 'error'), false);

    const accountDetail = await requestJson(
      baseUrl,
      '/api/jobs/' + encodeURIComponent(accountJob.id) + '/reconciliation',
      { token: ADMIN_TOKEN },
    );
    assert.equal(accountDetail.status, 200);
    assert.deepEqual(accountDetail.json.targetContext.targets, [{
      remoteAccountId: 381,
      identityDigest: 'd'.repeat(64),
      baselineStatus: 'error',
      baselineSchedulable: false,
    }]);

    const phase3Detail = await requestJson(
      baseUrl,
      '/api/jobs/' + encodeURIComponent(phase3Job.id) + '/reconciliation',
      { token: ADMIN_TOKEN },
    );
    assert.equal(phase3Detail.status, 200);
    assert.deepEqual(phase3Detail.json.targetContext.targets, [{
      sourcePath: 'use_token/phase3-account.json',
      email: 'phase3@example.test',
      phone: '13800138000',
    }]);
    assert.equal(JSON.stringify(phase3Detail.json).includes(secretCanary), false);

    const invalidPath = await requestJson(
      baseUrl,
      '/api/jobs/not-a-job/reconciliation',
      { token: ADMIN_TOKEN },
    );
    assert.equal(invalidPath.status, 400);
    assert.equal(invalidPath.json.error, 'JOB_RECONCILIATION_JOB_ID_INVALID');
  } finally {
    await close(server);
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.insecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.insecureWrite;
  }
});

test('loopback insecure-write mode cannot acknowledge a hold as the local actor', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    insecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  delete process.env.PANEL_ADMIN_TOKEN;
  process.env.PANEL_REQUIRE_AUTH = '0';
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  const db = new PanelDb(testDbPath('local-rejected'));
  const held = await heldJob(db, 'phase3:local-rejected');
  const logger = {
    requestId: () => 'ack-local-request',
    probe: () => true,
    checkpoint: () => true,
    info() {}, warn() {}, error() {},
  };
  const server = createServer({ db, logger });
  try {
    const baseUrl = await listen(server);
    const result = await requestJson(
      baseUrl,
      '/api/jobs/' + encodeURIComponent(held.id) + '/reconciliation/acknowledge',
      { method: 'POST', body: acknowledgementBody(held) },
    );
    assert.equal(result.status, 403);
    assert.equal(result.json.error, 'JOB_RECONCILIATION_ADMIN_REQUIRED');
    assert.equal((await db.getJob(held.id)).result.reconciliationHold, true);
  } finally {
    await close(server);
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.insecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.insecureWrite;
  }
});

test('an unresolved hold blocks token cleanup before its audit intent or filesystem mutation', async () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    insecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_ADMIN_TOKEN = ADMIN_TOKEN;
  process.env.PANEL_REQUIRE_AUTH = '1';
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '0';
  const db = new PanelDb(testDbPath('cleanup-blocked'));
  const held = await heldJob(db, 'phase3:cleanup-blocked');
  const logger = {
    requestId: () => 'cleanup-blocked-request',
    probe: () => true,
    checkpoint: () => true,
    info() {}, warn() {}, error() {},
  };
  const server = createServer({ db, logger });
  try {
    const baseUrl = await listen(server);
    const response = await requestJson(baseUrl, '/api/tokens/expired/delete', {
      method: 'POST',
      token: ADMIN_TOKEN,
      body: {
        version: '0'.repeat(64),
        confirmation: TOKEN_CLEANUP_CONFIRMATION,
      },
    });
    assert.equal(response.status, 409);
    assert.equal(response.json.error, 'JOB_RECONCILIATION_REQUIRED');
    assert.equal((await db.getJob(held.id)).result.reconciliationHold, true);
    assert.equal((await db.listAudit(50)).some((entry) => (
      entry.action === 'expired_token_cleanup'
    )), false);
  } finally {
    await close(server);
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.insecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.insecureWrite;
  }
});
