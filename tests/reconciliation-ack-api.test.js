const assert = require('node:assert/strict');
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
const { createServer } = require('../backend/server');
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
    assert.equal(persistenceFailure.json.error, 'SIMULATED_DATABASE_PERSISTENCE_FAILURE');
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
