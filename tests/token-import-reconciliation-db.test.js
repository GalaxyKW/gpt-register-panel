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
const {
  buildTokenImportReconciliationContext,
  TOKEN_IMPORT_CONTEXT_COVERAGE,
} = require('../backend/reconciliationContext');
const {
  createServer,
  reconciliationReviewDetail,
} = require('../backend/server');

const ADMIN_TOKEN = 'panel-test-token-16-chars';
const SNAPSHOT_VERSION = 'a'.repeat(64);
const PLAN_INTENT_VERSION = `sync-plan-v1.${'B'.repeat(43)}`;
const EXECUTION_TARGET = {
  schema: 'sub2api-admin-target-v1',
  fingerprint: `sha256.${'T'.repeat(43)}`,
};

function databasePath(label) {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), `panel-import-context-${label}-`)),
    'panel.sqlite3',
  );
}

function importPlanItem(index = 1) {
  const sequence = String(index).padStart(5, '0');
  const email = `account-${sequence}@example.test`;
  return {
    source: 'tokens',
    relativePath: `account-${sequence}.json`,
    action: 'create',
    accountId: null,
    accountName: `free${sequence}`,
    email,
    sourceIdentityKeys: [
      `account:account-${sequence}`,
      `user:user-${sequence}`,
      `email:${email}`,
    ],
    fingerprints: { access: index.toString(16).padStart(16, '0') },
    availability: 'not_present',
    availabilityReason: 'not_in_sub2api',
    _record: { contentHash: index.toString(16).padStart(64, '0') },
  };
}

function buildContext(plan = [importPlanItem()]) {
  const hasCreates = plan.some((item) => item.action === 'create');
  return buildTokenImportReconciliationContext(plan, {
    snapshotVersion: SNAPSHOT_VERSION,
    planIntentVersion: PLAN_INTENT_VERSION,
    groupBinding: hasCreates
      ? { mode: 'explicit', groupIds: [7] }
      : { mode: 'not_applicable', groupIds: [] },
    executionBinding: { target: EXECUTION_TARGET },
  });
}

async function createTokenImportJob(db) {
  return db.createJob('token_import', {
    snapshotVersion: SNAPSHOT_VERSION,
    planIntentVersion: PLAN_INTENT_VERSION,
  }, 'panel-admin', { claimKeys: ['token_import'] });
}

async function persistedExecutionState(db) {
  return db.read((database) => {
    const result = database.exec(`SELECT status, reconciliation_context_json,
        reconciliation_context_required
      FROM sync_jobs ORDER BY rowid ASC LIMIT 1`)[0];
    if (!result?.values?.[0]) return null;
    return {
      status: result.values[0][0],
      reconciliationContextJson: result.values[0][1],
      reconciliationContextRequired: result.values[0][2],
    };
  });
}

async function makeOwnerDead(db, jobId) {
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET owner_pid = ?, owner_start_id = ?, owner_boot_id = ? WHERE id = ?`);
    try {
      statement.run([
        2147483647,
        '1',
        '00000000-0000-0000-0000-000000000000',
        jobId,
      ]);
    } finally {
      statement.free();
    }
  });
}

function requestJson(baseUrl, pathname, options = {}) {
  return new Promise((resolve, reject) => {
    const body = options.body === undefined ? '' : JSON.stringify(options.body);
    const request = http.request(baseUrl + pathname, {
      method: options.method || 'GET',
      headers: {
        ...(options.token ? { 'x-panel-token': options.token } : {}),
        ...(body ? { 'content-type': 'application/json' } : {}),
        'content-length': Buffer.byteLength(body),
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => {
        let json = null;
        try { json = responseBody ? JSON.parse(responseBody) : null; } catch {}
        resolve({ status: response.statusCode, json });
      });
    });
    request.on('error', reject);
    request.end(body);
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

function close(server) {
  return new Promise((resolve) => {
    if (!server?.listening) return resolve();
    server.close(() => resolve());
  });
}

test('token import can enter running only through an atomic validated context start', async () => {
  const db = new PanelDb(databasePath('start-contract'));
  const job = await createTokenImportJob(db);
  const context = buildContext();

  await assert.rejects(
    db.startMutationJob(job.id),
    (error) => error.code === 'JOB_RECONCILIATION_GUARD_UNAVAILABLE',
  );
  assert.deepEqual(await persistedExecutionState(db), {
    status: 'queued',
    reconciliationContextJson: null,
    reconciliationContextRequired: 0,
  });

  const tampered = structuredClone(context);
  tampered.targets[0].accountName = 'free99999';
  await assert.rejects(
    db.startMutationJob(job.id, { reconciliationContext: tampered }),
    (error) => error.code === 'JOB_RECONCILIATION_GUARD_UNAVAILABLE',
  );
  assert.deepEqual(await persistedExecutionState(db), {
    status: 'queued',
    reconciliationContextJson: null,
    reconciliationContextRequired: 0,
  });

  await assert.rejects(
    db.updateJob(job.id, {
      status: 'running',
      startedAt: new Date().toISOString(),
    }),
    (error) => error.code === 'JOB_RECONCILIATION_GUARD_UNAVAILABLE',
  );
  assert.deepEqual(await persistedExecutionState(db), {
    status: 'queued',
    reconciliationContextJson: null,
    reconciliationContextRequired: 0,
  });

  const started = await db.startMutationJob(job.id, { reconciliationContext: context });
  assert.equal(started.status, 'running');
  const persisted = await persistedExecutionState(db);
  assert.equal(persisted.status, 'running');
  assert.equal(persisted.reconciliationContextRequired, 1);
  assert.deepEqual(JSON.parse(persisted.reconciliationContextJson), context);

  const publicJob = await db.getJob(job.id);
  assert.equal(Object.hasOwn(publicJob, 'reconciliationContext'), false);
  const publicJobs = await db.listJobs();
  assert.equal(publicJobs.length, 1);
  assert.equal(Object.hasOwn(publicJobs[0], 'reconciliationContext'), false);

  const reviewJob = await db.getJobForReconciliation(job.id);
  assert.deepEqual(reviewJob.reconciliationContext, context);
  assert.deepEqual(reviewJob.claimKeys, ['token_import']);
  assert.equal(reviewJob.reconciliationClaimDigest, null);
});

test('marker migration discards a queued legacy import context before validation', async () => {
  const file = databasePath('queued-marker-migration');
  const legacyDb = new PanelDb(file);
  const job = await createTokenImportJob(legacyDb);
  const context = buildContext();

  // Reproduce the persisted schema of the short-lived context-capable build:
  // it could leave a context on a queued row but had no non-downgrade marker.
  await legacyDb.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET reconciliation_context_json = ? WHERE id = ?`);
    try {
      statement.run([JSON.stringify(context), job.id]);
    } finally {
      statement.free();
    }
    database.run('ALTER TABLE sync_jobs DROP COLUMN reconciliation_context_required');
  });

  const migrated = new PanelDb(file);
  assert.deepEqual(await persistedExecutionState(migrated), {
    status: 'queued',
    reconciliationContextJson: null,
    reconciliationContextRequired: 0,
  });

  // The migration must leave the queued job usable through the current atomic
  // start boundary rather than blessing or retaining its old context.
  await migrated.startMutationJob(job.id, { reconciliationContext: context });
  assert.equal((await persistedExecutionState(migrated)).reconciliationContextRequired, 1);
});

test('marker migration preserves and marks a running import context', async () => {
  const file = databasePath('running-marker-migration');
  const legacyDb = new PanelDb(file);
  const job = await createTokenImportJob(legacyDb);
  const context = buildContext();
  await legacyDb.startMutationJob(job.id, { reconciliationContext: context });
  await legacyDb.write((database) => {
    database.run('ALTER TABLE sync_jobs DROP COLUMN reconciliation_context_required');
  });

  const migrated = new PanelDb(file);
  const persisted = await persistedExecutionState(migrated);
  assert.equal(persisted.status, 'running');
  assert.equal(persisted.reconciliationContextRequired, 1);
  assert.deepEqual(JSON.parse(persisted.reconciliationContextJson), context);
});

test('marker migration keeps legacy context-free jobs compatible', async () => {
  for (const scenario of [
    {
      label: 'running-token-import',
      type: 'token_import',
      claimKeys: ['token_import'],
      prepare: async (db, job) => db.write((database) => {
        const statement = database.prepare(`UPDATE sync_jobs
          SET status = 'running', started_at = ? WHERE id = ?`);
        try { statement.run([new Date().toISOString(), job.id]); } finally { statement.free(); }
      }),
      expectedStatus: 'running',
    },
    {
      label: 'held-token-import',
      type: 'token_import',
      claimKeys: ['token_import'],
      prepare: async (db, job) => {
        await db.write((database) => {
          const statement = database.prepare(`UPDATE sync_jobs
            SET status = 'running', started_at = ? WHERE id = ?`);
          try { statement.run([new Date().toISOString(), job.id]); } finally { statement.free(); }
        });
        await db.updateJob(job.id, {
          status: 'failed',
          finishedAt: new Date().toISOString(),
          result: { requiresReconciliation: true, writeOutcomeUnknown: true },
        });
      },
      expectedStatus: 'failed',
      expectedHold: true,
    },
    {
      label: 'terminal-token-import',
      type: 'token_import',
      claimKeys: ['token_import'],
      prepare: (db, job) => db.updateJob(job.id, {
        status: 'failed',
        finishedAt: new Date().toISOString(),
        result: { requiresReconciliation: false },
      }),
      expectedStatus: 'failed',
    },
    {
      label: 'queued-non-token',
      type: 'phase3',
      claimKeys: ['phase3:marker-migration'],
      prepare: async () => {},
      expectedStatus: 'queued',
    },
  ]) {
    const file = databasePath(scenario.label);
    const legacyDb = new PanelDb(file);
    const job = await legacyDb.createJob(scenario.type, {}, 'tester', {
      claimKeys: scenario.claimKeys,
    });
    await scenario.prepare(legacyDb, job);
    await legacyDb.write((database) => {
      database.run('ALTER TABLE sync_jobs DROP COLUMN reconciliation_context_required');
    });

    const migrated = new PanelDb(file);
    const persisted = await persistedExecutionState(migrated);
    assert.equal(persisted.status, scenario.expectedStatus, scenario.label);
    assert.equal(persisted.reconciliationContextJson, null, scenario.label);
    assert.equal(persisted.reconciliationContextRequired, 0, scenario.label);
    if (scenario.expectedHold) {
      assert.equal((await migrated.getJob(job.id)).result.reconciliationHold, true);
    }
  }
});

test('marker migration does not erase an undeclared non-token context', async () => {
  const file = databasePath('non-token-context-marker-migration');
  const legacyDb = new PanelDb(file);
  const job = await legacyDb.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:undeclared-context'],
  });
  await legacyDb.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET reconciliation_context_json = '{}' WHERE id = ?`);
    try { statement.run([job.id]); } finally { statement.free(); }
    database.run('ALTER TABLE sync_jobs DROP COLUMN reconciliation_context_required');
  });

  await assert.rejects(
    new PanelDb(file).ready,
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
});

test('queued jobs cannot manufacture an unknown-outcome hold before execution starts', async () => {
  const db = new PanelDb(databasePath('queued-hold'));
  const job = await createTokenImportJob(db);

  await assert.rejects(
    db.updateJob(job.id, {
      status: 'failed',
      finishedAt: new Date().toISOString(),
      result: {
        outcome: 'requires_reconciliation',
        executionOutcome: 'unknown',
        writeOutcomeUnknown: true,
        requiresReconciliation: true,
      },
    }),
    (error) => error.code === 'JOB_STATUS_CONFLICT',
  );
  assert.deepEqual(await persistedExecutionState(db), {
    status: 'queued',
    reconciliationContextJson: null,
    reconciliationContextRequired: 0,
  });
  assert.equal((await db.getJob(job.id)).result, null);
  const recovery = await db.interruptOwnedQueuedJobsBeforeDispatch([job.id]);
  assert.deepEqual(recovery.interrupted, [job.id]);
  assert.equal((await db.getJob(job.id)).result.executionOutcome, 'not_started');
  const replacement = await createTokenImportJob(db);
  assert.equal((await db.getJob(replacement.id)).status, 'queued');
});

test('completed token imports discard the large context while retaining its non-downgrade marker', async () => {
  const file = databasePath('completed-context');
  const db = new PanelDb(file);
  const job = await createTokenImportJob(db);
  const context = buildContext();
  await db.startMutationJob(job.id, { reconciliationContext: context });
  await db.updateJob(job.id, {
    status: 'succeeded',
    finishedAt: new Date().toISOString(),
    result: { imported: [], requiresReconciliation: false },
  });

  assert.deepEqual(await persistedExecutionState(db), {
    status: 'succeeded',
    reconciliationContextJson: null,
    reconciliationContextRequired: 1,
  });

  // Simulate the short-lived build that retained a completed manifest. A
  // restart must reclaim the bounded-but-large field after proving that the
  // terminal result has no reconciliation signal.
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET reconciliation_context_json = ? WHERE id = ?`);
    try {
      statement.run([JSON.stringify(context), job.id]);
    } finally {
      statement.free();
    }
  });
  const restarted = new PanelDb(file);
  await restarted.ready;
  assert.deepEqual(await persistedExecutionState(restarted), {
    status: 'succeeded',
    reconciliationContextJson: null,
    reconciliationContextRequired: 1,
  });
});

test('running required contexts are parsed and intent-bound before owner recovery', async () => {
  for (const [label, tamper] of [
    ['malformed', (database, jobId) => {
      const statement = database.prepare(`UPDATE sync_jobs
        SET reconciliation_context_json = '{}' WHERE id = ?`);
      try { statement.run([jobId]); } finally { statement.free(); }
    }],
    ['intent-mismatch', (database, jobId) => {
      const statement = database.prepare(`UPDATE sync_jobs
        SET payload_json = ? WHERE id = ?`);
      try {
        statement.run([JSON.stringify({
          snapshotVersion: '9'.repeat(64),
          planIntentVersion: PLAN_INTENT_VERSION,
        }), jobId]);
      } finally {
        statement.free();
      }
    }],
  ]) {
    const file = databasePath('running-context-' + label);
    const db = new PanelDb(file);
    const job = await createTokenImportJob(db);
    await db.startMutationJob(job.id, { reconciliationContext: buildContext() });
    await db.write((database) => tamper(database, job.id));

    await assert.rejects(
      new PanelDb(file).ready,
      (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
    );
  }
});

test('dead token-import owner keeps conservative targets and requires manual reconciliation', async () => {
  const previousEnvironment = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    insecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_ADMIN_TOKEN = ADMIN_TOKEN;
  process.env.PANEL_REQUIRE_AUTH = '1';
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '0';

  const file = databasePath('dead-owner');
  const ownerDb = new PanelDb(file);
  const job = await createTokenImportJob(ownerDb);
  const context = buildContext([importPlanItem(7)]);
  await ownerDb.startMutationJob(job.id, { reconciliationContext: context });
  await makeOwnerDead(ownerDb, job.id);

  const recoveredDb = new PanelDb(file);
  const recoveredPublic = await recoveredDb.getJob(job.id);
  assert.equal(recoveredPublic.status, 'interrupted');
  assert.equal(recoveredPublic.result.executionOutcome, 'unknown');
  assert.equal(recoveredPublic.result.reconciliationHold, true);
  assert.equal(Object.hasOwn(recoveredPublic.result, 'imported'), false);
  assert.equal(Object.hasOwn(recoveredPublic.result, 'reconciliationCount'), false);
  assert.equal(Object.hasOwn(recoveredPublic, 'reconciliationContext'), false);

  const recoveredReviewJob = await recoveredDb.getJobForReconciliation(job.id);
  const detail = reconciliationReviewDetail(recoveredReviewJob, {
    currentImportTargetFingerprint: EXECUTION_TARGET.fingerprint,
  });
  assert.equal(detail.targetContext.coverage, TOKEN_IMPORT_CONTEXT_COVERAGE);
  assert.equal(detail.targetContext.total, 1);
  assert.equal(detail.targetContext.returned, 1);
  assert.equal(detail.targetContext.truncated, false);
  assert.equal(detail.targetContext.targets[0].targetDigest, context.targets[0].targetDigest);
  assert.equal(detail.targetContext.targets[0].sourcePath, 'tokens/account-00007.json');
  assert.deepEqual(detail.targetContext.createGroupBinding, {
    mode: 'explicit',
    groupIds: [7],
  });
  assert.equal(detail.targetContext.executionTarget.currentMatches, true);
  assert.equal(detail.targetContext.manifestDigest, context.manifestDigest);

  const logger = {
    requestId: () => 'token-import-reconciliation-db-test',
    probe: () => true,
    checkpoint: () => true,
    info() {},
    warn() {},
    error() {},
  };
  let currentTargetFingerprint = `sha256.${'U'.repeat(43)}`;
  const server = createServer({
    db: recoveredDb,
    logger,
    syncTargetBindingResolver: () => ({
      schema: 'sub2api-admin-target-v1',
      fingerprint: currentTargetFingerprint,
    }),
  });
  try {
    const baseUrl = await listen(server);
    const detailRoute = `/api/jobs/${encodeURIComponent(job.id)}/reconciliation`;
    const route = `/api/jobs/${encodeURIComponent(job.id)}/reconciliation/acknowledge`;
    const acknowledgement = {
      jobId: job.id,
      confirmation: RECONCILIATION_ACK_CONFIRMATION,
      claimDigest: recoveredPublic.result.reconciliationClaimDigest,
      contextDigest: detail.reconciliationContextDigest,
    };

    const mismatchedDetail = await requestJson(baseUrl, detailRoute, {
      token: ADMIN_TOKEN,
    });
    assert.equal(mismatchedDetail.status, 200);
    assert.equal(mismatchedDetail.json.targetContext.executionTarget.currentMatches, false);
    assert.equal(mismatchedDetail.json.targetContext.manifestDigest, context.manifestDigest);

    const wrongTarget = await requestJson(baseUrl, route, {
      method: 'POST',
      token: ADMIN_TOKEN,
      body: { ...acknowledgement, resolution: 'state_manually_reconciled' },
    });
    assert.equal(wrongTarget.status, 409);
    assert.equal(wrongTarget.json.error, 'JOB_RECONCILIATION_TARGET_MISMATCH');
    assert.equal((await recoveredDb.getJob(job.id)).result.reconciliationHold, true);
    currentTargetFingerprint = EXECUTION_TARGET.fingerprint;
    const matchingDetail = await requestJson(baseUrl, detailRoute, {
      token: ADMIN_TOKEN,
    });
    assert.equal(matchingDetail.status, 200);
    assert.equal(matchingDetail.json.targetContext.executionTarget.currentMatches, true);
    assert.equal(
      matchingDetail.json.reconciliationContextDigest,
      detail.reconciliationContextDigest,
    );

    const nonManual = await requestJson(baseUrl, route, {
      method: 'POST',
      token: ADMIN_TOKEN,
      body: { ...acknowledgement, resolution: 'operation_applied' },
    });
    assert.equal(nonManual.status, 409);
    assert.equal(
      nonManual.json.error,
      'JOB_RECONCILIATION_RESOLUTION_REQUIRES_MANUAL_RECONCILIATION',
    );
    assert.equal((await recoveredDb.getJob(job.id)).result.reconciliationHold, true);

    const replacementContext = buildTokenImportReconciliationContext([importPlanItem(7)], {
      snapshotVersion: '9'.repeat(64),
      planIntentVersion: `sync-plan-v1.${'C'.repeat(43)}`,
      groupBinding: { mode: 'explicit', groupIds: [7] },
      executionBinding: { target: EXECUTION_TARGET },
    });
    assert.equal(
      replacementContext.targets[0].targetDigest,
      context.targets[0].targetDigest,
    );
    assert.notEqual(replacementContext.manifestDigest, context.manifestDigest);
    await recoveredDb.write((database) => {
      const statement = database.prepare(`UPDATE sync_jobs
        SET payload_json = ?, reconciliation_context_json = ? WHERE id = ?`);
      try {
        statement.run([
          JSON.stringify({
            snapshotVersion: replacementContext.snapshotVersion,
            planIntentVersion: replacementContext.planIntentVersion,
          }),
          JSON.stringify(replacementContext),
          job.id,
        ]);
      } finally {
        statement.free();
      }
    });
    const staleManifest = await requestJson(baseUrl, route, {
      method: 'POST',
      token: ADMIN_TOKEN,
      body: { ...acknowledgement, resolution: 'state_manually_reconciled' },
    });
    assert.equal(staleManifest.status, 409);
    assert.equal(staleManifest.json.error, 'JOB_RECONCILIATION_CONTEXT_DIGEST_MISMATCH');
    assert.equal((await recoveredDb.getJob(job.id)).result.reconciliationHold, true);

    const refreshedReviewJob = await recoveredDb.getJobForReconciliation(job.id);
    const refreshedDetail = reconciliationReviewDetail(refreshedReviewJob, {
      currentImportTargetFingerprint: EXECUTION_TARGET.fingerprint,
    });

    const manual = await requestJson(baseUrl, route, {
      method: 'POST',
      token: ADMIN_TOKEN,
      body: {
        ...acknowledgement,
        contextDigest: refreshedDetail.reconciliationContextDigest,
        resolution: 'state_manually_reconciled',
      },
    });
    assert.equal(manual.status, 200);
    assert.equal(manual.json.resolution, 'state_manually_reconciled');
    assert.equal(manual.json.releasedClaimCount, 1);

    const resolved = await recoveredDb.getJob(job.id);
    assert.equal(resolved.result.reconciliationHold, false);
    assert.equal(resolved.result.reconciliationResolved, true);
    assert.equal(resolved.result.futureOperationsUnblocked, true);
    assert.deepEqual(await persistedExecutionState(recoveredDb), {
      status: 'interrupted',
      reconciliationContextJson: null,
      reconciliationContextRequired: 1,
    });
  } finally {
    await close(server);
    if (previousEnvironment.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previousEnvironment.token;
    if (previousEnvironment.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previousEnvironment.requireAuth;
    if (previousEnvironment.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previousEnvironment.writeEnabled;
    if (previousEnvironment.insecureWrite === undefined) {
      delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    } else {
      process.env.PANEL_ALLOW_INSECURE_WRITE = previousEnvironment.insecureWrite;
    }
  }
});

test('a required import context cannot be erased to downgrade a hold into legacy review', async () => {
  const file = databasePath('context-downgrade');
  const ownerDb = new PanelDb(file);
  const job = await createTokenImportJob(ownerDb);
  await ownerDb.startMutationJob(job.id, { reconciliationContext: buildContext() });
  await makeOwnerDead(ownerDb, job.id);

  const recoveredDb = new PanelDb(file);
  assert.equal((await recoveredDb.getJob(job.id)).result.reconciliationHold, true);
  await recoveredDb.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET reconciliation_context_json = NULL WHERE id = ?`);
    try {
      statement.run([job.id]);
    } finally {
      statement.free();
    }
  });

  await assert.rejects(
    recoveredDb.getJobForReconciliation(job.id),
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
});

test('reconciliation detail rejects a held job whose actual claim mapping was removed', async () => {
  const file = databasePath('claim-mapping');
  const ownerDb = new PanelDb(file);
  const job = await createTokenImportJob(ownerDb);
  await ownerDb.startMutationJob(job.id, { reconciliationContext: buildContext() });
  await makeOwnerDead(ownerDb, job.id);

  const recoveredDb = new PanelDb(file);
  assert.equal((await recoveredDb.getJob(job.id)).result.reconciliationHold, true);
  await recoveredDb.write((database) => {
    const statement = database.prepare('DELETE FROM job_claims WHERE job_id = ?');
    try {
      statement.run([job.id]);
    } finally {
      statement.free();
    }
  });

  await assert.rejects(
    recoveredDb.getJobForReconciliation(job.id),
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
});
