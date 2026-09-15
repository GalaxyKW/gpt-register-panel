const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { PanelDb, RECONCILIATION_ACK_CONFIRMATION } = require('../backend/db');
const {
  canonicalJson,
  mutationRequestDigest,
  promptDigest,
  requestIdempotencyKey,
} = require('../backend/idempotency');

function databasePath(label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-idempotency-' + label + '-'));
  return path.join(root, 'panel.sqlite3');
}

function submissionOptions(overrides = {}) {
  return {
    workflow: 'token_import',
    requestedBy: 'panel-admin',
    idempotencyKey: 'idem_v1_123456789012345678901234567890',
    requestDigest: 'a'.repeat(64),
    jobs: [{
      type: 'token_import',
      payload: { snapshotVersion: 'b'.repeat(64) },
      claimKeys: ['token_import'],
    }],
    responseFactory: ({ createdJobs }) => ({
      jobId: createdJobs[0].job.id,
      status: 'queued',
    }),
    ...overrides,
  };
}

function acknowledge(db, job, resolution = 'state_manually_reconciled') {
  return db.acknowledgeJobReconciliation(job.id, {
    actor: 'panel-admin',
    confirmation: RECONCILIATION_ACK_CONFIRMATION,
    resolution,
    claimDigest: job.result.reconciliationClaimDigest,
  });
}

test('Idempotency-Key and semantic request digests use strict canonical boundaries', () => {
  const valid = 'idem_v1_12345678901234567890';
  const secondKey = 'idem_v1_09876543210987654321';
  assert.equal(requestIdempotencyKey({
    headers: { 'idempotency-key': valid },
    rawHeaders: ['Idempotency-Key', valid],
  }), valid);
  for (const request of [
    { headers: {}, rawHeaders: [] },
    { headers: { 'idempotency-key': 'short' }, rawHeaders: ['Idempotency-Key', 'short'] },
    {
      headers: { 'idempotency-key': valid + ', ' + valid },
      rawHeaders: ['Idempotency-Key', valid, 'idempotency-key', valid],
    },
    {
      headers: { 'idempotency-key': valid + ' ' },
      rawHeaders: ['Idempotency-Key', valid + ' '],
    },
  ]) assert.throws(() => requestIdempotencyKey(request), /Idempotency-Key/);

  assert.equal(canonicalJson({ b: [2, 1], a: true }), '{"a":true,"b":[2,1]}');
  assert.equal(
    mutationRequestDigest('account_test', { modelId: 'm', targets: [{ accountId: 1 }] }, valid),
    mutationRequestDigest('account_test', { targets: [{ accountId: 1 }], modelId: 'm' }, valid),
  );
  assert.notEqual(
    mutationRequestDigest('account_test', { modelId: 'm', targets: [{ accountId: 1 }] }, valid),
    mutationRequestDigest('account_test', { modelId: 'm', targets: [{ accountId: 1 }] }, secondKey),
  );
  assert.notEqual(promptDigest('first'), promptDigest('second'));
  assert.equal(promptDigest('first').includes('first'), false);
});

test('Idempotency-Key rejects synthetic or ambiguous header representations', () => {
  const valid = 'idem_v1_12345678901234567890';
  for (const request of [
    { headers: { 'idempotency-key': valid }, rawHeaders: [] },
    {
      headers: { 'idempotency-key': valid },
      rawHeaders: ['Idempotency-Key', valid + '-different'],
    },
    {
      headers: { 'idempotency-key': valid },
      rawHeaders: ['Idempotency-Key'],
    },
    {
      headers: Object.create({ 'idempotency-key': valid }),
      rawHeaders: ['Idempotency-Key', valid],
    },
  ]) {
    assert.throws(
      () => requestIdempotencyKey(request),
      (error) => ['IDEMPOTENCY_KEY_INVALID', 'IDEMPOTENCY_KEY_REQUIRED'].includes(error.code),
    );
  }
});

test('canonical request encoding rejects array holes, hidden extras and recursive shapes', () => {
  const sparse = [];
  sparse.length = 1;
  const extra = [1];
  extra.intent = 'different';
  const symbolic = { safe: true };
  symbolic[Symbol('intent')] = 'different';
  const cyclic = {};
  cyclic.self = cyclic;
  let tooDeep = true;
  for (let index = 0; index < 65; index += 1) tooDeep = [tooDeep];

  for (const value of [sparse, extra, symbolic, cyclic, tooDeep]) {
    assert.throws(
      () => canonicalJson(value),
      (error) => error.code === 'IDEMPOTENCY_REQUEST_INVALID',
    );
  }
  assert.throws(
    () => promptDigest({ toString: () => 'silently-coerced' }),
    (error) => error.code === 'IDEMPOTENCY_REQUEST_INVALID',
  );
});

test('a receipt replays the exact response across terminal state and database restart', async () => {
  const file = databasePath('restart');
  const firstDb = new PanelDb(file);
  const options = submissionOptions();
  const created = await firstDb.createMutationSubmission(options);
  assert.equal(created.replayed, false);
  assert.equal(created.receipt.statusCode, 202);
  assert.equal(created.createdJobs.length, 1);
  const originalResponse = created.receipt.response;
  await firstDb.updateJob(created.createdJobs[0].job.id, {
    status: 'succeeded',
    result: { succeeded: 1 },
    finishedAt: new Date().toISOString(),
  });

  const restarted = new PanelDb(file);
  const lookup = await restarted.getMutationReceipt({
    workflow: options.workflow,
    requestedBy: options.requestedBy,
    idempotencyKey: options.idempotencyKey,
    requestDigest: options.requestDigest,
  });
  assert.deepEqual(lookup.response, originalResponse);
  const replay = await restarted.createMutationSubmission(options);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.receipt.response, originalResponse);
  assert.equal((await restarted.listJobs()).length, 1);
  await assert.rejects(
    restarted.getMutationReceipt({
      workflow: options.workflow,
      requestedBy: options.requestedBy,
      idempotencyKey: options.idempotencyKey,
      requestDigest: 'c'.repeat(64),
    }),
    (error) => error.code === 'IDEMPOTENCY_KEY_REUSED',
  );
});

test('receipt schema without a single-column unique key hash fails closed on restart', async () => {
  const file = databasePath('duplicate-receipt-schema');
  const db = new PanelDb(file);
  const options = submissionOptions({
    idempotencyKey: 'idem_v1_duplicate_receipt_schema_1234567890',
  });
  await db.createMutationSubmission(options);

  await db.write((database) => database.run(`
    ALTER TABLE mutation_receipts RENAME TO mutation_receipts_with_identity;
    CREATE TABLE mutation_receipts (
      key_hash TEXT NOT NULL,
      workflow TEXT NOT NULL,
      request_digest TEXT NOT NULL,
      http_status INTEGER NOT NULL,
      response_json TEXT NOT NULL,
      job_ids_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    INSERT INTO mutation_receipts SELECT * FROM mutation_receipts_with_identity;
    INSERT INTO mutation_receipts SELECT * FROM mutation_receipts_with_identity;
    DROP TABLE mutation_receipts_with_identity;
  `));

  assert.equal(await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM mutation_receipts')[0].values[0][0],
  )), 2);
  await assert.rejects(
    new PanelDb(file).ready,
    (error) => error.code === 'IDEMPOTENCY_RECEIPT_INVALID'
      && /主键或唯一性/.test(error.message),
  );
  assert.equal(await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM mutation_receipts')[0].values[0][0],
  )), 2);
});

test('the durable database stores neither the raw key nor an account-test prompt', async () => {
  const file = databasePath('secret-boundary');
  const db = new PanelDb(file);
  const rawKey = 'idem_v1_raw_key_marker_12345678901234567';
  const rawPrompt = 'prompt-marker-that-must-never-be-durable';
  const requestDigest = mutationRequestDigest('account_test', {
    targets: [{ accountId: 7, targetRevision: 'account-test-v1.' + 'A'.repeat(43) }],
    modelId: 'gpt-5.6-luna',
    promptDigest: promptDigest(rawPrompt),
  }, rawKey);
  await db.createMutationSubmission(submissionOptions({
    workflow: 'account_test',
    idempotencyKey: rawKey,
    requestDigest,
    jobs: [{
      type: 'account_test',
      payload: { accountIds: [7], promptPresent: true, promptLength: rawPrompt.length },
      claimKeys: ['account_test:7'],
    }],
  }));
  const bytes = fs.readFileSync(file);
  assert.equal(bytes.includes(Buffer.from(rawKey)), false);
  assert.equal(bytes.includes(Buffer.from(rawPrompt)), false);
});

test('two PanelDb instances atomically converge on one job for the same key', async () => {
  const file = databasePath('concurrent');
  const firstDb = new PanelDb(file);
  const secondDb = new PanelDb(file);
  await Promise.all([firstDb.ready, secondDb.ready]);
  const options = submissionOptions({
    idempotencyKey: 'idem_v1_concurrent_12345678901234567890',
    jobs: [{ type: 'phase3', payload: { ordinal: 1 }, claimKeys: ['phase3:account:1'] }],
  });
  const results = await Promise.all([
    firstDb.createMutationSubmission(options),
    secondDb.createMutationSubmission(options),
  ]);
  assert.deepEqual(results.map((item) => item.replayed).sort(), [false, true]);
  assert.equal(results[0].receipt.response.jobId, results[1].receipt.response.jobId);
  assert.equal((await firstDb.listJobs()).length, 1);
});

test('multi-job admission stores jobs, claims, partial decisions and receipt in one transaction', async () => {
  const db = new PanelDb(databasePath('batch'));
  const blocker = await db.createJob('phase3', {}, 'panel-admin', {
    claimKeys: ['phase3:email:block@example.test'],
  });
  const options = submissionOptions({
    workflow: 'phase3',
    idempotencyKey: 'idem_v1_batch_123456789012345678901234',
    requestDigest: 'd'.repeat(64),
    allowPartial: true,
    maximumActiveByType: { phase3: 100 },
    jobs: [
      { type: 'phase3', payload: { ordinal: 1 }, claimKeys: ['phase3:email:a@example.test'], metadata: { ordinal: 1 } },
      { type: 'phase3', payload: { ordinal: 2 }, claimKeys: ['phase3:email:b@example.test'], metadata: { ordinal: 2 } },
      { type: 'phase3', payload: { ordinal: 3 }, claimKeys: ['phase3:email:block@example.test'], metadata: { ordinal: 3 } },
      { type: 'phase3', payload: { ordinal: 4 }, claimKeys: ['phase3:email:a@example.test'], metadata: { ordinal: 4 } },
    ],
    responseFactory: ({ createdJobs, rejections }) => ({
      status: 'queued',
      jobIds: createdJobs.map((item) => item.job.id),
      accepted: createdJobs.map((item) => item.metadata.ordinal),
      rejected: rejections.map((item) => ({
        ordinal: item.metadata.ordinal,
        reason: item.reason,
        existingJobId: item.existingJobId || null,
      })),
    }),
  });
  const created = await db.createMutationSubmission(options);
  assert.equal(created.createdJobs.length, 2);
  assert.deepEqual(created.receipt.response.accepted, [1, 2]);
  assert.deepEqual(created.receipt.response.rejected.map((item) => item.reason), [
    'claim_conflict',
    'duplicate_in_submission',
  ]);
  assert.equal(created.receipt.response.rejected[0].existingJobId, blocker.id);
  const replay = await db.createMutationSubmission(options);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.receipt.response, created.receipt.response);
  assert.equal((await db.listJobs()).length, 3);
});

test('receipt construction failure rolls back every job and claim', async () => {
  const db = new PanelDb(databasePath('rollback'));
  const options = submissionOptions({
    idempotencyKey: 'idem_v1_rollback_12345678901234567890',
    jobs: [
      { type: 'phase3', payload: { ordinal: 1 }, claimKeys: ['phase3:rollback:1'] },
      { type: 'phase3', payload: { ordinal: 2 }, claimKeys: ['phase3:rollback:2'] },
    ],
    responseFactory: () => ({ oversized: 'x'.repeat(70 * 1024) }),
  });
  await assert.rejects(
    db.createMutationSubmission(options),
    (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE',
  );
  assert.equal((await db.listJobs()).length, 0);
  const replacement = await db.createJob('phase3', {}, 'panel-admin', {
    claimKeys: ['phase3:rollback:1'],
  });
  assert.match(replacement.id, /^job_[a-f0-9]{24}$/);
});

test('response formatting cannot rewrite the durable receipt job graph', async () => {
  const db = new PanelDb(databasePath('response-factory-isolation'));
  let originalIds;
  const options = submissionOptions({
    idempotencyKey: 'idem_v1_response_factory_isolation_1234567890',
    jobs: [
      { type: 'phase3', payload: { ordinal: 1 }, claimKeys: ['phase3:factory:1'] },
      { type: 'phase3', payload: { ordinal: 2 }, claimKeys: ['phase3:factory:2'] },
    ],
    responseFactory: ({ createdJobs }) => {
      originalIds = createdJobs.map((item) => item.job.id);
      createdJobs[0].job.id = 'job_' + 'f'.repeat(24);
      createdJobs.splice(0, 1);
      return { status: 'queued', jobIds: originalIds };
    },
  });

  const created = await db.createMutationSubmission(options);
  assert.deepEqual(created.receipt.jobIds, originalIds);
  assert.deepEqual(
    created.createdJobs.map((item) => item.job.id),
    originalIds,
  );
  for (const id of originalIds) {
    await db.updateJob(id, { status: 'failed', error: 'test cleanup' });
  }
  const replay = await db.createMutationSubmission(options);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.receipt.jobIds, originalIds);
});

test('receipt capacity fails closed and does not evict an unexpired receipt', async () => {
  const previous = process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
  process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = '1';
  try {
    const db = new PanelDb(databasePath('capacity'));
    const first = submissionOptions({
      idempotencyKey: 'idem_v1_capacity_first_123456789012345',
      jobs: [{ type: 'phase3', payload: {}, claimKeys: ['phase3:capacity:1'] }],
    });
    const created = await db.createMutationSubmission(first);
    await assert.rejects(
      db.createMutationSubmission(submissionOptions({
        idempotencyKey: 'idem_v1_capacity_second_12345678901234',
        requestDigest: 'e'.repeat(64),
        jobs: [{ type: 'phase3', payload: {}, claimKeys: ['phase3:capacity:2'] }],
      })),
      (error) => error.code === 'IDEMPOTENCY_CAPACITY_EXCEEDED',
    );
    const replay = await db.createMutationSubmission(first);
    assert.equal(replay.replayed, true);
    assert.equal(replay.receipt.response.jobId, created.receipt.response.jobId);
    assert.equal((await db.listJobs()).length, 1);
  } finally {
    if (previous === undefined) delete process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
    else process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = previous;
  }
});

test('expiry releases only ordinary terminal receipts and pins active work', async () => {
  const db = new PanelDb(databasePath('expiry'));
  const terminalOptions = submissionOptions({
    idempotencyKey: 'idem_v1_expired_terminal_123456789012345',
  });
  const terminal = await db.createMutationSubmission(terminalOptions);
  await db.updateJob(terminal.createdJobs[0].job.id, {
    status: 'succeeded',
    result: {},
    finishedAt: new Date().toISOString(),
  });
  await db.write((database) => database.run(
    "UPDATE mutation_receipts SET created_at = '1999-01-01T00:00:00.000Z', expires_at = '2000-01-01T00:00:00.000Z'",
  ));
  assert.equal(await db.getMutationReceipt({
    workflow: terminalOptions.workflow,
    requestedBy: terminalOptions.requestedBy,
    idempotencyKey: terminalOptions.idempotencyKey,
    requestDigest: terminalOptions.requestDigest,
  }), null);

  const activeOptions = submissionOptions({
    idempotencyKey: 'idem_v1_expired_active_12345678901234567',
    requestDigest: 'f'.repeat(64),
    jobs: [{ type: 'phase3', payload: {}, claimKeys: ['phase3:expiry:active'] }],
  });
  const active = await db.createMutationSubmission(activeOptions);
  await db.write((database) => database.run(
    "UPDATE mutation_receipts SET created_at = '1999-01-01T00:00:00.000Z', expires_at = '2000-01-01T00:00:00.000Z'",
  ));
  const pinned = await db.getMutationReceipt({
    workflow: activeOptions.workflow,
    requestedBy: activeOptions.requestedBy,
    idempotencyKey: activeOptions.idempotencyKey,
    requestDigest: activeOptions.requestDigest,
  });
  assert.equal(pinned.response.jobId, active.receipt.response.jobId);
});

test('bounded receipt projections reject polluted stored fields before replay', async () => {
  const corruptions = [
    ['key_hash', 'k'.repeat(65)],
    ['workflow', 'w'.repeat(65)],
    ['request_digest', Buffer.from('a'.repeat(64))],
    ['http_status', 'not-an-integer'],
    ['response_json', JSON.stringify({ status: 'queued', padding: 'x'.repeat(70 * 1024) })],
    ['job_ids_json', Buffer.from('[]')],
    ['created_at', 'not-a-canonical-timestamp'],
    ['expires_at', Buffer.from('2099-01-01T00:00:00.000Z')],
  ];
  for (const [field, value] of corruptions) {
    const db = new PanelDb(databasePath('polluted-receipt-' + field));
    const options = submissionOptions({
      idempotencyKey: 'idem_v1_polluted_' + field + '_12345678901234567890',
    });
    await db.createMutationSubmission(options);
    await db.write((database) => {
      const statement = database.prepare(`UPDATE mutation_receipts SET ${field} = ?`);
      try { statement.run([value]); } finally { statement.free(); }
    });
    await assert.rejects(
      db.getMutationReceipt({
        workflow: options.workflow,
        requestedBy: options.requestedBy,
        idempotencyKey: options.idempotencyKey,
        requestDigest: options.requestDigest,
      }),
      (error) => error.code === 'IDEMPOTENCY_RECEIPT_INVALID',
      field,
    );
  }
});

test('linked receipt projections reject polluted identity, state and reconciliation fields', async () => {
  const corruptions = [
    'id',
    'status',
    'submission_key_hash',
    'reconciliation_hold',
    'reconciliation_scope',
    'reconciliation_claim_digest',
    'reconciliation_acknowledged_at',
    'reconciliation_resolution',
    'reconciliation_acknowledged_by',
  ];
  for (const corruption of corruptions) {
    const db = new PanelDb(databasePath('polluted-linked-' + corruption));
    const options = submissionOptions({
      idempotencyKey: 'idem_v1_linked_' + corruption + '_1234567890123456789012',
    });
    const created = await db.createMutationSubmission(options);
    await db.updateJob(created.createdJobs[0].job.id, {
      status: 'succeeded',
      result: {},
      finishedAt: new Date().toISOString(),
    });
    await db.write((database) => {
      if (corruption !== 'id') {
        const values = {
          status: 'terminal-but-invalid',
          submission_key_hash: Buffer.from('f'.repeat(64)),
          reconciliation_hold: Buffer.from([0]),
          reconciliation_scope: Buffer.from('claims'),
          reconciliation_claim_digest: Buffer.from('a'.repeat(64)),
          reconciliation_acknowledged_at: Buffer.from('2099-01-01T00:00:00.000Z'),
          reconciliation_resolution: Buffer.from('operation_applied'),
          reconciliation_acknowledged_by: Buffer.from('panel-admin'),
        };
        const update = database.prepare(`UPDATE sync_jobs SET ${corruption} = ?`);
        try { update.run([values[corruption]]); } finally { update.free(); }
        return;
      }
      const invalidId = 'job_invalid';
      const updateJob = database.prepare('UPDATE sync_jobs SET id = ?');
      const updateReceipt = database.prepare(`UPDATE mutation_receipts
        SET response_json = ?, job_ids_json = ?`);
      try {
        updateJob.run([invalidId]);
        updateReceipt.run([
          JSON.stringify({ jobId: invalidId, status: 'queued' }),
          JSON.stringify([invalidId]),
        ]);
      } finally {
        updateReceipt.free();
        updateJob.free();
      }
    });
    await assert.rejects(
      db.getMutationReceipt({
        workflow: options.workflow,
        requestedBy: options.requestedBy,
        idempotencyKey: options.idempotencyKey,
        requestDigest: options.requestDigest,
      }),
      (error) => error.code === 'IDEMPOTENCY_RECEIPT_INVALID'
        || error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
      corruption,
    );
  }
});

test('receipt graph validation rejects more linked rows than one submission can own', async () => {
  const db = new PanelDb(databasePath('linked-row-limit'));
  const options = submissionOptions({
    idempotencyKey: 'idem_v1_linked_row_limit_12345678901234567890',
  });
  const created = await db.createMutationSubmission(options);
  await db.updateJob(created.createdJobs[0].job.id, {
    status: 'succeeded',
    result: {},
    finishedAt: new Date().toISOString(),
  });
  await db.write((database) => {
    const keyHash = database.exec('SELECT key_hash FROM mutation_receipts')[0].values[0][0];
    const insert = database.prepare(`INSERT INTO sync_jobs
      (id, type, status, requested_by, payload_json, result_json, created_at,
        finished_at, claim_keys_json, reconciliation_hold, submission_key_hash)
      VALUES (?, 'phase3', 'succeeded', 'panel-admin', '{}', '{}', ?, ?, '[]', 0, ?)`);
    try {
      for (let index = 0; index < 100; index += 1) {
        const id = 'job_e' + index.toString(16).padStart(23, '0');
        const timestamp = new Date(Date.UTC(2099, 0, 1, 0, 0, index)).toISOString();
        insert.run([id, timestamp, timestamp, keyHash]);
      }
    } finally {
      insert.free();
    }
  });
  await assert.rejects(
    db.getMutationReceipt({
      workflow: options.workflow,
      requestedBy: options.requestedBy,
      idempotencyKey: options.idempotencyKey,
      requestDigest: options.requestDigest,
    }),
    (error) => error.code === 'IDEMPOTENCY_RECEIPT_INVALID',
  );
});

test('an acknowledged reconciliation permanently pins exact replay and digest conflict', async () => {
  const db = new PanelDb(databasePath('acknowledged-pin'));
  const options = submissionOptions({
    idempotencyKey: 'idem_v1_acknowledged_pin_12345678901234567890',
    jobs: [{ type: 'phase3', payload: {}, claimKeys: ['phase3:acknowledged-pin'] }],
  });
  const created = await db.createMutationSubmission(options);
  const jobId = created.createdJobs[0].job.id;
  await db.updateJob(jobId, { status: 'running', startedAt: new Date().toISOString() });
  await db.updateJob(jobId, {
    status: 'interrupted',
    result: {
      code: 'REMOTE_WRITE_OUTCOME_UNKNOWN',
      writeOutcomeUnknown: true,
      requiresReconciliation: true,
      retryAllowed: false,
      doNotRetry: true,
    },
    finishedAt: new Date().toISOString(),
  });
  await db.write((database) => database.run(`UPDATE mutation_receipts
    SET created_at = '1999-01-01T00:00:00.000Z',
        expires_at = '2000-01-01T00:00:00.000Z'`));
  const held = await db.getJob(jobId);
  await acknowledge(db, held, 'operation_applied');

  const exactReplay = await db.createMutationSubmission(options);
  assert.equal(exactReplay.replayed, true);
  assert.deepEqual(exactReplay.receipt.response, created.receipt.response);
  await assert.rejects(
    db.createMutationSubmission({ ...options, requestDigest: '9'.repeat(64) }),
    (error) => error.code === 'IDEMPOTENCY_KEY_REUSED',
  );
  const previousMaximum = process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
  process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = '1';
  try {
    await assert.rejects(
      db.createMutationSubmission(submissionOptions({
        idempotencyKey: 'idem_v1_after_ack_capacity_123456789012345678',
        requestDigest: '8'.repeat(64),
        jobs: [{ type: 'phase3', payload: {}, claimKeys: ['phase3:after-ack-capacity'] }],
      })),
      (error) => error.code === 'IDEMPOTENCY_CAPACITY_EXCEEDED',
    );
  } finally {
    if (previousMaximum === undefined) delete process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
    else process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = previousMaximum;
  }
  assert.equal((await db.listJobs()).length, 1);
  assert.equal(await db.read((database) => Number(
    database.exec('SELECT COUNT(*) FROM mutation_receipts')[0].values[0][0],
  )), 1);
});

test('legacy reconciliation signals migrate before expired receipt pruning', async () => {
  const db = new PanelDb(databasePath('legacy-before-prune'));
  const options = submissionOptions({
    idempotencyKey: 'idem_v1_legacy_before_prune_12345678901234567',
    jobs: [{ type: 'phase3', payload: {}, claimKeys: ['phase3:legacy-before-prune'] }],
  });
  const created = await db.createMutationSubmission(options);
  const jobId = created.createdJobs[0].job.id;
  const originalPruneRows = db.pruneRows;
  db.pruneRows = () => {};
  try {
    await db.write((database) => {
      const legacyResult = JSON.stringify({
        code: 'LEGACY_WRITE_OUTCOME_UNKNOWN',
        writeOutcomeUnknown: true,
        requiresReconciliation: true,
        retryAllowed: false,
        doNotRetry: true,
      });
      const update = database.prepare(`UPDATE sync_jobs
        SET status = 'interrupted', result_json = ?, finished_at = ?,
          reconciliation_hold = 0, reconciliation_scope = NULL,
          reconciliation_claim_digest = NULL, reconciliation_acknowledged_at = NULL,
          reconciliation_resolution = NULL, reconciliation_acknowledged_by = NULL
        WHERE id = ?`);
      try { update.run([legacyResult, new Date().toISOString(), jobId]); } finally { update.free(); }
      database.run(`DELETE FROM job_claims WHERE job_id = '${jobId}'`);
      database.run(`UPDATE mutation_receipts
        SET created_at = '1999-01-01T00:00:00.000Z',
            expires_at = '2000-01-01T00:00:00.000Z'`);
    });
  } finally {
    db.pruneRows = originalPruneRows;
  }

  const receipt = await db.getMutationReceipt({
    workflow: options.workflow,
    requestedBy: options.requestedBy,
    idempotencyKey: options.idempotencyKey,
    requestDigest: options.requestDigest,
  });
  assert.deepEqual(receipt.response, created.receipt.response);
  const migrated = await db.getJob(jobId);
  assert.equal(migrated.result.requiresReconciliation, true);
  assert.equal(migrated.result.reconciliationHold, true);
  assert.equal(migrated.result.retryAllowed, false);
});

test('expired receipts with missing or extra linked jobs remain fail-closed across restart', async () => {
  for (const corruption of ['missing', 'extra']) {
    const file = databasePath('corrupt-' + corruption);
    const db = new PanelDb(file);
    const options = submissionOptions({
      idempotencyKey: 'idem_v1_corrupt_' + corruption + '_12345678901234567890',
      jobs: [{
        type: 'phase3',
        payload: { corruption },
        claimKeys: ['phase3:corrupt:' + corruption],
      }],
    });
    const submission = await db.createMutationSubmission(options);
    const jobId = submission.createdJobs[0].job.id;
    await db.updateJob(jobId, {
      status: 'succeeded',
      result: {},
      finishedAt: new Date().toISOString(),
    });

    // Persist a deliberately corrupt legacy state without letting the normal
    // post-write validator repair or reject the fixture itself.
    const originalPruneRows = db.pruneRows;
    db.pruneRows = () => {};
    try {
      await db.write((database) => {
        if (corruption === 'missing') {
          database.run(`DELETE FROM job_claims WHERE job_id = '${jobId}'`);
          database.run(`DELETE FROM sync_jobs WHERE id = '${jobId}'`);
        } else {
          const keyHash = database.exec('SELECT key_hash FROM mutation_receipts')[0].values[0][0];
          const insert = database.prepare(`INSERT INTO sync_jobs
            (id, type, status, requested_by, payload_json, result_json, created_at,
              finished_at, claim_keys_json, reconciliation_hold, submission_key_hash)
            VALUES (?, 'phase3', 'succeeded', 'panel-admin', '{}', '{}', ?, ?, '[]', 0, ?)`);
          try {
            const timestamp = new Date().toISOString();
            insert.run(['job_' + '9'.repeat(24), timestamp, timestamp, keyHash]);
          } finally {
            insert.free();
          }
        }
        database.run(`UPDATE mutation_receipts
          SET created_at = '1999-01-01T00:00:00.000Z',
              expires_at = '2000-01-01T00:00:00.000Z'`);
      });
    } finally {
      db.pruneRows = originalPruneRows;
    }

    await assert.rejects(
      db.getMutationReceipt({
        workflow: options.workflow,
        requestedBy: options.requestedBy,
        idempotencyKey: options.idempotencyKey,
        requestDigest: options.requestDigest,
      }),
      (error) => error.code === 'IDEMPOTENCY_RECEIPT_INVALID',
    );
    assert.equal(await db.read((database) => Number(
      database.exec('SELECT COUNT(*) FROM mutation_receipts')[0].values[0][0],
    )), 1);
    await assert.rejects(
      new PanelDb(file).ready,
      (error) => error.code === 'IDEMPOTENCY_RECEIPT_INVALID',
    );
  }
});

test('receipt graph validation streams bounded rows before any expiry mutation', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'backend', 'db.js'), 'utf8');
  const projectionStart = source.indexOf('function mutationReceiptSqlProjection(');
  const start = source.indexOf('function pruneExpiredMutationReceipts(');
  const end = source.indexOf('\nclass PanelDb', start);
  assert.ok(projectionStart >= 0 && start > projectionStart && end > start);
  const projectionsAndPrune = source.slice(projectionStart, end);
  const implementation = source.slice(start, end);
  assert.doesNotMatch(source, /SELECT \* FROM mutation_receipts/);
  assert.match(projectionsAndPrune, /typeof\(response_json\) = 'text'/);
  assert.match(projectionsAndPrune, /length\(CAST\(response_json AS BLOB\)\)/);
  assert.match(projectionsAndPrune, /has_reconciliation_history/);
  assert.match(implementation, /SELECT 1 AS orphan/);
  assert.match(implementation, /while \(receiptScan\.step\(\)\)/);
  assert.match(implementation, /LIMIT \$\{MAX_MUTATION_RECEIPT_JOBS \+ 1\}/);
  assert.match(implementation, /FROM mutation_receipts ORDER BY rowid ASC/);
  assert.match(implementation, /ORDER BY rowid ASC LIMIT \$\{MAX_MUTATION_RECEIPT_JOBS \+ 1\}/);
  assert.match(implementation, /No durable graph row is changed until the complete first pass succeeds/);
  assert.ok(implementation.indexOf('while (receiptScan.step())')
    < implementation.indexOf('UPDATE sync_jobs SET submission_key_hash = NULL'));
});

test('writes validate legacy claims before one receipt prune and do not prune again afterward', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'backend', 'db.js'), 'utf8');
  const start = source.indexOf('  async write(callback) {');
  const end = source.indexOf('\n  async read(callback)', start);
  assert.ok(start >= 0 && end > start);
  const implementation = source.slice(start, end);
  const validation = implementation.indexOf('validateJobClaims(this.database');
  const receiptPrune = implementation.indexOf('pruneExpiredMutationReceipts(this.database');
  const callback = implementation.indexOf('await callback(this.database)');
  const historyPrune = implementation.indexOf('this.pruneRows({ pruneMutationReceipts: false })');
  assert.ok(validation >= 0 && validation < receiptPrune);
  assert.ok(receiptPrune < callback && callback < historyPrune);
  assert.equal(implementation.match(/pruneExpiredMutationReceipts\(/g)?.length, 1);
});

test('job history pruning retains a terminal job referenced by an unexpired receipt', async () => {
  const previous = process.env.PANEL_MAX_JOBS;
  process.env.PANEL_MAX_JOBS = '100';
  try {
    const db = new PanelDb(databasePath('prune'));
    const options = submissionOptions({
      idempotencyKey: 'idem_v1_prune_123456789012345678901234',
    });
    const protectedSubmission = await db.createMutationSubmission(options);
    const protectedJobId = protectedSubmission.createdJobs[0].job.id;
    await db.updateJob(protectedJobId, {
      status: 'succeeded',
      result: {},
      finishedAt: new Date().toISOString(),
    });
    await db.write((database) => {
      const insert = database.prepare(`INSERT INTO sync_jobs
        (id, type, status, requested_by, payload_json, result_json, created_at,
          finished_at, claim_keys_json, reconciliation_hold)
        VALUES (?, 'preview', 'succeeded', 'local', '{}', '{}', ?, ?, '[]', 0)`);
      try {
        for (let index = 0; index < 101; index += 1) {
          const timestamp = new Date(Date.UTC(2099, 0, 1, 0, 0, index)).toISOString();
          insert.run(['job_' + String(index).padStart(24, '0'), timestamp, timestamp]);
        }
      } finally {
        insert.free();
      }
    });
    assert.ok(await db.getJob(protectedJobId));
    const receipt = await db.getMutationReceipt({
      workflow: options.workflow,
      requestedBy: options.requestedBy,
      idempotencyKey: options.idempotencyKey,
      requestDigest: options.requestDigest,
    });
    assert.equal(receipt.response.jobId, protectedJobId);
  } finally {
    if (previous === undefined) delete process.env.PANEL_MAX_JOBS;
    else process.env.PANEL_MAX_JOBS = previous;
  }
});
