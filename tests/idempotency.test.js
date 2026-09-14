const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { PanelDb } = require('../backend/db');
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
  const start = source.indexOf('function pruneExpiredMutationReceipts(');
  const end = source.indexOf('\nclass PanelDb', start);
  assert.ok(start >= 0 && end > start);
  const implementation = source.slice(start, end);
  assert.doesNotMatch(
    implementation,
    /resultRows\(database\.exec\([\s\S]*SELECT \* FROM mutation_receipts ORDER BY/,
  );
  assert.match(implementation, /while \(receiptScan\.step\(\)\)/);
  assert.match(implementation, /length\(CAST\(response_json AS BLOB\)\)/);
  assert.match(implementation, /LIMIT \$\{MAX_MUTATION_RECEIPT_JOBS \+ 1\}/);
  assert.match(implementation, /No durable graph row is changed until the complete first pass succeeds/);
  assert.ok(implementation.indexOf('while (receiptScan.step())')
    < implementation.indexOf('UPDATE sync_jobs SET submission_key_hash = NULL'));
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
