const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { PanelDb } = require('../backend/db');

function databasePath(label) {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'panel-claim-bounds-' + label + '-')),
    'panel.sqlite3',
  );
}

async function scalar(db, sql) {
  return db.read((database) => database.exec(sql)[0]?.values?.[0]?.[0]);
}

test('lowering retention prunes ordinary history instead of rejecting the database first', async () => {
  const previousJobs = process.env.PANEL_MAX_JOBS;
  const previousReceipts = process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
  process.env.PANEL_MAX_JOBS = '5000';
  process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = '1';
  try {
    const file = databasePath('retention-lowered');
    const db = new PanelDb(file);
    await db.write((database) => {
      const insert = database.prepare(`INSERT INTO sync_jobs
        (id, type, status, requested_by, payload_json, result_json, created_at,
          finished_at, claim_keys_json, reconciliation_hold)
        VALUES (?, 'fixture', 'succeeded', 'tester', '{}', '{}', ?, ?, '[]', 0)`);
      try {
        for (let index = 0; index < 201; index += 1) {
          insert.run([
            'job_retained_' + String(index).padStart(18, '0'),
            new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
            new Date(Date.UTC(2026, 0, 1, 0, 1, index)).toISOString(),
          ]);
        }
      } finally {
        insert.free();
      }
    });

    process.env.PANEL_MAX_JOBS = '100';
    const reopened = new PanelDb(file);
    await reopened.ready;
    assert.equal(await scalar(reopened, 'SELECT COUNT(*) FROM sync_jobs'), 100);
  } finally {
    if (previousJobs === undefined) delete process.env.PANEL_MAX_JOBS;
    else process.env.PANEL_MAX_JOBS = previousJobs;
    if (previousReceipts === undefined) delete process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
    else process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = previousReceipts;
  }
});

test('blank job retention config keeps the historical default retention target', async () => {
  const previousJobs = process.env.PANEL_MAX_JOBS;
  const previousReceipts = process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
  process.env.PANEL_MAX_JOBS = '';
  process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = '1';
  try {
    // A blank value historically means the 5000-row default. If it were
    // accidentally coerced to the 100-row minimum, 101 of these rows would be
    // pruned during restart.
    const file = databasePath('blank-job-config');
    const db = new PanelDb(file);
    await db.write((database) => {
      const insert = database.prepare(`INSERT INTO sync_jobs
        (id, type, status, requested_by, payload_json, result_json, created_at,
          finished_at, claim_keys_json, reconciliation_hold)
        VALUES (?, 'fixture', 'succeeded', 'tester', '{}', '{}', ?, ?, '[]', 0)`);
      try {
        for (let index = 0; index < 201; index += 1) {
          insert.run([
            'job_default_' + String(index).padStart(18, '0'),
            '2026-09-15T00:00:00.000Z',
            '2026-09-15T00:00:01.000Z',
          ]);
        }
      } finally {
        insert.free();
      }
    });

    await new PanelDb(file).ready;
    assert.equal(await scalar(db, 'SELECT COUNT(*) FROM sync_jobs'), 201);
  } finally {
    if (previousJobs === undefined) delete process.env.PANEL_MAX_JOBS;
    else process.env.PANEL_MAX_JOBS = previousJobs;
    if (previousReceipts === undefined) delete process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS;
    else process.env.PANEL_IDEMPOTENCY_MAX_RECEIPTS = previousReceipts;
  }
});

test('job creation rejects invalid persisted identity fields without poisoning later writes', async () => {
  const db = new PanelDb(databasePath('create-input-bounds'));
  await assert.rejects(
    db.createJob('x'.repeat(65), {}, 'tester'),
    (error) => error.code === 'JOB_TYPE_INVALID',
  );
  await assert.rejects(
    db.createJob('diagnostic', {}, 'x'.repeat(33)),
    (error) => error.code === 'JOB_REQUESTED_BY_INVALID',
  );
  assert.equal(await scalar(db, 'SELECT COUNT(*) FROM sync_jobs'), 0);

  const valid = await db.createJob('diagnostic', {}, 'tester');
  await db.updateJob(valid.id, { status: 'failed', error: 'test cleanup' });
  assert.equal(await scalar(db, 'SELECT COUNT(*) FROM sync_jobs'), 1);
});

test('job updates reject invalid results and timestamps without poisoning later writes', async () => {
  const db = new PanelDb(databasePath('update-input-bounds'));
  const job = await db.createJob('diagnostic', {}, 'tester');

  for (const result of [null, 'scalar', [], 42]) {
    await assert.rejects(
      db.updateJob(job.id, { result }),
      (error) => error.code === 'JOB_RESULT_INVALID',
    );
  }
  await assert.rejects(
    db.updateJob(job.id, { startedAt: 'x'.repeat(65) }),
    (error) => error.code === 'JOB_TIMESTAMP_INVALID'
      && error.field === 'sync_jobs.started_at',
  );
  await assert.rejects(
    db.updateJob(job.id, { finishedAt: 'not-a-canonical-timestamp' }),
    (error) => error.code === 'JOB_TIMESTAMP_INVALID'
      && error.field === 'sync_jobs.finished_at',
  );

  const unchanged = await db.getJob(job.id);
  assert.equal(unchanged.status, 'queued');
  assert.equal(unchanged.result, null);
  assert.equal(unchanged.startedAt, null);
  assert.equal(unchanged.finishedAt, null);

  await db.updateJob(job.id, {
    status: 'succeeded',
    result: { completed: true },
    finishedAt: '2026-09-15T00:00:01.000Z',
  });
  const later = await db.createJob('diagnostic', {}, 'tester');
  await db.updateJob(later.id, { status: 'failed', error: 'test cleanup' });
});

test('fractional retention settings cannot inject a decimal SQLite OFFSET', async () => {
  const previousAudit = process.env.PANEL_MAX_AUDIT_EVENTS;
  const previousSnapshots = process.env.PANEL_MAX_SNAPSHOTS;
  process.env.PANEL_MAX_AUDIT_EVENTS = '100.5';
  process.env.PANEL_MAX_SNAPSHOTS = '20.75';
  try {
    const db = new PanelDb(databasePath('fractional-retention'));
    await db.ready;
    await db.audit({ actor: 'tester', action: 'fractional_retention', result: 'ok' });
    const job = await db.createJob('diagnostic', {}, 'tester');
    await db.updateJob(job.id, { status: 'failed', error: 'test cleanup' });
    assert.equal(await scalar(db, 'SELECT COUNT(*) FROM sync_jobs'), 1);
  } finally {
    if (previousAudit === undefined) delete process.env.PANEL_MAX_AUDIT_EVENTS;
    else process.env.PANEL_MAX_AUDIT_EVENTS = previousAudit;
    if (previousSnapshots === undefined) delete process.env.PANEL_MAX_SNAPSHOTS;
    else process.env.PANEL_MAX_SNAPSHOTS = previousSnapshots;
  }
});

test('shutdown interruption rejects an oversized reason before changing job state', async () => {
  const db = new PanelDb(databasePath('interrupt-reason-bound'));
  const job = await db.createJob('diagnostic', {}, 'tester');
  await assert.rejects(
    db.interruptOwnedActiveJobs('x'.repeat((64 * 1024) + 1)),
    (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE'
      && error.field === 'sync_jobs.error',
  );
  assert.equal((await db.getJob(job.id)).status, 'queued');
  await db.updateJob(job.id, { status: 'failed', error: 'test cleanup' });
  const later = await db.createJob('diagnostic', {}, 'tester');
  await db.updateJob(later.id, { status: 'failed', error: 'test cleanup' });
});

test('shutdown interruption materializes only selected compact active-job references', async () => {
  const db = new PanelDb(databasePath('interrupt-compact-reference'));
  const interrupted = await db.createJob('diagnostic', {}, 'tester');
  const excluded = await db.createJob('diagnostic', {}, 'tester');

  assert.deepEqual(
    await db.interruptOwnedActiveJobs('controlled shutdown', {
      excludeJobIds: [excluded.id],
    }),
    [interrupted.id],
  );
  assert.equal((await db.getJob(interrupted.id)).status, 'interrupted');
  assert.equal((await db.getJob(interrupted.id)).error, 'controlled shutdown');
  assert.equal((await db.getJob(excluded.id)).status, 'queued');
  await db.updateJob(excluded.id, { status: 'failed', error: 'test cleanup' });

  const source = fs.readFileSync(path.join(__dirname, '..', 'backend', 'db.js'), 'utf8');
  const start = source.indexOf('  interruptOwnedActiveJobs(');
  const end = source.indexOf('\n  decodeJob(', start);
  assert.ok(start >= 0 && end > start);
  const implementation = source.slice(start, end);
  assert.match(implementation, /recovery_reference: true/);
  assert.doesNotMatch(implementation, /SELECT id, type, status, claim_keys_json/);
  assert.doesNotMatch(implementation, /started_at, finished_at, result_json/);
});

test('all task admission paths stop at the durable restart recovery capacity', async () => {
  const db = new PanelDb(databasePath('active-recovery-capacity'));
  const template = await db.createJob('diagnostic', {}, 'tester');
  await db.write((database) => {
    const insert = database.prepare(`INSERT INTO sync_jobs
      (id, type, status, requested_by, payload_json, created_at, claim_keys_json,
        owner_pid, owner_start_id, owner_boot_id)
      SELECT ?, type, status, requested_by, payload_json, created_at, claim_keys_json,
        owner_pid, owner_start_id, owner_boot_id
      FROM sync_jobs WHERE id = ?`);
    try {
      // The validator can materialize at most 2,000 active rows after their
      // owner exits. Seed that exact boundary without exercising admission.
      for (let index = 1; index < 2000; index += 1) {
        insert.run([
          'job_capacity_' + String(index).padStart(8, '0'),
          template.id,
        ]);
      }
    } finally {
      insert.free();
    }
  });
  assert.equal(
    await scalar(db, "SELECT COUNT(*) FROM sync_jobs WHERE status IN ('queued', 'running')"),
    2000,
  );

  await assert.rejects(
    db.createJob('diagnostic', {}, 'tester'),
    (error) => error.code === 'JOB_QUEUE_FULL'
      && /可恢复安全上限/.test(error.message),
  );
  await assert.rejects(
    db.createMutationSubmission({
      workflow: 'diagnostic',
      requestedBy: 'panel-admin',
      idempotencyKey: 'idem_v1_recovery_capacity_1234567890',
      requestDigest: 'a'.repeat(64),
      jobs: [{ type: 'diagnostic', payload: {}, claimKeys: [] }],
      responseFactory: ({ createdJobs }) => ({
        jobId: createdJobs[0].job.id,
        status: 'queued',
      }),
    }),
    (error) => error.code === 'JOB_QUEUE_FULL'
      && /可恢复安全上限/.test(error.message),
  );
  assert.equal(await scalar(db, 'SELECT COUNT(*) FROM mutation_receipts'), 0);
});

test('claim validation enforces the per-job claim limit without loading the graph', async () => {
  const file = databasePath('per-job-claim-count');
  const db = new PanelDb(file);
  const overloaded = await db.createJob('phase3', {}, 'tester');
  await db.createJob('phase3', {}, 'tester');
  await db.write((database) => {
    const insert = database.prepare(`INSERT INTO job_claims
      (claim_key, job_id, job_type, created_at) VALUES (?, ?, 'phase3', ?)`);
    try {
      for (let index = 0; index < 1001; index += 1) {
        insert.run([
          'phase3:per-job-bound:' + String(index).padStart(4, '0'),
          overloaded.id,
          '2026-09-15T00:00:00.000Z',
        ]);
      }
    } finally {
      insert.free();
    }
  });

  await assert.rejects(
    new PanelDb(file).ready,
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID'
      && /单个任务的保护键数量超过/.test(error.message),
  );
  assert.equal(await scalar(db, 'SELECT COUNT(*) FROM job_claims'), 1001);
});

test('claim validation rejects oversized stored job fields without releasing claims', async () => {
  const variants = [
    {
      label: 'result',
      column: 'result_json',
      expectedField: 'sync_jobs.result_json',
      value: 'r'.repeat((2 * 1024 * 1024) + 1),
    },
    {
      label: 'error',
      column: 'error',
      expectedField: 'sync_jobs.error',
      value: 'e'.repeat((64 * 1024) + 1),
    },
    {
      label: 'payload',
      column: 'payload_json',
      expectedField: 'sync_jobs.payload_json',
      value: 'p'.repeat((1024 * 1024) + 1),
    },
  ];

  for (const variant of variants) {
    const file = databasePath('field-' + variant.label);
    const db = new PanelDb(file);
    const claimKey = 'phase3:oversized-stored-' + variant.label;
    const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
    await db.write((database) => {
      const statement = database.prepare(
        `UPDATE sync_jobs SET ${variant.column} = ? WHERE id = ?`,
      );
      try {
        statement.run([variant.value, job.id]);
      } finally {
        statement.free();
      }
    });

    await assert.rejects(
      new PanelDb(file).ready,
      (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE'
        && error.field === variant.expectedField
        && error.actualBytes > error.maximumBytes,
      variant.label,
    );
    assert.equal(
      await scalar(db, `SELECT COUNT(*) FROM job_claims WHERE job_id = '${job.id}'`),
      1,
      variant.label,
    );
  }
});

test('clean terminal jobs do not emit repeated zero-row claim cleanup audits', async () => {
  const file = databasePath('clean-terminal-audit');
  const db = new PanelDb(file);
  const job = await db.createJob('diagnostic', {}, 'tester');
  await db.updateJob(job.id, {
    status: 'succeeded',
    result: { completed: true },
    finishedAt: '2026-09-15T00:00:01.000Z',
  });

  await new PanelDb(file).ready;
  await new PanelDb(file).ready;
  const cleanupCount = await scalar(db, `SELECT COUNT(*) FROM audit_events
    WHERE job_id = '${job.id}' AND action = 'job_claim_recovery'
      AND result = 'stale_terminal_claim_removed'`);
  assert.equal(cleanupCount, 0);
});

test('claim validation source uses bounded counts and per-job result reads', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'backend', 'db.js'), 'utf8');
  const start = source.indexOf('function validateJobClaims(');
  const end = source.indexOf('\nfunction jobExecutionOutcomeUnknown(', start);
  assert.ok(start >= 0 && end > start);
  const implementation = source.slice(start, end);

  assert.match(implementation, /strictIntegrityTableCount\(database, 'sync_jobs'\)/);
  assert.match(implementation, /strictIntegrityTableCount\(database, 'job_claims'\)/);
  assert.match(implementation, /readBoundedStoredJobResult\(resultStatement, job\)/);
  assert.match(implementation, /FROM sync_jobs WHERE id = \? ORDER BY rowid ASC LIMIT 1/);
  assert.match(implementation, /activeJobs\.push\(\{/);
  assert.doesNotMatch(implementation, /activeJobs\.push\(job\)/);
  assert.match(source, /function materializeRecoveryJob\(database, reference\)/);
  assert.doesNotMatch(implementation, /resultRows\(database\.exec\(`SELECT id, type, status/);
  assert.doesNotMatch(implementation, /SELECT claim_key, job_id, job_type FROM job_claims/);
  assert.doesNotMatch(implementation, /staleTerminalJobs/);
  assert.doesNotMatch(source, /ORDER BY CASE WHEN typeof\((?:id|c\.claim_key)\)/);
});
