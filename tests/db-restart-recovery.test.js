const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { PanelDb, RECONCILIATION_ACK_CONFIRMATION } = require('../backend/db');

function databasePath(label) {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'panel-' + label + '-')), 'panel.sqlite3');
}

async function makeOwnerDead(db, jobId) {
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET owner_pid = ?, owner_start_id = ?, owner_boot_id = ? WHERE id = ?`);
    statement.run([2147483647, 'dead-owner-start', 'dead-owner-boot', jobId]);
    statement.free();
  });
}

function acknowledge(db, job, resolution = 'state_manually_reconciled', extra = {}) {
  return db.acknowledgeJobReconciliation(job.id, {
    actor: 'panel-admin',
    confirmation: RECONCILIATION_ACK_CONFIRMATION,
    resolution,
    claimDigest: job.result.reconciliationClaimDigest,
    ...extra,
  });
}

async function scalar(db, sql) {
  return db.read((database) => database.exec(sql)[0]?.values?.[0]?.[0]);
}

function claimKeysDigest(claimKeys) {
  return crypto.createHash('sha256')
    .update(JSON.stringify([...claimKeys].sort()))
    .digest('hex');
}

test('restart releases clean queued work but persistently holds an unknown running outcome', async () => {
  const queuedFile = databasePath('queued');
  const queuedDb = new PanelDb(queuedFile);
  const queued = await queuedDb.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:queued'],
  });
  await makeOwnerDead(queuedDb, queued.id);
  const queuedRestart = new PanelDb(queuedFile);
  const recoveredQueued = await queuedRestart.getJob(queued.id);
  assert.equal(recoveredQueued.status, 'interrupted');
  assert.deepEqual({
    outcome: recoveredQueued.result.executionOutcome,
    requiresReconciliation: recoveredQueued.result.requiresReconciliation,
    retryAllowed: recoveredQueued.result.retryAllowed,
  }, { outcome: 'not_started', requiresReconciliation: false, retryAllowed: true });
  const queuedReplacement = await queuedRestart.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:queued'],
  });
  await queuedRestart.updateJob(queuedReplacement.id, { status: 'failed', error: 'cleanup' });

  const file = databasePath('running');
  const db = new PanelDb(file);
  const claimKey = 'token_import';
  const running = await db.createJob('token_import', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(running.id, { status: 'running', startedAt: new Date().toISOString() });
  await makeOwnerDead(db, running.id);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(
      db.createJob('token_import', {}, 'tester', { claimKeys: [claimKey] }),
      (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
        && error.existingJobId === running.id
        && error.retryAllowed === false
        && error.doNotRetry === true,
    );
  }
  const restarted = new PanelDb(file);
  const held = await restarted.getJob(running.id);
  assert.equal(held.status, 'interrupted');
  assert.equal(held.result.executionOutcome, 'unknown');
  assert.equal(held.result.reconciliationHold, true);
  assert.equal(held.result.reconciliationHoldScope, 'claim_keys');
  assert.match(held.result.reconciliationClaimDigest, /^[a-f0-9]{64}$/);
  assert.equal(held.result.heldClaimCount, 1);
  await assert.rejects(
    restarted.createJob('token_import', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED',
  );
});

test('restart preserves a running job whose exact owner process is still alive', async () => {
  const file = databasePath('live');
  const db = new PanelDb(file);
  const claimKey = 'phase3:live';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });
  const restarted = new PanelDb(file);
  assert.equal((await restarted.getJob(job.id)).status, 'running');
  await assert.rejects(
    restarted.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_ALREADY_CLAIMED' && error.existingJobId === job.id,
  );
  await restarted.updateJob(job.id, { status: 'failed', error: 'cleanup' });
});

test('an already-open database converts every provably dead running owner before admitting other work', async () => {
  const file = databasePath('multi-instance-dead-running');
  const first = new PanelDb(file);
  await first.ready;
  const second = new PanelDb(file);
  await second.ready;
  const running = await first.createJob('token_import', {}, 'tester', {
    claimKeys: ['token_import'],
  });
  await first.updateJob(running.id, {
    status: 'running',
    startedAt: new Date().toISOString(),
  });
  await makeOwnerDead(first, running.id);

  await assert.rejects(
    second.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:other-target'] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === running.id
      && error.reconciliationBlockScope === 'all_mutating_operations',
  );
  const held = await second.getJob(running.id);
  assert.equal(held.status, 'interrupted');
  assert.equal(held.result.reconciliationHold, true);
});

test('a queued mutation rechecks holds at execution time and exits without creating another hold', async () => {
  const db = new PanelDb(databasePath('queued-execution-barrier'));
  const first = await db.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:first'],
  });
  const second = await db.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:second'],
  });
  await db.startMutationJob(first.id);
  await db.updateJob(first.id, {
    status: 'failed',
    result: { writeOutcomeUnknown: true },
    finishedAt: new Date().toISOString(),
  });

  await assert.rejects(
    db.startMutationJob(second.id),
    (error) => error.code === 'JOB_BLOCKED_BY_RECONCILIATION'
      && error.blockedBeforeStart === true
      && error.executionOutcome === 'not_started'
      && error.requiresReconciliation !== true
      && error.existingJobId === first.id,
  );
  assert.equal((await db.getJob(second.id)).status, 'queued');
  await db.updateJob(second.id, {
    status: 'failed',
    result: { code: 'JOB_BLOCKED_BY_RECONCILIATION', executionOutcome: 'not_started' },
    finishedAt: new Date().toISOString(),
  });
  const blocked = await db.getJob(second.id);
  assert.equal(blocked.result.reconciliationHold, undefined);
  assert.equal(await scalar(db,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${second.id}'`), 0);
});

test('acknowledgement is CAS-protected, audited, idempotent, and never makes the old operation retryable', async () => {
  const file = databasePath('ack');
  const db = new PanelDb(file);
  const claimKey = 'phase3:ack';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });
  await makeOwnerDead(db, job.id);
  await assert.rejects(
    db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED',
  );
  const held = await db.getJob(job.id);
  const originalError = held.error;

  await assert.rejects(
    acknowledge(db, held, 'operation_applied', { confirmation: 'wrong' }),
    (error) => error.code === 'JOB_RECONCILIATION_CONFIRMATION_INVALID',
  );
  await assert.rejects(
    acknowledge(db, held, 'operation_applied', { claimDigest: '0'.repeat(64) }),
    (error) => error.code === 'JOB_RECONCILIATION_DIGEST_MISMATCH',
  );
  await assert.rejects(
    acknowledge(db, held, 'invalid'),
    (error) => error.code === 'JOB_RECONCILIATION_RESOLUTION_INVALID',
  );
  await assert.rejects(
    acknowledge(db, held, 'operation_applied', { actor: 'local' }),
    (error) => {
      assert.equal(error.code, 'JOB_RECONCILIATION_ADMIN_REQUIRED');
      assert.deepEqual(Object.keys(error), ['code']);
      return true;
    },
  );

  let checkpointFields;
  const released = await acknowledge(db, held, 'operation_applied', {
    beforeRelease(fields) { checkpointFields = fields; },
  });
  assert.equal(released.idempotent, false);
  assert.equal(released.releasedClaimCount, 1);
  assert.equal(checkpointFields.jobId, job.id);
  const resolved = await db.getJob(job.id);
  assert.equal(resolved.status, 'interrupted');
  assert.equal(resolved.result.reconciliationResolved, true);
  assert.equal(resolved.result.futureOperationsUnblocked, true);
  assert.equal(resolved.result.reconciliationResolution, 'operation_applied');
  assert.equal(resolved.result.retryAllowed, false);
  assert.equal(resolved.result.doNotRetry, true);
  assert.equal(resolved.error, originalError);
  assert.equal((await acknowledge(db, held, 'operation_applied')).idempotent, true);
  await assert.rejects(
    acknowledge(db, held, 'operation_not_applied'),
    (error) => error.code === 'JOB_RECONCILIATION_ACK_CONFLICT',
  );
  assert.ok((await db.listAudit(20)).some((event) => (
    event.jobId === job.id
      && event.action === 'job_reconciliation_acknowledge'
      && event.details.resolution === 'operation_applied'
  )));
  const replacement = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(replacement.id, { status: 'failed', error: 'cleanup' });
});

test('acknowledgement compacts an oversized legacy result instead of trapping its hold', async () => {
  const db = new PanelDb(databasePath('ack-large-result'));
  const claimKey = 'phase3:large-result';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, {
    status: 'failed',
    result: {
      writeOutcomeUnknown: true,
      padding: 'x'.repeat(2_096_550),
    },
    finishedAt: new Date().toISOString(),
  });
  const held = await db.getJob(job.id);
  assert.equal(held.result.reconciliationHold, true);

  const released = await acknowledge(db, held);
  assert.equal(released.releasedClaimCount, 1);
  const resolved = await db.getJob(job.id);
  assert.equal(resolved.result.originalResultCompacted, true);
  assert.match(resolved.result.originalResultDigest, /^[a-f0-9]{64}$/);
  assert.ok(resolved.result.originalResultBytes > 2_000_000);
  assert.equal(resolved.result.reconciliationResolved, true);
  assert.equal(resolved.result.retryAllowed, false);
  const replacement = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(replacement.id, { status: 'failed', error: 'cleanup' });
});

test('new unknown terminal work compacts near-limit detail while creating its hold', async () => {
  const db = new PanelDb(databasePath('new-large-hold'));
  const claimKey = 'phase3:new-large-hold';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.startMutationJob(job.id);
  await db.updateJob(job.id, {
    status: 'failed',
    result: {
      requiresReconciliation: true,
      writeOutcomeUnknown: true,
      padding: 'x'.repeat(2_096_700),
    },
    finishedAt: new Date().toISOString(),
  });

  const held = await db.getJob(job.id);
  assert.equal(held.result.reconciliationHold, true);
  assert.equal(held.result.originalResultCompacted, true);
  assert.ok(held.result.originalResultBytes > 2_000_000);
  assert.match(held.result.originalResultDigest, /^[a-f0-9]{64}$/);
  assert.equal(held.result.retryAllowed, false);
  await acknowledge(db, held);
});

test('an audit checkpoint failure rolls back acknowledgement and preserves the hold', async () => {
  const db = new PanelDb(databasePath('ack-rollback'));
  const claimKey = 'account_test:88';
  const job = await db.createJob('account_test', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, { status: 'failed', result: { writeOutcomeUnknown: true } });
  const held = await db.getJob(job.id);
  const checkpointError = new Error('checkpoint unavailable');
  checkpointError.code = 'AUDIT_LOG_UNAVAILABLE';
  await assert.rejects(
    acknowledge(db, held, 'state_manually_reconciled', {
      beforeRelease() { throw checkpointError; },
    }),
    (error) => error.code === 'AUDIT_LOG_UNAVAILABLE',
  );
  assert.equal((await db.getJob(job.id)).result.reconciliationHold, true);
  await assert.rejects(
    db.createJob('account_test', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED',
  );
});

test('persistence failures after acknowledgement leave a durable hold-or-idempotent safe state', async () => {
  for (const mode of ['before_rename', 'after_persist']) {
    const file = databasePath('ack-persist-' + mode);
    const db = new PanelDb(file);
    const claimKey = 'phase3:persist-' + mode;
    const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
    await db.updateJob(job.id, { status: 'failed', result: { writeOutcomeUnknown: true } });
    const held = await db.getJob(job.id);
    const simulated = new Error('simulated persistence failure');
    simulated.code = 'SIMULATED_PERSISTENCE_FAILURE';

    let restore;
    if (mode === 'before_rename') {
      const originalRename = fs.renameSync;
      let failed = false;
      fs.renameSync = function failOneDatabaseRename(source, target) {
        if (!failed && String(source).includes('.tmp-')
            && path.basename(String(target)) === path.basename(file)) {
          failed = true;
          throw simulated;
        }
        return originalRename.apply(this, arguments);
      };
      restore = () => { fs.renameSync = originalRename; };
    } else {
      const originalPersist = db.persistUnlocked.bind(db);
      db.persistUnlocked = () => {
        originalPersist();
        throw simulated;
      };
      restore = () => { db.persistUnlocked = originalPersist; };
    }
    try {
      await assert.rejects(
        acknowledge(db, held, 'operation_applied'),
        (error) => error.code === 'SIMULATED_PERSISTENCE_FAILURE',
      );
    } finally {
      restore();
    }

    const reloaded = new PanelDb(file);
    const durable = await reloaded.getJob(job.id);
    if (durable.result.reconciliationHold === true) {
      await assert.rejects(
        reloaded.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
        (error) => error.code === 'JOB_RECONCILIATION_REQUIRED',
      );
      assert.equal((await acknowledge(reloaded, durable, 'operation_applied')).idempotent, false);
    } else {
      assert.equal(durable.result.reconciliationResolved, true);
      assert.equal(durable.result.futureOperationsUnblocked, true);
      assert.equal(durable.result.retryAllowed, false);
      assert.equal((await acknowledge(reloaded, held, 'operation_applied')).idempotent, true);
    }
    const allowed = await reloaded.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
    await reloaded.updateJob(allowed.id, { status: 'failed', error: 'cleanup' });
  }
});

test('all explicit unknown terminal result signals retain claims without rewriting the terminal status', async () => {
  const cases = [
    ['succeeded', { requiresReconciliation: true }],
    ['partial', { reconciliationHold: true, reconciliationResolved: true }],
    ['failed', { requiresReconciliation: true, doNotRetry: true }],
    ['interrupted', { writeOutcomeUnknown: true }],
  ];
  for (const [index, [status, result]] of cases.entries()) {
    const db = new PanelDb(databasePath('terminal-' + index));
    const claimKey = 'account_test:' + String(7000 + index);
    const job = await db.createJob('account_test', {}, 'tester', { claimKeys: [claimKey] });
    await db.updateJob(job.id, { status, result, finishedAt: new Date().toISOString() });
    const held = await db.getJob(job.id);
    assert.equal(held.status, status);
    assert.deepEqual({
      requiresReconciliation: held.result.requiresReconciliation,
      hold: held.result.reconciliationHold,
      resolved: held.result.reconciliationResolved,
      futureOperationsUnblocked: held.result.futureOperationsUnblocked,
      retryAllowed: held.result.retryAllowed,
      doNotRetry: held.result.doNotRetry,
    }, {
      requiresReconciliation: true,
      hold: true,
      resolved: false,
      futureOperationsUnblocked: false,
      retryAllowed: false,
      doNotRetry: true,
    });
    assert.equal(held.result.reconciliationHoldScope, 'claim_keys');
    await assert.rejects(
      db.createJob('account_test', {}, 'tester', { claimKeys: [claimKey] }),
      (error) => error.code === 'JOB_RECONCILIATION_REQUIRED',
    );
    await acknowledge(db, held, [
      'operation_applied',
      'operation_not_applied',
      'state_manually_reconciled',
    ][index % 3]);
    const resolved = await db.getJob(job.id);
    assert.equal(resolved.status, status);
    assert.equal(resolved.result.retryAllowed, false);
    assert.equal(resolved.result.doNotRetry, true);
  }
});

test('a known permanent failure marked doNotRetry releases its claims without creating a hold', async () => {
  const db = new PanelDb(databasePath('known-permanent-failure'));
  const claimKey = 'account_test:known-failure';
  const job = await db.createJob('account_test', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, {
    status: 'failed',
    result: { doNotRetry: true, failureOutcomeKnown: true },
    error: 'known permanent failure',
  });
  const failed = await db.getJob(job.id);
  assert.equal(failed.result.doNotRetry, true);
  assert.equal(failed.result.requiresReconciliation, undefined);
  assert.equal(failed.result.reconciliationHold, undefined);
  assert.equal(await scalar(db,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${job.id}'`), 0);
  const replacement = await db.createJob('account_test', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(replacement.id, { status: 'failed', error: 'cleanup' });
});

test('unknown terminal work without claims receives an acknowledgeable global hold', async () => {
  const db = new PanelDb(databasePath('no-claim'));
  const job = await db.createJob('diagnostic', {}, 'tester');
  await db.updateJob(job.id, {
    status: 'failed',
    result: { writeOutcomeUnknown: true },
    finishedAt: new Date().toISOString(),
  });
  const terminal = await db.getJob(job.id);
  assert.deepEqual({
    hold: terminal.result.reconciliationHold,
    unavailable: terminal.result.reconciliationHoldUnavailable,
    count: terminal.result.heldClaimCount,
    scope: terminal.result.reconciliationHoldScope,
    blockScope: terminal.result.reconciliationBlockScope,
    retryAllowed: terminal.result.retryAllowed,
  }, {
    hold: true,
    unavailable: false,
    count: 1,
    scope: 'all_future_jobs',
    blockScope: 'all_mutating_operations',
    retryAllowed: false,
  });
  await acknowledge(db, terminal);
  assert.equal((await db.getJob(job.id)).result.reconciliationResolved, true);
});

test('claim corruption and orphan claims fail closed without deleting the barrier', async () => {
  const missingFile = databasePath('missing');
  const missingDb = new PanelDb(missingFile);
  const missing = await missingDb.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:missing'] });
  await missingDb.write((database) => database.run(`DELETE FROM job_claims WHERE job_id = '${missing.id}'`));
  await assert.rejects(new PanelDb(missingFile).ready, (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID');

  const malformedFile = databasePath('malformed');
  const malformedDb = new PanelDb(malformedFile);
  const malformed = await malformedDb.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:malformed'] });
  await malformedDb.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET claim_keys_json = ? WHERE id = ?');
    statement.run(['{"bad":true}', malformed.id]);
    statement.free();
  });
  await assert.rejects(new PanelDb(malformedFile).ready, (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID');

  const orphanFile = databasePath('orphan');
  const orphanDb = new PanelDb(orphanFile);
  await orphanDb.write((database) => database.run(`INSERT INTO job_claims
    (claim_key, job_id, job_type, created_at)
    VALUES ('phase3:orphan', 'job_missing', 'phase3', '2026-09-14T00:00:00.000Z')`));
  await assert.rejects(new PanelDb(orphanFile).ready, (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID');
  assert.equal(await scalar(orphanDb, "SELECT COUNT(*) FROM job_claims WHERE job_id = 'job_missing'"), 1);
});

test('legacy NULL claim metadata is reconstructed before stale terminal claims are audit-cleaned', async () => {
  const activeFile = databasePath('legacy-active');
  const activeDb = new PanelDb(activeFile);
  const active = await activeDb.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:legacy-active'] });
  await activeDb.write((database) => database.run(
    `UPDATE sync_jobs SET claim_keys_json = NULL WHERE id = '${active.id}'`,
  ));
  const activeRestart = new PanelDb(activeFile);
  assert.equal((await activeRestart.getJob(active.id)).status, 'queued');
  assert.equal(await scalar(activeRestart,
    `SELECT claim_keys_json FROM sync_jobs WHERE id = '${active.id}'`), '["phase3:legacy-active"]');
  await activeRestart.updateJob(active.id, { status: 'failed', error: 'cleanup' });

  const terminalFile = databasePath('legacy-terminal');
  const terminalDb = new PanelDb(terminalFile);
  const terminal = await terminalDb.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:legacy-terminal'] });
  await terminalDb.updateJob(terminal.id, { status: 'succeeded', result: { completed: true } });
  await terminalDb.write((database) => {
    database.run(`UPDATE sync_jobs SET claim_keys_json = NULL WHERE id = '${terminal.id}'`);
    database.run(`INSERT INTO job_claims (claim_key, job_id, job_type, created_at)
      VALUES ('phase3:legacy-terminal', '${terminal.id}', 'phase3', '2026-09-14T00:00:00.000Z')`);
  });
  const terminalRestart = new PanelDb(terminalFile);
  await terminalRestart.ready;
  assert.equal(await scalar(terminalRestart,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${terminal.id}'`), 0);
  assert.ok((await terminalRestart.listAudit(20)).some((event) => (
    event.jobId === terminal.id
      && event.action === 'job_claim_recovery'
      && event.result === 'stale_terminal_claim_removed'
      && event.details.claimCount === 1
  )));
});

test('live queued work with missing claim metadata cannot silently lose its barrier', async () => {
  const file = databasePath('live-queued-missing-claims');
  const db = new PanelDb(file);
  const job = await db.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:live-missing'],
  });
  await db.write((database) => database.run(`
    UPDATE sync_jobs SET claim_keys_json = NULL WHERE id = '${job.id}';
    DELETE FROM job_claims WHERE job_id = '${job.id}';
  `));

  await assert.rejects(
    new PanelDb(file).ready,
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID'
      && /活动任务缺少可恢复/.test(error.message),
  );
  await assert.rejects(
    db.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:live-missing'] }),
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
  assert.equal(await scalar(db,
    `SELECT status FROM sync_jobs WHERE id = '${job.id}'`), 'queued');
  assert.equal(await scalar(db,
    `SELECT claim_keys_json FROM sync_jobs WHERE id = '${job.id}'`), null);

  const incompleteFile = databasePath('live-queued-incomplete-owner');
  const incompleteDb = new PanelDb(incompleteFile);
  const incomplete = await incompleteDb.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:live-incomplete'],
  });
  await incompleteDb.write((database) => database.run(`
    UPDATE sync_jobs SET claim_keys_json = NULL, owner_start_id = NULL,
      owner_boot_id = NULL WHERE id = '${incomplete.id}';
    DELETE FROM job_claims WHERE job_id = '${incomplete.id}';
  `));
  await assert.rejects(
    new PanelDb(incompleteFile).ready,
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID'
      && /活动任务缺少可恢复/.test(error.message),
  );
});

test('a provably dead clean queue with missing claim metadata is terminalized before new work', async () => {
  const file = databasePath('dead-queued-missing-claims');
  const db = new PanelDb(file);
  const job = await db.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:dead-missing'],
  });
  await db.write((database) => database.run(`
    UPDATE sync_jobs SET claim_keys_json = NULL, owner_pid = 2147483647,
      owner_start_id = 'dead-owner-start', owner_boot_id = 'dead-owner-boot'
      WHERE id = '${job.id}';
    DELETE FROM job_claims WHERE job_id = '${job.id}';
  `));

  const replacement = await db.createJob('phase3', {}, 'tester', {
    claimKeys: ['phase3:dead-missing'],
  });
  const recovered = await db.getJob(job.id);
  assert.equal(recovered.status, 'interrupted');
  assert.equal(recovered.result.executionOutcome, 'not_started');
  assert.equal(recovered.result.requiresReconciliation, false);
  await db.updateJob(replacement.id, { status: 'failed', error: 'cleanup' });
});

test('legacy terminal reconciliation results rebuild missing claims into a durable hold', async () => {
  const file = databasePath('legacy-terminal-hold');
  const db = new PanelDb(file);
  const claimKey = 'phase3:legacy-terminal-unknown';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, { status: 'failed', result: { completed: false } });
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET result_json = ?, reconciliation_hold = 0, reconciliation_scope = NULL,
        reconciliation_claim_digest = NULL
      WHERE id = ?`);
    try {
      statement.run([JSON.stringify({
        requiresReconciliation: true,
        writeOutcomeUnknown: true,
        legacyDetail: 'safe',
      }), job.id]);
      database.run(`DELETE FROM job_claims WHERE job_id = '${job.id}'`);
    } finally {
      statement.free();
    }
  });

  await assert.rejects(
    db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === job.id,
  );
  let restarted = new PanelDb(file);
  const held = await restarted.getJob(job.id);
  assert.equal(held.status, 'failed');
  assert.equal(held.result.reconciliationHold, true);
  assert.equal(held.result.reconciliationHoldScope, 'claim_keys');
  assert.equal(held.result.retryAllowed, false);
  assert.equal(await scalar(restarted,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${job.id}'`), 1);
  assert.ok((await restarted.listAudit(20)).some((event) => (
    event.jobId === job.id
      && event.action === 'job_claim_recovery'
      && event.result === 'legacy_terminal_hold_rebuilt'
      && event.details.claimCount === 1
  )));
  await assert.rejects(
    restarted.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === job.id,
  );
  restarted = new PanelDb(file);
  await assert.rejects(
    restarted.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED',
  );
});

test('legacy near-limit reconciliation detail cannot prevent hold migration or acknowledgement', async () => {
  const file = databasePath('legacy-large-hold-migration');
  const db = new PanelDb(file);
  const claimKey = 'phase3:legacy-large-hold';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.updateJob(job.id, { status: 'failed', result: { completed: false } });
  const legacyResult = JSON.stringify({
    requiresReconciliation: true,
    writeOutcomeUnknown: true,
    padding: 'x'.repeat(2_096_700),
  });
  assert.ok(Buffer.byteLength(legacyResult, 'utf8') < 2 * 1024 * 1024);
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET result_json = ?, reconciliation_hold = 0, reconciliation_scope = NULL,
        reconciliation_claim_digest = NULL WHERE id = ?`);
    try {
      statement.run([legacyResult, job.id]);
      database.run(`DELETE FROM job_claims WHERE job_id = '${job.id}'`);
    } finally {
      statement.free();
    }
  });

  const restarted = new PanelDb(file);
  const held = await restarted.getJob(job.id);
  assert.equal(held.result.reconciliationHold, true);
  assert.equal(held.result.originalResultCompacted, true);
  assert.equal(held.result.originalResultBytes, Buffer.byteLength(legacyResult, 'utf8'));
  assert.match(held.result.originalResultDigest, /^[a-f0-9]{64}$/);
  assert.equal(await scalar(restarted,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${job.id}'`), 1);
  await acknowledge(restarted, held);
});

test('legacy dead-owner interruption after start rebuilds the claim instead of allowing a retry', async () => {
  const file = databasePath('legacy-dead-running');
  const db = new PanelDb(file);
  const claimKey = 'token_import';
  const job = await db.createJob('token_import', {}, 'tester', { claimKeys: [claimKey] });
  const startedAt = new Date().toISOString();
  const finishedAt = new Date(Date.now() + 1).toISOString();
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET status = 'interrupted', started_at = ?, finished_at = ?, result_json = NULL,
        error = ? WHERE id = ?`);
    try {
      statement.run([
        startedAt,
        finishedAt,
        '面板服务停止，任务已安全中断',
        job.id,
      ]);
      database.run(`DELETE FROM job_claims WHERE job_id = '${job.id}'`);
    } finally {
      statement.free();
    }
  });

  const restarted = new PanelDb(file);
  const held = await restarted.getJob(job.id);
  assert.equal(held.result.reconciliationHold, true);
  assert.equal(held.result.reconciliationReason, 'legacy_owner_process_exited_while_running');
  await assert.rejects(
    restarted.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:different-workflow'] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === job.id
      && error.reconciliationBlockScope === 'all_mutating_operations',
  );
  await acknowledge(restarted, held, 'operation_not_applied');
  const replacement = await restarted.createJob('token_import', {}, 'tester', {
    claimKeys: [claimKey],
  });
  await restarted.updateJob(replacement.id, { status: 'failed', error: 'cleanup' });
});

test('legacy terminal reconciliation with an explicit empty claim list gains a global hold once', async () => {
  const file = databasePath('legacy-terminal-no-claims');
  const db = new PanelDb(file);
  const job = await db.createJob('diagnostic', {}, 'tester');
  await db.updateJob(job.id, { status: 'failed', result: { completed: false } });
  await db.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET result_json = ? WHERE id = ?');
    try {
      statement.run([JSON.stringify({ requiresReconciliation: true }), job.id]);
    } finally {
      statement.free();
    }
  });

  let restarted = new PanelDb(file);
  let migrated = await restarted.getJob(job.id);
  assert.deepEqual({
    hold: migrated.result.reconciliationHold,
    unavailable: migrated.result.reconciliationHoldUnavailable,
    heldClaimCount: migrated.result.heldClaimCount,
    scope: migrated.result.reconciliationHoldScope,
    blockScope: migrated.result.reconciliationBlockScope,
    retryAllowed: migrated.result.retryAllowed,
  }, {
    hold: true,
    unavailable: false,
    heldClaimCount: 1,
    scope: 'all_future_jobs',
    blockScope: 'all_mutating_operations',
    retryAllowed: false,
  });
  const auditCount = (await restarted.listAudit(20)).filter((event) => (
    event.jobId === job.id
      && event.action === 'job_claim_recovery'
      && event.result === 'legacy_terminal_global_hold_created'
  )).length;
  assert.equal(auditCount, 1);
  restarted = new PanelDb(file);
  migrated = await restarted.getJob(job.id);
  assert.equal(migrated.result.reconciliationHold, true);
  assert.equal((await restarted.listAudit(20)).filter((event) => (
    event.jobId === job.id
      && event.action === 'job_claim_recovery'
      && event.result === 'legacy_terminal_global_hold_created'
  )).length, 1);
  await acknowledge(restarted, migrated);
});

test('legacy NULL terminal claims gain a global hold only when the outcome is unknown', async () => {
  const unknownFile = databasePath('legacy-terminal-null-unknown');
  const unknownDb = new PanelDb(unknownFile);
  const unknown = await unknownDb.createJob('legacy_worker', {}, 'tester');
  await unknownDb.updateJob(unknown.id, { status: 'failed', result: { completed: false } });
  await unknownDb.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET claim_keys_json = NULL, result_json = ? WHERE id = ?`);
    try {
      statement.run([JSON.stringify({
        requiresReconciliation: true,
        writeOutcomeUnknown: true,
      }), unknown.id]);
    } finally {
      statement.free();
    }
  });

  const unknownRestart = new PanelDb(unknownFile);
  const held = await unknownRestart.getJob(unknown.id);
  assert.equal(held.result.reconciliationHold, true);
  assert.equal(held.result.reconciliationHoldScope, 'all_future_jobs');
  assert.equal(await scalar(unknownRestart,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${unknown.id}'`), 1);
  assert.ok((await unknownRestart.listAudit(20)).some((event) => (
    event.jobId === unknown.id
      && event.action === 'job_claim_recovery'
      && event.result === 'legacy_terminal_global_hold_created'
      && event.details.previousClaimMetadata === 'missing'
  )));

  const ordinaryFile = databasePath('legacy-terminal-null-ordinary');
  const ordinaryDb = new PanelDb(ordinaryFile);
  const ordinary = await ordinaryDb.createJob('legacy_worker', {}, 'tester');
  await ordinaryDb.updateJob(ordinary.id, {
    status: 'succeeded',
    result: { completed: true },
    finishedAt: new Date().toISOString(),
  });
  await ordinaryDb.write((database) => database.run(
    `UPDATE sync_jobs SET claim_keys_json = NULL WHERE id = '${ordinary.id}'`,
  ));

  const ordinaryRestart = new PanelDb(ordinaryFile);
  const unchanged = await ordinaryRestart.getJob(ordinary.id);
  assert.deepEqual(unchanged.result, { completed: true });
  assert.equal(await scalar(ordinaryRestart,
    `SELECT claim_keys_json FROM sync_jobs WHERE id = '${ordinary.id}'`), null);
  assert.equal(await scalar(ordinaryRestart,
    `SELECT reconciliation_hold FROM sync_jobs WHERE id = '${ordinary.id}'`), 0);
  assert.equal(await scalar(ordinaryRestart,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${ordinary.id}'`), 0);
});

test('legacy terminal reconciliation fails closed when a retained key belongs to another job', async () => {
  const file = databasePath('legacy-terminal-conflict');
  const db = new PanelDb(file);
  const claimKey = 'phase3:legacy-conflict';
  const active = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  const legacy = await db.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:old-key'] });
  await db.updateJob(legacy.id, { status: 'failed', result: { completed: false } });
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET claim_keys_json = ?, result_json = ? WHERE id = ?`);
    try {
      statement.run([
        JSON.stringify([claimKey]),
        JSON.stringify({ requiresReconciliation: true, writeOutcomeUnknown: true }),
        legacy.id,
      ]);
    } finally {
      statement.free();
    }
  });

  await assert.rejects(
    new PanelDb(file).ready,
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID'
      && /其他任务占用/.test(error.message),
  );
  assert.equal(await scalar(db,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${active.id}'`), 1);
  assert.equal(await scalar(db,
    `SELECT COUNT(*) FROM job_claims WHERE job_id = '${legacy.id}'`), 0);
  assert.equal(await scalar(db,
    `SELECT reconciliation_hold FROM sync_jobs WHERE id = '${legacy.id}'`), 0);
});

test('createJob persists a migrated legacy global hold before returning its conflict', async () => {
  const file = databasePath('legacy-create-global');
  const db = new PanelDb(file);
  const legacy = await db.createJob('legacy_worker', {}, 'tester');
  await db.updateJob(legacy.id, { status: 'running', startedAt: new Date().toISOString() });
  await db.write((database) => database.run(`UPDATE sync_jobs
    SET claim_keys_json = NULL, owner_pid = NULL, owner_start_id = NULL, owner_boot_id = NULL
    WHERE id = '${legacy.id}'`));

  await assert.rejects(
    db.createJob('unrelated', {}, 'tester', { claimKeys: ['unrelated:migration-check'] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === legacy.id
      && error.reconciliationHoldScope === 'all_future_jobs',
  );
  const restarted = new PanelDb(file);
  const held = await restarted.getJob(legacy.id);
  assert.equal(held.status, 'interrupted');
  assert.equal(held.result.reconciliationHold, true);
  assert.equal(held.result.reconciliationHoldScope, 'all_future_jobs');
  await assert.rejects(
    restarted.createJob('still-unrelated', {}, 'tester', { claimKeys: ['different:key'] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === legacy.id,
  );
});

test('a legacy synthetic global key cannot be downgraded to a scoped hold', async () => {
  const file = databasePath('global-scope-integrity');
  const db = new PanelDb(file);
  const legacy = await db.createJob('legacy_worker', {}, 'tester');
  await db.updateJob(legacy.id, { status: 'running', startedAt: new Date().toISOString() });
  await db.write((database) => database.run(`UPDATE sync_jobs
    SET claim_keys_json = NULL, owner_pid = NULL, owner_start_id = NULL, owner_boot_id = NULL
    WHERE id = '${legacy.id}'`));
  const restarted = new PanelDb(file);
  const held = await restarted.getJob(legacy.id);
  await restarted.write((database) => {
    const result = JSON.parse(database.exec(`SELECT result_json FROM sync_jobs
      WHERE id = '${legacy.id}'`)[0].values[0][0]);
    result.reconciliationHoldScope = 'claim_keys';
    const statement = database.prepare(`UPDATE sync_jobs
      SET reconciliation_scope = 'claims', result_json = ? WHERE id = ?`);
    try {
      statement.run([JSON.stringify(result), legacy.id]);
    } finally {
      statement.free();
    }
  });
  assert.equal(held.result.reconciliationHoldScope, 'all_future_jobs');
  await assert.rejects(
    new PanelDb(file).ready,
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
});

test('multiple legacy unknown jobs create global holds that block all claims until each is acknowledged', async () => {
  const file = databasePath('global');
  const db = new PanelDb(file);
  const jobs = [];
  for (let index = 0; index < 2; index += 1) {
    const job = await db.createJob('legacy_worker', { index }, 'tester');
    jobs.push(job);
  }
  for (const job of jobs) {
    await db.updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });
  }
  await db.write((database) => {
    for (const job of jobs) database.run(`UPDATE sync_jobs
      SET claim_keys_json = NULL, owner_pid = NULL, owner_start_id = NULL, owner_boot_id = NULL
      WHERE id = '${job.id}'`);
  });

  let restarted = new PanelDb(file);
  const held = await Promise.all(jobs.map((job) => restarted.getJob(job.id)));
  for (const job of held) {
    assert.equal(job.status, 'interrupted');
    assert.equal(job.result.reconciliationHold, true);
    assert.equal(job.result.reconciliationHoldScope, 'all_future_jobs');
  }
  await assert.rejects(
    restarted.createJob('unrelated', {}, 'tester', { claimKeys: ['unrelated:key'] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.reconciliationHoldScope === 'all_future_jobs',
  );
  await acknowledge(restarted, held[0]);
  await assert.rejects(
    restarted.createJob('different', {}, 'tester', { claimKeys: ['different:key'] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED' && error.existingJobId === held[1].id,
  );
  restarted = new PanelDb(file);
  await assert.rejects(
    restarted.createJob('another', {}, 'tester', { claimKeys: ['another:key'] }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED' && error.existingJobId === held[1].id,
  );
  await acknowledge(restarted, held[1], 'operation_not_applied');
  const allowed = await restarted.createJob('another', {}, 'tester', { claimKeys: ['another:key'] });
  await restarted.updateJob(allowed.id, { status: 'failed', error: 'cleanup' });
  assert.equal((await restarted.listAudit(50)).filter((event) => (
    event.action === 'job_claim_recovery' && event.result === 'legacy_global_hold_created'
  )).length, 2);
});

test('job listing returns holds older than the normal history limit and normalizes unsafe limits', async () => {
  const db = new PanelDb(databasePath('held-listing'));
  const heldJob = await db.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:old-hold'] });
  await db.updateJob(heldJob.id, { status: 'failed', result: { requiresReconciliation: true } });
  await db.write((database) => {
    const statement = database.prepare(`INSERT INTO sync_jobs
      (id, type, status, requested_by, payload_json, result_json, created_at,
        finished_at, claim_keys_json, reconciliation_hold)
      VALUES (?, 'history', 'succeeded', 'tester', '{}', '{}', ?, ?, '[]', 0)`);
    try {
      for (let index = 0; index < 205; index += 1) {
        const timestamp = new Date(Date.UTC(2027, 0, 1, 0, 0, index)).toISOString();
        statement.run(['job_history_' + String(index).padStart(4, '0'), timestamp, timestamp]);
      }
    } finally {
      statement.free();
    }
  });

  const decimal = await db.listJobsPage('1.9');
  assert.equal(decimal.history.limit, 1);
  assert.equal(decimal.history.returned, 1);
  assert.equal(decimal.reconciliationHolds.total, 1);
  assert.equal(decimal.reconciliationHolds.returned, 1);
  assert.equal(decimal.reconciliationHolds.truncated, false);
  assert.equal(decimal.jobs[0].id, heldJob.id);
  assert.equal(decimal.jobs.length, 2);
  assert.equal((await db.listJobsPage('not-a-number')).history.limit, 50);
  assert.equal((await db.listJobsPage('999999')).history.limit, 200);
  assert.equal((await db.listJobsPage(Number.MAX_VALUE)).history.limit, 200);
  assert.equal((await db.listJobsPage(Number.NaN)).history.limit, 50);
  assert.equal((await db.listJobsPage('-10')).history.limit, 1);
});

test('job listing reports rather than hides reconciliation-hold response truncation', async () => {
  const file = databasePath('held-list-cap');
  const db = new PanelDb(file);
  await db.write((database) => {
    const jobStatement = database.prepare(`INSERT INTO sync_jobs
      (id, type, status, requested_by, payload_json, result_json, created_at,
        finished_at, claim_keys_json, reconciliation_hold, reconciliation_scope,
        reconciliation_claim_digest)
      VALUES (?, 'fixture', 'failed', 'tester', '{}', ?, ?, ?, ?, 1, 'claims', ?)`);
    const claimStatement = database.prepare(`INSERT INTO job_claims
      (claim_key, job_id, job_type, created_at) VALUES (?, ?, 'fixture', ?)`);
    try {
      for (let index = 0; index < 101; index += 1) {
        const id = 'job_' + index.toString(16).padStart(24, '0');
        const claimKey = 'fixture:hold:' + index;
        const digest = claimKeysDigest([claimKey]);
        const timestamp = new Date(Date.UTC(2027, 0, 1, 0, 0, index)).toISOString();
        const result = {
          writeOutcomeUnknown: true,
          requiresReconciliation: true,
          reconciliationHold: true,
          reconciliationResolved: false,
          futureOperationsUnblocked: false,
          reconciliationHoldUnavailable: false,
          reconciliationHoldReason: null,
          reconciliationClaimDigest: digest,
          heldClaimCount: 1,
          reconciliationHoldScope: 'claim_keys',
          reconciliationBlockScope: 'all_mutating_operations',
          reconciliationResolution: null,
          reconciliationAcknowledgedAt: null,
          reconciliationAcknowledgedBy: null,
          retryAllowed: false,
          doNotRetry: true,
        };
        jobStatement.run([
          id,
          JSON.stringify(result),
          timestamp,
          timestamp,
          JSON.stringify([claimKey]),
          digest,
        ]);
        claimStatement.run([claimKey, id, timestamp]);
      }
    } finally {
      jobStatement.free();
      claimStatement.free();
    }
  });
  // Loading through a fresh PanelDb proves the fixture satisfies the same
  // bidirectional claim/hold validation as production data.
  const reloaded = new PanelDb(file);
  await reloaded.ready;
  const page = await reloaded.listJobsPage(1);
  assert.deepEqual(page.reconciliationHolds, {
    total: 101,
    returned: 100,
    truncated: true,
    maximumReturned: 100,
  });
  assert.equal(page.jobs.length, 100);
  assert.equal(page.history.limit, 1);
  assert.equal(page.history.returned, 0);
  assert.ok(Buffer.byteLength(JSON.stringify(page)) < 200_000);
});

test('public job pages are compact while internal listJobs retains active payloads', async () => {
  const db = new PanelDb(databasePath('list-summary'));
  const payload = { accountIds: [77], padding: 'x'.repeat(512 * 1024) };
  const job = await db.createJob('account_test', payload, 'tester', {
    claimKeys: ['account_test:77'],
  });
  const internal = await db.listJobs(10);
  assert.equal(internal[0].id, job.id);
  assert.deepEqual(internal[0].payload.accountIds, [77]);
  assert.equal(internal[0].payload.padding.length, 512 * 1024);

  const page = await db.listJobsPage(10);
  const summary = page.jobs.find((item) => item.id === job.id);
  assert.equal(summary.payload, null);
  assert.equal(summary.result, null);
  assert.ok(Buffer.byteLength(JSON.stringify(page)) < 20_000);
});

test('new jobs reject invalid and reserved claim keys instead of silently dropping them', async () => {
  const db = new PanelDb(databasePath('invalid'));
  await assert.rejects(
    db.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:valid', '   '] }),
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
  await assert.rejects(
    db.createJob('phase3', {}, 'tester', { claimKeys: 'not-an-array' }),
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
  await assert.rejects(
    db.createJob('phase3', {}, 'tester', {
      claimKeys: ['reconciliation:legacy-global:' + 'a'.repeat(32)],
    }),
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
  assert.equal((await db.listJobs()).length, 0);
});
