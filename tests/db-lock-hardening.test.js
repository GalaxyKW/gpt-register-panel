const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const initSqlJs = require('sql.js');

require('./test-isolation');

const { PanelDb } = require('../backend/db');
const {
  currentProcessOwner,
  isProcessOwnerAlive,
  withControlPlaneLock,
} = require('../backend/taskCoordinator');
const { acquireBakeryLease, releaseBakeryLease } = require('../backend/lib/bakeryLock');

function queryRows(database, sql) {
  const result = database.exec(sql);
  if (!result.length) return [];
  const [{ columns, values }] = result;
  return values.map((valuesRow) => Object.fromEntries(
    columns.map((column, index) => [column, valuesRow[index]]),
  ));
}

function alternateBootId(current) {
  const zero = '00000000-0000-0000-0000-000000000000';
  return String(current || '').toLowerCase() === zero
    ? '11111111-1111-1111-1111-111111111111'
    : zero;
}

function isTicketPath(filePath, lockName) {
  const name = path.basename(String(filePath));
  return name.startsWith(lockName + '.lease-v2-') && name.endsWith('.ticket');
}

function cleanupLeaseEntries(root, lockName, originalUnlink) {
  for (const name of fs.readdirSync(root)) {
    if (!name.startsWith(lockName + '.lease-v2-')) continue;
    try { originalUnlink.call(fs, path.join(root, name)); } catch {}
  }
}

function leaseEntries(root, lockName) {
  return fs.readdirSync(root)
    .filter((name) => name.startsWith(lockName + '.lease-v2-'));
}

async function writeLegacyDatabase(file) {
  const SQL = await initSqlJs({
    locateFile: (name) => path.join(path.dirname(require.resolve('sql.js')), name),
  });
  const database = new SQL.Database();
  database.run(`CREATE TABLE sync_jobs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    result_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    claim_keys_json TEXT,
    owner_pid INTEGER,
    owner_start_id TEXT
  )`);
  fs.writeFileSync(file, Buffer.from(database.export()), { mode: 0o600 });
  database.close();
}

test('an existing empty database fails closed instead of erasing durable task barriers', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-empty-db-'));
  const file = path.join(root, 'panel.sqlite3');
  fs.writeFileSync(file, Buffer.alloc(0), { mode: 0o600 });

  const db = new PanelDb(file);
  await assert.rejects(db.ready, (error) => error.code === 'PANEL_DB_EMPTY');
  assert.equal(fs.statSync(file).size, 0);
});

test('malformed live owner identities are unverifiable rather than reclaimable', async () => {
  const owner = currentProcessOwner();
  assert.equal(isProcessOwnerAlive(process.pid, 'not-a-start-id', owner.processBootId), true);
  assert.equal(isProcessOwnerAlive(
    process.pid,
    owner.processStartId,
    '000000000000000000000000000000000000',
  ), true);
  assert.equal(isProcessOwnerAlive(
    2147483647,
    'not-a-start-id',
    '000000000000000000000000000000000000',
  ), false);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-owner-shape-'));
  const lockName = 'owner-shape.lock';
  const kind = 'test-malformed-owner-lock';
  const descriptor = fs.openSync(
    root,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0),
  );
  const accessDirectory = process.platform === 'linux'
    ? '/proc/self/fd/' + descriptor
    : root;
  const options = {
    directoryDescriptor: descriptor,
    accessDirectory,
    lockName,
    kind,
    owner,
    isOwnerAlive: isProcessOwnerAlive,
    timeoutMs: 50,
    pollMs: 5,
    timeoutCode: 'TEST_OWNER_TIMEOUT',
  };
  const malformedToken = 'a'.repeat(32);
  const malformedPath = path.join(
    root,
    lockName + '.lease-v2-' + malformedToken + '.ticket',
  );
  try {
    const initial = await acquireBakeryLease(options);
    releaseBakeryLease(initial);
    fs.writeFileSync(malformedPath, JSON.stringify({
      kind,
      protocol: 'lamport-bakery',
      version: 2,
      role: 'lease',
      phase: 'ticket',
      pid: process.pid,
      processStartId: owner.processStartId,
      processBootId: '000000000000000000000000000000000000',
      token: malformedToken,
      ticket: 1,
      createdAt: new Date().toISOString(),
    }), { mode: 0o600 });
    await assert.rejects(
      acquireBakeryLease(options),
      (error) => error.code === 'TEST_OWNER_TIMEOUT',
    );
    assert.equal(fs.existsSync(malformedPath), true);
  } finally {
    try { fs.unlinkSync(malformedPath); } catch {}
    fs.closeSync(descriptor);
  }
});

test('PanelDb distinguishes a proven boot mismatch from an unverifiable incomplete owner', async (context) => {
  const owner = currentProcessOwner();
  if (!owner.processBootId) {
    context.skip('Linux boot_id is unavailable');
    return;
  }

  const file = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-owner-boot-')),
    'panel.sqlite3',
  );
  await writeLegacyDatabase(file);
  const claimKey = 'phase3:owner-boot-mismatch';
  const db = new PanelDb(file);
  const abandoned = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  const storedOwner = await db.read((database) => queryRows(
    database,
    `SELECT owner_pid, owner_start_id, owner_boot_id FROM sync_jobs
      WHERE id = '${abandoned.id}'`,
  )[0]);
  assert.equal(storedOwner.owner_pid, owner.pid);
  assert.equal(storedOwner.owner_start_id, owner.processStartId);
  assert.equal(storedOwner.owner_boot_id, owner.processBootId);

  await db.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET owner_boot_id = ? WHERE id = ?');
    statement.run([alternateBootId(owner.processBootId), abandoned.id]);
    statement.free();
  });

  const restarted = new PanelDb(file);
  assert.equal((await restarted.getJob(abandoned.id)).status, 'interrupted');
  const replacement = await restarted.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  assert.equal(replacement.status, 'queued');
  await restarted.updateJob(replacement.id, { status: 'failed', error: 'test cleanup' });

  const liveClaimKey = 'phase3:owner-boot-live-reclaim';
  const liveAbandoned = await restarted.createJob('phase3', {}, 'tester', {
    claimKeys: [liveClaimKey],
  });
  await restarted.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET owner_boot_id = ? WHERE id = ?');
    statement.run([alternateBootId(owner.processBootId), liveAbandoned.id]);
    statement.free();
  });
  const liveReplacement = await restarted.createJob('phase3', {}, 'tester', {
    claimKeys: [liveClaimKey],
  });
  assert.equal((await restarted.getJob(liveAbandoned.id)).status, 'interrupted');
  assert.equal(liveReplacement.status, 'queued');
  await restarted.updateJob(liveReplacement.id, { status: 'failed', error: 'test cleanup' });

  const legacyClaimKey = 'phase3:owner-boot-missing';
  const legacyOwned = await restarted.createJob('phase3', {}, 'tester', {
    claimKeys: [legacyClaimKey],
  });
  await restarted.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET owner_boot_id = NULL WHERE id = ?');
    statement.run([legacyOwned.id]);
    statement.free();
  });
  const afterLegacyMigration = new PanelDb(file);
  const incompleteOwner = await afterLegacyMigration.getJob(legacyOwned.id);
  assert.equal(incompleteOwner.status, 'interrupted');
  assert.equal(incompleteOwner.result.executionOutcome, 'unknown');
  assert.equal(incompleteOwner.result.reconciliationReason, 'owner_identity_unverifiable');
  assert.equal(incompleteOwner.result.reconciliationHold, true);
  assert.equal(incompleteOwner.result.reconciliationHoldScope, 'claim_keys');
  await assert.rejects(
    afterLegacyMigration.createJob('phase3', {}, 'tester', {
      claimKeys: [legacyClaimKey],
    }),
    (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
      && error.existingJobId === legacyOwned.id,
  );
  assert.equal((await afterLegacyMigration.getJob(legacyOwned.id)).status, 'interrupted');
});

test('malformed persisted owner fields become unknown holds instead of dead-owner releases', async (context) => {
  const owner = currentProcessOwner();
  if (!owner.processStartId || !owner.processBootId) {
    context.skip('full Linux process identity is unavailable');
    return;
  }
  const variants = [
    {
      label: 'start-format',
      pid: owner.pid,
      startId: 'not-a-start-time',
      bootId: owner.processBootId,
    },
    {
      label: 'boot-format',
      pid: owner.pid,
      startId: owner.processStartId,
      bootId: 'not-a-boot-id',
    },
    {
      label: 'pid-storage-type',
      pid: 'not-a-pid',
      startId: owner.processStartId,
      bootId: owner.processBootId,
    },
    {
      label: 'pid-fraction',
      pid: 1.5,
      startId: owner.processStartId,
      bootId: owner.processBootId,
    },
    {
      label: 'pid-unsafe-integer',
      pid: Number.MAX_SAFE_INTEGER + 1,
      startId: owner.processStartId,
      bootId: owner.processBootId,
    },
  ];

  for (const variant of variants) {
    const file = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-owner-' + variant.label + '-')),
      'panel.sqlite3',
    );
    const db = new PanelDb(file);
    const claimKey = 'phase3:malformed-owner:' + variant.label;
    const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
    await db.write((database) => {
      const statement = database.prepare(`UPDATE sync_jobs
        SET owner_pid = ?, owner_start_id = ?, owner_boot_id = ? WHERE id = ?`);
      try {
        statement.run([variant.pid, variant.startId, variant.bootId, job.id]);
      } finally {
        statement.free();
      }
    });

    const restarted = new PanelDb(file);
    const held = await restarted.getJob(job.id);
    assert.equal(held.status, 'interrupted', variant.label);
    assert.equal(held.result.executionOutcome, 'unknown', variant.label);
    assert.equal(held.result.reconciliationReason, 'owner_identity_unverifiable', variant.label);
    assert.equal(held.result.reconciliationHold, true, variant.label);
    assert.equal(held.result.reconciliationHoldScope, 'claim_keys', variant.label);
    const claims = await restarted.read((database) => queryRows(
      database,
      `SELECT claim_key FROM job_claims WHERE job_id = '${job.id}'`,
    ));
    assert.deepEqual(claims.map((row) => row.claim_key), [claimKey], variant.label);
    await assert.rejects(
      restarted.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
      (error) => error.code === 'JOB_RECONCILIATION_REQUIRED'
        && error.existingJobId === job.id,
      variant.label,
    );
  }
});

test('bakery lock cancellation interrupts polling and removes only its own lease', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-bakery-abort-'));
  const lockName = 'abortable.lock';
  const descriptor = fs.openSync(
    root,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0),
  );
  const accessDirectory = process.platform === 'linux'
    ? '/proc/self/fd/' + descriptor
    : root;
  const baseOptions = {
    directoryDescriptor: descriptor,
    accessDirectory,
    lockName,
    kind: 'test-abortable-bakery-lock',
    owner: currentProcessOwner(),
    isOwnerAlive: () => true,
    timeoutMs: 10_000,
    // A long poll proves abort wakes the waiter instead of waiting for the
    // next timeout tick.
    pollMs: 5_000,
  };
  let firstLease;
  try {
    firstLease = await acquireBakeryLease(baseOptions);
    const controller = new AbortController();
    const waiting = acquireBakeryLease({ ...baseOptions, signal: controller.signal });
    const publishDeadline = Date.now() + 1_000;
    while (leaseEntries(root, lockName).length < 2 && Date.now() < publishDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(leaseEntries(root, lockName).length, 2);
    const abortedAt = Date.now();
    controller.abort();
    await assert.rejects(waiting, (error) => error.code === 'JOB_INTERRUPTED');
    assert.ok(Date.now() - abortedAt < 1_000, 'abort should wake a bakery lock waiter promptly');
    assert.equal(leaseEntries(root, lockName).length, 1);
    releaseBakeryLease(firstLease);
    firstLease = null;
    assert.deepEqual(leaseEntries(root, lockName), []);
  } finally {
    if (firstLease) releaseBakeryLease(firstLease);
    fs.closeSync(descriptor);
  }
});

test('bakery lock bounds the complete directory scan before allocating an unbounded name list', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-bakery-bounded-'));
  const lockName = 'bounded.lock';
  fs.writeFileSync(path.join(root, 'unrelated-a'), 'a');
  fs.writeFileSync(path.join(root, 'unrelated-b'), 'b');
  const descriptor = fs.openSync(
    root,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0),
  );
  const accessDirectory = process.platform === 'linux'
    ? '/proc/self/fd/' + descriptor
    : root;
  try {
    await assert.rejects(acquireBakeryLease({
      directoryDescriptor: descriptor,
      accessDirectory,
      lockName,
      kind: 'test-bounded-bakery-lock',
      owner: currentProcessOwner(),
      isOwnerAlive: () => true,
      timeoutMs: 1_000,
      pollMs: 10,
      maximumDirectoryEntries: 3,
      invalidCode: 'TEST_LOCK_DIRECTORY_LIMIT',
    }), (error) => error.code === 'TEST_LOCK_DIRECTORY_LIMIT'
      && /条目超过安全上限/.test(error.message));
    assert.deepEqual(leaseEntries(root, lockName), []);
    assert.equal(fs.existsSync(path.join(root, lockName)), true);
  } finally {
    fs.closeSync(descriptor);
  }
});

test('control-plane in-process queue cancellation never runs the queued callback', async () => {
  let releaseFirst;
  let markFirstEntered;
  const firstEntered = new Promise((resolve) => { markFirstEntered = resolve; });
  const first = withControlPlaneLock(async () => {
    markFirstEntered();
    await new Promise((resolve) => { releaseFirst = resolve; });
  });
  await firstEntered;

  const controller = new AbortController();
  let queuedCallbacks = 0;
  const queued = withControlPlaneLock(async () => {
    queuedCallbacks += 1;
  }, { signal: controller.signal });
  const abortedAt = Date.now();
  controller.abort();
  await assert.rejects(queued, (error) => error.code === 'JOB_INTERRUPTED');
  assert.ok(Date.now() - abortedAt < 1_000, 'queued abort should not wait for the preceding callback');
  assert.equal(queuedCallbacks, 0);

  releaseFirst();
  await first;
  await withControlPlaneLock(async () => {});
  assert.equal(queuedCallbacks, 0);
});

test('control-plane lease release retries bounded transient unlink failures', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-release-retry-'));
  const lockName = 'release-retry.lock';
  const lockPath = path.join(root, lockName);
  const previousPath = process.env.PANEL_CONTROL_LOCK_PATH;
  const originalUnlink = fs.unlinkSync;
  let injectedFailures = 0;
  process.env.PANEL_CONTROL_LOCK_PATH = lockPath;
  fs.unlinkSync = function injectedUnlink(filePath) {
    if (isTicketPath(filePath, lockName) && injectedFailures < 2) {
      injectedFailures += 1;
      const error = new Error('injected transient unlink failure');
      error.code = 'EBUSY';
      throw error;
    }
    return originalUnlink.call(fs, filePath);
  };
  try {
    await withControlPlaneLock(async () => {});
    assert.equal(injectedFailures, 2);
    await withControlPlaneLock(async () => {});
    assert.deepEqual(
      fs.readdirSync(root).filter((name) => name.startsWith(lockName + '.lease-v2-')),
      [],
    );
  } finally {
    fs.unlinkSync = originalUnlink;
    if (previousPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousPath;
    cleanupLeaseEntries(root, lockName, originalUnlink);
  }
});

test('control-plane lease release failure is reported and poisons the namespace', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-release-fail-'));
  const lockName = 'release-fail.lock';
  const lockPath = path.join(root, lockName);
  const previousPath = process.env.PANEL_CONTROL_LOCK_PATH;
  const originalUnlink = fs.unlinkSync;
  let attempts = 0;
  let callbacks = 0;
  process.env.PANEL_CONTROL_LOCK_PATH = lockPath;
  fs.unlinkSync = function injectedUnlink(filePath) {
    if (isTicketPath(filePath, lockName)) {
      attempts += 1;
      const error = new Error('injected permanent unlink failure');
      error.code = 'EBUSY';
      throw error;
    }
    return originalUnlink.call(fs, filePath);
  };
  try {
    await assert.rejects(
      withControlPlaneLock(async () => { callbacks += 1; }),
      (error) => error.code === 'CONTROL_PLANE_LOCK_RELEASE_FAILED',
    );
    assert.equal(attempts, 3);
    const startedAt = Date.now();
    await assert.rejects(
      withControlPlaneLock(async () => { callbacks += 1; }),
      (error) => error.code === 'CONTROL_PLANE_LOCK_RELEASE_FAILED',
    );
    assert.equal(callbacks, 1);
    assert.ok(Date.now() - startedAt < 1000, 'poisoned namespace should fail without lock timeout');
  } finally {
    fs.unlinkSync = originalUnlink;
    if (previousPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousPath;
    cleanupLeaseEntries(root, lockName, originalUnlink);
  }
});

test('a directory fsync release failure poisons the namespace after ticket unlink', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-release-fsync-'));
  const lockName = 'release-fsync.lock';
  const previousPath = process.env.PANEL_CONTROL_LOCK_PATH;
  const originalUnlink = fs.unlinkSync;
  const originalFsync = fs.fsyncSync;
  let failDirectorySync = false;
  let directorySyncFailures = 0;
  let callbacks = 0;
  process.env.PANEL_CONTROL_LOCK_PATH = path.join(root, lockName);
  fs.unlinkSync = function unlinkThenFailDirectorySync(filePath) {
    const result = originalUnlink.call(fs, filePath);
    if (isTicketPath(filePath, lockName)) failDirectorySync = true;
    return result;
  };
  fs.fsyncSync = function injectedDirectorySyncFailure(descriptor) {
    if (failDirectorySync && fs.fstatSync(descriptor).isDirectory()) {
      directorySyncFailures += 1;
      const error = new Error('injected directory durability failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsync.call(fs, descriptor);
  };
  try {
    await assert.rejects(
      withControlPlaneLock(async () => { callbacks += 1; }),
      (error) => error.code === 'CONTROL_PLANE_LOCK_RELEASE_FAILED',
    );
    assert.ok(directorySyncFailures >= 3);
    assert.deepEqual(leaseEntries(root, lockName), []);

    failDirectorySync = false;
    const startedAt = Date.now();
    await assert.rejects(
      withControlPlaneLock(async () => { callbacks += 1; }),
      (error) => error.code === 'CONTROL_PLANE_LOCK_RELEASE_FAILED',
    );
    assert.equal(callbacks, 1);
    assert.ok(Date.now() - startedAt < 1000, 'durability failure must poison the namespace');
  } finally {
    fs.fsyncSync = originalFsync;
    fs.unlinkSync = originalUnlink;
    if (previousPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousPath;
    cleanupLeaseEntries(root, lockName, originalUnlink);
  }
});

test('PanelDb propagates lease release failures and fails later writes fast', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-release-fail-'));
  const file = path.join(root, 'panel.sqlite3');
  const lockName = 'panel.sqlite3.lock';
  const previousTimeout = process.env.PANEL_DB_LOCK_TIMEOUT_MS;
  const originalUnlink = fs.unlinkSync;
  const db = new PanelDb(file);
  await db.ready;
  let attempts = 0;
  fs.unlinkSync = function injectedUnlink(filePath) {
    if (isTicketPath(filePath, lockName)) {
      attempts += 1;
      const error = new Error('injected permanent unlink failure');
      error.code = 'EBUSY';
      throw error;
    }
    return originalUnlink.call(fs, filePath);
  };
  process.env.PANEL_DB_LOCK_TIMEOUT_MS = '5000';
  try {
    await assert.rejects(
      db.audit({ actor: 'tester', action: 'release_failure', result: 'ok' }),
      (error) => error.code === 'DB_LOCK_RELEASE_FAILED',
    );
    assert.equal(attempts, 3);
    const startedAt = Date.now();
    await assert.rejects(
      db.audit({ actor: 'tester', action: 'must_not_run', result: 'ok' }),
      (error) => error.code === 'DB_LOCK_RELEASE_FAILED',
    );
    assert.ok(Date.now() - startedAt < 1000, 'poisoned DB namespace should fail without lock timeout');
  } finally {
    fs.unlinkSync = originalUnlink;
    if (previousTimeout === undefined) delete process.env.PANEL_DB_LOCK_TIMEOUT_MS;
    else process.env.PANEL_DB_LOCK_TIMEOUT_MS = previousTimeout;
    cleanupLeaseEntries(root, lockName, originalUnlink);
  }
});
