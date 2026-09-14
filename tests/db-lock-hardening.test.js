const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const initSqlJs = require('sql.js');

require('./test-isolation');

const { PanelDb } = require('../backend/db');
const { currentProcessOwner, withControlPlaneLock } = require('../backend/taskCoordinator');
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

test('PanelDb persists boot identity and rejects a live PID from another boot', async (context) => {
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
  assert.equal((await afterLegacyMigration.getJob(legacyOwned.id)).status, 'interrupted');
  const afterLegacyReplacement = await afterLegacyMigration.createJob('phase3', {}, 'tester', {
    claimKeys: [legacyClaimKey],
  });
  assert.equal(afterLegacyReplacement.status, 'queued');
  await afterLegacyMigration.updateJob(afterLegacyReplacement.id, {
    status: 'failed',
    error: 'test cleanup',
  });
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
