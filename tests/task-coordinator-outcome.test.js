const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { withControlPlaneLock } = require('../backend/taskCoordinator');

function isTicketPath(filePath, lockName) {
  const name = path.basename(String(filePath));
  return name.startsWith(lockName + '.lease-v2-') && name.endsWith('.ticket');
}

function leaseEntries(root, lockName) {
  return fs.readdirSync(root)
    .filter((name) => name.startsWith(lockName + '.lease-v2-'));
}

function cleanupLeaseEntries(root, lockName, originalUnlink) {
  for (const name of leaseEntries(root, lockName)) {
    try { originalUnlink.call(fs, path.join(root, name)); } catch {}
  }
}

async function withInjectedReleaseFailure(prefix, callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const lockName = 'control.lock';
  const previousPath = process.env.PANEL_CONTROL_LOCK_PATH;
  const originalUnlink = fs.unlinkSync;
  let attempts = 0;
  process.env.PANEL_CONTROL_LOCK_PATH = path.join(root, lockName);
  fs.unlinkSync = function injectedUnlink(filePath) {
    if (isTicketPath(filePath, lockName)) {
      attempts += 1;
      const error = new Error('release credential=must-not-escape');
      error.code = 'EBUSY';
      throw error;
    }
    return originalUnlink.call(fs, filePath);
  };
  try {
    await callback({ root, lockName, attempts: () => attempts });
  } finally {
    fs.unlinkSync = originalUnlink;
    if (previousPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousPath;
    cleanupLeaseEntries(root, lockName, originalUnlink);
  }
}

test('successful critical section plus release failure returns a safe non-retryable outcome', async () => {
  await withInjectedReleaseFailure('gpt-register-panel-completed-release-', async ({ attempts }) => {
    let observed;
    try {
      await withControlPlaneLock(async () => ({
        accountId: 42,
        credential: 'Bearer highly-sensitive-value',
        nested: {
          password: 'highly-sensitive-password',
          note: 'access_token=highly-sensitive-token',
        },
        customSerialization: {
          toJSON() {
            return { password: 'highly-sensitive-to-json', safeCount: 2 };
          },
        },
      }));
      assert.fail('release failure must reject after the callback completed');
    } catch (error) {
      observed = error;
    }

    assert.equal(attempts(), 3);
    assert.equal(observed.code, 'CONTROL_PLANE_LOCK_RELEASE_FAILED');
    assert.equal(observed.criticalSectionCompleted, true);
    assert.equal(observed.controlPlaneLeaseReleaseFailed, true);
    assert.equal(observed.requiresReconciliation, true);
    assert.equal(observed.retryAllowed, false);
    assert.equal(observed.doNotRetry, true);
    assert.equal(observed.criticalSectionResultAvailable, true);
    assert.equal(observed.criticalSectionResult.accountId, 42);
    assert.equal(observed.criticalSectionResult.credential, '[redacted]');
    assert.equal(observed.criticalSectionResult.nested.password, '[redacted]');
    assert.equal(observed.criticalSectionResult.customSerialization.toJSON, '[redacted]');
    assert.equal(observed.criticalSectionResult.customSerialization.password, undefined);
    assert.equal(observed.criticalSectionResult.customSerialization.safeCount, undefined);
    assert.doesNotMatch(JSON.stringify(observed), /highly-sensitive/);
    assert.equal(observed.releaseFailure.code, 'CONTROL_PLANE_LOCK_RELEASE_FAILED');
    assert.doesNotMatch(JSON.stringify(observed.releaseFailure), /must-not-escape/);
  });
});

test('callback failure remains the primary error when lease release also fails', async () => {
  await withInjectedReleaseFailure('gpt-register-panel-failed-release-', async ({ attempts }) => {
    const primary = new Error('业务校验失败');
    primary.code = 'BUSINESS_VALIDATION_FAILED';
    primary.businessMarker = 'preserved';
    let observed;
    try {
      await withControlPlaneLock(async () => { throw primary; });
      assert.fail('callback failure must reject');
    } catch (error) {
      observed = error;
    }

    assert.strictEqual(observed, primary);
    assert.equal(observed.code, 'BUSINESS_VALIDATION_FAILED');
    assert.equal(observed.message, '业务校验失败');
    assert.equal(observed.businessMarker, 'preserved');
    assert.equal(observed.criticalSectionCompleted, false);
    assert.equal(observed.controlPlaneLeaseReleaseFailed, true);
    assert.equal(observed.releaseFailure.code, 'CONTROL_PLANE_LOCK_RELEASE_FAILED');
    assert.doesNotMatch(JSON.stringify(observed.releaseFailure), /must-not-escape/);
    assert.equal(observed.requiresReconciliation, undefined);
    assert.equal(observed.doNotRetry, undefined);
    assert.equal(attempts(), 3);
  });
});

test('ordinary callback failure releases its lease and preserves the original error', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-callback-fail-'));
  const lockName = 'control.lock';
  const previousPath = process.env.PANEL_CONTROL_LOCK_PATH;
  process.env.PANEL_CONTROL_LOCK_PATH = path.join(root, lockName);
  const primary = new Error('expected callback failure');
  primary.code = 'EXPECTED_CALLBACK_FAILURE';
  try {
    let observed;
    try {
      await withControlPlaneLock(async () => { throw primary; });
      assert.fail('callback failure must reject');
    } catch (error) {
      observed = error;
    }
    assert.strictEqual(observed, primary);
    assert.deepEqual(leaseEntries(root, lockName), []);
    await withControlPlaneLock(async () => 'next callback ran');
    assert.deepEqual(leaseEntries(root, lockName), []);
  } finally {
    if (previousPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousPath;
  }
});
