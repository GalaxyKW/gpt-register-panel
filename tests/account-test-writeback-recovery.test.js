'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
require('./test-isolation');
const { accountTestTargetBaseline, runAccountTestJobNow } = require('../backend/accountTestWorker');
const { accountTestTargetDigest } = require('../backend/accountTargetRevision');

function fixture(options = {}) {
  let account = {
    id: 47, name: 'free00047', platform: 'openai', type: 'oauth', planType: 'free',
    status: 'active', schedulable: false, groupIds: [1],
    identityKeys: ['account:written-account', 'user:written-user'],
    tokenFingerprints: { access: 'a'.repeat(64), refresh: 'b'.repeat(64) },
    maintenanceEvidence: { category: 'network_unknown', code: 'no_error_evidence' },
    ...options.initial,
  };
  const baseline = accountTestTargetBaseline(account);
  const calls = []; const logs = [];
  const copy = () => structuredClone(account);
  const f = {
    calls, logs,
    get account() { return copy(); },
    change(values) { account = { ...account, ...values }; },
    async run(extra = {}) {
      return runAccountTestJobNow({
        accountIds: [47], targetBaselines: [baseline], jobId: 'writeback-recovery-test',
        logger: {
          checkpoint() { return true; },
          info(event, fields) { logs.push({ event, fields }); },
          warn(event, fields) { logs.push({ event, fields }); },
          error(event, fields) { logs.push({ event, fields }); },
        },
        client: {
          async listAccounts() { calls.push('list'); return [copy()]; },
          async getAccount() { calls.push('get'); return copy(); },
          async testAccount() {
            calls.push('test');
            if (options.afterTest) f.change(options.afterTest);
            if (options.testUnknown) throw Object.assign(new Error('synthetic test response lost'), {
              code: 'SUB2API_TEST_UNKNOWN', requiresReconciliation: true, testOutcomeUnknown: true,
              reconciliationScope: 'test',
            });
            return { success: options.testSuccess !== false, ...options.testFlags };
          },
          async setSchedulable(id, enabled) {
            calls.push('enable'); assert.equal(id, 47); assert.equal(enabled, true);
            if (options.writeUnknown) throw Object.assign(new Error('synthetic scheduler response lost'), {
              code: 'SUB2API_WRITE_UNKNOWN', requiresReconciliation: true, writeOutcomeUnknown: true,
            });
            account = { ...account, schedulable: enabled }; return copy();
          },
        },
        ...extra,
      });
    },
  };
  return f;
}

test('proven credential writeback resumes active unscheduled account through test and scheduler recovery', async () => {
  const f = fixture();
  const result = await f.run({
    async beforeTestAccount(account) { f.calls.push('policy'); assert.equal(account.status, 'active'); },
    async authorizeSchedulingRecovery(account) {
      f.calls.push('authorize'); assert.equal(account.schedulable, false); return true;
    },
  });
  assert.equal(result.succeeded, 1); assert.equal(result.failed, 0);
  assert.equal(result.results[0].code, 'account_recovered');
  assert.equal(result.results[0].statusBefore, 'active');
  assert.equal(result.results[0].enabled, true);
  assert.equal(f.account.schedulable, true);
  assert.deepEqual(f.calls, ['list', 'get', 'policy', 'authorize', 'get', 'policy', 'test', 'get', 'enable', 'get']);
});

test('failed model test after proven writeback never enables scheduling', async () => {
  const f = fixture({ testSuccess: false });
  const result = await f.run({ authorizeSchedulingRecovery: async () => true });
  assert.equal(result.failed, 1); assert.equal(result.results[0].testSuccess, false);
  assert.equal(result.requiresReconciliation, false);
  assert.equal(f.calls.filter(call => call === 'test').length, 1);
  assert.equal(f.calls.includes('enable'), false); assert.equal(f.account.schedulable, false);
});

test('ordinary active unscheduled tests preserve the setting without an internal writeback authorization', async () => {
  const f = fixture();
  const result = await f.run();
  assert.equal(result.succeeded, 1); assert.equal(result.results[0].enabled, false);
  assert.equal(result.results[0].code, 'account_test_succeeded');
  assert.equal(f.calls.includes('enable'), false); assert.equal(f.account.schedulable, false);
});

test('explicit recovery requires a strict true authorization before any probe', async () => {
  for (const permission of [false, undefined, null, 1, 'true', {}]) {
    const f = fixture();
    const result = await f.run({ authorizeSchedulingRecovery: async () => permission });
    assert.equal(result.failed, 1); assert.equal(result.attemptedCount, 0);
    assert.equal(result.results[0].code, 'ACCOUNT_TEST_RECOVERY_NOT_AUTHORIZED');
    assert.equal(result.results[0].attempted, false);
    assert.equal(result.requiresReconciliation, false);
    assert.equal(f.calls.includes('test'), false); assert.equal(f.calls.includes('enable'), false);
  }
});

test('non-callable or failing recovery authorization never sends a test and redacts errors', async () => {
  const invalid = fixture();
  const invalidResult = await invalid.run({ authorizeSchedulingRecovery: 'allow' });
  assert.equal(invalidResult.results[0].code, 'ACCOUNT_TEST_POLICY_INVALID');
  assert.equal(invalid.calls.includes('test'), false);
  const f = fixture();
  const result = await f.run({ authorizeSchedulingRecovery: async () => {
    throw new Error('Authorization: Bearer synthetic-private-authorization-value');
  } });
  assert.equal(result.attemptedCount, 0); assert.equal(result.results[0].attempted, false);
  assert.equal(f.calls.includes('test'), false); assert.equal(f.calls.includes('enable'), false);
  assert.equal(JSON.stringify({ result, logs: f.logs }).includes('synthetic-private-authorization-value'), false);
});

test('recovery proof cannot survive target changes during its asynchronous lookup', async () => {
  const changes = [
    { identityKeys: ['account:replacement', 'user:replacement'] },
    { tokenFingerprints: { access: 'c'.repeat(64), refresh: 'b'.repeat(64) } },
    { groupIds: [2] },
    { proxyId: 8, proxyIdPresent: true },
    { status: 'inactive' },
    { schedulable: true },
    { expiresAt: '2000-01-01T00:00:00.000Z', expiryStatus: 'valid' },
  ];
  for (const change of changes) {
    const f = fixture();
    const result = await f.run({ authorizeSchedulingRecovery: async () => { f.change(change); return true; } });
    assert.equal(result.failed, 1, JSON.stringify(change)); assert.equal(result.attemptedCount, 0);
    assert.equal(f.calls.includes('test'), false); assert.equal(f.calls.includes('enable'), false);
  }
});

test('new console maintenance evidence is checked again after the recovery proof lookup', async () => {
  const f = fixture(); let policyCalls = 0;
  const result = await f.run({
    authorizeSchedulingRecovery: async () => {
      f.change({ maintenanceEvidence: { category: 'quota_wait', code: 'quota_or_cooldown' } }); return true;
    },
    beforeTestAccount: async account => {
      policyCalls += 1;
      if (account.maintenanceEvidence.category === 'quota_wait') throw Object.assign(new Error('quota changed'), {
        code: 'CONSOLE_TEST_TARGET_CHANGED',
      });
    },
  });
  assert.equal(policyCalls, 2); assert.equal(result.results[0].code, 'CONSOLE_TEST_TARGET_CHANGED');
  assert.equal(result.attemptedCount, 0); assert.equal(f.calls.includes('test'), false);
});

test('a proven writeback does not bypass current account lifetime or quota restrictions', async () => {
  const blockers = [
    { expiresAt: '2000-01-01T00:00:00.000Z', expiryStatus: 'valid' },
    { rateLimitResetAt: '2099-01-01T00:00:00.000Z', rateLimitResetStatus: 'valid' },
    { tempUnschedulableUntil: '2099-01-01T00:00:00.000Z', tempUnschedulableUntilStatus: 'valid' },
    { maintenanceEvidence: { category: 'quota_wait', code: 'quota_or_cooldown' } },
    { maintenanceEvidence: { category: 'confirmed_banned', code: 'account_deactivated' } },
  ];
  for (const initial of blockers) {
    const f = fixture({ initial });
    const result = await f.run({ authorizeSchedulingRecovery: async () => true });
    assert.equal(result.results[0].code, 'ACCOUNT_TEST_RECOVERY_NOT_ALLOWED');
    assert.equal(result.attemptedCount, 0); assert.equal(f.calls.includes('test'), false);
    assert.equal(f.calls.includes('enable'), false);
  }
});

test('inactive accounts cannot be promoted to recovery by the new authorization hook', async () => {
  const f = fixture({ initial: { status: 'inactive' } }); let calls = 0;
  const result = await f.run({ authorizeSchedulingRecovery: async () => { calls += 1; return true; } });
  assert.equal(calls, 0); assert.equal(result.results[0].enabled, false);
  assert.equal(f.calls.includes('enable'), false); assert.equal(f.account.status, 'inactive');
});

test('post-test credentials or ownership changes still prevent writeback scheduler recovery', async () => {
  for (const afterTest of [
    { tokenFingerprints: { access: 'c'.repeat(64), refresh: 'b'.repeat(64) } },
    { identityKeys: ['account:replaced', 'user:replaced'] },
    { groupIds: [2] },
    { proxyId: 8, proxyIdPresent: true },
  ]) {
    const f = fixture({ afterTest });
    const result = await f.run({ authorizeSchedulingRecovery: async () => true });
    assert.equal(result.failed, 1); assert.equal(result.results[0].testSuccess, true);
    assert.equal(result.requiresReconciliation, true); assert.equal(f.calls.includes('enable'), false);
  }
});

test('post-test quota and manual disable keep a proven writeback unscheduled', async () => {
  for (const afterTest of [
    { status: 'inactive' },
    { rateLimitResetAt: '2099-01-01T00:00:00.000Z', rateLimitResetStatus: 'valid' },
    { maintenanceEvidence: { category: 'quota_wait', code: 'quota_or_cooldown' } },
  ]) {
    const f = fixture({ afterTest });
    const result = await f.run({ authorizeSchedulingRecovery: async () => true });
    assert.equal(result.results[0].code, 'account_recovery_not_confirmed');
    assert.equal(result.results[0].testSuccess, true); assert.equal(result.requiresReconciliation, false);
    assert.equal(f.calls.includes('enable'), false); assert.equal(f.account.schedulable, false);
  }
});

test('unknown scheduler response after authorized writeback recovery preserves the reconciliation hold', async () => {
  const f = fixture({ writeUnknown: true });
  const result = await f.run({ authorizeSchedulingRecovery: async () => true });
  assert.equal(result.failed, 1); assert.equal(result.requiresReconciliation, true);
  assert.equal(result.results[0].code, 'account_scheduler_reconciliation_required');
  assert.equal(result.results[0].testSuccess, true); assert.equal(result.results[0].writeOutcomeUnknown, true);
  assert.equal(f.calls.filter(call => call === 'enable').length, 1);
});

test('known failed authorized probe records its verified post-test version for a later retry', async () => {
  const updatedAt = '2026-11-02T02:30:00.123456Z';
  const f = fixture({ initial: { updatedAt: '2026-11-02T02:29:00.000001Z' },
    afterTest: { updatedAt }, testSuccess: false });
  const result = await f.run({ authorizeSchedulingRecovery: async () => true });
  assert.equal(result.requiresReconciliation, false); assert.equal(result.results[0].code, 'upstream_test_failed');
  assert.deepEqual(result.results[0].recoveryObservation, {
    targetDigest: accountTestTargetDigest(f.account), updatedAt,
  });
  assert.equal(f.calls.includes('enable'), false);
});

test('ordinary tests and invalid post-test versions never create recovery observations', async () => {
  const withoutAuthorization = fixture({ initial: { updatedAt: '2026-11-02T02:30:00.123456Z' }, testSuccess: false });
  const plain = await withoutAuthorization.run();
  assert.equal(Object.hasOwn(plain.results[0], 'recoveryObservation'), false);
  for (const updatedAt of [undefined, null, '', 'not-a-date', '2026-11-02']) {
    const f = fixture({ afterTest: { updatedAt }, testSuccess: false });
    const result = await f.run({ authorizeSchedulingRecovery: async () => true });
    assert.equal(Object.hasOwn(result.results[0], 'recoveryObservation'), false);
  }
});

test('unknown or ambiguously flagged probe failures never advance recovery evidence', async () => {
  for (const options of [
    { testUnknown: true },
    { testSuccess: false, testFlags: { requiresReconciliation: true } },
    { testSuccess: false, testFlags: { writeOutcomeUnknown: true } },
    { testSuccess: false, testFlags: { testOutcomeUnknown: true } },
  ]) {
    const f = fixture({ ...options, afterTest: { updatedAt: '2026-11-02T02:30:00.123456Z' } });
    const result = await f.run({ authorizeSchedulingRecovery: async () => true });
    assert.equal(Object.hasOwn(result.results[0], 'recoveryObservation'), false);
    assert.equal(f.calls.includes('enable'), false);
    if (options.testUnknown) assert.equal(result.requiresReconciliation, true);
  }
});
