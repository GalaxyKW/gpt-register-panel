'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
require('./test-isolation');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { accountTestTargetRevision, accountTestTargetDigest } = require('../backend/accountTargetRevision');
const { remotePhase3EndpointDigest } = require('../backend/remotePhase3');
const { findPendingWritebackRecoveries, matchesWritebackProof, resolveImmediateWritebackRecovery } = require('../backend/writebackRecovery');

function fixture() {
  const client = { baseUrl: 'http://127.0.0.1:9' };
  const raw = { id: 47, name: 'free00047', platform: 'openai', type: 'oauth', status: 'active', schedulable: false,
    group_ids: [1], updated_at: '2026-11-02T10:13:54.899190+08:00', credentials: {
      chatgpt_account_id: 'synthetic-account', chatgpt_user_id: 'synthetic-user', plan_type: 'free',
      access_token: 'synthetic-access-not-a-real-token', refresh_token: 'synthetic-refresh-not-a-real-token',
      expires_at: '2099-01-01T00:00:00Z' } };
  const account = safeAccount(raw), parentId = 'job_' + 'a'.repeat(24), phaseId = 'job_' + 'b'.repeat(24), importId = 'job_' + 'c'.repeat(24);
  const source = { action: 'update', accountId: 47, sourceIdentityKeys: [...account.identityKeys],
    fingerprints: { ...account.tokenFingerprints }, relativePath: 'tokens/synthetic.json', sourceExpired: false };
  const original = safeAccount({ ...raw, status: 'error', error_message: '{"error":{"code":"invalid_grant"}}' });
  const parent = { id: parentId, type: 'console_maintain', status: 'partial', result: {
    childJobIds: [phaseId, importId], items: [{ accountId: 47, status: 'failed', code: 'CONSOLE_TEST_TARGET_CHANGED',
      phases: { tokenGenerated: true, tokenUpdated: true, tested: false, verified: false } }] } };
  const phase = { id: phaseId, type: 'phase3', status: 'succeeded', finishedAt: '2026-11-02T02:13:53Z',
    payload: { parentJobId: parentId, remoteTarget: { accountId: 47, identityKeys: [...original.identityKeys],
      targetRevision: accountTestTargetRevision(original), targetDigest: accountTestTargetDigest(original),
      endpointDigest: remotePhase3EndpointDigest(client) } }, result: { tokenFile: source.relativePath } };
  const imported = { id: importId, type: 'token_import', status: 'succeeded',
    startedAt: '2026-11-02T02:13:54Z', finishedAt: '2026-11-02T02:13:55Z', payload: { parentJobId: parentId },
    result: { succeeded: 1, failed: 0, items: [source], imported: [{ action: 'update', accountId: 47,
      result: { success: true, accountId: 47, updated: 1, failed: 0 },
      verification: { accountId: 47, status: 'active', fingerprint: source.fingerprints.access } }] } };
  const jobs = new Map([[parentId, parent], [phaseId, phase], [importId, imported]]);
  const db = { listWritebackRecoveryJobReferences: async () => [parentId], getJob: async id => jobs.get(id),
    getJobForReconciliation: async id => ({ status: jobs.get(id)?.status, reconciliationHold: false, reconciliationContext: null }) };
  return { client, raw, account, original, parent, phase, imported, jobs, db,
    find: () => findPendingWritebackRecoveries({ db, accounts: [safeAccount(raw)], client }) };
}

test('safe account retains a precise change marker without accepting malformed or conflicting timestamps', () => {
  const f = fixture(); assert.equal(f.account.updatedAt, f.raw.updated_at);
  assert.equal(safeAccount({ ...f.raw, updated_at: 'Bearer SYNTHETIC_SECRET' }).updatedAt, null);
  assert.equal(safeAccount({ ...f.raw, updatedAt: '2026-11-03T00:00:00Z' }).updatedAt, null);
});

test('legacy verified writeback exposes only a candidate until a current explicit test selection authorizes its policy', async () => {
  const f = fixture(), found = await f.find();
  assert.equal(found.size, 1);
  const proof = found.get(47); assert.equal(proof.importJobId, f.imported.id);
  assert.equal(proof.requiresExplicitTestSelection, true);
  assert.equal(matchesWritebackProof(proof, f.account, f.client), false);
  assert.equal(matchesWritebackProof(proof, { ...f.account, updatedAt: '2026-11-02T10:13:54.899191+08:00' }, f.client), false);
});

for (const [name, change] of [
  ['later manual scheduling change', f => { f.raw.updated_at = '2026-11-02T02:13:56Z'; }],
  ['old remote version', f => { f.raw.updated_at = '2026-11-02T02:13:53Z'; }],
  ['missing change marker', f => { delete f.raw.updated_at; }],
  ['other original ID', f => { f.phase.payload.remoteTarget.accountId = 48; }],
  ['different service', f => { f.client.baseUrl = 'http://127.0.0.1:10'; }],
  ['different strong identity', f => { f.raw.credentials.chatgpt_account_id = 'other-account'; }],
  ['changed refresh credential', f => { f.raw.credentials.refresh_token = 'synthetic-new-refresh'; }],
  ['mismatched source file', f => { f.phase.result.tokenFile = 'tokens/other.json'; }],
  ['unknown import outcome', f => { f.imported.result.requiresReconciliation = true; }],
  ['failed import', f => { f.imported.status = 'failed'; }],
  ['already tested original flow', f => { f.parent.result.items[0].phases.tested = true; }],
  ['quota pause', f => { f.raw.error_message = '{"error":{"code":"insufficient_quota"}}'; }],
  ['explicit inactive account', f => { f.raw.status = 'inactive'; }],
  ['administrator account expiry', f => { f.raw.expires_at = '2001-01-01T00:00:00Z'; }],
]) test('writeback recovery rejects ' + name, async () => { const f = fixture(); change(f); assert.equal((await f.find()).size, 0); });

test('immediate writeback uses its execution endpoint and requires the original error account', async () => {
  const f = fixture();
  const args = { db: f.db, parent: f.parent, origin: f.original, account: f.account, client: f.client,
    importJobId: f.imported.id, importEndpointDigest: remotePhase3EndpointDigest(f.client) };
  assert.ok(await resolveImmediateWritebackRecovery(args));
  assert.equal(await resolveImmediateWritebackRecovery({ ...args, origin: f.account }), null);
  assert.equal(await resolveImmediateWritebackRecovery({ ...args, importEndpointDigest: 'changed' }), null);
  assert.equal(await resolveImmediateWritebackRecovery({ ...args, account: { ...f.account, groupIds: [2] } }), null);
  assert.equal(await resolveImmediateWritebackRecovery({ ...args, account: { ...f.account, autoPauseOnExpired: !f.account.autoPauseOnExpired } }), null);
});

test('only an authorized known failed test may advance a persisted recovery version', async () => {
  const f = fixture(), proof = (await f.find()).get(47);
  delete proof.requiresExplicitTestSelection;
  const parentId = 'job_' + 'd'.repeat(24), testId = 'job_' + 'e'.repeat(24);
  f.raw.updated_at = '2026-11-02T02:14:00Z';
  const current = safeAccount(f.raw);
  const saved = { ...proof, updatedAt: current.updatedAt, targetDigest: accountTestTargetDigest(current), failedTestJobId: testId };
  f.jobs.set(parentId, { id: parentId, type: 'console_maintain', status: 'failed', result: {
    childJobIds: [testId], writebackRecoveries: [saved], items: [] } });
  const failed = { id: testId, type: 'account_test', status: 'failed', payload: { parentJobId: parentId }, result: {
    results: [{ accountId: 47, code: 'upstream_test_failed', testSuccess: false,
      recoveryObservation: { targetDigest: saved.targetDigest, updatedAt: saved.updatedAt } }] } };
  f.jobs.set(testId, failed); f.db.listWritebackRecoveryJobReferences = async () => [parentId, f.parent.id];
  assert.equal((await f.find()).size, 1);
  failed.result.requiresReconciliation = true; assert.equal((await f.find()).size, 0);
  delete failed.result.requiresReconciliation; failed.result.results[0].recoveryObservation.updatedAt = '2026-11-02T02:14:01Z';
  assert.equal((await f.find()).size, 0);
});

test('saved complete proof rejects a group-only change even when updated_at is unchanged', async () => {
  const f = fixture();
  const proof = await resolveImmediateWritebackRecovery({ db: f.db, parent: f.parent, origin: f.original,
    account: f.account, client: f.client, importJobId: f.imported.id, importEndpointDigest: remotePhase3EndpointDigest(f.client) });
  f.parent.result.writebackRecoveries = [proof];
  assert.equal(matchesWritebackProof((await f.find()).get(47), f.account, f.client), true);
  f.raw.group_ids = [2];
  const candidate = (await f.find()).get(47);
  assert.equal(candidate.requiresExplicitTestSelection, true);
  assert.equal(matchesWritebackProof(candidate, safeAccount(f.raw), f.client), false);
});
