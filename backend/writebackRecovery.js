'use strict';

const { accountTestTargetDigest, accountTestOwnershipDigest } = require('./accountTargetRevision');
const { accountInMaintenanceScope, lifecycleIdentityKeys } = require('./accountLifecycle');
const { classifyAccountMaintenance } = require('./accountMaintenance');
const { getAccountAvailability } = require('./accountAvailability');
const { remotePhase3EndpointDigest, validateBoundRemoteTarget } = require('./remotePhase3');
const { resolveImportTargetBinding } = require('./sync');
const { strongIdentityContradiction } = require('./diff');

const JOB = /^job_[a-f0-9]{24}$/;
const FINGERPRINT = /^[a-f0-9]{16}$/;
const strong = keys => (Array.isArray(keys) ? keys : []).filter(key => /^(account|user):/.test(key));
function pendingState(account) {
  return accountInMaintenanceScope(account) && account.status === 'active' && account.schedulable === false
    && classifyAccountMaintenance(account).reasonCode === 'administrator_unscheduled'
    && getAccountAvailability({ ...account, schedulable: true }).key === 'available'
    && typeof account.updatedAt === 'string' && Number.isFinite(Date.parse(account.updatedAt))
    && Boolean(accountTestTargetDigest(account));
}
function matchesWritebackProof(proof, account, client) {
  return proof?.requiresExplicitTestSelection !== true && pendingState(account) && proof?.accountId === account.id
    && proof.endpointDigest === remotePhase3EndpointDigest(client)
    && proof.updatedAt === account.updatedAt
    && proof.targetDigest === accountTestTargetDigest(account);
}
function refreshOrigin(origin, current) {
  const before = lifecycleIdentityKeys(origin), after = lifecycleIdentityKeys(current);
  const expectedOwnership = origin && accountTestOwnershipDigest({ ...origin, identityKeys: current.identityKeys,
    accountId: current.accountId, userId: current.userId, tokenFingerprints: current.tokenFingerprints,
    credentialPresence: current.credentialPresence });
  return origin?.id === current.id && origin.status === 'error'
    && ['expired', 'auth_invalid'].includes(classifyAccountMaintenance(origin).classification)
    && accountInMaintenanceScope(origin) && !strongIdentityContradiction(before, after)
    && strong(before).some(key => after.includes(key))
    && expectedOwnership !== null && expectedOwnership === accountTestOwnershipDigest(current)
    && ['expiresAt', 'expiryStatus', 'autoPauseOnExpired'].every(field => origin[field] === current[field]);
}
function verifiedImport(job, review, parentId, account, client, importUpdatedAt = account.updatedAt) {
  const result = job?.result;
  if (!JOB.test(job?.id || '') || job.type !== 'token_import' || job.status !== 'succeeded'
      || job.payload?.parentJobId !== parentId || !job.startedAt || !job.finishedAt
      || review?.status !== 'succeeded' || review.reconciliationHold !== false
      || (review.reconciliationContext && review.reconciliationContext.executionTarget?.fingerprint !== resolveImportTargetBinding(client).fingerprint)
      || result?.succeeded !== 1 || result.failed !== 0 || result.requiresReconciliation === true
      || result.writeOutcomeUnknown === true || result.halted === true
      || result.items?.length !== 1 || result.imported?.length !== 1) return false;
  const item = result.items[0], imported = result.imported[0], verified = imported.verification;
  const keys = strong(item.sourceIdentityKeys), currentKeys = lifecycleIdentityKeys(account);
  const target = review.reconciliationContext?.targets?.find(row => row.remoteAccountId === account.id);
  if (item.action !== 'update' || item.accountId !== account.id || item.identityConflict === true
      || item.sourceExpired === true || !keys.length || keys.some(key => !currentKeys.includes(key))
      || strongIdentityContradiction(keys, currentKeys)
      || (review.reconciliationContext && (target?.action !== 'update' || target.accessFingerprint !== item.fingerprints?.access))
      || imported.action !== 'update' || imported.accountId !== account.id
      || imported.result?.updated !== 1 || imported.result?.failed !== 0
      || imported.result?.accountId !== account.id || imported.result?.success !== true
      || verified?.accountId !== account.id || verified.status !== 'active'
      || !FINGERPRINT.test(item.fingerprints?.access || '') || verified.fingerprint !== item.fingerprints.access) return false;
  for (const field of ['access', 'refresh', 'id']) {
    if (item.fingerprints?.[field] && item.fingerprints[field] !== account.tokenFingerprints?.[field]) return false;
  }
  // Scheduling changes increment updated_at. Group-only edits may not, so
  // this window alone is never a complete recovery authorization.
  const updated = Date.parse(importUpdatedAt);
  return updated >= Date.parse(job.startedAt) && updated <= Date.parse(job.finishedAt);
}
function makeProof(account, client, importJobId, originParentId) {
  return { accountId: account.id, importJobId, originParentId, importUpdatedAt: account.updatedAt, endpointDigest: remotePhase3EndpointDigest(client),
    updatedAt: account.updatedAt, targetDigest: accountTestTargetDigest(account) };
}
async function resolveImmediateWritebackRecovery({ db, parent, origin, account, client, importJobId, importEndpointDigest }) {
  if (!pendingState(account) || !refreshOrigin(origin, account)
      || importEndpointDigest !== remotePhase3EndpointDigest(client)
      || !parent.result.childJobIds.includes(importJobId)) return null;
  const job = await db.getJob(importJobId), review = await db.getJobForReconciliation(importJobId);
  return verifiedImport(job, review, parent.id, account, client) ? makeProof(account, client, importJobId, parent.id) : null;
}
async function findPendingWritebackRecoveries({ db, accounts, client }) {
  const candidates = new Map(accounts.filter(pendingState).map(account => [account.id, account]));
  const proofs = new Map();
  if (!candidates.size) return proofs;
  const jobs = new Map(), reviews = new Map();
  const get = id => { if (!jobs.has(id)) jobs.set(id, db.getJob(id)); return jobs.get(id); };
  const review = id => { if (!reviews.has(id)) reviews.set(id, db.getJobForReconciliation(id)); return reviews.get(id); };
  for (const parentId of await db.listWritebackRecoveryJobReferences()) {
    if (proofs.size === candidates.size) break;
    const parent = await get(parentId);
    if (parent?.type !== 'console_maintain' || parent.result?.requiresReconciliation
        || parent.result?.writeOutcomeUnknown) continue;
    const children = parent.result?.childJobIds;
    if (!Array.isArray(children) || children.length > 3000 || children.some(id => !JOB.test(id))) continue;
    for (const saved of Array.isArray(parent.result.writebackRecoveries) ? parent.result.writebackRecoveries : []) {
      const account = candidates.get(saved.accountId);
      if (!account || proofs.has(account.id) || !JOB.test(saved.originParentId || '') || !JOB.test(saved.importJobId || '')
          || !matchesWritebackProof(saved, account, client)) continue;
      const origin = await get(saved.originParentId);
      if (origin?.type !== 'console_maintain' || !origin.result?.childJobIds?.includes(saved.importJobId)) continue;
      if (saved.failedTestJobId) {
        if (!children.includes(saved.failedTestJobId)) continue;
        const test = await get(saved.failedTestJobId), testReview = await review(saved.failedTestJobId);
        const outcome = test?.result?.results?.find(item => item.accountId === account.id);
        if (test?.type !== 'account_test' || test.status !== 'failed' || test.payload?.parentJobId !== parentId
            || testReview?.reconciliationHold !== false || test.result.requiresReconciliation || test.result.writeOutcomeUnknown
            || outcome?.testSuccess !== false || outcome.code !== 'upstream_test_failed'
            || outcome.recoveryObservation?.targetDigest !== saved.targetDigest
            || outcome.recoveryObservation?.updatedAt !== saved.updatedAt) continue;
      } else {
        const selectedHere = saved.selectedTestParentId === parentId && parent.payload?.testOnly === true
          && parent.payload.accountTargets?.some(target => target.accountId === account.id);
        if ((saved.originParentId !== parentId && !selectedHere) || saved.importUpdatedAt !== saved.updatedAt) continue;
      }
      if (verifiedImport(await get(saved.importJobId), await review(saved.importJobId), saved.originParentId, account, client, saved.importUpdatedAt)) {
        proofs.set(account.id, { ...saved });
      }
    }
    // Compatibility for the existing interrupted chain: all of these facts
    // were already persisted before this fix. Its old post-write group policy
    // was not saved, so expose a candidate only. A current, revision-checked
    // explicit test selection must authorize and persist its complete proof.
    const legacy = (parent.result.items || []).filter(item => candidates.has(item.accountId)
      && !proofs.has(item.accountId) && item.status === 'failed' && item.code === 'CONSOLE_TEST_TARGET_CHANGED'
      && item.phases?.tokenGenerated === true && item.phases.tokenUpdated === true
      && item.phases.tested === false && item.phases.verified === false);
    if (!legacy.length) continue;
    const childJobs = [];
    for (const id of children) { const job = await get(id); if (job?.payload?.parentJobId === parentId) childJobs.push(job); }
    for (const item of legacy) {
      const account = candidates.get(item.accountId);
      const imports = childJobs.filter(job => job.type === 'token_import' && job.status === 'succeeded'
        && job.result?.items?.some(row => row.accountId === account.id));
      for (const imported of imports) {
        if (!verifiedImport(imported, await review(imported.id), parentId, account, client)) continue;
        const source = imported.result.items[0];
        const phase = childJobs.find(job => {
          if (job.type !== 'phase3' || job.status !== 'succeeded' || !job.finishedAt
              || Date.parse(job.finishedAt) > Date.parse(imported.startedAt)
              || job.result?.tokenFile !== source.relativePath) return false;
          let binding;
          try { binding = validateBoundRemoteTarget(job.payload.remoteTarget); } catch { return false; }
          return binding.accountId === account.id && binding.endpointDigest === remotePhase3EndpointDigest(client)
            && !strongIdentityContradiction(binding.identityKeys, lifecycleIdentityKeys(account))
            && strong(binding.identityKeys).some(key => lifecycleIdentityKeys(account).includes(key));
        });
        if (phase) {
          proofs.set(account.id, { ...makeProof(account, client, imported.id, parentId), requiresExplicitTestSelection: true });
          break;
        }
      }
    }
  }
  return proofs;
}

module.exports = { pendingState, matchesWritebackProof, resolveImmediateWritebackRecovery, findPendingWritebackRecoveries };
