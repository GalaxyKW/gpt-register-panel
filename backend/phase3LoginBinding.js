'use strict';

const crypto = require('node:crypto');
const { accountTestTargetDigest } = require('./accountTargetRevision');
const { accountInMaintenanceScope, lifecycleIdentityKeys } = require('./accountLifecycle');
const { strongIdentitiesFullyMatch } = require('./diff');
const { safeAccount } = require('./adapters/sub2apiAdmin');
const { normalizeEmail, normalizeTokenDocument, parseJwtPayload, tokenCredentialField } = require('./lib/token');
const { remotePhase3EndpointDigest } = require('./remotePhase3');
const { throwIfJobInterrupted } = require('./jobLifecycle');

const PROOF_FIELDS = ['version', 'source', 'accountId', 'accountName', 'endpointDigest', 'targetDigest',
  'updatedAt', 'identityKeys', 'loginEmailDigest', 'fingerprints'];
const KINDS = ['access', 'refresh', 'id'];
const HEX = /^[a-f0-9]{64}$/;
const FINGERPRINT = /^[a-f0-9]{16}$/;
const plain = value => value && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const emailDigest = email => crypto.createHash('sha256').update('phase3-login-email/v1\0').update(email).digest('hex');
const updatedAt = account => account.updatedAt ?? null;

function bindingError(code) {
  return Object.assign(new Error(code === 'PHASE3_LOGIN_BINDING_TARGET_CHANGED'
    ? '本地登录关联核验期间远端账号已变化，未启动 Phase3'
    : '无法核验远端既存凭据与本地登录记录的关联，未启动 Phase3'), { code });
}

function sameFingerprints(expected, actual) {
  return KINDS.every(kind => (expected?.[kind] ?? null) === (actual?.[kind] ?? null));
}

function matchesPhase3LoginBinding(proof, { account, loginEmail, client }) {
  try {
    const email = normalizeEmail(loginEmail), targetDigest = accountTestTargetDigest(account);
    return Boolean(email && targetDigest && accountInMaintenanceScope(account) && plain(proof)
      && Object.keys(proof).length === PROOF_FIELDS.length && PROOF_FIELDS.every(field => Object.hasOwn(proof, field))
      && proof.version === 1 && proof.source === 'stored_oauth_claims'
      && proof.accountId === account.id && proof.accountName === account.name
      && HEX.test(proof.endpointDigest) && proof.endpointDigest === remotePhase3EndpointDigest(client)
      && HEX.test(proof.targetDigest) && proof.targetDigest === targetDigest
      && proof.updatedAt === updatedAt(account)
      && HEX.test(proof.loginEmailDigest) && proof.loginEmailDigest === emailDigest(email)
      && Array.isArray(proof.identityKeys)
      && JSON.stringify(proof.identityKeys) === JSON.stringify(lifecycleIdentityKeys(account))
      && plain(proof.fingerprints) && Object.keys(proof.fingerprints).length === KINDS.length
      && KINDS.every(kind => Object.hasOwn(proof.fingerprints, kind)
        && (proof.fingerprints[kind] === null || FINGERPRINT.test(proof.fingerprints[kind])))
      && FINGERPRINT.test(proof.fingerprints.access)
      && sameFingerprints(proof.fingerprints, account.tokenFingerprints));
  } catch { return false; }
}

// These are claims from the exact credentials already stored for this remote
// ID. Decoding is not signature verification or proof that an expired JWT is
// usable. It supplies the missing login-to-identity association only.
function claimedLogin(credentials) {
  const fields = Object.fromEntries(KINDS.map(kind => [kind, tokenCredentialField(credentials, kind)]));
  if (KINDS.some(kind => fields[kind].invalid) || !fields.access.value) return null;
  const access = parseJwtPayload(fields.access.value);
  const id = fields.id.value ? parseJwtPayload(fields.id.value) : null;
  if (!access || (fields.id.value && !id)) return null;
  const profileEmails = [];
  for (const payload of [access, id]) {
    const profile = payload?.['https://api.openai.com/profile'];
    if (profile === undefined || profile === null) continue;
    if (!plain(profile)) return null;
    if (profile.email === undefined || profile.email === null || profile.email === '') continue;
    if (typeof profile.email !== 'string' || !normalizeEmail(profile.email)) return null;
    profileEmails.push(normalizeEmail(profile.email));
  }
  if (new Set(profileEmails).size > 1) return null;
  const token = normalizeTokenDocument({ data: {
    access_token: fields.access.value, refresh_token: fields.refresh.value, id_token: fields.id.value,
    // This email came from a JWT claim, never from credentials.email or an
    // administrator-controlled account label. The normalizer rejects a
    // disagreement with any access/id-token top-level or auth email claim.
    ...(profileEmails.length ? { email: profileEmails[0] } : {}),
  } });
  return token.parseStatus === 'ok' && token.email ? token : null;
}

function optionalExportUnavailable(error) {
  return ['SUB2API_TIMEOUT', 'SUB2API_TRANSPORT_ERROR'].includes(error?.code)
    || error?.code === 'SUB2API_REQUEST_REJECTED' && [401, 403, 404].includes(error.upstreamStatus);
}

async function resolvePhase3LoginBinding({ account, loginEmail, client, signal = null }) {
  throwIfJobInterrupted(signal);
  const email = normalizeEmail(loginEmail), targetDigest = accountTestTargetDigest(account);
  if (!email || !targetDigest || !accountInMaintenanceScope(account)
      || !FINGERPRINT.test(account.tokenFingerprints?.access || '')
      || typeof client?.exportAccounts !== 'function' || typeof client?.getAccount !== 'function') return null;
  const endpointDigest = remotePhase3EndpointDigest(client);
  let exported;
  try { exported = await client.exportAccounts([account.id], { includeProxies: false, signal }); }
  catch (error) {
    throwIfJobInterrupted(signal);
    if (optionalExportUnavailable(error)) return null;
    throw bindingError('PHASE3_LOGIN_BINDING_EXPORT_INVALID');
  }
  throwIfJobInterrupted(signal);
  if (!plain(exported) || !Array.isArray(exported.accounts) || exported.accounts.length !== 1
      || !Array.isArray(exported.proxies) || exported.proxies.length !== 0) {
    throw bindingError('PHASE3_LOGIN_BINDING_EXPORT_INVALID');
  }
  const raw = exported.accounts[0];
  if (!plain(raw) || !plain(raw.credentials)
      || (raw.id !== undefined && raw.id !== account.id)
      || raw.name !== account.name || raw.platform !== account.platform || raw.type !== account.type) {
    throw bindingError('PHASE3_LOGIN_BINDING_TARGET_CHANGED');
  }
  const credentials = { ...raw.credentials }, extra = plain(raw.extra) ? { ...raw.extra } : raw.extra;
  // Import-time digest metadata can be stale after OAuth refresh. Compute
  // fingerprints from this authenticated exact-ID export's actual values.
  for (const field of ['access_token_sha256', 'refresh_token_sha256', 'id_token_sha256']) {
    delete credentials[field];
    if (plain(extra)) delete extra[field];
  }
  const exportedAccount = safeAccount({ ...raw, id: account.id, credentials, extra });
  if (!accountInMaintenanceScope(exportedAccount)
      || !strongIdentitiesFullyMatch(lifecycleIdentityKeys(exportedAccount), lifecycleIdentityKeys(account))
      || !sameFingerprints(exportedAccount.tokenFingerprints, account.tokenFingerprints)) {
    throw bindingError('PHASE3_LOGIN_BINDING_TARGET_CHANGED');
  }
  const claims = claimedLogin(credentials);
  if (!claims || claims.email !== email
      || !strongIdentitiesFullyMatch(claims.identityKeys, lifecycleIdentityKeys(account))) return null;
  const proof = Object.freeze({ version: 1, source: 'stored_oauth_claims', accountId: account.id,
    accountName: account.name, endpointDigest, targetDigest, updatedAt: updatedAt(account),
    identityKeys: Object.freeze(lifecycleIdentityKeys(account)), loginEmailDigest: emailDigest(email),
    fingerprints: Object.freeze(Object.fromEntries(KINDS.map(kind => [kind, claims.fingerprints[kind] ?? null]))),
  });
  let current;
  try { current = await client.getAccount(account.id, { signal }); }
  catch (error) {
    throwIfJobInterrupted(signal);
    throw bindingError(error?.upstreamStatus === 404 ? 'PHASE3_LOGIN_BINDING_TARGET_CHANGED' : 'PHASE3_LOGIN_BINDING_READ_FAILED');
  }
  throwIfJobInterrupted(signal);
  if (!matchesPhase3LoginBinding(proof, { account: current, loginEmail: email, client })) {
    throw bindingError('PHASE3_LOGIN_BINDING_TARGET_CHANGED');
  }
  return proof;
}

module.exports = { resolvePhase3LoginBinding, matchesPhase3LoginBinding };
