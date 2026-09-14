const crypto = require('node:crypto');

const { normalizeIdentityValue } = require('./lib/token');

const REVISION_PREFIX = 'account-test-v1.';
const REVISION_PATTERN = /^account-test-v1\.[A-Za-z0-9_-]{43}$/;
const CREDENTIAL_FIELDS = ['access', 'refresh', 'id'];

function positiveAccountId(value) {
  const text = String(value ?? '').trim();
  if (!/^[1-9]\d*$/.test(text)) return null;
  const id = Number(text);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function normalizedScalar(value, maximumLength = 1024) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const text = String(value).trim();
  if (!text || text.length > maximumLength || /[\u0000-\u001f\u007f]/.test(text)) return null;
  return text;
}

function canonicalStrongIdentities(account) {
  const values = { account: new Set(), user: new Set() };
  let invalid = false;
  const add = (kind, value) => {
    if (value === undefined || value === null || value === '') return;
    const prefix = kind + ':';
    const normalized = normalizeIdentityValue(prefix, value);
    if (!normalized || normalized.length > 512) invalid = true;
    else values[kind].add(normalized);
  };
  for (const key of Array.isArray(account?.identityKeys) ? account.identityKeys : []) {
    const raw = String(key || '').trim();
    const separator = raw.indexOf(':');
    if (separator <= 0) continue;
    const kind = raw.slice(0, separator).toLowerCase();
    if (kind === 'account' || kind === 'user') add(kind, raw.slice(separator + 1));
  }
  add('account', account?.accountId);
  add('user', account?.userId);
  return {
    account: [...values.account].sort(),
    user: [...values.user].sort(),
    invalid,
  };
}

function knownAccountState(account) {
  const status = String(account?.status || '').trim().toLowerCase();
  const statusKnown = account?.statusKnown === undefined
    ? ['active', 'disabled', 'error'].includes(status)
    : account.statusKnown === true;
  const schedulableKnown = account?.schedulableKnown === undefined
    ? typeof account?.schedulable === 'boolean'
    : account.schedulableKnown === true && typeof account?.schedulable === 'boolean';
  if (!statusKnown || !schedulableKnown) return null;
  return {
    status,
    statusKnown: true,
    schedulable: account.schedulable,
    schedulableKnown: true,
  };
}

function canonicalOptionalScalar(value, maximumLength = 1024) {
  if (value === undefined || value === null || value === '') return null;
  return normalizedScalar(value, maximumLength);
}

function canonicalAccountTestTarget(account) {
  const id = positiveAccountId(account?.id);
  const platform = normalizedScalar(account?.platform, 64)?.toLowerCase() || null;
  const type = normalizedScalar(account?.type, 64)?.toLowerCase() || null;
  const identities = canonicalStrongIdentities(account);
  const state = knownAccountState(account);
  if (!id || !platform || !type || !state || account?.schemaValid === false || identities.invalid
      || identities.account.length + identities.user.length === 0) return null;

  const fingerprints = {};
  const presence = {};
  let invalidEvidence = false;
  for (const field of CREDENTIAL_FIELDS) {
    const rawFingerprint = account?.tokenFingerprints?.[field];
    const fingerprint = canonicalOptionalScalar(rawFingerprint, 128);
    if (rawFingerprint !== undefined && rawFingerprint !== null && rawFingerprint !== ''
        && !fingerprint) invalidEvidence = true;
    fingerprints[field] = fingerprint && /^[a-f0-9]+$/i.test(fingerprint)
      ? fingerprint.toLowerCase()
      : fingerprint;
    const rawPresenceValue = account?.credentialPresence?.[field];
    if (rawPresenceValue === undefined || rawPresenceValue === null || rawPresenceValue === '') {
      presence[field] = fingerprints[field] ? 'present' : 'unknown';
    } else {
      const rawPresence = String(rawPresenceValue).trim().toLowerCase();
      if (!['present', 'absent', 'unknown'].includes(rawPresence)) invalidEvidence = true;
      presence[field] = rawPresence;
    }
  }

  const scalarState = {};
  for (const [field, maximumLength, lowercase] of [
    ['expiresAt', 1024, false],
    ['expiryStatus', 32, true],
    ['credentialExpiresAt', 1024, false],
    ['credentialExpiryStatus', 32, true],
    ['tempUnschedulableUntil', 1024, false],
    ['tempUnschedulableUntilStatus', 32, true],
    ['rateLimitResetAt', 1024, false],
    ['rateLimitResetStatus', 32, true],
    ['overloadUntil', 1024, false],
    ['overloadUntilStatus', 32, true],
  ]) {
    const raw = account?.[field];
    const value = canonicalOptionalScalar(raw, maximumLength);
    if (raw !== undefined && raw !== null && raw !== '' && !value) invalidEvidence = true;
    scalarState[field] = lowercase && value ? value.toLowerCase() : value;
  }
  if (invalidEvidence) return null;

  return {
    version: 1,
    id,
    platform,
    type,
    identities: { account: identities.account, user: identities.user },
    credentials: { fingerprints, presence },
    state: {
      ...state,
      schemaValid: account?.schemaValid !== false,
      identityConflict: account?.identityConflict === true,
      fingerprintConflict: account?.fingerprintConflict === true,
      credentialsStatusConflict: account?.credentialsStatusConflict === true,
      autoPauseOnExpired: typeof account?.autoPauseOnExpired === 'boolean'
        ? account.autoPauseOnExpired
        : null,
      ...scalarState,
    },
  };
}

function createAccountTargetRevisionIssuer(secret = crypto.randomBytes(32)) {
  const key = Buffer.from(secret);
  if (key.length < 32) throw new Error('账号测试 revision 密钥长度不足');

  function issue(account) {
    const target = canonicalAccountTestTarget(account);
    if (!target) return null;
    return REVISION_PREFIX + crypto.createHmac('sha256', key)
      .update('gpt-register-panel/account-test-target/v1\0')
      .update(JSON.stringify(target))
      .digest('base64url');
  }

  function matches(revision, account) {
    if (typeof revision !== 'string' || !REVISION_PATTERN.test(revision)) return false;
    const expected = issue(account);
    if (!expected) return false;
    const suppliedBuffer = Buffer.from(revision, 'ascii');
    const expectedBuffer = Buffer.from(expected, 'ascii');
    return suppliedBuffer.length === expectedBuffer.length
      && crypto.timingSafeEqual(suppliedBuffer, expectedBuffer);
  }

  return Object.freeze({ issue, matches });
}

function accountTestTargetDigest(account) {
  const target = canonicalAccountTestTarget(account);
  if (!target) return null;
  return crypto.createHash('sha256')
    .update('gpt-register-panel/account-test-target-baseline/v1\0')
    .update(JSON.stringify(target))
    .digest('hex');
}

const processIssuer = createAccountTargetRevisionIssuer();

function accountTestTargetRevision(account) {
  return processIssuer.issue(account);
}

function matchesAccountTestTargetRevision(revision, account) {
  return processIssuer.matches(revision, account);
}

module.exports = {
  REVISION_PATTERN,
  accountTestTargetDigest,
  accountTestTargetRevision,
  createAccountTargetRevisionIssuer,
  matchesAccountTestTargetRevision,
};
