const crypto = require('node:crypto');

const { normalizeIdentityValue, parseDateValue } = require('./lib/token');

const REVISION_PREFIX = 'account-test-v1.';
const REVISION_PATTERN = /^account-test-v1\.[A-Za-z0-9_-]{43}$/;
const CREDENTIAL_FIELDS = ['access', 'refresh', 'id'];
const ACCOUNT_TEST_STATUSES = new Set(['active', 'inactive', 'disabled', 'error']);
const CANONICAL_STRONG_IDENTITY = /^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/;
const UNSAFE_SCALAR_TEXT = /[\p{Cc}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function ownValue(object, key) {
  return object && Object.prototype.hasOwnProperty.call(object, key)
    ? object[key]
    : undefined;
}

function positiveAccountId(value) {
  let id;
  if (typeof value === 'number') id = value;
  else if (typeof value === 'string' && /^[1-9]\d*$/.test(value)) id = Number(value);
  else return null;
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function normalizedScalar(value, maximumLength = 1024) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text || value !== text || text.length > maximumLength || UNSAFE_SCALAR_TEXT.test(value)) {
    return null;
  }
  return text;
}

function canonicalStrongIdentities(account) {
  const values = { account: new Set(), user: new Set() };
  let invalid = false;
  const add = (kind, value) => {
    if (value === undefined || value === null || value === '') return;
    if ((typeof value !== 'string' && typeof value !== 'number')
        || (typeof value === 'number' && (!Number.isSafeInteger(value) || Object.is(value, -0)))
        || (typeof value === 'string' && value !== value.trim())) {
      invalid = true;
      return;
    }
    const prefix = kind + ':';
    const normalized = normalizeIdentityValue(prefix, value);
    if (!normalized || normalized.length > 512 || !CANONICAL_STRONG_IDENTITY.test(normalized)) {
      invalid = true;
    }
    else values[kind].add(normalized);
  };
  const identityKeys = ownValue(account, 'identityKeys');
  if (identityKeys !== undefined && !Array.isArray(identityKeys)) invalid = true;
  for (const key of Array.isArray(identityKeys) ? identityKeys : []) {
    if (typeof key !== 'string' || key !== key.trim()) {
      invalid = true;
      continue;
    }
    const raw = key;
    const separator = raw.indexOf(':');
    if (separator <= 0) continue;
    const kind = raw.slice(0, separator).toLowerCase();
    if (kind === 'account' || kind === 'user') add(kind, raw.slice(separator + 1));
  }
  add('account', ownValue(account, 'accountId'));
  add('user', ownValue(account, 'userId'));
  if (values.account.size > 1 || values.user.size > 1) invalid = true;
  return {
    account: [...values.account].sort(),
    user: [...values.user].sort(),
    invalid,
  };
}

function knownAccountState(account) {
  const status = String(ownValue(account, 'status') || '').trim().toLowerCase();
  const recognizedStatus = ACCOUNT_TEST_STATUSES.has(status);
  const rawStatusKnown = ownValue(account, 'statusKnown');
  const rawSchedulable = ownValue(account, 'schedulable');
  const rawSchedulableKnown = ownValue(account, 'schedulableKnown');
  const statusKnown = rawStatusKnown === undefined
    ? recognizedStatus
    : rawStatusKnown === true && recognizedStatus;
  const schedulableKnown = rawSchedulableKnown === undefined
    ? typeof rawSchedulable === 'boolean'
    : rawSchedulableKnown === true && typeof rawSchedulable === 'boolean';
  if (!statusKnown || !schedulableKnown) return null;
  return {
    status,
    statusKnown: true,
    schedulable: rawSchedulable,
    schedulableKnown: true,
  };
}

function canonicalOptionalScalar(value, maximumLength = 1024) {
  if (value === undefined || value === null || value === '') return null;
  return normalizedScalar(value, maximumLength);
}

function canonicalGroupIds(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return null;
  const ids = [];
  for (const raw of value) {
    let id;
    if (typeof raw === 'number') id = raw;
    else if (typeof raw === 'string' && /^[1-9]\d*$/.test(raw)) id = Number(raw);
    else return null;
    if (!Number.isSafeInteger(id) || id <= 0) return null;
    ids.push(id);
  }
  return [...new Set(ids)].sort((left, right) => left - right);
}

function canonicalTimeEvidence(account, valueField, statusField) {
  const rawValue = ownValue(account, valueField);
  const rawStatus = ownValue(account, statusField);
  const value = canonicalOptionalScalar(rawValue, 1024);
  const status = canonicalOptionalScalar(rawStatus, 32)?.toLowerCase() || null;
  if ((rawValue !== undefined && rawValue !== null && rawValue !== '' && !value)
      || (rawStatus !== undefined && rawStatus !== null && rawStatus !== '' && !status)
      || (status && !['valid', 'missing', 'invalid'].includes(status))) return null;
  const normalizedValue = value ? parseDateValue(value) : null;
  if ((value && !normalizedValue) || status === 'invalid'
      || (status === 'valid' && !normalizedValue)
      || (status === 'missing' && normalizedValue)) return null;
  return {
    value: normalizedValue,
    status: status || (normalizedValue ? 'valid' : 'missing'),
  };
}

function canonicalAccountTestTarget(account) {
  if (!isPlainObject(account)) return null;
  const id = positiveAccountId(ownValue(account, 'id'));
  const platform = normalizedScalar(ownValue(account, 'platform'), 64)?.toLowerCase() || null;
  const type = normalizedScalar(ownValue(account, 'type'), 64)?.toLowerCase() || null;
  const identities = canonicalStrongIdentities(account);
  const state = knownAccountState(account);
  const groupIds = canonicalGroupIds(ownValue(account, 'groupIds'));
  const booleanEvidenceFields = [
    'schemaValid',
    'identityConflict',
    'fingerprintConflict',
    'credentialsStatusConflict',
  ];
  const invalidBooleanEvidence = booleanEvidenceFields.some((field) => (
    Object.prototype.hasOwnProperty.call(account, field)
      && account[field] !== undefined
      && typeof account[field] !== 'boolean'
  ));
  const conflictEvidence = ownValue(account, 'identityConflict') === true
    || ownValue(account, 'fingerprintConflict') === true
    || ownValue(account, 'credentialsStatusConflict') === true;
  const tokenFingerprints = ownValue(account, 'tokenFingerprints');
  const credentialPresence = ownValue(account, 'credentialPresence');
  const invalidCredentialShape = (
    Object.prototype.hasOwnProperty.call(account, 'tokenFingerprints')
      && !isPlainObject(tokenFingerprints)
  ) || (
    Object.prototype.hasOwnProperty.call(account, 'credentialPresence')
      && !isPlainObject(credentialPresence)
  );
  if (!id || platform !== 'openai' || type !== 'oauth' || !state
      || ownValue(account, 'schemaValid') === false || identities.invalid
      || invalidBooleanEvidence || conflictEvidence || invalidCredentialShape
      || !groupIds || identities.account.length + identities.user.length === 0) return null;

  const fingerprints = {};
  const presence = {};
  let invalidEvidence = false;
  for (const field of CREDENTIAL_FIELDS) {
    const rawFingerprint = Object.prototype.hasOwnProperty.call(tokenFingerprints || {}, field)
      ? tokenFingerprints[field]
      : undefined;
    const fingerprint = canonicalOptionalScalar(rawFingerprint, 128);
    if (rawFingerprint !== undefined && rawFingerprint !== null && rawFingerprint !== ''
        && !fingerprint) invalidEvidence = true;
    fingerprints[field] = fingerprint && /^[a-f0-9]+$/i.test(fingerprint)
      ? fingerprint.toLowerCase()
      : fingerprint;
    const rawPresenceValue = Object.prototype.hasOwnProperty.call(credentialPresence || {}, field)
      ? credentialPresence[field]
      : undefined;
    if (rawPresenceValue === undefined || rawPresenceValue === null || rawPresenceValue === '') {
      presence[field] = fingerprints[field] ? 'present' : 'unknown';
    } else {
      const rawPresence = String(rawPresenceValue).trim().toLowerCase();
      if (!['present', 'absent', 'unknown'].includes(rawPresence)) invalidEvidence = true;
      presence[field] = rawPresence;
    }
    if (fingerprints[field] && presence[field] === 'absent') invalidEvidence = true;
  }

  const scalarState = {};
  for (const [valueField, statusField] of [
    ['expiresAt', 'expiryStatus'],
    ['credentialExpiresAt', 'credentialExpiryStatus'],
    ['tempUnschedulableUntil', 'tempUnschedulableUntilStatus'],
    ['rateLimitResetAt', 'rateLimitResetStatus'],
    ['overloadUntil', 'overloadUntilStatus'],
  ]) {
    const evidence = canonicalTimeEvidence(account, valueField, statusField);
    if (!evidence) {
      invalidEvidence = true;
      continue;
    }
    scalarState[valueField] = evidence.value;
    scalarState[statusField] = evidence.status;
  }
  if (invalidEvidence) return null;

  const rawAutoPauseOnExpired = ownValue(account, 'autoPauseOnExpired');
  const canonicalAutoPauseOnExpired = typeof rawAutoPauseOnExpired === 'boolean'
    ? rawAutoPauseOnExpired
    : rawAutoPauseOnExpired === undefined ? null : 'invalid';

  return {
    version: 1,
    id,
    platform,
    type,
    identities: { account: identities.account, user: identities.user },
    credentials: { fingerprints, presence },
    groupIds,
    state: {
      ...state,
      schemaValid: ownValue(account, 'schemaValid') !== false,
      identityConflict: ownValue(account, 'identityConflict') === true,
      fingerprintConflict: ownValue(account, 'fingerprintConflict') === true,
      credentialsStatusConflict: ownValue(account, 'credentialsStatusConflict') === true,
      autoPauseOnExpired: canonicalAutoPauseOnExpired,
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

function accountTestOwnershipDigest(account) {
  const target = canonicalAccountTestTarget(account);
  if (!target) return null;
  return crypto.createHash('sha256')
    .update('gpt-register-panel/account-test-ownership/v1\0')
    .update(JSON.stringify({
      id: target.id,
      platform: target.platform,
      type: target.type,
      identities: target.identities,
      credentials: target.credentials,
      groupIds: target.groupIds,
    }))
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
  accountTestOwnershipDigest,
  accountTestTargetDigest,
  accountTestTargetRevision,
  createAccountTargetRevisionIssuer,
  matchesAccountTestTargetRevision,
};
