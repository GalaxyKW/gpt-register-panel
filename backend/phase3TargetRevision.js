const crypto = require('node:crypto');

const { normalizeEmail, normalizeIdentityValue } = require('./lib/token');
const {
  PHASE3_PHONE_USERNAME_MAX_BYTES,
  normalizePhase3Phone,
  normalizePhase3RelativePath,
  normalizeLocalPhase3SelectedKey,
  phase3SelectedKeyForToken,
} = require('./lib/phase3Identity');

const REVISION_PREFIX = 'phase3-target-v1.';
const REVISION_PATTERN = /^phase3-target-v1\.[A-Za-z0-9_-]{43}$/;
const LOCAL_REVISION_PATTERN = /^phase3-local-v1\.[A-Za-z0-9_-]{43}$/;
const CANONICAL_STRONG_IDENTITY = /^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/;
const TERMINAL_USERNAME_STATUSES = new Set([
  'account_deactivated',
  'account_deleted',
  'account_disabled',
]);

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

function canonicalIdentityValues(token, kind) {
  const prefix = kind + ':';
  const values = new Set();
  let invalid = false;
  const add = (value) => {
    if (value === undefined || value === null || value === '') return;
    if ((typeof value !== 'string' && typeof value !== 'number')
        || (typeof value === 'number' && (!Number.isSafeInteger(value) || Object.is(value, -0)))
        || (typeof value === 'string' && value !== value.trim())) {
      invalid = true;
      return;
    }
    const normalized = normalizeIdentityValue(prefix, value);
    if (!normalized || normalized.length > 512 || !CANONICAL_STRONG_IDENTITY.test(normalized)) {
      invalid = true;
    }
    else values.add(normalized);
  };
  add(ownValue(token, kind === 'account' ? 'accountId' : 'userId'));
  const identityKeys = ownValue(token, 'identityKeys');
  if (!Array.isArray(identityKeys)) invalid = true;
  for (const key of Array.isArray(identityKeys) ? identityKeys : []) {
    if (typeof key !== 'string' || key !== key.trim()) {
      invalid = true;
      continue;
    }
    const text = key;
    if (text.toLowerCase().startsWith(prefix)) add(text.slice(prefix.length));
  }
  if (values.size > 1) invalid = true;
  return { values: [...values].sort(), invalid };
}

function canonicalPhase3Target(evidence = {}) {
  if (!isPlainObject(evidence)) return null;
  const token = ownValue(evidence, 'token');
  const username = ownValue(evidence, 'username');
  const usernameContentHash = ownValue(evidence, 'usernameContentHash');
  if (!isPlainObject(token) || !isPlainObject(username)
      || typeof usernameContentHash !== 'string') return null;
  const source = ownValue(token, 'source');
  const relativePath = ownValue(token, 'relativePath');
  const rawContentHash = ownValue(token, 'contentHash');
  const contentHash = typeof rawContentHash === 'string' ? rawContentHash.toLowerCase() : '';
  const usernameHash = usernameContentHash.toLowerCase();
  const usernameIndex = ownValue(username, 'index');
  const tokenEmail = ownValue(token, 'email');
  const rawUsernameEmail = ownValue(username, 'email');
  const email = typeof tokenEmail === 'string' ? normalizeEmail(tokenEmail) : '';
  const usernameEmail = typeof rawUsernameEmail === 'string' ? normalizeEmail(rawUsernameEmail) : '';
  const phone = normalizePhase3Phone(ownValue(username, 'phone'), {
    maximumBytes: PHASE3_PHONE_USERNAME_MAX_BYTES,
    allowNumber: true,
    allowNull: true,
  });
  const accountIdentities = canonicalIdentityValues(token, 'account');
  const userIdentities = canonicalIdentityValues(token, 'user');
  const rawStatus = ownValue(username, 'status');
  const status = rawStatus === undefined
    ? ''
    : typeof rawStatus === 'string' ? rawStatus.trim().toLowerCase() : null;
  if (!['tokens', 'use_token'].includes(source)
      || !normalizePhase3RelativePath(relativePath, source)
      || !phase3SelectedKeyForToken(token)
      || !/^[a-f0-9]{64}$/.test(contentHash)
      || !/^[a-f0-9]{64}$/.test(usernameHash)
      || !Number.isSafeInteger(usernameIndex) || usernameIndex < 0
      || ownValue(token, 'historical') !== false || ownValue(token, 'parseStatus') !== 'ok'
      || !email || email !== usernameEmail
      || ownValue(username, 'hasPassword') !== true
      || ownValue(username, 'phoneValid') === false || phone === null
      || accountIdentities.invalid || userIdentities.invalid
      || status === null || status.length > 64 || (status && !/^[a-z0-9_-]+$/.test(status))
      || TERMINAL_USERNAME_STATUSES.has(status)) return null;
  return {
    version: 1,
    token: {
      source,
      relativePath,
      contentHash,
      email,
      identities: {
        account: accountIdentities.values,
        user: userIdentities.values,
      },
    },
    username: {
      fileContentHash: usernameHash,
      index: usernameIndex,
      email: usernameEmail,
      phone,
      status,
      hasPassword: true,
    },
  };
}

function createPhase3TargetRevisionIssuer(secret = crypto.randomBytes(32)) {
  const key = Buffer.from(secret);
  if (key.length < 32) throw new Error('Phase3 revision 密钥长度不足');

  function issue(evidence) {
    const target = canonicalPhase3Target(evidence);
    if (!target) return null;
    return REVISION_PREFIX + crypto.createHmac('sha256', key)
      .update('gpt-register-panel/phase3-target/v1\0')
      .update(JSON.stringify(target))
      .digest('base64url');
  }

  function matches(revision, evidence) {
    if (typeof revision !== 'string' || !REVISION_PATTERN.test(revision)) return false;
    const expected = issue(evidence);
    if (!expected) return false;
    const supplied = Buffer.from(revision, 'ascii');
    const actual = Buffer.from(expected, 'ascii');
    return supplied.length === actual.length && crypto.timingSafeEqual(supplied, actual);
  }

  return Object.freeze({ issue, matches });
}

function canonicalLocalPhase3Target(evidence = {}) {
  if (!isPlainObject(evidence)) return null;
  const username = ownValue(evidence, 'username');
  const hash = ownValue(evidence, 'usernameContentHash');
  if (!isPlainObject(username) || typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) {
    return null;
  }
  const index = ownValue(username, 'index');
  const email = typeof ownValue(username, 'email') === 'string'
    ? normalizeEmail(username.email) : '';
  const phone = normalizePhase3Phone(ownValue(username, 'phone'), {
    maximumBytes: PHASE3_PHONE_USERNAME_MAX_BYTES,
    allowNumber: true,
    allowNull: true,
  });
  const rawStatus = ownValue(username, 'status');
  const status = rawStatus === undefined ? ''
    : typeof rawStatus === 'string' ? rawStatus.trim().toLowerCase() : null;
  if (!Number.isSafeInteger(index) || index < 0
      || !normalizeLocalPhase3SelectedKey('username:' + index)
      || !email || phone === null || ownValue(username, 'phoneValid') === false
      || ownValue(username, 'hasPassword') !== true
      || status === null || status.length > 64 || (status && !/^[a-z0-9_-]+$/.test(status))
      || TERMINAL_USERNAME_STATUSES.has(status)) return null;
  return {
    version: 1,
    sourceMode: 'username',
    username: { fileContentHash: hash, index, email, phone, status, hasPassword: true },
  };
}

function createLocalPhase3TargetRevisionIssuer(secret = crypto.randomBytes(32)) {
  const key = Buffer.from(secret);
  if (key.length < 32) throw new Error('Phase3 revision 密钥长度不足');
  function issue(evidence) {
    const target = canonicalLocalPhase3Target(evidence);
    if (!target) return null;
    return 'phase3-local-v1.' + crypto.createHmac('sha256', key)
      .update('gpt-register-panel/phase3-local/v1\0')
      .update(JSON.stringify(target)).digest('base64url');
  }
  function matches(revision, evidence) {
    if (typeof revision !== 'string' || !LOCAL_REVISION_PATTERN.test(revision)) return false;
    const expected = issue(evidence);
    return Boolean(expected && crypto.timingSafeEqual(
      Buffer.from(revision, 'ascii'), Buffer.from(expected, 'ascii'),
    ));
  }
  return Object.freeze({ issue, matches });
}

const processIssuer = createPhase3TargetRevisionIssuer();
const localProcessIssuer = createLocalPhase3TargetRevisionIssuer();

function phase3TargetRevision(evidence) {
  return processIssuer.issue(evidence);
}

function phase3TargetRevisionMatches(revision, evidence) {
  return processIssuer.matches(revision, evidence);
}

module.exports = {
  REVISION_PATTERN,
  LOCAL_REVISION_PATTERN,
  canonicalLocalPhase3Target,
  createLocalPhase3TargetRevisionIssuer,
  localPhase3TargetRevision: (evidence) => localProcessIssuer.issue(evidence),
  localPhase3TargetRevisionMatches: (revision, evidence) => localProcessIssuer.matches(revision, evidence),
  canonicalPhase3Target,
  createPhase3TargetRevisionIssuer,
  phase3TargetRevision,
  phase3TargetRevisionMatches,
};
