const crypto = require('node:crypto');

const { normalizeEmail, normalizeIdentityValue } = require('./lib/token');
const {
  PHASE3_PHONE_USERNAME_MAX_BYTES,
  normalizePhase3Phone,
  normalizePhase3RelativePath,
  phase3SelectedKeyForToken,
} = require('./lib/phase3Identity');

const REVISION_PREFIX = 'phase3-target-v1.';
const REVISION_PATTERN = /^phase3-target-v1\.[A-Za-z0-9_-]{43}$/;

function canonicalIdentityValues(token, kind) {
  const prefix = kind + ':';
  const values = new Set();
  let invalid = false;
  const add = (value) => {
    if (value === undefined || value === null || value === '') return;
    const normalized = normalizeIdentityValue(prefix, value);
    if (!normalized || normalized.length > 512) invalid = true;
    else values.add(normalized);
  };
  add(kind === 'account' ? token?.accountId : token?.userId);
  for (const key of Array.isArray(token?.identityKeys) ? token.identityKeys : []) {
    const text = String(key || '').trim();
    if (text.toLowerCase().startsWith(prefix)) add(text.slice(prefix.length));
  }
  return { values: [...values].sort(), invalid };
}

function canonicalPhase3Target({ token, username, usernameContentHash } = {}) {
  const source = String(token?.source || '');
  const relativePath = String(token?.relativePath || '');
  const contentHash = String(token?.contentHash || '').toLowerCase();
  const usernameHash = String(usernameContentHash || '').toLowerCase();
  const usernameIndex = Number(username?.index);
  const email = normalizeEmail(token?.email);
  const usernameEmail = normalizeEmail(username?.email);
  const phone = normalizePhase3Phone(username?.phone, {
    maximumBytes: PHASE3_PHONE_USERNAME_MAX_BYTES,
    allowNumber: true,
    allowNull: true,
  });
  const accountIdentities = canonicalIdentityValues(token, 'account');
  const userIdentities = canonicalIdentityValues(token, 'user');
  const status = String(username?.status || '').trim().toLowerCase();
  if (!['tokens', 'use_token'].includes(source)
      || !normalizePhase3RelativePath(relativePath, source)
      || !phase3SelectedKeyForToken(token)
      || !/^[a-f0-9]{64}$/.test(contentHash)
      || !/^[a-f0-9]{64}$/.test(usernameHash)
      || !Number.isSafeInteger(usernameIndex) || usernameIndex < 0
      || token?.historical === true || token?.parseStatus !== 'ok'
      || !email || email !== usernameEmail
      || username?.hasPassword !== true
      || username?.phoneValid === false || phone === null
      || accountIdentities.invalid || userIdentities.invalid
      || status.length > 64 || (status && !/^[a-z0-9_-]+$/.test(status))) return null;
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

const processIssuer = createPhase3TargetRevisionIssuer();

function phase3TargetRevision(evidence) {
  return processIssuer.issue(evidence);
}

function phase3TargetRevisionMatches(revision, evidence) {
  return processIssuer.matches(revision, evidence);
}

module.exports = {
  REVISION_PATTERN,
  canonicalPhase3Target,
  createPhase3TargetRevisionIssuer,
  phase3TargetRevision,
  phase3TargetRevisionMatches,
};
