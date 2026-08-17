const crypto = require('node:crypto');

function asString(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

function normalizeEmail(value) {
  return asString(value).toLowerCase();
}

function parseDateValue(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    const ms = value < 100000000000 ? value * 1000 : value;
    const date = new Date(ms);
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  }
  const text = asString(value);
  if (!text) return null;
  const numeric = Number(text);
  if (Number.isFinite(numeric) && /^\d+(\.\d+)?$/.test(text)) {
    const ms = numeric < 100000000000 ? numeric * 1000 : numeric;
    const date = new Date(ms);
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  }
  const date = new Date(text);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function parseJwtPayload(token) {
  const value = asString(token);
  const parts = value.split('.');
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1], 'base64url').toString('utf8');
    const payload = JSON.parse(json);
    return payload && typeof payload === 'object' ? payload : null;
  } catch {
    return null;
  }
}

function tokenFingerprint(value) {
  const text = asString(value);
  if (!text) return null;
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, 16);
}

function openAiAuth(payload) {
  const value = payload && payload['https://api.openai.com/auth'];
  return value && typeof value === 'object' ? value : {};
}

function buildIdentityKeys({ accountId, userId, email } = {}) {
  const keys = [];
  const add = (prefix, value) => {
    const normalized = asString(value);
    if (!normalized) return;
    const key = prefix + normalized.toLowerCase();
    if (!keys.includes(key)) keys.push(key);
  };
  add('account:', accountId);
  add('user:', userId);
  add('email:', normalizeEmail(email));
  return keys;
}

function normalizeTokenDocument({
  source,
  relativePath,
  fileName,
  mtimeMs,
  data,
  parseError,
  includeRaw = false,
}) {
  if (parseError) {
    return {
      source,
      relativePath,
      fileName,
      mtimeMs,
      parseStatus: 'invalid',
      parseError: String(parseError.message || parseError),
      identityKeys: [],
      fingerprints: {},
    };
  }

  const document = data && typeof data === 'object' ? data : {};
  const accessToken = asString(document.access_token || document.accessToken);
  const refreshToken = asString(document.refresh_token || document.refreshToken);
  const idToken = asString(document.id_token || document.idToken);
  const accessPayload = parseJwtPayload(accessToken);
  const auth = openAiAuth(accessPayload);
  const accountId = asString(
    document.chatgpt_account_id
      || document.account_id
      || document.accountId
      || auth.chatgpt_account_id,
  );
  const userId = asString(
    document.chatgpt_user_id
      || document.user_id
      || document.userId
      || auth.chatgpt_user_id
      || accessPayload?.sub,
  );
  const email = normalizeEmail(
    document.email
      || auth.email
      || accessPayload?.email,
  );
  const expiry = parseDateValue(
    document.expired
      || document.expires_at
      || document.expiresAt
      || accessPayload?.exp,
  );
  const record = {
    source,
    relativePath,
    fileName,
    mtimeMs,
    parseStatus: 'ok',
    email,
    accountId,
    userId,
    identityKeys: buildIdentityKeys({ accountId, userId, email }),
    expiresAt: expiry,
    lastRefresh: parseDateValue(document.last_refresh || document.lastRefresh),
    disabled: document.disabled === true,
    type: asString(document.type || 'codex'),
    fingerprints: {
      access: tokenFingerprint(accessToken),
      refresh: tokenFingerprint(refreshToken),
      id: tokenFingerprint(idToken),
    },
  };
  if (includeRaw) {
    Object.defineProperty(record, 'raw', {
      value: document,
      enumerable: false,
      configurable: false,
      writable: false,
    });
  }
  return record;
}

function toSafeTokenSummary(record) {
  if (!record || typeof record !== 'object') return null;
  return {
    source: record.source,
    relativePath: record.relativePath,
    fileName: record.fileName,
    mtimeMs: record.mtimeMs,
    parseStatus: record.parseStatus,
    parseError: record.parseError || null,
    email: record.email || '',
    accountId: record.accountId || '',
    userId: record.userId || '',
    identityKeys: Array.isArray(record.identityKeys) ? record.identityKeys : [],
    expiresAt: record.expiresAt || null,
    lastRefresh: record.lastRefresh || null,
    disabled: record.disabled === true,
    type: record.type || '',
    fingerprints: record.fingerprints || {},
  };
}

module.exports = {
  asString,
  normalizeEmail,
  parseDateValue,
  parseJwtPayload,
  tokenFingerprint,
  buildIdentityKeys,
  normalizeTokenDocument,
  toSafeTokenSummary,
};
