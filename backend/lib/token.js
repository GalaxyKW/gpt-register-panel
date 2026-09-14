const crypto = require('node:crypto');

function asString(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

function normalizeEmail(value) {
  return asString(value).toLowerCase();
}

function normalizeIdentityValue(prefix, value) {
  const text = asString(value);
  if (prefix === 'email:') return text.toLowerCase();
  if (prefix === 'account:' || prefix === 'user:') {
    const match = /^\{?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\}?$/i.exec(text);
    if (match && (text.startsWith('{') === text.endsWith('}'))) return match[1].toLowerCase();
  }
  return text;
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
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function stringAliases(object, keys, maximumLength) {
  let value = '';
  let invalid = false;
  for (const key of keys) {
    if (!object || !Object.prototype.hasOwnProperty.call(object, key)) continue;
    const raw = object[key];
    if (raw === undefined || raw === null || raw === '') continue;
    if (typeof raw !== 'string') {
      invalid = true;
      continue;
    }
    const normalized = raw.trim();
    if (normalized.length > maximumLength || (value && value !== normalized)) invalid = true;
    else if (normalized) value = normalized;
  }
  return { value, invalid };
}

function claimScalar(object, key, maximumLength, allowNumber = true) {
  if (!object || !Object.prototype.hasOwnProperty.call(object, key)) {
    return { value: '', invalid: false };
  }
  const raw = object[key];
  if (raw === undefined || raw === null || raw === '') return { value: '', invalid: false };
  if (typeof raw !== 'string' && !(allowNumber && typeof raw === 'number' && Number.isFinite(raw))) {
    return { value: '', invalid: true };
  }
  const value = String(raw).trim();
  return value.length <= maximumLength
    ? { value, invalid: false }
    : { value: '', invalid: true };
}

function expectedDateScalar(value) {
  return value === undefined || value === null || value === ''
    || typeof value === 'string'
    || (typeof value === 'number' && Number.isFinite(value));
}

function buildIdentityKeys({ accountId, userId, email } = {}) {
  const keys = [];
  const add = (prefix, value) => {
    const normalized = normalizeIdentityValue(prefix, value);
    if (!normalized) return;
    const key = prefix + normalized;
    if (!keys.includes(key)) keys.push(key);
  };
  add('account:', accountId);
  add('user:', userId);
  add('email:', normalizeEmail(email));
  return keys;
}

function identityDimensionConflict(prefix, fields = []) {
  const values = new Set(fields
    .map((field) => normalizeIdentityValue(prefix, field?.value))
    .filter(Boolean));
  return values.size > 1;
}

function normalizeTokenDocument({
  source,
  relativePath,
  fileName,
  mtimeMs,
  data,
  parseError,
  contentHash = null,
  historical = false,
  includeRaw = false,
}) {
  if (parseError) {
    return {
      source,
      relativePath,
      fileName,
      mtimeMs,
      contentHash,
      historical: historical === true,
      parseStatus: 'invalid',
      parseError: String(parseError.message || parseError),
      expiryStatus: 'missing',
      identityKeys: [],
      fingerprints: {},
    };
  }

  const document = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
  const accessField = stringAliases(document, ['access_token', 'accessToken'], 2 * 1024 * 1024);
  const refreshField = stringAliases(document, ['refresh_token', 'refreshToken'], 256 * 1024);
  const idField = stringAliases(document, ['id_token', 'idToken'], 2 * 1024 * 1024);
  const explicitAccount = stringAliases(
    document,
    ['chatgpt_account_id', 'account_id', 'accountId'],
    512,
  );
  const explicitUser = stringAliases(document, ['chatgpt_user_id', 'user_id', 'userId'], 512);
  const explicitEmail = stringAliases(document, ['email'], 320);
  const explicitTypeField = stringAliases(document, ['type'], 32);
  const accessToken = accessField.value;
  const refreshToken = refreshField.value;
  const idToken = idField.value;
  const accessPayload = parseJwtPayload(accessToken);
  const idPayload = parseJwtPayload(idToken);
  const auth = openAiAuth(accessPayload);
  const idAuth = openAiAuth(idPayload);
  const claimAccount = claimScalar(auth, 'chatgpt_account_id', 512);
  const claimChatGptUser = claimScalar(auth, 'chatgpt_user_id', 512);
  const claimUser = claimScalar(auth, 'user_id', 512);
  const claimSubject = claimScalar(accessPayload, 'sub', 512);
  const idClaimAccount = claimScalar(idAuth, 'chatgpt_account_id', 512);
  const idClaimChatGptUser = claimScalar(idAuth, 'chatgpt_user_id', 512);
  const idClaimUser = claimScalar(idAuth, 'user_id', 512);
  const idClaimSubject = claimScalar(idPayload, 'sub', 512);
  const claimAuthEmail = claimScalar(auth, 'email', 320, false);
  const claimEmail = claimScalar(accessPayload, 'email', 320, false);
  const rawAuth = accessPayload?.['https://api.openai.com/auth'];
  const rawIdAuth = idPayload?.['https://api.openai.com/auth'];
  const authShapeInvalid = rawAuth !== undefined && rawAuth !== null
    && (typeof rawAuth !== 'object' || Array.isArray(rawAuth));
  const idAuthShapeInvalid = rawIdAuth !== undefined && rawIdAuth !== null
    && (typeof rawIdAuth !== 'object' || Array.isArray(rawIdAuth));
  const accountId = explicitAccount.value || claimAccount.value || idClaimAccount.value;
  const primaryUserFields = [
    explicitUser,
    claimChatGptUser,
    claimUser,
    idClaimChatGptUser,
    idClaimUser,
  ];
  const subjectFields = [claimSubject, idClaimSubject];
  const userId = primaryUserFields.find((field) => field.value)?.value
    || subjectFields.find((field) => field.value)?.value
    || '';
  const email = normalizeEmail(explicitEmail.value || claimAuthEmail.value || claimEmail.value);
  const strongIdentityConflict = identityDimensionConflict('account:', [
    explicitAccount,
    claimAccount,
    idClaimAccount,
  ])
    || identityDimensionConflict('user:', primaryUserFields)
    // OAuth `sub` is an issuer subject, not necessarily the same identifier as
    // OpenAI's chatgpt_user_id.  Compare access/id subjects with each other,
    // but never collapse them into the business-user identity dimension.
    || identityDimensionConflict('user:', subjectFields);
  const expiryValues = [document.expired, document.expires_at, document.expiresAt, accessPayload?.exp]
    .filter((value) => value !== undefined && value !== null && value !== '');
  const parsedExpiryValues = expiryValues.map(parseDateValue);
  const expiryInvalid = expiryValues.some((value, index) => (
    !expectedDateScalar(value) || !parsedExpiryValues[index]
  ));
  // When redundant expiry metadata differs, the earliest value is the safe
  // one: a later wrapper value must never hide an already-expired JWT.
  const expiry = expiryInvalid || parsedExpiryValues.length === 0
    ? null
    : new Date(Math.min(...parsedExpiryValues.map((value) => Date.parse(value)))).toISOString();
  const expiryStatus = expiryValues.length === 0 ? 'missing' : expiry ? 'valid' : 'invalid';
  const identityKeys = buildIdentityKeys({ accountId, userId, email });
  const explicitType = explicitTypeField.value;
  const type = !explicitType
    ? 'codex'
    : /^[a-z0-9_-]{1,32}$/i.test(explicitType) ? explicitType.toLowerCase() : 'unsupported';
  const lastRefreshValues = [document.last_refresh, document.lastRefresh]
    .filter((value) => value !== undefined && value !== null && value !== '');
  const parsedLastRefreshValues = lastRefreshValues.map(parseDateValue);
  const lastRefreshInvalid = lastRefreshValues.some((value, index) => (
    !expectedDateScalar(value) || !parsedLastRefreshValues[index]
  ));
  const lastRefreshConflict = new Set(parsedLastRefreshValues.filter(Boolean)).size > 1;
  const lastRefresh = lastRefreshInvalid || lastRefreshConflict || parsedLastRefreshValues.length === 0
    ? null
    : parsedLastRefreshValues[0];
  const disabledInvalid = Object.prototype.hasOwnProperty.call(document, 'disabled')
    && typeof document.disabled !== 'boolean';
  const schemaInvalid = !data || typeof data !== 'object' || Array.isArray(data)
    || authShapeInvalid
    || idAuthShapeInvalid
    || disabledInvalid
    || lastRefreshInvalid
    || lastRefreshConflict
    || [
      accessField,
      refreshField,
      idField,
      explicitAccount,
      explicitUser,
      explicitEmail,
      explicitTypeField,
      claimAccount,
      claimChatGptUser,
      claimUser,
      claimSubject,
      idClaimAccount,
      idClaimChatGptUser,
      idClaimUser,
      idClaimSubject,
      claimAuthEmail,
      claimEmail,
    ].some((field) => field.invalid);
  const semanticError = strongIdentityConflict
    ? 'token 强身份字段互相矛盾'
    : schemaInvalid
    ? 'token 字段类型或长度无效'
    : !accessToken
    ? '缺少 access_token'
    : identityKeys.length === 0
      ? '缺少可匹配的账号身份（email/account_id/user_id）'
      : type !== 'codex'
        ? '不支持的 token type'
      : null;
  const record = {
    source,
    relativePath,
    fileName,
    mtimeMs,
    contentHash,
    historical: historical === true,
    parseStatus: semanticError ? 'invalid' : 'ok',
    parseError: semanticError,
    expiryStatus,
    email,
    accountId,
    userId,
    identityKeys,
    expiresAt: expiry,
    lastRefresh,
    disabled: document.disabled === true,
    type,
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
    historical: record.historical === true,
    parseStatus: record.parseStatus,
    parseError: record.parseError || null,
    email: record.email || '',
    accountId: record.accountId || '',
    userId: record.userId || '',
    identityKeys: Array.isArray(record.identityKeys) ? record.identityKeys : [],
    expiresAt: record.expiresAt || null,
    expiryStatus: record.expiryStatus || (record.expiresAt ? 'valid' : 'missing'),
    lastRefresh: record.lastRefresh || null,
    disabled: record.disabled === true,
    type: record.type || '',
    fingerprints: record.fingerprints || {},
  };
}

module.exports = {
  asString,
  normalizeEmail,
  normalizeIdentityValue,
  parseDateValue,
  parseJwtPayload,
  tokenFingerprint,
  buildIdentityKeys,
  normalizeTokenDocument,
  toSafeTokenSummary,
};
