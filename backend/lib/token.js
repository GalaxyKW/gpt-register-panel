const crypto = require('node:crypto');
const C0_OR_DEL = /[\u0000-\u001f\u007f]/;
const CREDENTIAL_LINE_CONTROL = /[\u0000\u000a\u000d]/;
const IDENTITY_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
const EMAIL_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/;
const CANONICAL_STRONG_IDENTITY = /^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/;
const COMPACT_JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
const CREDENTIAL_IDENTITY_LABEL = /(?:^|[._:@/+~-])(?:authorization|bearer|credential|password|passwd|access[-_]?token|refresh[-_]?token|id[-_]?token|api[-_]?key|apikey|token)(?:$|[._:@/+~=-])/i;
const CREDENTIAL_IDENTITY_PREFIX = /^(?:sk|rk|pk|sess|secret)[-_][A-Za-z0-9_-]{12,}$/i;
const LONG_OPAQUE_IDENTITY = /^(?=.{96,}$)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_+./=-]+$/;
const RFC3339_DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/;

function asString(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

function normalizeEmail(value) {
  const raw = value === undefined || value === null ? '' : String(value);
  const text = raw.trim();
  return !text
    || text.length > 320
    || EMAIL_CONTROL_OR_BIDI.test(raw)
    || !/^[^\s@]+@[^\s@]+$/.test(text)
    ? ''
    : text.toLowerCase();
}

function normalizeIdentityValue(prefix, value) {
  const raw = value === undefined || value === null ? '' : String(value);
  if (C0_OR_DEL.test(raw)) return '';
  const text = raw.trim();
  if (prefix === 'email:') return normalizeEmail(raw);
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
  // Date.parse accepts implementation-dependent forms and silently rolls some
  // impossible civil dates (for example 2026-02-30) into the next month. Token
  // ordering and deletion must only use an explicit, validated instant.
  if (typeof value !== 'string' || value !== text) return null;
  const match = RFC3339_DATE_TIME.exec(text);
  if (!match) return null;
  // RFC 3339 uses "-00:00" to mean that the local offset is unknown. It is
  // not an assertion of UTC and therefore cannot safely drive expiry/deletion.
  if (text.endsWith('-00:00')) return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText,
    offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const offsetHour = offsetHourText === undefined ? 0 : Number(offsetHourText);
  const offsetMinute = offsetMinuteText === undefined ? 0 : Number(offsetMinuteText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12
      || day < 1 || day > daysInMonth[month - 1]
      || hour > 23 || minute > 59 || second > 59
      || offsetHour > 23 || offsetMinute > 59) return null;
  const timestamp = Date.parse(text);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
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

function stringAliases(object, keys, maximumLength, options = {}) {
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
    if (normalized.length > maximumLength
        || (options.rejectControls && options.rejectControls.test(raw))
        || (value && value !== normalized)) invalid = true;
    else if (normalized) value = normalized;
  }
  return { value, invalid };
}

const TOKEN_CREDENTIAL_FIELDS = Object.freeze({
  access: Object.freeze({ keys: Object.freeze(['access_token', 'accessToken']), maximumLength: 2 * 1024 * 1024 }),
  refresh: Object.freeze({ keys: Object.freeze(['refresh_token', 'refreshToken']), maximumLength: 256 * 1024 }),
  id: Object.freeze({ keys: Object.freeze(['id_token', 'idToken']), maximumLength: 2 * 1024 * 1024 }),
});

function tokenCredentialField(document, kind) {
  const definition = TOKEN_CREDENTIAL_FIELDS[kind];
  if (!definition) return { value: '', invalid: true };
  return stringAliases(document, definition.keys, definition.maximumLength, {
    rejectControls: CREDENTIAL_LINE_CONTROL,
  });
}

function claimScalar(object, key, maximumLength, allowNumber = true) {
  if (!object || !Object.prototype.hasOwnProperty.call(object, key)) {
    return { value: '', invalid: false };
  }
  const raw = object[key];
  if (raw === undefined || raw === null || raw === '') return { value: '', invalid: false };
  if (typeof raw !== 'string'
      && !(allowNumber && typeof raw === 'number'
        && Number.isSafeInteger(raw) && !Object.is(raw, -0))) {
    return { value: '', invalid: true };
  }
  const rawText = String(raw);
  const value = rawText.trim();
  return value.length <= maximumLength && !C0_OR_DEL.test(rawText)
    ? { value, invalid: false }
    : { value: '', invalid: true };
}

function looksLikeCredentialIdentity(value) {
  return /^(?:bearer|basic)\s+\S+/i.test(value)
    || COMPACT_JWT.test(value)
    || CREDENTIAL_IDENTITY_LABEL.test(value)
    || CREDENTIAL_IDENTITY_PREFIX.test(value)
    || LONG_OPAQUE_IDENTITY.test(value);
}

function strongIdentityField(field, prefix, maximumLength = 512) {
  if (!field || field.invalid) return { value: '', invalid: true };
  if (!field.value) return { value: '', invalid: false };
  const raw = String(field.value);
  const normalized = normalizeIdentityValue(prefix, raw);
  if (!normalized || raw !== raw.trim() || normalized.length > maximumLength
      || IDENTITY_CONTROL_OR_BIDI.test(raw)
      || !CANONICAL_STRONG_IDENTITY.test(normalized)
      || looksLikeCredentialIdentity(normalized)) {
    return { value: '', invalid: true };
  }
  return { value: normalized, invalid: false };
}

function emailIdentityField(field) {
  if (!field || field.invalid) return { value: '', invalid: true };
  if (!field.value) return { value: '', invalid: false };
  const value = normalizeEmail(field.value);
  return value
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
  const accessField = tokenCredentialField(document, 'access');
  const refreshField = tokenCredentialField(document, 'refresh');
  const idField = tokenCredentialField(document, 'id');
  const explicitAccount = strongIdentityField(stringAliases(
    document,
    ['chatgpt_account_id', 'account_id', 'accountId'],
    512,
    { rejectControls: C0_OR_DEL },
  ), 'account:');
  const explicitUser = strongIdentityField(stringAliases(
    document,
    ['chatgpt_user_id', 'user_id', 'userId'],
    512,
    { rejectControls: C0_OR_DEL },
  ), 'user:');
  const explicitEmail = emailIdentityField(stringAliases(
    document,
    ['email'],
    320,
    { rejectControls: C0_OR_DEL },
  ));
  const explicitTypeField = stringAliases(document, ['type'], 32, { rejectControls: C0_OR_DEL });
  const accessToken = accessField.value;
  const refreshToken = refreshField.value;
  const idToken = idField.value;
  const accessPayload = parseJwtPayload(accessToken);
  const idPayload = parseJwtPayload(idToken);
  const auth = openAiAuth(accessPayload);
  const idAuth = openAiAuth(idPayload);
  const claimAccount = strongIdentityField(claimScalar(auth, 'chatgpt_account_id', 512), 'account:');
  const claimChatGptUser = strongIdentityField(claimScalar(auth, 'chatgpt_user_id', 512), 'user:');
  const claimUser = strongIdentityField(claimScalar(auth, 'user_id', 512), 'user:');
  const claimSubject = strongIdentityField(claimScalar(accessPayload, 'sub', 512), 'user:');
  const idClaimAccount = strongIdentityField(claimScalar(idAuth, 'chatgpt_account_id', 512), 'account:');
  const idClaimChatGptUser = strongIdentityField(claimScalar(idAuth, 'chatgpt_user_id', 512), 'user:');
  const idClaimUser = strongIdentityField(claimScalar(idAuth, 'user_id', 512), 'user:');
  const idClaimSubject = strongIdentityField(claimScalar(idPayload, 'sub', 512), 'user:');
  const claimAuthEmail = emailIdentityField(claimScalar(auth, 'email', 320, false));
  const claimEmail = emailIdentityField(claimScalar(accessPayload, 'email', 320, false));
  const idClaimAuthEmail = emailIdentityField(claimScalar(idAuth, 'email', 320, false));
  const idClaimEmail = emailIdentityField(claimScalar(idPayload, 'email', 320, false));
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
  const emailFields = [
    explicitEmail,
    claimAuthEmail,
    claimEmail,
    idClaimAuthEmail,
    idClaimEmail,
  ];
  const email = normalizeEmail(emailFields.find((field) => field.value)?.value || '');
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
  const emailIdentityConflict = identityDimensionConflict('email:', emailFields);
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
      idClaimAuthEmail,
      idClaimEmail,
    ].some((field) => field.invalid);
  const semanticError = strongIdentityConflict
    ? 'token 强身份字段互相矛盾'
    : emailIdentityConflict
    ? 'token email 字段互相矛盾'
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
  tokenCredentialField,
  buildIdentityKeys,
  normalizeTokenDocument,
  toSafeTokenSummary,
};
