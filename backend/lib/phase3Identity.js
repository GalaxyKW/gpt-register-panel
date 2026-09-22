const path = require('node:path');

const { normalizeEmail } = require('./token');

const PHASE3_PHONE_HTTP_MAX_BYTES = 80;
const PHASE3_PHONE_USERNAME_MAX_BYTES = 64;
const PHASE3_SELECTION_KEY_MAX_BYTES = 512;
const UNSAFE_IDENTITY_TEXT = /[\p{Cc}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
const PHASE3_PHONE_CHARACTERS = /^[0-9 +().-]+$/;

function utf8LengthWithin(value, maximumBytes) {
  return Buffer.byteLength(value, 'utf8') <= maximumBytes;
}

function normalizePhase3Email(value, options = {}) {
  if (value === undefined || (options.allowNull === true && value === null)) return '';
  if (typeof value !== 'string') return null;
  if (value === '') return '';
  const normalized = normalizeEmail(value);
  return normalized || null;
}

function normalizePhase3Phone(value, options = {}) {
  const maximumBytes = Number.isSafeInteger(options.maximumBytes) && options.maximumBytes > 0
    ? Math.min(options.maximumBytes, PHASE3_PHONE_HTTP_MAX_BYTES)
    : PHASE3_PHONE_HTTP_MAX_BYTES;
  if (value === undefined || (options.allowNull === true && value === null)) return '';
  let raw;
  if (typeof value === 'string') raw = value;
  else if (options.allowNumber === true
      && typeof value === 'number'
      && Number.isSafeInteger(value)
      && value >= 0) raw = String(value);
  else return null;
  if (raw === '') return '';
  if (!utf8LengthWithin(raw, maximumBytes)
      || UNSAFE_IDENTITY_TEXT.test(raw)
      || !PHASE3_PHONE_CHARACTERS.test(raw)) return null;
  const digits = raw.replace(/[^0-9]/g, '');
  return digits || null;
}

function normalizePhase3Identity(value, options = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const emailValue = Object.prototype.hasOwnProperty.call(value, 'email')
    ? value.email
    : undefined;
  const phoneValue = Object.prototype.hasOwnProperty.call(value, 'phone')
    ? value.phone
    : undefined;
  const email = normalizePhase3Email(emailValue, { allowNull: options.allowNull === true });
  const phone = normalizePhase3Phone(phoneValue, {
    maximumBytes: options.phoneMaximumBytes,
    allowNumber: options.allowPhoneNumber === true,
    allowNull: options.allowNull === true,
  });
  if (email === null || phone === null || (!email && !phone)) return null;
  return {
    email,
    phone,
    keys: [email ? 'email:' + email : null, phone ? 'phone:' + phone : null]
      .filter(Boolean),
  };
}

function normalizePhase3RelativePath(value, source, options = {}) {
  if (typeof value !== 'string' || !['tokens', 'use_token'].includes(source)) return null;
  const maximumBytes = Number.isSafeInteger(options.maximumBytes) && options.maximumBytes > 0
    ? Math.min(options.maximumBytes, PHASE3_SELECTION_KEY_MAX_BYTES)
    : PHASE3_SELECTION_KEY_MAX_BYTES;
  if (!value || value.normalize('NFC') !== value || !utf8LengthWithin(value, maximumBytes)
      || value.includes('\\') || path.posix.isAbsolute(value)
      || UNSAFE_IDENTITY_TEXT.test(value)) return null;
  const segments = value.split('/');
  if (segments.length < 2 || segments[0] !== source
      || segments.some((segment) => !segment || segment === '.' || segment === '..')
      || !segments.at(-1).toLowerCase().endsWith('.json')) return null;
  return value;
}

function normalizePhase3SelectedKey(value) {
  if (typeof value !== 'string' || value !== value.trim()
      || !value || !utf8LengthWithin(value, PHASE3_SELECTION_KEY_MAX_BYTES)
      || UNSAFE_IDENTITY_TEXT.test(value)) return null;
  const match = /^token:(tokens|use_token):(.+)$/u.exec(value);
  if (!match) return null;
  const source = match[1];
  const relativePath = normalizePhase3RelativePath(match[2], source, {
    maximumBytes: PHASE3_SELECTION_KEY_MAX_BYTES,
  });
  return relativePath ? value : null;
}

function phase3SelectedKeyForToken(token) {
  const source = typeof token?.source === 'string' ? token.source : '';
  const relativePath = normalizePhase3RelativePath(token?.relativePath, source);
  if (!relativePath) return null;
  return normalizePhase3SelectedKey('token:' + source + ':' + relativePath);
}

// Local credential recovery is an explicit, separate selection namespace.
// Do not teach the token selection parser to accept these keys: an ordinary
// token request must never fall back to username.json merely by matching email.
function normalizeLocalPhase3SelectedKey(value) {
  if (typeof value !== 'string' || !/^username:(0|[1-9]\d{0,15})$/.test(value)) return null;
  const index = Number(value.slice('username:'.length));
  return Number.isSafeInteger(index) ? value : null;
}

function normalizePhase3CanonicalKey(value) {
  if (typeof value !== 'string' || !value || value !== value.trim()
      || UNSAFE_IDENTITY_TEXT.test(value)) return null;
  if (value.startsWith('email:')) {
    const email = normalizePhase3Email(value.slice('email:'.length));
    return email && value === 'email:' + email ? value : null;
  }
  if (value.startsWith('phone:')) {
    const phone = value.slice('phone:'.length);
    return /^\d{1,80}$/.test(phone) ? value : null;
  }
  return null;
}

function normalizePhase3CanonicalKeys(value, options = {}) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 2) return null;
  const keys = value.map(normalizePhase3CanonicalKey);
  if (keys.some((key) => !key) || new Set(keys).size !== keys.length) return null;
  if (new Set(keys.map((key) => key.slice(0, key.indexOf(':')))).size !== keys.length) {
    return null;
  }
  if (Object.prototype.hasOwnProperty.call(options, 'requiredKeys')
      && !Array.isArray(options.requiredKeys)) return null;
  const requiredKeys = Array.isArray(options.requiredKeys) ? options.requiredKeys : [];
  if (requiredKeys.length > 2
      || requiredKeys.some((key) => normalizePhase3CanonicalKey(key) !== key)
      || new Set(requiredKeys).size !== requiredKeys.length) return null;
  if (requiredKeys.some((key) => !keys.includes(key))) return null;
  return keys.sort();
}

module.exports = {
  PHASE3_PHONE_HTTP_MAX_BYTES,
  PHASE3_PHONE_USERNAME_MAX_BYTES,
  PHASE3_SELECTION_KEY_MAX_BYTES,
  normalizePhase3CanonicalKey,
  normalizePhase3CanonicalKeys,
  normalizePhase3Email,
  normalizePhase3Identity,
  normalizePhase3Phone,
  normalizePhase3RelativePath,
  normalizePhase3SelectedKey,
  normalizeLocalPhase3SelectedKey,
  phase3SelectedKeyForToken,
};
