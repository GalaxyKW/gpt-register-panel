const {
  normalizeEmail,
  tokenFingerprint,
  parseDateValue,
  asString,
  normalizeIdentityValue,
} = require('../lib/token');
const crypto = require('node:crypto');
const net = require('node:net');
const { TextDecoder } = require('node:util');
const { redactText } = require('../logger');

const DEFAULT_REQUEST_TIMEOUT_MS = 15000;
const MAX_REQUEST_TIMEOUT_MS = 120000;
const DEFAULT_TEST_TIMEOUT_MS = 120000;
const MAX_TEST_TIMEOUT_MS = 600000;
const DEFAULT_RESPONSE_BODY_BYTES = 4 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES = 32 * 1024 * 1024;
const MAX_ADMIN_BASE_URL_BYTES = 4096;
const MAX_ADMIN_REQUEST_PATH_BYTES = 4096;
const MAX_BATCH_ACCOUNT_IDS = 1000;
const ADMIN_REQUEST_METHODS = new Set(['GET', 'POST']);
const SUB2API_EXPORT_TYPES = new Set(['', 'sub2api-data', 'sub2api-bundle']);
const SUB2API_EXPORT_VERSIONS = new Set([0, 1]);
const IDENTITY_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
const URL_WHITESPACE_CONTROL_OR_BIDI = /[\s\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
const CREDENTIAL_WHITESPACE_CONTROL_OR_BIDI = /[\s\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/u;
const CANONICAL_STRONG_IDENTITY = /^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/;
const COMPACT_JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
const CREDENTIAL_LABEL = /(?:^|[._:@/+~-])(?:authorization|bearer|credential|password|passwd|access[-_]?token|refresh[-_]?token|id[-_]?token|api[-_]?key|apikey|token)(?:$|[._:@/+~=-])/i;
const CREDENTIAL_PREFIX = /^(?:sk|rk|pk|sess|secret)[-_][A-Za-z0-9_-]{12,}$/i;
const LONG_OPAQUE_CREDENTIAL = /^(?=.{96,}$)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_+./=-]+$/;
const CANONICAL_MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:+@~*\/-]{0,255}$/;
const CODEX_IMPORT_COUNTER_KEYS = Object.freeze(['total', 'created', 'updated', 'skipped', 'failed']);
const CODEX_IMPORT_ACTIONS = Object.freeze(['created', 'updated', 'skipped', 'failed']);

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    return Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

function isValidExportPayload(value) {
  if (!isPlainObject(value)) return false;
  if (!Object.prototype.hasOwnProperty.call(value, 'accounts')
      || !Array.isArray(value.accounts)) return false;
  if (!Object.prototype.hasOwnProperty.call(value, 'proxies')
      || !Array.isArray(value.proxies)) return false;
  if (Object.prototype.hasOwnProperty.call(value, 'type')
      && (typeof value.type !== 'string' || !SUB2API_EXPORT_TYPES.has(value.type))) return false;
  if (Object.prototype.hasOwnProperty.call(value, 'version')
      && (!Number.isSafeInteger(value.version)
        || !SUB2API_EXPORT_VERSIONS.has(value.version))) return false;
  return true;
}

function groupListRows(value) {
  // The current Sub2API /groups/all contract returns data as a bare array.
  // Do not reuse account-list aliases here: accepting `{ accounts: [...] }`
  // can turn a response from the wrong endpoint into group bindings.
  if (!Array.isArray(value)) return null;
  const ids = new Set();
  for (const row of value) {
    const id = isPlainObject(row) ? positiveAccountId(row.id) : null;
    if (!id
        || !hasOwn(row, 'name')
        || typeof row.name !== 'string'
        || !hasOwn(row, 'description')
        || typeof row.description !== 'string'
        || !hasOwn(row, 'platform')
        || typeof row.platform !== 'string'
        || !hasOwn(row, 'status')
        || typeof row.status !== 'string'
        || ids.has(id)) return null;
    ids.add(id);
  }
  return value;
}

function modelListRows(value) {
  if (Array.isArray(value)) return value;
  if (!isPlainObject(value)
      || !hasOwn(value, 'models')
      || !Array.isArray(value.models)) return null;
  // Retain the legacy `{ models: [...] }` envelope, but reject an ambiguous
  // object that also carries a collection name belonging to another endpoint.
  if (ACCOUNT_LIST_ALIASES.some((key) => hasOwn(value, key))) return null;
  return value.models;
}

function modelRowId(value) {
  if (typeof value === 'string') return safeModelId(value);
  if (!isPlainObject(value)) return '';
  const aliases = ['id', 'model_id', 'name'].filter((key) => hasOwn(value, key));
  if (aliases.length === 0) return '';
  const normalized = aliases.map((key) => safeModelId(value[key]));
  if (normalized.some((item) => !item) || new Set(normalized).size !== 1) return '';
  return normalized[0];
}

function codexImportMessageIsValid(value, total) {
  return isPlainObject(value)
    && Number.isSafeInteger(value.index)
    && value.index >= 1
    && value.index <= total
    && typeof value.message === 'string'
    && value.message.length > 0
    && (!hasOwn(value, 'name') || typeof value.name === 'string');
}

function codexImportResultStatus(value) {
  if (!isPlainObject(value)) return 'invalid';
  const flags = ['success', 'ok'].filter((key) => hasOwn(value, key));
  if (flags.some((key) => typeof value[key] !== 'boolean')
      || new Set(flags.map((key) => value[key])).size > 1) return 'invalid';
  if (CODEX_IMPORT_COUNTER_KEYS.some((key) => (
    !hasOwn(value, key)
      || !Number.isSafeInteger(value[key])
      || value[key] < 0
  ))) return 'invalid';
  if (value.total < 1
      || value.total !== value.created + value.updated + value.skipped + value.failed
      || !hasOwn(value, 'items')
      || !Array.isArray(value.items)
      || value.items.length !== value.total) return 'invalid';

  const actionCounts = Object.fromEntries(CODEX_IMPORT_ACTIONS.map((action) => [action, 0]));
  const itemIndices = new Set();
  const failedIndices = new Set();
  const accountIds = new Set();
  for (const item of value.items) {
    if (!isPlainObject(item)
        || !Number.isSafeInteger(item.index)
        || item.index < 1
        || item.index > value.total
        || itemIndices.has(item.index)
        || !CODEX_IMPORT_ACTIONS.includes(item.action)
        || (hasOwn(item, 'name') && typeof item.name !== 'string')
        || (hasOwn(item, 'message') && typeof item.message !== 'string')
        || hasOwn(item, 'accountId')) return 'invalid';
    const requiresAccountId = item.action === 'created' || item.action === 'updated';
    if (requiresAccountId !== hasOwn(item, 'account_id')
        || (requiresAccountId && (
          !Number.isSafeInteger(item.account_id) || item.account_id <= 0
        ))) return 'invalid';
    itemIndices.add(item.index);
    actionCounts[item.action] += 1;
    if (item.action === 'failed') failedIndices.add(item.index);
    if (requiresAccountId) accountIds.add(item.account_id);
  }
  if (CODEX_IMPORT_ACTIONS.some((action) => actionCounts[action] !== value[action])) {
    return 'invalid';
  }

  const errors = hasOwn(value, 'errors') ? value.errors : [];
  const warnings = hasOwn(value, 'warnings') ? value.warnings : [];
  if (!Array.isArray(errors)
      || !Array.isArray(warnings)
      || errors.length !== value.failed
      || errors.some((item) => !codexImportMessageIsValid(item, value.total))
      || warnings.some((item) => !codexImportMessageIsValid(item, value.total))) return 'invalid';
  const errorIndices = new Set(errors.map((item) => item.index));
  if (errorIndices.size !== errors.length
      || [...errorIndices].some((index) => !failedIndices.has(index))) return 'invalid';

  const directIds = ['account_id', 'accountId']
    .filter((key) => hasOwn(value, key))
    .map((key) => value[key]);
  if (directIds.some((id) => !Number.isSafeInteger(id) || id <= 0)
      || new Set(directIds).size > 1
      || (directIds.length > 0
        && (value.total !== 1 || accountIds.size !== 1 || !accountIds.has(directIds[0])))) {
    return 'invalid';
  }
  return flags.some((key) => value[key] === false) || value.failed > 0
    ? 'unsuccessful'
    : 'success';
}

const ACCOUNT_LIST_ALIASES = Object.freeze(['items', 'records', 'list', 'accounts']);

function hasOwn(object, key) {
  return Boolean(object && Object.prototype.hasOwnProperty.call(object, key));
}

function accountListRows(value, requireCanonical = false) {
  if (Array.isArray(value)) {
    return requireCanonical ? { rows: null, invalid: true } : { rows: value, invalid: false };
  }
  if (!isPlainObject(value)) return { rows: null, invalid: true };
  const aliases = ACCOUNT_LIST_ALIASES.filter((key) => hasOwn(value, key));
  if (aliases.length !== 1) return { rows: null, invalid: true };
  if (requireCanonical && aliases[0] !== 'items') return { rows: null, invalid: true };
  return Array.isArray(value[aliases[0]])
    ? { rows: value[aliases[0]], invalid: false }
    : { rows: null, invalid: true };
}

function canonicalPaginationInteger(value, minimum) {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= minimum
    ? value
    : null;
}

function paginationAlias(value, directKeys, nestedKeys, parser) {
  const entries = [];
  for (const key of directKeys) {
    if (hasOwn(value, key)) entries.push(value[key]);
  }
  const hasPagination = hasOwn(value, 'pagination')
    && value.pagination !== undefined
    && value.pagination !== null;
  if (hasPagination && !isPlainObject(value.pagination)) {
    return { provided: true, value: null, invalid: true, conflict: false };
  }
  if (hasPagination) {
    for (const key of nestedKeys) {
      if (hasOwn(value.pagination, key)) entries.push(value.pagination[key]);
    }
  }
  if (entries.length === 0) {
    return { provided: false, value: null, invalid: false, conflict: false };
  }
  const normalized = entries.map(parser);
  const valid = normalized.filter((item) => item !== null);
  return {
    provided: true,
    value: valid[0] ?? null,
    invalid: valid.length !== normalized.length,
    conflict: new Set(valid).size > 1,
  };
}

function accountPagination(value) {
  return {
    total: paginationAlias(value, ['total'], ['total'], paginationTotal),
    page: paginationAlias(
      value,
      ['page'],
      ['page'],
      (item) => canonicalPaginationInteger(item, 1),
    ),
    pageSize: paginationAlias(
      value,
      ['page_size', 'pageSize'],
      ['page_size', 'pageSize'],
      (item) => canonicalPaginationInteger(item, 1),
    ),
    pages: paginationAlias(
      value,
      ['pages', 'total_pages', 'totalPages'],
      ['pages', 'total_pages', 'totalPages'],
      (item) => canonicalPaginationInteger(item, 1),
    ),
  };
}

function unwrapData(value) {
  if (value && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, 'data')) {
    return value.data;
  }
  return value;
}

function accountCredentials(account) {
  return account?.credentials && typeof account.credentials === 'object'
    && !Array.isArray(account.credentials)
    ? account.credentials
    : {};
}

function scalarText(value, maximumLength = 1024, allowNumber = false) {
  if (typeof value !== 'string'
      && !(allowNumber && typeof value === 'number' && Number.isFinite(value))) return '';
  const text = String(value).trim();
  return text.length <= maximumLength ? text : '';
}

function firstScalar(values, maximumLength, allowNumber = false) {
  for (const value of values) {
    const text = scalarText(value, maximumLength, allowNumber);
    if (text) return text;
  }
  return '';
}

function positiveAccountId(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const text = String(value).trim();
  if (!/^[1-9]\d*$/.test(text)) return null;
  const id = Number(text);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function requestedAccountId(value, code, message) {
  const id = typeof value === 'number' && Number.isSafeInteger(value) && value > 0
    ? value
    : (typeof value === 'string'
        && /^[1-9]\d*$/.test(value)
        && Number.isSafeInteger(Number(value))
      ? Number(value)
      : null);
  if (id) return id;
  const error = new Error(message);
  error.code = code;
  throw error;
}

function paginationTotal(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d*)$/.test(value)) return null;
  const total = Number(value);
  return Number.isSafeInteger(total) ? total : null;
}

function scalarAliases(values, maximumLength, options = {}) {
  const present = values.filter((value) => value !== undefined && value !== null && value !== '');
  const normalized = [];
  let invalid = false;
  for (const raw of present) {
    const text = scalarText(raw, maximumLength, options.allowNumber === true);
    if (!text
        || (options.rejectOuterWhitespace === true
          && typeof raw === 'string' && raw !== text)
        || (options.rejectPattern instanceof RegExp
          && typeof raw === 'string' && options.rejectPattern.test(raw))) {
      invalid = true;
      continue;
    }
    const value = options.normalize ? options.normalize(text) : text;
    if (!value) invalid = true;
    else normalized.push(value);
  }
  const unique = [...new Set(normalized)];
  return {
    value: unique[0] || '',
    values: unique,
    invalid,
    conflict: unique.length > 1,
  };
}

function looksLikeCredential(value) {
  return /^(?:bearer|basic)\s+\S+/i.test(value)
    || COMPACT_JWT.test(value)
    || CREDENTIAL_LABEL.test(value)
    || CREDENTIAL_PREFIX.test(value)
    || LONG_OPAQUE_CREDENTIAL.test(value);
}

function strongIdentityScalar(raw, prefix, maximumLength = 512) {
  let text;
  if (typeof raw === 'number') {
    if (!Number.isSafeInteger(raw) || Object.is(raw, -0)) {
      return { value: '', invalid: true };
    }
    text = String(raw);
  } else if (typeof raw === 'string') {
    text = raw;
  } else {
    return { value: '', invalid: true };
  }
  if (!text || text !== text.trim() || text.length > maximumLength
      || IDENTITY_CONTROL_OR_BIDI.test(text)) {
    return { value: '', invalid: true };
  }
  const value = normalizeIdentityValue(prefix, text);
  if (!value || value.length > maximumLength
      || !CANONICAL_STRONG_IDENTITY.test(value)
      || looksLikeCredential(value)) {
    return { value: '', invalid: true };
  }
  return { value, invalid: false };
}

function identityAliases(values, prefix, maximumLength = 512) {
  const present = values.filter((value) => value !== undefined && value !== null && value !== '');
  const normalized = [];
  let invalid = false;
  for (const raw of present) {
    const field = strongIdentityScalar(raw, prefix, maximumLength);
    if (field.invalid) invalid = true;
    else normalized.push(field.value);
  }
  const unique = [...new Set(normalized)];
  return {
    value: unique[0] || '',
    values: unique,
    invalid,
    conflict: unique.length > 1,
  };
}

function identityKeysFromFields(accountField, userField, emailField) {
  return [
    ...accountField.values.map((value) => 'account:' + value),
    ...userField.values.map((value) => 'user:' + value),
    ...emailField.values.map((value) => 'email:' + value),
  ];
}

function boundedTimeout(value, fallback, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return fallback;
  return Math.min(Math.floor(number), maximum);
}

function isLoopbackHostname(hostname) {
  if (typeof hostname !== 'string') return false;
  // WHATWG URL keeps brackets around IPv6 hostnames and canonicalizes IPv4
  // alternative spellings before this function is called. Strip only a
  // complete bracket pair, then require a numeric address.
  const normalized = hostname.toLowerCase();
  const value = normalized.startsWith('[') && normalized.endsWith(']')
    ? normalized.slice(1, -1)
    : normalized;
  const family = net.isIP(value);
  if (family === 6) return value === '::1';
  if (family !== 4) return false;
  return Number(value.split('.')[0]) === 127;
}

function adminRequestTargetError(code) {
  const error = new Error(code === 'SUB2API_REQUEST_METHOD_INVALID'
    ? 'Sub2API 管理请求方法无效'
    : 'Sub2API 管理请求目标无效');
  error.code = code;
  return error;
}

function validatedAdminRequestTarget(baseUrl, baseOrigin, method, pathname) {
  if (typeof method !== 'string' || !ADMIN_REQUEST_METHODS.has(method)) {
    throw adminRequestTargetError('SUB2API_REQUEST_METHOD_INVALID');
  }
  const queryOffset = typeof pathname === 'string' ? pathname.indexOf('?') : -1;
  const pathOnly = typeof pathname === 'string' && queryOffset >= 0
    ? pathname.slice(0, queryOffset)
    : pathname;
  if (typeof pathname !== 'string'
      || pathname.length === 0
      || Buffer.byteLength(pathname, 'utf8') > MAX_ADMIN_REQUEST_PATH_BYTES
      || pathname[0] !== '/'
      || pathname.startsWith('//')
      || pathname.includes('\\')
      || pathname.includes('#')
      || /[\u0000-\u001f\u007f-\u009f]/.test(pathname)
      || /%(?:2f|5c)/i.test(pathOnly)
      || /%(?![0-9a-f]{2})/i.test(pathname)) {
    throw adminRequestTargetError('SUB2API_REQUEST_TARGET_INVALID');
  }
  let target;
  try {
    target = new URL(baseUrl + pathname);
  } catch {
    throw adminRequestTargetError('SUB2API_REQUEST_TARGET_INVALID');
  }
  if (target.origin !== baseOrigin || target.username || target.password || target.hash) {
    throw adminRequestTargetError('SUB2API_REQUEST_TARGET_INVALID');
  }
  return { method, pathname, url: target.toString() };
}

function normalizedAccountIds(ids) {
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_BATCH_ACCOUNT_IDS) {
    const error = new Error('Sub2API 批量统计必须包含 1-1000 个账号 ID');
    error.code = 'SUB2API_ACCOUNT_IDS_INVALID';
    throw error;
  }
  const normalized = ids.map((value) => requestedAccountId(
    value,
    'SUB2API_ACCOUNT_IDS_INVALID',
    'Sub2API 批量统计账号 ID 必须是规范正整数',
  ));
  if (new Set(normalized).size !== normalized.length) {
    const error = new Error('Sub2API 批量统计账号 ID 不能重复');
    error.code = 'SUB2API_ACCOUNT_IDS_DUPLICATE';
    throw error;
  }
  return normalized;
}

function storedFingerprint(value) {
  const text = asString(value).toLowerCase();
  return /^[a-f0-9]{64}$/.test(text) ? text : null;
}

function fullTokenFingerprint(value) {
  const text = asString(value);
  return text ? crypto.createHash('sha256').update(text).digest('hex') : null;
}

function shortStoredFingerprint(field) {
  return field.invalid || field.conflict || !field.value
    ? null
    : field.value.slice(0, 16);
}

function normalizedDateAliases(...values) {
  const present = values.filter((value) => value !== undefined && value !== null && value !== '');
  if (present.length === 0) return { value: null, status: 'missing', conflict: false };
  const normalized = present.map((value) => (
    typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))
      ? parseDateValue(value)
      : null
  ));
  const unique = [...new Set(normalized.filter(Boolean))];
  const conflict = unique.length > 1;
  return normalized.some((value) => !value) || conflict
    ? { value: null, status: 'invalid', conflict }
    : { value: unique[0], status: 'valid', conflict: false };
}

function normalizedCredentialsStatus(account) {
  const aliases = [account?.credentials_status, account?.credentialsStatus]
    .filter((value) => value !== undefined && value !== null);
  if (aliases.length === 0) return { provided: false, value: null, valid: true };
  if (aliases.length !== 1) return { provided: true, value: null, valid: false };
  const value = aliases[0];
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { provided: true, value: null, valid: false };
  }
  const valid = Object.entries(value).every(([key, present]) => (
    /^has_[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(key) && typeof present === 'boolean'
  ));
  return { provided: true, value: valid ? value : null, valid };
}

function credentialPresence(status, statusKey, rawField, storedFingerprintField = null) {
  const localEvidence = Boolean(rawField?.value || storedFingerprintField?.value);
  if (!status.valid) return { value: 'unknown', conflict: false };
  if (!status.provided) {
    return { value: localEvidence ? 'present' : 'unknown', conflict: false };
  }
  const declaredPresent = status.value[statusKey] === true;
  return {
    value: declaredPresent ? 'present' : 'absent',
    conflict: !declaredPresent && localEvidence,
  };
}

function normalizedAccountGroupIds(account) {
  const aliases = [];
  for (const [key, objectKeys, allowScalar] of [
    ['group_ids', null, true],
    ['groupIds', null, true],
    ['groups', ['id'], true],
    ['account_groups', ['group_id', 'groupId'], false],
    ['accountGroups', ['group_id', 'groupId'], false],
  ]) {
    if (!hasOwn(account, key) || account[key] === undefined || account[key] === null) continue;
    const rawValues = account[key];
    if (!Array.isArray(rawValues) || rawValues.length > 10000) {
      return { value: [], valid: false };
    }
    const ids = [];
    for (const raw of rawValues) {
      let candidate = raw;
      if (objectKeys) {
        if (isPlainObject(raw)) {
          const fields = objectKeys.filter((field) => hasOwn(raw, field));
          if (fields.length !== 1) return { value: [], valid: false };
          candidate = raw[fields[0]];
        } else if (!allowScalar) {
          return { value: [], valid: false };
        }
      }
      if (typeof candidate !== 'string' && typeof candidate !== 'number') {
        return { value: [], valid: false };
      }
      const text = String(candidate);
      if (text !== text.trim() || !/^[1-9]\d*$/.test(text)) {
        return { value: [], valid: false };
      }
      const id = Number(text);
      if (!Number.isSafeInteger(id) || id <= 0) return { value: [], valid: false };
      ids.push(id);
    }
    aliases.push([...new Set(ids)].sort((left, right) => left - right));
  }
  if (aliases.length === 0) return { value: [], valid: true };
  const expected = JSON.stringify(aliases[0]);
  if (aliases.some((ids) => JSON.stringify(ids) !== expected)) {
    return { value: [], valid: false };
  }
  return { value: aliases[0], valid: true };
}

function safeAccount(account) {
  const id = positiveAccountId(account?.id);
  if (!id) return null;
  const credentialsShapeValid = account?.credentials === undefined
    || account?.credentials === null
    || (typeof account.credentials === 'object' && !Array.isArray(account.credentials));
  const extraShapeValid = account?.extra === undefined
    || account?.extra === null
    || (typeof account.extra === 'object' && !Array.isArray(account.extra));
  const credentials = accountCredentials(account);
  const extra = account?.extra && typeof account.extra === 'object' && !Array.isArray(account.extra)
    ? account.extra
    : {};
  const emailField = scalarAliases([credentials.email, account.email], 320, {
    normalize: normalizeEmail,
  });
  const accountField = identityAliases([
    credentials.chatgpt_account_id,
    credentials.account_id,
    account.chatgpt_account_id,
    account.account_id,
    account.accountId,
  ], 'account:');
  const userField = identityAliases([
    credentials.chatgpt_user_id,
    credentials.user_id,
    account.chatgpt_user_id,
    account.user_id,
    account.userId,
  ], 'user:');
  const accessField = scalarAliases(
    [credentials.access_token, credentials.accessToken],
    2 * 1024 * 1024,
    {
      rejectOuterWhitespace: true,
      rejectPattern: CREDENTIAL_WHITESPACE_CONTROL_OR_BIDI,
    },
  );
  const refreshField = scalarAliases(
    [credentials.refresh_token, credentials.refreshToken],
    256 * 1024,
    {
      rejectOuterWhitespace: true,
      rejectPattern: CREDENTIAL_WHITESPACE_CONTROL_OR_BIDI,
    },
  );
  const idTokenField = scalarAliases(
    [credentials.id_token, credentials.idToken],
    2 * 1024 * 1024,
    {
      rejectOuterWhitespace: true,
      rejectPattern: CREDENTIAL_WHITESPACE_CONTROL_OR_BIDI,
    },
  );
  const storedFingerprintField = scalarAliases([
    extra.access_token_sha256,
    credentials.access_token_sha256,
  ], 128, {
    normalize: storedFingerprint,
    rejectOuterWhitespace: true,
    rejectPattern: CREDENTIAL_WHITESPACE_CONTROL_OR_BIDI,
  });
  const storedRefreshFingerprintField = scalarAliases([
    extra.refresh_token_sha256,
    credentials.refresh_token_sha256,
  ], 128, {
    normalize: storedFingerprint,
    rejectOuterWhitespace: true,
    rejectPattern: CREDENTIAL_WHITESPACE_CONTROL_OR_BIDI,
  });
  const computedAccessFingerprint = tokenFingerprint(accessField.value);
  const computedRefreshFingerprint = tokenFingerprint(refreshField.value);
  const computedAccessDigest = fullTokenFingerprint(accessField.value);
  const computedRefreshDigest = fullTokenFingerprint(refreshField.value);
  const accessFingerprintConflict = Boolean(
    storedFingerprintField.value
      && computedAccessDigest
      && storedFingerprintField.value !== computedAccessDigest,
  );
  const refreshFingerprintConflict = Boolean(
    storedRefreshFingerprintField.value
      && computedRefreshDigest
      && storedRefreshFingerprintField.value !== computedRefreshDigest,
  );
  const credentialsStatus = normalizedCredentialsStatus(account);
  const accessPresence = credentialPresence(
    credentialsStatus,
    'has_access_token',
    accessField,
    storedFingerprintField,
  );
  const refreshPresence = credentialPresence(
    credentialsStatus,
    'has_refresh_token',
    refreshField,
    storedRefreshFingerprintField,
  );
  const idPresence = credentialPresence(credentialsStatus, 'has_id_token', idTokenField);
  const credentialsStatusConflict = accessPresence.conflict
    || refreshPresence.conflict
    || idPresence.conflict;
  const fingerprintConflict = accessFingerprintConflict
    || refreshFingerprintConflict
    || storedFingerprintField.invalid
    || storedFingerprintField.conflict
    || storedRefreshFingerprintField.invalid
    || storedRefreshFingerprintField.conflict;
  const identityConflict = accountField.conflict || userField.conflict;
  const scalarSchemaValid = credentialsShapeValid
    && extraShapeValid
    && credentialsStatus.valid
    && !credentialsStatusConflict
    && !identityConflict
    && !fingerprintConflict
    && ![
      emailField,
      accountField,
      userField,
      accessField,
      refreshField,
      idTokenField,
      storedFingerprintField,
      storedRefreshFingerprintField,
    ].some((field) => field.invalid || field.conflict);
  const email = emailField.value;
  const accountId = accountField.value;
  const userId = userField.value;
  const credentialExpiry = normalizedDateAliases(
    credentials.expired,
    credentials.expires_at,
    credentials.expiresAt,
    credentials.expire_at,
  );
  const accountExpiry = normalizedDateAliases(account.expires_at, account.expiresAt);
  const tempUnschedulable = normalizedDateAliases(
    account.temp_unschedulable_until,
    account.tempUnschedulableUntil,
  );
  const rateLimitReset = normalizedDateAliases(
    account.rate_limit_reset_at,
    account.rateLimitResetAt,
  );
  const overload = normalizedDateAliases(account.overload_until, account.overloadUntil);
  const autoPauseValues = [account.auto_pause_on_expired, account.autoPauseOnExpired]
    .filter((value) => value !== undefined && value !== null);
  const autoPauseInvalid = autoPauseValues.some((value) => typeof value !== 'boolean')
    || new Set(autoPauseValues).size > 1;
  const autoPauseOnExpired = autoPauseValues.length === 0
    ? true
    : autoPauseInvalid ? null : autoPauseValues[0];
  const dateFields = [
    credentialExpiry,
    accountExpiry,
    tempUnschedulable,
    rateLimitReset,
    overload,
  ];
  const groupIds = normalizedAccountGroupIds(account);
  const schemaValid = scalarSchemaValid
    && !autoPauseInvalid
    && groupIds.valid
    && dateFields.every((field) => field.status !== 'invalid');
  const nestedUsage = normalizeTableUsageStats(account.usage);
  const hasNestedUsageShape = account.usage && typeof account.usage === 'object'
    && ['historical', 'history', 'current', 'today', 'historical_usage', 'current_usage']
      .some((key) => Object.prototype.hasOwnProperty.call(account.usage, key));
  const name = safeRemoteText(scalarText(account.name, 256), 256);
  const rawStatus = scalarText(account.status, 64).toLowerCase();
  const status = /^[a-z0-9_-]{1,64}$/.test(rawStatus) ? rawStatus : '';
  // Sub2API's account contract uses `inactive`; retain `disabled` only as a
  // conservative compatibility value for older responses.
  const statusKnown = ['active', 'inactive', 'disabled', 'error'].includes(status);
  const schedulableKnown = typeof account.schedulable === 'boolean';
  const tempUnschedulableReasonPresent = Boolean(firstScalar(
    [account.temp_unschedulable_reason, account.tempUnschedulableReason],
    4000,
  ));
  const errorMessagePresent = Boolean(firstScalar(
    [account.error_message, account.errorMessage],
    4000,
  ));
  return {
    id,
    name,
    platform: safeRemoteText(scalarText(account.platform, 64), 64),
    type: safeRemoteText(scalarText(account.type, 64), 64),
    status,
    statusKnown,
    schedulable: schedulableKnown ? account.schedulable : null,
    schedulableKnown,
    tempUnschedulableUntil: tempUnschedulable.value,
    tempUnschedulableUntilStatus: tempUnschedulable.status,
    // These are arbitrary administrator-API strings, not trusted display
    // data. Regex redaction cannot prove that an opaque value is not a
    // credential, so preserve only the fact that a reason/error was present.
    tempUnschedulableReason: tempUnschedulableReasonPresent
      ? 'Sub2API 已报告暂停调度原因（详情已隐藏）'
      : '',
    errorMessage: errorMessagePresent
      ? 'Sub2API 已报告账号错误（详情已隐藏）'
      : '',
    email,
    accountId,
    userId,
    identityKeys: identityKeysFromFields(accountField, userField, emailField),
    schemaValid,
    identityConflict,
    fingerprintConflict,
    credentialsStatusConflict,
    credentialPresence: {
      access: accessPresence.value,
      refresh: refreshPresence.value,
      id: idPresence.value,
    },
    expiresAt: accountExpiry.value,
    expiryStatus: accountExpiry.status,
    credentialExpiresAt: credentialExpiry.value,
    credentialExpiryStatus: credentialExpiry.status,
    // A malformed non-boolean value must not be coerced to true: doing so can
    // turn an active, schedulable account into an apparently unavailable
    // update target solely because it has an old informational expiry.
    autoPauseOnExpired,
    rateLimitResetAt: rateLimitReset.value,
    rateLimitResetStatus: rateLimitReset.status,
    overloadUntil: overload.value,
    overloadUntilStatus: overload.status,
    tokenFingerprints: {
      access: accessField.invalid
        || accessField.conflict
        || storedFingerprintField.invalid
        || storedFingerprintField.conflict
        || accessFingerprintConflict
        ? null
        : shortStoredFingerprint(storedFingerprintField) || computedAccessFingerprint,
      refresh: refreshField.invalid
        || refreshField.conflict
        || storedRefreshFingerprintField.invalid
        || storedRefreshFingerprintField.conflict
        || refreshFingerprintConflict
        ? null
        : shortStoredFingerprint(storedRefreshFingerprintField) || computedRefreshFingerprint,
      id: idTokenField.invalid || idTokenField.conflict ? null : tokenFingerprint(idTokenField.value),
    },
    groupIds: groupIds.value,
    usage: nestedUsage || (!hasNestedUsageShape ? normalizeUsageStats(account.usage) : null),
  };
}

function optionalNumber(value) {
  if (value === undefined || value === null || typeof value === 'boolean') return null;
  if (typeof value === 'string' && !value.trim()) return null;
  if (!['number', 'string'].includes(typeof value)) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function firstOwnValue(object, keys) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(object, key)) {
      return { present: true, value: object[key] };
    }
  }
  return { present: false, value: undefined };
}

function normalizeUsageStats(stats) {
  if (!isPlainObject(stats)) return null;
  const knownKeys = [
    'requests', 'total_requests', 'tokens', 'total_tokens', 'input_tokens',
    'total_input_tokens', 'output_tokens', 'total_output_tokens', 'cost',
    'actual_cost', 'standard_cost', 'user_cost',
  ];
  if (!knownKeys.some((key) => Object.prototype.hasOwnProperty.call(stats, key))) return null;
  const requests = optionalNumber(firstOwnValue(stats, ['requests', 'total_requests']).value);
  const inputTokens = optionalNumber(firstOwnValue(stats, ['input_tokens', 'total_input_tokens']).value);
  const outputTokens = optionalNumber(firstOwnValue(stats, ['output_tokens', 'total_output_tokens']).value);
  const explicitTotal = firstOwnValue(stats, ['tokens', 'total_tokens']);
  let totalTokens = explicitTotal.present ? optionalNumber(explicitTotal.value) : null;
  if (!explicitTotal.present && (inputTokens !== null || outputTokens !== null)) {
    totalTokens = (inputTokens || 0) + (outputTokens || 0);
  }
  return {
    requests,
    totalTokens,
    inputTokens,
    outputTokens,
    cost: optionalNumber(firstOwnValue(stats, ['cost', 'actual_cost']).value),
    standardCost: optionalNumber(firstOwnValue(stats, ['standard_cost']).value),
    userCost: optionalNumber(firstOwnValue(stats, ['user_cost']).value),
  };
}

function normalizeTableUsageStats(value) {
  if (!isPlainObject(value)) return null;
  const historical = normalizeUsageStats(value.historical || value.history || value.historical_usage);
  const current = normalizeUsageStats(value.current || value.today || value.current_usage);
  if (!historical && !current) return null;
  return {
    historical,
    current,
    currentWindowStart: parseDateValue(value.current_window_start ?? value.currentWindowStart),
    currentWindowEnd: parseDateValue(value.current_window_end ?? value.currentWindowEnd),
  };
}

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Network logging must never change the adapter result.
  }
}

function safeRemoteText(value, limit = 1000) {
  let text = value;
  if (value && typeof value === 'object') {
    try { text = JSON.stringify(value); } catch { text = '[unavailable remote detail]'; }
  }
  return redactText(String(text === undefined || text === null ? '' : text))
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .slice(0, limit);
}

function safeModelId(value) {
  if (typeof value !== 'string') return '';
  const cleaned = value.trim();
  if (!cleaned
      || cleaned !== value
      || cleaned.length > 256
      || IDENTITY_CONTROL_OR_BIDI.test(cleaned)
      || !CANONICAL_MODEL_ID.test(cleaned)
      || looksLikeCredential(cleaned)) return '';
  return cleaned;
}

function testOptionError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function requestedTestModelId(options) {
  const aliases = ['modelId', 'model_id']
    .filter((key) => hasOwn(options, key) && options[key] !== undefined && options[key] !== null);
  if (aliases.length === 0) return '';
  const values = aliases.map((key) => options[key]);
  if (values.some((value) => typeof value !== 'string' || value.length > 256)) {
    throw testOptionError('SUB2API_TEST_MODEL_INVALID', 'Sub2API 账号测试模型无效');
  }
  const normalized = values.map((value) => (value ? safeModelId(value) : ''));
  if (values.some((value, index) => value && !normalized[index])
      || new Set(normalized).size !== 1) {
    throw testOptionError('SUB2API_TEST_MODEL_INVALID', 'Sub2API 账号测试模型无效');
  }
  return normalized[0];
}

function requestedTestPrompt(options) {
  if (!hasOwn(options, 'prompt') || options.prompt === undefined || options.prompt === null) return '';
  if (typeof options.prompt !== 'string' || options.prompt.length > 2000) {
    throw testOptionError('SUB2API_TEST_PROMPT_INVALID', 'Sub2API 账号测试提示词无效');
  }
  return options.prompt.trim();
}

function decodeResponseBytes(bytes, fatalUtf8) {
  if (!fatalUtf8) return Buffer.from(bytes).toString('utf8');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    const error = new Error('Sub2API response is not valid UTF-8');
    error.code = 'SUB2API_RESPONSE_UTF8_INVALID';
    throw error;
  }
}

async function readResponseTextWithLimit(response, limit = DEFAULT_RESPONSE_BODY_BYTES, options = {}) {
  const fatalUtf8 = options.fatalUtf8 === true;
  const signal = options.signal;
  const byteLimit = Number.isSafeInteger(limit) && limit > 0
    ? Math.min(limit, MAX_RESPONSE_BODY_BYTES)
    : DEFAULT_RESPONSE_BODY_BYTES;
  let reader;
  let releaseReader = () => {};
  let cancelReader = () => {};
  try {
    if (response?.body && typeof response.body.getReader === 'function') {
      reader = response.body.getReader();
      releaseReader = () => reader.releaseLock();
      cancelReader = () => reader.cancel();
    } else if (response?.body
        && typeof response.body[Symbol.asyncIterator] === 'function') {
      const iterator = response.body[Symbol.asyncIterator]();
      reader = { read: () => iterator.next() };
      cancelReader = () => {
        if (typeof iterator.return === 'function') return iterator.return();
        if (typeof response.body.destroy === 'function') response.body.destroy();
        return undefined;
      };
    }
  } catch {
    reader = null;
  }
  if (!reader || typeof reader.read !== 'function') {
    // response.text()/arrayBuffer() allocate the complete response before a
    // postflight size check. Fail closed when the fetch implementation cannot
    // expose a stream whose bytes can be counted as they arrive.
    const error = new Error('Sub2API response body is not a readable stream');
    error.code = 'SUB2API_RESPONSE_STREAM_UNAVAILABLE';
    throw error;
  }

  const readChunk = () => {
    if (!signal || typeof signal.addEventListener !== 'function') return reader.read();
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        try { signal.removeEventListener('abort', abort); } catch {}
      };
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        cleanup();
        callback(value);
      };
      const abort = () => {
        const error = new Error('Sub2API response body read aborted');
        error.name = 'AbortError';
        finish(reject, error);
      };
      try { signal.addEventListener('abort', abort, { once: true }); } catch {}
      if (signal.aborted) {
        abort();
        return;
      }
      Promise.resolve()
        .then(() => reader.read())
        .then(
          (value) => finish(resolve, value),
          (error) => finish(reject, error),
        );
    });
  };
  const chunks = [];
  let total = 0;
  let complete = false;
  try {
    while (true) {
      const result = await readChunk();
      if (!result || typeof result !== 'object') {
        const error = new Error('Sub2API response stream returned an invalid chunk');
        error.code = 'SUB2API_RESPONSE_STREAM_UNAVAILABLE';
        throw error;
      }
      const { done, value } = result;
      if (done === true) {
        complete = true;
        break;
      }
      let byteLength;
      if (value instanceof Uint8Array) {
        byteLength = value.byteLength;
      } else if (value instanceof ArrayBuffer) {
        byteLength = value.byteLength;
      } else {
        const error = new Error('Sub2API response stream returned an invalid chunk');
        error.code = 'SUB2API_RESPONSE_STREAM_UNAVAILABLE';
        throw error;
      }
      total += byteLength;
      if (total > byteLimit) {
        const error = new Error('Sub2API response body too large');
        error.code = 'SUB2API_RESPONSE_TOO_LARGE';
        throw error;
      }
      chunks.push(value instanceof Uint8Array
        ? Buffer.from(value)
        : Buffer.from(new Uint8Array(value)));
    }
  } finally {
    if (!complete) {
      try {
        const cancellation = cancelReader();
        if (cancellation && typeof cancellation.catch === 'function') cancellation.catch(() => {});
      } catch {}
    }
    try { releaseReader(); } catch {}
  }
  return decodeResponseBytes(Buffer.concat(chunks), fatalUtf8);
}

function cancelUnreadResponseBody(response) {
  try {
    if (response?.body && typeof response.body.cancel === 'function') {
      const cancellation = response.body.cancel();
      if (cancellation && typeof cancellation.catch === 'function') cancellation.catch(() => {});
    } else if (response?.body && typeof response.body.destroy === 'function') {
      response.body.destroy();
    }
  } catch {}
}

function parseAccountTestSse(text) {
  const events = [];
  let terminal = null;
  let invalidReason = null;
  let doneSeen = false;
  let frameLines = [];

  const invalidate = (reason) => {
    if (!invalidReason) invalidReason = reason;
  };
  const consumeFrame = () => {
    if (frameLines.length === 0 || invalidReason) {
      frameLines = [];
      return;
    }
    const dataLines = [];
    for (const line of frameLines) {
      if (line.startsWith(':')) continue;
      const colon = line.indexOf(':');
      const field = colon < 0 ? line : line.slice(0, colon);
      if (field !== 'data') continue;
      let value = colon < 0 ? '' : line.slice(colon + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      dataLines.push(value);
    }
    frameLines = [];
    if (dataLines.length === 0) return;
    const data = dataLines.join('\n');
    if (data.trim() === '[DONE]') {
      if (!terminal) invalidate('done_before_terminal');
      else doneSeen = true;
      return;
    }
    if (doneSeen) {
      invalidate('event_after_done');
      return;
    }
    if (!data.trim()) {
      invalidate('malformed_json');
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(data);
    } catch {
      invalidate('malformed_json');
      return;
    }
    if (!isPlainObject(parsed) || typeof parsed.type !== 'string' || !parsed.type) {
      invalidate('invalid_event_shape');
      return;
    }
    if (terminal) {
      invalidate(
        parsed.type === 'error' || parsed.type === 'test_complete'
          ? 'duplicate_terminal'
          : 'event_after_terminal',
      );
      return;
    }
    events.push(parsed);
    if (parsed.type === 'error') {
      terminal = { kind: 'failure', event: parsed };
      return;
    }
    if (parsed.type === 'test_complete') {
      if (typeof parsed.success !== 'boolean') {
        invalidate('invalid_terminal');
        return;
      }
      if (parsed.success === true
          && (Object.prototype.hasOwnProperty.call(parsed, 'error')
            || Object.prototype.hasOwnProperty.call(parsed, 'message'))) {
        invalidate('conflicting_terminal');
        return;
      }
      terminal = {
        kind: parsed.success ? 'success' : 'failure',
        event: parsed,
      };
    }
  };

  let source = String(text || '');
  if (source.charCodeAt(0) === 0xfeff) source = source.slice(1);
  for (const line of source.split(/\r\n|\r|\n/)) {
    if (line === '') consumeFrame();
    else frameLines.push(line);
  }
  // A fully-consumed HTTP body is an unambiguous EOF boundary. Accept the
  // final SSE frame even when the producer omitted the customary blank line.
  consumeFrame();
  return { events, terminal, invalidReason };
}

function parseSseEvents(text) {
  const parsed = parseAccountTestSse(text);
  if (parsed.invalidReason) {
    const error = new Error('Sub2API SSE response contract is invalid');
    error.code = 'SUB2API_SSE_INVALID';
    error.reason = parsed.invalidReason;
    throw error;
  }
  return parsed.events;
}

function responseContentType(response) {
  try {
    if (response?.headers && typeof response.headers.get === 'function') {
      return String(response.headers.get('content-type') || '');
    }
    if (response?.headers && typeof response.headers === 'object') {
      const entry = Object.entries(response.headers).find(
        ([name]) => String(name).toLowerCase() === 'content-type',
      );
      if (entry) return Array.isArray(entry[1]) ? entry[1].join(', ') : String(entry[1] || '');
    }
  } catch {}
  return '';
}

function isEventStreamResponse(response) {
  const contentType = responseContentType(response).split(';', 1)[0].trim().toLowerCase();
  return contentType === 'text/event-stream';
}

function isJsonResponse(response) {
  const contentType = responseContentType(response).split(';', 1)[0].trim().toLowerCase();
  return contentType === 'application/json'
    || /^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(contentType);
}

function isSuccessfulHttpResponse(response) {
  const status = Number(response?.status);
  return response?.ok === true
    && Number.isSafeInteger(status)
    && status >= 200
    && status <= 299;
}

function forwardAbortSignal(signal, controller, markExternalAbort = null) {
  if (!signal || typeof signal.addEventListener !== 'function') return () => {};
  const abort = () => {
    if (typeof markExternalAbort === 'function') markExternalAbort();
    controller.abort();
  };
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  return () => {
    try { signal.removeEventListener('abort', abort); } catch {}
  };
}

function interruptedRequestError(message) {
  const error = new Error(message);
  error.code = 'JOB_INTERRUPTED';
  return error;
}

function requestFailure(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function markWriteOutcomeUnknown(error, reason) {
  const target = error instanceof Error
    ? error
    : requestFailure('SUB2API_WRITE_OUTCOME_UNKNOWN', 'Sub2API 写入结果无法确认');
  target.writeOutcomeUnknown = true;
  target.requiresReconciliation = true;
  const normalizedReason = String(reason || '').trim().toLowerCase();
  target.writeOutcomeReason = /^[a-z0-9_]{1,64}$/.test(normalizedReason)
    ? normalizedReason
    : 'unknown';
  return target;
}

function markAccountTestReconciliation(error, reason, options = {}) {
  const target = error instanceof Error
    ? error
    : requestFailure('SUB2API_TEST_OUTCOME_UNKNOWN', 'Sub2API 账号测试结果无法确认');
  if (options.testOutcomeUnknown === true) target.testOutcomeUnknown = true;
  if (typeof options.testSuccess === 'boolean') {
    target.testSuccess = options.testSuccess;
    target.testSuccessKnown = true;
  }
  target.requiresReconciliation = true;
  target.reconciliationScope = 'test';
  const normalizedReason = String(reason || '').trim().toLowerCase();
  target.reconciliationReason = /^[a-z0-9_]{1,64}$/.test(normalizedReason)
    ? normalizedReason
    : 'unknown';
  return target;
}

function markAccountTestOutcomeUnknown(error, reason) {
  return markAccountTestReconciliation(error, reason, { testOutcomeUnknown: true });
}

function writeAwareFailure(error, requestOptions, requestDispatched, reason) {
  if (requestOptions.writeOperation === true && requestDispatched) {
    return markWriteOutcomeUnknown(error, reason);
  }
  return error;
}

function requiredIdempotencyKey(value) {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > 128
      || !/^[\x21-\x7e]+$/.test(value)) {
    const error = new Error('Sub2API 幂等键必须是 1-128 个可打印 ASCII 字符');
    error.code = 'SUB2API_IDEMPOTENCY_KEY_INVALID';
    throw error;
  }
  return value;
}

function configuredCredential(value) {
  let text;
  try {
    text = String(value ?? '');
  } catch {
    text = '';
  }
  if (!text) return '';
  // Sub2API API keys and compact JWTs are visible ASCII. Reject whitespace,
  // controls, obs-text, and Unicode before they reach Headers/fetch, whose
  // conversion errors are implementation-defined and may reflect input.
  if (text.length > 16 * 1024 || !/^[\x21-\x7e]+$/.test(text)) {
    const error = new Error('Sub2API 管理凭据格式无效');
    error.code = 'SUB2API_CREDENTIAL_INVALID';
    throw error;
  }
  return text;
}

function configuredBaseUrl(value) {
  let text;
  try {
    text = String(value ?? '');
  } catch {
    text = '';
  }
  if (!text) return '';
  // WHATWG URL parsing silently strips tabs/newlines and surrounding ASCII
  // whitespace. Reject that ambiguous deployment input before canonicalizing
  // it, and bound it before any error path can retain an oversized value.
  if (Buffer.byteLength(text, 'utf8') > MAX_ADMIN_BASE_URL_BYTES
      || URL_WHITESPACE_CONTROL_OR_BIDI.test(text)) {
    const error = new Error('Sub2API 管理 API 地址格式无效');
    error.code = 'SUB2API_BASE_URL_INVALID';
    throw error;
  }
  return text.replace(/\/$/, '');
}

function statsSchemaError(message = 'Sub2API 账号统计响应结构无效') {
  const error = new Error(message);
  error.code = 'SUB2API_STATS_SCHEMA_INVALID';
  return error;
}

function canonicalBatchAccountId(rawId, allowed) {
  if (!/^[1-9]\d*$/.test(rawId)) return null;
  const id = Number(rawId);
  return Number.isSafeInteger(id) && allowed.has(id) ? id : null;
}

class Sub2ApiAdminClient {
  constructor(options = {}) {
    this.baseUrl = configuredBaseUrl(
      options.baseUrl || process.env.SUB2API_BASE_URL || '',
    );
    this.apiKey = configuredCredential(
      options.apiKey || process.env.SUB2API_ADMIN_API_KEY || '',
    );
    this.jwt = configuredCredential(
      options.jwt || process.env.SUB2API_JWT || '',
    );
    this.timeoutMs = boundedTimeout(
      options.timeoutMs ?? process.env.SUB2API_TIMEOUT_MS,
      DEFAULT_REQUEST_TIMEOUT_MS,
      MAX_REQUEST_TIMEOUT_MS,
    );
    this.testTimeoutMs = boundedTimeout(
      options.testTimeoutMs ?? process.env.SUB2API_TEST_TIMEOUT_MS,
      Math.max(this.timeoutMs, DEFAULT_TEST_TIMEOUT_MS),
      MAX_TEST_TIMEOUT_MS,
    );
    const maxResponseBytes = Number(
      options.maxResponseBytes || process.env.SUB2API_MAX_RESPONSE_BYTES || DEFAULT_RESPONSE_BODY_BYTES,
    );
    this.maxResponseBytes = Number.isSafeInteger(maxResponseBytes) && maxResponseBytes >= 1024
      ? Math.min(maxResponseBytes, MAX_RESPONSE_BODY_BYTES)
      : DEFAULT_RESPONSE_BODY_BYTES;
    this.logger = options.logger || null;
    this.logContext = options.logContext && typeof options.logContext === 'object'
      ? options.logContext
      : {};
    if (!this.baseUrl) {
      throw new Error('SUB2API_BASE_URL is required');
    }
    try {
      const parsedBaseUrl = new URL(this.baseUrl);
      if (!['http:', 'https:'].includes(parsedBaseUrl.protocol)) throw new Error('unsupported protocol');
      if (!parsedBaseUrl.hostname) throw new Error('hostname is required');
      if (parsedBaseUrl.username || parsedBaseUrl.password) throw new Error('embedded credentials are not allowed');
      if (parsedBaseUrl.search || parsedBaseUrl.hash) throw new Error('query and fragment are not allowed');
      const allowInsecureHttp = options.allowInsecureHttp === true
        || process.env.SUB2API_ALLOW_INSECURE_HTTP === '1';
      if (parsedBaseUrl.protocol === 'http:'
          && !isLoopbackHostname(parsedBaseUrl.hostname)
          && !allowInsecureHttp) {
        const error = new Error('non-loopback HTTP is not allowed');
        error.code = 'SUB2API_INSECURE_HTTP';
        throw error;
      }
      this.baseUrl = parsedBaseUrl.toString().replace(/\/$/, '');
      this.baseOrigin = parsedBaseUrl.origin;
    } catch (error) {
      if (error?.code === 'SUB2API_INSECURE_HTTP') throw error;
      throw new Error('SUB2API_BASE_URL 必须是无查询参数、片段或内嵌凭据的 http(s) 地址');
    }
    if (!this.apiKey && !this.jwt) {
      throw new Error('SUB2API_ADMIN_API_KEY or SUB2API_JWT is required');
    }
  }

  async request(method, pathname, body, requestOptions = {}) {
    const target = validatedAdminRequestTarget(
      this.baseUrl,
      this.baseOrigin,
      method,
      pathname,
    );
    method = target.method;
    pathname = target.pathname;
    const startedAt = Date.now();
    writeLog(this.logger, 'info', 'sub2api.request_started', { ...this.logContext, method, path: pathname });
    const headers = { Accept: 'application/json' };
    if (this.apiKey) headers['x-api-key'] = this.apiKey;
    else headers.Authorization = 'Bearer ' + this.jwt;
    if (requestOptions.idempotencyKey !== undefined) {
      // This is the only caller-controlled header supported by the generic
      // admin request path. Do not accept a headers object here: doing so
      // would allow credentials or hop-by-hop headers to cross this boundary.
      headers['Idempotency-Key'] = requiredIdempotencyKey(requestOptions.idempotencyKey);
    }
    const controller = new AbortController();
    const externalSignal = requestOptions.signal;
    let abortSource = null;
    const stopForwardingAbort = forwardAbortSignal(externalSignal, controller, () => {
      if (!abortSource) abortSource = 'external';
    });
    const timer = setTimeout(() => {
      if (!abortSource) abortSource = 'timeout';
      controller.abort();
    }, this.timeoutMs);
    const fetchOptions = {
      method,
      headers,
      signal: controller.signal,
    };
    let response;
    let text;
    let requestDispatched = false;
    try {
      if (body !== undefined) {
        headers['content-type'] = 'application/json';
        try {
          fetchOptions.body = JSON.stringify(body);
        } catch {
          throw requestFailure(
            'SUB2API_REQUEST_SERIALIZATION_FAILED',
            'Sub2API 请求数据无法序列化：' + method + ' ' + pathname,
          );
        }
      }
      if (externalSignal?.aborted) {
        throw interruptedRequestError('Sub2API 管理请求在发送前因面板停机中断');
      }
      requestDispatched = true;
      response = await fetch(target.url, {
        ...fetchOptions,
        // Admin calls must never silently follow a redirect to another host.
        redirect: 'error',
      });
      if (!isJsonResponse(response)) {
        cancelUnreadResponseBody(response);
        throw requestFailure(
          'SUB2API_RESPONSE_CONTENT_TYPE_INVALID',
          'Sub2API 返回的响应类型不是 JSON：' + method + ' ' + pathname,
        );
      }
      // Keep the timeout active while consuming the response body too. A
      // server can accept the request and then stall before sending JSON.
      text = await readResponseTextWithLimit(
        response,
        requestOptions.maxResponseBytes || this.maxResponseBytes,
        { fatalUtf8: true, signal: controller.signal },
      );
    } catch (error) {
      let failure;
      let reason = 'transport';
      if (abortSource === 'external') {
        failure = interruptedRequestError('Sub2API 管理请求因面板停机中断');
        reason = 'external_abort';
      } else if (abortSource === 'timeout') {
        failure = requestFailure(
          'SUB2API_TIMEOUT',
          'Sub2API request timed out: ' + method + ' ' + pathname,
        );
        reason = 'timeout';
      } else if (error?.code === 'SUB2API_RESPONSE_TOO_LARGE') {
        failure = error;
        reason = 'response_too_large';
      } else if (error?.code === 'SUB2API_RESPONSE_UTF8_INVALID') {
        failure = error;
        reason = 'invalid_utf8';
      } else if (error?.code === 'SUB2API_RESPONSE_STREAM_UNAVAILABLE') {
        failure = error;
        reason = 'response_stream_unavailable';
      } else if (error?.code === 'SUB2API_RESPONSE_CONTENT_TYPE_INVALID') {
        failure = error;
        reason = 'invalid_content_type';
      } else if (error?.code === 'SUB2API_REQUEST_SERIALIZATION_FAILED') {
        failure = error;
        reason = 'request_validation';
      } else {
        failure = requestFailure(
          'SUB2API_TRANSPORT_ERROR',
          'Sub2API 管理请求传输失败：' + method + ' ' + pathname,
        );
      }
      failure = writeAwareFailure(failure, requestOptions, requestDispatched, reason);
      writeLog(this.logger, 'error', 'sub2api.request_failed', {
        ...this.logContext,
        method,
        path: pathname,
        durationMs: Date.now() - startedAt,
        error: safeRemoteText(failure.message),
        writeOutcomeUnknown: failure.writeOutcomeUnknown === true,
      });
      throw failure;
    } finally {
      clearTimeout(timer);
      stopForwardingAbort();
    }
    if (!text || !text.trim()) {
      const error = writeAwareFailure(
        requestFailure('SUB2API_EMPTY_RESPONSE', 'Sub2API 返回空响应：' + method + ' ' + pathname),
        requestOptions,
        requestDispatched,
        'empty_response',
      );
      writeLog(this.logger, 'warn', 'sub2api.response_invalid', {
        ...this.logContext,
        method,
        path: pathname,
        statusCode: response.status,
        error: error.message,
      });
      throw error;
    }
    let payload;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      const error = writeAwareFailure(
        requestFailure('SUB2API_INVALID_JSON', 'Sub2API 返回非法 JSON：' + method + ' ' + pathname),
        requestOptions,
        requestDispatched,
        'invalid_json',
      );
      writeLog(this.logger, 'warn', 'sub2api.response_invalid', {
        ...this.logContext,
        method,
        path: pathname,
        statusCode: response.status,
        error: error.message,
      });
      throw error;
    }
    const payloadFailure = payload && (
      payload.success === false
      || payload.ok === false
      || payload.data?.success === false
      || payload.data?.ok === false
    );
    const payloadCode = payload?.code ?? payload?.data?.code;
    if (!response.ok || payloadFailure
        || (payloadCode !== undefined && payloadCode !== 0 && payloadCode !== '0')) {
      const upstreamDetailPresent = Boolean(
        payload?.message !== undefined
        || payload?.data?.message !== undefined
        || payloadCode !== undefined,
      );
      const upstreamStatus = Number.isSafeInteger(response.status) ? response.status : null;
      const error = writeAwareFailure(
        requestFailure(
          'SUB2API_REQUEST_REJECTED',
          'Sub2API ' + method + ' ' + pathname + ' 请求被上游拒绝'
            + (upstreamStatus === null ? '' : '（HTTP ' + upstreamStatus + '）'),
        ),
        requestOptions,
        requestDispatched,
        'response_rejected',
      );
      error.upstreamStatus = upstreamStatus;
      error.upstreamDetailPresent = upstreamDetailPresent;
      writeLog(this.logger, 'warn', 'sub2api.request_rejected', {
        ...this.logContext,
        method,
        path: pathname,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: error.message,
        upstreamDetailPresent,
        writeOutcomeUnknown: error.writeOutcomeUnknown === true,
      });
      throw error;
    }
    if (payload === null || payload === undefined
        || (typeof payload !== 'object' && !Array.isArray(payload))) {
      throw writeAwareFailure(
        requestFailure('SUB2API_SCHEMA_INVALID', 'Sub2API 返回数据结构无效：' + method + ' ' + pathname),
        requestOptions,
        requestDispatched,
        'response_schema',
      );
    }
    writeLog(this.logger, 'info', 'sub2api.request_completed', {
      ...this.logContext,
      method,
      path: pathname,
      statusCode: response.status,
      durationMs: Date.now() - startedAt,
    });
    return unwrapData(payload);
  }

  async listAccounts(options = {}) {
    const pageSize = options.pageSize === undefined ? 200 : options.pageSize;
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 1000) {
      const error = new Error('Sub2API 账号列表分页大小必须是 1-1000 的安全整数');
      error.code = 'SUB2API_ACCOUNTS_PAGE_SIZE_INVALID';
      throw error;
    }
    const requirePaginationMetadata = options.requirePaginationMetadata === true;
    const requireTotal = options.requireTotal === true || requirePaginationMetadata;
    const rows = new Map();
    let expectedTotal = null;
    let page = 1;
    while (page <= 100) {
      const query = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
        sort_by: String(options.sortBy || 'name'),
        sort_order: String(options.sortOrder || 'asc'),
        lite: '1',
      });
      if (options.platform) query.set('platform', options.platform);
      if (options.type) query.set('type', options.type);
      if (options.status) query.set('status', options.status);
      if (options.search) query.set('search', options.search);
      const value = await this.request(
        'GET',
        '/api/v1/admin/accounts?' + query.toString(),
        undefined,
        { signal: options.signal },
      );
      const listResult = accountListRows(value, requirePaginationMetadata);
      const pageRows = listResult.rows;
      if (listResult.invalid || !pageRows) {
        const error = new Error('Sub2API 账号列表响应结构无效');
        error.code = 'SUB2API_ACCOUNTS_SCHEMA_INVALID';
        throw error;
      }
      const pagination = accountPagination(value);
      const paginationFields = [
        pagination.total,
        pagination.page,
        pagination.pageSize,
        pagination.pages,
      ];
      if (paginationFields.some((field) => field.invalid || field.conflict)) {
        const error = new Error('Sub2API 账号列表分页统计无效或存在冲突');
        error.code = 'SUB2API_ACCOUNTS_PAGINATION_INVALID';
        throw error;
      }
      if (!pagination.total.provided && requireTotal) {
        const error = new Error('Sub2API 账号列表分页缺少完整统计');
        error.code = 'SUB2API_ACCOUNTS_TOTAL_REQUIRED';
        throw error;
      }
      const hasAnyPageMetadata = [pagination.page, pagination.pageSize, pagination.pages]
        .some((field) => field.provided);
      const hasCompletePageMetadata = [pagination.page, pagination.pageSize, pagination.pages]
        .every((field) => field.provided);
      const hasCanonicalPaginationMetadata = isPlainObject(value)
        && hasOwn(value, 'total')
        && hasOwn(value, 'page')
        && hasOwn(value, 'page_size')
        && hasOwn(value, 'pages');
      const hasNonCanonicalPaginationAliases = isPlainObject(value)
        && (hasOwn(value, 'pagination')
          || hasOwn(value, 'pageSize')
          || hasOwn(value, 'total_pages')
          || hasOwn(value, 'totalPages'));
      if ((requirePaginationMetadata && !hasCanonicalPaginationMetadata)
          || (hasAnyPageMetadata && !hasCompletePageMetadata)) {
        const error = new Error('Sub2API 账号列表分页缺少规范元数据');
        error.code = 'SUB2API_ACCOUNTS_PAGINATION_REQUIRED';
        throw error;
      }
      if (requirePaginationMetadata && hasNonCanonicalPaginationAliases) {
        const error = new Error('Sub2API 账号列表包含非规范分页别名');
        error.code = 'SUB2API_ACCOUNTS_PAGINATION_INVALID';
        throw error;
      }
      if (hasCompletePageMetadata) {
        const total = pagination.total.value;
        const expectedPages = total === null
          ? null
          : Math.max(1, Math.ceil(total / pagination.pageSize.value));
        const expectedPageRows = total === null
          ? null
          : Math.min(
              pagination.pageSize.value,
              Math.max(total - ((pagination.page.value - 1) * pagination.pageSize.value), 0),
            );
        if (total === null
            || pagination.page.value !== page
            || pagination.pageSize.value !== pageSize
            || pagination.pages.value !== expectedPages
            || pagination.page.value > pagination.pages.value
            || (requirePaginationMetadata && pageRows.length !== expectedPageRows)) {
          const error = new Error('Sub2API 账号列表分页元数据与请求或内容不一致');
          error.code = 'SUB2API_ACCOUNTS_PAGINATION_INVALID';
          throw error;
        }
        if (pagination.pages.value > 100) {
          const error = new Error('Sub2API 账号列表超过分页安全上限');
          error.code = 'SUB2API_PAGE_LIMIT';
          throw error;
        }
      }
      const normalizedRows = pageRows.map(safeAccount);
      if (normalizedRows.some((account) => !account)) {
        const error = new Error('Sub2API 账号列表包含无效账号标识');
        error.code = 'SUB2API_ACCOUNTS_SCHEMA_INVALID';
        throw error;
      }
      for (const account of normalizedRows) {
        const accountKey = String(account.id);
        if (rows.has(accountKey)) {
          const error = new Error('Sub2API 账号列表包含重复账号标识');
          error.code = 'SUB2API_ACCOUNT_ID_DUPLICATE';
          throw error;
        }
        rows.set(accountKey, account);
      }
      if (pagination.total.provided) {
        const total = pagination.total.value;
        if (expectedTotal !== null && expectedTotal !== total) {
          const error = new Error('Sub2API 账号列表分页统计无效或已变化');
          error.code = 'SUB2API_ACCOUNTS_PAGINATION_INVALID';
          throw error;
        }
        expectedTotal = total;
      }
      if (expectedTotal !== null) {
        if (rows.size > expectedTotal || (pageRows.length === 0 && rows.size < expectedTotal)) {
          const error = new Error('Sub2API 账号列表分页未完整返回');
          error.code = 'SUB2API_ACCOUNTS_PAGINATION_INVALID';
          throw error;
        }
        if (rows.size === expectedTotal) break;
      } else if (pageRows.length === 0) {
        break;
      }
      page += 1;
    }
    if (page > 100) {
      const error = new Error('Sub2API 账号列表超过分页安全上限');
      error.code = 'SUB2API_PAGE_LIMIT';
      throw error;
    }
    return [...rows.values()];
  }

  async listGroups(options = {}) {
    const value = await this.request(
      'GET',
      '/api/v1/admin/groups/all',
      undefined,
      { signal: options.signal },
    );
    const rows = groupListRows(value);
    if (!rows) {
      const error = new Error('Sub2API 分组列表响应结构无效');
      error.code = 'SUB2API_GROUPS_SCHEMA_INVALID';
      throw error;
    }
    return rows;
  }

  async getAccount(id, options = {}) {
    const accountId = requestedAccountId(
      id,
      'SUB2API_ACCOUNT_ID_INVALID',
      'Sub2API 账号详情缺少有效账号 ID',
    );
    const value = await this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(accountId)),
      undefined,
      { signal: options.signal },
    );
    const account = safeAccount(value);
    if (!account) {
      const error = new Error('Sub2API 账号详情响应结构无效');
      error.code = 'SUB2API_ACCOUNT_SCHEMA_INVALID';
      throw error;
    }
    if (account.id !== accountId) {
      const error = new Error('Sub2API 账号详情响应与请求 ID 不一致');
      error.code = 'SUB2API_ACCOUNT_RESPONSE_MISMATCH';
      throw error;
    }
    return account;
  }

  async getAvailableModels(id) {
    const accountId = requestedAccountId(
      id,
      'SUB2API_MODELS_ID_INVALID',
      'Sub2API 模型列表缺少有效账号 ID',
    );
    const value = await this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(accountId)) + '/models',
    );
    const rows = modelListRows(value);
    if (!rows) {
      const error = new Error('Sub2API 模型列表响应结构无效');
      error.code = 'SUB2API_MODELS_SCHEMA_INVALID';
      throw error;
    }
    return [...new Set(rows.slice(0, 2000).map(modelRowId).filter(Boolean))].slice(0, 1000);
  }

  async testAccount(id, options = {}) {
    const accountId = requestedAccountId(
      id,
      'SUB2API_TEST_ID_INVALID',
      'Sub2API 账号测试缺少有效账号 ID',
    );
    const startedAt = Date.now();
    const pathname = '/api/v1/admin/accounts/' + encodeURIComponent(String(accountId)) + '/test';
    const modelId = requestedTestModelId(options);
    const prompt = requestedTestPrompt(options);
    const body = {};
    if (modelId) body.model_id = modelId;
    if (prompt) body.prompt = prompt;
    writeLog(this.logger, 'info', 'sub2api.account_test_started', {
      ...this.logContext,
      accountId,
      model: modelId || null,
    });
    const headers = {
      Accept: 'text/event-stream',
      'content-type': 'application/json',
    };
    if (this.apiKey) headers['x-api-key'] = this.apiKey;
    else headers.Authorization = 'Bearer ' + this.jwt;
    const controller = new AbortController();
    const externalSignal = options.signal;
    let abortSource = null;
    const stopForwardingAbort = forwardAbortSignal(externalSignal, controller, () => {
      if (!abortSource) abortSource = 'external';
    });
    const callTimeoutMs = boundedTimeout(
      options.timeoutMs,
      this.testTimeoutMs,
      this.testTimeoutMs,
    );
    const timer = setTimeout(() => {
      if (!abortSource) abortSource = 'timeout';
      controller.abort();
    }, callTimeoutMs);
    let response;
    let text = '';
    let requestDispatched = false;
    try {
      if (externalSignal?.aborted) {
        throw interruptedRequestError('Sub2API 账号测试在发送前因面板停机中断');
      }
      requestDispatched = true;
      response = await fetch(this.baseUrl + pathname, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
        // Account-test calls carry an admin credential and must not leak it
        // through a cross-host redirect.
        redirect: 'error',
      });
      if (!isSuccessfulHttpResponse(response)) {
        cancelUnreadResponseBody(response);
        throw markAccountTestOutcomeUnknown(
          requestFailure(
            'SUB2API_TEST_REQUEST_REJECTED',
            'Sub2API 账号测试请求被上游拒绝（HTTP ' + response?.status + '）',
          ),
          'response_rejected',
        );
      }
      if (!isEventStreamResponse(response)) {
        cancelUnreadResponseBody(response);
        throw markAccountTestOutcomeUnknown(
          requestFailure('SUB2API_TEST_RESPONSE_INVALID', 'Sub2API 账号测试响应类型无效'),
          'invalid_content_type',
        );
      }
      text = await readResponseTextWithLimit(
        response,
        this.maxResponseBytes,
        { fatalUtf8: true, signal: controller.signal },
      );
    } catch (error) {
      let failure;
      let reason = 'transport';
      if (abortSource === 'external') {
        failure = interruptedRequestError('Sub2API 账号测试因面板停机中断');
        reason = 'external_abort';
        writeLog(this.logger, 'warn', 'sub2api.account_test_interrupted', {
          ...this.logContext,
          accountId,
          model: modelId || null,
          durationMs: Date.now() - startedAt,
        });
      } else if (abortSource === 'timeout') {
        failure = requestFailure('SUB2API_TEST_TIMEOUT', 'Sub2API 账号测试超时');
        reason = 'timeout';
      } else if (error?.code === 'SUB2API_RESPONSE_TOO_LARGE') {
        failure = requestFailure('SUB2API_TEST_RESPONSE_TOO_LARGE', 'Sub2API 账号测试响应过大');
        reason = 'response_too_large';
      } else if (error?.code === 'SUB2API_RESPONSE_UTF8_INVALID') {
        failure = requestFailure('SUB2API_TEST_RESPONSE_INVALID', 'Sub2API 账号测试响应编码无效');
        reason = 'invalid_utf8';
      } else if (error?.code === 'SUB2API_RESPONSE_STREAM_UNAVAILABLE') {
        failure = requestFailure('SUB2API_TEST_RESPONSE_INVALID', 'Sub2API 账号测试响应无法安全读取');
        reason = 'response_stream_unavailable';
      } else if (error?.code === 'JOB_INTERRUPTED') {
        failure = error;
        reason = 'external_abort';
      } else if (error?.code === 'SUB2API_TEST_REQUEST_REJECTED'
          || error?.code === 'SUB2API_TEST_RESPONSE_INVALID') {
        failure = error;
        reason = error.reconciliationReason || 'invalid_response';
      } else {
        failure = requestFailure('SUB2API_TEST_TRANSPORT_ERROR', 'Sub2API 账号测试请求失败');
      }
      if (requestDispatched) failure = markAccountTestOutcomeUnknown(failure, reason);
      const rejected = failure.code === 'SUB2API_TEST_REQUEST_REJECTED';
      writeLog(this.logger, rejected ? 'warn' : 'error', rejected
        ? 'sub2api.account_test_rejected'
        : 'sub2api.account_test_failed', {
        ...this.logContext,
        accountId,
        model: modelId || null,
        statusCode: Number.isSafeInteger(response?.status) ? response.status : null,
        durationMs: Date.now() - startedAt,
        error: safeRemoteText(failure.message),
        testOutcomeUnknown: failure.testOutcomeUnknown === true,
      });
      throw failure;
    } finally {
      clearTimeout(timer);
      stopForwardingAbort();
    }

    if (!text.trim()) {
      throw markAccountTestOutcomeUnknown(
        requestFailure('SUB2API_TEST_RESPONSE_INVALID', 'Sub2API 账号测试返回空响应'),
        'empty_response',
      );
    }
    const parsedSse = parseAccountTestSse(text);
    if (parsedSse.invalidReason || !parsedSse.terminal) {
      throw markAccountTestOutcomeUnknown(
        requestFailure('SUB2API_TEST_RESPONSE_INVALID', 'Sub2API 账号测试响应契约无效'),
        parsedSse.invalidReason || 'missing_terminal',
      );
    }
    const completed = parsedSse.terminal.event;
    const eventModel = safeModelId(completed?.model);
    // The request model is local trusted context. A response model is useful
    // only for mismatch detection; never reflect arbitrary upstream text in a
    // result or log record.
    const completedModel = modelId || null;
    if (parsedSse.terminal.kind === 'success' && hasOwn(completed, 'model') && !eventModel) {
      const detail = 'Sub2API 返回的测试模型字段无效';
      writeLog(this.logger, 'warn', 'sub2api.account_test_model_invalid', {
        ...this.logContext,
        accountId,
        model: modelId || null,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: detail,
      });
      const error = new Error(detail);
      error.code = 'SUB2API_TEST_RESPONSE_INVALID';
      throw markAccountTestReconciliation(error, 'invalid_model', { testSuccess: true });
    }
    if (parsedSse.terminal.kind === 'success' && modelId && eventModel && eventModel !== modelId) {
      const detail = 'Sub2API 返回的测试模型与请求不一致';
      writeLog(this.logger, 'warn', 'sub2api.account_test_model_mismatch', {
        ...this.logContext,
        accountId,
        model: modelId,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: detail,
      });
      const error = new Error(detail);
      error.code = 'SUB2API_TEST_MODEL_MISMATCH';
      throw markAccountTestReconciliation(error, 'model_mismatch', { testSuccess: true });
    }
    if (parsedSse.terminal.kind === 'failure') {
      const detail = 'Sub2API 返回失败测试结果';
      writeLog(this.logger, 'warn', 'sub2api.account_test_unsuccessful', {
        ...this.logContext,
        accountId,
        model: completedModel,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: detail,
      });
      return {
        success: false,
        model: completedModel,
        message: detail,
        durationMs: Date.now() - startedAt,
      };
    }
    writeLog(this.logger, 'info', 'sub2api.account_test_succeeded', {
      ...this.logContext,
      accountId,
      model: completedModel,
      statusCode: response.status,
      durationMs: Date.now() - startedAt,
    });
    return {
      success: true,
      model: completedModel,
      message: '测试请求成功',
      durationMs: Date.now() - startedAt,
    };
  }

  async setSchedulable(id, schedulable = true, options = {}) {
    const accountId = requestedAccountId(
      id,
      'SUB2API_SCHEDULABLE_ID_INVALID',
      'Sub2API 调度设置缺少有效账号 ID',
    );
    if (typeof schedulable !== 'boolean') {
      const error = new Error('Sub2API 调度设置必须是布尔值');
      error.code = 'SUB2API_SCHEDULABLE_VALUE_INVALID';
      throw error;
    }
    const expectedSchedulable = schedulable;
    const value = await this.request(
      'POST',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(accountId)) + '/schedulable',
      { schedulable: expectedSchedulable },
      { signal: options.signal, writeOperation: true },
    );
    const account = safeAccount(value);
    if (!account) {
      const error = new Error('Sub2API 调度设置响应结构无效');
      error.code = 'SUB2API_SCHEDULABLE_SCHEMA_INVALID';
      throw markWriteOutcomeUnknown(error, 'response_schema');
    }
    if (account.id !== accountId
        || account.schedulableKnown !== true
        || account.schedulable !== expectedSchedulable) {
      const error = new Error('Sub2API 调度设置响应与请求不一致');
      error.code = 'SUB2API_SCHEDULABLE_RESPONSE_MISMATCH';
      throw markWriteOutcomeUnknown(error, 'response_mismatch');
    }
    return account;
  }

  async getAccountStats(id, days = 30) {
    const accountId = requestedAccountId(
      id,
      'SUB2API_STATS_ID_INVALID',
      'Sub2API 账号统计缺少有效账号 ID',
    );
    if (!Number.isSafeInteger(days) || days < 1 || days > 90) {
      const error = new Error('Sub2API 账号统计天数必须是 1-90 的整数');
      error.code = 'SUB2API_STATS_DAYS_INVALID';
      throw error;
    }
    const value = await this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(accountId)) + '/stats?days=' + encodeURIComponent(String(days)),
    );
    return value;
  }

  async getAccountTodayStats(id) {
    const accountId = requestedAccountId(
      id,
      'SUB2API_STATS_ID_INVALID',
      'Sub2API 账号统计缺少有效账号 ID',
    );
    return this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(accountId)) + '/today-stats',
    );
  }

  async getBatchTodayStats(ids) {
    const requestedIds = normalizedAccountIds(ids);
    const value = await this.request('POST', '/api/v1/admin/accounts/today-stats/batch', {
      account_ids: requestedIds,
    });
    if (!isPlainObject(value) || !hasOwn(value, 'stats') || !isPlainObject(value.stats)) {
      throw statsSchemaError('Sub2API 当期统计响应结构无效');
    }
    const allowed = new Set(requestedIds);
    const normalized = Object.create(null);
    for (const [rawId, item] of Object.entries(value.stats)) {
      const id = canonicalBatchAccountId(rawId, allowed);
      const stats = normalizeUsageStats(item);
      if (!id || !stats) throw statsSchemaError('Sub2API 当期统计响应结构无效');
      normalized[String(id)] = stats;
    }
    if (Object.keys(normalized).length !== requestedIds.length) {
      throw statsSchemaError('Sub2API 当期统计响应不完整');
    }
    return normalized;
  }

  async getBatchTableUsageStats(ids, options = {}) {
    const requestedIds = normalizedAccountIds(ids);
    const value = await this.request(
      'POST',
      '/api/v1/admin/accounts/table-usage-stats/batch',
      { account_ids: requestedIds },
      { signal: options.signal },
    );
    if (!isPlainObject(value)
        || !hasOwn(value, 'stats')
        || !isPlainObject(value.stats)
        || !hasOwn(value, 'errors')
        || !isPlainObject(value.errors)) {
      throw statsSchemaError();
    }
    const allowed = new Set(requestedIds);
    const normalized = Object.create(null);
    for (const [rawId, item] of Object.entries(value.stats)) {
      const id = canonicalBatchAccountId(rawId, allowed);
      const stats = normalizeTableUsageStats(item);
      if (!id || !stats) throw statsSchemaError();
      normalized[String(id)] = stats;
    }
    const errors = Object.create(null);
    for (const [rawId, remoteError] of Object.entries(value.errors)) {
      const id = canonicalBatchAccountId(rawId, allowed);
      if (!id
          || hasOwn(normalized, String(id))
          || typeof remoteError !== 'string'
          || !remoteError.trim()) {
        throw statsSchemaError();
      }
      // Batch errors are arbitrary upstream strings. A fixed marker keeps the
      // per-account failure signal without persisting or returning its body.
      errors[String(id)] = 'Sub2API 账号统计读取失败（详情已隐藏）';
    }
    if (Object.keys(normalized).length + Object.keys(errors).length !== requestedIds.length) {
      throw statsSchemaError('Sub2API 账号统计响应不完整');
    }
    return {
      stats: normalized,
      errors,
    };
  }

  async exportAccounts(ids = [], options = {}) {
    const query = ids.length > 0 ? '?ids=' + encodeURIComponent(ids.join(',')) : '';
    const value = await this.request(
      'GET',
      '/api/v1/admin/accounts/data' + query,
      undefined,
      { signal: options.signal },
    );
    if (!isValidExportPayload(value)) {
      const error = new Error('Sub2API 导出响应结构无效');
      error.code = 'SUB2API_EXPORT_SCHEMA_INVALID';
      throw error;
    }
    return value;
  }

  async importCodexSession(payload, options = {}) {
    const idempotencyKey = requiredIdempotencyKey(options?.idempotencyKey);
    const value = await this.request(
      'POST',
      '/api/v1/admin/accounts/import/codex-session',
      payload,
      { idempotencyKey, signal: options.signal, writeOperation: true },
    );
    const resultStatus = codexImportResultStatus(value);
    if (resultStatus === 'invalid') {
      const error = new Error('Sub2API 导入响应结构无效');
      error.code = 'SUB2API_IMPORT_SCHEMA_INVALID';
      throw markWriteOutcomeUnknown(error, 'response_schema');
    }
    if (resultStatus === 'unsuccessful') {
      const error = new Error('Sub2API 导入返回失败结果，账号状态需要重新核验');
      error.code = 'SUB2API_IMPORT_UNSUCCESSFUL';
      throw markWriteOutcomeUnknown(error, 'response_unsuccessful');
    }
    return value;
  }

  async applyOAuthCredentials(id, payload, options = {}) {
    const accountId = requestedAccountId(
      id,
      'SUB2API_CREDENTIALS_ID_INVALID',
      'Sub2API 凭证更新缺少有效账号 ID',
    );
    const value = await this.request(
      'POST',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(accountId)) + '/apply-oauth-credentials',
      payload,
      { signal: options.signal, writeOperation: true },
    );
    const account = safeAccount(value);
    if (!account) {
      const error = new Error('Sub2API 凭证更新响应结构无效');
      error.code = 'SUB2API_CREDENTIALS_SCHEMA_INVALID';
      throw markWriteOutcomeUnknown(error, 'response_schema');
    }
    if (account.id !== accountId) {
      const error = new Error('Sub2API 凭证更新响应与请求 ID 不一致');
      error.code = 'SUB2API_CREDENTIALS_RESPONSE_MISMATCH';
      throw markWriteOutcomeUnknown(error, 'response_mismatch');
    }
    return account;
  }
}

module.exports = {
  Sub2ApiAdminClient,
  normalizeUsageStats,
  normalizeTableUsageStats,
  parseSseEvents,
  safeAccount,
  safeModelId,
};
