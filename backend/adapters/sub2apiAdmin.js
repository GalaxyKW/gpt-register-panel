const {
  normalizeEmail,
  tokenFingerprint,
  parseDateValue,
  asString,
  normalizeIdentityValue,
} = require('../lib/token');
const { redactText } = require('../logger');

const DEFAULT_REQUEST_TIMEOUT_MS = 15000;
const MAX_REQUEST_TIMEOUT_MS = 120000;
const DEFAULT_TEST_TIMEOUT_MS = 120000;
const MAX_TEST_TIMEOUT_MS = 600000;
const SUB2API_EXPORT_TYPES = new Set(['', 'sub2api-data', 'sub2api-bundle']);
const SUB2API_EXPORT_VERSIONS = new Set([0, 1]);

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

function asList(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return null;
  for (const key of ['items', 'records', 'list', 'accounts']) {
    if (Array.isArray(value[key])) return value[key];
  }
  return null;
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

function scalarAliases(values, maximumLength, options = {}) {
  const present = values.filter((value) => value !== undefined && value !== null && value !== '');
  const normalized = [];
  let invalid = false;
  for (const raw of present) {
    const text = scalarText(raw, maximumLength, options.allowNumber === true);
    if (!text) {
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
  const value = String(hostname || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (value === 'localhost' || value === '::1') return true;
  const ipv4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(value);
  return Boolean(ipv4
    && ipv4.slice(1).every((part) => Number(part) >= 0 && Number(part) <= 255)
    && Number(ipv4[1]) === 127);
}

function normalizedAccountIds(ids) {
  if (!Array.isArray(ids)) return [];
  return [...new Set(ids.map((value) => Number(value)).filter(
    (value) => Number.isSafeInteger(value) && value > 0,
  ))];
}

function storedFingerprint(value) {
  const text = asString(value).toLowerCase();
  return /^[a-f0-9]{16,64}$/.test(text) ? text.slice(0, 16) : null;
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
  const accountField = scalarAliases([
    credentials.chatgpt_account_id,
    credentials.account_id,
    account.chatgpt_account_id,
    account.account_id,
    account.accountId,
  ], 512, {
    allowNumber: true,
    normalize: (value) => normalizeIdentityValue('account:', value),
  });
  const userField = scalarAliases([
    credentials.chatgpt_user_id,
    credentials.user_id,
    account.chatgpt_user_id,
    account.user_id,
    account.userId,
  ], 512, {
    allowNumber: true,
    normalize: (value) => normalizeIdentityValue('user:', value),
  });
  const accessField = scalarAliases(
    [credentials.access_token, credentials.accessToken],
    2 * 1024 * 1024,
  );
  const refreshField = scalarAliases(
    [credentials.refresh_token, credentials.refreshToken],
    256 * 1024,
  );
  const idTokenField = scalarAliases(
    [credentials.id_token, credentials.idToken],
    2 * 1024 * 1024,
  );
  const storedFingerprintField = scalarAliases([
    extra.access_token_sha256,
    credentials.access_token_sha256,
  ], 128, { normalize: storedFingerprint });
  const storedRefreshFingerprintField = scalarAliases([
    extra.refresh_token_sha256,
    credentials.refresh_token_sha256,
  ], 128, { normalize: storedFingerprint });
  const computedAccessFingerprint = tokenFingerprint(accessField.value);
  const computedRefreshFingerprint = tokenFingerprint(refreshField.value);
  const accessFingerprintConflict = Boolean(
    storedFingerprintField.value
      && computedAccessFingerprint
      && storedFingerprintField.value !== computedAccessFingerprint,
  );
  const refreshFingerprintConflict = Boolean(
    storedRefreshFingerprintField.value
      && computedRefreshFingerprint
      && storedRefreshFingerprintField.value !== computedRefreshFingerprint,
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
  const fingerprintConflict = accessFingerprintConflict || refreshFingerprintConflict;
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
  const schemaValid = scalarSchemaValid
    && !autoPauseInvalid
    && dateFields.every((field) => field.status !== 'invalid');
  const rawGroupIds = account.group_ids ?? account.groupIds ?? account.groups;
  const groupIds = Array.isArray(rawGroupIds)
    ? rawGroupIds.map((value) => Number(value?.id ?? value)).filter((value) => Number.isSafeInteger(value) && value > 0)
    : [];
  const nestedUsage = normalizeTableUsageStats(account.usage);
  const hasNestedUsageShape = account.usage && typeof account.usage === 'object'
    && ['historical', 'history', 'current', 'today', 'historical_usage', 'current_usage']
      .some((key) => Object.prototype.hasOwnProperty.call(account.usage, key));
  const name = safeRemoteText(scalarText(account.name, 256), 256);
  const rawStatus = scalarText(account.status, 64).toLowerCase();
  const status = /^[a-z0-9_-]{1,64}$/.test(rawStatus) ? rawStatus : '';
  const statusKnown = ['active', 'disabled', 'error'].includes(status);
  const schedulableKnown = typeof account.schedulable === 'boolean';
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
    tempUnschedulableReason: safeRemoteText(
      firstScalar([account.temp_unschedulable_reason, account.tempUnschedulableReason], 4000),
      1000,
    ),
    errorMessage: safeRemoteText(firstScalar([account.error_message, account.errorMessage], 4000), 1000),
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
      access: accessFingerprintConflict
        ? null
        : storedFingerprintField.value || computedAccessFingerprint,
      refresh: refreshField.conflict || refreshFingerprintConflict
        ? null
        : storedRefreshFingerprintField.value || computedRefreshFingerprint,
      id: idTokenField.conflict ? null : tokenFingerprint(idTokenField.value),
    },
    groupIds,
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
  if (!stats || typeof stats !== 'object') return null;
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
  if (!value || typeof value !== 'object') return null;
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
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  if (!cleaned || cleaned.length > 256) return '';
  const redacted = safeRemoteText(cleaned, 256);
  return redacted.includes('[redacted]') ? '' : redacted;
}

async function readResponseTextWithLimit(response, limit = 4 * 1024 * 1024) {
  if (!response?.body || typeof response.body.getReader !== 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > limit) {
      const error = new Error('Sub2API response body too large');
      error.code = 'SUB2API_RESPONSE_TOO_LARGE';
      throw error;
    }
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > limit) {
        try { await reader.cancel(); } catch {}
        const error = new Error('Sub2API response body too large');
        error.code = 'SUB2API_RESPONSE_TOO_LARGE';
        throw error;
      }
      chunks.push(chunk);
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return Buffer.concat(chunks).toString('utf8');
}

function parseSseEvents(text) {
  const events = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!/^data\s*:/i.test(line)) continue;
    const value = line.replace(/^data\s*:/i, '').trim();
    if (!value || value === '[DONE]') continue;
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object') events.push(parsed);
    } catch {
      // Sub2API emits JSON SSE events. Ignore non-JSON keepalive lines.
    }
  }
  return events;
}

function sseErrorMessage(events) {
  const errorEvent = [...(events || [])].reverse().find((event) => (
    event?.type === 'error'
      || (event?.type === 'test_complete' && event?.success === false)
  ));
  return errorEvent?.error || errorEvent?.message || null;
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

class Sub2ApiAdminClient {
  constructor(options = {}) {
    this.baseUrl = String(
      options.baseUrl || process.env.SUB2API_BASE_URL || '',
    ).replace(/\/$/, '');
    this.apiKey = String(
      options.apiKey || process.env.SUB2API_ADMIN_API_KEY || '',
    );
    this.jwt = String(
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
      options.maxResponseBytes || process.env.SUB2API_MAX_RESPONSE_BYTES || 4 * 1024 * 1024,
    );
    this.maxResponseBytes = Number.isSafeInteger(maxResponseBytes) && maxResponseBytes >= 1024
      ? Math.min(maxResponseBytes, 32 * 1024 * 1024)
      : 4 * 1024 * 1024;
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
    } catch (error) {
      if (error?.code === 'SUB2API_INSECURE_HTTP') throw error;
      throw new Error('SUB2API_BASE_URL 必须是无查询参数、片段或内嵌凭据的 http(s) 地址');
    }
    if (!this.apiKey && !this.jwt) {
      throw new Error('SUB2API_ADMIN_API_KEY or SUB2API_JWT is required');
    }
  }

  async request(method, pathname, body, requestOptions = {}) {
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
      response = await fetch(this.baseUrl + pathname, {
        ...fetchOptions,
        // Admin calls must never silently follow a redirect to another host.
        redirect: 'error',
      });
      // Keep the timeout active while consuming the response body too. A
      // server can accept the request and then stall before sending JSON.
      text = await readResponseTextWithLimit(
        response,
        requestOptions.maxResponseBytes || this.maxResponseBytes,
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
      } else if (error?.code === 'SUB2API_REQUEST_SERIALIZATION_FAILED') {
        failure = error;
        reason = 'request_validation';
      } else {
        const safeDetail = safeRemoteText(error?.message || error);
        failure = requestFailure(
          'SUB2API_TRANSPORT_ERROR',
          'Sub2API request failed: ' + method + ' ' + pathname + ': ' + safeDetail,
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
      const detail = payload?.message || payload?.data?.message || payloadCode || response.statusText || 'request failed';
      const safeDetail = safeRemoteText(detail);
      const error = writeAwareFailure(
        requestFailure(
          'SUB2API_REQUEST_REJECTED',
          'Sub2API ' + method + ' ' + pathname + ' failed: ' + safeDetail,
        ),
        requestOptions,
        requestDispatched,
        'response_rejected',
      );
      writeLog(this.logger, 'warn', 'sub2api.request_rejected', {
        ...this.logContext,
        method,
        path: pathname,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: safeDetail,
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
    const pageSize = Number(options.pageSize || 200);
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
      const pageRows = asList(value);
      if (!pageRows) {
        const error = new Error('Sub2API 账号列表响应结构无效');
        error.code = 'SUB2API_ACCOUNTS_SCHEMA_INVALID';
        throw error;
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
      const rawTotal = value?.total ?? value?.pagination?.total;
      if (rawTotal !== undefined && rawTotal !== null && rawTotal !== '') {
        const total = Number(rawTotal);
        if (!Number.isSafeInteger(total) || total < 0
            || (expectedTotal !== null && expectedTotal !== total)) {
          const error = new Error('Sub2API 账号列表分页统计无效或已变化');
          error.code = 'SUB2API_ACCOUNTS_PAGINATION_INVALID';
          throw error;
        }
        expectedTotal = total;
      } else if (options.requireTotal === true) {
        const error = new Error('Sub2API 账号列表分页缺少完整统计');
        error.code = 'SUB2API_ACCOUNTS_TOTAL_REQUIRED';
        throw error;
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
    const rows = asList(value);
    if (!rows) {
      const error = new Error('Sub2API 分组列表响应结构无效');
      error.code = 'SUB2API_GROUPS_SCHEMA_INVALID';
      throw error;
    }
    return rows;
  }

  async getAccount(id, options = {}) {
    const accountId = positiveAccountId(id);
    if (!accountId) {
      const error = new Error('Sub2API 账号详情缺少有效账号 ID');
      error.code = 'SUB2API_ACCOUNT_ID_INVALID';
      throw error;
    }
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
    const value = await this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(id)) + '/models',
    );
    const rows = Array.isArray(value)
      ? value
      : (Array.isArray(value?.models) ? value.models : asList(value));
    if (!rows) {
      const error = new Error('Sub2API 模型列表响应结构无效');
      error.code = 'SUB2API_MODELS_SCHEMA_INVALID';
      throw error;
    }
    return [...new Set(rows.slice(0, 2000).map((item) => {
      if (typeof item === 'string') return safeModelId(item);
      return safeModelId(item?.id || item?.model_id || item?.name);
    }).filter(Boolean))].slice(0, 1000);
  }

  async testAccount(id, options = {}) {
    const startedAt = Date.now();
    const pathname = '/api/v1/admin/accounts/' + encodeURIComponent(String(id)) + '/test';
    const modelId = safeModelId(options.modelId || options.model_id);
    const prompt = asString(options.prompt).trim();
    const body = {};
    if (modelId) body.model_id = modelId;
    if (prompt) body.prompt = prompt;
    writeLog(this.logger, 'info', 'sub2api.account_test_started', {
      ...this.logContext,
      accountId: Number(id),
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
      text = await readResponseTextWithLimit(response, this.maxResponseBytes);
    } catch (error) {
      let failure;
      let reason = 'transport';
      if (abortSource === 'external') {
        failure = interruptedRequestError('Sub2API 账号测试因面板停机中断');
        reason = 'external_abort';
        writeLog(this.logger, 'warn', 'sub2api.account_test_interrupted', {
          ...this.logContext,
          accountId: Number(id),
          model: modelId || null,
          durationMs: Date.now() - startedAt,
        });
      } else if (abortSource === 'timeout') {
        failure = requestFailure('SUB2API_TEST_TIMEOUT', 'Sub2API 账号测试超时');
        reason = 'timeout';
      } else if (error?.code === 'SUB2API_RESPONSE_TOO_LARGE') {
        failure = requestFailure('SUB2API_TEST_RESPONSE_TOO_LARGE', 'Sub2API 账号测试响应过大');
        reason = 'response_too_large';
      } else if (error?.code === 'JOB_INTERRUPTED') {
        failure = error;
        reason = 'external_abort';
      } else {
        failure = requestFailure('SUB2API_TEST_TRANSPORT_ERROR', 'Sub2API 账号测试请求失败');
      }
      if (requestDispatched) failure = markAccountTestOutcomeUnknown(failure, reason);
      writeLog(this.logger, 'error', 'sub2api.account_test_failed', {
        ...this.logContext,
        accountId: Number(id),
        model: modelId || null,
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
    if (!response.ok) {
      const error = markAccountTestOutcomeUnknown(
        requestFailure('SUB2API_TEST_REQUEST_REJECTED', 'Sub2API 账号测试请求被上游拒绝（HTTP ' + response.status + '）'),
        'response_rejected',
      );
      writeLog(this.logger, 'warn', 'sub2api.account_test_rejected', {
        ...this.logContext,
        accountId: Number(id),
        model: modelId || null,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: error.message,
        testOutcomeUnknown: true,
      });
      throw error;
    }

    const events = parseSseEvents(text);
    const errorMessage = sseErrorMessage(events);
    const completions = events.filter((event) => event?.type === 'test_complete');
    const completed = completions.at(-1);
    const terminalInvalid = completions.length > 1
      || (completed && typeof completed.success !== 'boolean')
      || Boolean(errorMessage && completed?.success === true);
    if (terminalInvalid || (!completed && !errorMessage)) {
      throw markAccountTestOutcomeUnknown(
        requestFailure('SUB2API_TEST_RESPONSE_INVALID', 'Sub2API 账号测试缺少可确认的终态'),
        terminalInvalid ? 'invalid_terminal' : 'missing_terminal',
      );
    }
    const eventModel = safeModelId(completed?.model);
    const completedModel = eventModel || modelId || null;
    if (completed?.success === true && modelId && eventModel && eventModel !== modelId) {
      const detail = 'Sub2API 返回的测试模型与请求不一致';
      writeLog(this.logger, 'warn', 'sub2api.account_test_model_mismatch', {
        ...this.logContext,
        accountId: Number(id),
        model: modelId,
        returnedModel: eventModel,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: detail,
      });
      const error = new Error(detail);
      error.code = 'SUB2API_TEST_MODEL_MISMATCH';
      throw markAccountTestReconciliation(error, 'model_mismatch', { testSuccess: true });
    }
    if (errorMessage || completed?.success !== true) {
      const detail = errorMessage
        ? 'Sub2API 返回失败测试结果'
        : 'Sub2API 未返回成功测试结果';
      writeLog(this.logger, 'warn', 'sub2api.account_test_unsuccessful', {
        ...this.logContext,
        accountId: Number(id),
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
      accountId: Number(id),
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
    const accountId = positiveAccountId(id);
    if (!accountId) {
      const error = new Error('Sub2API 调度设置缺少有效账号 ID');
      error.code = 'SUB2API_SCHEDULABLE_ID_INVALID';
      throw error;
    }
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
    const value = await this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(id)) + '/stats?days=' + encodeURIComponent(String(days)),
    );
    return value;
  }

  async getAccountTodayStats(id) {
    return this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(id)) + '/today-stats',
    );
  }

  async getBatchTodayStats(ids) {
    const requestedIds = normalizedAccountIds(ids);
    const value = await this.request('POST', '/api/v1/admin/accounts/today-stats/batch', {
      account_ids: requestedIds,
    });
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      const error = new Error('Sub2API 当期统计响应结构无效');
      error.code = 'SUB2API_STATS_SCHEMA_INVALID';
      throw error;
    }
    const allowed = new Set(requestedIds);
    const normalized = Object.create(null);
    for (const [rawId, item] of Object.entries(value)) {
      const id = Number(rawId);
      if (!Number.isSafeInteger(id) || id <= 0 || !allowed.has(id)) continue;
      normalized[String(id)] = normalizeUsageStats(item);
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
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      const error = new Error('Sub2API 账号统计响应结构无效');
      error.code = 'SUB2API_STATS_SCHEMA_INVALID';
      throw error;
    }
    const stats = value?.stats && typeof value.stats === 'object' ? value.stats : value;
    const allowed = new Set(requestedIds);
    const normalized = Object.create(null);
    for (const [rawId, item] of Object.entries(stats || {})) {
      const id = Number(rawId);
      if (!Number.isSafeInteger(id) || id <= 0 || !allowed.has(id)) continue;
      normalized[String(id)] = normalizeTableUsageStats(item);
    }
    const errors = Object.create(null);
    if (value?.errors && typeof value.errors === 'object' && !Array.isArray(value.errors)) {
      for (const [rawId, error] of Object.entries(value.errors)) {
        const id = Number(rawId);
        if (!Number.isSafeInteger(id) || id <= 0 || !allowed.has(id)) continue;
        errors[String(id)] = safeRemoteText(error);
      }
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
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      const error = new Error('Sub2API 导入响应结构无效');
      error.code = 'SUB2API_IMPORT_SCHEMA_INVALID';
      throw markWriteOutcomeUnknown(error, 'response_schema');
    }
    const knownField = ['success', 'ok', 'account_id', 'accountId', 'created', 'updated', 'skipped', 'failed', 'total', 'message', 'errors', 'warnings']
      .some((key) => Object.prototype.hasOwnProperty.call(value, key));
    if (!knownField) {
      const error = new Error('Sub2API 导入响应缺少结果字段');
      error.code = 'SUB2API_IMPORT_SCHEMA_INVALID';
      throw markWriteOutcomeUnknown(error, 'response_schema');
    }
    return value;
  }

  async applyOAuthCredentials(id, payload, options = {}) {
    const accountId = positiveAccountId(id);
    if (!accountId) {
      const error = new Error('Sub2API 凭证更新缺少有效账号 ID');
      error.code = 'SUB2API_CREDENTIALS_ID_INVALID';
      throw error;
    }
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
};
