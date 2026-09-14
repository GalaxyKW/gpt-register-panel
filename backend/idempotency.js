const crypto = require('node:crypto');

const IDEMPOTENCY_KEY_MIN_BYTES = 20;
const IDEMPOTENCY_KEY_MAX_BYTES = 128;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

function idempotencyError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function normalizeIdempotencyKey(value) {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') < IDEMPOTENCY_KEY_MIN_BYTES
      || Buffer.byteLength(value, 'utf8') > IDEMPOTENCY_KEY_MAX_BYTES
      || !IDEMPOTENCY_KEY_PATTERN.test(value)) {
    throw idempotencyError(
      'IDEMPOTENCY_KEY_INVALID',
      'Idempotency-Key 必须是 20 至 128 字节的受限 ASCII 字符串',
    );
  }
  return value;
}

function requestIdempotencyKey(request) {
  const rawHeaders = Array.isArray(request?.rawHeaders) ? request.rawHeaders : [];
  let occurrences = 0;
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (String(rawHeaders[index]).toLowerCase() === 'idempotency-key') occurrences += 1;
  }
  const value = request?.headers?.['idempotency-key'];
  if (occurrences > 1 || Array.isArray(value)) {
    throw idempotencyError(
      'IDEMPOTENCY_KEY_INVALID',
      'Idempotency-Key 必须且只能提供一次',
    );
  }
  if (value === undefined || value === null || value === '') {
    throw idempotencyError(
      'IDEMPOTENCY_KEY_REQUIRED',
      '写操作必须提供 Idempotency-Key',
    );
  }
  return normalizeIdempotencyKey(value);
}

function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求包含非有限数值');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (typeof value !== 'object') {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求包含无法规范化的值');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求必须由普通对象组成');
  }
  const fields = Object.keys(value).sort().map((key) => {
    if (value[key] === undefined) {
      throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求包含未定义字段');
    }
    return JSON.stringify(key) + ':' + canonicalJson(value[key]);
  });
  return '{' + fields.join(',') + '}';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function mutationRequestDigest(workflow, normalizedIntent, idempotencyKey) {
  if (typeof workflow !== 'string' || !/^[a-z][a-z0-9_]{1,63}$/.test(workflow)) {
    throw idempotencyError('IDEMPOTENCY_WORKFLOW_INVALID', '幂等工作流标识无效');
  }
  const normalizedKey = normalizeIdempotencyKey(idempotencyKey);
  // The raw key exists only in request memory. Keying the intent digest keeps
  // short account-test prompts from becoming dictionary-testable if an
  // attacker obtains the durable database and already knows the other fields.
  return crypto.createHmac('sha256', normalizedKey)
    .update('mutation-request-v2\0' + workflow + '\0' + canonicalJson(normalizedIntent))
    .digest('hex');
}

function mutationKeyHash(workflow, actor, key) {
  const normalizedKey = normalizeIdempotencyKey(key);
  const normalizedActor = typeof actor === 'string' && /^[a-z][a-z0-9-]{0,31}$/.test(actor)
    ? actor
    : null;
  if (!normalizedActor || typeof workflow !== 'string' || !/^[a-z][a-z0-9_]{1,63}$/.test(workflow)) {
    throw idempotencyError('IDEMPOTENCY_SCOPE_INVALID', '幂等键作用域无效');
  }
  return sha256('mutation-key-v1\0' + workflow + '\0' + normalizedActor + '\0' + normalizedKey);
}

function promptDigest(prompt) {
  return sha256('account-test-prompt-v1\0' + String(prompt || ''));
}

module.exports = {
  IDEMPOTENCY_KEY_MAX_BYTES,
  IDEMPOTENCY_KEY_MIN_BYTES,
  canonicalJson,
  mutationKeyHash,
  mutationRequestDigest,
  normalizeIdempotencyKey,
  promptDigest,
  requestIdempotencyKey,
};
