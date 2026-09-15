const crypto = require('node:crypto');

const IDEMPOTENCY_KEY_MIN_BYTES = 20;
const IDEMPOTENCY_KEY_MAX_BYTES = 128;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const CANONICAL_JSON_MAX_DEPTH = 64;
const CANONICAL_JSON_MAX_COLLECTION_ITEMS = 10000;

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
  let rawValue;
  if (rawHeaders.length % 2 !== 0) {
    throw idempotencyError(
      'IDEMPOTENCY_KEY_INVALID',
      'Idempotency-Key 请求头结构无效',
    );
  }
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (typeof rawHeaders[index] === 'string'
        && rawHeaders[index].toLowerCase() === 'idempotency-key') {
      occurrences += 1;
      rawValue = rawHeaders[index + 1];
    }
  }
  const headers = request?.headers;
  const value = headers && Object.prototype.hasOwnProperty.call(headers, 'idempotency-key')
    ? headers['idempotency-key']
    : undefined;
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
  if (occurrences !== 1 || typeof rawValue !== 'string' || rawValue !== value) {
    throw idempotencyError(
      'IDEMPOTENCY_KEY_INVALID',
      'Idempotency-Key 必须与唯一的原始请求头完全一致',
    );
  }
  return normalizeIdempotencyKey(value);
}

function canonicalJsonValue(value, state, depth) {
  if (depth > CANONICAL_JSON_MAX_DEPTH) {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求嵌套层级过深');
  }
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求包含非有限数值');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length > CANONICAL_JSON_MAX_COLLECTION_ITEMS
        || Object.keys(value).length !== value.length
        || Object.getOwnPropertySymbols(value).some((symbol) => (
          Object.prototype.propertyIsEnumerable.call(value, symbol)
        ))) {
      throw idempotencyError(
        'IDEMPOTENCY_REQUEST_INVALID',
        '幂等请求数组必须连续且不能包含额外字段',
      );
    }
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.prototype.hasOwnProperty.call(value, index)) {
        throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求数组不能包含空位');
      }
    }
    if (state.ancestors.has(value)) {
      throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求不能循环引用');
    }
    state.ancestors.add(value);
    try {
      return '[' + value.map((item) => canonicalJsonValue(item, state, depth + 1)).join(',') + ']';
    } finally {
      state.ancestors.delete(value);
    }
  }
  if (typeof value !== 'object') {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求包含无法规范化的值');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求必须由普通对象组成');
  }
  const keys = Object.keys(value);
  if (keys.length > CANONICAL_JSON_MAX_COLLECTION_ITEMS
      || Object.getOwnPropertySymbols(value).some((symbol) => (
        Object.prototype.propertyIsEnumerable.call(value, symbol)
      ))) {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求对象字段无效或过多');
  }
  if (state.ancestors.has(value)) {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求不能循环引用');
  }
  state.ancestors.add(value);
  try {
    const fields = keys.sort().map((key) => {
      if (value[key] === undefined) {
        throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '幂等请求包含未定义字段');
      }
      return JSON.stringify(key) + ':' + canonicalJsonValue(value[key], state, depth + 1);
    });
    return '{' + fields.join(',') + '}';
  } finally {
    state.ancestors.delete(value);
  }
}

function canonicalJson(value) {
  return canonicalJsonValue(value, { ancestors: new Set() }, 0);
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

function promptDigest(prompt = '') {
  if (typeof prompt !== 'string') {
    throw idempotencyError('IDEMPOTENCY_REQUEST_INVALID', '账号测试提示词必须是字符串');
  }
  return sha256('account-test-prompt-v1\0' + prompt);
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
