'use strict';

// Display-only diagnostics. These labels never authorize a refresh, status
// change or deletion; those operations retain their separate identity checks.
const MESSAGES = Object.freeze({
  network: 'Sub2API 向模型上游发起网络请求失败；不代表 token 未导入或账号被封禁',
  model_unavailable: '所选模型不可用或当前账号无权使用；无需重新注册，请核对测试模型',
  quota: '上游报告额度不足；保留账号与 token，等待额度恢复',
  rate_limited: '上游请求被限流；保留账号与 token，稍后再测试',
  authentication: '上游鉴权未通过；需要核对凭据，不能据此认定账号封禁',
  account_status: '上游返回账号状态错误；需要进一步核对，不自动删除账号',
  upstream: '模型上游返回错误；本次调用验证未通过，不等于导入失败',
  unknown: 'Sub2API 返回失败测试结果',
});
const HTTP_STATUSES = new Set([400, 401, 402, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504]);
const CODES = Object.freeze({
  model_not_found: 'model_unavailable', model_not_supported: 'model_unavailable',
  unsupported_model: 'model_unavailable', invalid_model: 'model_unavailable',
  insufficient_quota: 'quota', usage_limit_reached: 'quota', usage_limit_exceeded: 'quota',
  rate_limit_exceeded: 'rate_limited', rate_limit_error: 'rate_limited',
  invalid_token: 'authentication', token_expired: 'authentication', token_invalidated: 'authentication',
  invalid_api_key: 'authentication', authentication_error: 'authentication',
  account_deactivated: 'account_status', user_deactivated: 'account_status',
  account_suspended: 'account_status', account_banned: 'account_status',
});

function ownValue(value, key) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch { return undefined; }
}

function normalizeAccountTestFailure(value) {
  const proposed = ownValue(value, 'failureCategory');
  const failureCategory = typeof proposed === 'string' && Object.hasOwn(MESSAGES, proposed) ? proposed : 'unknown';
  const status = ownValue(value, 'upstreamStatus');
  return { failureCategory, upstreamStatus: HTTP_STATUSES.has(status) ? status : null, message: MESSAGES[failureCategory] };
}

function codeCategory(value) {
  for (const key of ['code', 'type']) {
    const code = ownValue(value, key);
    if (typeof code === 'string' && Object.hasOwn(CODES, code)) return CODES[code];
  }
  return null;
}

function classifyAccountTestFailure(event) {
  let category = codeCategory(event);
  let upstreamStatus = null;
  const error = ownValue(event, 'error');
  category ||= codeCategory(error);
  for (const raw of [error, ownValue(event, 'message')]) {
    if (typeof raw !== 'string' || raw.length > 16384) continue;
    // These are Sub2API's fixed error wrappers, not arbitrary matches in an
    // upstream paragraph. Never retain their URLs, headers, messages or body.
    const http = /^API returned (400|401|402|403|404|408|409|422|429|500|502|503|504):\s*([\s\S]*)$/.exec(raw);
    if (http) {
      upstreamStatus = Number(http[1]);
      try {
        const body = JSON.parse(http[2]);
        category ||= codeCategory(ownValue(body, 'error')) || codeCategory(body);
      } catch { /* Unknown bodies remain generic and are never exposed. */ }
      category ||= upstreamStatus === 429 ? 'rate_limited'
        : upstreamStatus === 401 ? 'authentication' : 'upstream';
    } else if (/^Request failed: [^\r\n]+$/.test(raw)) {
      category ||= 'network';
    }
  }
  return normalizeAccountTestFailure({ failureCategory: category || 'unknown', upstreamStatus });
}

module.exports = { classifyAccountTestFailure, normalizeAccountTestFailure };
