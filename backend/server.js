const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { URL } = require('node:url');
const { TextDecoder } = require('node:util');

const {
  booleanEnvEnabled,
  loadEnv,
  validateBooleanEnvironment,
} = require('./config');
const {
  buildSnapshot,
  buildImportPlan,
  buildImportPlanIntentVersion,
  importPlanSummary,
  executeImport,
  resolveImportGroupBinding,
  resolveImportExecutionBinding,
  configuredForSub2Api,
  confirmedSub2ApiRead,
  isImportPlanIntentVersion,
  safeErrorMessage,
} = require('./sync');
const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const {
  PanelDb,
  RECONCILIATION_ACK_CONFIRMATION,
  RECONCILIATION_ACK_RESOLUTIONS,
} = require('./db');
const {
  PHASE3_TERMINATION_MAX_TOTAL_MS,
  runPhase3Job,
  canonicalPhase3Keys,
  resolvePhase3Requests,
} = require('./phase3Worker');
const {
  activeAccountTestJobs,
  accountTestJobStatus,
  accountTestTargetBaseline,
  assertAccountTestTargetRevisions,
  classifyAccountTestTargets,
  normalizeAccountTestRequest,
  runAccountTestJob,
  safeErrorMessage: safeAccountTestErrorMessage,
  withAccountTestSubmissionLock,
} = require('./accountTestWorker');
const {
  assertAuditLogCheckpoint,
  createLogger,
  redactText,
  safeErrorText,
} = require('./logger');
const {
  CONFIRMATION: TOKEN_CLEANUP_CONFIRMATION,
  assertTokenCleanupRecoveryNotRequired,
  listExpiredTokens,
  deleteExpiredTokens,
} = require('./tokenCleanup');
const { withControlPlaneLock } = require('./taskCoordinator');
const { assertDirectoryTree } = require('./lib/safeFs');
const {
  normalizePhase3Identity,
  normalizePhase3SelectedKey,
} = require('./lib/phase3Identity');
const {
  createAdmissionDispatchGuard,
  createBackgroundJobManager,
  throwIfJobInterrupted,
  updateTerminalJob,
} = require('./jobLifecycle');
const {
  mutationRequestDigest,
  promptDigest,
  requestIdempotencyKey,
} = require('./idempotency');

const FRONTEND_ROOT = path.resolve(__dirname, '..', 'frontend');
const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};
const MIN_PHASE3_SHUTDOWN_TIMEOUT_MS = PHASE3_TERMINATION_MAX_TOTAL_MS + 1000;
const CONTENT_SECURITY_POLICY = "default-src 'self'; base-uri 'none'; object-src 'none'; form-action 'none'; style-src 'self'; script-src 'self'; frame-ancestors 'none'";
const STATIC_ALLOWLIST = new Set(['/index.html', '/app.js', '/styles.css']);
const JSON_BODY_ENDPOINTS = new Set([
  '/api/sync/preview',
  '/api/sync/import',
  '/api/phase3',
  '/api/tokens/expired/delete',
  '/api/account-tests',
]);
const GET_API_ENDPOINTS = new Set([
  '/api/health',
  '/api/snapshot',
  '/api/account-tests/models',
  '/api/tokens/expired',
  '/api/jobs',
  '/api/audit',
  '/api/logs',
]);
const RECONCILIATION_ACK_RESOLUTION_SET = new Set(RECONCILIATION_ACK_RESOLUTIONS);
const PHASE3_RECONCILIATION_SCOPES = new Set([
  'phase3_account_disposition',
  'phase3_process_tree',
  'phase3_token_output',
]);
const PHASE3_RECONCILIATION_REASONS = new Set([
  'account_disposition_write_unknown',
  'account_disposition_checkpoint_unavailable',
  'account_disposition_not_persisted',
  'phase3_process_tree_unconfirmed',
  'phase3_postflight_source_unavailable',
  'phase3_token_identity_mismatch',
]);
const PHASE3_DISPOSITION_OUTCOMES = new Set([
  'persisted',
  'not_persisted',
  'unknown',
  'not_attempted',
]);
const TOKEN_CLEANUP_JOB_TYPE = 'token_cleanup';
const TOKEN_CLEANUP_CLAIM_KEY = 'token_cleanup:expired_tokens';
// One additional summary target is included in reconciliation responses.
const MAX_TOKEN_CLEANUP_REVIEW_TARGETS = 99;
const MUTATION_WORKFLOWS = Object.freeze({
  import: 'token_import',
  phase3: 'phase3',
  accountTest: 'account_test',
  tokenCleanup: 'token_cleanup',
});

const authFailureBuckets = new Map();
const MAX_AUTH_FAILURE_BUCKETS = 10_000;

function boundedEnvNumber(name, fallback, minimum, maximum) {
  const raw = process.env[name];
  if (raw === undefined || String(raw).trim() === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(parsed)));
}

function requestAddress(request) {
  return String(request?.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

function tokensEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ''));
  const rightBuffer = Buffer.from(String(right || ''));
  return leftBuffer.length === rightBuffer.length
    && leftBuffer.length > 0
    && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function authRateLimit(request) {
  // Buckets live only in this process, so civil-clock adjustments must not
  // shorten or indefinitely extend their security window.
  const now = performance.now();
  const windowMs = boundedEnvNumber('PANEL_AUTH_WINDOW_MS', 60_000, 1_000, 3_600_000);
  const blockMs = boundedEnvNumber('PANEL_AUTH_BLOCK_MS', 60_000, 1_000, 3_600_000);
  const maxFailures = boundedEnvNumber('PANEL_AUTH_MAX_FAILURES', 10, 1, 1_000);
  const key = requestAddress(request);
  const current = authFailureBuckets.get(key);
  if (!current) return null;
  if (current.blockedUntil > now) {
    return Math.max(1, Math.ceil((current.blockedUntil - now) / 1000));
  }
  if (current.windowStartedAt + windowMs <= now) {
    authFailureBuckets.delete(key);
    return null;
  }
  if (current.count >= maxFailures) {
    current.blockedUntil = now + blockMs;
    return Math.ceil(blockMs / 1000);
  }
  return null;
}

function reserveAuthFailureBucket(key, now, windowMs) {
  if (authFailureBuckets.has(key)) return;
  if (authFailureBuckets.size >= MAX_AUTH_FAILURE_BUCKETS) {
    for (const [bucketKey, bucket] of authFailureBuckets) {
      if (bucket.windowStartedAt + windowMs <= now && bucket.blockedUntil <= now) {
        authFailureBuckets.delete(bucketKey);
      }
    }
  }
  // Preserve a strict memory bound even if every bucket is still active. The
  // oldest entry is least useful once an attacker can present more unique
  // network sources than the limiter can retain.
  if (authFailureBuckets.size >= MAX_AUTH_FAILURE_BUCKETS) {
    const oldestKey = authFailureBuckets.keys().next().value;
    if (oldestKey !== undefined) authFailureBuckets.delete(oldestKey);
  }
}

function recordAuthFailure(request) {
  const now = performance.now();
  const windowMs = boundedEnvNumber('PANEL_AUTH_WINDOW_MS', 60_000, 1_000, 3_600_000);
  const blockMs = boundedEnvNumber('PANEL_AUTH_BLOCK_MS', 60_000, 1_000, 3_600_000);
  const maxFailures = boundedEnvNumber('PANEL_AUTH_MAX_FAILURES', 10, 1, 1_000);
  const key = requestAddress(request);
  reserveAuthFailureBucket(key, now, windowMs);
  const current = authFailureBuckets.get(key);
  const bucket = !current || current.windowStartedAt + windowMs <= now
    ? { count: 0, windowStartedAt: now, blockedUntil: 0 }
    : current;
  bucket.count += 1;
  if (bucket.count >= maxFailures) bucket.blockedUntil = now + blockMs;
  authFailureBuckets.set(key, bucket);
}

function clearAuthFailures(request) {
  authFailureBuckets.delete(requestAddress(request));
}

function resetAuthFailureBuckets() {
  authFailureBuckets.clear();
}

function authFailureBucketCount() {
  return authFailureBuckets.size;
}

function jsonResponse(response, statusCode, body) {
  const payload = JSON.stringify(body);
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': CONTENT_SECURITY_POLICY,
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
  });
  response.end(payload);
}

function mutationContext(request, workflow, normalizedIntent) {
  const idempotencyKey = requestIdempotencyKey(request);
  return {
    workflow,
    idempotencyKey,
    requestDigest: mutationRequestDigest(workflow, normalizedIntent, idempotencyKey),
  };
}

async function existingMutationReceipt(db, context, actor) {
  if (!db || typeof db.getMutationReceipt !== 'function') {
    const error = new Error('幂等回执存储不可用，已拒绝写操作');
    error.code = 'IDEMPOTENCY_STORE_UNAVAILABLE';
    throw error;
  }
  return db.getMutationReceipt({
    ...context,
    requestedBy: actor,
  });
}

function sendMutationReceipt(response, receipt, replayed = false) {
  if (!receipt || receipt.statusCode !== 202
      || !receipt.response || typeof receipt.response !== 'object'
      || Array.isArray(receipt.response)) {
    const error = new Error('幂等回执响应无效');
    error.code = 'IDEMPOTENCY_RECEIPT_INVALID';
    throw error;
  }
  response.setHeader('idempotency-replayed', replayed ? 'true' : 'false');
  jsonResponse(response, receipt.statusCode, receipt.response);
}

const PUBLIC_BAD_REQUEST_ERRORS = new Set([
  'INVALID_JSON_BODY',
  'INVALID_REQUEST_BODY',
  'INVALID_REQUEST_TARGET',
  'IDEMPOTENCY_KEY_REQUIRED',
  'IDEMPOTENCY_KEY_INVALID',
  'SNAPSHOT_VERSION_REQUIRED',
  'IMPORT_PLAN_VERSION_REQUIRED',
  'IMPORT_SELECTION_REQUIRED',
  'IMPORT_SELECTION_INVALID',
  'IMPORT_SELECTION_MISMATCH',
  'PHASE3_BATCH_INVALID',
  'PHASE3_SELECTION_INVALID',
  'PHASE3_ACCOUNT_INVALID',
  'PHASE3_TARGET_REVISION_INVALID',
  'PHASE3_BATCH_EMPTY',
  'ACCOUNT_TEST_REQUEST_INVALID',
  'ACCOUNT_TEST_TARGET_REVISION_REQUIRED',
  'ACCOUNT_TEST_SELECTION_INVALID',
  'ACCOUNT_TEST_TARGET_INVALID',
  'ACCOUNT_TEST_ACCOUNT_ID_INVALID',
  'ACCOUNT_TEST_TARGET_DUPLICATE',
  'ACCOUNT_TEST_TARGET_REVISION_INVALID',
  'ACCOUNT_TEST_MODEL_INVALID',
  'ACCOUNT_TEST_PROMPT_INVALID',
  'TOKEN_CLEANUP_CONFIRMATION_REQUIRED',
  'TOKEN_CLEANUP_VERSION_REQUIRED',
  'JOB_RECONCILIATION_JOB_ID_INVALID',
  'JOB_RECONCILIATION_REQUEST_INVALID',
  'JOB_RECONCILIATION_JOB_ID_MISMATCH',
  'JOB_RECONCILIATION_CONFIRMATION_INVALID',
  'JOB_RECONCILIATION_RESOLUTION_INVALID',
  'JOB_RECONCILIATION_DIGEST_INVALID',
]);
const PUBLIC_CONFLICT_ERRORS = new Set([
  'IDEMPOTENCY_KEY_REUSED',
  'IMPORT_PLAN_STALE',
  'PHASE3_DUPLICATE',
  'JOB_ALREADY_CLAIMED',
  'JOB_QUEUE_FULL',
  'JOB_RECONCILIATION_REQUIRED',
  'JOB_BLOCKED_BY_RECONCILIATION',
  'JOB_BLOCKED_BY_RUNNING_MUTATION',
  'ACCOUNT_TEST_TARGET_REVISION_STALE',
  'ACCOUNT_TEST_NO_ELIGIBLE_ACCOUNTS',
  'TOKEN_CLEANUP_STALE',
  'TOKEN_CLEANUP_RECOVERY_REQUIRED',
  'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT',
  'JOB_RECONCILIATION_NOT_HELD',
  'JOB_RECONCILIATION_ACK_CONFLICT',
  'JOB_RECONCILIATION_DIGEST_MISMATCH',
  'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE',
]);
const PUBLIC_FORBIDDEN_ERRORS = new Set([
  'PHASE3_DISABLED',
  'WRITE_DISABLED',
]);
const PUBLIC_BAD_GATEWAY_ERRORS = new Set([
  'SUB2API_READ_FAILED',
  'SUB2API_ACCOUNTS_TOTAL_REQUIRED',
  'SUB2API_ACCOUNTS_PAGINATION_REQUIRED',
  'SUB2API_ACCOUNTS_PAGINATION_INVALID',
  'SUB2API_GROUP_RESOLVE_FAILED',
  'SUB2API_GROUP_NOT_FOUND',
  'SUB2API_GROUP_AMBIGUOUS',
  'SUB2API_GROUP_NOT_ACTIVE',
  'SUB2API_GROUP_PLATFORM_MISMATCH',
]);
const PUBLIC_SERVICE_ERRORS = new Set([
  'REQUEST_ABORTED',
  'JOB_INTERRUPTED',
  'IDEMPOTENCY_REQUEST_INVALID',
  'IDEMPOTENCY_WORKFLOW_INVALID',
  'IDEMPOTENCY_SCOPE_INVALID',
  'IDEMPOTENCY_RESPONSE_INVALID',
  'IDEMPOTENCY_JOBS_INVALID',
  'IDEMPOTENCY_CAPACITY_EXCEEDED',
  'IDEMPOTENCY_RECEIPT_INVALID',
  'IDEMPOTENCY_STORE_UNAVAILABLE',
  'CONTROL_PLANE_LOCK_RELEASE_FAILED',
  'JOB_ADMISSION_RECOVERY_FAILED',
  'JOB_RECONCILIATION_GUARD_UNAVAILABLE',
  'JOB_CLAIM_INTEGRITY_INVALID',
  'AUDIT_LOG_UNAVAILABLE',
  'TOKEN_CLEANUP_AUDIT_INTENT_FAILED',
  'ACCOUNT_TEST_BASELINE_INVALID',
  'GPT_REGISTER_PATH_INVALID',
  'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
  'GPT_REGISTER_FILE_TOO_LARGE',
  'GPT_REGISTER_SOURCE_LIMIT',
  'GPT_REGISTER_SOURCE_MISSING',
  'GPT_REGISTER_SOURCE_INCOMPLETE',
  'GPT_REGISTER_SOURCE_CHANGED',
  'GPT_REGISTER_USERNAME_INVALID',
  'GPT_REGISTER_USERNAME_RECORD_LIMIT',
  'SUB2API_GROUP_CONFIG_INVALID',
]);
const PUBLIC_ERROR_MESSAGES = Object.freeze({
  REQUEST_BODY_TOO_LARGE: '请求体超过允许的大小上限',
  INVALID_JSON_BODY: '请求体不是有效的 JSON',
  INVALID_REQUEST_BODY: '请求体必须是 JSON 对象',
  INVALID_REQUEST_TARGET: '请求目标格式无效',
  IDEMPOTENCY_KEY_REQUIRED: '写请求必须提供 Idempotency-Key',
  IDEMPOTENCY_KEY_INVALID: 'Idempotency-Key 格式无效',
  IDEMPOTENCY_KEY_REUSED: '该 Idempotency-Key 已用于不同请求',
  JOB_ALREADY_CLAIMED: '该操作目标已有任务排队或运行中',
  JOB_RECONCILIATION_REQUIRED: '存在需要人工核对的任务，已阻止继续写入',
  ACCOUNT_TEST_TARGET_REVISION_STALE: '账号状态已变化，请刷新后重新选择',
  ACCOUNT_TEST_NO_ELIGIBLE_ACCOUNTS: '没有可测试的上游账号',
  ACCOUNT_TEST_BASELINE_INVALID: '无法安全确认账号测试基线，请稍后重试',
  IMPORT_PLAN_VERSION_REQUIRED: '缺少有效的导入计划版本，请重新检查差异',
  IMPORT_PLAN_STALE: '导入计划已变化，请重新检查差异',
  PHASE3_DISABLED: 'Phase 3 未启用',
  WRITE_DISABLED: '写操作未启用',
  SUB2API_READ_FAILED: '无法确认 Sub2API 当前账号列表',
  SUB2API_GROUP_RESOLVE_FAILED: '无法确认 Sub2API 当前分组列表',
  SUB2API_GROUP_NOT_FOUND: '配置的 Sub2API 分组不存在或当前不可用',
  SUB2API_GROUP_AMBIGUOUS: '配置的 Sub2API 分组标识不唯一',
  SUB2API_GROUP_NOT_ACTIVE: '配置的 Sub2API 分组当前未启用',
  SUB2API_GROUP_PLATFORM_MISMATCH: '配置的 Sub2API 分组不是 OpenAI 分组',
  SUB2API_GROUP_CONFIG_INVALID: 'Sub2API 分组配置无效',
  TOKEN_CLEANUP_STALE: '过期 token 清单已变化，请重新扫描',
  TOKEN_CLEANUP_RECOVERY_REQUIRED: '过期 token 清理存在待恢复状态，已阻止继续删除',
  TOKEN_CLEANUP_CLAIM_SCAN_LIMIT: 'token 清理声明扫描超过安全上限，已阻止继续操作',
  JOB_RECONCILIATION_NOT_FOUND: '待对账任务不存在',
  JOB_RECONCILIATION_ADMIN_REQUIRED: '只允许经过认证的面板管理员执行该操作',
  AUDIT_LOG_UNAVAILABLE: '审计日志不可用，已拒绝写操作',
  GPT_REGISTER_PATH_INVALID: 'gpt_register 来源路径不可信或不可读取',
  GPT_REGISTER_PATH_PERMISSIONS_INVALID: 'gpt_register 来源权限不安全',
  GPT_REGISTER_FILE_TOO_LARGE: 'gpt_register 来源文件超过安全读取上限',
  GPT_REGISTER_SOURCE_LIMIT: 'gpt_register 来源数量或总大小超过安全上限',
  GPT_REGISTER_SOURCE_MISSING: 'gpt_register 必需来源缺失，无法形成可信快照',
  GPT_REGISTER_SOURCE_INCOMPLETE: 'gpt_register 来源读取不完整，无法形成可信快照',
  GPT_REGISTER_SOURCE_CHANGED: 'gpt_register 来源在读取期间发生变化，请重试',
  GPT_REGISTER_USERNAME_INVALID: 'username.json 内容无效，无法形成可信快照',
  GPT_REGISTER_USERNAME_RECORD_LIMIT: 'username.json 记录数超过安全上限',
});

function storedErrorCode(error) {
  try {
    return typeof error?.code === 'string' ? error.code : '';
  } catch {
    return '';
  }
}

function safeHttpErrorMessage(error) {
  try {
    return safeErrorMessage(error);
  } catch {
    return 'unknown error';
  }
}

function publicApiError(error, options = {}) {
  const code = storedErrorCode(error);
  let statusCode = null;
  if (code === 'REQUEST_BODY_TOO_LARGE') statusCode = 413;
  else if (PUBLIC_BAD_GATEWAY_ERRORS.has(code)) statusCode = 502;
  else if (code === 'JOB_RECONCILIATION_NOT_FOUND') statusCode = 404;
  else if (code === 'JOB_RECONCILIATION_ADMIN_REQUIRED'
      || PUBLIC_FORBIDDEN_ERRORS.has(code)) statusCode = 403;
  else if (PUBLIC_BAD_REQUEST_ERRORS.has(code)) statusCode = 400;
  else if (PUBLIC_CONFLICT_ERRORS.has(code)) statusCode = 409;
  else if (PUBLIC_SERVICE_ERRORS.has(code)) statusCode = 503;
  if (statusCode !== null) {
    const defaultMessage = statusCode === 400
      ? '请求参数无效，请检查后重试'
      : statusCode === 409
        ? '请求与当前状态冲突，请刷新后重试'
        : statusCode === 502
          ? '上游服务响应无效'
          : statusCode === 503
            ? '服务暂时无法安全完成请求'
            : statusCode === 404
              ? '请求的资源不存在'
              : '当前身份不允许执行该操作';
    return {
      statusCode,
      body: {
        error: code,
        message: PUBLIC_ERROR_MESSAGES[code] || defaultMessage,
      },
    };
  }
  const write = options.write === true;
  return {
    statusCode: write ? 503 : 500,
    body: {
      error: options.fallbackCode || (write ? 'write_request_failed' : 'internal_error'),
      message: options.fallbackMessage || (write
        ? '写请求未能安全完成，请稍后重试'
        : '请求处理失败，请稍后重试'),
    },
  };
}

function sendPublicApiError(response, error, options = {}) {
  const output = publicApiError(error, options);
  jsonResponse(response, output.statusCode, {
    ...output.body,
    ...(options.extraFields ? options.extraFields(output.body.error, error) : {}),
  });
  return output;
}

function configuredPanelToken() {
  return String(process.env.PANEL_ADMIN_TOKEN || '');
}

function validateRuntimeConfiguration() {
  validateBooleanEnvironment();
  const configuredToken = configuredPanelToken();
  const requireAuthentication = booleanEnvEnabled('PANEL_REQUIRE_AUTH', true);
  if (requireAuthentication && !configuredToken) {
    const error = new Error('已启用面板认证，但未配置管理员令牌');
    error.code = 'PANEL_AUTH_CONFIG_REQUIRED';
    throw error;
  }
  // A configured token protects reads even when PANEL_REQUIRE_AUTH=0, so it
  // must meet the same requirements whenever it would participate in auth.
  if ((requireAuthentication || configuredToken)
      && !/^[\x21-\x7e]{16,4096}$/.test(configuredToken)) {
    const error = new Error('面板管理员令牌不符合安全要求');
    error.code = 'PANEL_ADMIN_TOKEN_INVALID';
    throw error;
  }
  if (booleanEnvEnabled('PANEL_PHASE3_ENABLED', false)) {
    const configuredShutdownTimeout = String(
      process.env.PANEL_SHUTDOWN_TIMEOUT_MS ?? '',
    ).trim();
    const shutdownTimeoutMs = configuredShutdownTimeout
      ? Number(configuredShutdownTimeout)
      : 10_000;
    if (!Number.isFinite(shutdownTimeoutMs)
        || Math.floor(shutdownTimeoutMs) < MIN_PHASE3_SHUTDOWN_TIMEOUT_MS) {
      const error = new Error(
        'Phase3 启用时服务停止等待必须至少为 '
          + String(MIN_PHASE3_SHUTDOWN_TIMEOUT_MS) + ' 毫秒',
      );
      error.code = 'PANEL_SHUTDOWN_BUDGET_TOO_SMALL';
      throw error;
    }
  }
}

function panelCredential(request) {
  const authorization = singleRequestHeader(request, 'authorization');
  const panelToken = singleRequestHeader(request, 'x-panel-token');
  if (!authorization.valid || !panelToken.valid) return { valid: false, value: '' };

  let bearerValue = null;
  if (authorization.present) {
    const match = /^Bearer[ \t]+([^\r\n]+)$/i.exec(authorization.value);
    if (!match) return { valid: false, value: '' };
    bearerValue = match[1].trim();
  }
  const panelValue = panelToken.present ? panelToken.value.trim() : null;
  if (bearerValue !== null && panelValue !== null
      && !tokensEqual(bearerValue, panelValue)) {
    return { valid: false, value: '' };
  }
  const value = bearerValue ?? panelValue ?? '';
  return value.length > 0 && value.length <= 4096
    ? { valid: true, value }
    : { valid: false, value: '' };
}

function headerToken(request) {
  const credential = panelCredential(request);
  return credential.valid ? credential.value : '';
}

function authorizationError(request, write = false) {
  const configuredToken = configuredPanelToken();
  const shouldProtectRead = booleanEnvEnabled('PANEL_REQUIRE_AUTH', true) || configuredToken;
  if (shouldProtectRead) {
    const authorized = Boolean(configuredToken)
      && tokensEqual(headerToken(request), configuredToken);
    if (!authorized) {
      const retryAfterSeconds = authRateLimit(request);
      if (retryAfterSeconds) {
        return {
          status: 429,
          error: 'panel_auth_rate_limited',
          message: '认证失败次数过多，请稍后重试',
          retryAfterSeconds,
        };
      }
      recordAuthFailure(request);
      return { status: 401, error: 'panel_auth_required', message: '需要有效的面板管理员令牌' };
    }
    clearAuthFailures(request);
  }
  if (write) {
    if (process.env.PANEL_WRITE_ENABLED !== '1') {
      return { status: 403, error: 'write_disabled', message: '写操作未启用，请设置 PANEL_WRITE_ENABLED=1' };
    }
    if (!configuredToken && process.env.PANEL_ALLOW_INSECURE_WRITE !== '1') {
      return { status: 503, error: 'write_auth_required', message: '写操作必须配置 PANEL_ADMIN_TOKEN' };
    }
    if (!configuredToken && process.env.PANEL_ALLOW_INSECURE_WRITE === '1') {
      const localWriteError = insecureLocalWriteRequestError(request);
      if (localWriteError) return localWriteError;
    }
  }
  return null;
}

function requestActor(request) {
  const configuredToken = configuredPanelToken();
  if (configuredToken && tokensEqual(headerToken(request), configuredToken)) return 'panel-admin';
  if (!configuredToken && isLoopbackRequest(request)) return 'local';
  return 'anonymous';
}

function isLoopbackAddress(address) {
  const value = String(address || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIP(value) === 4) {
    const octets = value.split('.').map((item) => Number(item));
    return octets.length === 4 && octets.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)
      && octets[0] === 127;
  }
  if (net.isIP(value) !== 6) return false;
  // Parse IPv6 without a dependency so compressed and IPv4-mapped loopback
  // forms are handled consistently for both listen and request addresses.
  const zoneIndex = value.indexOf('%');
  if (zoneIndex >= 0) return false;
  if (value.startsWith('::ffff:') && isLoopbackAddress(value.slice('::ffff:'.length))) return true;
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const parseHalf = (half) => {
    if (!half) return [];
    const parts = half.split(':');
    const output = [];
    for (const part of parts) {
      if (!part) return null;
      if (part.includes('.')) {
        const octets = part.split('.').map((item) => Number(item));
        if (octets.length !== 4 || octets.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) return null;
        output.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
        output.push(Number.parseInt(part, 16));
      }
    }
    return output;
  };
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves.length === 2 ? halves[1] : '');
  if (!left || !right) return false;
  const groups = halves.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill(0), ...right]
    : [...left];
  return groups.length === 8 && groups.slice(0, 7).every((item) => item === 0) && groups[7] === 1;
}

function isLoopbackHost(host) {
  if (typeof host !== 'string') return false;
  const value = host.trim().toLowerCase();
  const family = net.isIP(value);
  if (family === 4) return isLoopbackAddress(value);
  // Listening hosts are passed directly to net.Server. Do not grant the
  // loopback deployment exemption to DNS names, bracket notation, or an
  // IPv4-mapped spelling: only the IPv6 loopback address itself is trusted.
  return family === 6
    && !value.startsWith('::ffff:')
    && isLoopbackAddress(value);
}

function configuredListenHost(optionHost, environment = process.env) {
  const raw = optionHost !== undefined ? optionHost : environment.PANEL_HOST;
  if (raw === undefined) return '127.0.0.1';
  if (typeof raw !== 'string' || raw.length > 253 || raw.includes('\0') || raw.trim() === '') {
    const error = new Error('PANEL_HOST 必须是非空监听主机名或地址');
    error.code = 'PANEL_HOST_INVALID';
    throw error;
  }
  return raw.trim();
}

function configuredListenPort(optionPort, environment = process.env) {
  const fromOption = optionPort !== undefined;
  const raw = fromOption ? optionPort : environment.PANEL_PORT;
  if (!fromOption && (raw === undefined || String(raw).trim() === '')) return 4170;
  const normalized = typeof raw === 'number' ? String(raw) : String(raw || '').trim();
  if (!/^\d+$/.test(normalized)) {
    const error = new Error('PANEL_PORT 必须是有效的十进制端口');
    error.code = 'PANEL_PORT_INVALID';
    throw error;
  }
  const port = Number(normalized);
  const minimum = fromOption ? 0 : 1;
  if (!Number.isSafeInteger(port) || port < minimum || port > 65535) {
    const error = new Error(fromOption
      ? '监听端口必须是 0 到 65535 的整数'
      : 'PANEL_PORT 必须是 1 到 65535 的整数');
    error.code = 'PANEL_PORT_INVALID';
    throw error;
  }
  return port;
}

function validateListenConfiguration(host) {
  validateRuntimeConfiguration();
  const configuredToken = configuredPanelToken();
  if (isLoopbackHost(host)) return;
  if (!configuredToken) {
    const error = new Error('非回环监听必须配置 PANEL_ADMIN_TOKEN');
    error.code = 'PANEL_REMOTE_AUTH_REQUIRED';
    throw error;
  }
  if (!booleanEnvEnabled('PANEL_ALLOW_INSECURE_REMOTE')) {
    const error = new Error('非回环监听会使用明文 HTTP，必须明确设置 PANEL_ALLOW_INSECURE_REMOTE=1');
    error.code = 'PANEL_REMOTE_HTTP_CONFIRMATION_REQUIRED';
    throw error;
  }
}

function isLoopbackRequest(request) {
  const address = String(request?.socket?.remoteAddress || '').replace(/^::ffff:/i, '');
  return isLoopbackAddress(address);
}

function singleRequestHeader(request, name) {
  const normalizedName = String(name || '').toLowerCase();
  const value = request?.headers?.[normalizedName];
  if (value === undefined) return { present: false, valid: true, value: null };
  if (typeof value !== 'string') return { present: true, valid: false, value: null };

  // Node normally exposes only one value for Host. Check rawHeaders as well so
  // duplicate security-sensitive headers cannot be hidden by normalization.
  if (Array.isArray(request?.rawHeaders)) {
    const rawValues = [];
    for (let index = 0; index + 1 < request.rawHeaders.length; index += 2) {
      if (String(request.rawHeaders[index]).toLowerCase() === normalizedName) {
        rawValues.push(request.rawHeaders[index + 1]);
      }
    }
    if (rawValues.length !== 1 || rawValues[0] !== value) {
      return { present: true, valid: false, value: null };
    }
  }
  return { present: true, valid: true, value };
}

function loopbackHostOrigin(request) {
  const header = singleRequestHeader(request, 'host');
  if (!header.present || !header.valid || header.value.length > 64
      || header.value !== header.value.trim()) return null;

  let address;
  let port;
  const ipv6 = /^\[(::1)\](?::(\d{1,5}))?$/i.exec(header.value);
  if (ipv6) {
    address = '[::1]';
    port = ipv6[2];
  } else {
    const ipv4 = /^([^:]+)(?::(\d{1,5}))?$/.exec(header.value);
    if (!ipv4 || net.isIP(ipv4[1]) !== 4 || !isLoopbackAddress(ipv4[1])) return null;
    address = ipv4[1];
    port = ipv4[2];
  }
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) return null;
  try {
    return new URL('http://' + address + (port === undefined ? '' : ':' + port)).origin;
  } catch {
    return null;
  }
}

function insecureLocalWriteRequestError(request) {
  if (!isLoopbackRequest(request)) {
    return { status: 503, error: 'write_loopback_required', message: '未配置 PANEL_ADMIN_TOKEN 时，写操作只允许本机访问' };
  }
  const expectedOrigin = loopbackHostOrigin(request);
  if (!expectedOrigin) {
    return {
      status: 403,
      error: 'write_loopback_host_required',
      message: '未配置 PANEL_ADMIN_TOKEN 时，写请求 Host 必须使用回环 IP 地址',
    };
  }
  const originHeader = singleRequestHeader(request, 'origin');
  if (!originHeader.present) return null;
  if (!originHeader.valid || originHeader.value.length > 512
      || originHeader.value !== originHeader.value.trim()) {
    return {
      status: 403,
      error: 'write_origin_forbidden',
      message: '未配置 PANEL_ADMIN_TOKEN 时，写请求 Origin 必须与回环 Host 同源',
    };
  }
  try {
    const origin = new URL(originHeader.value);
    if (origin.protocol === 'http:'
        && origin.username === ''
        && origin.password === ''
        && originHeader.value === origin.origin
        && origin.origin === expectedOrigin) return null;
  } catch {}
  return {
    status: 403,
    error: 'write_origin_forbidden',
    message: '未配置 PANEL_ADMIN_TOKEN 时，写请求 Origin 必须与回环 Host 同源',
  };
}


function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Request handling must continue if the log destination is unavailable.
  }
}

async function withCombinedAbortSignal(signals, callback) {
  const controller = new AbortController();
  const subscriptions = [];
  try {
    for (const signal of signals) {
      if (!signal || typeof signal.addEventListener !== 'function') continue;
      const abort = () => {
        if (!controller.signal.aborted) controller.abort(signal.reason);
      };
      if (signal.aborted) abort();
      else {
        signal.addEventListener('abort', abort, { once: true });
        subscriptions.push([signal, abort]);
      }
    }
    throwIfJobInterrupted(controller.signal);
    return await callback(controller.signal);
  } finally {
    for (const [signal, abort] of subscriptions) {
      try { signal.removeEventListener('abort', abort); } catch {}
    }
  }
}

function readJsonBody(request, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bodyBytes = 0;
    let settled = false;
    const cleanup = () => {
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.removeListener('aborted', onAborted);
      request.removeListener('error', onError);
      request.removeListener('close', onClose);
    };
    const fail = (error, waitForStreamEnd = false) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      request.removeListener('data', onData);
      if (!waitForStreamEnd) cleanup();
      reject(error);
    };
    function onData(chunk) {
      if (settled) return;
      // Keep the original octets until the complete body is available.
      // IncomingMessage#setEncoding uses a replacement character for malformed
      // UTF-8, which can silently turn damaged mutation input into a different
      // valid JSON document and therefore a different idempotency intent.
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
      bodyBytes += bytes.length;
      if (bodyBytes > limit) {
        const error = new Error('request body too large');
        error.code = 'REQUEST_BODY_TOO_LARGE';
        // Keep only terminal/error listeners while the oversized request is
        // drained. Removing the data listener releases buffered chunks, while
        // retaining the error listener prevents a later socket reset from
        // becoming an unhandled EventEmitter error.
        fail(error, true);
        request.resume();
        return;
      }
      chunks.push(bytes);
    }
    function onEnd() {
      if (settled) {
        cleanup();
        return;
      }
      let body;
      try {
        body = new TextDecoder('utf-8', {
          fatal: true,
          // Preserve a leading BOM so JSON.parse rejects it instead of silently
          // accepting bytes outside the JSON text grammar.
          ignoreBOM: true,
        }).decode(Buffer.concat(chunks, bodyBytes));
      } catch {
        const error = new Error('invalid UTF-8 JSON body');
        error.code = 'INVALID_JSON_BODY';
        fail(error);
        return;
      }
      if (!body.trim()) {
        settled = true;
        cleanup();
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(body);
        settled = true;
        cleanup();
        resolve(parsed);
      } catch {
        const error = new Error('invalid JSON body');
        error.code = 'INVALID_JSON_BODY';
        fail(error);
      }
    }
    function onAborted() {
      const error = new Error('request aborted');
      error.code = 'REQUEST_ABORTED';
      // IncomingMessage can emit ECONNRESET after `aborted`; retain the error
      // listener until its terminal `error`/`close` event.
      fail(error, true);
    }
    function onError(error) {
      if (!settled) fail(error);
      cleanup();
    }
    function onClose() {
      if (!settled) {
        const error = new Error('request closed before body completed');
        error.code = 'REQUEST_ABORTED';
        fail(error);
      }
      cleanup();
    }
    request.on('data', onData);
    request.once('end', onEnd);
    request.once('aborted', onAborted);
    request.once('error', onError);
    request.once('close', onClose);
  });
}

function hasJsonContentType(request) {
  const header = singleRequestHeader(request, 'content-type');
  if (!header.present || !header.valid) return false;
  return header.value.split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

function invalidRequestTargetError() {
  const error = new Error('请求目标必须是无歧义的 origin-form');
  error.code = 'INVALID_REQUEST_TARGET';
  return error;
}

function decodedPathSegmentIsAmbiguous(rawSegment) {
  let candidate = rawSegment;
  for (let depth = 0; depth < 3; depth += 1) {
    let decoded;
    try { decoded = decodeURIComponent(candidate); } catch { return true; }
    if (decoded === '.' || decoded === '..'
        || /[\\/?#\u0000-\u001f\u007f-\u009f]/u.test(decoded)) return true;
    if (decoded === candidate || !/%[0-9a-f]{2}/i.test(decoded)) {
      return false;
    }
    candidate = decoded;
  }
  // More than three nested encodings is never needed by the panel and leaves
  // too much room for a proxy and the application to select different routes.
  return true;
}

function parseRequestTarget(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')
      || /[\\#\u0000-\u001f\u007f-\u009f]/u.test(value)
      || /%(?![0-9a-f]{2})/i.test(value)
      || /%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(value)) {
    throw invalidRequestTargetError();
  }
  const queryOffset = value.indexOf('?');
  const rawPath = queryOffset < 0 ? value : value.slice(0, queryOffset);
  const rawQuery = queryOffset < 0 ? '' : value.slice(queryOffset + 1);
  let decodedQuery;
  try { decodedQuery = decodeURIComponent(rawQuery); } catch { throw invalidRequestTargetError(); }
  if (!rawPath || rawPath.includes('//')
      || /[\u0000-\u001f\u007f-\u009f]/u.test(decodedQuery)
      || rawPath.split('/').some(decodedPathSegmentIsAmbiguous)) {
    throw invalidRequestTargetError();
  }
  try {
    const parsed = new URL(value, 'http://localhost');
    if (parsed.origin !== 'http://localhost') throw invalidRequestTargetError();
    return parsed;
  } catch (error) {
    if (storedErrorCode(error) === 'INVALID_REQUEST_TARGET') throw error;
    throw invalidRequestTargetError();
  }
}

function pathParam(pathname, prefix) {
  if (!pathname.startsWith(prefix)) return null;
  const value = pathname.slice(prefix.length);
  if (!value || value.includes('/')) return null;
  try { return decodeURIComponent(value); } catch { return null; }
}

function accountTestModelQueryId(searchParams) {
  const values = [
    ...searchParams.getAll('accountId'),
    ...searchParams.getAll('account_id'),
  ];
  // Both spellings remain supported, but accepting duplicates or coercing
  // values such as `01` and `1e0` lets intermediaries select a different ID.
  if (values.length !== 1 || !/^[1-9]\d*$/.test(values[0])) return null;
  const accountId = Number(values[0]);
  return Number.isSafeInteger(accountId) ? accountId : null;
}

function reconciliationAcknowledgePath(pathname) {
  const prefix = '/api/jobs/';
  const suffix = '/reconciliation/acknowledge';
  if (!pathname.startsWith(prefix) || !pathname.endsWith(suffix)) {
    return { matched: false, jobId: null };
  }
  const encoded = pathname.slice(prefix.length, -suffix.length);
  let jobId = null;
  try { jobId = decodeURIComponent(encoded); } catch {}
  if (!/^job_[a-f0-9]{24}$/.test(String(jobId || ''))) jobId = null;
  return { matched: true, jobId };
}

function reconciliationReviewPath(pathname) {
  const prefix = '/api/jobs/';
  const suffix = '/reconciliation';
  if (!pathname.startsWith(prefix) || !pathname.endsWith(suffix)) {
    return { matched: false, jobId: null };
  }
  const encoded = pathname.slice(prefix.length, -suffix.length);
  let jobId = null;
  try { jobId = decodeURIComponent(encoded); } catch {}
  if (!/^job_[a-f0-9]{24}$/.test(String(jobId || ''))) jobId = null;
  return { matched: true, jobId };
}

function allowedRequestMethod(pathname, reconciliationAck, reconciliationReview) {
  if (JSON_BODY_ENDPOINTS.has(pathname) || reconciliationAck.matched) return 'POST';
  if (GET_API_ENDPOINTS.has(pathname) || reconciliationReview.matched
      || pathParam(pathname, '/api/jobs/')) return 'GET';
  if (pathname === '/' || STATIC_ALLOWLIST.has(pathname)) return 'GET';
  return null;
}

const HTTP_LOG_FIXED_PATHS = new Set([
  '/',
  ...STATIC_ALLOWLIST,
  '/api/health',
  '/api/snapshot',
  '/api/sync/preview',
  '/api/sync/import',
  '/api/phase3',
  '/api/account-tests',
  '/api/account-tests/models',
  '/api/tokens/expired',
  '/api/tokens/expired/delete',
  '/api/jobs',
  '/api/audit',
  '/api/logs',
]);

function requestLogPath(pathname) {
  if (typeof pathname !== 'string') return '<unknown-path>';
  if (HTTP_LOG_FIXED_PATHS.has(pathname)) return pathname;
  const jobPrefix = '/api/jobs/';
  if (pathname.startsWith(jobPrefix)) {
    const suffix = pathname.slice(jobPrefix.length).split('/');
    if (suffix.length === 1 && suffix[0]) return '/api/jobs/:jobId';
    if (suffix.length === 2 && suffix[0] && suffix[1] === 'reconciliation') {
      return '/api/jobs/:jobId/reconciliation';
    }
    if (suffix.length === 3 && suffix[0]
        && suffix[1] === 'reconciliation' && suffix[2] === 'acknowledge') {
      return '/api/jobs/:jobId/reconciliation/acknowledge';
    }
  }
  return pathname.startsWith('/api/') ? '/api/<unknown>' : '<unknown-path>';
}

const UNSAFE_REVIEW_TEXT = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/;
const REVIEW_AVAILABILITY_REASONS = new Set([
  'not_in_sub2api',
  'sub2api_schema_invalid',
  'sub2api_status_unknown',
  'sub2api_status_missing',
  'sub2api_status_inactive',
  'sub2api_status_disabled',
  'sub2api_status_error',
  'sub2api_schedulable_missing',
  'sub2api_unschedulable',
  'sub2api_auto_pause_invalid',
  'sub2api_expiry_invalid',
  'sub2api_expired',
  'sub2api_temp_unschedulable_invalid',
  'sub2api_temp_unschedulable',
  'sub2api_rate_limit_invalid',
  'sub2api_rate_limited',
  'sub2api_overload_invalid',
  'sub2api_overloaded',
  'sub2api_available',
]);

function boundedReviewText(value, maximum = 256) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text || text.length > maximum || UNSAFE_REVIEW_TEXT.test(text)) return null;
  return redactText(text).slice(0, maximum);
}

function safeReviewRelativePath(value) {
  const text = boundedReviewText(value, 512);
  if (!text || path.isAbsolute(text) || text.includes('\\')) return null;
  const segments = text.split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) return null;
  return text;
}

function normalizedReviewSourcePath(source, relativeValue) {
  if (!['tokens', 'use_token'].includes(source)) return null;
  const relativePath = safeReviewRelativePath(relativeValue);
  if (!relativePath) return null;
  const firstSegment = relativePath.split('/', 1)[0];
  if (['tokens', 'use_token'].includes(firstSegment)) {
    return firstSegment === source ? relativePath : null;
  }
  return source + '/' + relativePath;
}

function sourcePathFromSelectionKey(value) {
  const text = normalizePhase3SelectedKey(value);
  if (!text) return null;
  const separator = text.indexOf(':', 'token:'.length);
  if (separator < 0) return null;
  const source = text.slice('token:'.length, separator);
  return normalizedReviewSourcePath(source, text.slice(separator + 1));
}

function safeReviewSourcePath(value) {
  if (typeof value !== 'string') return null;
  const separator = value.indexOf('/');
  if (separator < 0) return null;
  const source = value.slice(0, separator);
  return normalizedReviewSourcePath(source, value.slice(separator + 1));
}

function safeReviewAccountId(value) {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function safeReviewFingerprint(value) {
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return /^[a-f0-9]{8,128}$/.test(text) ? text : null;
}

function safeReviewCode(value, allowed = null) {
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!/^[a-z0-9_]{1,64}$/.test(text)) return null;
  return !allowed || allowed.has(text) ? text : null;
}

function safeReviewStrongIdentities(value) {
  if (!Array.isArray(value)) return { keys: [], truncated: false };
  const keys = [];
  const seen = new Set();
  for (const rawKey of value.slice(0, 1000)) {
    if (typeof rawKey !== 'string' || rawKey.length > 520
        || UNSAFE_REVIEW_TEXT.test(rawKey)) continue;
    const separator = rawKey.indexOf(':');
    const prefix = rawKey.slice(0, separator + 1);
    if (!['account:', 'user:'].includes(prefix)) continue;
    const identity = boundedReviewText(rawKey.slice(separator + 1), 512);
    const key = identity ? prefix + identity : null;
    if (!key || seen.has(key)) continue;
    seen.add(key);
    keys.push(key);
  }
  keys.sort();
  return { keys: keys.slice(0, 10), truncated: value.length > 1000 || keys.length > 10 };
}

function tokenImportReviewTargets(job) {
  const targets = [];
  const resultItems = Array.isArray(job?.result?.imported)
    ? job.result.imported.slice(0, 1000)
    : [];
  const uncertain = resultItems.filter((item) => (
    item?.requiresReconciliation === true || item?.writeOutcomeUnknown === true
      || item?.outcome === 'requires_reconciliation'
  ));
  const selectedItems = uncertain.length > 0 ? uncertain : resultItems;
  for (const item of selectedItems) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const source = safeReviewCode(item.source, new Set(['tokens', 'use_token']));
    const sourcePath = source
      ? normalizedReviewSourcePath(source, item.relativePath || item.fileName)
      : null;
    const remoteAccountId = safeReviewAccountId(
      item.accountId ?? item.sub2apiAccountId ?? item.sub2apiId ?? item?.verification?.accountId,
    );
    const strongIdentities = safeReviewStrongIdentities(item.sourceIdentityKeys);
    if (!sourcePath && !remoteAccountId) continue;
    targets.push({
      sourcePath: sourcePath || undefined,
      remoteAccountId: remoteAccountId || undefined,
      accountName: boundedReviewText(item.accountName ?? item?.verification?.accountName, 128)
        || undefined,
      email: boundedReviewText(item.email, 320) || undefined,
      action: safeReviewCode(item.action, new Set(['create', 'update'])) || undefined,
      accessFingerprint: safeReviewFingerprint(item?.fingerprints?.access) || undefined,
      strongIdentityKeys: strongIdentities.keys.length > 0 ? strongIdentities.keys : undefined,
      strongIdentityTruncated: strongIdentities.truncated || undefined,
      availability: safeReviewCode(
        item.availability,
        new Set(['available', 'unavailable', 'unknown', 'not_present']),
      ) || undefined,
      availabilityReason: safeReviewCode(item.availabilityReason, REVIEW_AVAILABILITY_REASONS)
        || undefined,
    });
  }
  if (targets.length === 0) {
    const selectedSourcePaths = Array.isArray(job?.payload?.selectedSourcePaths)
      ? job.payload.selectedSourcePaths.slice(0, 1000)
      : [];
    for (const selectedPath of selectedSourcePaths) {
      const sourcePath = safeReviewSourcePath(selectedPath);
      if (sourcePath) targets.push({ sourcePath });
    }
  }
  return targets;
}

function accountTestReviewTargets(job) {
  const baselines = new Map();
  for (const baseline of Array.isArray(job?.payload?.targetBaselines)
    ? job.payload.targetBaselines.slice(0, 1000) : []) {
    const accountId = safeReviewAccountId(baseline?.accountId);
    if (!accountId || baselines.has(accountId)) continue;
    baselines.set(accountId, {
      identityDigest: /^[a-f0-9]{64}$/.test(String(baseline?.identityDigest || ''))
        ? baseline.identityDigest
        : undefined,
      baselineStatus: safeReviewCode(
        baseline?.status,
        new Set(['active', 'inactive', 'disabled', 'error']),
      ) || undefined,
      baselineSchedulable: typeof baseline?.schedulable === 'boolean'
        ? baseline.schedulable
        : undefined,
    });
  }
  const resultItems = Array.isArray(job?.result?.results)
    ? job.result.results.slice(0, 1000)
    : [];
  const uncertainIds = new Set(resultItems.filter((item) => (
    item?.requiresReconciliation === true || item?.writeOutcomeUnknown === true
      || item?.outcome === 'requires_reconciliation'
  )).map((item) => safeReviewAccountId(item?.accountId)).filter(Boolean));
  const payloadIds = Array.isArray(job?.payload?.accountIds)
    ? job.payload.accountIds.slice(0, 1000)
    : [];
  const ids = uncertainIds.size > 0 ? [...uncertainIds] : payloadIds;
  const targets = [];
  const seen = new Set();
  for (const value of ids) {
    const remoteAccountId = safeReviewAccountId(value);
    if (!remoteAccountId || seen.has(remoteAccountId)) continue;
    seen.add(remoteAccountId);
    targets.push({ remoteAccountId, ...(baselines.get(remoteAccountId) || {}) });
  }
  return targets;
}

function phase3ReviewTargets(job) {
  const payload = job?.payload && typeof job.payload === 'object' && !Array.isArray(job.payload)
    ? job.payload
    : {};
  const sourcePath = safeReviewSourcePath(payload.sourcePath)
    || sourcePathFromSelectionKey(payload.selectedKey);
  const email = boundedReviewText(payload.email, 320);
  const rawPhone = typeof payload.phone === 'string' ? payload.phone.trim() : '';
  const phone = /^\d{1,80}$/.test(rawPhone) ? rawPhone : null;
  if (!sourcePath && !email && !phone) return [];
  return [{
    sourcePath: sourcePath || undefined,
    email: email || undefined,
    phone: phone || undefined,
  }];
}

function tokenCleanupReviewContext(job) {
  const payload = job?.payload && typeof job.payload === 'object' && !Array.isArray(job.payload)
    ? job.payload
    : {};
  const expectedVersion = /^[a-f0-9]{64}$/.test(String(payload.expectedVersion || ''))
    ? payload.expectedVersion
    : null;
  const targetCount = Number(payload.targetCount);
  if (!expectedVersion || !Number.isSafeInteger(targetCount)
      || targetCount < 0 || targetCount > 1_000_000) return null;
  const rawTargets = Array.isArray(payload.reviewTargets)
    ? payload.reviewTargets.slice(0, MAX_TOKEN_CLEANUP_REVIEW_TARGETS)
    : [];
  const targets = rawTargets.map((target) => {
    const sourcePath = safeReviewSourcePath(target?.sourcePath);
    const contentHash = /^[a-f0-9]{64}$/.test(String(target?.contentHash || ''))
      ? target.contentHash
      : null;
    if (!sourcePath || !contentHash) return null;
    return {
      sourcePath,
      contentHash,
      accessFingerprint: safeReviewFingerprint(target?.accessFingerprint) || undefined,
    };
  }).filter(Boolean);
  const complete = payload.reviewTargetsTruncated === false
    && rawTargets.length === targetCount
    && targets.length === targetCount;
  return {
    total: targetCount + 1,
    truncated: !complete,
    targets: [{
      cleanupScope: 'expired_tokens',
      expectedVersion,
      targetCount,
    }, ...targets],
  };
}

function reconciliationReviewDetail(job) {
  if (!job) {
    const error = new Error('待对账任务不存在');
    error.code = 'JOB_RECONCILIATION_NOT_FOUND';
    throw error;
  }
  const digest = String(job?.result?.reconciliationClaimDigest || '');
  if (!['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)
      || job?.result?.requiresReconciliation !== true
      || job?.result?.reconciliationHold !== true
      || job?.result?.reconciliationResolved === true
      || !/^[a-f0-9]{64}$/.test(digest)) {
    const error = new Error('该任务当前没有可供人工核对的持久阻挡');
    error.code = 'JOB_RECONCILIATION_NOT_HELD';
    throw error;
  }
  let targets = [];
  let targetTotal = 0;
  let targetsAlreadyTruncated = false;
  if (job.type === 'token_import') targets = tokenImportReviewTargets(job);
  else if (job.type === 'account_test') targets = accountTestReviewTargets(job);
  else if (job.type === 'phase3') targets = phase3ReviewTargets(job);
  else if (job.type === TOKEN_CLEANUP_JOB_TYPE) {
    const context = tokenCleanupReviewContext(job);
    if (context) {
      targets = context.targets;
      targetTotal = context.total;
      targetsAlreadyTruncated = context.truncated;
    }
  }
  if (targets.length === 0) {
    const error = new Error('该任务未保留足够的安全目标信息，不能从面板确认人工对账');
    error.code = 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE';
    throw error;
  }
  const returnedTargets = targets.slice(0, 100);
  const totalTargets = Math.max(targetTotal, targets.length);
  return {
    version: 1,
    id: job.id,
    type: job.type,
    status: job.status,
    reconciliationHold: true,
    reconciliationResolved: false,
    reconciliationClaimDigest: digest,
    reconciliationHoldScope: safeReviewCode(job.result.reconciliationHoldScope) || null,
    reconciliationBlockScope: safeReviewCode(job.result.reconciliationBlockScope) || null,
    targetContext: {
      available: true,
      total: totalTargets,
      returned: returnedTargets.length,
      truncated: targetsAlreadyTruncated || totalTargets > returnedTargets.length,
      targets: returnedTargets,
    },
  };
}

function reconciliationAcknowledgeRequestError(body, jobId) {
  if (!jobId) {
    const error = new Error('待对账任务标识无效');
    error.code = 'JOB_RECONCILIATION_JOB_ID_INVALID';
    return error;
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.getPrototypeOf(body) !== Object.prototype) {
    const error = new Error('请求体必须是 JSON 对象');
    error.code = 'INVALID_REQUEST_BODY';
    return error;
  }
  const allowed = new Set(['jobId', 'confirmation', 'resolution', 'claimDigest']);
  if (Object.keys(body).some((key) => !allowed.has(key))) {
    const error = new Error('人工对账请求包含未允许的字段');
    error.code = 'JOB_RECONCILIATION_REQUEST_INVALID';
    return error;
  }
  if (typeof body.jobId !== 'string' || body.jobId !== jobId) {
    const error = new Error('请求体中的任务标识与路径不一致');
    error.code = 'JOB_RECONCILIATION_JOB_ID_MISMATCH';
    return error;
  }
  if (body.confirmation !== RECONCILIATION_ACK_CONFIRMATION) {
    const error = new Error('人工对账确认语不正确');
    error.code = 'JOB_RECONCILIATION_CONFIRMATION_INVALID';
    return error;
  }
  if (typeof body.resolution !== 'string'
      || body.resolution.length > 32
      || !RECONCILIATION_ACK_RESOLUTION_SET.has(body.resolution)) {
    const error = new Error('人工对账结论无效');
    error.code = 'JOB_RECONCILIATION_RESOLUTION_INVALID';
    return error;
  }
  if (typeof body.claimDigest !== 'string'
      || !/^[a-f0-9]{64}$/.test(body.claimDigest)) {
    const error = new Error('任务保护键摘要无效');
    error.code = 'JOB_RECONCILIATION_DIGEST_INVALID';
    return error;
  }
  return null;
}

function safeStaticPath(urlPath) {
  let decoded;
  try { decoded = decodeURIComponent(urlPath === '/' ? '/index.html' : urlPath); } catch { return null; }
  if (!STATIC_ALLOWLIST.has(decoded)) return null;
  const absolute = path.resolve(FRONTEND_ROOT, '.' + decoded);
  if (absolute !== FRONTEND_ROOT && !absolute.startsWith(FRONTEND_ROOT + path.sep)) return null;
  return absolute;
}

function staticPathError() {
  const error = new Error('静态文件路径无效');
  error.code = 'STATIC_PATH_INVALID';
  return error;
}

function staticObjectOwnedAndReadonly(stat, kind) {
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
  return Boolean(stat
    && (kind === 'directory' ? stat.isDirectory() : stat.isFile())
    && !stat.isSymbolicLink()
    && (currentUid === null || stat.uid === currentUid)
    && (stat.mode & 0o022) === 0
    && (kind === 'directory' || stat.nlink === 1));
}

function sameStaticObject(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function openVerifiedStaticFile(filePath, rootDirectory = FRONTEND_ROOT) {
  const root = path.resolve(rootDirectory);
  const absolute = path.resolve(filePath);
  if (absolute === root || !absolute.startsWith(root + path.sep)) throw staticPathError();
  let initialRootStat;
  try {
    assertDirectoryTree(root, '静态文件根目录');
    assertDirectoryTree(path.dirname(absolute), '静态文件目录');
    initialRootStat = fs.lstatSync(root);
    if (!staticObjectOwnedAndReadonly(initialRootStat, 'directory')) throw staticPathError();
  } catch {
    throw staticPathError();
  }
  let realRoot;
  try { realRoot = fs.realpathSync(root); } catch { throw staticPathError(); }
  const expectedRealPath = path.resolve(realRoot, path.relative(root, absolute));

  let descriptor;
  try {
    const flags = fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0)
      | (fs.constants.O_NONBLOCK || 0);
    descriptor = fs.openSync(absolute, flags);
    const descriptorStat = fs.fstatSync(descriptor);
    if (!staticObjectOwnedAndReadonly(descriptorStat, 'file')) throw staticPathError();

    let realFile;
    try {
      // Resolve the object that was actually opened, not the pathname that an
      // attacker could swap after validation.
      realFile = fs.realpathSync('/proc/self/fd/' + descriptor);
    } catch {
      realFile = fs.realpathSync(absolute);
      const currentStat = fs.statSync(absolute);
      if (fs.realpathSync(root) !== realRoot
          || currentStat.dev !== descriptorStat.dev || currentStat.ino !== descriptorStat.ino) {
        throw staticPathError();
      }
    }
    if (realFile !== expectedRealPath) throw staticPathError();
    const latestRootStat = fs.lstatSync(root);
    if (!staticObjectOwnedAndReadonly(latestRootStat, 'directory')
        || !sameStaticObject(initialRootStat, latestRootStat)
        || fs.realpathSync(root) !== realRoot) {
      throw staticPathError();
    }
    return { descriptor, stat: descriptorStat };
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (error?.code === 'STATIC_PATH_INVALID') throw error;
    throw staticPathError();
  }
}

function normalizedSelectedKeys(value, options = {}) {
  if (!Array.isArray(value)) return null;
  if (value.length > 500) return null;
  if (value.some((item) => (
    typeof item !== 'string'
      || !item
      || item.length > 512
      || item.trim() !== item
  ))) return null;
  const allowEmpty = options.allowEmpty === true;
  if (value.length === 0 && !allowEmpty) return null;
  if (new Set(value).size !== value.length) return null;
  return [...value];
}

function requestBodyObjectError(body) {
  if (body && typeof body === 'object' && !Array.isArray(body)) return null;
  const error = new Error('请求体必须是 JSON 对象');
  error.code = 'INVALID_REQUEST_BODY';
  return error;
}

function normalizePhase3Requests(body) {
  const hasBatch = body && body.accounts !== undefined;
  const rawItems = hasBatch ? body.accounts : [body];
  if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > 100) {
    const error = new Error('Phase 3 至少需要一个账号，且单次最多提交 100 个账号');
    error.code = 'PHASE3_BATCH_INVALID';
    throw error;
  }
  const rawSelectedKeys = body?.selectedKeys;
  if (!Array.isArray(rawSelectedKeys)
      || rawSelectedKeys.length !== rawItems.length
      || rawSelectedKeys.some((value) => typeof value !== 'string')) {
    const error = new Error('selectedKeys 必须与 Phase 3 账号逐项对应');
    error.code = 'PHASE3_SELECTION_INVALID';
    throw error;
  }
  const selectedKeys = rawSelectedKeys.map(normalizePhase3SelectedKey);
  if (selectedKeys.some((value) => !value)
      || new Set(selectedKeys).size !== selectedKeys.length) {
    const error = new Error('Phase 3 账号选择键格式无效或重复');
    error.code = 'PHASE3_SELECTION_INVALID';
    throw error;
  }
  const requests = [];
  const duplicateIndexes = [];
  const seenKeys = new Set();
  const itemSelectedKeys = new Set();
  rawItems.forEach((rawItem, index) => {
    if (!rawItem || typeof rawItem !== 'object' || Array.isArray(rawItem)) {
      const error = new Error('Phase 3 账号项必须是对象');
      error.code = 'PHASE3_ACCOUNT_INVALID';
      throw error;
    }
    const selectedKey = normalizePhase3SelectedKey(rawItem.selectedKey);
    if (!selectedKey || itemSelectedKeys.has(selectedKey)
        || selectedKey !== selectedKeys[index]) {
      const error = new Error('每个 Phase 3 账号必须提供唯一的 selectedKey');
      error.code = 'PHASE3_SELECTION_INVALID';
      throw error;
    }
    itemSelectedKeys.add(selectedKey);
    const phase3TargetRevision = typeof rawItem.phase3TargetRevision === 'string'
      ? rawItem.phase3TargetRevision
      : '';
    if (!/^phase3-target-v1\.[A-Za-z0-9_-]{43}$/.test(phase3TargetRevision)) {
      const error = new Error('每个 Phase 3 账号必须提供当前快照的目标 revision');
      error.code = 'PHASE3_TARGET_REVISION_INVALID';
      throw error;
    }
    const identity = normalizePhase3Identity(rawItem);
    if (!identity) {
      const error = new Error('Phase 3 email 或 phone 格式或长度无效');
      error.code = 'PHASE3_ACCOUNT_INVALID';
      throw error;
    }
    const { email, phone, keys } = identity;
    if (keys.some((key) => seenKeys.has(key))) {
      duplicateIndexes.push(index);
      return;
    }
    keys.forEach((key) => seenKeys.add(key));
    requests.push({
      originalIndex: index,
      email,
      phone,
      selectedKey,
      phase3TargetRevision,
    });
  });
  if (requests.length === 0) {
    const error = new Error('Phase 3 账号均为重复项，未创建任务');
    error.code = 'PHASE3_BATCH_EMPTY';
    throw error;
  }
  return { requests, duplicateIndexes, selectedKeys };
}

function phase3ClaimKeys(requestItem = {}) {
  return canonicalPhase3Keys(requestItem).map((key) => 'phase3:' + key);
}

function safeExpiredTokenItem(item) {
  const output = {
    source: item.source,
    relativePath: item.relativePath,
    email: item.email || '',
    expiresAt: item.expiresAt || null,
    fingerprint: item.fingerprint || null,
    mtimeMs: item.mtimeMs || 0,
  };
  if (item.quarantinePath) output.quarantinePath = item.quarantinePath;
  if (item.reason) output.reason = item.reason;
  return output;
}

function boundedCleanupCount(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 && number <= 1_000_000
    ? number
    : 0;
}

function publicTokenCleanupErrorFields(publicCode, error) {
  if (publicCode === 'TOKEN_CLEANUP_STALE') {
    let currentVersion = null;
    try {
      if (typeof error?.currentVersion === 'string'
          && /^[a-f0-9]{64}$/.test(error.currentVersion)) {
        currentVersion = error.currentVersion;
      }
    } catch {}
    return currentVersion ? { currentVersion } : {};
  }
  if (publicCode === 'TOKEN_CLEANUP_RECOVERY_REQUIRED'
      || publicCode === 'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT') {
    let recoveryRequired = false;
    let claimCount = 0;
    let claimCountTruncated = false;
    try {
      recoveryRequired = error?.recoveryRequired === true;
      claimCount = boundedCleanupCount(error?.claimCount);
      claimCountTruncated = error?.claimCountTruncated === true;
    } catch {}
    return recoveryRequired
      ? { recoveryRequired, claimCount, claimCountTruncated }
      : {};
  }
  return {};
}

function tokenCleanupReviewTarget(item) {
  const source = safeReviewCode(item?.source, new Set(['tokens', 'use_token']));
  const sourcePath = source
    ? normalizedReviewSourcePath(source, item?.relativePath)
    : null;
  const contentHash = /^[a-f0-9]{64}$/i.test(String(item?.contentHash || ''))
    ? String(item.contentHash).toLowerCase()
    : null;
  if (!sourcePath || !contentHash) return null;
  return {
    sourcePath,
    contentHash,
    accessFingerprint: safeReviewFingerprint(item?.fingerprint) || undefined,
  };
}

function tokenCleanupJobPayload(listing) {
  const items = Array.isArray(listing?._internalItems) ? listing._internalItems : [];
  const targets = items.map(tokenCleanupReviewTarget).filter(Boolean);
  const targetCount = boundedCleanupCount(listing?.count);
  return {
    expectedVersion: /^[a-f0-9]{64}$/i.test(String(listing?.version || ''))
      ? String(listing.version).toLowerCase()
      : null,
    targetCount,
    reviewTargets: targets.slice(0, MAX_TOKEN_CLEANUP_REVIEW_TARGETS),
    reviewTargetsTruncated: targets.length !== targetCount
      || targets.length > MAX_TOKEN_CLEANUP_REVIEW_TARGETS,
  };
}

function tokenCleanupResultSummary(result) {
  const deletedCount = boundedCleanupCount(result?.count);
  const skippedItems = Array.isArray(result?.skipped) ? result.skipped : [];
  const skipped = boundedCleanupCount(skippedItems.length);
  const skippedByReason = {};
  for (const item of skippedItems.slice(0, 1_000_000)) {
    const reason = safeReviewCode(item?.reason);
    if (!reason || Object.keys(skippedByReason).length >= 32 && skippedByReason[reason] === undefined) {
      continue;
    }
    skippedByReason[reason] = boundedCleanupCount((skippedByReason[reason] || 0) + 1);
  }
  return {
    version: /^[a-f0-9]{64}$/i.test(String(result?.version || ''))
      ? String(result.version).toLowerCase()
      : null,
    outcome: skipped > 0 ? 'partial' : 'succeeded',
    succeeded: deletedCount,
    failed: 0,
    skipped,
    deletedCount,
    skippedCount: skipped,
    skippedByReason,
  };
}

function tokenCleanupFailureMetadata(error, completedResult = null) {
  const output = mutationFailureMetadata(error);
  const completedCount = completedResult
    ? boundedCleanupCount(completedResult.count)
    : boundedCleanupCount(error?.completedCount);
  const skippedCount = completedResult && Array.isArray(completedResult.skipped)
    ? boundedCleanupCount(completedResult.skipped.length)
    : boundedCleanupCount(error?.skippedCount);
  output.outcome = output.requiresReconciliation === true
    ? 'requires_reconciliation'
    : output.executionOutcome || 'failed';
  output.succeeded = completedCount;
  output.failed = 1;
  output.skipped = skippedCount;
  output.completedCount = completedCount;
  output.skippedCount = skippedCount;
  if (error?.reconciliationScope === 'expired_token_cleanup') {
    output.reconciliationScope = 'expired_token_cleanup';
  }
  const currentSource = safeReviewCode(error?.currentItem?.source, new Set(['tokens', 'use_token']));
  const currentSourcePath = currentSource
    ? normalizedReviewSourcePath(currentSource, error?.currentItem?.relativePath)
    : null;
  if (currentSourcePath) output.currentSourcePath = currentSourcePath;
  const recoveredCount = boundedCleanupCount(error?.recoveredCount);
  if (recoveredCount > 0) output.recoveredCount = recoveredCount;
  if (error?.recoveryRequired === true) {
    output.recoveryRequired = true;
    output.claimCount = boundedCleanupCount(error?.claimCount);
    output.claimCountTruncated = error?.claimCountTruncated === true;
  }
  const causeCode = safePhase3FailureCode(error?.causeCode);
  if (causeCode) output.causeCode = causeCode;
  return output;
}

function tokenCleanupReconciliationError(
  result,
  reason,
  code = 'TOKEN_CLEANUP_OUTCOME_UNKNOWN',
  cause = null,
) {
  const error = new Error('过期 token 清理结果需要人工核对，禁止自动重试');
  error.code = code;
  error.requiresReconciliation = true;
  error.writeOutcomeUnknown = true;
  error.retryAllowed = false;
  error.doNotRetry = true;
  error.reconciliationScope = 'expired_token_cleanup';
  error.reconciliationReason = reason;
  error.completedCount = result
    ? boundedCleanupCount(result.count)
    : boundedCleanupCount(cause?.completedCount);
  error.skippedCount = result
    ? boundedCleanupCount(result?.skipped?.length)
    : boundedCleanupCount(cause?.skippedCount);
  const causeCode = safePhase3FailureCode(cause?.code);
  if (causeCode) error.causeCode = causeCode;
  const currentSource = safeReviewCode(cause?.currentItem?.source, new Set(['tokens', 'use_token']));
  const currentRelativePath = currentSource
    ? normalizedReviewSourcePath(currentSource, cause?.currentItem?.relativePath)
    : null;
  if (currentRelativePath) {
    error.currentItem = {
      source: currentSource,
      relativePath: currentRelativePath,
    };
  }
  const recoveredCount = boundedCleanupCount(cause?.recoveredCount);
  if (recoveredCount > 0) error.recoveredCount = recoveredCount;
  return error;
}

function terminalUpdateOptions({ logger, event, requestId, jobId, actor }) {
  return {
    onRetry(error, attempt) {
      writeLog(logger, 'warn', event, {
        requestId,
        jobId,
        actor,
        attempt,
        error: safeErrorMessage(error),
      });
    },
  };
}

function serverAdmissionDispatchGuard({ db, jobManager, logger, requestId, actor, workflow }) {
  return createAdmissionDispatchGuard({
    db,
    jobManager,
    onRetry(error, attempt, context) {
      writeLog(logger, 'warn', 'job.admission_interrupt_retry', {
        requestId,
        actor,
        workflow,
        attempt,
        jobCount: context.jobIds.length,
        code: context.code,
        error: safeErrorMessage(error),
      });
    },
    onInterrupted(context) {
      writeLog(logger, 'warn', 'job.admission_interrupted_before_dispatch', {
        requestId,
        actor,
        workflow,
        jobCount: context.jobIds.length,
        code: context.code,
      });
    },
  });
}

function safePhase3FailureCode(value) {
  const code = typeof value === 'string' ? value.trim().toUpperCase() : '';
  return /^[A-Z0-9_]{1,96}$/.test(code) ? code : null;
}

function phase3FailureMetadata(error) {
  const output = {
    code: safePhase3FailureCode(error?.code),
    accountDisposition: error?.accountDisposition === 'discard' ? 'discard' : null,
  };
  if (error?.requiresReconciliation === true) output.requiresReconciliation = true;
  if (error?.writeOutcomeUnknown === true) output.writeOutcomeUnknown = true;
  if (error?.doNotRetry === true) output.doNotRetry = true;
  if (error?.retryAllowed === false) output.retryAllowed = false;
  if (PHASE3_RECONCILIATION_SCOPES.has(error?.reconciliationScope)) {
    output.reconciliationScope = error.reconciliationScope;
  }
  if (PHASE3_RECONCILIATION_REASONS.has(error?.reconciliationReason)) {
    output.reconciliationReason = error.reconciliationReason;
  }
  if (error?.dispositionPersisted === true
      || error?.dispositionPersisted === false
      || error?.dispositionPersisted === null) {
    output.dispositionPersisted = error.dispositionPersisted;
  }
  if (PHASE3_DISPOSITION_OUTCOMES.has(error?.dispositionOutcome)) {
    output.dispositionOutcome = error.dispositionOutcome;
  }
  if (error?.dispositionWriteOutcomeUnknown === true) {
    output.dispositionWriteOutcomeUnknown = true;
  } else if (error?.dispositionWriteOutcomeUnknown === false) {
    output.dispositionWriteOutcomeUnknown = false;
  }
  const dispositionCode = safePhase3FailureCode(error?.dispositionCode);
  if (dispositionCode) output.dispositionCode = dispositionCode;
  const dispositionErrorCode = safePhase3FailureCode(error?.dispositionErrorCode);
  if (dispositionErrorCode) output.dispositionErrorCode = dispositionErrorCode;
  return output;
}

function mutationFailureMetadata(error) {
  const output = { code: safePhase3FailureCode(error?.code) };
  if (error?.requiresReconciliation === true) output.requiresReconciliation = true;
  if (error?.writeOutcomeUnknown === true) output.writeOutcomeUnknown = true;
  if (error?.doNotRetry === true) output.doNotRetry = true;
  if (error?.retryAllowed === false) output.retryAllowed = false;
  if (error?.blockedBeforeStart === true) output.blockedBeforeStart = true;
  if (['not_started', 'unknown'].includes(error?.executionOutcome)) {
    output.executionOutcome = error.executionOutcome;
  }
  const reconciliationReason = typeof error?.reconciliationReason === 'string'
    ? error.reconciliationReason.trim().toLowerCase()
    : '';
  if (/^[a-z0-9_]{1,64}$/.test(reconciliationReason)) {
    output.reconciliationReason = reconciliationReason;
  }
  if (error?.criticalSectionCompleted === true) output.criticalSectionCompleted = true;
  if (error?.controlPlaneLeaseReleaseFailed === true) {
    output.controlPlaneLeaseReleaseFailed = true;
  }
  return output;
}

function observeTokenCleanupJob({
  job,
  expectedVersion,
  actor,
  db,
  logger,
  requestId,
  jobManager = null,
  taskRecord = null,
}) {
  const tracked = taskRecord || jobManager?.begin(job, TOKEN_CLEANUP_JOB_TYPE, actor) || null;
  let terminalPersisted = false;
  let completedResult = null;
  let mutationBoundaryEntered = false;
  const terminalOptions = terminalUpdateOptions({
    logger,
    event: 'token_cleanup.job_update_retry',
    requestId,
    jobId: job.id,
    actor,
  });
  const persistFailure = async (error) => {
    const result = tokenCleanupFailureMetadata(error, completedResult);
    const interrupted = error?.code === 'JOB_INTERRUPTED'
      || tracked?.controller.signal.aborted === true;
    const status = result.requiresReconciliation === true && result.completedCount > 0
      ? 'partial'
      : interrupted && result.requiresReconciliation !== true
        ? 'interrupted'
        : 'failed';
    await updateTerminalJob(db, job.id, {
      status,
      error: safeErrorMessage(error),
      result,
      finishedAt: new Date().toISOString(),
    }, terminalOptions);
    terminalPersisted = true;
    return { status, result };
  };
  const persistSuccess = async (result) => {
    const status = result.skipped > 0 ? 'partial' : 'succeeded';
    await updateTerminalJob(db, job.id, {
      status,
      result,
      finishedAt: new Date().toISOString(),
    }, terminalOptions);
    terminalPersisted = true;
    return status;
  };

  const observation = Promise.resolve().then(async () => {
    let finalSummary = null;
    try {
      finalSummary = await withControlPlaneLock(async () => {
        try {
          throwIfJobInterrupted(tracked?.controller.signal);
          if (!db || typeof db.startMutationJob !== 'function'
              || typeof db.updateJob !== 'function'
              || typeof db.audit !== 'function') {
            const error = new Error('token 清理任务持久化安全检查不可用，未修改任何文件');
            error.code = 'JOB_RECONCILIATION_GUARD_UNAVAILABLE';
            throw error;
          }
          await db.startMutationJob(job.id);
          throwIfJobInterrupted(tracked?.controller.signal);
          try {
            await db.audit({
              jobId: job.id,
              actor,
              action: 'expired_token_cleanup',
              targetKey: 'gpt_register:expired_tokens',
              result: 'intent',
              details: {
                requestId,
                expectedVersion,
              },
            });
          } catch {
            const error = new Error('过期 token 删除审计意图无法持久化，未修改任何 token 文件');
            error.code = 'TOKEN_CLEANUP_AUDIT_INTENT_FAILED';
            throw error;
          }
          throwIfJobInterrupted(tracked?.controller.signal);
          const result = deleteExpiredTokens({
            expectedVersion,
            confirmation: TOKEN_CLEANUP_CONFIRMATION,
            signal: tracked?.controller.signal,
            beforeMutation() {
              assertAuditLogCheckpoint(logger, 'token_cleanup.mutation_checkpoint', {
                requestId,
                jobId: job.id,
                actor,
                expectedVersion,
              });
              mutationBoundaryEntered = true;
            },
          });
          completedResult = result;
          const summary = tokenCleanupResultSummary(result);
          let databaseAuditFailed = false;
          try {
            await db.audit({
              jobId: job.id,
              actor,
              action: 'expired_token_cleanup',
              targetKey: 'gpt_register:expired_tokens',
              result: result.skipped.length > 0 ? 'partial' : 'ok',
              details: {
                requestId,
                version: summary.version,
                deletedCount: summary.deletedCount,
                skippedCount: summary.skippedCount,
                skippedByReason: summary.skippedByReason,
              },
            });
          } catch (auditError) {
            databaseAuditFailed = true;
            writeLog(logger, 'error', 'token_cleanup.audit_failed_after_mutation', {
              requestId,
              jobId: job.id,
              actor,
              error: safeErrorMessage(auditError),
            });
          }
          let logCheckpointFailed = false;
          try {
            assertAuditLogCheckpoint(logger, 'token_cleanup.mutation_completed', {
              requestId,
              jobId: job.id,
              actor,
              deletedCount: summary.deletedCount,
              skippedCount: summary.skippedCount,
              databaseAuditFailed,
            });
          } catch {
            logCheckpointFailed = true;
          }
          if (databaseAuditFailed || logCheckpointFailed) {
            throw tokenCleanupReconciliationError(
              result,
              databaseAuditFailed && logCheckpointFailed
                ? 'completion_audit_unavailable'
                : databaseAuditFailed
                  ? 'completion_database_audit_unavailable'
                  : 'completion_log_checkpoint_unavailable',
              'TOKEN_CLEANUP_AUDIT_RECONCILIATION_REQUIRED',
            );
          }
          // Keep the running claim until the cross-process lease has been
          // released. A crash or ambiguous lease release in this narrow gap is
          // recovered as an unknown running job, never as a retryable success.
          return summary;
        } catch (error) {
          let terminalError = error;
          if ((completedResult || mutationBoundaryEntered)
              && error?.requiresReconciliation !== true
              && error?.writeOutcomeUnknown !== true) {
            terminalError = tokenCleanupReconciliationError(
              completedResult,
              completedResult ? 'post_mutation_failure' : 'mutation_boundary_failure',
              'TOKEN_CLEANUP_OUTCOME_UNKNOWN',
              error,
            );
          }
          if (!terminalPersisted) {
            try {
              await persistFailure(terminalError);
            } catch (jobError) {
              writeLog(logger, 'error', 'token_cleanup.job_update_deferred', {
                requestId,
                jobId: job.id,
                actor,
                terminalOutcome: 'failed',
                error: safeErrorMessage(jobError),
              });
            }
          }
          throw terminalError;
        }
      }, { signal: tracked?.controller.signal });

      try {
        const status = await persistSuccess(finalSummary);
        writeLog(logger, status === 'succeeded' ? 'info' : 'warn', 'token_cleanup.job_completed', {
          requestId,
          jobId: job.id,
          actor,
          status,
          deletedCount: finalSummary.deletedCount,
          skippedCount: finalSummary.skippedCount,
        });
      } catch (jobError) {
        const terminalError = tokenCleanupReconciliationError(
          completedResult,
          'terminal_persistence_unavailable',
          'TOKEN_CLEANUP_TERMINAL_PERSISTENCE_UNKNOWN',
          jobError,
        );
        try {
          await persistFailure(terminalError);
        } catch (retryError) {
          writeLog(logger, 'error', 'token_cleanup.job_update_failed_after_completion', {
            requestId,
            jobId: job.id,
            actor,
            error: safeErrorMessage(retryError),
          });
        }
        writeLog(logger, 'error', 'token_cleanup.job_completion_persistence_unknown', {
          requestId,
          jobId: job.id,
          actor,
          error: safeErrorMessage(jobError),
        });
      }
    } catch (error) {
      let terminalError = error;
      if ((completedResult || mutationBoundaryEntered)
          && error?.requiresReconciliation !== true
          && error?.writeOutcomeUnknown !== true) {
        terminalError = tokenCleanupReconciliationError(
          completedResult,
          completedResult ? 'control_plane_completion_unknown' : 'mutation_boundary_failure',
          'TOKEN_CLEANUP_OUTCOME_UNKNOWN',
          error,
        );
      }
      if (!terminalPersisted) {
        try {
          await persistFailure(terminalError);
        } catch (jobError) {
          writeLog(logger, 'error', 'token_cleanup.job_update_failed', {
            requestId,
            jobId: job.id,
            actor,
            error: safeErrorMessage(jobError),
          });
        }
      }
      writeLog(logger, terminalError?.requiresReconciliation === true ? 'warn' : 'error',
        terminalError?.requiresReconciliation === true
          ? 'token_cleanup.job_reconciliation_required'
          : 'token_cleanup.job_failed', {
          requestId,
          jobId: job.id,
          actor,
          code: terminalError?.code || null,
          error: safeErrorMessage(terminalError),
        });
    }
  });
  return tracked && jobManager ? jobManager.track(tracked, observation) : observation;
}

function observePhase3Job({
  job,
  email,
  phone,
  canonicalKeys,
  executionBinding,
  actor,
  db,
  logger,
  requestId,
  jobManager = null,
  taskRecord = null,
}) {
  const tracked = taskRecord || jobManager?.begin(job, 'phase3', actor) || null;
  let successPersisted = false;
  let failurePersisted = false;
  const persistSuccess = async (result) => {
    await updateTerminalJob(db, job.id, {
      status: 'succeeded',
      result,
      finishedAt: new Date().toISOString(),
    }, terminalUpdateOptions({
      logger,
      event: 'phase3.job_update_retry',
      requestId,
      jobId: job.id,
      actor,
    }));
    successPersisted = true;
  };
  const persistFailure = async (error) => {
    const interrupted = error?.code === 'JOB_INTERRUPTED'
      || tracked?.controller.signal.aborted === true;
    await updateTerminalJob(db, job.id, {
      status: interrupted ? 'interrupted' : 'failed',
      error: safeErrorMessage(error),
      result: phase3FailureMetadata(error),
      finishedAt: new Date().toISOString(),
    }, terminalUpdateOptions({
      logger,
      event: 'phase3.job_update_retry',
      requestId,
      jobId: job.id,
      actor,
    }));
    failurePersisted = true;
  };
  const observation = runPhase3Job({
    email,
    phone,
    canonicalKeys,
    executionBinding,
    requireExecutionBinding: true,
    actor,
    db,
    jobId: job.id,
    logger,
    signal: tracked?.controller.signal || null,
    persistSuccess,
    persistFailure,
  })
    .then(async (result) => {
      if (!successPersisted) try {
        await persistSuccess(result);
      } catch (jobError) {
        writeLog(logger, 'error', 'phase3.job_update_failed_after_completion', {
          requestId,
          jobId: job.id,
          actor,
          error: safeErrorMessage(jobError),
        });
      }
      writeLog(logger, 'info', 'phase3.job_completed', {
        requestId,
        jobId: job.id,
        actor,
        email: result.email,
        tokenFile: result.tokenFile,
        fingerprint: result.fingerprint,
      });
    })
    .catch(async (error) => {
      const message = safeErrorMessage(error);
      const failureMetadata = phase3FailureMetadata(error);
      const interrupted = error?.code === 'JOB_INTERRUPTED'
        || tracked?.controller.signal.aborted === true;
      if (!successPersisted && !failurePersisted) try {
        await persistFailure(error);
      } catch (jobError) {
        writeLog(logger, 'error', 'phase3.job_update_failed', {
          requestId,
          jobId: job.id,
          actor,
          error: safeErrorMessage(jobError),
        });
      }
      try {
        await db.audit({
          jobId: job.id,
          actor,
          action: 'phase3',
          result: interrupted ? 'interrupted' : 'failed',
          details: {
            error: message,
            ...failureMetadata,
          },
        });
      } catch (auditError) {
        writeLog(logger, 'error', 'phase3.audit_failed', {
          requestId,
          jobId: job.id,
          actor,
          error: safeErrorMessage(auditError),
        });
      }
      writeLog(logger, interrupted ? 'warn' : 'error', interrupted
        ? 'phase3.job_interrupted'
        : 'phase3.job_failed', {
        requestId,
        jobId: job.id,
        actor,
        error: message,
        ...failureMetadata,
      });
    });
  return tracked && jobManager ? jobManager.track(tracked, observation) : observation;
}

function observeAccountTestJob({
  job,
  accountIds,
  targetBaselines,
  modelId,
  prompt,
  actor,
  db,
  logger,
  requestId,
  jobManager = null,
  taskRecord = null,
}) {
  const tracked = taskRecord || jobManager?.begin(job, 'account_test', actor) || null;
  let resultPersisted = false;
  let failurePersisted = false;
  const persistResult = async (result) => {
    const status = accountTestJobStatus(result);
    await updateTerminalJob(db, job.id, {
      status,
      result,
      finishedAt: new Date().toISOString(),
    }, terminalUpdateOptions({
      logger,
      event: 'account_test.job_update_retry',
      requestId,
      jobId: job.id,
      actor,
    }));
    resultPersisted = true;
  };
  const persistFailure = async (error) => {
    const interrupted = error?.code === 'JOB_INTERRUPTED'
      || tracked?.controller.signal.aborted === true;
    await updateTerminalJob(db, job.id, {
      status: interrupted ? 'interrupted' : 'failed',
      error: safeAccountTestErrorMessage(error),
      result: mutationFailureMetadata(error),
      finishedAt: new Date().toISOString(),
    }, terminalUpdateOptions({
      logger,
      event: 'account_test.job_update_retry',
      requestId,
      jobId: job.id,
      actor,
    }));
    failurePersisted = true;
  };
  const observation = runAccountTestJob({
    accountIds,
    targetBaselines,
    modelId,
    prompt,
    actor,
    db,
    jobId: job.id,
    logger,
    signal: tracked?.controller.signal || null,
    persistResult,
    persistFailure,
  }).then(async (result) => {
    const status = accountTestJobStatus(result);
    if (!resultPersisted) try {
      await persistResult(result);
    } catch (jobError) {
      writeLog(logger, 'error', 'account_test.job_update_failed_after_completion', {
        requestId,
        jobId: job.id,
        actor,
        status,
        error: safeErrorMessage(jobError),
      });
    }
    writeLog(logger, status === 'succeeded' ? 'info' : 'warn', 'account_test.job_completed', {
      requestId,
      jobId: job.id,
      actor,
      status,
      requested: result.requested,
      succeeded: result.succeeded,
      failed: result.failed,
      skipped: result.skipped,
      durationMs: result.durationMs,
    });
  }).catch(async (error) => {
    const message = safeAccountTestErrorMessage(error);
    const interrupted = error?.code === 'JOB_INTERRUPTED'
      || tracked?.controller.signal.aborted === true;
    if (!resultPersisted && !failurePersisted) try {
      await persistFailure(error);
    } catch (jobError) {
      writeLog(logger, 'error', 'account_test.job_update_failed', {
        requestId,
        jobId: job.id,
        actor,
        error: safeErrorMessage(jobError),
      });
    }
    try {
      await db.audit({
        jobId: job.id,
        actor,
        action: 'account_test',
        result: interrupted ? 'interrupted' : 'failed',
        details: { error: message, code: error?.code || null },
      });
    } catch (auditError) {
      writeLog(logger, 'error', 'account_test.audit_failed', {
        requestId,
        jobId: job.id,
        actor,
        error: safeErrorMessage(auditError),
      });
    }
    writeLog(logger, interrupted ? 'warn' : 'error', interrupted
      ? 'account_test.job_interrupted'
      : 'account_test.job_failed', {
      requestId,
      jobId: job.id,
      actor,
      error: message,
    });
  });
  return tracked && jobManager ? jobManager.track(tracked, observation) : observation;
}

function tokenImportJobStatus(result = {}) {
  const imported = Array.isArray(result.imported) ? result.imported : [];
  const derivedFailed = imported.filter((item) => Boolean(item?.error)).length;
  const skipped = imported.filter((item) => !item?.error
    && (item?.skipped === true || item?.action === 'skip')).length;
  const reportedFailed = Number(result.failed);
  const failed = Math.max(derivedFailed, Number.isSafeInteger(reportedFailed) && reportedFailed > 0
    ? reportedFailed
    : 0);
  const reportedSucceeded = Number(result.succeeded);
  const succeeded = imported.length > 0
    ? Math.max(0, imported.length - derivedFailed - skipped)
    : (Number.isSafeInteger(reportedSucceeded) && reportedSucceeded > 0 ? reportedSucceeded : 0);
  return failed > 0 ? (succeeded > 0 ? 'partial' : 'failed') : 'succeeded';
}

function observeImportJob({
  job,
  snapshotVersion,
  planIntentVersion,
  selectedKeys,
  actor,
  db,
  logger,
  requestId,
  jobManager,
  taskRecord,
}) {
  const tracked = taskRecord || jobManager?.begin(job, 'token_import', actor) || null;
  let resultPersisted = false;
  let failurePersisted = false;
  const persistImportResult = async (result) => {
    const status = tokenImportJobStatus(result);
    await updateTerminalJob(db, job.id, {
      status,
      result,
      finishedAt: new Date().toISOString(),
    }, terminalUpdateOptions({
      logger,
      event: 'import.job_update_retry',
      requestId,
      jobId: job.id,
      actor,
    }));
    resultPersisted = true;
  };
  const persistImportFailure = async (error) => {
    const interrupted = error?.code === 'JOB_INTERRUPTED'
      || tracked?.controller.signal.aborted === true;
    await updateTerminalJob(db, job.id, {
      status: interrupted ? 'interrupted' : 'failed',
      error: safeErrorMessage(error),
      result: mutationFailureMetadata(error),
      finishedAt: new Date().toISOString(),
    }, terminalUpdateOptions({
      logger,
      event: 'import.job_update_retry',
      requestId,
      jobId: job.id,
      actor,
    }));
    failurePersisted = true;
  };
  const observation = Promise.resolve().then(() => {
    throwIfJobInterrupted(tracked?.controller.signal);
    return executeImport({
      snapshotVersion,
      planIntentVersion,
      selectedKeys,
      actor,
      db,
      jobId: job.id,
      logger,
      signal: tracked?.controller.signal || null,
      persistResult: persistImportResult,
      persistFailure: persistImportFailure,
    });
  }).then(async (result) => {
    const status = tokenImportJobStatus(result);
    if (!resultPersisted && !failurePersisted) try {
      await persistImportResult(result);
    } catch (jobError) {
      // The remote operation has already completed. Keep that outcome in logs
      // instead of relabeling a successful remote write as a failed import.
      writeLog(logger, 'error', 'import.job_update_failed_after_completion', {
        requestId,
        jobId: job.id,
        actor,
        status,
        error: safeErrorMessage(jobError),
      });
    }
    writeLog(logger, status === 'succeeded' ? 'info' : 'warn', 'import.job_completed', {
      requestId,
      jobId: job.id,
      actor,
      status,
      importedCount: result.imported?.length || 0,
      failed: result.failed || 0,
    });
  }).catch(async (error) => {
    const message = safeErrorMessage(error);
    const interrupted = error?.code === 'JOB_INTERRUPTED'
      || tracked?.controller.signal.aborted === true;
    if (!resultPersisted && !failurePersisted) try {
      await persistImportFailure(error);
    } catch (jobError) {
      writeLog(logger, 'error', 'import.job_update_failed', {
        requestId,
        jobId: job.id,
        actor,
        error: safeErrorMessage(jobError),
      });
    }
    try {
      await db.audit({
        jobId: job.id,
        actor,
        action: 'token_import',
        result: interrupted ? 'interrupted' : 'failed',
        details: { error: message },
      });
    } catch (auditError) {
      writeLog(logger, 'error', 'import.audit_failed', {
        requestId,
        jobId: job.id,
        actor,
        error: safeErrorMessage(auditError),
      });
    }
    writeLog(logger, interrupted ? 'warn' : 'error', interrupted
      ? 'import.job_interrupted'
      : 'import.job_failed', {
      requestId,
      jobId: job.id,
      actor,
      error: message,
    });
  });
  return tracked && jobManager ? jobManager.track(tracked, observation) : observation;
}

function importRequestError(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    const error = new Error('请求体必须是 JSON 对象');
    error.code = 'INVALID_REQUEST_BODY';
    return error;
  }
  if (!/^[a-f0-9]{64}$/i.test(String(body.snapshotVersion || ''))) {
    const error = new Error('缺少有效的差异快照版本，请先执行“检查差异”');
    error.code = 'SNAPSHOT_VERSION_REQUIRED';
    return error;
  }
  if (!isImportPlanIntentVersion(body.planIntentVersion)) {
    const error = new Error('缺少有效的导入计划版本，请重新检查差异');
    error.code = 'IMPORT_PLAN_VERSION_REQUIRED';
    return error;
  }
  const selectedKeys = normalizedSelectedKeys(body.selectedKeys);
  if (!selectedKeys) {
    const error = new Error('必须选择至少一个账号后才能导入');
    error.code = 'IMPORT_SELECTION_REQUIRED';
    return error;
  }
  return null;
}

function serveStatic(pathname, response) {
  const filePath = safeStaticPath(pathname);
  let opened;
  try { opened = filePath ? openVerifiedStaticFile(filePath) : null; } catch {}
  if (!opened) {
    jsonResponse(response, 404, { error: 'not_found' });
    return;
  }
  const extension = path.extname(filePath).toLowerCase();
  response.writeHead(200, {
    'content-type': CONTENT_TYPES[extension] || 'application/octet-stream',
    'cache-control': 'no-cache',
    'x-content-type-options': 'nosniff',
    'content-security-policy': CONTENT_SECURITY_POLICY,
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
  });
  let stream;
  try {
    stream = fs.createReadStream(filePath, { fd: opened.descriptor, autoClose: true });
  } catch {
    try { fs.closeSync(opened.descriptor); } catch {}
    if (!response.writableEnded) response.destroy();
    return;
  }
  stream.once('error', () => {
    if (!response.headersSent) jsonResponse(response, 404, { error: 'not_found' });
    else if (!response.writableEnded) response.destroy();
  });
  stream.pipe(response);
}

function createServer(options = {}) {
  validateRuntimeConfiguration();
  const db = options.db || new PanelDb(options.dbPath);
  const logger = options.logger || createLogger({ dbPath: options.dbPath || db.dbPath });
  const jobManager = options.jobManager || createBackgroundJobManager({ db });
  // Narrow injection points keep replay-order tests deterministic without
  // weakening the production path. These callbacks are consulted only after
  // the second durable receipt lookup inside the cross-process control lock.
  const phase3RequestResolver = options.phase3RequestResolver || resolvePhase3Requests;
  const accountTestClientFactory = options.accountTestClientFactory
    || ((clientOptions) => new Sub2ApiAdminClient(clientOptions));
  const syncClientFactory = options.syncClientFactory
    || ((clientOptions) => new Sub2ApiAdminClient(clientOptions));
  const expiredTokenLister = options.expiredTokenLister || listExpiredTokens;
  const admissionControlPlaneLock = options.admissionControlPlaneLock || withControlPlaneLock;
  let server;
  server = http.createServer(async (request, response) => {
    const requestId = typeof logger.requestId === 'function'
      ? logger.requestId(request.headers['x-request-id'])
      : crypto.randomUUID();
    const actor = requestActor(request);
    const startedAt = Date.now();
    let requestPath = '<unknown-path>';
    let completed = false;
    const requestDisconnectController = new AbortController();
    // Admission is still reversible: its dispatch guard can interrupt a row
    // proven not to have started. Once dispatch returns, the background job's
    // own controller remains authoritative and a lost HTTP response must not
    // cancel work that may already have crossed an external-write boundary.
    const withRequestAdmission = (callback) => jobManager.withAdmission((admissionSignal) => (
      withCombinedAbortSignal(
        [admissionSignal, requestDisconnectController.signal],
        callback,
      )
    ));
    response.setHeader('x-request-id', requestId);
    response.once('finish', () => {
      completed = true;
      writeLog(logger, 'info', 'http.request_completed', {
        requestId,
        actor,
        method: request.method,
        path: requestPath,
        statusCode: response.statusCode,
        durationMs: Date.now() - startedAt,
      });
    });
    response.once('close', () => {
      if (!completed) {
        requestDisconnectController.abort();
        writeLog(logger, 'warn', 'http.request_closed', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
          statusCode: response.statusCode,
          durationMs: Date.now() - startedAt,
        });
      }
    });
    let parsedRequestUrl = null;
    try {
      parsedRequestUrl = parseRequestTarget(request.url);
      requestPath = requestLogPath(parsedRequestUrl.pathname);
    } catch {}
    writeLog(logger, 'info', 'http.request_started', {
      requestId,
      actor,
      method: request.method,
      path: requestPath,
    });
    try {
      const requestUrl = parsedRequestUrl || parseRequestTarget(request.url);
      requestPath = requestLogPath(requestUrl.pathname);
      const reconciliationAckPath = reconciliationAcknowledgePath(requestUrl.pathname);
      const reconciliationReviewRoute = reconciliationReviewPath(requestUrl.pathname);
      const allowedMethod = allowedRequestMethod(
        requestUrl.pathname,
        reconciliationAckPath,
        reconciliationReviewRoute,
      );
      if (jobManager.shuttingDown) {
        response.setHeader('connection', 'close');
        jsonResponse(response, 503, {
          error: 'JOB_INTERRUPTED',
          message: '面板服务正在停止，请稍后重试',
        });
        return;
      }
      const requiresWrite = request.method === 'POST'
        && (reconciliationAckPath.matched
          || ['/api/sync/import', '/api/phase3', '/api/tokens/expired/delete', '/api/account-tests'].includes(requestUrl.pathname));
      const authError = requestUrl.pathname.startsWith('/api/')
        ? authorizationError(request, requiresWrite)
        : null;
      if (authError) {
        writeLog(logger, 'warn', 'http.auth_failed', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
          statusCode: authError.status,
          error: authError.error,
        });
        if (authError.retryAfterSeconds) response.setHeader('retry-after', String(authError.retryAfterSeconds));
        jsonResponse(response, authError.status, authError);
        return;
      }
      if (allowedMethod && request.method !== allowedMethod) {
        writeLog(logger, 'warn', 'http.method_not_allowed', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
          allowedMethod,
        });
        response.setHeader('allow', allowedMethod);
        jsonResponse(response, 405, {
          error: 'method_not_allowed',
          message: '该接口只允许 ' + allowedMethod + ' 请求',
        });
        return;
      }
      if (request.method === 'POST'
          && (JSON_BODY_ENDPOINTS.has(requestUrl.pathname) || reconciliationAckPath.matched)
          && !hasJsonContentType(request)) {
        writeLog(logger, 'warn', 'http.unsupported_media_type', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
        });
        jsonResponse(response, 415, {
          error: 'json_content_type_required',
          message: '该接口只接受 application/json 请求',
        });
        return;
      }
      // A mutating workflow without a writable audit sink would violate the
      // panel's recovery trail. Probe only after authentication and basic
      // method/content-type checks so unauthenticated traffic cannot amplify
      // disk writes.
      if (requiresWrite && typeof logger.probe === 'function' && !logger.probe()) {
        writeLog(logger, 'error', 'http.write_blocked_without_audit_log', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
        });
        jsonResponse(response, 503, {
          error: 'audit_log_unavailable',
          message: '审计日志不可写，已拒绝写操作',
        });
        return;
      }

    if (requestUrl.pathname === '/api/health') {
      if (request.method !== 'GET') {
        writeLog(logger, 'warn', 'http.method_not_allowed', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
        });
        response.setHeader('allow', 'GET');
        jsonResponse(response, 405, { error: 'read_only_endpoint' });
        return;
      }
      jsonResponse(response, 200, {
        ok: true,
        readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
        sub2apiConfigured: configuredForSub2Api(),
        authConfigured: Boolean(configuredPanelToken()),
        auditLog: typeof logger.health === 'function'
          ? logger.health()
          : { healthy: null },
        time: new Date().toISOString(),
      });
      return;
    }

    if (requestUrl.pathname === '/api/snapshot') {
      if (request.method !== 'GET') {
        writeLog(logger, 'warn', 'http.method_not_allowed', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
        });
        response.setHeader('allow', 'GET');
        jsonResponse(response, 405, { error: 'read_only_endpoint' });
        return;
      }
      try {
        const snapshot = await buildSnapshot(requestUrl.searchParams, {
          logger,
          requestId,
          actor,
          // A missing token directory or damaged username file is not an
          // empty account set. Refuse the comparison instead of presenting a
          // misleading wave of Sub2API-only rows.
          requireCompleteSources: true,
        });
        jsonResponse(response, 200, {
          ...snapshot,
          capabilities: {
            phase3Enabled: booleanEnvEnabled('PANEL_PHASE3_ENABLED', false),
          },
        });
      } catch (error) {
        writeLog(logger, 'error', 'http.snapshot_failed', {
          requestId,
          actor,
          error: safeHttpErrorMessage(error),
        });
        sendPublicApiError(response, error, {
          fallbackCode: 'snapshot_failed',
          fallbackMessage: '账号快照读取失败，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/sync/preview') {
      const previewStartedAt = Date.now();
      writeLog(logger, 'info', 'preview.started', { requestId, actor });
      try {
        const body = await readJsonBody(request);
        const bodyError = requestBodyObjectError(body);
        if (bodyError) throw bodyError;
        if (body.selectedKeys !== undefined && body.selectedKeys !== null
            && !Array.isArray(body.selectedKeys)) {
          const error = new Error('selectedKeys 必须是数组');
          error.code = 'IMPORT_SELECTION_INVALID';
          throw error;
        }
        const selectedKeys = body.selectedKeys === undefined || body.selectedKeys === null
          ? []
          : normalizedSelectedKeys(body.selectedKeys, { allowEmpty: true });
        if (body.selectedKeys !== undefined && !selectedKeys) {
          const error = new Error('selectedKeys 必须包含有效的账号键');
          error.code = 'IMPORT_SELECTION_INVALID';
          throw error;
        }
        let syncClient = null;
        const getSyncClient = (clientOptions = {}) => {
          if (!syncClient) syncClient = syncClientFactory(clientOptions);
          return syncClient;
        };
        const snapshot = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
          includeRaw: true,
          includeInternal: true,
          requireCompleteSources: true,
          logger,
          requestId,
          actor,
          clientFactory: getSyncClient,
        });
        if (!confirmedSub2ApiRead(snapshot)) {
          const error = new Error('无法确认 Sub2API 当前账号列表，已停止生成导入计划');
          error.code = 'SUB2API_READ_FAILED';
          throw error;
        }
        const plan = buildImportPlan(snapshot._internal.sources, snapshot._internal.accounts, selectedKeys);
        const client = getSyncClient({ logger, logContext: { requestId, actor } });
        const groupBinding = await resolveImportGroupBinding(client, plan);
        const executionBinding = resolveImportExecutionBinding(client, plan);
        const planIntentVersion = buildImportPlanIntentVersion(
          snapshot.version,
          selectedKeys,
          plan,
          groupBinding,
          executionBinding,
        );
        const snapshotId = await db.saveSnapshot(snapshot);
        writeLog(logger, 'info', 'preview.completed', {
          requestId,
          actor,
          snapshotId,
          version: snapshot.version,
          planIntentVersion,
          groupBinding,
          durationMs: Date.now() - previewStartedAt,
          counts: importPlanSummary(plan).counts,
        });
        jsonResponse(response, 200, {
          readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
          snapshotId,
          version: snapshot.version,
          planIntentVersion,
          groupBinding,
          generatedAt: snapshot.generatedAt,
          selectedKeys,
          ...importPlanSummary(plan),
        });
      } catch (error) {
        writeLog(logger, 'error', 'preview.failed', {
          requestId,
          actor,
          durationMs: Date.now() - previewStartedAt,
          error: safeHttpErrorMessage(error),
        });
        sendPublicApiError(response, error, {
          fallbackCode: 'preview_failed',
          fallbackMessage: '差异预览未能安全完成，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/sync/import') {
      const importRequestStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        const requestError = importRequestError(body);
        if (requestError) throw requestError;
        const selectedKeys = normalizedSelectedKeys(body.selectedKeys);
        const normalizedSnapshotVersion = String(body.snapshotVersion).toLowerCase();
        const planIntentVersion = body.planIntentVersion;
        const idempotency = mutationContext(request, MUTATION_WORKFLOWS.import, {
          snapshotVersion: normalizedSnapshotVersion,
          planIntentVersion,
          selectedKeys,
        });
        const priorReceipt = await existingMutationReceipt(db, idempotency, actor);
        if (priorReceipt) {
          writeLog(logger, 'info', 'import.request_replayed', { requestId, actor });
          sendMutationReceipt(response, priorReceipt, true);
          return;
        }
        const dispatchGuard = serverAdmissionDispatchGuard({
          db,
          jobManager,
          logger,
          requestId,
          actor,
          workflow: MUTATION_WORKFLOWS.import,
        });
        const { submission, job } = await withRequestAdmission((signal) => (
          dispatchGuard.run(async ({ recordCommitted, dispatch }) => {
            const created = await admissionControlPlaneLock(async () => {
              throwIfJobInterrupted(signal);
              const lockedReceipt = await existingMutationReceipt(db, idempotency, actor);
              if (lockedReceipt) {
                return { receipt: lockedReceipt, replayed: true, createdJobs: [], rejections: [] };
              }
              const createdSubmission = await db.createMutationSubmission({
                ...idempotency,
                requestedBy: actor,
                jobs: [{
                  type: 'token_import',
                  payload: {
                    snapshotVersion: normalizedSnapshotVersion,
                    planIntentVersion,
                    selectedKeys,
                    // Keep a separately validated, non-secret display path because
                    // generic text redaction intentionally masks `token:...` values.
                    selectedSourcePaths: selectedKeys
                      .map(sourcePathFromSelectionKey)
                      .filter(Boolean),
                  },
                  claimKeys: ['token_import'],
                }],
                responseFactory: ({ createdJobs }) => ({
                  jobId: createdJobs[0].job.id,
                  status: 'queued',
                }),
              });
              if (!createdSubmission.replayed) {
                recordCommitted(createdSubmission.createdJobs);
              }
              throwIfJobInterrupted(signal);
              return createdSubmission;
            }, { signal });
            if (created.replayed) return { submission: created, job: null };
            const createdJob = created.createdJobs[0]?.job;
            if (!createdJob) {
              const error = new Error('导入任务未能原子入队');
              error.code = 'IDEMPOTENCY_RECEIPT_INVALID';
              throw error;
            }
            throwIfJobInterrupted(signal);
            writeLog(logger, 'info', 'import.job_queued', {
              requestId,
              jobId: createdJob.id,
              actor,
              expectedVersion: normalizedSnapshotVersion,
              planIntentVersion,
              selectedCount: selectedKeys.length,
              durationMs: Date.now() - importRequestStartedAt,
            });
            dispatch(createdJob, 'token_import', actor, (taskRecord) => observeImportJob({
              job: createdJob,
              snapshotVersion: normalizedSnapshotVersion,
              planIntentVersion,
              selectedKeys,
              actor,
              db,
              logger,
              requestId,
              jobManager,
              taskRecord,
            }));
            return { submission: created, job: createdJob };
          })
        ));
        if (submission.replayed) {
          writeLog(logger, 'info', 'import.request_replayed', { requestId, actor });
          sendMutationReceipt(response, submission.receipt, true);
          return;
        }
        sendMutationReceipt(response, submission.receipt, false);
      } catch (error) {
        writeLog(logger, 'error', 'import.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - importRequestStartedAt,
          error: safeHttpErrorMessage(error),
        });
        sendPublicApiError(response, error, {
          write: true,
          fallbackCode: 'import_failed',
          fallbackMessage: '导入请求未能安全完成，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/phase3') {
      const phase3RequestStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        const bodyError = requestBodyObjectError(body);
        if (bodyError) throw bodyError;
        const {
          requests,
          duplicateIndexes,
          selectedKeys: normalizedSelectedKeys,
        } = normalizePhase3Requests(body);
        const idempotency = mutationContext(request, MUTATION_WORKFLOWS.phase3, {
          accounts: requests.map((item) => ({
            originalIndex: item.originalIndex,
            email: item.email,
            phone: item.phone,
            selectedKey: item.selectedKey,
            phase3TargetRevision: item.phase3TargetRevision,
          })),
          duplicateIndexes,
          selectedKeys: normalizedSelectedKeys,
        });
        const priorReceipt = await existingMutationReceipt(db, idempotency, actor);
        if (priorReceipt) {
          writeLog(logger, 'info', 'phase3.request_replayed', { requestId, actor });
          sendMutationReceipt(response, priorReceipt, true);
          return;
        }
        // The feature flag is process configuration, so a new request can be
        // rejected before waiting for admission. Keep the identical check
        // under the lock below as a defence against in-process configuration
        // changes and preserve receipt lookup ahead of both checks.
        if (!booleanEnvEnabled('PANEL_PHASE3_ENABLED', false)) {
          const error = new Error('Phase 3 未启用，请设置 PANEL_PHASE3_ENABLED=1 后重启面板');
          error.code = 'PHASE3_DISABLED';
          throw error;
        }
        let resolvedRequests = [];
        let initiallyRejected = [];
        const rejectionFromDatabase = (item) => {
          const requestItem = item.metadata || {};
          if (item.reason === 'duplicate_in_submission') {
            return {
              index: requestItem.originalIndex,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              error: 'duplicate_in_request',
              message: '同一请求中账号重复，已合并为一个任务',
            };
          }
          if (item.reason === 'queue_full') {
            return {
              index: requestItem.originalIndex,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              error: 'phase3_queue_full',
              message: 'Phase 3 活跃任务已达到安全上限',
            };
          }
          return {
            index: requestItem.originalIndex,
            email: requestItem.email || null,
            phone: requestItem.phone || null,
            error: 'phase3_already_running',
            message: '该账号已有 Phase 3 任务排队或运行中',
            jobId: item.existingJobId || null,
          };
        };
        const dispatchGuard = serverAdmissionDispatchGuard({
          db,
          jobManager,
          logger,
          requestId,
          actor,
          workflow: MUTATION_WORKFLOWS.phase3,
        });
        const admission = await withRequestAdmission((signal) => (
          dispatchGuard.run(async ({ recordCommitted, dispatch }) => {
            const submission = await admissionControlPlaneLock(async () => {
              throwIfJobInterrupted(signal);
              const lockedReceipt = await existingMutationReceipt(db, idempotency, actor);
              if (lockedReceipt) {
                return { receipt: lockedReceipt, replayed: true, createdJobs: [], rejections: [] };
              }
              // Do not create durable jobs that the worker is configured to
              // reject. This must follow the receipt recheck under the lock:
              // an earlier accepted request remains safely recoverable after
              // a restart even if Phase 3 has since been disabled.
              if (!booleanEnvEnabled('PANEL_PHASE3_ENABLED', false)) {
                const error = new Error(
                  'Phase 3 未启用，请设置 PANEL_PHASE3_ENABLED=1 后重启面板',
                );
                error.code = 'PHASE3_DISABLED';
                throw error;
              }
              // Resolution reads mutable gpt_register files and validates the
              // process-local target revision. It must happen only after the
              // authoritative receipt recheck while this cross-process lock is
              // held; otherwise a concurrent committed submission could be
              // rejected as stale instead of replayed.
              const resolved = phase3RequestResolver(requests);
              resolvedRequests = resolved.eligible;
              initiallyRejected = duplicateIndexes.map((index) => ({
                index,
                error: 'duplicate_in_request',
                message: '同一请求中账号重复，已合并为一个任务',
              })).concat(resolved.rejected);
              if (resolvedRequests.length === 0) {
                return { noJobs: true, createdJobs: [], rejections: [] };
              }
              const created = await db.createMutationSubmission({
                ...idempotency,
                requestedBy: actor,
                allowPartial: true,
                maximumActiveByType: {
                  phase3: boundedEnvNumber('PANEL_PHASE3_MAX_ACTIVE_JOBS', 100, 1, 100),
                },
                jobs: resolvedRequests.map((requestItem) => ({
                  type: 'phase3',
                  payload: {
                    email: requestItem.email || null,
                    phone: requestItem.phone || null,
                    canonicalKeys: requestItem.canonicalKeys,
                    selectedKey: requestItem.selectedKey || null,
                    // selectedKey itself is redacted in persisted job payloads;
                    // retain only its validated source-relative path for review.
                    sourcePath: sourcePathFromSelectionKey(requestItem.selectedKey),
                    batch: resolvedRequests.length > 1,
                  },
                  claimKeys: phase3ClaimKeys(requestItem),
                  metadata: requestItem,
                })),
                responseFactory: ({ createdJobs, rejections }) => {
                  const queuedJobs = createdJobs.map((item) => ({
                    jobId: item.job.id,
                    email: item.metadata.email || null,
                    phone: item.metadata.phone || null,
                    status: 'queued',
                  }));
                  const jobIds = queuedJobs.map((item) => item.jobId);
                  return {
                    batch: jobIds.length > 1,
                    status: 'queued',
                    jobId: jobIds.length === 1 ? jobIds[0] : null,
                    jobIds,
                    jobs: queuedJobs,
                    rejected: initiallyRejected.concat(rejections.map(rejectionFromDatabase)),
                  };
                },
              });
              if (!created.replayed) recordCommitted(created.createdJobs);
              throwIfJobInterrupted(signal);
              return created;
            }, { signal });
            if (submission.replayed || submission.noJobs) return { submission, queued: [] };
            const queued = submission.createdJobs.map((item) => ({
              ...item.metadata,
              executionBinding: item.metadata.executionBinding,
              job: item.job,
            }));
            for (const item of queued) {
              writeLog(logger, 'info', 'phase3.job_queued', {
                requestId,
                jobId: item.job.id,
                actor,
                email: item.email || null,
                phone: item.phone || null,
                batch: resolvedRequests.length > 1,
                durationMs: Date.now() - phase3RequestStartedAt,
              });
              dispatch(item.job, 'phase3', actor, (taskRecord) => observePhase3Job({
                job: item.job,
                email: item.email,
                phone: item.phone,
                canonicalKeys: item.canonicalKeys,
                executionBinding: item.executionBinding,
                actor,
                db,
                logger,
                requestId,
                jobManager,
                taskRecord,
              }));
            }
            return { submission, queued };
          })
        ));
        if (admission.submission.replayed) {
          writeLog(logger, 'info', 'phase3.request_replayed', { requestId, actor });
          sendMutationReceipt(response, admission.submission.receipt, true);
          return;
        }
        if (admission.submission.noJobs) {
          const rejected = initiallyRejected.concat(
            admission.submission.rejections.map(rejectionFromDatabase),
          );
          jsonResponse(response, 409, {
            error: rejected.some((item) => item.error === 'phase3_queue_full')
              ? 'phase3_queue_full'
              : 'phase3_no_eligible_accounts',
            message: '没有可提交的 Phase 3 账号',
            jobIds: [],
            rejected,
          });
          return;
        }
        sendMutationReceipt(response, admission.submission.receipt, false);
      } catch (error) {
        writeLog(logger, 'error', 'phase3.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - phase3RequestStartedAt,
          error: safeHttpErrorMessage(error),
        });
        sendPublicApiError(response, error, {
          write: true,
          fallbackCode: 'phase3_failed',
          fallbackMessage: 'Phase 3 请求未能安全完成，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/account-tests/models') {
      const accountId = accountTestModelQueryId(requestUrl.searchParams);
      if (accountId === null) {
        jsonResponse(response, 400, {
          error: 'ACCOUNT_TEST_ACCOUNT_ID_INVALID',
          message: '需要有效的 Sub2API 账号 ID',
        });
        return;
      }
      const modelStartedAt = Date.now();
      try {
        const client = new Sub2ApiAdminClient({ logger, logContext: { requestId, actor } });
        const models = await client.getAvailableModels(accountId);
        writeLog(logger, 'info', 'account_test.models_loaded', {
          requestId,
          actor,
          accountId,
          count: models.length,
          durationMs: Date.now() - modelStartedAt,
        });
        jsonResponse(response, 200, { models });
      } catch (error) {
        writeLog(logger, 'warn', 'account_test.models_failed', {
          requestId,
          actor,
          accountId,
          durationMs: Date.now() - modelStartedAt,
          error: safeHttpErrorMessage(error),
        });
        sendPublicApiError(response, error, {
          fallbackCode: 'ACCOUNT_TEST_MODELS_FAILED',
          fallbackMessage: '测试模型列表读取失败，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/account-tests') {
      const accountTestRequestStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        const requestData = normalizeAccountTestRequest(body);
        const idempotency = mutationContext(request, MUTATION_WORKFLOWS.accountTest, {
          targets: requestData.targets,
          modelId: requestData.modelId,
          promptDigest: promptDigest(requestData.prompt),
        });
        const priorReceipt = await existingMutationReceipt(db, idempotency, actor);
        if (priorReceipt) {
          writeLog(logger, 'info', 'account_test.request_replayed', { requestId, actor });
          sendMutationReceipt(response, priorReceipt, true);
          return;
        }
        const dispatchGuard = serverAdmissionDispatchGuard({
          db,
          jobManager,
          logger,
          requestId,
          actor,
          workflow: MUTATION_WORKFLOWS.accountTest,
        });
        const admission = await withRequestAdmission((signal) => (
          dispatchGuard.run(async ({ recordCommitted, dispatch }) => {
            const submitted = await withAccountTestSubmissionLock(() => (
              admissionControlPlaneLock(async () => {
              throwIfJobInterrupted(signal);
              const lockedReceipt = await existingMutationReceipt(db, idempotency, actor);
              if (lockedReceipt) {
                return {
                  mutationSubmission: {
                    receipt: lockedReceipt,
                    replayed: true,
                    createdJobs: [],
                    rejections: [],
                  },
                  job: null,
                };
              }
              const client = accountTestClientFactory({
                logger,
                logContext: { requestId, actor },
              });
              const accounts = await client.listAccounts({
                platform: 'openai',
                type: 'oauth',
                pageSize: 200,
                requireTotal: true,
                requirePaginationMetadata: true,
                signal,
              });
              throwIfJobInterrupted(signal);
              // Validate the exact UI-reviewed account identity, credential
              // evidence and state before consulting active jobs or creating a
              // durable task. The opaque revisions themselves are never stored.
              assertAccountTestTargetRevisions(accounts, requestData.targets);
              throwIfJobInterrupted(signal);
              const jobs = await db.listActiveAccountTestJobsForAccounts(
                requestData.accountIds,
              );
              throwIfJobInterrupted(signal);
              const classified = classifyAccountTestTargets(
                accounts,
                requestData.accountIds,
                activeAccountTestJobs(jobs),
              );
              if (classified.eligible.length === 0) return classified;
              const accountIds = classified.eligible.map((item) => item.id);
              const targetBaselines = classified.eligible
                .map((item) => accountTestTargetBaseline(item.account));
              if (targetBaselines.some((baseline) => !baseline)) {
                const error = new Error('无法建立账号测试目标的身份与状态基线');
                error.code = 'ACCOUNT_TEST_BASELINE_INVALID';
                throw error;
              }
              throwIfJobInterrupted(signal);
              const mutationSubmission = await db.createMutationSubmission({
                ...idempotency,
                requestedBy: actor,
                jobs: [{
                  type: 'account_test',
                  payload: {
                    accountIds,
                    targetBaselines,
                    modelId: requestData.modelId,
                    // Prompts are forwarded only through the in-memory worker closure.
                    // Persisting arbitrary prompt text would make an unlabelled secret
                    // retrievable through the jobs API even after log redaction.
                    promptPresent: requestData.prompt.length > 0,
                    promptLength: requestData.prompt.length,
                  },
                  claimKeys: accountIds.map((id) => 'account_test:' + String(id)),
                }],
                responseFactory: ({ createdJobs }) => ({
                  jobId: createdJobs[0].job.id,
                  status: 'queued',
                  accountIds,
                  rejected: classified.rejected,
                }),
              });
              if (!mutationSubmission.replayed) {
                recordCommitted(mutationSubmission.createdJobs);
              }
              throwIfJobInterrupted(signal);
              return {
                ...classified,
                accountIds,
                targetBaselines,
                mutationSubmission,
                job: mutationSubmission.replayed
                  ? null
                  : mutationSubmission.createdJobs[0]?.job || null,
              };
              }, { signal })
            ));
            throwIfJobInterrupted(signal);
            if (submitted.job && !submitted.mutationSubmission?.replayed) {
              writeLog(logger, 'info', 'account_test.job_queued', {
                requestId,
                jobId: submitted.job.id,
                actor,
                accountCount: submitted.accountIds.length,
                rejectedCount: submitted.rejected.length,
                model: requestData.modelId || null,
                durationMs: Date.now() - accountTestRequestStartedAt,
              });
              dispatch(submitted.job, 'account_test', actor, (taskRecord) => observeAccountTestJob({
                job: submitted.job,
                accountIds: submitted.accountIds,
                targetBaselines: submitted.targetBaselines,
                modelId: requestData.modelId,
                prompt: requestData.prompt,
                actor,
                db,
                logger,
                requestId,
                jobManager,
                taskRecord,
              }));
            }
            return { submission: submitted };
          })
        ));
        const submission = admission.submission;
        if (submission.mutationSubmission?.replayed) {
          writeLog(logger, 'info', 'account_test.request_replayed', { requestId, actor });
          sendMutationReceipt(response, submission.mutationSubmission.receipt, true);
          return;
        }
        if (!submission.job) {
          writeLog(logger, 'warn', 'account_test.request_rejected', {
            requestId,
            actor,
            rejectedCount: submission.rejected.length,
            durationMs: Date.now() - accountTestRequestStartedAt,
          });
          jsonResponse(response, 409, {
            error: 'ACCOUNT_TEST_NO_ELIGIBLE_ACCOUNTS',
            message: '没有可测试的上游账号',
            rejected: submission.rejected,
          });
          return;
        }
        sendMutationReceipt(response, submission.mutationSubmission.receipt, false);
      } catch (error) {
        writeLog(logger, 'error', 'account_test.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - accountTestRequestStartedAt,
          code: storedErrorCode(error) || null,
          error: safeHttpErrorMessage(error),
        });
        sendPublicApiError(response, error, {
          write: true,
          fallbackCode: 'account_test_failed',
          fallbackMessage: '账号测试请求未能安全完成，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/tokens/expired') {
      try {
        const listing = listExpiredTokens();
        jsonResponse(response, 200, {
          generatedAt: listing.generatedAt,
          version: listing.version,
          count: listing.count,
          items: listing.items.map(safeExpiredTokenItem),
          recoveryRequired: listing.recoveryRequired === true,
          claimCount: boundedCleanupCount(listing.claimCount),
          claimCountTruncated: listing.claimCountTruncated === true,
        });
      } catch (error) {
        writeLog(logger, 'error', 'token_cleanup.scan_failed', {
          requestId,
          actor,
          error: safeHttpErrorMessage(error),
        });
        sendPublicApiError(response, error, {
          fallbackCode: 'token_cleanup_scan_failed',
          fallbackMessage: '过期 token 扫描失败，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/tokens/expired/delete') {
      const cleanupStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        const bodyError = requestBodyObjectError(body);
        if (bodyError) throw bodyError;
        if (body.confirmation !== TOKEN_CLEANUP_CONFIRMATION) {
          const error = new Error('请输入明确的过期 token 删除确认值');
          error.code = 'TOKEN_CLEANUP_CONFIRMATION_REQUIRED';
          throw error;
        }
        if (!/^[a-f0-9]{64}$/i.test(String(body.version || ''))) {
          const error = new Error('缺少有效的过期 token 清单版本，请重新扫描');
          error.code = 'TOKEN_CLEANUP_VERSION_REQUIRED';
          throw error;
        }
        const expectedVersion = String(body.version).toLowerCase();
        const idempotency = mutationContext(request, MUTATION_WORKFLOWS.tokenCleanup, {
          confirmation: TOKEN_CLEANUP_CONFIRMATION,
          version: expectedVersion,
        });
        const priorReceipt = await existingMutationReceipt(db, idempotency, actor);
        if (priorReceipt) {
          writeLog(logger, 'info', 'token_cleanup.request_replayed', { requestId, actor });
          sendMutationReceipt(response, priorReceipt, true);
          return;
        }
        const dispatchGuard = serverAdmissionDispatchGuard({
          db,
          jobManager,
          logger,
          requestId,
          actor,
          workflow: MUTATION_WORKFLOWS.tokenCleanup,
        });
        const { submission, job } = await withRequestAdmission((signal) => (
          dispatchGuard.run(async ({ recordCommitted, dispatch }) => {
            const created = await admissionControlPlaneLock(async () => {
              throwIfJobInterrupted(signal);
              const lockedReceipt = await existingMutationReceipt(db, idempotency, actor);
              if (lockedReceipt) {
                return { receipt: lockedReceipt, replayed: true, createdJobs: [], rejections: [] };
              }
              if (!db || typeof db.createMutationSubmission !== 'function') {
                const error = new Error('token 清理任务持久化安全检查不可用，未修改任何文件');
                error.code = 'JOB_RECONCILIATION_GUARD_UNAVAILABLE';
                throw error;
              }
              if (typeof db.assertNoReconciliationHold !== 'function') {
                const error = new Error('token 清理任务对账安全检查不可用，未修改任何文件');
                error.code = 'JOB_RECONCILIATION_GUARD_UNAVAILABLE';
                throw error;
              }
              // Once replay has been ruled out, reject a global hold/running
              // mutation before touching even the live cleanup scan. The final
              // atomic create repeats this check to protect against DB-level
              // callers and future lock-boundary changes.
              await db.assertNoReconciliationHold();
              throwIfJobInterrupted(signal);
              const listing = expiredTokenLister();
              if (listing.version.toLowerCase() !== expectedVersion) {
                const error = new Error('过期 token 清单已变化，请重新扫描后再删除');
                error.code = 'TOKEN_CLEANUP_STALE';
                error.currentVersion = listing.version;
                throw error;
              }
              assertTokenCleanupRecoveryNotRequired(listing);
              const createdSubmission = await db.createMutationSubmission({
                ...idempotency,
                requestedBy: actor,
                jobs: [{
                  type: TOKEN_CLEANUP_JOB_TYPE,
                  payload: tokenCleanupJobPayload(listing),
                  claimKeys: [TOKEN_CLEANUP_CLAIM_KEY],
                }],
                responseFactory: ({ createdJobs }) => ({
                  jobId: createdJobs[0].job.id,
                  status: 'queued',
                }),
              });
              if (!createdSubmission.replayed) {
                recordCommitted(createdSubmission.createdJobs);
              }
              throwIfJobInterrupted(signal);
              return createdSubmission;
            }, { signal });
            if (created.replayed) return { submission: created, job: null };
            const createdJob = created.createdJobs[0]?.job;
            if (!createdJob) {
              const error = new Error('token 清理任务未能原子入队');
              error.code = 'IDEMPOTENCY_RECEIPT_INVALID';
              throw error;
            }
            throwIfJobInterrupted(signal);
            writeLog(logger, 'info', 'token_cleanup.job_queued', {
              requestId,
              jobId: createdJob.id,
              actor,
              expectedVersion,
              durationMs: Date.now() - cleanupStartedAt,
            });
            dispatch(createdJob, TOKEN_CLEANUP_JOB_TYPE, actor, (taskRecord) => observeTokenCleanupJob({
              job: createdJob,
              expectedVersion,
              actor,
              db,
              logger,
              requestId,
              jobManager,
              taskRecord,
            }));
            return { submission: created, job: createdJob };
          })
        ));
        if (submission.replayed) {
          writeLog(logger, 'info', 'token_cleanup.request_replayed', { requestId, actor });
          sendMutationReceipt(response, submission.receipt, true);
          return;
        }
        sendMutationReceipt(response, submission.receipt, false);
      } catch (error) {
        writeLog(logger, 'error', 'token_cleanup.failed', {
          requestId,
          actor,
          code: storedErrorCode(error) || null,
          error: safeHttpErrorMessage(error),
          durationMs: Date.now() - cleanupStartedAt,
        });
        sendPublicApiError(response, error, {
          write: true,
          fallbackCode: 'token_cleanup_failed',
          fallbackMessage: '过期 token 删除请求未能安全完成，请稍后重试',
          extraFields: publicTokenCleanupErrorFields,
        });
      }
      return;
    }

    if (request.method === 'POST' && reconciliationAckPath.matched) {
      const acknowledgeStartedAt = Date.now();
      if (actor !== 'panel-admin') {
        writeLog(logger, 'warn', 'job.reconciliation_acknowledge_admin_required', {
          requestId,
          actor,
          jobId: reconciliationAckPath.jobId,
        });
        jsonResponse(response, 403, {
          error: 'JOB_RECONCILIATION_ADMIN_REQUIRED',
          message: '只允许经过认证的面板管理员解除待对账阻挡',
        });
        return;
      }
      try {
        const body = await readJsonBody(request, 4096);
        const requestError = reconciliationAcknowledgeRequestError(
          body,
          reconciliationAckPath.jobId,
        );
        if (requestError) throw requestError;
        writeLog(logger, 'warn', 'job.reconciliation_acknowledge_started', {
          requestId,
          actor,
          jobId: reconciliationAckPath.jobId,
          resolution: body.resolution,
        });
        const acknowledgement = await withRequestAdmission(async (signal) => {
          throwIfJobInterrupted(signal);
          return db.acknowledgeJobReconciliation(reconciliationAckPath.jobId, {
            actor,
            confirmation: body.confirmation,
            resolution: body.resolution,
            claimDigest: body.claimDigest,
            beforeRelease: (fields) => {
              throwIfJobInterrupted(signal);
              assertAuditLogCheckpoint(logger, 'job.reconciliation_acknowledge_checkpoint', {
                requestId,
                actor,
                jobId: fields.jobId,
                resolution: fields.resolution,
                claimDigest: fields.claimDigest,
                holdScope: fields.holdScope,
                releasedClaimCount: fields.releasedClaimCount,
              });
            },
          });
        });
        writeLog(logger, 'warn', 'job.reconciliation_acknowledge_completed', {
          requestId,
          actor,
          jobId: acknowledgement.jobId,
          resolution: acknowledgement.resolution,
          releasedClaimCount: acknowledgement.releasedClaimCount,
          idempotent: acknowledgement.idempotent,
          durationMs: Date.now() - acknowledgeStartedAt,
        });
        jsonResponse(response, 200, {
          ...acknowledgement,
          message: '已记录管理员的人工核对结论并解除该任务对未来操作的阻挡；原任务仍不可重试',
        });
      } catch (error) {
        writeLog(logger, 'error', 'job.reconciliation_acknowledge_failed', {
          requestId,
          actor,
          jobId: reconciliationAckPath.jobId,
          code: storedErrorCode(error) || null,
          error: safeHttpErrorMessage(error),
          durationMs: Date.now() - acknowledgeStartedAt,
        });
        sendPublicApiError(response, error, {
          write: true,
          fallbackCode: 'JOB_RECONCILIATION_ACKNOWLEDGE_FAILED',
          fallbackMessage: '人工对账确认未能安全完成，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'GET' && reconciliationReviewRoute.matched) {
      if (actor !== 'panel-admin') {
        jsonResponse(response, 403, {
          error: 'JOB_RECONCILIATION_ADMIN_REQUIRED',
          message: '只允许经过认证的面板管理员读取人工对账目标',
        });
        return;
      }
      if (!reconciliationReviewRoute.jobId) {
        jsonResponse(response, 400, {
          error: 'JOB_RECONCILIATION_JOB_ID_INVALID',
          message: '待对账任务标识无效',
        });
        return;
      }
      try {
        const job = await db.getJob(reconciliationReviewRoute.jobId);
        jsonResponse(response, 200, reconciliationReviewDetail(job));
      } catch (error) {
        sendPublicApiError(response, error, {
          fallbackCode: 'JOB_RECONCILIATION_DETAIL_FAILED',
          fallbackMessage: '人工对账详情读取失败，请稍后重试',
        });
      }
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/jobs') {
      const page = typeof db.listJobsPage === 'function'
        ? await db.listJobsPage(requestUrl.searchParams.get('limit'))
        : { jobs: await db.listJobs(requestUrl.searchParams.get('limit')) };
      jsonResponse(response, 200, page);
      return;
    }

    const jobId = pathParam(requestUrl.pathname, '/api/jobs/');
    if (request.method === 'GET' && jobId) {
      const job = await db.getJob(jobId);
      if (!job) jsonResponse(response, 404, { error: 'job_not_found' });
      else jsonResponse(response, 200, job);
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/audit') {
      jsonResponse(response, 200, { events: await db.listAudit(requestUrl.searchParams.get('limit')) });
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/logs') {
      const requestedLevel = requestUrl.searchParams.get('level');
      const requestedEvent = requestUrl.searchParams.get('event');
      let logs = logger.tail(requestUrl.searchParams.get('limit'));
      if (requestedLevel) logs = logs.filter((entry) => entry.level === requestedLevel);
      if (requestedEvent) logs = logs.filter((entry) => entry.event === requestedEvent);
      jsonResponse(response, 200, {
        count: logs.length,
        logs,
      });
      return;
    }

    serveStatic(requestUrl.pathname, response);
    } catch (error) {
      const publicError = publicApiError(error, {
        write: request.method !== 'GET',
        fallbackCode: request.method === 'GET' ? 'internal_error' : 'write_request_failed',
      });
      writeLog(logger, 'error', 'http.request_failed', {
        requestId,
        actor,
        method: request.method,
        path: requestPath,
        statusCode: publicError.statusCode,
        error: safeHttpErrorMessage(error),
      });
      if (!response.headersSent) {
        jsonResponse(response, publicError.statusCode, publicError.body);
      } else if (!response.writableEnded) {
        response.end();
      }
    }
  });
  // Node's requestTimeout covers receipt of request headers/body; it is not a
  // deadline for the asynchronous route handler after the body is complete.
  // Long upstream/worker operations keep their own abortable timeouts.
  const requestReceiveTimeout = boundedEnvNumber(
    'PANEL_HTTP_REQUEST_TIMEOUT_MS',
    30_000,
    1_000,
    300_000,
  );
  server.requestTimeout = requestReceiveTimeout;
  server.headersTimeout = Math.min(
    requestReceiveTimeout,
    boundedEnvNumber('PANEL_HTTP_HEADERS_TIMEOUT_MS', 15_000, 1_000, 120_000),
  );
  server.keepAliveTimeout = boundedEnvNumber('PANEL_HTTP_KEEP_ALIVE_TIMEOUT_MS', 5_000, 1_000, 60_000);
  // Node checks headersTimeout/requestTimeout on a periodic sweep whose
  // default is 30 seconds. Without tightening that interval, a configured
  // 1-second boundary can remain open for roughly 30 seconds.
  server.connectionsCheckingInterval = Math.min(
    1_000,
    server.headersTimeout,
    server.requestTimeout,
  );
  server.maxHeadersCount = boundedEnvNumber('PANEL_HTTP_MAX_HEADERS', 100, 16, 1_000);
  server.maxRequestsPerSocket = boundedEnvNumber('PANEL_HTTP_MAX_REQUESTS_PER_SOCKET', 100, 1, 10_000);
  server.panelLogger = logger;
  server.panelDb = db;
  server.panelJobManager = jobManager;
  return server;
}

async function startServer(options = {}) {
  validateRuntimeConfiguration();
  const host = configuredListenHost(options.host);
  const port = configuredListenPort(options.port);
  let server;
  try {
    validateListenConfiguration(host);
    server = createServer(options);
  } catch (error) {
    throw error;
  }
  await server.panelDb?.ready;
  return new Promise((resolve, reject) => {
    const onStartError = (error) => {
      server.removeListener('listening', onListening);
      writeLog(server.panelLogger, 'error', 'server.start_failed', {
        host,
        port,
        error: safeErrorMessage(error),
      });
      reject(error);
    };
    const onListening = () => {
      // This listener exists only to reject the startup promise. Leaving it
      // installed after a successful bind would consume the first runtime
      // server error and mislabel it as a startup failure, while the already
      // resolved promise makes the rejection invisible to the caller.
      server.removeListener('error', onStartError);
      const address = server.address();
      writeLog(server.panelLogger, 'info', 'server.started', {
        host,
        port: address.port,
        pid: process.pid,
      });
      process.stdout.write('gpt-register-panel listening on http://' + host + ':' + address.port + '\n');
      resolve(server);
    };
    server.once('error', onStartError);
    server.once('listening', onListening);
    server.listen(port, host);
    server.once('close', () => {
      writeLog(server.panelLogger, 'info', 'server.stopped', { host, port });
    });
  });
}

function closeServerListener(server) {
  return new Promise((resolve) => {
    if (!server?.listening) {
      resolve();
      return;
    }
    try {
      server.close(() => resolve());
    } catch {
      resolve();
    }
  });
}

async function shutdownServer(server, options = {}) {
  if (!server) return { active: 0, interrupted: [] };
  if (server.panelShutdownPromise) return server.panelShutdownPromise;
  const logger = server.panelLogger;
  const signal = String(options.signal || 'shutdown').slice(0, 32);
  const configuredTimeout = options.timeoutMs ?? process.env.PANEL_SHUTDOWN_TIMEOUT_MS;
  const parsedTimeout = configuredTimeout === undefined
    || String(configuredTimeout).trim() === ''
    ? Number.NaN
    : Number(configuredTimeout);
  const timeoutMs = Number.isFinite(parsedTimeout)
    ? Math.max(0, Math.min(12_000, Math.floor(parsedTimeout)))
    : 10_000;
  server.panelShutdownPromise = (async () => {
    writeLog(logger, 'info', 'server.shutdown_started', {
      signal,
      timeoutMs,
      activeJobs: server.panelJobManager?.activeCount || 0,
    });
    // shutdown() flips the admission gate and aborts registered workers before
    // the first await. close() then prevents new TCP connections while current
    // responses are allowed to finish during the bounded drain window.
    const jobsPromise = server.panelJobManager
      ? server.panelJobManager.shutdown({ timeoutMs })
      : Promise.resolve({ active: 0, interrupted: [] });
    const listenerPromise = closeServerListener(server);
    try { server.closeIdleConnections?.(); } catch {}
    let result;
    let shutdownError = null;
    try {
      result = await jobsPromise;
    } catch (error) {
      shutdownError = error;
      result = { active: server.panelJobManager?.activeCount || 0, interrupted: [] };
      writeLog(logger, 'error', 'server.shutdown_job_persistence_failed', {
        signal,
        error: safeErrorMessage(error),
      });
    }
    try { server.closeAllConnections?.(); } catch {}
    let closeTimer;
    await Promise.race([
      listenerPromise,
      new Promise((resolve) => { closeTimer = setTimeout(resolve, 1000); }),
    ]);
    if (closeTimer) clearTimeout(closeTimer);
    writeLog(logger, shutdownError ? 'error' : 'info', 'server.shutdown_completed', {
      signal,
      activeJobs: result.active || 0,
      interruptedJobs: Array.isArray(result.interrupted) ? result.interrupted.length : 0,
    });
    if (shutdownError) throw shutdownError;
    return result;
  })();
  return server.panelShutdownPromise;
}

function installShutdownSignalHandlers(server, options = {}) {
  const emitter = options.emitter || process;
  const exit = typeof options.exit === 'function' ? options.exit : (code) => process.exit(code);
  const reportError = typeof options.reportError === 'function'
    ? options.reportError
    : (error) => process.stderr.write(safeErrorText(error) + '\n');
  let requested = false;
  const stop = (signal) => {
    if (requested) return;
    requested = true;
    shutdownServer(server, { signal }).then(
      () => exit(0),
      (error) => {
        reportError(error);
        exit(1);
      },
    );
  };
  const onSigterm = () => stop('SIGTERM');
  const onSigint = () => stop('SIGINT');
  // Keep both handlers installed throughout draining. With `once`, a second
  // SIGTERM of the same type would hit Node's default handler and terminate
  // immediately, bypassing process-tree cleanup and terminal persistence.
  emitter.on('SIGTERM', onSigterm);
  emitter.on('SIGINT', onSigint);
  return () => {
    emitter.removeListener('SIGTERM', onSigterm);
    emitter.removeListener('SIGINT', onSigint);
  };
}

if (require.main === module) {
  // Loading deployment configuration is an executable-entrypoint concern.
  // Importing createServer() from tests or another module must not silently
  // read the project's real .env and connect to production services.
  Promise.resolve().then(() => {
    loadEnv();
    return startServer();
  }).then((server) => {
    installShutdownSignalHandlers(server);
  }).catch((error) => {
    process.stderr.write(safeErrorText(error) + '\n');
    process.exitCode = 1;
  });
}

module.exports = {
  buildSnapshot,
  configuredListenHost,
  configuredListenPort,
  createServer,
  installShutdownSignalHandlers,
  shutdownServer,
  startServer,
  authorizationError,
  authFailureBucketCount,
  hasJsonContentType,
  readJsonBody,
  requestActor,
  validateRuntimeConfiguration,
  validateListenConfiguration,
  normalizedSelectedKeys,
  openVerifiedStaticFile,
  parseRequestTarget,
  publicApiError,
  publicTokenCleanupErrorFields,
  requestBodyObjectError,
  requestLogPath,
  resetAuthFailureBuckets,
  safeStaticPath,
  tokenImportJobStatus,
  normalizePhase3Requests,
  phase3FailureMetadata,
  mutationFailureMetadata,
  observeTokenCleanupJob,
  phase3ClaimKeys,
  reconciliationAcknowledgePath,
  reconciliationAcknowledgeRequestError,
  reconciliationReviewDetail,
  sourcePathFromSelectionKey,
  tokenCleanupFailureMetadata,
  tokenCleanupJobPayload,
  tokenCleanupResultSummary,
};
