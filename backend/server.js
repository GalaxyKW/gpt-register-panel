const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const {
  booleanEnvEnabled,
  loadEnv,
  validateBooleanEnvironment,
} = require('./config');
const {
  buildSnapshot,
  buildImportPlan,
  importPlanSummary,
  executeImport,
  configuredForSub2Api,
  confirmedSub2ApiRead,
  safeErrorMessage,
} = require('./sync');
const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const { PanelDb } = require('./db');
const {
  runPhase3Job,
  getActivePhase3Job,
  canonicalPhase3Keys,
  resolvePhase3Requests,
} = require('./phase3Worker');
const {
  activeAccountTestJobs,
  accountTestTargetBaseline,
  classifyAccountTestTargets,
  normalizeAccountTestRequest,
  runAccountTestJob,
  safeErrorMessage: safeAccountTestErrorMessage,
  withAccountTestSubmissionLock,
} = require('./accountTestWorker');
const { createLogger, safeErrorText } = require('./logger');
const { CONFIRMATION: TOKEN_CLEANUP_CONFIRMATION, listExpiredTokens, deleteExpiredTokens } = require('./tokenCleanup');
const { withControlPlaneLock } = require('./taskCoordinator');
const { assertDirectoryTree } = require('./lib/safeFs');
const {
  createBackgroundJobManager,
  throwIfJobInterrupted,
  updateTerminalJob,
} = require('./jobLifecycle');

const FRONTEND_ROOT = path.resolve(__dirname, '..', 'frontend');
const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};
const CONTENT_SECURITY_POLICY = "default-src 'self'; base-uri 'none'; object-src 'none'; form-action 'none'; style-src 'self'; script-src 'self'; frame-ancestors 'none'";
const STATIC_ALLOWLIST = new Set(['/index.html', '/app.js', '/styles.css']);
const JSON_BODY_ENDPOINTS = new Set([
  '/api/sync/preview',
  '/api/sync/import',
  '/api/phase3',
  '/api/tokens/expired/delete',
  '/api/account-tests',
]);

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
  const now = Date.now();
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
  const now = Date.now();
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
}

function headerToken(request) {
  const authorization = String(request.headers.authorization || '');
  const value = authorization.toLowerCase().startsWith('bearer ')
    ? authorization.slice(7).trim()
    : String(request.headers['x-panel-token'] || '').trim();
  return value.length <= 4096 ? value : '';
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
    if (!configuredToken && process.env.PANEL_ALLOW_INSECURE_WRITE === '1' && !isLoopbackRequest(request)) {
      return { status: 503, error: 'write_loopback_required', message: '未配置 PANEL_ADMIN_TOKEN 时，写操作只允许本机访问' };
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
  const value = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  return value === 'localhost' || isLoopbackAddress(value);
}

function validateListenConfiguration(host) {
  validateRuntimeConfiguration();
  const configuredToken = configuredPanelToken();
  if (!isLoopbackHost(host)
      && !configuredToken
      && !booleanEnvEnabled('PANEL_ALLOW_INSECURE_REMOTE')) {
    const error = new Error('非回环监听必须配置 PANEL_ADMIN_TOKEN，或明确设置 PANEL_ALLOW_INSECURE_REMOTE=1');
    error.code = 'PANEL_REMOTE_AUTH_REQUIRED';
    throw error;
  }
}

function isLoopbackRequest(request) {
  const address = String(request?.socket?.remoteAddress || '').replace(/^::ffff:/i, '');
  return isLoopbackAddress(address);
}


function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Request handling must continue if the log destination is unavailable.
  }
}

function readJsonBody(request, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bodyBytes = 0;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      if (settled) return;
      const chunkBytes = Buffer.byteLength(chunk);
      bodyBytes += chunkBytes;
      if (bodyBytes > limit) {
        const error = new Error('request body too large');
        error.code = 'REQUEST_BODY_TOO_LARGE';
        fail(error);
        request.resume();
        return;
      }
      body += chunk;
    });
    request.on('end', () => {
      if (settled) return;
      if (!body.trim()) {
        settled = true;
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(body);
        settled = true;
        resolve(parsed);
      } catch {
        const error = new Error('invalid JSON body');
        error.code = 'INVALID_JSON_BODY';
        fail(error);
      }
    });
    request.on('aborted', () => {
      const error = new Error('request aborted');
      error.code = 'REQUEST_ABORTED';
      fail(error);
    });
    request.on('error', fail);
  });
}

function hasJsonContentType(request) {
  const value = String(request?.headers?.['content-type'] || '');
  return value.split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

function pathParam(pathname, prefix) {
  if (!pathname.startsWith(prefix)) return null;
  const value = pathname.slice(prefix.length);
  if (!value || value.includes('/')) return null;
  try { return decodeURIComponent(value); } catch { return null; }
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
  if (value.some((item) => typeof item !== 'string')) return null;
  const keys = value
    .map((item) => item.trim())
    .filter(Boolean);
  const allowEmpty = options.allowEmpty === true;
  if (keys.length === 0 && (!allowEmpty || value.length > 0)) return null;
  if (keys.some((key) => key.length > 512)) return null;
  return [...new Set(keys)];
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
  if (body.selectedKeys !== undefined) {
    const selectedKeys = normalizedSelectedKeys(body.selectedKeys, { allowEmpty: true });
    if (!selectedKeys) {
      const error = new Error('selectedKeys 必须是字符串数组');
      error.code = 'PHASE3_SELECTION_INVALID';
      throw error;
    }
  }
  const requests = [];
  const duplicateIndexes = [];
  const seenKeys = new Set();
  rawItems.forEach((rawItem, index) => {
    if (!rawItem || typeof rawItem !== 'object' || Array.isArray(rawItem)) {
      const error = new Error('Phase 3 账号项必须是对象');
      error.code = 'PHASE3_ACCOUNT_INVALID';
      throw error;
    }
    const email = typeof rawItem.email === 'string' ? rawItem.email.trim().toLowerCase() : '';
    const phone = typeof rawItem.phone === 'string' ? rawItem.phone.trim() : '';
    const normalizedPhone = phone.replace(/[^0-9]/g, '');
    if (!email && !normalizedPhone) {
      const error = new Error('每个 Phase 3 账号必须提供 email 或 phone');
      error.code = 'PHASE3_ACCOUNT_INVALID';
      throw error;
    }
    if (email.length > 320 || phone.length > 80) {
      const error = new Error('Phase 3 email 或 phone 长度无效');
      error.code = 'PHASE3_ACCOUNT_INVALID';
      throw error;
    }
    const keys = [email ? 'email:' + email : null, normalizedPhone ? 'phone:' + normalizedPhone : null]
      .filter(Boolean);
    if (keys.some((key) => seenKeys.has(key))) {
      duplicateIndexes.push(index);
      return;
    }
    keys.forEach((key) => seenKeys.add(key));
    requests.push({
      originalIndex: index,
      email,
      phone: normalizedPhone || phone,
      selectedKey: typeof rawItem.selectedKey === 'string' ? rawItem.selectedKey.trim().slice(0, 512) : null,
    });
  });
  if (requests.length === 0) {
    const error = new Error('Phase 3 账号均为重复项，未创建任务');
    error.code = 'PHASE3_BATCH_EMPTY';
    throw error;
  }
  return { requests, duplicateIndexes };
}

function phase3ClaimKeys(requestItem = {}) {
  const fallback = [
    requestItem.email ? 'email:' + String(requestItem.email).trim().toLowerCase() : null,
    requestItem.phone ? 'phone:' + String(requestItem.phone).replace(/[^0-9]/g, '') : null,
  ].filter(Boolean);
  let identityKeys;
  try { identityKeys = canonicalPhase3Keys(requestItem); } catch { identityKeys = fallback; }
  const safeKeys = (Array.isArray(identityKeys) && identityKeys.length > 0 ? identityKeys : fallback)
    .map((key) => String(key || '').trim())
    .filter((key) => /^(?:email:[^\s]{1,320}|phone:\d{1,80})$/.test(key));
  const effectiveKeys = safeKeys.length > 0 ? safeKeys : fallback;
  return [...new Set(effectiveKeys)].sort().map((key) => 'phase3:' + key);
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

function observePhase3Job({
  job,
  email,
  phone,
  canonicalKeys,
  actor,
  db,
  logger,
  requestId,
  jobManager = null,
  taskRecord = null,
}) {
  const tracked = taskRecord || jobManager?.begin(job, 'phase3', actor) || null;
  let successPersisted = false;
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
  const observation = runPhase3Job({
    email,
    phone,
    canonicalKeys,
    actor,
    db,
    jobId: job.id,
    logger,
    signal: tracked?.controller.signal || null,
    persistSuccess,
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
      const interrupted = error?.code === 'JOB_INTERRUPTED'
        || tracked?.controller.signal.aborted === true;
      try {
        await db.audit({
          jobId: job.id,
          actor,
          action: 'phase3',
          result: interrupted ? 'interrupted' : 'failed',
          details: {
            error: message,
            code: error?.code || null,
            accountDisposition: error?.accountDisposition || null,
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
      try {
        await updateTerminalJob(db, job.id, {
          status: interrupted ? 'interrupted' : 'failed',
          error: message,
          result: {
            code: error?.code || null,
            accountDisposition: error?.accountDisposition || null,
          },
          finishedAt: new Date().toISOString(),
        }, terminalUpdateOptions({
          logger,
          event: 'phase3.job_update_retry',
          requestId,
          jobId: job.id,
          actor,
        }));
      } catch (jobError) {
        writeLog(logger, 'error', 'phase3.job_update_failed', {
          requestId,
          jobId: job.id,
          actor,
          error: safeErrorMessage(jobError),
        });
      }
      writeLog(logger, interrupted ? 'warn' : 'error', interrupted
        ? 'phase3.job_interrupted'
        : 'phase3.job_failed', {
        requestId,
        jobId: job.id,
        actor,
        error: message,
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
  const persistResult = async (result) => {
    const status = result.failed > 0
      ? (result.succeeded > 0 ? 'partial' : 'failed')
      : 'succeeded';
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
  }).then(async (result) => {
    const status = result.failed > 0
      ? (result.succeeded > 0 ? 'partial' : 'failed')
      : 'succeeded';
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
    try {
      await updateTerminalJob(db, job.id, {
        status: interrupted ? 'interrupted' : 'failed',
        error: message,
        result: { code: error?.code || null },
        finishedAt: new Date().toISOString(),
      }, terminalUpdateOptions({
        logger,
        event: 'account_test.job_update_retry',
        requestId,
        jobId: job.id,
        actor,
      }));
    } catch (jobError) {
      writeLog(logger, 'error', 'account_test.job_update_failed', {
        requestId,
        jobId: job.id,
        actor,
        error: safeErrorMessage(jobError),
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
  const selectedKeys = normalizedSelectedKeys(body.selectedKeys);
  if (!selectedKeys) {
    const error = new Error('必须选择至少一个账号后才能导入');
    error.code = 'IMPORT_SELECTION_REQUIRED';
    return error;
  }
  return null;
}

function serveStatic(request, response) {
  const filePath = safeStaticPath(new URL(request.url, 'http://localhost').pathname);
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
  let server;
  server = http.createServer(async (request, response) => {
    const requestId = typeof logger.requestId === 'function'
      ? logger.requestId(request.headers['x-request-id'])
      : crypto.randomUUID();
    const actor = requestActor(request);
    const startedAt = Date.now();
    let requestPath = '/';
    let completed = false;
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
    try { requestPath = new URL(request.url || '/', 'http://localhost').pathname; } catch {}
    writeLog(logger, 'info', 'http.request_started', {
      requestId,
      actor,
      method: request.method,
      path: requestPath,
    });
    try {
      const requestUrl = new URL(request.url || '/', 'http://localhost');
      requestPath = requestUrl.pathname;
      if (jobManager.shuttingDown) {
        response.setHeader('connection', 'close');
        jsonResponse(response, 503, {
          error: 'server_shutting_down',
          message: '面板服务正在停止，请稍后重试',
        });
        return;
      }
      const isReadOnlyGet = request.method === 'GET';
      const requiresWrite = request.method === 'POST'
        && ['/api/sync/import', '/api/phase3', '/api/tokens/expired/delete', '/api/account-tests'].includes(requestUrl.pathname);
      const authError = requestUrl.pathname.startsWith('/api/')
        ? authorizationError(request, requiresWrite)
        : null;
      if (authError) {
        writeLog(logger, 'warn', 'http.auth_failed', {
          requestId,
          actor,
          method: request.method,
          path: requestUrl.pathname,
          statusCode: authError.status,
          error: authError.error,
        });
        if (authError.retryAfterSeconds) response.setHeader('retry-after', String(authError.retryAfterSeconds));
        jsonResponse(response, authError.status, authError);
        return;
      }
      if (request.method === 'POST'
          && JSON_BODY_ENDPOINTS.has(requestUrl.pathname)
          && !hasJsonContentType(request)) {
        writeLog(logger, 'warn', 'http.unsupported_media_type', {
          requestId,
          actor,
          method: request.method,
          path: requestUrl.pathname,
        });
        jsonResponse(response, 415, {
          error: 'json_content_type_required',
          message: '该接口只接受 application/json 请求',
        });
        return;
      }
      if (!isReadOnlyGet && request.method !== 'POST') {
        writeLog(logger, 'warn', 'http.method_not_allowed', {
          requestId,
          actor,
          method: request.method,
          path: requestUrl.pathname,
        });
        response.setHeader('allow', 'GET');
        jsonResponse(response, 405, { error: 'read_only_endpoint' });
        return;
      }
      if (!requestUrl.pathname.startsWith('/api/') && request.method !== 'GET') {
        writeLog(logger, 'warn', 'http.static_method_not_allowed', {
          requestId,
          actor,
          method: request.method,
          path: requestUrl.pathname,
        });
        response.setHeader('allow', 'GET');
        jsonResponse(response, 405, { error: 'read_only_endpoint' });
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
          path: requestUrl.pathname,
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
          path: requestUrl.pathname,
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
          path: requestUrl.pathname,
        });
        response.setHeader('allow', 'GET');
        jsonResponse(response, 405, { error: 'read_only_endpoint' });
        return;
      }
      try {
        jsonResponse(response, 200, await buildSnapshot(requestUrl.searchParams, { logger, requestId, actor }));
      } catch (error) {
        writeLog(logger, 'error', 'http.snapshot_failed', {
          requestId,
          actor,
          error: safeErrorMessage(error),
        });
        jsonResponse(response, 500, {
          error: 'snapshot_failed',
          message: safeErrorMessage(error),
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
          throw new Error('selectedKeys 必须是数组');
        }
        const selectedKeys = body.selectedKeys === undefined || body.selectedKeys === null
          ? []
          : normalizedSelectedKeys(body.selectedKeys, { allowEmpty: true });
        if (body.selectedKeys !== undefined && !selectedKeys) {
          throw new Error('selectedKeys 必须包含有效的账号键');
        }
        const snapshot = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
          includeRaw: true,
          includeInternal: true,
          logger,
          requestId,
          actor,
        });
        if (!confirmedSub2ApiRead(snapshot)) {
          const error = new Error('无法确认 Sub2API 当前账号列表，已停止生成导入计划');
          error.code = 'SUB2API_READ_FAILED';
          throw error;
        }
        const plan = buildImportPlan(snapshot._internal.sources, snapshot._internal.accounts, selectedKeys);
        const snapshotId = await db.saveSnapshot(snapshot);
        writeLog(logger, 'info', 'preview.completed', {
          requestId,
          actor,
          snapshotId,
          version: snapshot.version,
          durationMs: Date.now() - previewStartedAt,
          counts: importPlanSummary(plan).counts,
        });
        jsonResponse(response, 200, {
          readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
          snapshotId,
          version: snapshot.version,
          generatedAt: snapshot.generatedAt,
          selectedKeys,
          ...importPlanSummary(plan),
        });
      } catch (error) {
        writeLog(logger, 'error', 'preview.failed', {
          requestId,
          actor,
          durationMs: Date.now() - previewStartedAt,
          error: safeErrorMessage(error),
        });
        const status = error?.code === 'REQUEST_BODY_TOO_LARGE' ? 413
          : error?.code === 'SUB2API_READ_FAILED' ? 502 : 400;
        jsonResponse(response, status, { error: error?.code || 'preview_failed', message: safeErrorMessage(error) });
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
        const { job, trackedImport } = await jobManager.withAdmission(async () => {
          const created = await withControlPlaneLock(async () => db.createJob('token_import', {
            snapshotVersion: body.snapshotVersion,
            selectedKeys,
          }, actor, { claimKeys: ['token_import'] }));
          return {
            job: created,
            trackedImport: jobManager.begin(created, 'token_import', actor),
          };
        });
        writeLog(logger, 'info', 'import.job_queued', {
          requestId,
          jobId: job.id,
          actor,
          expectedVersion: body.snapshotVersion || null,
          selectedCount: selectedKeys.length,
          durationMs: Date.now() - importRequestStartedAt,
        });
        const importObservation = Promise.resolve().then(() => {
          throwIfJobInterrupted(trackedImport.controller.signal);
          return executeImport({
            snapshotVersion: body.snapshotVersion,
            selectedKeys,
            actor,
            db,
            jobId: job.id,
            logger,
            signal: trackedImport.controller.signal,
          });
        }).then(async (result) => {
          const status = tokenImportJobStatus(result);
          try {
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
          } catch (jobError) {
            // The remote operation has already completed. Keep that outcome
            // in logs rather than relabeling a successful remote write as a
            // failed import because local SQLite became unavailable.
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
            || trackedImport.controller.signal.aborted;
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
          try {
            await updateTerminalJob(db, job.id, {
              status: interrupted ? 'interrupted' : 'failed',
              error: message,
              result: { code: error?.code || null },
              finishedAt: new Date().toISOString(),
            }, terminalUpdateOptions({
              logger,
              event: 'import.job_update_retry',
              requestId,
              jobId: job.id,
              actor,
            }));
          } catch (jobError) {
            writeLog(logger, 'error', 'import.job_update_failed', {
              requestId,
              jobId: job.id,
              actor,
              error: safeErrorMessage(jobError),
            });
          }
          writeLog(logger, 'error', 'import.job_failed', {
            requestId,
            jobId: job.id,
            actor,
            error: message,
          });
        });
        jobManager.track(trackedImport, importObservation);
        jsonResponse(response, 202, { jobId: job.id, status: 'queued' });
      } catch (error) {
        writeLog(logger, 'error', 'import.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - importRequestStartedAt,
          error: safeErrorMessage(error),
        });
        const status = error?.code === 'REQUEST_BODY_TOO_LARGE' ? 413
          : error?.code === 'JOB_ALREADY_CLAIMED' ? 409 : 400;
        jsonResponse(response, status, { error: error?.code || 'import_failed', message: safeErrorMessage(error) });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/phase3') {
      const phase3RequestStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        const bodyError = requestBodyObjectError(body);
        if (bodyError) throw bodyError;
        const { requests, duplicateIndexes } = normalizePhase3Requests(body);
        const resolved = resolvePhase3Requests(requests);
        const resolvedRequests = resolved.eligible;
        const queued = [];
        const rejected = duplicateIndexes.map((index) => ({
          index,
          error: 'duplicate_in_request',
          message: '同一请求中账号重复，已合并为一个任务',
        })).concat(resolved.rejected);
        let enqueueFailure = null;
        const enqueue = async () => {
        const batchClaimKeys = new Set();
        const maximumActive = boundedEnvNumber('PANEL_PHASE3_MAX_ACTIVE_JOBS', 100, 1, 100);
        let activeCount = await db.countActiveJobs('phase3');
        for (const requestItem of resolvedRequests) {
          if (activeCount >= maximumActive) {
            rejected.push({
              index: requestItem.originalIndex,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              error: 'phase3_queue_full',
              message: 'Phase 3 活跃任务已达到安全上限',
            });
            continue;
          }
          const claimKeys = phase3ClaimKeys(requestItem);
          if (claimKeys.some((key) => batchClaimKeys.has(key))) {
            rejected.push({
              index: requestItem.originalIndex,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              error: 'duplicate_in_request',
              message: '同一请求中账号重复，已合并为一个任务',
            });
            continue;
          }
          claimKeys.forEach((key) => batchClaimKeys.add(key));
          const existingPhase3Job = getActivePhase3Job(requestItem);
          if (existingPhase3Job) {
            rejected.push({
              index: requestItem.originalIndex,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              error: 'phase3_already_running',
              message: '该账号已有 Phase 3 任务排队或运行中',
              jobId: existingPhase3Job.jobId || null,
            });
            writeLog(logger, 'warn', 'phase3.duplicate_rejected', {
              requestId,
              actor,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              existingJobId: existingPhase3Job.jobId || null,
            });
            continue;
          }
          let job;
          try {
            job = await db.createJob('phase3', {
            email: requestItem.email || null,
            phone: requestItem.phone || null,
            canonicalKeys: requestItem.canonicalKeys,
            selectedKey: requestItem.selectedKey || null,
            batch: resolvedRequests.length > 1,
            }, actor, {
              claimKeys,
            });
          } catch (error) {
            if (error?.code !== 'JOB_ALREADY_CLAIMED') {
              enqueueFailure = error;
              rejected.push({
                index: requestItem.originalIndex,
                email: requestItem.email || null,
                phone: requestItem.phone || null,
                error: 'phase3_enqueue_failed',
                message: 'Phase 3 任务入队失败，已停止本批后续入队',
              });
              break;
            }
            rejected.push({
              index: requestItem.originalIndex,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              error: 'phase3_already_running',
              message: '该账号已有 Phase 3 任务排队或运行中',
              jobId: error.existingJobId || null,
            });
            writeLog(logger, 'warn', 'phase3.duplicate_rejected', {
              requestId,
              actor,
              email: requestItem.email || null,
              phone: requestItem.phone || null,
              existingJobId: error.existingJobId || null,
            });
            continue;
          }
          queued.push({ ...requestItem, job });
          activeCount += 1;
          writeLog(logger, 'info', 'phase3.job_queued', {
            requestId,
            jobId: job.id,
            actor,
            email: requestItem.email || null,
            phone: requestItem.phone || null,
            batch: resolvedRequests.length > 1,
            durationMs: Date.now() - phase3RequestStartedAt,
          });
        }
        };
        await jobManager.withAdmission(async () => {
          try {
            await withControlPlaneLock(enqueue);
          } catch (error) {
            enqueueFailure = error;
          }
          // Jobs already persisted before a later batch failure must always be
          // observed; otherwise they would remain queued with live claims until
          // the whole service restarts.
          for (const item of queued) {
            observePhase3Job({
              job: item.job,
              email: item.email,
              phone: item.phone,
              canonicalKeys: item.canonicalKeys,
              actor,
              db,
              logger,
              requestId,
              jobManager,
            });
          }
        });
        if (queued.length === 0) {
          if (enqueueFailure) throw enqueueFailure;
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
        if (enqueueFailure) {
          writeLog(logger, 'error', 'phase3.batch_enqueue_partial', {
            requestId,
            actor,
            queuedCount: queued.length,
            rejectedCount: rejected.length,
            error: safeErrorMessage(enqueueFailure),
          });
        }
        const jobIds = queued.map((item) => item.job.id);
        jsonResponse(response, 202, {
          batch: jobIds.length > 1,
          status: 'queued',
          jobId: jobIds.length === 1 ? jobIds[0] : null,
          jobIds,
          jobs: queued.map((item) => ({
            jobId: item.job.id,
            email: item.email || null,
            phone: item.phone || null,
            status: 'queued',
          })),
          rejected,
        });
      } catch (error) {
        writeLog(logger, 'error', 'phase3.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - phase3RequestStartedAt,
          error: safeErrorMessage(error),
        });
        const status = error?.code === 'REQUEST_BODY_TOO_LARGE' ? 413 : 400;
        jsonResponse(response, status, { error: error?.code || 'phase3_failed', message: safeErrorMessage(error) });
      }
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/account-tests/models') {
      const accountId = Number(requestUrl.searchParams.get('accountId') || requestUrl.searchParams.get('account_id'));
      if (!Number.isSafeInteger(accountId) || accountId <= 0) {
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
          error: safeErrorMessage(error),
        });
        jsonResponse(response, 502, {
          error: 'ACCOUNT_TEST_MODELS_FAILED',
          message: safeErrorMessage(error),
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/account-tests') {
      const accountTestRequestStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        const requestData = normalizeAccountTestRequest(body);
        const { submission, taskRecord } = await jobManager.withAdmission(async () => {
          const submitted = await withAccountTestSubmissionLock(async () => {
            const client = new Sub2ApiAdminClient({ logger, logContext: { requestId, actor } });
            const accounts = await client.listAccounts({ platform: 'openai', type: 'oauth', pageSize: 200 });
            const jobs = await db.listJobs(200);
            const classified = classifyAccountTestTargets(accounts, requestData.accountIds, activeAccountTestJobs(jobs));
            if (classified.eligible.length === 0) return classified;
            const accountIds = classified.eligible.map((item) => item.id);
            const targetBaselines = classified.eligible.map((item) => accountTestTargetBaseline(item.account));
            if (targetBaselines.some((baseline) => !baseline)) {
              const error = new Error('无法建立账号测试目标的身份与状态基线');
              error.code = 'ACCOUNT_TEST_BASELINE_INVALID';
              throw error;
            }
            const job = await db.createJob('account_test', {
              accountIds,
              targetBaselines,
              modelId: requestData.modelId,
              // Prompts are forwarded only through the in-memory worker closure.
              // Persisting arbitrary prompt text would make an unlabelled secret
              // retrievable through the jobs API even after log redaction.
              promptPresent: requestData.prompt.length > 0,
              promptLength: requestData.prompt.length,
            }, actor, {
              claimKeys: accountIds.map((id) => 'account_test:' + String(id)),
            });
            return { ...classified, accountIds, targetBaselines, job };
          });
          return {
            submission: submitted,
            taskRecord: submitted.job
              ? jobManager.begin(submitted.job, 'account_test', actor)
              : null,
          };
        });
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
        writeLog(logger, 'info', 'account_test.job_queued', {
          requestId,
          jobId: submission.job.id,
          actor,
          accountCount: submission.accountIds.length,
          rejectedCount: submission.rejected.length,
          model: requestData.modelId || null,
          durationMs: Date.now() - accountTestRequestStartedAt,
        });
        observeAccountTestJob({
          job: submission.job,
          accountIds: submission.accountIds,
          targetBaselines: submission.targetBaselines,
          modelId: requestData.modelId,
          prompt: requestData.prompt,
          actor,
          db,
          logger,
          requestId,
          jobManager,
          taskRecord,
        });
        jsonResponse(response, 202, {
          jobId: submission.job.id,
          status: 'queued',
          accountIds: submission.accountIds,
          rejected: submission.rejected,
        });
      } catch (error) {
        writeLog(logger, 'error', 'account_test.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - accountTestRequestStartedAt,
          code: error?.code || null,
          error: safeErrorMessage(error),
        });
        const status = error?.code === 'REQUEST_BODY_TOO_LARGE' ? 413
          : error?.code === 'ACCOUNT_TEST_NO_ELIGIBLE_ACCOUNTS' ? 409
            : error?.code === 'JOB_ALREADY_CLAIMED' ? 409
            : error?.message?.includes('required') ? 503 : 400;
        jsonResponse(response, status, {
          error: error?.code || 'account_test_failed',
          message: safeErrorMessage(error),
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
        });
      } catch (error) {
        writeLog(logger, 'error', 'token_cleanup.scan_failed', {
          requestId,
          actor,
          error: safeErrorMessage(error),
        });
        jsonResponse(response, 500, { error: 'token_cleanup_scan_failed', message: safeErrorMessage(error) });
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
        const result = await withControlPlaneLock(() => deleteExpiredTokens({
          expectedVersion: body.version,
          confirmation: body.confirmation,
        }));
        const details = {
          count: result.count,
          skipped: result.skipped,
          items: result.deleted,
        };
        try {
          await db.audit({
            actor,
            action: 'expired_token_cleanup',
            targetKey: 'gpt_register:expired_tokens',
            result: result.skipped.length > 0 ? 'partial' : 'ok',
            details,
          });
        } catch (auditError) {
          writeLog(logger, 'error', 'token_cleanup.audit_failed', {
            requestId,
            actor,
            error: safeErrorMessage(auditError),
          });
        }
        writeLog(logger, result.skipped.length > 0 ? 'warn' : 'info', 'token_cleanup.completed', {
          requestId,
          actor,
          deletedCount: result.count,
          skippedCount: result.skipped.length,
          durationMs: Date.now() - cleanupStartedAt,
        });
        jsonResponse(response, 200, {
          status: result.skipped.length > 0 ? 'partial' : 'succeeded',
          count: result.count,
          deleted: result.deleted.map(safeExpiredTokenItem),
          skipped: result.skipped.map(safeExpiredTokenItem),
        });
      } catch (error) {
        writeLog(logger, 'error', 'token_cleanup.failed', {
          requestId,
          actor,
          code: error?.code || null,
          error: safeErrorMessage(error),
          durationMs: Date.now() - cleanupStartedAt,
        });
        const status = ['TOKEN_CLEANUP_STALE', 'JOB_ALREADY_CLAIMED'].includes(error?.code) ? 409 : 400;
        jsonResponse(response, status, {
          error: error?.code || 'token_cleanup_failed',
          message: safeErrorMessage(error),
          currentVersion: error?.currentVersion || undefined,
        });
      }
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/jobs') {
      jsonResponse(response, 200, { jobs: await db.listJobs(requestUrl.searchParams.get('limit')) });
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

    serveStatic(request, response);
    } catch (error) {
      writeLog(logger, 'error', 'http.request_failed', {
        requestId,
        actor,
        method: request.method,
        path: requestPath,
        statusCode: 500,
        error: safeErrorMessage(error),
      });
      if (!response.headersSent) {
        jsonResponse(response, 500, { error: 'internal_error', message: safeErrorMessage(error) });
      } else if (!response.writableEnded) {
        response.end();
      }
    }
  });
  const requestTimeout = boundedEnvNumber('PANEL_HTTP_REQUEST_TIMEOUT_MS', 30_000, 1_000, 300_000);
  server.requestTimeout = requestTimeout;
  server.headersTimeout = Math.min(
    requestTimeout,
    boundedEnvNumber('PANEL_HTTP_HEADERS_TIMEOUT_MS', 15_000, 1_000, 120_000),
  );
  server.keepAliveTimeout = boundedEnvNumber('PANEL_HTTP_KEEP_ALIVE_TIMEOUT_MS', 5_000, 1_000, 60_000);
  server.maxHeadersCount = boundedEnvNumber('PANEL_HTTP_MAX_HEADERS', 100, 16, 1_000);
  server.maxRequestsPerSocket = boundedEnvNumber('PANEL_HTTP_MAX_REQUESTS_PER_SOCKET', 100, 1, 10_000);
  server.panelLogger = logger;
  server.panelDb = db;
  server.panelJobManager = jobManager;
  return server;
}

async function startServer(options = {}) {
  validateRuntimeConfiguration();
  const host = options.host ?? process.env.PANEL_HOST ?? '127.0.0.1';
  const port = Number(options.port ?? process.env.PANEL_PORT ?? 4170);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    const error = new Error('PANEL_PORT 必须是 0 到 65535 的整数');
    error.code = 'PANEL_PORT_INVALID';
    throw error;
  }
  let server;
  try {
    validateListenConfiguration(host);
    server = createServer(options);
  } catch (error) {
    throw error;
  }
  await server.panelDb?.ready;
  return new Promise((resolve, reject) => {
    server.once('error', (error) => {
      writeLog(server.panelLogger, 'error', 'server.start_failed', {
        host,
        port,
        error: safeErrorMessage(error),
      });
      reject(error);
    });
    server.listen(port, host, () => {
      const address = server.address();
      writeLog(server.panelLogger, 'info', 'server.started', {
        host,
        port: address.port,
        pid: process.pid,
      });
      process.stdout.write('gpt-register-panel listening on http://' + host + ':' + address.port + '\n');
      resolve(server);
    });
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
  emitter.once('SIGTERM', onSigterm);
  emitter.once('SIGINT', onSigint);
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
  requestBodyObjectError,
  resetAuthFailureBuckets,
  safeStaticPath,
  tokenImportJobStatus,
  normalizePhase3Requests,
  phase3ClaimKeys,
};
