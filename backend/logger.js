const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { ensureDirectoryTree, assertDirectoryTree } = require('./lib/safeFs');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MAX_LOG_BYTES = 128 * 1024 * 1024;
const MAX_LOG_ROTATIONS = 100;
const LOG_TAIL_BLOCK_BYTES = 64 * 1024;
const LOG_TAIL_MAX_BYTES = 4 * 1024 * 1024;
const SECRET_KEY = /(^|_)(access_tokens?|refresh_tokens?|id_tokens?|passwords?|passwds?|pwds?|prompts?|secrets?|secret_keys?|private_keys?|signing_keys?|encryption_keys?|secret_access_keys?|access_key_ids?|service_account_keys?|key_materials?|mfa_secrets?|totp_secrets?|recovery_codes?|api_?keys?|authorizations?|authorization_codes?|oauth_codes?|verification_codes?|code_verifiers?|cookies?|tokens?|credentials?|nonces?|client_secrets?|jwts?|验证码|授权码)(?:_(?:values?|payloads?|data|raw|headers?|bodies|texts?|json|lists?|maps?|objects?|arrays?))?$/i;
const NON_SECRET_METADATA_WORDS = new Set([
  'count', 'counts', 'fingerprint', 'fingerprints', 'status', 'statuses',
  'state', 'states', 'expiry', 'expiries', 'expiration', 'expirations',
  'expires', 'expires_at', 'mtime', 'mtime_ms', 'size', 'length',
]);
const SECRET_TEXT = [
  /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----|$)/gi,
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /Basic\s+[A-Za-z0-9._~+/=-]+/gi,
  /admin-[A-Za-z0-9._~-]{16,}/gi,
  /sk-[A-Za-z0-9_-]{16,}/gi,
  /eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*){2,4}/g,
  /\brt(?:\.[A-Za-z0-9_-]+){1,5}\b/gi,
];

function asLevel(value) {
  const level = String(value || 'info').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(LEVELS, level) ? level : 'info';
}

function normalizeSecretKey(key) {
  return String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9\u4e00-\u9fff]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function jsonRedaction(value) {
  const trimmed = String(value || '').trim();
  if (!trimmed || !['{', '['].includes(trimmed[0])) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== 'object') return null;
    return JSON.stringify(redactValue(parsed));
  } catch {
    return null;
  }
}

function assignedValueSpan(text, start) {
  if (start >= text.length) return { end: start, replacement: '[redacted]' };
  const quote = text[start] === '"' || text[start] === "'" ? text[start] : null;
  if (quote) {
    let escaped = false;
    for (let index = start + 1; index < text.length; index += 1) {
      const character = text[index];
      if (!escaped && character === quote) {
        return { end: index + 1, replacement: quote + '[redacted]' + quote };
      }
      if (!escaped && character === '\\') escaped = true;
      else escaped = false;
    }
    return {
      end: text.length,
      replacement: quote + '[redacted]',
    };
  }

  const opening = text[start];
  const closing = opening === '{' ? '}' : opening === '[' ? ']' : null;
  if (closing) {
    const stack = [closing];
    let stringQuote = null;
    let escaped = false;
    for (let index = start + 1; index < text.length; index += 1) {
      const character = text[index];
      if (stringQuote) {
        if (!escaped && character === stringQuote) stringQuote = null;
        if (!escaped && character === '\\') escaped = true;
        else escaped = false;
        continue;
      }
      if (character === '"' || character === "'") {
        stringQuote = character;
        continue;
      }
      if (character === '{') stack.push('}');
      else if (character === '[') stack.push(']');
      else if (character === stack[stack.length - 1]) {
        stack.pop();
        if (stack.length === 0) return { end: index + 1, replacement: '[redacted]' };
      }
    }
    return {
      end: text.length,
      replacement: '[redacted]',
    };
  }

  // Unquoted credentials are a single token. Stopping at whitespace avoids
  // hiding the rest of an ordinary diagnostic sentence; callers can quote a
  // credential that genuinely contains spaces.
  const delimiterOffset = text.slice(start).search(/[\s,;}&]/);
  const end = delimiterOffset < 0 ? text.length : start + delimiterOffset;
  return { end, replacement: '[redacted]' };
}

function redactMultiwordAssignments(value) {
  const text = String(value || '');
  // Natural-language diagnostics often spell names as "access token" or
  // "API key". Match a bounded label (at most four words), then use the same
  // normalized allowlist as structured fields rather than accepting arbitrary
  // prose before a colon.
  const pattern = /(^|[^A-Za-z0-9_])(["']?)([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_\-\u4e00-\u9fff]*(?:[ \t]+[A-Za-z_\u4e00-\u9fff][A-Za-z0-9_\-\u4e00-\u9fff]*){1,3})(["']?[ \t]*[:=][ \t]*)/gi;
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (!SECRET_KEY.test(normalizeSecretKey(match[3]))) continue;
    if (match.index < cursor) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3] + match[4];
    const span = assignedValueSpan(text, pattern.lastIndex);
    output += span.replacement;
    cursor = span.end;
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function redactAssignments(value) {
  const text = String(value || '');
  const pattern = /(^|[^A-Za-z0-9_])(["']?)([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_\-\u4e00-\u9fff]*)(["']?[ \t]*[:=][ \t]*)/gi;
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (!SECRET_KEY.test(normalizeSecretKey(match[3]))) continue;
    if (match.index < cursor) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3] + match[4];
    const span = assignedValueSpan(text, pattern.lastIndex);
    output += span.replacement;
    cursor = span.end;
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function startsWithNonSecretMetadata(text, start) {
  const match = /^[A-Za-z_][A-Za-z0-9_-]{0,63}/.exec(text.slice(start));
  return Boolean(match && NON_SECRET_METADATA_WORDS.has(normalizeSecretKey(match[0])));
}

function redactSpaceSeparatedPattern(value, pattern) {
  const text = String(value || '');
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (match.index < cursor) continue;
    if (match[3].length > 128 || !SECRET_KEY.test(normalizeSecretKey(match[3]))) continue;
    let valueStart = pattern.lastIndex;
    const connector = /^(?:is|was|are|were)\b[ \t]+/i.exec(text.slice(valueStart));
    if (connector) valueStart += connector[0].length;
    if (valueStart >= text.length || startsWithNonSecretMetadata(text, valueStart)) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3] + match[4];
    output += text.slice(pattern.lastIndex, valueStart);
    const span = assignedValueSpan(text, valueStart);
    output += span.replacement;
    cursor = span.end;
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function redactSpaceSeparatedSecrets(value) {
  // These labels deliberately enumerate credential concepts. The optional
  // container word covers phrases such as "credential map {...}" without
  // turning ordinary "token count/status/fingerprint" diagnostics into
  // secrets. Labels and single-key forms are both length bounded.
  const naturalPattern = /(^|[^A-Za-z0-9_])(["']?)((?:(?:access|refresh|id)[ \t]+tokens?|api[ \t]+keys?|private[ \t]+keys?|signing[ \t]+keys?|encryption[ \t]+keys?|secret[ \t]+access[ \t]+keys?|access[ \t]+key[ \t]+ids?|service[ \t]+account[ \t]+keys?|key[ \t]+materials?|mfa[ \t]+secrets?|totp[ \t]+secrets?|recovery[ \t]+codes?|authorization(?:[ \t]+codes?)?|oauth[ \t]+codes?|verification[ \t]+codes?|code[ \t]+verifiers?|client[ \t]+secrets?|secret[ \t]+keys?|passwords?|passwds?|secrets?|cookies?|tokens?|credentials?|nonces?|jwts?)(?:[ \t]+(?:values?|payloads?|data|raw|headers?|bodies|texts?|json|lists?|maps?|objects?|arrays?))?)(["']?[ \t]+)/gi;
  const singleKeyPattern = /(^|[^A-Za-z0-9_])(["']?)([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_\-\u4e00-\u9fff]{0,127})(["']?[ \t]+)/gi;
  return redactSpaceSeparatedPattern(
    redactSpaceSeparatedPattern(value, naturalPattern),
    singleKeyPattern,
  );
}

function redactUrlUserinfo(value) {
  return String(value || '').replace(
    /\b([A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/)([^/?#\s@]+)@/g,
    '$1[redacted]@',
  );
}

function redactText(value) {
  let text = String(value === undefined || value === null ? '' : value);
  const structured = jsonRedaction(text);
  if (structured !== null) return structured;

  // Authorization and cookie header values may contain spaces or multiple
  // semicolon-delimited credentials. Treat the entire header value as secret.
  text = redactUrlUserinfo(text);
  text = text.replace(/\b((?:proxy[_-]?)?authorization|(?:set[_-]?)?cookie)\s*:\s*[^\r\n]*/gi, '$1: [redacted]');
  for (const pattern of SECRET_TEXT) text = text.replace(pattern, '[redacted]');
  // Assignment forms must run first: otherwise the whitespace-only matcher
  // could consume the container word in `credential payload: {...}` as if it
  // were the secret value and leave the actual payload behind.
  return redactSpaceSeparatedSecrets(redactAssignments(redactMultiwordAssignments(text)));
}

function readTailText(descriptor, fileSize, lineLimit) {
  let position = Math.max(0, Math.floor(Number(fileSize) || 0));
  let totalRead = 0;
  let completeLines = 0;
  let currentLineHasContent = false;
  let startsAtLineBoundary = position === 0;
  const chunks = [];

  while (position > 0 && totalRead < LOG_TAIL_MAX_BYTES) {
    const length = Math.min(
      LOG_TAIL_BLOCK_BYTES,
      position,
      LOG_TAIL_MAX_BYTES - totalRead,
    );
    const start = position - length;
    const buffer = Buffer.alloc(length);
    const bytesRead = fs.readSync(descriptor, buffer, 0, length, start);
    if (bytesRead !== length) throw new Error('日志文件在读取期间发生变化');
    totalRead += bytesRead;
    position = start;

    let sliceStart = 0;
    for (let index = bytesRead - 1; index >= 0; index -= 1) {
      const byte = buffer[index];
      if (byte === 0x0a) {
        if (!currentLineHasContent) continue;
        completeLines += 1;
        currentLineHasContent = false;
        if (completeLines >= lineLimit) {
          sliceStart = index + 1;
          startsAtLineBoundary = true;
          break;
        }
      } else if (byte !== 0x0d) {
        currentLineHasContent = true;
      }
    }
    chunks.unshift(buffer.subarray(sliceStart));
    if (startsAtLineBoundary) break;
  }

  if (position === 0) startsAtLineBoundary = true;
  let bytes = Buffer.concat(chunks);
  if (!startsAtLineBoundary) {
    const firstNewline = bytes.indexOf(0x0a);
    bytes = firstNewline < 0 ? Buffer.alloc(0) : bytes.subarray(firstNewline + 1);
  }
  return bytes.toString('utf8');
}

function redactValue(value, key = '', seen = new WeakSet()) {
  const normalizedKey = normalizeSecretKey(key);
  if (SECRET_KEY.test(normalizedKey)) return '[redacted]';
  if (typeof value === 'string') return redactText(value);
  if (typeof value === 'bigint') return String(value);
  if (Array.isArray(value)) {
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    return value.map((item) => redactValue(item, '', seen));
  }
  if (value && typeof value === 'object') {
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    const output = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      output[childKey] = redactValue(childValue, childKey, seen);
    }
    return output;
  }
  return value;
}

function safeErrorText(error, limit = 8192) {
  const safeLimit = Math.max(256, Math.min(64 * 1024, Number(limit) || 8192));
  let stack;
  let code;
  try { stack = String(error?.stack || error?.message || error || 'unknown error'); } catch {
    stack = 'unknown error';
  }
  try {
    const candidate = String(error?.code || '').trim();
    code = /^[A-Za-z0-9_.-]{1,100}$/.test(candidate) ? candidate : '';
  } catch {
    code = '';
  }
  return redactText((code ? 'code=' + code + '\n' : '') + stack).slice(0, safeLimit);
}

function numberFromEnv(value, fallback, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= minimum ? Math.min(parsed, maximum) : fallback;
}

class PanelLogger {
  constructor(options = {}) {
    const dbPath = String(options.dbPath || process.env.PANEL_DB_PATH || '');
    const defaultDirectory = dbPath
      ? path.dirname(path.resolve(dbPath))
      : path.join('/tmp', 'gpt-register-panel');
    this.filePath = path.resolve(
      options.filePath || process.env.PANEL_LOG_PATH || path.join(defaultDirectory, 'panel.log'),
    );
    this.level = asLevel(options.level || process.env.PANEL_LOG_LEVEL || 'info');
    this.maxBytes = Math.floor(numberFromEnv(
      options.maxBytes || process.env.PANEL_LOG_MAX_BYTES,
      10 * 1024 * 1024,
      1024,
      MAX_LOG_BYTES,
    ));
    this.rotations = Math.floor(numberFromEnv(
      options.rotations || process.env.PANEL_LOG_ROTATIONS,
      5,
      1,
      MAX_LOG_ROTATIONS,
    ));
    const consoleValue = options.console === undefined
      ? process.env.PANEL_LOG_CONSOLE ?? '1'
      : options.console;
    this.consoleEnabled = consoleValue !== false
      && String(consoleValue).toLowerCase() !== '0'
      && String(consoleValue).toLowerCase() !== 'false';
    this.failedWrites = 0;
    this.fallbackReports = 0;
    this.consecutiveWriteFailures = 0;
    this.lastWriteFailureAt = null;
    this.lastWriteSucceededAt = null;
    this.fileHealthy = false;
    this.pid = process.pid;
    this.directoryIdentity = null;
    this.ensureDirectory();
  }

  ensureDirectory() {
    let descriptor;
    let pinnedDirectory;
    try {
      const directory = ensureDirectoryTree(path.dirname(this.filePath), '日志目录');
      const directoryStat = fs.lstatSync(directory);
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
      if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()
          || (currentUid !== null && directoryStat.uid !== currentUid)
          || (directoryStat.mode & 0o022) !== 0) {
        throw new Error('日志目录必须由当前用户持有且不可由组或其他用户写入');
      }
      this.directoryIdentity = {
        realPath: fs.realpathSync(directory),
        dev: directoryStat.dev,
        ino: directoryStat.ino,
      };
      pinnedDirectory = this.openPinnedDirectory();
      const pinnedFilePath = this.filePathIn(pinnedDirectory);
      let fileStat;
      try { fileStat = fs.lstatSync(pinnedFilePath); } catch (error) {
        if (error?.code === 'ENOENT') fileStat = null;
        else throw error;
      }
      if (fileStat && (fileStat.isSymbolicLink() || !fileStat.isFile() || fileStat.nlink !== 1
          || (currentUid !== null && fileStat.uid !== currentUid)
          || (fileStat.mode & 0o022) !== 0)) {
        throw new Error('日志文件必须是当前用户持有且不可被其他用户修改的普通文件');
      }

      // Probe the actual destination during startup. Merely validating the
      // parent directory would let a read-only mount, exhausted filesystem,
      // or an unsafe file replacement silently disable the entire audit log.
      const timestamp = new Date().toISOString();
      const line = JSON.stringify({
        timestamp,
        level: 'info',
        event: 'logger.write_preflight',
        pid: this.pid,
      }) + '\n';
      this.rotateIfNeeded(Buffer.byteLength(line), pinnedDirectory);
      descriptor = this.openValidatedFile(pinnedDirectory);
      fs.fchmodSync(descriptor, 0o600);
      fs.writeFileSync(descriptor, line);
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      // A file fsync does not make a newly-created current log or rotation
      // rename durable. Sync the exact directory FD used for the write before
      // the startup preflight is allowed to report success.
      this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.lastWriteSucceededAt = timestamp;
    } catch (error) {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      this.directoryIdentity = null;
      this.fileHealthy = false;
      this.fallback('error', 'logger.initialize_failed', { error: error.message });
      const wrapped = new Error('审计日志初始化失败，拒绝启动');
      wrapped.code = 'PANEL_LOG_INITIALIZATION_FAILED';
      wrapped.cause = error;
      throw wrapped;
    } finally {
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
  }

  filePathIn(pinnedDirectory) {
    return path.join(pinnedDirectory.accessDirectory, path.basename(this.filePath));
  }

  assertPinnedDirectory(pinnedDirectory) {
    if (!pinnedDirectory || !Number.isInteger(pinnedDirectory.descriptor)) {
      throw new Error('日志目录未固定');
    }
    const stat = fs.fstatSync(pinnedDirectory.descriptor);
    const identity = this.directoryIdentity;
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (!identity || !stat.isDirectory()
        || stat.dev !== identity.dev || stat.ino !== identity.ino
        || (currentUid !== null && stat.uid !== currentUid)
        || (stat.mode & 0o022) !== 0) {
      throw new Error('日志目录 FD 与初始化时的安全目录不一致');
    }
    this.assertDirectorySafe();
  }

  openPinnedDirectory() {
    this.assertDirectorySafe();
    const identity = this.directoryIdentity;
    let descriptor;
    try {
      descriptor = fs.openSync(
        identity.realPath,
        fs.constants.O_RDONLY
          | (fs.constants.O_DIRECTORY || 0)
          | (fs.constants.O_NOFOLLOW || 0),
      );
      const pinnedDirectory = {
        descriptor,
        accessDirectory: identity.realPath,
      };
      this.assertPinnedDirectory(pinnedDirectory);
      if (process.platform === 'linux') {
        const accessDirectory = '/proc/self/fd/' + descriptor;
        if (fs.realpathSync(accessDirectory) !== identity.realPath) {
          throw new Error('日志目录 FD 解析结果不一致');
        }
        pinnedDirectory.accessDirectory = accessDirectory;
      }
      descriptor = undefined;
      return pinnedDirectory;
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
    }
  }

  syncPinnedDirectory(pinnedDirectory) {
    this.assertPinnedDirectory(pinnedDirectory);
    fs.fsyncSync(pinnedDirectory.descriptor);
    // Do not return a durable-checkpoint success if the configured path was
    // replaced while the pinned directory itself was being synchronized.
    this.assertPinnedDirectory(pinnedDirectory);
  }

  openValidatedFile(pinnedDirectory) {
    this.assertPinnedDirectory(pinnedDirectory);
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    const descriptor = fs.openSync(
      this.filePathIn(pinnedDirectory),
      fs.constants.O_APPEND
        | fs.constants.O_CREAT
        | fs.constants.O_WRONLY
        | noFollow
        | (fs.constants.O_NONBLOCK || 0),
      0o600,
    );
    try {
      const stat = fs.fstatSync(descriptor);
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
      if (!stat.isFile() || stat.nlink !== 1
          || (currentUid !== null && stat.uid !== currentUid)
          || (stat.mode & 0o022) !== 0) {
        throw new Error('日志文件必须是当前用户持有且不可被其他用户修改的普通文件');
      }
      return descriptor;
    } catch (error) {
      try { fs.closeSync(descriptor); } catch {}
      throw error;
    }
  }

  probe() {
    let descriptor;
    let pinnedDirectory;
    try {
      const line = JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'debug',
        event: 'logger.write_preflight',
        pid: this.pid,
      }) + '\n';
      pinnedDirectory = this.openPinnedDirectory();
      this.rotateIfNeeded(Buffer.byteLength(line), pinnedDirectory);
      descriptor = this.openValidatedFile(pinnedDirectory);
      fs.fchmodSync(descriptor, 0o600);
      fs.writeFileSync(descriptor, line);
      fs.fsyncSync(descriptor);
      this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.consecutiveWriteFailures = 0;
      this.lastWriteSucceededAt = new Date().toISOString();
      return true;
    } catch (error) {
      this.fileHealthy = false;
      this.failedWrites += 1;
      this.consecutiveWriteFailures += 1;
      this.lastWriteFailureAt = new Date().toISOString();
      this.fallback('error', 'logger.probe_failed', { error: error.message });
      return false;
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
  }

  checkpoint(event, fields = {}) {
    let descriptor;
    let pinnedDirectory;
    const checkpointEvent = String(event || 'logger.audit_checkpoint');
    try {
      const timestamp = new Date().toISOString();
      const safeFields = fields && typeof fields === 'object' && !Array.isArray(fields)
        ? redactValue(fields)
        : {};
      const line = JSON.stringify({
        ...safeFields,
        timestamp,
        level: 'info',
        event: redactText(checkpointEvent),
        pid: this.pid,
      }) + '\n';
      pinnedDirectory = this.openPinnedDirectory();
      this.rotateIfNeeded(Buffer.byteLength(line), pinnedDirectory);
      descriptor = this.openValidatedFile(pinnedDirectory);
      fs.fchmodSync(descriptor, 0o600);
      fs.writeFileSync(descriptor, line);
      fs.fsyncSync(descriptor);
      this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.consecutiveWriteFailures = 0;
      this.lastWriteSucceededAt = timestamp;
      return true;
    } catch (error) {
      this.fileHealthy = false;
      this.failedWrites += 1;
      this.consecutiveWriteFailures += 1;
      this.lastWriteFailureAt = new Date().toISOString();
      this.fallback('error', 'logger.checkpoint_failed', {
        checkpointEvent,
        error: error.message,
      });
      return false;
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
  }

  health() {
    return {
      healthy: this.fileHealthy && this.directoryIdentity !== null,
      failedWrites: this.failedWrites,
      consecutiveWriteFailures: this.consecutiveWriteFailures,
      lastWriteFailureAt: this.lastWriteFailureAt,
      lastWriteSucceededAt: this.lastWriteSucceededAt,
    };
  }

  assertDirectorySafe() {
    if (!this.directoryIdentity) throw new Error('日志目录未通过安全校验');
    const directory = path.dirname(this.filePath);
    const stat = fs.lstatSync(directory);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (stat.isSymbolicLink() || !stat.isDirectory()
        || stat.dev !== this.directoryIdentity.dev || stat.ino !== this.directoryIdentity.ino
        || fs.realpathSync(directory) !== this.directoryIdentity.realPath
        || (currentUid !== null && stat.uid !== currentUid)
        || (stat.mode & 0o022) !== 0) {
      throw new Error('日志目录在初始化后发生变化或权限不安全');
    }
  }

  shouldLog(level) {
    return LEVELS[level] >= LEVELS[this.level];
  }

  rotateIfNeeded(nextBytes, pinnedDirectory) {
    this.assertPinnedDirectory(pinnedDirectory);
    const currentPath = this.filePathIn(pinnedDirectory);
    let fileStat;
    try {
      fileStat = fs.lstatSync(currentPath);
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      throw error;
    }
    if (fileStat.isSymbolicLink() || !fileStat.isFile()) {
      throw new Error('日志轮转源必须是普通文件');
    }
    if (fileStat.size + nextBytes <= this.maxBytes) return false;
    let directoryChanged = false;
    try {
      for (let index = this.rotations - 1; index >= 1; index -= 1) {
        const from = currentPath + '.' + index;
        const to = currentPath + '.' + (index + 1);
        let fromStat;
        try { fromStat = fs.lstatSync(from); } catch (error) {
          if (error?.code === 'ENOENT') fromStat = null;
          else throw error;
        }
        if (!fromStat) continue;
        if (fromStat.isSymbolicLink() || !fromStat.isFile()) {
          throw new Error('日志轮转源必须是普通文件');
        }
        let toStat;
        try { toStat = fs.lstatSync(to); } catch (error) {
          if (error?.code === 'ENOENT') toStat = null;
          else throw error;
        }
        if (toStat && (toStat.isSymbolicLink() || !toStat.isFile())) {
          throw new Error('日志轮转目标必须是普通文件');
        }
        fs.renameSync(from, to);
        directoryChanged = true;
      }
      const target = currentPath + '.1';
      let targetStat;
      try { targetStat = fs.lstatSync(target); } catch (error) {
        if (error?.code === 'ENOENT') targetStat = null;
        else throw error;
      }
      if (targetStat && (targetStat.isSymbolicLink() || !targetStat.isFile())) {
        throw new Error('日志轮转目标必须是普通文件');
      }
      fs.renameSync(currentPath, target);
      directoryChanged = true;
      return true;
    } catch (error) {
      // If a multi-file rotation stopped part way through, at least persist the
      // resulting directory state before reporting the operation as failed.
      if (directoryChanged) {
        try { this.syncPinnedDirectory(pinnedDirectory); } catch (syncError) {
          error = syncError;
        }
      }
      this.fallback('error', 'logger.rotate_failed', { error: error.message });
      const wrapped = new Error('日志轮转失败');
      wrapped.code = 'PANEL_LOG_ROTATION_FAILED';
      wrapped.cause = error;
      throw wrapped;
    }
  }

  fallback(level, event, fields = {}) {
    if (this.fallbackReports > 1 || !this.consoleEnabled) return;
    this.fallbackReports += 1;
    try {
      process.stderr.write(JSON.stringify({
        ...redactValue(fields),
        timestamp: new Date().toISOString(),
        level,
        event: redactText(event),
        pid: this.pid,
      }) + '\n');
    } catch {}
  }

  log(level, event, fields = {}) {
    const normalizedLevel = asLevel(level);
    if (!this.shouldLog(normalizedLevel)) return null;
    let entry;
    let line;
    try {
      entry = {
        ...redactValue(fields),
        timestamp: new Date().toISOString(),
        level: normalizedLevel,
        event: redactText(String(event || 'event')),
        pid: this.pid,
      };
      line = JSON.stringify(entry) + '\n';
    } catch (error) {
      this.fallback('error', 'logger.serialize_failed', { error: error.message, originalEvent: event });
      return null;
    }
    let pinnedDirectory;
    try {
      pinnedDirectory = this.openPinnedDirectory();
      const bytes = Buffer.byteLength(line);
      const rotated = this.rotateIfNeeded(bytes, pinnedDirectory);
      const currentPath = this.filePathIn(pinnedDirectory);
      let currentExisted = true;
      try { fs.lstatSync(currentPath); } catch (error) {
        if (error?.code === 'ENOENT') currentExisted = false;
        else throw error;
      }
      const descriptor = this.openValidatedFile(pinnedDirectory);
      try {
        fs.fchmodSync(descriptor, 0o600);
        fs.writeFileSync(descriptor, line);
      } finally { fs.closeSync(descriptor); }
      if (rotated || !currentExisted) this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.consecutiveWriteFailures = 0;
      this.lastWriteSucceededAt = new Date().toISOString();
    } catch (error) {
      this.fileHealthy = false;
      this.failedWrites += 1;
      this.consecutiveWriteFailures += 1;
      this.lastWriteFailureAt = new Date().toISOString();
      this.fallback('error', 'logger.write_failed', { error: error.message, originalEvent: event });
    } finally {
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
    if (this.consoleEnabled) {
      try { process.stdout.write(line); } catch {}
    }
    return entry;
  }

  debug(event, fields) { return this.log('debug', event, fields); }
  info(event, fields) { return this.log('info', event, fields); }
  warn(event, fields) { return this.log('warn', event, fields); }
  error(event, fields) { return this.log('error', event, fields); }

  requestId(value) {
    const candidate = String(value || '').trim();
    return candidate && /^[A-Za-z0-9_.:@-]{1,100}$/.test(candidate)
      ? candidate
      : crypto.randomUUID();
  }

  tail(limit = 200) {
    const safeLimit = Math.max(1, Math.min(2000, Math.floor(Number(limit) || 200)));
    let text = '';
    let descriptor;
    try {
      const directory = path.dirname(this.filePath);
      this.assertDirectorySafe();
      assertDirectoryTree(directory, '日志目录');
      const realDirectory = fs.realpathSync(directory);
      const expectedPath = path.join(realDirectory, path.basename(this.filePath));
      descriptor = fs.openSync(
        this.filePath,
        fs.constants.O_RDONLY
          | (fs.constants.O_NOFOLLOW || 0)
          | (fs.constants.O_NONBLOCK || 0),
      );
      const descriptorStat = fs.fstatSync(descriptor);
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
      if (!descriptorStat.isFile() || descriptorStat.nlink !== 1
          || (currentUid !== null && descriptorStat.uid !== currentUid)
          || (descriptorStat.mode & 0o022) !== 0) return [];
      try {
        if (fs.realpathSync('/proc/self/fd/' + descriptor) !== expectedPath) return [];
      } catch {
        const latest = fs.lstatSync(this.filePath);
        const current = fs.statSync(this.filePath);
        if (fs.realpathSync(directory) !== realDirectory
            || latest.isSymbolicLink() || !latest.isFile()
            || current.dev !== descriptorStat.dev || current.ino !== descriptorStat.ino) {
          return [];
        }
      }
      text = readTailText(descriptor, descriptorStat.size, safeLimit);
    } catch { return []; } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
    }
    return text.split(/\r?\n/).filter(Boolean).slice(-safeLimit).map((line) => {
      try { return redactValue(JSON.parse(line)); } catch {
        return { level: 'error', event: 'logger.invalid_line', message: redactText(line) };
      }
    });
  }
}

function createLogger(options = {}) {
  return new PanelLogger(options);
}

function assertAuditLogCheckpoint(logger, event, fields = {}) {
  let succeeded = false;
  try {
    if (logger && typeof logger.checkpoint === 'function') {
      succeeded = logger.checkpoint(event, fields) === true;
    } else if (logger && typeof logger.probe === 'function') {
      // Compatibility for injected loggers while every production
      // PanelLogger writes the contextual, fsynced checkpoint above.
      succeeded = logger.probe() === true;
    }
  } catch {}
  if (succeeded) return true;
  const error = new Error('审计日志不可写，已在文件变更前停止操作');
  error.code = 'AUDIT_LOG_UNAVAILABLE';
  throw error;
}

module.exports = {
  LEVELS,
  PanelLogger,
  assertAuditLogCheckpoint,
  createLogger,
  redactText,
  redactValue,
  safeErrorText,
};
