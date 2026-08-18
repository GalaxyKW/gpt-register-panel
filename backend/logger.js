const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const SECRET_KEY = /(^|_|-)(access[_-]?token|refresh[_-]?token|id[_-]?token|password|passwd|secret|api[_-]?key|authorization|cookie|token|tokens|credential|credentials|验证码|授权码)$/i;
const SECRET_TEXT = [
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /admin-[A-Za-z0-9._~-]{16,}/gi,
  /sk-[A-Za-z0-9_-]{16,}/gi,
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
];

function asLevel(value) {
  const level = String(value || 'info').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(LEVELS, level) ? level : 'info';
}

function redactText(value) {
  let text = String(value === undefined || value === null ? '' : value);
  for (const pattern of SECRET_TEXT) text = text.replace(pattern, '[redacted]');
  text = text.replace(
    /((?:access[_-]?token|refresh[_-]?token|id[_-]?token|password|passwd|secret|api[_-]?key|authorization|cookie|验证码|授权码)\s*[:=]\s*)([^\s,;}]+)/gi,
    '$1[redacted]',
  );
  // Process output and JSON error strings often quote both the field and value.
  text = text.replace(
    /((?:["']?)(?:access[_-]?token|refresh[_-]?token|id[_-]?token|password|passwd|secret|api[_-]?key|authorization|cookie|验证码|授权码)(?:["']?\s*[:=]\s*["']))([^"'\r\n,}]+)/gi,
    '$1[redacted]',
  );
  return text;
}

function redactValue(value, key = '', seen = new WeakSet()) {
  if (SECRET_KEY.test(String(key))) return '[redacted]';
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

function numberFromEnv(value, fallback, minimum = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= minimum ? parsed : fallback;
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
    ));
    this.rotations = Math.floor(numberFromEnv(
      options.rotations || process.env.PANEL_LOG_ROTATIONS,
      5,
      1,
    ));
    const consoleValue = options.console === undefined
      ? process.env.PANEL_LOG_CONSOLE ?? '1'
      : options.console;
    this.consoleEnabled = consoleValue !== false
      && String(consoleValue).toLowerCase() !== '0'
      && String(consoleValue).toLowerCase() !== 'false';
    this.failedWrites = 0;
    this.pid = process.pid;
    this.ensureDirectory();
  }

  ensureDirectory() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
      if (fs.existsSync(this.filePath)) fs.chmodSync(this.filePath, 0o600);
    } catch (error) {
      this.fallback('error', 'logger.initialize_failed', { error: error.message });
    }
  }

  shouldLog(level) {
    return LEVELS[level] >= LEVELS[this.level];
  }

  rotateIfNeeded(nextBytes) {
    let size = 0;
    try { size = fs.statSync(this.filePath).size; } catch {}
    if (size + nextBytes <= this.maxBytes) return;
    try {
      for (let index = this.rotations - 1; index >= 1; index -= 1) {
        const from = this.filePath + '.' + index;
        const to = this.filePath + '.' + (index + 1);
        if (fs.existsSync(from)) fs.renameSync(from, to);
      }
      if (fs.existsSync(this.filePath)) fs.renameSync(this.filePath, this.filePath + '.1');
    } catch (error) {
      this.fallback('error', 'logger.rotate_failed', { error: error.message });
    }
  }

  fallback(level, event, fields = {}) {
    if (this.failedWrites > 1 || !this.consoleEnabled) return;
    this.failedWrites += 1;
    try {
      process.stderr.write(JSON.stringify({
        timestamp: new Date().toISOString(),
        level,
        event,
        pid: this.pid,
        ...redactValue(fields),
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
        timestamp: new Date().toISOString(),
        level: normalizedLevel,
        event: String(event || 'event'),
        pid: this.pid,
        ...redactValue(fields),
      };
      line = JSON.stringify(entry) + '\n';
    } catch (error) {
      this.fallback('error', 'logger.serialize_failed', { error: error.message, originalEvent: event });
      return null;
    }
    try {
      const bytes = Buffer.byteLength(line);
      this.rotateIfNeeded(bytes);
      fs.appendFileSync(this.filePath, line, { mode: 0o600 });
      try { fs.chmodSync(this.filePath, 0o600); } catch {}
    } catch (error) {
      this.fallback('error', 'logger.write_failed', { error: error.message, originalEvent: event });
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
    const safeLimit = Math.max(1, Math.min(2000, Number(limit) || 200));
    let text = '';
    try { text = fs.readFileSync(this.filePath, 'utf8'); } catch { return []; }
    return text.split(/\r?\n/).filter(Boolean).slice(-safeLimit).map((line) => {
      try { return JSON.parse(line); } catch { return { level: 'error', event: 'logger.invalid_line', message: redactText(line) }; }
    });
  }
}

function createLogger(options = {}) {
  return new PanelLogger(options);
}

module.exports = {
  LEVELS,
  PanelLogger,
  createLogger,
  redactText,
  redactValue,
};
