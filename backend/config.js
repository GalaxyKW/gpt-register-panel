const fs = require('node:fs');
const path = require('node:path');
const { assertDirectoryTree } = require('./lib/safeFs');
const MAX_ENV_BYTES = 1024 * 1024;
const BOOLEAN_ENV_NAMES = Object.freeze([
  'PANEL_LOG_CONSOLE',
  'PANEL_REQUIRE_AUTH',
  'PANEL_WRITE_ENABLED',
  'PANEL_ALLOW_INSECURE_WRITE',
  'PANEL_ALLOW_INSECURE_REMOTE',
  'PANEL_ALLOW_UNBACKED_WRITES',
  'PANEL_PHASE3_ENABLED',
  'SUB2API_ALLOW_INSECURE_HTTP',
  'SUB2API_CONFIRM_MIXED_CHANNEL_RISK',
]);

function parseValue(value) {
  const trimmed = String(value || '').trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"'))
      || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function envPathError() {
  const error = new Error('.env 必须是位于非符号链接目录中的普通文件');
  error.code = 'ENV_PATH_INVALID';
  return error;
}

function envConfigurationError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function validateBooleanEnvironment(environment = process.env) {
  for (const name of BOOLEAN_ENV_NAMES) {
    const value = environment[name];
    if (value !== undefined && value !== '0' && value !== '1') {
      throw envConfigurationError('ENV_BOOLEAN_INVALID', name + ' 必须严格设置为 0 或 1');
    }
  }
}

function booleanEnvEnabled(name, fallback = false, environment = process.env) {
  const value = environment[name];
  if (value === undefined) return Boolean(fallback);
  if (value !== '0' && value !== '1') {
    throw envConfigurationError('ENV_BOOLEAN_INVALID', name + ' 必须严格设置为 0 或 1');
  }
  return value === '1';
}

function parseEnvContent(content) {
  const entries = [];
  const seen = new Map();
  const lines = String(content || '').split(/\r?\n/);
  for (const [lineIndex, line] of lines.entries()) {
    const lineNumber = lineIndex + 1;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) {
      throw envConfigurationError('ENV_SYNTAX_INVALID', '.env 包含无效配置行');
    }
    const key = trimmed.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw envConfigurationError('ENV_SYNTAX_INVALID', '.env 包含无效配置项名');
    }
    if (seen.has(key)) {
      throw envConfigurationError(
        'ENV_DUPLICATE_KEY',
        '.env 包含重复配置项 ' + key
          + '（第 ' + seen.get(key) + ' 行和第 ' + lineNumber + ' 行）',
      );
    }
    seen.set(key, lineNumber);
    entries.push([key, parseValue(trimmed.slice(separator + 1))]);
  }
  return entries;
}

function sameFileState(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function secureEnvFileStat(stat) {
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
  return stat.isFile()
    && !stat.isSymbolicLink()
    && stat.nlink === 1
    && (currentUid === null || stat.uid === currentUid)
    && (stat.mode & 0o022) === 0;
}

function readBoundedFile(descriptor, maximumBytes) {
  const chunks = [];
  let total = 0;
  while (total <= maximumBytes) {
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
    const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    total += bytesRead;
  }
  if (total > maximumBytes) throw envPathError();
  return Buffer.concat(chunks, total).toString('utf8');
}

function readEnvFile(filePath) {
  const absolute = path.resolve(filePath);
  let initialStat;
  try { initialStat = fs.lstatSync(absolute); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw envPathError();
  }
  if (!secureEnvFileStat(initialStat)) throw envPathError();
  try { assertDirectoryTree(path.dirname(absolute), '.env 父目录'); } catch { throw envPathError(); }
  let realParent;
  try { realParent = fs.realpathSync(path.dirname(absolute)); } catch { throw envPathError(); }
  const expectedPath = path.join(realParent, path.basename(absolute));

  let descriptor;
  try {
    descriptor = fs.openSync(
      absolute,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0),
    );
    const descriptorStat = fs.fstatSync(descriptor);
    if (!secureEnvFileStat(descriptorStat)
        || descriptorStat.dev !== initialStat.dev
        || descriptorStat.ino !== initialStat.ino
        || descriptorStat.size > MAX_ENV_BYTES) throw envPathError();

    try {
      if (fs.realpathSync('/proc/self/fd/' + descriptor) !== expectedPath) throw envPathError();
    } catch (error) {
      if (error?.code === 'ENV_PATH_INVALID') throw error;
      const latest = fs.lstatSync(absolute);
      const current = fs.statSync(absolute);
      if (fs.realpathSync(path.dirname(absolute)) !== realParent
          || !secureEnvFileStat(latest)
          || current.dev !== descriptorStat.dev || current.ino !== descriptorStat.ino) {
        throw envPathError();
      }
    }
    const content = readBoundedFile(descriptor, MAX_ENV_BYTES);
    const finalDescriptorStat = fs.fstatSync(descriptor);
    const latest = fs.lstatSync(absolute);
    const current = fs.statSync(absolute);
    if (!sameFileState(descriptorStat, finalDescriptorStat)
        || fs.realpathSync(path.dirname(absolute)) !== realParent
        || !secureEnvFileStat(latest)
        || current.dev !== finalDescriptorStat.dev || current.ino !== finalDescriptorStat.ino) {
      throw envPathError();
    }
    return content;
  } catch (error) {
    if (error?.code === 'ENV_PATH_INVALID') throw error;
    throw envPathError();
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function loadEnv(filePath = path.resolve(__dirname, '..', '.env'), environment = process.env) {
  const content = readEnvFile(filePath);
  if (content === null) return false;
  // Parse and validate the complete file before mutating process.env. This
  // prevents an invalid trailing line or duplicate from leaving a partially
  // applied deployment configuration behind.
  const entries = parseEnvContent(content);
  const prospectiveEnvironment = { ...environment };
  for (const [key, value] of entries) {
    if (prospectiveEnvironment[key] === undefined) prospectiveEnvironment[key] = value;
  }
  validateBooleanEnvironment(prospectiveEnvironment);
  for (const [key, value] of entries) {
    if (environment[key] === undefined) environment[key] = value;
  }
  return true;
}

module.exports = {
  BOOLEAN_ENV_NAMES,
  booleanEnvEnabled,
  loadEnv,
  parseEnvContent,
  readEnvFile,
  validateBooleanEnvironment,
};
