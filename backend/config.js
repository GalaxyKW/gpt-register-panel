const fs = require('node:fs');
const path = require('node:path');
const { TextDecoder } = require('node:util');
const { assertDirectoryTree } = require('./lib/safeFs');
const MAX_ENV_BYTES = 1024 * 1024;
const MAX_ENV_ENTRIES = 4096;
const MAX_ENV_LINE_BYTES = 64 * 1024;
const DEFAULT_ENV_FILE = path.resolve(__dirname, '..', '.env');
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

function parseValue(value, lineNumber) {
  const trimmed = String(value || '').trim();
  if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
    const quote = trimmed[0];
    if (trimmed.length < 2 || !trimmed.endsWith(quote)) {
      throw envConfigurationError(
        'ENV_SYNTAX_INVALID',
        '.env 第 ' + lineNumber + ' 行包含未闭合的引号',
      );
    }
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function envPathError(code = 'ENV_PATH_INVALID', message = '环境配置必须是位于可信目录中的私有普通文件') {
  const error = new Error(message);
  error.code = code;
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
  const source = String(content || '');
  if (source.includes('\0')) {
    throw envConfigurationError('ENV_SYNTAX_INVALID', '.env 不能包含 NUL 字节');
  }
  if (/[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(source)) {
    throw envConfigurationError('ENV_SYNTAX_INVALID', '.env 不能包含控制字符');
  }
  // Accept Unix, Windows and old-style bare-CR line endings. Treating a bare
  // CR as value data would otherwise merge the following assignment into a
  // credential or filesystem path.
  const lines = source.split(/\r\n|\r|\n/);
  for (const [lineIndex, line] of lines.entries()) {
    const lineNumber = lineIndex + 1;
    if (Buffer.byteLength(line, 'utf8') > MAX_ENV_LINE_BYTES) {
      throw envConfigurationError(
        'ENV_LINE_TOO_LONG',
        '.env 第 ' + lineNumber + ' 行超过允许的长度上限',
      );
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (entries.length >= MAX_ENV_ENTRIES) {
      throw envConfigurationError(
        'ENV_ENTRY_LIMIT_EXCEEDED',
        '.env 配置项数量超过允许的上限',
      );
    }
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
    entries.push([key, parseValue(trimmed.slice(separator + 1), lineNumber)]);
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

function envFileStatError(stat) {
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
  if (!stat?.isFile() || stat.isSymbolicLink()) {
    return envPathError('ENV_FILE_TYPE_INVALID', '环境配置必须是普通文件且不能是符号链接');
  }
  if (stat.nlink !== 1) {
    return envPathError('ENV_FILE_LINK_INVALID', '环境配置不能有额外硬链接');
  }
  if (currentUid !== null && stat.uid !== currentUid) {
    return envPathError('ENV_FILE_OWNER_INVALID', '环境配置必须由服务账号持有');
  }
  if ((stat.mode & 0o400) === 0 || (stat.mode & 0o7177) !== 0) {
    return envPathError(
      'ENV_FILE_PERMISSIONS_INVALID',
      '环境配置权限必须为 0400 或 0600 且不能设置特殊权限位',
    );
  }
  return null;
}

function assertSecureEnvFileStat(stat) {
  const error = envFileStatError(stat);
  if (error) throw error;
}

function assertSecureEnvParentTree(directory) {
  const absolute = path.resolve(directory);
  const parsed = path.parse(absolute);
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
  const parts = absolute.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (const part of parts) {
    current = path.join(current, part);
    let stat;
    try { stat = fs.lstatSync(current); } catch {
      throw envPathError('ENV_PARENT_INVALID', '环境配置父目录无法安全检查');
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw envPathError('ENV_PARENT_INVALID', '环境配置父目录不能包含符号链接');
    }
    const trustedOwner = currentUid === null || stat.uid === currentUid || stat.uid === 0;
    const writableByOthers = (stat.mode & 0o022) !== 0;
    // Root/current-user owned sticky directories (for example /tmp) prevent
    // unrelated users from replacing entries they do not own. Other writable
    // ancestors would let a local user swap a verified environment path.
    const trustedStickyDirectory = trustedOwner && (stat.mode & 0o1000) !== 0;
    if (!trustedOwner || (writableByOthers && !trustedStickyDirectory)) {
      throw envPathError(
        'ENV_PARENT_PERMISSIONS_INVALID',
        '环境配置父目录所有权或写权限不安全',
      );
    }
  }
}

function isEnvironmentFileError(error) {
  return typeof error?.code === 'string' && error.code.startsWith('ENV_');
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
  if (total > maximumBytes) {
    throw envPathError('ENV_FILE_TOO_LARGE', '环境配置超过允许的大小上限');
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total));
  } catch {
    throw envPathError('ENV_FILE_ENCODING_INVALID', '环境配置必须是有效的 UTF-8 文本');
  }
}

function readEnvFile(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0
      || filePath.length > 4096 || filePath.includes('\0')
      || !path.isAbsolute(filePath)) {
    throw envConfigurationError('ENV_FILE_PATH_INVALID', '环境配置路径必须是非空绝对路径');
  }
  const absolute = path.resolve(filePath);
  let initialStat;
  try { initialStat = fs.lstatSync(absolute); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw envPathError('ENV_FILE_STAT_FAILED', '无法安全检查环境配置');
  }
  assertSecureEnvFileStat(initialStat);
  try { assertDirectoryTree(path.dirname(absolute), '环境配置父目录'); } catch {
    throw envPathError('ENV_PARENT_INVALID', '环境配置父目录不可信');
  }
  assertSecureEnvParentTree(path.dirname(absolute));
  let realParent;
  try { realParent = fs.realpathSync(path.dirname(absolute)); } catch {
    throw envPathError('ENV_PARENT_INVALID', '环境配置父目录无法解析');
  }
  const expectedPath = path.join(realParent, path.basename(absolute));

  let descriptor;
  try {
    descriptor = fs.openSync(
      absolute,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0),
    );
    const descriptorStat = fs.fstatSync(descriptor);
    assertSecureEnvFileStat(descriptorStat);
    if (descriptorStat.dev !== initialStat.dev || descriptorStat.ino !== initialStat.ino) {
      throw envPathError('ENV_FILE_CHANGED', '环境配置在打开前发生变化');
    }
    if (descriptorStat.size > MAX_ENV_BYTES) {
      throw envPathError('ENV_FILE_TOO_LARGE', '环境配置超过允许的大小上限');
    }

    try {
      if (fs.realpathSync('/proc/self/fd/' + descriptor) !== expectedPath) {
        throw envPathError('ENV_FILE_CHANGED', '环境配置路径在打开期间发生变化');
      }
    } catch (error) {
      if (isEnvironmentFileError(error)) throw error;
      const latest = fs.lstatSync(absolute);
      const current = fs.statSync(absolute);
      if (fs.realpathSync(path.dirname(absolute)) !== realParent
          || envFileStatError(latest)
          || current.dev !== descriptorStat.dev || current.ino !== descriptorStat.ino) {
        throw envPathError('ENV_FILE_CHANGED', '环境配置路径在打开期间发生变化');
      }
    }
    const content = readBoundedFile(descriptor, MAX_ENV_BYTES);
    const finalDescriptorStat = fs.fstatSync(descriptor);
    const latest = fs.lstatSync(absolute);
    const current = fs.statSync(absolute);
    if (!sameFileState(descriptorStat, finalDescriptorStat)
        || fs.realpathSync(path.dirname(absolute)) !== realParent
        || envFileStatError(latest)
        || current.dev !== finalDescriptorStat.dev || current.ino !== finalDescriptorStat.ino) {
      throw envPathError('ENV_FILE_CHANGED', '环境配置在读取期间发生变化');
    }
    return content;
  } catch (error) {
    if (isEnvironmentFileError(error)) throw error;
    throw envPathError('ENV_FILE_OPEN_FAILED', '无法安全打开环境配置');
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function configuredEnvFile(environment = process.env) {
  const configured = environment.PANEL_ENV_FILE;
  if (configured === undefined) return DEFAULT_ENV_FILE;
  if (typeof configured !== 'string' || configured.length === 0
      || configured.length > 4096 || configured.includes('\0')
      || !path.isAbsolute(configured)) {
    throw envConfigurationError(
      'ENV_FILE_PATH_INVALID',
      'PANEL_ENV_FILE 必须是非空绝对路径',
    );
  }
  return path.normalize(configured);
}

function loadEnv(filePath, environment = process.env) {
  const explicitlySelected = filePath !== undefined || environment.PANEL_ENV_FILE !== undefined;
  const selectedFile = filePath === undefined ? configuredEnvFile(environment) : filePath;
  const content = readEnvFile(selectedFile);
  if (content === null) {
    if (explicitlySelected) {
      throw envPathError('ENV_FILE_MISSING', '显式指定的环境配置文件不存在');
    }
    return false;
  }
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
  configuredEnvFile,
  loadEnv,
  parseEnvContent,
  readEnvFile,
  validateBooleanEnvironment,
};
