const fs = require('node:fs');
const path = require('node:path');
const { assertDirectoryTree } = require('./lib/safeFs');
const MAX_ENV_BYTES = 1024 * 1024;

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

function loadEnv(filePath = path.resolve(__dirname, '..', '.env')) {
  const content = readEnvFile(filePath);
  if (content === null) return false;
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) continue;
    const key = trimmed.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || process.env[key] !== undefined) continue;
    process.env[key] = parseValue(trimmed.slice(separator + 1));
  }
  return true;
}

module.exports = { loadEnv, readEnvFile };
