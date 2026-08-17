const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { readJsonArray, readGptRegisterSources } = require('./adapters/gptRegisterFs');
const { normalizeEmail } = require('./lib/token');

function registerRoot() {
  return path.resolve(process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register');
}

function findUsernameEntry({ email, phone } = {}) {
  const records = readJsonArray(path.join(registerRoot(), 'username.json'));
  const normalizedEmail = normalizeEmail(email);
  const normalizedPhone = String(phone || '').trim();
  const index = records.findIndex((record) => {
    if (!record || !record.password || !record.email) return false;
    return (normalizedEmail && normalizeEmail(record.email) === normalizedEmail)
      || (normalizedPhone && String(record.phone || '').trim() === normalizedPhone);
  });
  if (index < 0) throw new Error('username.json 中未找到可用于 phase3 的账号');
  const record = records[index];
  return {
    index,
    email: normalizeEmail(record.email),
    phone: String(record.phone || '').trim(),
    createdAt: record.createdAt || null,
  };
}

function sanitizeLog(value) {
  return String(value || '')
    .replace(/(access_token|refresh_token|id_token|password|验证码|授权码)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [redacted]')
    .slice(-12000);
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const append = (target, chunk) => {
      const text = String(chunk || '');
      return (target + text).slice(-12000);
    };
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    const timeoutMs = Number(options.timeoutMs || 30 * 60 * 1000);
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 5000).unref();
      reject(new Error('phase3 超时')); 
    }, timeoutMs);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      const result = { code, signal, stdout: sanitizeLog(stdout), stderr: sanitizeLog(stderr) };
      if (code !== 0) {
        const error = new Error('phase3 进程失败（退出码 ' + String(code) + '）');
        error.details = result;
        reject(error);
      } else resolve(result);
    });
  });
}

async function runPhase3Job({ email, phone, actor = 'local', db, jobId }) {
  if (process.env.PANEL_PHASE3_ENABLED !== '1') {
    const error = new Error('Phase 3 未启用，请设置 PANEL_PHASE3_ENABLED=1 后重启面板');
    error.code = 'PHASE3_DISABLED';
    throw error;
  }
  const entry = findUsernameEntry({ email, phone });
  const startedAt = Date.now();
  const nodePath = path.resolve(process.env.GPT_REGISTER_NODE_PATH || process.execPath);
  const scriptPath = path.join(registerRoot(), 'index.js');
  const result = await runCommand(nodePath, [scriptPath, '--phase3', '--email=' + entry.email], {
    cwd: registerRoot(),
    env: { ...process.env, NODE_ENV: process.env.NODE_ENV || 'production' },
    timeoutMs: process.env.PANEL_PHASE3_TIMEOUT_MS,
  });
  const sources = readGptRegisterSources({ rootDirectory: registerRoot() });
  const token = sources.tokens
    .filter((item) => item.parseStatus === 'ok' && item.email === entry.email && item.mtimeMs >= startedAt)
    .sort((left, right) => right.mtimeMs - left.mtimeMs)[0];
  if (!token) throw new Error('phase3 已退出但未检测到对应的新 token 文件');
  const output = {
    email: entry.email,
    tokenFile: token.relativePath,
    fingerprint: token.fingerprints?.access || null,
    process: result,
  };
  await db?.audit({
    jobId,
    actor,
    action: 'phase3',
    targetKey: 'email:' + entry.email,
    afterFingerprint: token.fingerprints?.access || null,
    result: 'ok',
    details: { tokenFile: token.relativePath },
  });
  return output;
}

module.exports = {
  findUsernameEntry,
  runPhase3Job,
  sanitizeLog,
};
