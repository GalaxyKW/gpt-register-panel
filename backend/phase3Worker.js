const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { readJsonArray, readGptRegisterSources } = require('./adapters/gptRegisterFs');
const { normalizeEmail } = require('./lib/token');
const { redactText } = require('./logger');

// Phase 3 drives a real browser and gpt_register uses a shared profile. Only
// one process may run at a time; jobs for different accounts wait in order.
let phase3Queue = Promise.resolve();
const activePhase3Jobs = new Map();

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
  return redactText(String(value || '')).slice(-12000);
}

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Logging must never change the outcome of a Phase 3 task.
  }
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
      const error = new Error('phase3 超时');
      error.code = 'PHASE3_TIMEOUT';
      error.details = {
        code: null,
        signal: 'SIGTERM',
        stdout: sanitizeLog(stdout),
        stderr: sanitizeLog(stderr),
      };
      reject(error);
    }, timeoutMs);
    child.once('error', (error) => {
      clearTimeout(timer);
      error.details = {
        code: null,
        signal: null,
        stdout: sanitizeLog(stdout),
        stderr: sanitizeLog(stderr),
      };
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

async function runPhase3JobNow({ email, phone, actor = 'local', db, jobId, logger = null }) {
  const startedAt = Date.now();
  writeLog(logger, 'info', 'phase3.started', {
    jobId,
    actor,
    email: email || null,
    phone: phone || null,
  });
  try {
    if (process.env.PANEL_PHASE3_ENABLED !== '1') {
      const error = new Error('Phase 3 未启用，请设置 PANEL_PHASE3_ENABLED=1 后重启面板');
      error.code = 'PHASE3_DISABLED';
      throw error;
    }
    const entry = findUsernameEntry({ email, phone });
    writeLog(logger, 'info', 'phase3.account_resolved', {
      jobId,
      actor,
      email: entry.email,
      createdAt: entry.createdAt,
    });
    const processStartedAt = Date.now();
    const nodePath = path.resolve(process.env.GPT_REGISTER_NODE_PATH || process.execPath);
    const scriptPath = path.join(registerRoot(), 'index.js');
    writeLog(logger, 'info', 'phase3.process_started', {
      jobId,
      actor,
      email: entry.email,
      command: path.basename(nodePath),
      script: path.relative(registerRoot(), scriptPath),
    });
    let result;
    try {
      result = await runCommand(nodePath, [scriptPath, '--phase3', '--email=' + entry.email], {
        cwd: registerRoot(),
        env: { ...process.env, NODE_ENV: process.env.NODE_ENV || 'production' },
        timeoutMs: process.env.PANEL_PHASE3_TIMEOUT_MS,
      });
    } catch (error) {
      writeLog(logger, 'error', 'phase3.process_failed', {
        jobId,
        actor,
        email: entry.email,
        durationMs: Date.now() - processStartedAt,
        code: error?.details?.code ?? null,
        signal: error?.details?.signal || null,
        stdout: error?.details?.stdout || null,
        stderr: error?.details?.stderr || null,
        error: redactText(String(error?.message || error)),
      });
      throw error;
    }
    writeLog(logger, 'info', 'phase3.process_completed', {
      jobId,
      actor,
      email: entry.email,
      durationMs: Date.now() - processStartedAt,
      code: result.code,
      signal: result.signal,
      stdout: result.stdout || null,
      stderr: result.stderr || null,
    });
    const sources = readGptRegisterSources({ rootDirectory: registerRoot() });
    const token = sources.tokens
      .filter((item) => item.parseStatus === 'ok' && item.email === entry.email && item.mtimeMs >= startedAt)
      .sort((left, right) => right.mtimeMs - left.mtimeMs)[0];
    if (!token) throw new Error('phase3 已退出但未检测到对应的新 token 文件');
    writeLog(logger, 'info', 'phase3.token_detected', {
      jobId,
      actor,
      email: entry.email,
      tokenFile: token.relativePath,
      fingerprint: token.fingerprints?.access || null,
    });
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
    writeLog(logger, 'info', 'phase3.completed', {
      jobId,
      actor,
      email: entry.email,
      tokenFile: token.relativePath,
      fingerprint: token.fingerprints?.access || null,
      durationMs: Date.now() - startedAt,
    });
    return output;
  } catch (error) {
    writeLog(logger, 'error', 'phase3.failed', {
      jobId,
      actor,
      email: email || null,
      durationMs: Date.now() - startedAt,
      error: redactText(String(error?.message || error)),
      code: error?.code || null,
    });
    throw error;
  }
}

function phase3Key({ email, phone } = {}) {
  const normalizedEmail = normalizeEmail(email);
  if (normalizedEmail) return 'email:' + normalizedEmail;
  const normalizedPhone = String(phone || '').trim();
  return normalizedPhone ? 'phone:' + normalizedPhone : null;
}

function getActivePhase3Job({ email, phone } = {}) {
  const key = phase3Key({ email, phone });
  return key ? activePhase3Jobs.get(key) || null : null;
}

function runPhase3Job(args = {}) {
  const key = phase3Key(args);
  if (!key) return Promise.reject(new Error('email 或 phone 必须提供一个'));
  const duplicate = activePhase3Jobs.get(key);
  if (duplicate) {
    const error = new Error('该账号已有 Phase 3 任务排队或运行中');
    error.code = 'PHASE3_DUPLICATE';
    error.existingJobId = duplicate.jobId || null;
    return Promise.reject(error);
  }
  const queuedAt = Date.now();
  activePhase3Jobs.set(key, {
    jobId: args.jobId || null,
    email: normalizeEmail(args.email),
    phone: String(args.phone || '').trim() || null,
    queuedAt,
  });
  writeLog(args.logger, 'info', 'phase3.queued', {
    jobId: args.jobId || null,
    actor: args.actor || 'local',
    email: normalizeEmail(args.email) || null,
    phone: String(args.phone || '').trim() || null,
    queueWaitMs: null,
  });
  const run = phase3Queue.then(async () => {
    const queueWaitMs = Date.now() - queuedAt;
    writeLog(args.logger, 'info', 'phase3.started_after_queue', {
      jobId: args.jobId || null,
      actor: args.actor || 'local',
      email: normalizeEmail(args.email) || null,
      phone: String(args.phone || '').trim() || null,
      queueWaitMs,
    });
    if (args.db && args.jobId) {
      await args.db.updateJob(args.jobId, {
        status: 'running',
        startedAt: new Date().toISOString(),
      });
    }
    return runPhase3JobNow(args);
  }).finally(() => {
    activePhase3Jobs.delete(key);
  });
  phase3Queue = run.catch(() => {});
  return run;
}

module.exports = {
  findUsernameEntry,
  getActivePhase3Job,
  runPhase3Job,
  sanitizeLog,
};
