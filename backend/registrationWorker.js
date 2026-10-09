'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { runCommand, _registrationExecution: execution } = require('./phase3Worker');
const { readGptRegisterSources, closeDirectoryHandle } = require('./adapters/gptRegisterFs');
const { PROFILE_ENV, createPhase3BrowserProfile, removePhase3BrowserProfile } = require('./lib/phase3BrowserProfile');
const { readRegistrationSettings } = require('./registrationSettings');
const { assertAuditLogCheckpoint } = require('./logger');
const RESUME_REVISION_KEY = crypto.randomBytes(32);
const ACCOUNT_TIMEOUT_MS = 30 * 60 * 1000;
const BATCH_TIMEOUT_MAX_MS = 24 * 60 * 60 * 1000;

function failure(code, message, details) { return Object.assign(new Error(message), { code, ...(details ? { details } : {}) }); }
function normalizeRegistrationOptions(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
      || Object.keys(options).some(key => !['count', 'country', 'operator'].includes(key))) throw failure('REGISTRATION_OPTIONS_INVALID', '注册参数包含不允许的字段');
  const { count, country, operator = '' } = options;
  if (!Number.isSafeInteger(count) || count < 1 || count > 100
      || typeof country !== 'string' || !/^[A-Z]{2}$/.test(country)
      || typeof operator !== 'string' || !/^[A-Za-z0-9_-]{0,64}$/.test(operator)) throw failure('REGISTRATION_OPTIONS_INVALID', '数量、国家或运营商格式无效');
  return { count, country, operator };
}
function readProtocol(fd, partial = false) {
  const stat = fs.fstatSync(fd);
  if (!stat.isFile() || stat.size > 1024 * 1024) throw failure('REGISTRATION_PROTOCOL_INVALID', '注册结果通道超过安全上限');
  const bytes = Buffer.alloc(stat.size);
  fs.readSync(fd, bytes, 0, bytes.length, 0);
  let text = bytes.toString('utf8');
  if (partial && !text.endsWith('\n')) text = text.slice(0, text.lastIndexOf('\n') + 1);
  if (text && !text.endsWith('\n')) throw failure('REGISTRATION_PROTOCOL_INVALID', '注册结果未完整写入');
  const lines = text.split('\n').filter(Boolean);
  if (lines.length > 1000) throw failure('REGISTRATION_PROTOCOL_INVALID', '注册结果事件过多');
  return lines.map((line, index) => {
    let event; try { event = JSON.parse(line); } catch { throw failure('REGISTRATION_PROTOCOL_INVALID', '注册结果不是有效 JSON'); }
    if (!event || event.version !== 1 || event.sequence !== index + 1 || !['started', 'stage', 'account_completed', 'completed', 'failed', 'preflight_completed'].includes(event.type)) throw failure('REGISTRATION_PROTOCOL_INVALID', '注册结果协议无效');
    return event;
  });
}
function processSummary(result = {}) {
  return { exitCode: result.code ?? null, terminationConfirmed: result.terminationConfirmed === true,
    outputTruncated: result.outputTruncated === true, stdoutBytes: Number(result.stdoutBytes) || 0, stderrBytes: Number(result.stderrBytes) || 0 };
}
async function runEngineCommand({ rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register', arguments: args,
  signal, timeoutMs = ACCOUNT_TIMEOUT_MS, logger, jobId, actor, onProgress, runner = runCommand, resumeBinding } = {}) {
  let root, script, node, profile, resultFd, resumeFd, timer, safeToRemove = true, result, commandError;
  try {
    if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消，未启动注册机');
    execution.assertProcessTreeSafe();
    root = execution.openPinnedPhase3Root(path.resolve(rootDirectory));
    script = execution.openPinnedRegularFile(path.join(root.traversalPath, 'index.js'), 'gpt_register/index.js', { parentPinned: true });
    node = execution.openPinnedRegularFile(path.resolve(process.env.GPT_REGISTER_NODE_PATH || process.execPath), 'GPT_REGISTER_NODE_PATH', { executable: true });
    profile = createPhase3BrowserProfile();
    resultFd = fs.openSync(path.join(profile.path, 'panel-result.jsonl'), fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    if (resumeBinding) {
      const bindingPath = path.join(profile.path, 'panel-resume.json');
      const writer = fs.openSync(bindingPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      try { fs.writeFileSync(writer, JSON.stringify(resumeBinding)); fs.fsyncSync(writer); } finally { fs.closeSync(writer); }
      resumeFd = fs.openSync(bindingPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    }
    let delivered = 0;
    if (typeof onProgress === 'function') timer = setInterval(() => {
      try {
        for (const event of readProtocol(resultFd, true).slice(delivered)) {
          delivered += 1;
          // Never forward raw subprocess stdout or unknown protocol fields.
          onProgress({ type: event.type, stage: /^[a-z0-9_]{1,64}$/.test(event.stage || '') ? event.stage : undefined,
            completedCount: Number.isSafeInteger(event.completedCount) ? event.completedCount : undefined });
        }
      } catch { /* The final strict read determines whether any output is usable. */ }
    }, 500);
    assertAuditLogCheckpoint(logger, 'registration.process_spawn_checkpoint', { jobId, actor });
    if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消，未启动注册机');
    safeToRemove = false;
    try {
      result = await runner('/proc/self/fd/4', ['--preserve-symlinks', '--preserve-symlinks-main', '-e', execution.phase3LauncherSource(), '--', ...args], {
        cwd: '/proc/self/fd/5', env: { ...execution.phase3Environment(), [PROFILE_ENV]: profile.path, GPT_REGISTER_PANEL_RESULT_FD: '6', ...(resumeBinding ? { GPT_REGISTER_PANEL_RESUME_FD: '7' } : {}) },
        extraFileDescriptors: [script.descriptor, node.descriptor, root.descriptor, resultFd, ...(resumeBinding ? [resumeFd] : [])], signal,
        timeoutMs, registrationBatch: args.includes('--panel-register'), maxOutputBytes: 256 * 1024, terminationGraceMs: 4000,
      });
    } catch (error) {
      if (error?.code === 'JOB_INTERRUPTED' && !error.details) { safeToRemove = true; throw failure('JOB_INTERRUPTED', '任务已取消，未启动注册机'); }
      commandError = error; result = error.details || {};
    }
    safeToRemove = result?.terminationConfirmed === true;
    if (!safeToRemove) throw Object.assign(failure('REGISTRATION_TERMINATION_UNCONFIRMED', '注册进程树未确认停止，禁止继续注册', { processSummary: processSummary(result), reconciliationRequired: true }), { requiresReconciliation: true, writeOutcomeUnknown: true, doNotRetry: true });
    let events;
    try { events = readProtocol(resultFd); } catch (error) {
      if (args.includes('--panel-register') || args.includes('--panel-resume')) Object.assign(error, { requiresReconciliation: true, writeOutcomeUnknown: true, doNotRetry: true });
      throw error;
    }
    logger?.info?.('registration.process_finished', { jobId, actor, ...processSummary(result), eventCount: events.length });
    return { events, processSummary: processSummary(result), commandError };
  } finally {
    if (timer) clearInterval(timer);
    if (resultFd !== undefined) fs.closeSync(resultFd);
    if (resumeFd !== undefined) fs.closeSync(resumeFd);
    execution.closeRegularFileHandle(script); execution.closeRegularFileHandle(node); closeDirectoryHandle(root);
    if (profile && safeToRemove) removePhase3BrowserProfile(profile);
  }
}
function verifyRegistrationArtifacts(events, before, after, count) {
  const completed = events.filter(event => event.type === 'account_completed');
  const existing = new Set((before.tokens || []).flatMap(item => item.identityKeys || []).filter(key => /^(account|user):/.test(key)));
  const seen = new Set(); const outputs = [];
  if (completed.length > count) throw failure('REGISTRATION_OUTPUT_INVALID', '注册输出数量超过明确请求');
  for (const [index, event] of completed.entries()) {
    if (event.completedCount !== index + 1 || !Array.isArray(event.artifacts) || !event.artifacts.length || event.artifacts.length > 2) throw failure('REGISTRATION_OUTPUT_INVALID', '注册完成事件无效');
    const verified = event.artifacts.map(proof => {
      if (!proof || typeof proof.selectedKey !== 'string' || !/^token:(tokens|use_token):\1\/[^/\\\x00-\x1f]+\.json$/.test(proof.selectedKey)
          || !/^[a-f0-9]{64}$/.test(proof.contentHash || '')) throw failure('REGISTRATION_OUTPUT_INVALID', '注册结果缺少可信文件绑定');
      const matches = (after.tokens || []).filter(item => 'token:' + item.relativePath.split('/')[0] + ':' + item.relativePath === proof.selectedKey);
      const record = matches.length === 1 ? matches[0] : null;
      const strong = (record?.identityKeys || []).filter(key => /^(account|user):/.test(key));
      if (!record || record.contentHash !== proof.contentHash || record.parseStatus !== 'ok' || record.historical || record.disabled
          || record.expiryStatus !== 'valid' || Date.parse(record.expiresAt) <= Date.now() || !strong.length
          || strong.some(key => existing.has(key))) throw failure('REGISTRATION_OUTPUT_INVALID', '新 token 未通过文件、有效期和新增身份验证');
      return { selectedKey: proof.selectedKey, contentHash: proof.contentHash, identityKeys: strong };
    });
    const primary = verified.find(item => item.selectedKey.startsWith('token:tokens:')) || verified[0];
    if (verified.some(item => JSON.stringify([...item.identityKeys].sort()) !== JSON.stringify([...primary.identityKeys].sort()))
        || primary.identityKeys.some(key => seen.has(key))) throw failure('REGISTRATION_OUTPUT_INVALID', '注册结果重复或不同输出目录身份不一致');
    primary.identityKeys.forEach(key => seen.add(key)); outputs.push(primary);
  }
  return outputs;
}
async function runRegistrationJob({ rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register', options, signal,
  logger, jobId, actor = 'panel-admin', onProgress, preflight, runner } = {}) {
  const normalized = normalizeRegistrationOptions(options);
  const settings = readRegistrationSettings({ rootDirectory });
  if (!settings.ready || !settings.countries.some(item => item.code === normalized.country)) throw failure('REGISTRATION_CONFIG_INVALID', '注册配置或所选国家不完整，请先检查设置');
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消');
  onProgress?.({ type: 'stage', stage: 'network_preflight' });
  const network = await (preflight || require('./networkPreflight').runNetworkPreflight)({ rootDirectory, signal, logger, jobId, actor });
  if (!network.ok) throw failure('REGISTRATION_PREFLIGHT_FAILED', '网络预检未通过，未申请号码或启动注册', { preflight: network });
  if (readRegistrationSettings({ rootDirectory }).revision !== settings.revision) throw failure('REGISTRATION_CONFIG_CHANGED', '网络预检期间注册配置已变化，未申请号码，请重新开始');
  const before = readGptRegisterSources({ rootDirectory, strictCompleteSnapshot: true });
  const output = await runEngineCommand({ rootDirectory, arguments: [String(normalized.count), '--panel-register', '--country=' + normalized.country, '--operator=' + normalized.operator],
    signal, logger, jobId, actor, onProgress, runner, timeoutMs: Math.min(BATCH_TIMEOUT_MAX_MS, normalized.count * ACCOUNT_TIMEOUT_MS) });
  let artifacts;
  try {
    const after = readGptRegisterSources({ rootDirectory, strictCompleteSnapshot: true });
    artifacts = verifyRegistrationArtifacts(output.events, before, after, normalized.count);
  } catch (error) {
    Object.assign(error, { requiresReconciliation: true, writeOutcomeUnknown: true, doNotRetry: true });
    throw error;
  }
  const result = { requestedCount: normalized.count, completedCount: artifacts.length,
    selectedKeys: artifacts.map(item => item.selectedKey), artifacts,
    phases: output.events.filter(item => item.type === 'stage').map(item => ({ stage: /^[a-z0-9_]{1,64}$/.test(item.stage || '') ? item.stage : 'unknown' })),
    processSummary: output.processSummary };
  const terminal = output.events.at(-1);
  if (output.commandError || terminal?.type !== 'completed' || terminal.requestedCount !== normalized.count || artifacts.length !== normalized.count) {
    const failed = output.events.findLast(item => item.type === 'failed');
    const nextAction = ['resume_phase2', 'resume_account'].includes(failed?.nextAction) ? failed.nextAction : null;
    const code = output.commandError?.code === 'JOB_INTERRUPTED' ? 'JOB_INTERRUPTED' : /^[A-Z0-9_]{1,100}$/.test(failed?.code || '') ? failed.code : 'REGISTRATION_INCOMPLETE';
    throw failure(code, nextAction ? '已有账号待继续，已停止租用新号码；请从账号恢复入口续跑' : '注册未完整完成，保留已落地账号与可验证产物', { ...result, nextAction });
  }
  return result;
}
function continuationSnapshot(rootDirectory) {
  const handle = execution.openPinnedPhase3Root(path.resolve(rootDirectory));
  let fd;
  try {
    try { fd = fs.openSync(path.join(handle.traversalPath, 'accounts.json'), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
    catch (error) { if (error.code === 'ENOENT') return { accounts: [], fileHash: null }; throw error; }
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 32 * 1024 * 1024) throw new Error();
    const bytes = fs.readFileSync(fd); const accounts = JSON.parse(bytes.toString('utf8'));
    if (!Array.isArray(accounts) || accounts.length > 10000 || accounts.some(item => !item || typeof item !== 'object' || Array.isArray(item))) throw new Error();
    return { accounts, fileHash: crypto.createHash('sha256').update(bytes).digest('hex') };
  } catch { throw failure('REGISTRATION_CONTINUATION_INVALID', '本地注册账本无法安全读取'); }
  finally { if (fd !== undefined) fs.closeSync(fd); closeDirectoryHandle(handle); }
}
function continuationPhone(account) {
  const raw = account?.phone;
  return typeof raw === 'string' && raw.length <= 64 && !/[^0-9 +().-]/.test(raw) ? raw.replace(/\D/g, '') : '';
}
function continuationItems(snapshot) {
  const phase2Statuses = new Set(['registered', 'oauth_phase2_failed', 'registration_sms_submission_attempted', 'registration_sms_submitted', 'registration_navigation_unconfirmed', 'registration_server_landed_pending_login']);
  const phase3Statuses = new Set(['email_bound', 'oauth_phase3_failed']);
  return snapshot.accounts.flatMap((account, index) => {
    const status = String(account.status || 'registered');
    const stage = phase3Statuses.has(status) ? 'phase3' : phase2Statuses.has(status) ? 'phase2' : null;
    if (!stage) return [];
    const phone = continuationPhone(account);
    const email = typeof account.email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(account.email) ? account.email.toLowerCase() : '';
    const samePhone = snapshot.accounts.filter(item => continuationPhone(item) === phone);
    let reason = null;
    if (!phone || typeof account.password !== 'string' || !account.password.trim() || /[\x00\r\n]/.test(account.password)) reason = '缺少有效的原手机号或登录凭据';
    else if (samePhone.length !== 1) reason = '本地手机号不唯一，需先核对原注册记录';
    else if (stage === 'phase3' && (!email || snapshot.accounts.filter(item => String(item.email || '').toLowerCase() === email).length !== 1)) reason = '原绑定邮箱缺失或不唯一';
    else if (status.startsWith('registration_') && !account.smsActivationId) reason = '短信注册检查点缺少原激活编号';
    const selectedKey = 'registration:accounts:' + index;
    const revision = crypto.createHmac('sha256', RESUME_REVISION_KEY).update(JSON.stringify([snapshot.fileHash, selectedKey, stage, account])).digest('hex');
    return [{ selectedKey, revision, stage, ...(email ? { email } : {}), phoneMasked: phone ? '***' + phone.slice(-4) : '', eligible: reason === null, reason }];
  });
}
function listRegistrationContinuations({ rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register' } = {}) {
  return { items: continuationItems(continuationSnapshot(rootDirectory)) };
}
function resolveContinuation(rootDirectory, target) {
  if (!target || typeof target !== 'object' || Array.isArray(target) || Object.keys(target).some(key => !['selectedKey', 'revision'].includes(key))
      || !/^registration:accounts:\d{1,5}$/.test(target.selectedKey || '') || !/^[a-f0-9]{64}$/.test(target.revision || '')) throw failure('REGISTRATION_RESUME_TARGET_INVALID', '请选择明确的一条待继续注册记录');
  const snapshot = continuationSnapshot(rootDirectory);
  const item = continuationItems(snapshot).find(item => item.selectedKey === target.selectedKey);
  if (!item?.eligible || !crypto.timingSafeEqual(Buffer.from(item.revision, 'hex'), Buffer.from(target.revision, 'hex'))) throw failure('REGISTRATION_RESUME_TARGET_CHANGED', '待继续账号已变化、不唯一或不再适合续跑，请刷新');
  const index = Number(target.selectedKey.split(':').at(-1));
  return { snapshot, item, account: snapshot.accounts[index], binding: { index, stage: item.stage, fileHash: snapshot.fileHash,
    recordHash: crypto.createHash('sha256').update(JSON.stringify(snapshot.accounts[index])).digest('hex') } };
}
async function runRegistrationResumeJob({ rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register', target, signal,
  logger, jobId, actor = 'panel-admin', onProgress, preflight, runner } = {}) {
  const selected = resolveContinuation(rootDirectory, target);
  const settings = readRegistrationSettings({ rootDirectory });
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '续跑已取消');
  onProgress?.({ type: 'stage', stage: 'network_preflight' });
  const network = await (preflight || require('./networkPreflight').runNetworkPreflight)({ rootDirectory, signal, logger, jobId, actor });
  if (!network.ok) throw failure('REGISTRATION_PREFLIGHT_FAILED', '网络预检未通过，未执行账号续跑', { preflight: network });
  resolveContinuation(rootDirectory, target);
  if (settings.revision !== readRegistrationSettings({ rootDirectory }).revision) throw failure('REGISTRATION_CONFIG_CHANGED', '网络预检期间注册配置已变化，未执行账号续跑');
  const before = readGptRegisterSources({ rootDirectory, strictCompleteSnapshot: true });
  const output = await runEngineCommand({ rootDirectory, arguments: ['--panel-resume', '--' + selected.item.stage], resumeBinding: selected.binding,
    signal, logger, jobId, actor, onProgress, runner, timeoutMs: ACCOUNT_TIMEOUT_MS });
  let artifacts;
  try {
    const after = readGptRegisterSources({ rootDirectory, strictCompleteSnapshot: true });
    artifacts = verifyRegistrationArtifacts(output.events, { tokens: [] }, after, 1);
    const latest = continuationSnapshot(rootDirectory).accounts.filter(item => continuationPhone(item) === continuationPhone(selected.account)
      && String(item.smsActivationId || '') === String(selected.account.smsActivationId || ''));
    if (artifacts.length) {
      if (latest.length !== 1 || !latest[0].email) throw failure('REGISTRATION_RESUME_OUTPUT_INVALID', '无法核验原账号续跑后的邮箱绑定');
      for (const artifact of artifacts) {
        const record = after.tokens.find(item => 'token:' + item.source + ':' + item.relativePath === artifact.selectedKey);
        if (record?.email !== String(latest[0].email).toLowerCase()) throw failure('REGISTRATION_RESUME_OUTPUT_INVALID', '续跑产物不属于原账号的已绑定邮箱');
        const originals = before.tokens.filter(item => item.email === record.email && item.parseStatus === 'ok');
        if (originals.some(item => (item.accountId && item.accountId !== record.accountId) || (item.userId && item.userId !== record.userId))) throw failure('REGISTRATION_RESUME_OUTPUT_INVALID', '续跑新 token 与该原账号既有强身份不一致');
      }
    }
  } catch (error) { Object.assign(error, { requiresReconciliation: true, writeOutcomeUnknown: true, doNotRetry: true }); throw error; }
  const result = { requestedCount: 1, completedCount: artifacts.length, selectedKeys: artifacts.map(item => item.selectedKey), artifacts,
    resumed: true, phases: output.events.filter(item => item.type === 'stage').map(item => ({ stage: /^[a-z0-9_]{1,64}$/.test(item.stage || '') ? item.stage : 'unknown' })), processSummary: output.processSummary };
  if (output.commandError || output.events.at(-1)?.type !== 'completed' || artifacts.length !== 1) {
    const failed = output.events.findLast(item => item.type === 'failed');
    throw failure(output.commandError?.code === 'JOB_INTERRUPTED' ? 'JOB_INTERRUPTED' : /^[A-Z0-9_]{1,100}$/.test(failed?.code || '') ? failed.code : 'REGISTRATION_RESUME_INCOMPLETE', '原账号续跑未完成，保留原检查点；未申请新号码', { ...result, nextAction: 'resume_account' });
  }
  return result;
}
module.exports = { normalizeRegistrationOptions, runEngineCommand, runRegistrationJob, runRegistrationResumeJob,
  listRegistrationContinuations, verifyRegistrationArtifacts, readRegistrationProtocol: readProtocol };
