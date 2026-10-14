'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { runCommand, _registrationExecution: execution } = require('./phase3Worker');
const { readGptRegisterSources, closeDirectoryHandle } = require('./adapters/gptRegisterFs');
const { PROFILE_ENV, createPhase3BrowserProfile, removePhase3BrowserProfile } = require('./lib/phase3BrowserProfile');
const { readRegistrationSettings } = require('./registrationSettings');
const { assertAuditLogCheckpoint } = require('./logger');
const { resolvePhase3LocalIdentity, isLocalAccountTerminal } = require('./lib/registrationContinuationIdentity');
const RESUME_REVISION_KEY = crypto.randomBytes(32);
const ACCOUNT_TIMEOUT_MS = 30 * 60 * 1000;
const BATCH_TIMEOUT_MAX_MS = 24 * 60 * 60 * 1000;

function failure(code, message, details) { return Object.assign(new Error(message), { code, ...(details ? { details } : {}) }); }
function registrationFailureMessage(code, { resumed = false, nextAction = null } = {}) {
  // Only exact pre-dispatch input failures may say the current form was not
  // submitted. Do not infer this from free-form engine text or from a failed
  // batch: earlier accounts / forms may already have completed successfully.
  if (['CREDENTIAL_INPUT_UNCONFIRMED', 'PASSWORD_INPUT_UNCONFIRMED',
    'CREDENTIAL_CONTEXT_CHANGED', 'CREDENTIAL_INPUT_CONTEXT_CHANGED', 'PHONE_COUNTRY_UNCONFIRMED',
    'PHONE_INPUT_UNCONFIRMED', 'PHONE_INPUT_INVALID', 'PHONE_INPUT_FORMAT_UNCONFIRMED'].includes(code)) {
    return '当前表单输入或页面上下文未通过确认，未继续主动提交；本次执行已停止。保留已有订单、账号检查点及已生成 token，请先核对原记录，不要重新租号';
  }
  if (code === 'SMS_SETTLEMENT_WAIT_EXHAUSTED') {
    return '旧短信订单结算等待已达安全上限，本次执行已停止，未继续申请新号码。已有订单与账本保留待核对；结算未确认不代表已退款，请先核对旧订单状态，不要重新租号';
  }
  if (resumed) return '原账号续跑未完成，保留原检查点；未申请新号码';
  return nextAction ? '已有账号待继续，已停止租用新号码；请从账号恢复入口续跑' : '注册未完整完成，保留已落地账号与可验证产物';
}
function normalizeRegistrationOptions(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
      || Object.keys(options).some(key => !['count', 'country', 'operator', 'smsMaxPriceUsd', 'smsMaxAcquisitions'].includes(key))) throw failure('REGISTRATION_OPTIONS_INVALID', '注册参数包含不允许的字段');
  const { count, country, operator = '' } = options;
  if (!Number.isSafeInteger(count) || count < 1 || count > 100
      || typeof country !== 'string' || !/^[A-Z]{2}$/.test(country)
      || typeof operator !== 'string' || !/^[A-Za-z0-9_-]{0,64}$/.test(operator)) throw failure('REGISTRATION_OPTIONS_INVALID', '数量、国家或运营商格式无效');
  const hasPrice = Object.hasOwn(options, 'smsMaxPriceUsd');
  const hasAcquisitions = Object.hasOwn(options, 'smsMaxAcquisitions');
  if (hasPrice || hasAcquisitions) {
    const price = options.smsMaxPriceUsd;
    if (!hasPrice || !hasAcquisitions || count !== 1 || options.smsMaxAcquisitions !== 1
        || typeof price !== 'string' || price.trim() !== price
        || !/^(?:0|1)(?:\.[0-9]{1,4})?$/.test(price) || Number(price) <= 0 || Number(price) > 1) {
      throw failure('REGISTRATION_OPTIONS_INVALID', '受控验证必须同时指定大于 0 且不超过 1 USD 的单价字符串（最多四位小数）及最多租号 1 次，且只能注册 1 个账号');
    }
  }
  // These are bounds on this one execution, not a renewable total-spend budget.
  return { count, country, operator, ...(hasPrice ? { smsMaxPriceUsd: options.smsMaxPriceUsd, smsMaxAcquisitions: 1 } : {}) };
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
        extraFileDescriptors: [script.descriptor, node.descriptor, root.descriptor, resultFd, ...(resumeBinding ? [resumeFd] : [])], signal, jobId,
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
  logger, jobId, actor = 'panel-admin', onProgress, preflight, runner, beforeExecute = null } = {}) {
  const normalized = normalizeRegistrationOptions(options);
  const settings = readRegistrationSettings({ rootDirectory });
  if (!settings.ready || !settings.countries.some(item => item.code === normalized.country)) throw failure('REGISTRATION_CONFIG_INVALID', '注册配置或所选国家不完整，请先检查设置');
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消');
  onProgress?.({ type: 'stage', stage: 'network_preflight' });
  const network = await (preflight || require('./networkPreflight').runNetworkPreflight)({ rootDirectory, signal, logger, jobId, actor });
  if (!network.ok) throw failure('REGISTRATION_PREFLIGHT_FAILED', '网络预检未通过，未申请号码或启动注册', { preflight: network });
  if (beforeExecute !== null) {
    if (typeof beforeExecute !== 'function') throw failure('REGISTRATION_DESTINATION_INVALID', '导入目标检查不可用，未启动注册');
    await beforeExecute();
  }
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消，未启动注册');
  if (readRegistrationSettings({ rootDirectory }).revision !== settings.revision) throw failure('REGISTRATION_CONFIG_CHANGED', '网络预检期间注册配置已变化，未申请号码，请重新开始');
  const before = readGptRegisterSources({ rootDirectory, strictCompleteSnapshot: true });
  const output = await runEngineCommand({ rootDirectory, arguments: [String(normalized.count), '--panel-register', '--country=' + normalized.country, '--operator=' + normalized.operator,
    ...(Object.hasOwn(normalized, 'smsMaxPriceUsd') ? ['--sms-max-price-usd=' + normalized.smsMaxPriceUsd, '--sms-max-acquisitions=1'] : [])],
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
    throw failure(code, registrationFailureMessage(code, { nextAction }), { ...result, nextAction });
  }
  return result;
}
function continuationSnapshot(rootDirectory) {
  const handle = execution.openPinnedPhase3Root(path.resolve(rootDirectory));
  const read = filename => {
    let fd;
    try {
      try { fd = fs.openSync(path.join(handle.traversalPath, filename), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
      catch (error) { if (error.code === 'ENOENT') return { rows: [], hash: null }; throw error; }
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 32 * 1024 * 1024) throw new Error();
      const bytes = Buffer.alloc(stat.size); let offset = 0;
      while (offset < bytes.length) { const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset); if (!count) throw new Error(); offset += count; }
      const final = fs.fstatSync(fd), current = fs.lstatSync(path.join(handle.traversalPath, filename));
      if (final.size !== stat.size || final.mtimeMs !== stat.mtimeMs || current.ino !== stat.ino || current.dev !== stat.dev || current.isSymbolicLink()) throw new Error();
      const rows = JSON.parse(bytes.toString('utf8'));
      if (!Array.isArray(rows) || rows.length > 10000 || rows.some(item => !item || typeof item !== 'object' || Array.isArray(item))) throw new Error();
      return { rows, hash: crypto.createHash('sha256').update(bytes).digest('hex') };
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  };
  try {
    const accounts = read('accounts.json'), usernames = read('username.json');
    return { accounts: accounts.rows, fileHash: accounts.hash, usernames: usernames.rows, usernameFileHash: usernames.hash };
  } catch { throw failure('REGISTRATION_CONTINUATION_INVALID', '本地注册账本无法安全读取'); }
  finally { closeDirectoryHandle(handle); }
}
function continuationPhone(account) {
  const raw = account?.phone;
  return typeof raw === 'string' && raw.length <= 64 && !/[^0-9 +().-]/.test(raw) ? raw.replace(/\D/g, '') : '';
}
function continuationItems(snapshot) {
  const phase2Statuses = new Set(['registered', 'oauth_phase2_failed', 'registration_sms_submission_attempted', 'registration_sms_submitted', 'registration_navigation_unconfirmed', 'registration_server_landed_pending_login']);
  const phase3Statuses = new Set(['email_bound', 'oauth_phase3_failed']);
  return snapshot.accounts.flatMap((account, index) => {
    const status = String(account.status || 'registered').trim().toLowerCase();
    const stage = phase3Statuses.has(status) ? 'phase3' : phase2Statuses.has(status) ? 'phase2' : null;
    if (!stage) return [];
    const phone = continuationPhone(account);
    const identity = stage === 'phase3' ? resolvePhase3LocalIdentity(snapshot.accounts, snapshot.usernames, index) : null;
    const email = identity?.ok ? identity.email : typeof account.email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(account.email) ? account.email.toLowerCase() : '';
    const samePhone = snapshot.accounts.filter(item => continuationPhone(item) === phone);
    let reason = null;
    if (!phone || typeof account.password !== 'string' || !account.password.trim() || /[\x00\r\n]/.test(account.password)) reason = '缺少有效的原手机号或登录凭据';
    else if (samePhone.length !== 1) reason = '本地手机号不唯一，需先核对原注册记录';
    else if (isLocalAccountTerminal(account) || snapshot.usernames.some(item => continuationPhone(item) === phone && isLocalAccountTerminal(item))) reason = '本地账号已终止，不可续跑';
    else if (stage === 'phase3' && !identity.ok) reason = ({ LOCAL_USERNAME_MISSING: '本地 username 记录缺失', LOCAL_USERNAME_AMBIGUOUS: '本地 username 手机号对应多条记录', LOCAL_PASSWORD_MISMATCH: '两份本地记录的密码不一致', LOCAL_ACTIVATION_MISMATCH: '两份本地记录的激活编号不一致', LOCAL_ACCOUNT_TERMINAL: '本地账号已终止，不可续跑', LOCAL_EMAIL_MISSING: '本地绑定邮箱缺失', LOCAL_EMAIL_AMBIGUOUS: '本地绑定邮箱不唯一', LOCAL_EMAIL_MISMATCH: '两份本地记录的邮箱不一致' })[identity.reason] || '本地身份无法唯一核验';
    else if (status.startsWith('registration_') && !account.smsActivationId) reason = '短信注册检查点缺少原激活编号';
    const selectedKey = 'registration:accounts:' + index;
    const revision = crypto.createHmac('sha256', RESUME_REVISION_KEY).update(JSON.stringify([snapshot.fileHash, snapshot.usernameFileHash, selectedKey, stage, account])).digest('hex');
    return [{ selectedKey, revision, stage, ...(email ? { email } : {}), phoneMasked: phone ? '***' + phone.slice(-4) : '', eligible: reason === null, reason,
      repairEmail: identity?.ok && identity.repairEmail === true, blockingRegistration: account.continuationRequired === true }];
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
  const identity = item.stage === 'phase3' ? resolvePhase3LocalIdentity(snapshot.accounts, snapshot.usernames, index) : null;
  return { snapshot, item, account: snapshot.accounts[index], binding: { index, stage: item.stage, fileHash: snapshot.fileHash,
    recordHash: crypto.createHash('sha256').update(JSON.stringify(snapshot.accounts[index])).digest('hex'),
    ...(identity?.ok ? { usernameFileHash: snapshot.usernameFileHash, usernameIndex: identity.usernameIndex,
      usernameRecordHash: crypto.createHash('sha256').update(JSON.stringify(snapshot.usernames[identity.usernameIndex])).digest('hex') } : {}) } };
}
async function runRegistrationResumeJob({ rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register', target, signal,
  logger, jobId, actor = 'panel-admin', onProgress, preflight, runner, beforeExecute = null } = {}) {
  const selected = resolveContinuation(rootDirectory, target);
  const settings = readRegistrationSettings({ rootDirectory });
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '续跑已取消');
  onProgress?.({ type: 'stage', stage: 'network_preflight' });
  const network = await (preflight || require('./networkPreflight').runNetworkPreflight)({ rootDirectory, signal, logger, jobId, actor, scope: selected.item.stage === 'phase3' ? 'phase3' : 'registration' });
  if (!network.ok) throw failure('REGISTRATION_PREFLIGHT_FAILED', '网络预检未通过，未执行账号续跑', { preflight: network });
  if (beforeExecute !== null) {
    if (typeof beforeExecute !== 'function') throw failure('REGISTRATION_DESTINATION_INVALID', '导入目标检查不可用，未启动续跑');
    await beforeExecute();
  }
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消，未启动续跑');
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
        if (record?.email !== String(latest[0].email).trim().toLowerCase()) throw failure('REGISTRATION_RESUME_OUTPUT_INVALID', '续跑产物不属于原账号的已绑定邮箱');
        const originals = before.tokens.filter(item => item.email === record.email && item.parseStatus === 'ok');
        if (originals.some(item => (item.accountId && item.accountId !== record.accountId) || (item.userId && item.userId !== record.userId))) throw failure('REGISTRATION_RESUME_OUTPUT_INVALID', '续跑新 token 与该原账号既有强身份不一致');
      }
    }
  } catch (error) { Object.assign(error, { requiresReconciliation: true, writeOutcomeUnknown: true, doNotRetry: true }); throw error; }
  const result = { requestedCount: 1, completedCount: artifacts.length, selectedKeys: artifacts.map(item => item.selectedKey), artifacts,
    resumed: true, phases: output.events.filter(item => item.type === 'stage').map(item => ({ stage: /^[a-z0-9_]{1,64}$/.test(item.stage || '') ? item.stage : 'unknown' })), processSummary: output.processSummary };
  if (output.commandError || output.events.at(-1)?.type !== 'completed' || artifacts.length !== 1) {
    const failed = output.events.findLast(item => item.type === 'failed');
    const code = output.commandError?.code === 'JOB_INTERRUPTED' ? 'JOB_INTERRUPTED' : /^[A-Z0-9_]{1,100}$/.test(failed?.code || '') ? failed.code : 'REGISTRATION_RESUME_INCOMPLETE';
    throw failure(code, registrationFailureMessage(code, { resumed: true }), { ...result, nextAction: 'resume_account' });
  }
  return result;
}
module.exports = { normalizeRegistrationOptions, runEngineCommand, runRegistrationJob, runRegistrationResumeJob,
  listRegistrationContinuations, verifyRegistrationArtifacts, readRegistrationProtocol: readProtocol };
