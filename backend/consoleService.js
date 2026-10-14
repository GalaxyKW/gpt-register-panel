'use strict';

const crypto = require('node:crypto');
const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const sync = require('./sync');
const { withControlPlaneLock } = require('./taskCoordinator');
const { createAdmissionDispatchGuard, throwIfJobInterrupted, updateTerminalJob } = require('./jobLifecycle');
const { mutationRequestDigest } = require('./idempotency');
const { safeFailureMessage, assertAuditLogCheckpoint } = require('./logger');
const lifecycle = require('./accountLifecycle');
const maintenance = require('./accountMaintenance');
const { readRegistrationSettings, updateRegistrationSettings } = require('./registrationSettings');
const { runRegistrationJob, normalizeRegistrationOptions, listRegistrationContinuations,
  runRegistrationResumeJob } = require('./registrationWorker');
const { runNetworkPreflight } = require('./networkPreflight');
const phase3 = require('./phase3Worker');
const { phase3TargetRevision } = require('./phase3TargetRevision');
const { accountTestTargetRevision, accountTestTargetDigest, REVISION_PATTERN } = require('./accountTargetRevision');
const { validateBoundRemoteTarget, remotePhase3EndpointDigest, bindRemotePhase3Targets } = require('./remotePhase3');
const { remotePhase3OutputIdentityMatches } = require('./identityCompletion');
const { accountTestTargetBaseline, runAccountTestJob, accountTestJobStatus, normalizeAccountTestModelId } = require('./accountTestWorker');
const { normalizeAccountTestFailure } = require('./lib/accountTestFailure');
const { strongIdentityContradiction } = require('./diff');
const logs = require('./consoleLogs');
const importProxy = require('./importProxy');

const PARENT_TYPES = new Set(['console_register', 'console_resume', 'console_maintain', 'console_log_cleanup']);
const TERMINAL = new Set(['succeeded', 'partial', 'failed', 'interrupted']);
const EXECUTION_REVISION = /^console-execution-v1\.[A-Za-z0-9_-]{43}$/;
function failure(code, message) { return Object.assign(new Error(message), { code }); }
function ordinaryObject(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function strongIdentityOverlaps(left, right) {
  return left.some(key => /^(account|user):/.test(key) && right.includes(key));
}
function maintenanceVersion(account) {
  return JSON.stringify([accountTestTargetDigest(account), account?.planType, account?.maintenanceEvidence]);
}
function assertRefreshCurrent(expected, actual) {
  if (!actual || actual.id !== expected.id || maintenanceVersion(expected) !== maintenanceVersion(actual)
      || !lifecycle.accountInMaintenanceScope(actual)
      || !['auth_invalid', 'expired'].includes(maintenance.classifyAccountMaintenance(actual).classification)) {
    throw failure('CONSOLE_TARGET_CHANGED', '账号状态或维护原因已变化，未继续刷新或回写');
  }
}
function freeTokenForAutomaticImport(item) {
  // The advanced manual importer supports other plans, but the automated
  // console must not relabel paid or unproven credentials as Free accounts.
  try { return sync.buildCodexSessionDocument(item).plan_type === 'free'; }
  catch { return false; }
}
function normalizeCommand(kind, body = {}) {
  if (!ordinaryObject(body)) throw failure('CONSOLE_REQUEST_INVALID', '请求格式无效');
  if (kind === 'resume') {
    if (Object.keys(body).some(k => !['selectedKey', 'revision', 'autoImport'].includes(k))
        || body.autoImport !== true || typeof body.selectedKey !== 'string'
        || !/^registration:accounts:\d{1,5}$/.test(body.selectedKey)
        || typeof body.revision !== 'string' || body.revision.length > 160 || !/^[A-Za-z0-9._-]+$/.test(body.revision)) {
      throw failure('CONSOLE_REQUEST_INVALID', '续跑目标或版本无效，请刷新待继续账号清单');
    }
    return { selectedKey: body.selectedKey, revision: body.revision, autoImport: true };
  }
  if (kind === 'register') {
    if (Object.keys(body).some(k => !['count', 'country', 'operator', 'autoImport', 'smsMaxPriceUsd', 'smsMaxAcquisitions'].includes(k))
        || body.autoImport !== true) throw failure('CONSOLE_REQUEST_INVALID', '注册任务必须明确自动入库');
    return { ...normalizeRegistrationOptions({ count: body.count, country: body.country, operator: body.operator || '',
      ...(Object.hasOwn(body, 'smsMaxPriceUsd') ? { smsMaxPriceUsd: body.smsMaxPriceUsd } : {}),
      ...(Object.hasOwn(body, 'smsMaxAcquisitions') ? { smsMaxAcquisitions: body.smsMaxAcquisitions } : {}) }), autoImport: true };
  }
  if (kind === 'maintain') {
    if (Object.keys(body).some(k => !['accountIds', 'importNew', 'refreshInvalid', 'deleteBanned',
      'localTokenTargets', 'testOnly', 'accountTargets', 'modelId'].includes(k))) throw failure('CONSOLE_REQUEST_INVALID', '维护参数包含未知字段');
    const ids = body.accountIds === undefined ? [] : body.accountIds;
    if (!Array.isArray(ids) || ids.length > 1000 || new Set(ids).size !== ids.length
        || Array.from(ids).some(id => !Number.isSafeInteger(id) || id < 1)) throw failure('CONSOLE_REQUEST_INVALID', '请选择有效且不重复的账号 ID');
    for (const key of ['importNew', 'refreshInvalid', 'deleteBanned']) if (typeof body[key] !== 'boolean') throw failure('CONSOLE_REQUEST_INVALID', '必须明确维护动作');
    if (ids.length && body.importNew) throw failure('CONSOLE_REQUEST_INVALID', '所选账号维护不能同时导入选择范围外的新账号');
    const intent = { accountIds: [...ids].sort((a, b) => a - b), importNew: body.importNew,
      refreshInvalid: body.refreshInvalid, deleteBanned: body.deleteBanned };
    const localMode = Object.hasOwn(body, 'localTokenTargets');
    const testMode = Object.hasOwn(body, 'testOnly') || Object.hasOwn(body, 'accountTargets');
    if (localMode || testMode) {
      if ((localMode && testMode) || body.importNew || body.refreshInvalid || body.deleteBanned
          || !ids.length || ids.length > 100 || (testMode && body.testOnly !== true)) {
        throw failure('CONSOLE_REQUEST_INVALID', '已有 token 回写或单独测试必须明确所选账号，且不能混合其他动作');
      }
      const targets = localMode ? body.localTokenTargets : body.accountTargets;
      const fields = localMode ? ['selectedKey', 'accountId', 'targetRevision', 'sourceContentHash', 'executionRevision']
        : ['accountId', 'targetRevision', 'executionRevision'];
      if (!Array.isArray(targets) || targets.length !== ids.length || targets.some(target => !ordinaryObject(target)
          || Object.keys(target).length !== fields.length || Object.keys(target).some(key => !fields.includes(key))
          || !ids.includes(target.accountId) || !REVISION_PATTERN.test(target.targetRevision || '')
          || !EXECUTION_REVISION.test(target.executionRevision || '')
          || (localMode && (typeof target.selectedKey !== 'string' || !/^token:/.test(target.selectedKey)
            || target.selectedKey.length > 512 || !/^[a-f0-9]{64}$/.test(target.sourceContentHash || ''))))
          || new Set(targets.map(target => target.accountId)).size !== ids.length
          || (localMode && new Set(targets.map(target => target.selectedKey)).size !== ids.length)) {
        throw failure('CONSOLE_REQUEST_INVALID', '审核目标或版本不完整，请重新读取清单');
      }
      const normalized = targets.map(target => Object.fromEntries(fields.map(field => [field, target[field]])))
        .sort((a, b) => a.accountId - b.accountId);
      if (localMode) intent.localTokenTargets = normalized;
      else { intent.testOnly = true; intent.accountTargets = normalized; }
    }
    if (Object.hasOwn(body, 'modelId')) intent.modelId = normalizeAccountTestModelId(body.modelId);
    return intent;
  }
  if (kind === 'log_cleanup') {
    if (Object.keys(body).some(k => !['olderThanDays', 'confirm'].includes(k)) || body.confirm !== true
        || !Number.isInteger(body.olderThanDays) || body.olderThanDays < 1 || body.olderThanDays > 365) {
      throw failure('CONSOLE_REQUEST_INVALID', '请明确确认清理范围及保留天数');
    }
    return { olderThanDays: body.olderThanDays, confirm: true };
  }
  throw failure('CONSOLE_REQUEST_INVALID', '未知操作');
}
function failureMetadata(error) {
  const result = { code: /^[A-Z0-9_]{1,100}$/.test(error?.code || '') ? error.code : 'CONSOLE_STEP_FAILED' };
  for (const key of ['requiresReconciliation', 'writeOutcomeUnknown', 'doNotRetry', 'retryAllowed',
    'reconciliationScope', 'reconciliationReason', 'accountDisposition', 'accountDispositionWriteOutcome',
    'dispositionPersisted', 'dispositionOutcome', 'dispositionWriteOutcomeUnknown', 'dispositionCode']) {
    if (['string', 'boolean'].includes(typeof error?.[key])) result[key] = error[key];
  }
  if (Number.isSafeInteger(error?.details?.completedCount)) result.completedCount = error.details.completedCount;
  if (['resume_phase2', 'resume_account'].includes(error?.details?.nextAction)) result.nextAction = error.details.nextAction;
  return result;
}
function jobSummary(job) {
  const result = job.result || {};
  return { id: job.id, type: job.type, status: job.status === 'queued' && result.startedAt ? 'running' : job.status,
    stage: result.stage || 'queued', progress: result.progress || { completed: 0, total: job.payload?.count || 0 },
    summary: result.summary || {}, items: (result.items || []).slice(-100),
    itemsTotal: result.items?.length || 0, itemsTruncated: result.items?.length > 100,
    childJobIds: (result.childJobIds || []).slice(-100),
    failureStage: result.failureStage || null, nextAction: result.nextAction || null,
    recoveryMessage: result.recoveryMessage || null,
    createdAt: job.createdAt, finishedAt: job.finishedAt || null, error: job.error || null };
}

function createConsoleService({ db, logger, jobManager,
  clientFactory = options => new Sub2ApiAdminClient(options),
  registrar = runRegistrationJob, resumer = runRegistrationResumeJob, preflight = runNetworkPreflight,
  snapshotBuilder = sync.buildSnapshot, phase3Runner = phase3.runPhase3Job,
  importer = sync.executeImport, tester = runAccountTestJob,
  describeFailure = failureMetadata } = {}) {
  const active = new Map();
  let network = null; let networkPromise = null; let timer = null; let ticking = false;
  let lastAutomaticRun = Date.now(); let snapshotCache = null; let snapshotPromise = null;
  const reviewSecret = crypto.randomBytes(32);
  const client = context => clientFactory({ logger, ...(context ? { logContext: { jobId: context.job.id } } : {}) });
  const executionRevision = material => 'console-execution-v1.' + crypto.createHmac('sha256', reviewSecret)
    .update(JSON.stringify(material)).digest('base64url');
  const testExecutionRevision = (account, remoteClient) => executionRevision(['test',
    remotePhase3EndpointDigest(remoteClient), accountTestTargetRevision(account), maintenanceVersion(account)]);
  const event = (level, name, fields = {}) => logger?.[level]?.(name, fields);
  async function snapshot({ fresh = false, signal, context } = {}) {
    if (!fresh && snapshotCache && Date.now() - snapshotCache.at < 10000) return snapshotCache.value;
    if (!fresh && snapshotPromise) return snapshotPromise;
    const operation = snapshotBuilder(new URLSearchParams('withSub2api=1'), {
      includeRaw: true, includeInternal: true, requireCompleteSources: true, client: client(context), logger, signal,
    }).then(value => { snapshotCache = { at: Date.now(), value }; return value; });
    if (fresh) return operation;
    snapshotPromise = operation;
    try { return await operation; } finally { snapshotPromise = null; }
  }
  function requireRemote(value) {
    if (!sync.confirmedSub2ApiRead(value)) throw failure('SUB2API_READ_FAILED', 'Sub2API 尚未连接，未启动账号操作');
    return value._internal.accounts;
  }
  async function settings() {
    const saved = await db.getConsoleSettings();
    let registration;
    try { registration = readRegistrationSettings(); }
    catch (error) { registration = { ready: false, phase3Ready: false, phase3Issues: ['注册配置暂不可读，请检查服务配置与权限'],
      issues: [{ code: error.code || 'REGISTRATION_CONFIG_UNAVAILABLE', message: '注册配置暂不可读，请检查服务配置与权限' }], fields: [], countries: [] }; }
    const proxy = await importProxy.readImportProxySettings(db);
    let endpointMatches = proxy.settings.proxyId === null;
    try { endpointMatches ||= proxy.settings.endpointDigest === importProxy.endpointDigest(client()); } catch {}
    return { revision: saved.revision, policy: saved.settings, registration,
      importProxy: { revision: proxy.revision, proxyId: proxy.settings.proxyId,
        configured: proxy.settings.proxyId !== null, endpointMatches, lastRequestId: proxy.settings.lastRequestId } };
  }
  async function proxies() {
    const remoteClient = client();
    const saved = await importProxy.readImportProxySettings(db);
    const rows = await remoteClient.listProxies();
    return { revision: saved.revision, selectedProxyId: saved.settings.proxyId,
      items: rows.map(proxy => ({ id: proxy.id, name: proxy.name, protocol: proxy.protocol, status: proxy.status,
        revision: proxy.revision, ...importProxy.proxyEligibility(proxy) })) };
  }
  async function localTokenReview(current, remoteClient, signal) {
    const accounts = requireRemote(current);
    const sources = current._internal.sources;
    const endpointKey = lifecycle.managementEndpointKey(remoteClient.baseUrl);
    const history = await db.listAccountLifecycles(endpointKey);
    const maintenancePlan = maintenance.buildMaintenancePlan({ accounts, lifecycles: history, endpointKey,
      policy: { refreshInvalid: true, deleteBanned: false } });
    const candidates = sync.listIdentityCompletionCandidates(sources, accounts);
    const rows = [];
    const shortIdentity = (keys, prefix) => {
      const value = (keys || []).find(key => key.startsWith(prefix + ':'))?.slice(prefix.length + 1);
      return value ? value.slice(0, 12) + (value.length > 12 ? '…' : '') : null;
    };
    for (const original of sync.buildImportPlan(sources, accounts)) {
      const candidate = candidates.find(item => item.selectedKey === original.key);
      let planItem = original; let reviewed = null;
      if (candidate) {
        const { selectedKey, accountId, targetRevision, sourceContentHash } = candidate;
        const targets = [{ selectedKey, accountId, targetRevision, sourceContentHash }];
        reviewed = sync.resolveIdentityCompletionReview(sources, accounts, [selectedKey], targets);
        reviewed.targets = targets;
        [planItem] = sync.buildScopedImportPlan(sources, accounts, [selectedKey], reviewed.sourceBindings);
      }
      let account = accounts.find(item => item.id === planItem.accountId);
      // This fallback is display-only: it explains why an available partial
      // identity is skipped, without minting a proof or enabling a write.
      if (!account) {
        const overlaps = accounts.filter(item => strongIdentityOverlaps(lifecycle.lifecycleIdentityKeys(item), original.sourceIdentityKeys || []));
        if (overlaps.length === 1 && !strongIdentityContradiction(lifecycle.lifecycleIdentityKeys(overlaps[0]), original.sourceIdentityKeys || [])) account = overlaps[0];
      }
      const decision = maintenancePlan.items.find(item => item.accountId === account?.id);
      let eligible = planItem.action === 'update' && decision?.action === 'refresh' && freeTokenForAutomaticImport(planItem);
      let action = eligible ? 'update' : ['create', 'skip'].includes(planItem.action) ? planItem.action : 'review';
      let reasonCode = eligible ? (candidate ? 'complete_account_identity' : 'existing_token_update') : planItem.reasonCode || 'source_requires_review';
      let reason = eligible ? (candidate ? '唯一 User ID 一致；确认后补全缺失 Account ID 并回写原 ID，不重新登录、不新增账号' : '强身份一致；将已有新 token 回写原 ID，不重新登录、不新增账号') : '来源或身份需要核对，未允许回写';
      if (planItem.action === 'skip') { reasonCode = 'source_skipped'; reason = '该来源无需回写或不是当前可用的新版本；可单独测试远端账号'; }
      if (decision && decision.action !== 'refresh') {
        reasonCode = decision.reasonCode;
        const reasons = { healthy: '账号当前可用，默认跳过，不覆盖现有 token', quota_wait: '额度或限流等待中，不通过换 token 绕过限制',
          manual_disabled: '账号被手动停用，保留停用状态', confirmed_banned: '账号已确认封禁，不回写 token', network_unknown: '无充分失效证据，请先测试或核对账号状态' };
        reason = reasons[decision.classification] || '账号身份或历史记录需核对，未允许回写';
        action = ['keep', 'wait', 'skip'].includes(decision.action) ? 'skip' : 'review';
      }
      if (planItem.action === 'create') { action = 'create'; reasonCode = 'never_imported'; reason = '从未入库的来源，请使用“导入新账号”'; eligible = false; }
      if (!freeTokenForAutomaticImport(planItem)) { eligible = false; action = 'review'; reasonCode = 'outside_free_oauth_scope'; reason = '只允许自动处理已确认 Free 的 OAuth token'; }
      const sourceContentHash = planItem._record?.contentHash || null;
      const targetRevision = account ? accountTestTargetRevision(account) : null;
      let binding = null;
      if (eligible) {
        const groupBinding = await sync.resolveImportGroupBinding(remoteClient, [planItem], { signal });
        const executionBinding = sync.resolveImportExecutionBinding(remoteClient, [planItem]);
        binding = executionRevision(['local_token', maintenanceVersion(account),
          sync.buildImportPlanIntentVersion('0'.repeat(64), [planItem.key], [planItem], groupBinding, executionBinding, reviewed?.remoteTargets)]);
      }
      const sourceKeys = planItem.sourceIdentityKeys || [];
      const targetKeys = lifecycle.lifecycleIdentityKeys(account);
      const matchedBy = candidate ? 'user_id' : sourceKeys.some(key => key.startsWith('account:') && targetKeys.includes(key))
        ? 'account_id' : sourceKeys.some(key => key.startsWith('user:') && targetKeys.includes(key)) ? 'user_id' : null;
      rows.push({ public: { selectedKey: planItem.key, sourceContentHash, accountId: account?.id || null,
        accountName: account?.name || '', sourceLabel: planItem.relativePath || '', email: planItem.email || '',
        action, eligible, reasonCode, reason, matchedBy, identityCompletion: candidate ? 'account_id' : null,
        targetRevision, executionRevision: binding,
        sourceFingerprint: planItem._record?.fingerprints?.access?.slice(0, 8) || null,
        targetFingerprint: account?.tokenFingerprints?.access?.slice(0, 8) || null,
        identitySummary: { sourceAccountId: shortIdentity(sourceKeys, 'account'), targetAccountId: shortIdentity(targetKeys, 'account'),
          sourceUserId: shortIdentity(sourceKeys, 'user'), targetUserId: shortIdentity(targetKeys, 'user') } },
      account, planItem, reviewed });
    }
    return rows;
  }
  async function localTokens() {
    const current = await snapshot({ fresh: true });
    const rows = await localTokenReview(current, client());
    return { snapshotVersion: current.version, items: rows.map(row => row.public) };
  }
  async function overview() {
    const configuration = await settings();
    const inventory = await db.listJobsPage(100);
    const jobs = [];
    // The general job list deliberately omits workflow-specific result data.
    // Query parent IDs independently of child history, then return only a
    // bounded projection; never turn an omitted result into progress 0.
    for (const id of await db.listConsoleJobReferences()) {
      const job = await db.getJob(id);
      if (job && PARENT_TYPES.has(job.type)) jobs.push(jobSummary(job));
    }
    let current = null; let warning = null;
    try { current = await snapshot(); requireRemote(current); }
    catch { warning = '账号数据暂不可完整读取；注册及维护不会在未知状态下启动。请先运行连接检测。'; }
    let endpointKey = null;
    try { endpointKey = lifecycle.managementEndpointKey(client().baseUrl); } catch {}
    const history = endpointKey ? await db.listAccountLifecycles(endpointKey) : [];
    const remote = current?._internal?.accounts || [];
    const plan = endpointKey ? maintenance.buildMaintenancePlan({ accounts: remote, lifecycles: history,
      endpointKey, policy: configuration.policy }) : { items: [] };
    const accounts = plan.items.map(item => {
      const account = remote.find(a => a.id === item.accountId);
      return { id: item.accountId, name: item.accountName, email: account?.email || '', status: account?.status || 'unknown',
        targetRevision: item.targetRevision, executionRevision: item.targetRevision ? testExecutionRevision(account, client()) : null,
        classification: item.classification, action: item.action, reason: item.reasonCode,
        retryAt: item.retryAt || null, usage: account?.usage || null,
        lastProcessedAt: history.find(row => row.sub2apiId === item.accountId)?.updatedAt || null };
    });
    let neverImported = 0;
    if (current && !warning) {
      const importPlan = sync.buildImportPlan(current._internal.sources, remote);
      for (const item of importPlan.filter(item => item.action === 'create')) {
        const eligibility = lifecycle.creationEligibility(history, { endpointKey, identityKeys: item.sourceIdentityKeys });
        if (eligibility.allowed && freeTokenForAutomaticImport(item)) {
          neverImported += 1;
          accounts.push({ id: null, key: item.key, name: item.accountName || '待分配', email: item.email || '',
            status: 'local', classification: 'never_imported', action: 'import', reason: 'never_imported', usage: null });
        } else if (eligibility.allowed) {
          accounts.push({ id: null, key: item.key, name: item.accountName || '本地 token', email: item.email || '',
            status: 'local', classification: 'needs_review', action: 'review', reason: 'outside_free_oauth_scope', usage: null });
        }
      }
    }
    const deleted = new Map();
    for (const row of history.filter(row => ['deleted', 'delete_pending', 'review_required'].includes(row.state))) {
      if (remote.some(a => a.id === row.sub2apiId) || deleted.has(row.sub2apiId)) continue;
      deleted.set(row.sub2apiId, true);
      accounts.push({ id: null, key: 'removed:' + row.sub2apiId, name: row.accountName, email: '',
        status: row.state, classification: row.state === 'deleted' ? 'deleted' : 'network_unknown', action: 'skip',
        reason: row.reasonCode, lastProcessedAt: row.updatedAt || null, usage: null });
    }
    const count = classification => accounts.filter(a => a.classification === classification).length;
    return { readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
      capabilities: { registrationEnabled: process.env.PANEL_PHASE3_ENABLED === '1',
        phase3Enabled: process.env.PANEL_PHASE3_ENABLED === '1', sub2apiConfigured: sync.configuredForSub2Api(),
        comparisonAvailable: !warning },
      summary: { total: remote.length, healthy: count('healthy'), quotaWait: count('quota_wait'),
        refreshNeeded: count('auth_invalid') + count('expired'), banned: count('confirmed_banned'),
        needsReview: accounts.filter(a => a.action === 'review').length, neverImported },
      accounts, jobs, settings: configuration, network, warning,
      reconciliation: inventory.reconciliationHolds, activeJobs: inventory.activeJobs,
      generatedAt: new Date().toISOString() };
  }
  async function runPreflight(signal) {
    if (networkPromise) return networkPromise;
    networkPromise = (async () => {
      let report;
      try { report = await preflight({ signal, logger }); }
      catch (error) { report = { ok: false, checkedAt: new Date().toISOString(), channels: ['sms', 'mail', 'oauth'].map(id => ({ id, ok: false, code: 'CONFIG_UNAVAILABLE', message: '注册配置或检测执行器不可用' })) }; }
      const started = Date.now(); let destination;
      try {
        await client().listAccounts({ pageSize: 200, requireTotal: true, requirePaginationMetadata: true, signal });
        destination = { id: 'sub2api', ok: true, code: 'OK', message: '管理 API 连接正常；模型调用需导入后单独测试', durationMs: Date.now() - started };
      } catch { destination = { id: 'sub2api', ok: false, code: 'SUB2API_UNAVAILABLE', message: '目标服务连接或鉴权失败', durationMs: Date.now() - started }; }
      network = { ...report, ok: report.ok && destination.ok, channels: [...report.channels, destination] };
      event('info', 'console.preflight_completed', { ok: network.ok, channels: network.channels.map(c => ({ id: c.id, ok: c.ok, code: c.code })) });
      return network;
    })();
    try { return await networkPromise; } finally { networkPromise = null; }
  }
  async function saveSettings(body) {
    if (!ordinaryObject(body) || Object.keys(body).some(k => !['revision', 'policy', 'registration', 'importProxy', 'confirm'].includes(k))
        || ['policy', 'registration', 'importProxy'].filter(key => Object.hasOwn(body, key)).length !== 1) {
      throw failure('CONSOLE_REQUEST_INVALID', '每次仅保存一组设置');
    }
    return withControlPlaneLock(async () => {
      await db.assertNoReconciliationHold();
      const inventory = await db.listJobsPage(1);
      if (inventory.activeJobs.total > 0) {
        throw failure('CONSOLE_SETTINGS_ACTIVE_CONFLICT', '后台任务仍在执行，请先停止或等待完成后再修改设置');
      }
      assertAuditLogCheckpoint(logger, 'console.settings_save_checkpoint', { section: body.policy ? 'policy' : body.importProxy ? 'importProxy' : 'registration' });
      if (body.importProxy) {
        const value = body.importProxy;
        if (body.confirm !== true || !ordinaryObject(value)
            || Object.keys(value).some(key => !['revision', 'proxyId', 'proxyRevision', 'requestId'].includes(key))
            || !Number.isSafeInteger(value.revision) || value.revision < 0
            || typeof value.requestId !== 'string' || !importProxy.UUID.test(value.requestId)
            || (value.proxyId !== null && (!Number.isSafeInteger(value.proxyId) || value.proxyId < 1))
            || (value.proxyId !== null && (typeof value.proxyRevision !== 'string' || value.proxyRevision.length > 160))) {
          throw failure('CONSOLE_IMPORT_PROXY_SETTINGS_INVALID', '请明确选择默认导入代理并确认保存');
        }
        let endpoint = null;
        if (value.proxyId !== null) {
          let proxy;
          // This catch covers only the read-only precondition. In particular
          // DB persistence and the response read remain outside: failures
          // there may represent a completed write and need receipt recovery.
          try {
            const remoteClient = client();
            proxy = await remoteClient.getProxy(value.proxyId);
            endpoint = importProxy.endpointDigest(remoteClient);
          } catch {
            throw failure('CONSOLE_IMPORT_PROXY_CHECK_FAILED', '保存前无法核验代理，设置未写入；请重载节点后重试');
          }
          const eligible = importProxy.proxyEligibility(proxy);
          if (proxy?.id !== value.proxyId || !eligible.eligible || proxy.revision !== value.proxyRevision) {
            throw failure('CONSOLE_IMPORT_PROXY_CHANGED', '所选代理配置已变化或不可用，请重新加载节点清单');
          }
        }
        await db.saveImportProxySettings({ proxyId: value.proxyId, endpointDigest: endpoint, lastRequestId: value.requestId },
          { expectedRevision: value.revision });
      } else if (body.policy) {
        const old = await db.getConsoleSettings();
        if (body.policy.enabled && !old.settings.enabled && body.confirm !== true) {
          throw failure('CONSOLE_REQUEST_INVALID', '启用自动维护须明确确认后续刷新和封禁删除策略');
        }
        await db.saveConsoleSettings(body.policy, { expectedRevision: body.revision });
        lastAutomaticRun = Date.now();
      } else updateRegistrationSettings(body.registration);
      snapshotCache = null;
      return settings();
    });
  }

  async function updateParent(context, stage, fields = {}) {
    throwIfJobInterrupted(context.signal);
    context.result = { ...context.result, ...fields, stage };
    await db.updateJob(context.job.id, { result: context.result });
    event('info', 'console.stage', { jobId: context.job.id, stage, progress: context.result.progress });
  }
  async function child(context, type, payload, claimKeys, operation, ownsLock = true) {
    throwIfJobInterrupted(context.signal);
    const job = await withControlPlaneLock(() => db.createJob(type, { ...payload, parentJobId: context.job.id }, context.actor, { claimKeys }), { signal: context.signal });
    let persisted = false;
    let invoked = false;
    const persistFailure = async error => {
      if (persisted) return;
      await updateTerminalJob(db, job.id, { status: context.signal.aborted ? 'interrupted' : 'failed',
        error: safeFailureMessage(error), result: { ...describeFailure(error), ...failureMetadata(error) }, finishedAt: new Date().toISOString() });
      persisted = true;
    };
    const persistResult = async result => {
      if (persisted) return;
      const status = type === 'account_test' ? accountTestJobStatus(result)
        : result?.failed > 0 ? (result.succeeded > 0 ? 'partial' : 'failed') : 'succeeded';
      await updateTerminalJob(db, job.id, { status, result, finishedAt: new Date().toISOString() });
      persisted = true;
    };
    const invoke = async () => {
      invoked = true;
      try {
        if (!ownsLock) await db.startMutationJob(job.id);
        const result = await operation({ jobId: job.id, signal: context.signal, db, logger, actor: context.actor,
          persistResult, persistSuccess: persistResult, persistFailure });
        await persistResult(result);
        if (result?.requiresReconciliation || result?.writeOutcomeUnknown) throw Object.assign(failure('CONSOLE_RECONCILIATION_REQUIRED', '执行结果需要核对，已停止后续操作'), { requiresReconciliation: true });
        return { jobId: job.id, result };
      } catch (error) { await persistFailure(error); error.consoleChildJobId = job.id; throw error; }
    };
    try {
      context.result.childJobIds.push(job.id);
      await db.updateJob(context.job.id, { result: context.result });
      throwIfJobInterrupted(context.signal);
      return await (ownsLock ? invoke() : withControlPlaneLock(invoke, { signal: context.signal }));
    } catch (error) {
      if (!invoked) await updateTerminalJob(db, job.id, { status: 'interrupted',
        result: { code: 'CONSOLE_CHILD_NOT_STARTED', executionOutcome: 'not_started' },
        finishedAt: new Date().toISOString() });
      throw error;
    }
  }

  async function importFiles(context, selectedKeys, expectedAccount = null, artifacts = [], frozenReview = null) {
    if (!selectedKeys.length) return { succeeded: 0, imported: [] };
    const current = await snapshot({ fresh: true, signal: context.signal, context });
    const accounts = requireRemote(current);
    const sources = current._internal.sources;
    const remoteClient = client(context);
    const endpointKey = lifecycle.managementEndpointKey(remoteClient.baseUrl);
    await lifecycle.recordObservedAccounts(db, { endpointKey, accounts });
    let plan = sync.buildImportPlan(sources, accounts, selectedKeys);
    let reviewed;
    if (frozenReview) {
      const row = (await localTokenReview(current, remoteClient, context.signal))
        .find(item => item.public.selectedKey === frozenReview.selectedKey);
      if (!row?.public.eligible || Object.keys(frozenReview).some(key => row.public[key] !== frozenReview[key])) {
        throw failure('CONSOLE_LOCAL_REVIEW_CHANGED', '已有 token、原账号或目标服务已变化，请重新审核；未重新登录或新增账号');
      }
    }
    if (expectedAccount) {
      const actual = accounts.find(a => a.id === expectedAccount.id);
      assertRefreshCurrent(expectedAccount, actual);
      const candidates = sync.listIdentityCompletionCandidates(sources, accounts, selectedKeys);
      if (plan.some(item => item.action === 'conflict') && candidates.length === selectedKeys.length
          && candidates.every(item => item.accountId === expectedAccount.id)) {
        const targets = candidates.map(({ selectedKey, accountId, targetRevision, sourceContentHash }) => (
          { selectedKey, accountId, targetRevision, sourceContentHash }
        ));
        reviewed = sync.resolveIdentityCompletionReview(sources, accounts, selectedKeys, targets);
        reviewed.targets = targets;
        plan = sync.buildScopedImportPlan(sources, accounts, selectedKeys, reviewed.sourceBindings);
      }
      if (plan.length !== 1 || plan.some(item => item.accountId !== expectedAccount.id
          || !['update', 'skip'].includes(item.action)
          || !remotePhase3OutputIdentityMatches(lifecycle.lifecycleIdentityKeys(expectedAccount), item.sourceIdentityKeys))) {
        throw failure('CONSOLE_TARGET_CHANGED', '新 token 与原账号强身份不一致，已阻止回写');
      }
    } else {
      if (plan.length !== selectedKeys.length || plan.some(item => item.action !== 'create')) {
        throw failure('CONSOLE_CREATE_PLAN_CHANGED', '来源或远端状态已变化，未执行新增导入');
      }
      if (plan.some(item => !freeTokenForAutomaticImport(item))) {
        throw failure('CONSOLE_TOKEN_PLAN_INVALID', '仅自动导入已明确验证为 Free 的 token；付费或套餐未知的来源请在高级诊断核对');
      }
      for (const item of plan) {
        const allowed = await lifecycle.canCreateAccount(db, { endpointKey, identityKeys: item.sourceIdentityKeys });
        if (!allowed.allowed) throw failure('CONSOLE_PREVIOUSLY_IMPORTED', '该账号有导入或删除履历，不会自动重新创建');
      }
    }
    for (const artifact of artifacts) {
      const item = plan.find(item => item.key === artifact.selectedKey);
      if (!item || item._record?.contentHash !== artifact.contentHash) throw failure('CONSOLE_SOURCE_CHANGED', '任务产出的 token 文件已变化，未继续导入');
    }
    const groupBinding = await sync.resolveImportGroupBinding(remoteClient, plan, { signal: context.signal });
    const proxyBinding = await importProxy.resolveImportProxyBinding(db, remoteClient, plan, { signal: context.signal });
    if (plan.some(item => item.action === 'create') && Object.hasOwn(context, 'importProxyBinding')
        && JSON.stringify(context.importProxyBinding) !== JSON.stringify(proxyBinding)) {
      throw failure('CONSOLE_IMPORT_PROXY_CHANGED', '任务启动后默认代理发生变化，已保留本地成果，未改为直连导入');
    }
    const executionBinding = sync.resolveImportExecutionBinding(remoteClient, plan, { importProxy: proxyBinding });
    const planIntentVersion = sync.buildImportPlanIntentVersion(current.version, selectedKeys, plan,
      groupBinding, executionBinding, reviewed?.remoteTargets);
    const { result } = await child(context, 'token_import', { snapshotVersion: current.version,
      planIntentVersion, selectedSourcePaths: plan.map(item => item.relativePath) }, ['token_import'], options => importer({
      ...options, client: Object.assign(remoteClient, { logContext: { jobId: options.jobId, parentJobId: context.job.id } }), snapshotVersion: current.version, planIntentVersion, selectedKeys,
      ...(reviewed ? { remoteTargets: reviewed.remoteTargets, remoteSourceHashes: reviewed.sources,
        remoteSourceBindings: reviewed.sourceBindings, remoteTargetBaselines: reviewed.baselines,
        identityCompletionTargets: reviewed.targets } : {}),
      beforeCreate: async item => {
        const allowed = await lifecycle.canCreateAccount(db, { endpointKey, identityKeys: item.sourceIdentityKeys });
        if (!allowed.allowed) throw failure('CONSOLE_PREVIOUSLY_IMPORTED', '账号已有导入或删除记录，已阻止重复创建');
      },
      beforeUpdate: expectedAccount ? async account => assertRefreshCurrent(expectedAccount, account) : undefined,
    }));
    if (result.requiresReconciliation || result.writeOutcomeUnknown || (expectedAccount && result.failed > 0)) {
      throw Object.assign(failure('CONSOLE_IMPORT_FAILED', '导入未完整成功，请查看该任务明细'),
        { requiresReconciliation: result.requiresReconciliation === true || result.writeOutcomeUnknown === true });
    }
    if (result.failed > 0) {
      context.result.summary.failed += result.failed;
      context.result.items.push({ status: 'failed', code: 'CONSOLE_IMPORT_PARTIAL',
        message: '本批有 ' + result.failed + ' 个导入失败；已验证成功的账号继续测试，失败项不会自动重交。' });
    }
    snapshotCache = null;
    return result;
  }

  async function verifyAccount(context, id, { expectedTarget = null, phases = {} } = {}) {
    const remoteClient = client(context);
    const account = await remoteClient.getAccount(id, { signal: context.signal });
    const assertTestPolicy = current => {
      if (!current || current.id !== id || maintenanceVersion(account) !== maintenanceVersion(current)
          || !lifecycle.accountInMaintenanceScope(current)
          || ['manual_disabled', 'quota_wait', 'confirmed_banned'].includes(maintenance.classifyAccountMaintenance(current).classification)) {
        throw failure('CONSOLE_TEST_TARGET_CHANGED', '账号维护状态已变化，未测试或改变调度');
      }
    };
    assertTestPolicy(account);
    if (expectedTarget && (accountTestTargetRevision(account) !== expectedTarget.targetRevision
        || testExecutionRevision(account, remoteClient) !== expectedTarget.executionRevision)) {
      throw failure('CONSOLE_TEST_TARGET_CHANGED', '账号或目标服务已变化，请重新选择测试目标');
    }
    const baseline = accountTestTargetBaseline(account);
    if (!baseline) throw failure('CONSOLE_TEST_TARGET_INVALID', '账号缺少可核验的测试身份，未恢复调度');
    const modelId = context.intent.modelId ?? context.policy.testModel;
    phases.tested = true;
    context.result.summary.tested += 1;
    const { result } = await child(context, 'account_test', { accountIds: [id], modelId },
      ['account:' + id], options => tester({ ...options, accountIds: [id], targetBaselines: [baseline],
        modelId, client: Object.assign(remoteClient, { logContext: { jobId: options.jobId, parentJobId: context.job.id } }),
        beforeTestAccount: assertTestPolicy }));
    if (accountTestJobStatus(result) !== 'succeeded') {
      const outcome = result.results?.find(item => item.accountId === id);
      if (outcome?.attempted === false) {
        phases.tested = false;
        context.result.summary.tested -= 1;
        if (outcome.code === 'CONSOLE_TEST_TARGET_CHANGED') {
          throw failure('CONSOLE_TEST_TARGET_CHANGED', '账号维护状态已变化，未发送测试或改变调度');
        }
      }
      const detail = normalizeAccountTestFailure(outcome);
      context.result.summary.testFailed += 1;
      throw Object.assign(failure('CONSOLE_TEST_FAILED', (phases.tokenUpdated ? '已回写原账号；' : '') + detail.message
        + '。未强行启用调度；可单独重试测试，无需重新获取 token'), { consoleTestFailure: detail });
    }
    phases.verified = true;
    context.result.summary.verified += 1;
    return result;
  }

  async function verifyImportedAccounts(context, imported) {
    for (const item of imported.imported || []) {
      const id = item.verification?.accountId;
      if (!Number.isSafeInteger(id)) throw failure('CONSOLE_IMPORT_RESULT_INVALID', '已导入账号缺少可核对的远端 ID，未继续测试');
      await updateParent(context, 'verifying_account');
      const phases = { imported: true, tested: false, verified: false };
      try {
        await verifyAccount(context, id, { phases });
        context.result.items.push({ accountId: id, status: 'verified', phases, message: '首次导入并验证成功' });
      } catch (error) {
        context.result.summary.failed += 1;
        context.result.items.push({ accountId: id, status: 'failed', code: error.code || 'CONSOLE_TEST_FAILED',
          phases, ...(error.consoleTestFailure || {}), message: safeFailureMessage(error) });
        if (context.signal.aborted || error.requiresReconciliation || error.writeOutcomeUnknown) throw error;
        // An ordinary test rejection for one newly imported account must not
        // abandon validation of the other already-imported accounts.
      }
    }
  }

  function remoteBinding(account, remoteClient) {
    return validateBoundRemoteTarget({ accountId: account.id, targetRevision: accountTestTargetRevision(account),
      identityKeys: lifecycle.lifecycleIdentityKeys(account), targetDigest: accountTestTargetDigest(account),
      endpointDigest: remotePhase3EndpointDigest(remoteClient) });
  }
  async function refreshAccount(context, account, phases) {
    const current = await snapshot({ fresh: true, signal: context.signal, context });
    const accounts = requireRemote(current);
    const actual = accounts.find(item => item.id === account.id);
    assertRefreshCurrent(account, actual);
    const sources = current._internal.sources;
    const keys = lifecycle.lifecycleIdentityKeys(account);
    const candidates = sync.collectCandidates(sources).filter(item =>
      strongIdentityOverlaps(keys, item.sourceIdentityKeys || []));
    const bound = remoteBinding(account, client(context));
    let request;
    if (candidates.length === 1 && !candidates[0].identityConflict
        && !strongIdentityContradiction(keys, candidates[0].sourceIdentityKeys)) {
      const token = candidates[0].record;
      const records = sources.usernames.filter(entry => entry.email === token.email);
      if (records.length !== 1) throw failure('CONSOLE_LOGIN_MAPPING_REQUIRED', '本地登录资料不唯一，请在高级诊断核对一次');
      const record = records[0];
      request = { sourceMode: 'token', selectedKey: 'token:' + token.source + ':' + token.relativePath,
        email: record.email, phone: record.phone || undefined,
        phase3TargetRevision: phase3TargetRevision({ token, username: record, usernameContentHash: sources.usernameContentHash }) };
    } else if (candidates.length === 0) {
      // Email selects a local login candidate only. It never authorizes a
      // credential write: Phase3 must prove the frozen remote strong identity.
      const listing = phase3.listLocalPhase3Targets();
      const matches = listing.accounts.filter(entry => entry.eligible && entry.email === account.email);
      if (!account.email || matches.length !== 1) throw failure('CONSOLE_LOGIN_MAPPING_REQUIRED', '缺少唯一的本地登录资料，请在高级诊断核对一次');
      request = { ...matches[0], sourceMode: 'username', remoteTarget: { accountId: account.id, targetRevision: bound.targetRevision } };
    } else throw failure('CONSOLE_LOGIN_MAPPING_REQUIRED', '存在真实身份冲突，未自动重新登录');
    const resolved = phase3.resolvePhase3Requests([request]);
    if (resolved.eligible.length !== 1 || resolved.rejected.length) throw failure('CONSOLE_LOGIN_MAPPING_REQUIRED', resolved.rejected[0]?.message || '本地登录资料校验失败');
    const target = resolved.eligible[0];
    if (target.sourceMode === 'username') bindRemotePhase3Targets([target], accounts, client(context));
    let completed;
    try { completed = await child(context, 'phase3', { email: target.email, phone: target.phone,
      sourceMode: target.sourceMode, remoteTarget: bound }, target.canonicalKeys, options => phase3Runner({
      ...options, email: target.email, phone: target.phone, canonicalKeys: target.canonicalKeys,
      sourceMode: target.sourceMode, executionBinding: target.executionBinding, requireExecutionBinding: true,
      remoteTarget: target.sourceMode === 'username' ? target.remoteTarget : null,
      remoteClientFactory: clientFactory,
      beforeExecute: async () => assertRefreshCurrent(account, await client(context).getAccount(account.id, { signal: context.signal })),
    })); } catch (error) {
      // A login candidate found only by email cannot prove that a failed
      // login's ban applies to the remote strong identity. Only an existing
      // strongly matched local token can authorize that deletion path.
      error.consoleHasStrongLocalBinding = target.sourceMode === 'token';
      throw error;
    }
    const { result } = completed;
    const output = await snapshot({ fresh: true, signal: context.signal, context });
    const tokens = output._internal.sources.tokens.filter(token => token.relativePath === result.tokenFile
      && token.historical !== true && token.parseStatus === 'ok');
    if (tokens.length !== 1 || !remotePhase3OutputIdentityMatches(keys, tokens[0].identityKeys)) {
      throw failure('CONSOLE_REFRESH_IDENTITY_MISMATCH', '重新登录输出未通过原账号强身份校验，未回写');
    }
    const token = tokens[0];
    phases.tokenGenerated = true;
    context.result.summary.tokensGenerated += 1;
    const selectedKey = 'token:' + token.source + ':' + token.relativePath;
    await updateParent(context, 'updating_token');
    const imported = await importFiles(context, [selectedKey], account, [{ selectedKey, contentHash: token.contentHash }]);
    phases.tokenUpdated = imported.succeeded > 0;
    context.result.summary.tokensUpdated += imported.succeeded || 0;
    await updateParent(context, 'verifying_account');
    await verifyAccount(context, account.id, { phases });
  }

  async function deleteAccount(context, item, phase3JobId = null) {
    const remoteClient = client(context);
    const endpointKey = lifecycle.managementEndpointKey(remoteClient.baseUrl);
    return child(context, 'account_delete', { accountId: item.accountId, reason: 'confirmed_ban' },
      ['account:' + item.accountId], options => maintenance.deleteConfirmedBannedAccount({
        ...options, client: remoteClient, target: { ...item, action: 'delete' }, endpointKey, backup: sync.writeBackup,
        ...(phase3JobId ? { verifyBanEvidence: account => maintenance.verifyPhase3BanEvidence(db, phase3JobId,
          { target: item, account, client: remoteClient }) } : {}),
      }), false);
  }
  async function register(context) {
    const current = await snapshot({ fresh: true, signal: context.signal, context });
    requireRemote(current);
    if (context.intent.autoImport) context.importProxyBinding = await importProxy.resolveImportProxyBinding(db, client(context), [{ action: 'create' }], { signal: context.signal });
    // This read happens before entering the engine: invalid destination
    // configuration must not be discovered only after a paid registration.
    await updateParent(context, 'checking_network');
    let progressWrites = Promise.resolve();
    let completedCount = 0;
    let result; let registrationFailure = null;
    const resuming = context.job.type === 'console_resume';
    try { ({ result } = await child(context, 'registration', context.intent, ['registration'], options => (resuming ? resumer : registrar)({
      ...(context.intent.autoImport ? { beforeExecute: () => importProxy.assertImportProxyCurrent(db, client(context), context.importProxyBinding, { signal: context.signal }) } : {}),
      ...options, ...(resuming ? { target: { selectedKey: context.intent.selectedKey, revision: context.intent.revision } }
        : { options: { count: context.intent.count, country: context.intent.country, operator: context.intent.operator,
          ...(Object.hasOwn(context.intent, 'smsMaxPriceUsd') ? { smsMaxPriceUsd: context.intent.smsMaxPriceUsd, smsMaxAcquisitions: context.intent.smsMaxAcquisitions } : {}) } }),
      onProgress: progress => {
        if (Number.isSafeInteger(progress.completedCount) && progress.completedCount >= completedCount
            && progress.completedCount <= (context.intent.count || 1)) completedCount = progress.completedCount;
        const observedCompleted = completedCount;
        progressWrites = progressWrites.then(() => updateParent(context, progress.stage || 'registering', {
          progress: { completed: observedCompleted, total: context.intent.count || 1 },
        })).catch(() => {});
      },
    }), false)); } catch (error) {
      const partial = error.details;
      if (error.requiresReconciliation || error.writeOutcomeUnknown
          || !Number.isSafeInteger(partial?.completedCount) || partial.completedCount < 1
          || partial.completedCount > (context.intent.count || 1)
          || !Array.isArray(partial.selectedKeys) || partial.selectedKeys.length !== partial.completedCount
          || !Array.isArray(partial.artifacts) || partial.artifacts.length !== partial.completedCount) throw error;
      if (context.signal.aborted) {
        // Stop forbids new work, not recording artifacts already verified by
        // the terminated child. Do not import or rent replacements here.
        context.result.summary.registered = partial.completedCount;
        context.result.summary.tokensGenerated = partial.completedCount;
        context.result.progress = { completed: partial.completedCount, total: context.intent.count || 1 };
        context.result.recoveryMessage = '任务已停止，已核验的 ' + partial.completedCount
          + ' 个本地 token 仍保留，未继续导入或租号。请先核对成果，再从账号维护处理未入库账号。';
        throw error;
      }
      result = partial; registrationFailure = error;
    } finally {
      // Drain queued progress before persisting any terminal failure, even
      // when registration failed without producing a single artifact.
      await progressWrites;
    }
    // Verified local output is a completed registration, independently of
    // the later Sub2API import. Persist it before an import read can fail.
    context.result.summary.registered = result.completedCount;
    context.result.summary.tokensGenerated = result.completedCount;
    if (registrationFailure) {
      context.result.summary.failed += 1;
      context.result.nextAction = registrationFailure.details.nextAction || 'review';
      context.result.items.push({ status: 'failed', code: registrationFailure.code || 'REGISTRATION_INCOMPLETE',
        message: '本批有未完成账号，保留原进度，不重新租号；已生成的 token 单独进行入库核验。' });
    }
    await updateParent(context, 'importing', { progress: { completed: result.completedCount, total: context.intent.count || 1 } });
    let imported;
    try { imported = await importFiles(context, result.selectedKeys, null, result.artifacts); }
    catch (error) {
      context.result.recoveryMessage = '已在本地生成 ' + result.completedCount
        + ' 个账号的 token，导入未完整确认。不要重新注册或租号；请先查看导入子任务和远端记录，结果明确后从账号维护导入未入库账号。';
      throw error;
    }
    context.result.summary.imported = imported.succeeded || 0;
    await updateParent(context, 'verifying_account');
    await verifyImportedAccounts(context, imported);
  }
  async function maintain(context) {
    const current = await snapshot({ fresh: true, signal: context.signal, context });
    const accounts = requireRemote(current);
    if (context.intent.importNew) {
      const creates = sync.buildImportPlan(current._internal.sources, accounts).filter(item => item.action === 'create' && freeTokenForAutomaticImport(item));
      context.importProxyBinding = await importProxy.resolveImportProxyBinding(db, client(context), creates, { signal: context.signal });
    }
    const endpointKey = lifecycle.managementEndpointKey(client(context).baseUrl);
    await lifecycle.recordObservedAccounts(db, { endpointKey, accounts });
    const history = await db.listAccountLifecycles(endpointKey);
    const plan = maintenance.buildMaintenancePlan({ accounts, lifecycles: history, endpointKey, policy: context.intent });
    const selected = context.intent.accountIds;
    if (selected.some(id => !accounts.some(a => a.id === id))) throw failure('CONSOLE_TARGET_CHANGED', '所选账号清单已变化，请刷新');
    if (context.intent.localTokenTargets || context.intent.testOnly) {
      const targets = context.intent.localTokenTargets || context.intent.accountTargets;
      const review = context.intent.localTokenTargets ? await localTokenReview(current, client(context), context.signal) : [];
      // Validate the complete frozen selection before the first side effect.
      for (const target of targets) {
        const account = accounts.find(item => item.id === target.accountId);
        if (context.intent.localTokenTargets) {
          const row = review.find(item => item.public.selectedKey === target.selectedKey);
          if (!row?.public.eligible || Object.keys(target).some(key => row.public[key] !== target[key])) {
            throw failure('CONSOLE_LOCAL_REVIEW_CHANGED', '审核清单已变化，请重新读取已有 token；未执行回写');
          }
        } else if (accountTestTargetRevision(account) !== target.targetRevision
            || testExecutionRevision(account, client(context)) !== target.executionRevision) {
          throw failure('CONSOLE_TEST_TARGET_CHANGED', '所选账号或目标服务已变化，请重新选择测试目标');
        }
      }
      await updateParent(context, 'planning', { progress: { completed: 0, total: targets.length } });
      for (const target of targets) {
        throwIfJobInterrupted(context.signal);
        const account = accounts.find(item => item.id === target.accountId);
        const phases = { tokenGenerated: false, tokenUpdated: false, tested: false, verified: false };
        let item = { accountId: account.id, accountName: account.name, status: 'verified', phases };
        try {
          const decision = plan.items.find(entry => entry.accountId === account.id);
          if (context.intent.testOnly && (!lifecycle.accountInMaintenanceScope(account)
              || ['manual_disabled', 'quota_wait', 'confirmed_banned'].includes(decision?.classification)
              || ['strong_identity_ambiguous', 'lifecycle_requires_reconciliation'].includes(decision?.reasonCode))) {
            context.result.summary.skipped += 1;
            item = { ...item, status: 'skipped', code: decision?.reasonCode,
              message: '账号处于手动停用、额度等待或需核对状态，未测试或改变调度' };
          } else {
            if (context.intent.localTokenTargets) {
              await updateParent(context, 'updating_token');
              const imported = await importFiles(context, [target.selectedKey], account,
                [{ selectedKey: target.selectedKey, contentHash: target.sourceContentHash }], target);
              phases.tokenUpdated = imported.succeeded > 0;
              context.result.summary.tokensUpdated += imported.succeeded || 0;
              // Persist the independently verified write before a later test
              // can fail. A network/model failure must not erase this outcome.
              await updateParent(context, 'verifying_account');
              await verifyAccount(context, account.id, { phases });
              item.message = '已有 token 已回写原 ID 并验证成功，未重新登录或新增账号';
            } else {
              await updateParent(context, 'verifying_account');
              await verifyAccount(context, account.id, { expectedTarget: target, phases });
              item.message = '账号测试成功，未获取或导入 token';
            }
          }
        } catch (error) {
          context.result.summary.failed += 1;
          item = { ...item, status: 'failed', code: error.code || 'CONSOLE_STEP_FAILED',
            ...(error.consoleTestFailure || {}), message: safeFailureMessage(error) };
          context.result.items.push(item);
          if (context.signal.aborted || error.requiresReconciliation || error.writeOutcomeUnknown) throw error;
          await updateParent(context, 'maintaining', { progress: { completed: context.result.items.length, total: targets.length } });
          continue;
        }
        context.result.items.push(item);
        await updateParent(context, 'maintaining', { progress: { completed: context.result.items.length, total: targets.length } });
      }
      return;
    }
    const items = plan.items.filter(item => !selected.length || selected.includes(item.accountId));
    await updateParent(context, 'planning', { progress: { completed: 0, total: items.length } });
    let connectionsChecked = false;
    for (const item of items) {
      throwIfJobInterrupted(context.signal);
      let status = 'skipped'; let errorCode = null; let message = item.reasonCode;
      const phases = { tokenGenerated: false, tokenUpdated: false, tested: false, verified: false };
      let diagnostic = {};
      try {
        if (item.action === 'refresh') {
          if (!connectionsChecked) {
            await updateParent(context, 'checking_network');
            const report = await preflight({ signal: context.signal, logger, scope: 'phase3' });
            // A reauthorization only needs mail and OAuth; unavailable SMS
            // must not prevent refreshing an existing account.
            if (!['mail', 'oauth'].every(id => report.channels.some(c => c.id === id && c.ok))) {
              throw failure('CONSOLE_NETWORK_UNAVAILABLE', '邮箱或登录通道不通，已停止本轮刷新');
            }
            connectionsChecked = true;
          }
          await updateParent(context, 'refreshing');
          try { await refreshAccount(context, accounts.find(a => a.id === item.accountId), phases); }
          catch (error) {
            if (error.code === 'ACCOUNT_DEACTIVATED' && error.accountDisposition === 'discard'
                && error.consoleHasStrongLocalBinding === true
                && !error.requiresReconciliation && context.intent.deleteBanned && error.consoleChildJobId) {
              await updateParent(context, 'removing_banned');
              await deleteAccount(context, item, error.consoleChildJobId);
              context.result.summary.deleted += 1; status = 'deleted';
            } else throw error;
          }
          if (status !== 'deleted') { context.result.summary.refreshed += 1; status = 'refreshed'; }
        } else if (item.action === 'delete') {
          await updateParent(context, 'removing_banned');
          await deleteAccount(context, item);
          context.result.summary.deleted += 1; status = 'deleted';
        } else context.result.summary.skipped += 1;
      } catch (error) {
        status = 'failed'; errorCode = error.code || 'CONSOLE_STEP_FAILED'; message = safeFailureMessage(error);
        diagnostic = error.consoleTestFailure || {};
        context.result.summary.failed += 1;
        if (context.signal.aborted || error.requiresReconciliation || error.writeOutcomeUnknown
            || error.code === 'CONSOLE_NETWORK_UNAVAILABLE') throw error;
      }
      context.result.items.push({ accountId: item.accountId, accountName: item.accountName, status, code: errorCode,
        phases, ...diagnostic, message });
      await updateParent(context, 'maintaining', { progress: { completed: context.result.items.length, total: items.length } });
    }
    if (context.intent.importNew) {
      await updateParent(context, 'importing_new');
      const fresh = await snapshot({ fresh: true, signal: context.signal, context });
      const historyNow = await db.listAccountLifecycles(endpointKey);
      const newItems = sync.buildImportPlan(fresh._internal.sources, requireRemote(fresh)).filter(item => item.action === 'create'
        && freeTokenForAutomaticImport(item)
        && lifecycle.creationEligibility(historyNow, { endpointKey, identityKeys: item.sourceIdentityKeys }).allowed);
      // Keep each bounded original importer transaction intact; no browser
      // round trips or resubmission are needed between server-side batches.
      for (let i = 0; i < newItems.length; i += 100) {
        const batch = newItems.slice(i, i + 100);
        const result = await importFiles(context, batch.map(item => item.key));
        context.result.summary.imported += result.succeeded || 0;
        await verifyImportedAccounts(context, result);
      }
    }
  }

  function dispatchParent(job, intent, actor, record) {
    const context = { job, intent, actor, signal: record.controller.signal,
      result: { startedAt: new Date().toISOString(), stage: 'queued',
        progress: { completed: 0, total: intent.count || 0 }, childJobIds: [], items: [],
        summary: { registered: 0, imported: 0, refreshed: 0, deleted: 0, skipped: 0, failed: 0,
          tokensGenerated: 0, tokensUpdated: 0, tested: 0, verified: 0, testFailed: 0 } } };
    active.set(job.id, record);
    const operation = Promise.resolve().then(async () => {
      throwIfJobInterrupted(context.signal);
      await withControlPlaneLock(() => db.startMutationJob(job.id), { signal: context.signal });
      context.policy = (await db.getConsoleSettings()).settings;
      await updateParent(context, 'starting');
      if (['console_register', 'console_resume'].includes(job.type)) await register(context);
      else if (job.type === 'console_maintain') await maintain(context);
      else if (job.type === 'console_log_cleanup') {
        const result = await child(context, 'log_cleanup', intent, ['log_cleanup'], async () => {
          assertAuditLogCheckpoint(logger, 'console.log_cleanup_checkpoint', { jobId: job.id, olderThanDays: intent.olderThanDays });
          // The control lease excludes registration/Phase3 for the full scan
          // and removal, so an old log cannot become active during cleanup.
          return logs.cleanupLogs(intent, { registerActive: false });
        }, false);
        context.result.summary = result.result;
      }
      const status = context.result.summary.failed > 0 ? 'partial' : 'succeeded';
      context.result.stage = 'completed';
      await updateTerminalJob(db, job.id, { status, result: context.result, finishedAt: new Date().toISOString() });
      event('info', 'console.task_completed', { jobId: job.id, type: job.type, status, summary: context.result.summary });
    }).catch(async error => {
      const failureStage = context.result.stage;
      context.result = { ...context.result, ...describeFailure(error), ...failureMetadata(error), failureStage,
        stage: context.signal.aborted ? 'stopped' : 'failed' };
      await updateTerminalJob(db, job.id, { status: context.signal.aborted ? 'interrupted' : 'failed',
        result: context.result, error: safeFailureMessage(error), finishedAt: new Date().toISOString() });
      event('error', 'console.task_failed', { jobId: job.id, code: error.code || 'CONSOLE_TASK_FAILED' });
    }).finally(() => { active.delete(job.id); snapshotCache = null; });
    return jobManager.track(record, operation);
  }
  async function submit(kind, body, { actor = 'local', idempotencyKey, signal } = {}) {
    const intent = normalizeCommand(kind, body);
    if (process.env.PANEL_WRITE_ENABLED !== '1') throw failure('WRITE_DISABLED', '当前为只读模式');
    if ((['register', 'resume'].includes(kind) || (kind === 'maintain' && intent.refreshInvalid)) && process.env.PANEL_PHASE3_ENABLED !== '1') {
      throw failure('PHASE3_DISABLED', '注册和重新授权执行器尚未启用');
    }
    const workflow = 'console_' + kind;
    const requestDigest = mutationRequestDigest(workflow, intent, idempotencyKey);
    const receiptQuery = { workflow, idempotencyKey, requestDigest, requestedBy: actor };
    const prior = await db.getMutationReceipt(receiptQuery);
    if (prior) return { receipt: prior, replayed: true };
    const guard = createAdmissionDispatchGuard({ db, jobManager });
    return guard.run(async ({ recordCommitted, dispatch }) => {
      const created = await withControlPlaneLock(async () => {
        throwIfJobInterrupted(signal);
        assertAuditLogCheckpoint(logger, 'console.task_admission_checkpoint', { workflow, actor });
        const submission = await db.createMutationSubmission({ ...receiptQuery,
          jobs: [{ type: workflow, payload: intent, claimKeys: ['console_pipeline'] }],
          responseFactory: ({ createdJobs }) => ({ jobId: createdJobs[0].job.id, status: 'queued' }),
        });
        if (!submission.replayed) recordCommitted(submission.createdJobs);
        return submission;
      }, { signal });
      if (!created.replayed) {
        throwIfJobInterrupted(signal);
        const job = created.createdJobs[0]?.job;
        if (!job) throw failure('CONSOLE_ADMISSION_FAILED', '任务未能持久入队');
        dispatch(job, workflow, actor, record => dispatchParent(job, intent, actor, record));
      }
      return created;
    });
  }
  async function stop(jobId) {
    const job = await db.getJob(jobId);
    if (!job || !PARENT_TYPES.has(job.type)) throw failure('CONSOLE_JOB_NOT_FOUND', '控制台任务不存在');
    if (TERMINAL.has(job.status)) return { jobId, status: job.status };
    const record = active.get(jobId);
    if (!record) throw failure('CONSOLE_JOB_OWNER_UNKNOWN', '任务不由当前进程执行，请刷新状态；不会猜测并终止其他进程');
    record.controller.abort();
    try { event('warn', 'console.stop_requested', { jobId }); } catch {}
    return { jobId, status: 'stopping' };
  }
  async function logOptions() {
    const inventory = await db.listJobsPage(100);
    // listJobsPage is a completeness-checked DB projection; any active
    // execution protects all registration logs from maintenance removal.
    const rows = Array.isArray(inventory) ? inventory : inventory.jobs || [];
    return { registerActive: inventory.activeJobs.truncated || rows.some(job => ['queued', 'running'].includes(job.status)
      && ['phase3', 'registration'].includes(job.type)) };
  }
  async function queryLogs(query) {
    const options = await logOptions();
    if (typeof query.jobId === 'string' && /^job_[a-f0-9]{24}$/.test(query.jobId)) {
      const parent = await db.getJob(query.jobId);
      if (parent && PARENT_TYPES.has(parent.type)) {
        options.jobIds = [parent.id, ...(parent.result?.childJobIds || [])
          .filter(id => typeof id === 'string' && /^job_[a-f0-9]{24}$/.test(id)).slice(0, 4000)];
      }
    }
    return logs.queryLogs(query, options);
  }
  async function tick() {
    if (ticking || active.size || jobManager.shuttingDown || process.env.PANEL_WRITE_ENABLED !== '1') return;
    ticking = true;
    try {
      const saved = await db.getConsoleSettings();
      if (!saved.settings.enabled || Date.now() - lastAutomaticRun < saved.settings.intervalMinutes * 60000) return;
      const inventory = await db.listJobsPage(100);
      if (inventory.activeJobs.total > 0 || inventory.reconciliationHolds.total > 0) return;
      lastAutomaticRun = Date.now();
      await submit('maintain', { accountIds: [], importNew: saved.settings.importNew,
        refreshInvalid: saved.settings.refreshInvalid, deleteBanned: saved.settings.deleteBanned },
      { actor: 'local', idempotencyKey: crypto.randomUUID() });
    } catch (error) { event('warn', 'console.automatic_maintenance_deferred', { code: error.code || 'CONSOLE_SCHEDULER_FAILED' }); }
    finally { ticking = false; }
  }
  function start() {
    if (!timer) { timer = setInterval(() => { tick().catch(() => {}); }, 30000); timer.unref?.(); }
  }
  function dispose() { if (timer) clearInterval(timer); timer = null; }
  return { overview, localTokens, proxies, settings, saveSettings, runPreflight, submit, stop, start, dispose,
    continuations: async () => listRegistrationContinuations(),
    queryLogs,
    downloadLog: async id => logs.downloadLog(id, await logOptions()),
    _test: { importFiles, child, snapshot, tick },
  };
}
module.exports = { createConsoleService, normalizeCommand, jobSummary };
