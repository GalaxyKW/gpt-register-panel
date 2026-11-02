'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  const icon = (name) => '<svg class="icon" aria-hidden="true"><use href="#icon-' + escape(name) + '"/></svg>';
  const PENDING_STORE = 'registerStudio.pending.v1';
  const REVIEW_STORE = 'registerStudio.registrationReview.v1';
  const MAX_REPLAY_AGE = 20 * 60 * 60 * 1000;
  const PAGE_TITLES = { register: '注册任务', accounts: '账号管理', logs: '运行日志', settings: '设置与连接' };
  const JOB_ID = /^job_[a-f0-9]{24}$/;
  const STAGES = { queued: '等待调度', starting: '准备执行', planning: '核对账号与维护范围', checking_network: '检查网络通道', preflight: '连接预检', network_preflight: '连接预检',
    registering: '正在注册', init: '初始化注册流程', phase1_register: '手机号注册与短信验证', phase1_register_recovery: '恢复已有手机号注册',
    phase1_5_profile: '完成账号个人资料', phase2_bind_email: '绑定邮箱', phase2_resume: '继续邮箱绑定', phase3_email_oauth: '邮箱验证并获取 token',
    importing: '导入 Sub2API', importing_new: '导入从未加入的账号', maintenance: '正在维护', maintaining: '继续处理账号',
    refreshing: '本地重新授权', updating_token: '核验身份并回写原账号', verifying_account: '测试账号及恢复调度', removing_banned: '复核并删除确认封禁的记录',
    completed: '处理完成', no_changes: '本次未执行账号操作', stopped: '已停止', failed: '执行失败' };
  const ACTIVE = new Set(['queued', 'pending', 'running', 'stopping', 'cancel_requested']);
  const STATUS_LABELS = { queued: '排队中', pending: '等待中', running: '进行中', stopping: '正在停止', cancel_requested: '正在停止', succeeded: '已完成', completed: '已完成', failed: '失败', cancelled: '已停止', canceled: '已停止', interrupted: '需核对', partial: '部分完成' };
  const CLASSIFICATION = {
    healthy: ['正常可用', 'good', '保持原样'], active: ['正常可用', 'good', '保持原样'],
    new: ['从未导入', 'neutral', '首次导入'], never_imported: ['从未导入', 'neutral', '首次导入'],
    refresh: ['需要授权', 'warn', '重新获取 token'], refresh_needed: ['需要授权', 'warn', '重新获取 token'],
    invalid: ['认证失效', 'warn', '重新获取 token'], auth_invalid: ['认证失效', 'warn', '重新获取 token'], expired: ['已过期', 'warn', '重新获取 token'],
    pending_verification: ['已回写，待测试', 'warn', '测试并恢复调度'],
    quota: ['额度耗尽', 'neutral', '等待恢复'], quota_wait: ['额度 / 冷却中', 'neutral', '等待恢复'], rate_limited: ['限流冷却', 'neutral', '等待恢复'],
    banned: ['确认封禁', 'bad', '删除远端记录'], confirmed_banned: ['确认封禁', 'bad', '删除远端记录'], disabled: ['调度关闭', 'unknown', '保留当前设置'], manual_disabled: ['调度关闭', 'unknown', '保留当前设置'],
    review: ['需要核对', 'unknown', '人工核对'], needs_review: ['需要核对', 'unknown', '人工核对'], network_unknown: ['原因待核对', 'unknown', '人工核对'], deleted: ['已删除', 'unknown', '不再导入'],
  };
  const ACTION_LABELS = { keep: '保持原样', wait: '等待恢复', refresh: '重新获取 token', verify: '测试并恢复调度', delete: '删除远端记录', review: '人工核对', skip: '本次跳过', import: '首次导入' };
  const REASONS = { account_available: '账号可用，不更新现有 token', quota_or_cooldown: '额度耗尽或限流冷却，等待恢复', credential_expired_unavailable: '凭据已过期且账号不可用，需要重新授权', administrator_disabled: '管理员已停用账号，不自动启用', administrator_lifetime_expired: '管理员设定的账号有效期已到期，不是 OAuth token 过期；保留停用，不自动刷新或删除', administrator_unscheduled: '调度当前关闭，且没有可自动恢复的回写记录；保留现有设置', writeback_pending_verification: '新 token 已回写到原账号，继续测试；通过后自动恢复调度，无需重新登录', temporary_scheduling_pause: '账号处于临时调度暂停，但不能确认是额度耗尽；保留账号，等待核对，不自动登录或删除', failure_requires_diagnosis: '目前不能确认失败原因，保留账号并等待核对', account_schema_unknown: '账号信息不完整或身份存在冲突', account_status_unknown: '远端状态未知', strong_identity_ambiguous: '强身份缺失或匹配不唯一，需要人工核对', lifecycle_requires_reconciliation: '导入或删除履历需要核对', outside_free_oauth_scope: '不属于 Free OAuth 账号，不自动处理', disabled_by_policy: '此动作已被维护策略关闭', never_imported: '未发现历史导入记录，可首次导入', confirmed_ban_deleted: '已确认封禁并删除远端记录，不会再次导入', invalid_grant: '重新授权凭据已失效', invalid_token: 'token 无效', token_expired: 'token 已过期', refresh_token_expired: '刷新凭据已过期', refresh_token_invalidated: '刷新凭据已失效，需要本地重新授权', refresh_token_reused: '刷新凭据已经使用，需重新登录', refresh_token_revoked: '刷新凭据被撤销', refresh_token_missing: '缺少刷新凭据，需重新登录', refresh_reauthorization_required: '无法直接续期，需要本地重新授权', account_deactivated: '上游明确确认账号已停用', user_deactivated: '上游明确确认用户已停用', account_suspended: '上游明确确认账号被暂停', account_banned: '上游明确确认账号被封禁' };
  const state = { overview: null, connected: false, pending: null, storageError: false, busy: false, refreshing: false, page: 'register', selected: new Set(), stoppingJobs: new Set(), logs: [], logFiles: [], continuations: [], nextCursor: null, logRevision: 0, token: '', settingsDirty: false, settingsRevision: null, cleanupDaysDirty: false, registrationDirty: false, registrationRevision: null, registrationFields: [], networkBusy: false, pollTimer: null,
    taskDetail: null, taskDetailRevision: 0, localTokens: [], localSelected: new Set(), localTokensBusy: false, localTokensLoaded: false, localTokensRevision: 0,
    registrationReview: null, registrationReviewJobId: null, registrationReviewRevision: 0, registrationReviewBusy: false, registrationReviewPending: null, registrationReviewOtherResolution: null,
    proxyList: null, proxyLoading: false, proxyLoadAttempted: false, proxyListError: '', proxyDirty: false, proxyRevision: null, proxySettingsRevision: null };

  function validToken(value) { return typeof value === 'string' && /^[\x21-\x7e]{16,4096}$/.test(value); }
  function notice(message, tone = '') { $('notice').textContent = message; $('notice').className = 'notice ' + tone; $('notice').hidden = !message; }
  function errorText(error) { return error?.message || '操作失败，请检查连接后重试。'; }
  function date(value) { if (!value) return '—'; const parsed = new Date(value); return Number.isFinite(parsed.getTime()) ? parsed.toLocaleString('zh-CN', { hour12: false, timeZone: 'Asia/Shanghai' }) : '—'; }
  function number(value) { return typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString('zh-CN') : '—'; }
  function tag(label, tone = 'neutral') { return '<span class="tag ' + tone + '">' + escape(label) + '</span>'; }
  function saveToken(value) {
    if (!validToken(value)) throw new Error('令牌须为 16–4096 位英文、数字或半角符号，不能含空格、中文或换行。');
    state.token = value;
    try { sessionStorage.setItem('panelToken', value); } catch { /* Memory-only credentials remain safe for this tab. */ }
  }
  function requestAuthentication(message) {
    state.connected = false;
    $('auth-error').textContent = message || '';
    if (!$('auth-dialog').open) $('auth-dialog').showModal();
    setTimeout(() => $('admin-token').focus(), 0);
    renderControls();
  }
  async function request(path, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), path === '/api/console/preflight' ? 170000 : 45000);
    const headers = new Headers(options.headers || {});
    headers.set('accept', 'application/json');
    if (state.token) {
      if (!validToken(state.token)) throw new Error('当前令牌格式无效，请重新登录。');
      headers.set('x-panel-token', state.token);
    }
    if (options.body !== undefined) headers.set('content-type', 'application/json');
    try {
      const { expectedStatus, ...fetchOptions } = options;
      const response = await fetch(path, { ...fetchOptions, headers, signal: controller.signal, credentials: 'same-origin', redirect: 'error', cache: 'no-store' });
      if (response.status === 401) requestAuthentication('认证失败，请检查管理员令牌。');
      const text = await response.text();
      if (text.length > 8 * 1024 * 1024) throw new Error('服务器响应过大，已停止读取。');
      let body;
      try { body = JSON.parse(text); } catch { throw new Error('服务器响应不是有效 JSON，无法确认请求结果。'); }
      if (response.status === 429 && body.error === 'panel_auth_rate_limited') requestAuthentication(body.message || '认证尝试过多，请稍后重试。');
      if (!response.ok) {
        const error = new Error(body.message || body.error?.message || (typeof body.error === 'string' ? body.error : '') || '请求失败（HTTP ' + response.status + '）');
        error.status = response.status;
        error.code = body.code || body.error?.code || (typeof body.error === 'string' ? body.error : undefined);
        error.writeOutcomeUnknown = body.writeOutcomeUnknown === true;
        error.definitive = response.status >= 400 && response.status < 500 && response.status !== 408 && response.status !== 409 && response.status !== 429;
        if (['REGISTRATION_SETTINGS_CHANGED', 'CONSOLE_SETTINGS_STALE'].includes(error.code)) error.definitive = true;
        // This exact settings response is emitted before any configuration write.
        // Other conflicts (and explicit unknown outcomes below) must keep their receipt.
        if (path === '/api/console/settings' && options.method === 'POST' && response.status === 409
            && error.code === 'CONSOLE_SETTINGS_ACTIVE_CONFLICT') error.definitive = true;
        if (path === '/api/console/settings' && options.method === 'POST' && response.status === 409
            && ['CONSOLE_IMPORT_PROXY_SETTINGS_STALE', 'CONSOLE_IMPORT_PROXY_SETTINGS_INVALID', 'CONSOLE_IMPORT_PROXY_CHANGED', 'CONSOLE_IMPORT_PROXY_CHECK_FAILED'].includes(error.code)) error.definitive = true;
        if (body.writeOutcomeUnknown === true || /WRITE_UNKNOWN|OUTCOME_UNKNOWN|RECONCILIATION/.test(error.code || '')) error.definitive = false;
        throw error;
      }
      if (expectedStatus && response.status !== expectedStatus) throw new Error('服务器成功状态与任务回执不一致，结果尚未确认；请核对本次请求。');
      return body;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error(path === '/api/console/preflight'
        ? '网络检测耗时较长，请稍后刷新查看服务器结果；不会因此租号或发送验证码。'
        : options.method === 'POST' ? '请求超时。写操作可能已被接受，请核对本次请求，不要重复新建任务。'
          : '读取超时，后台任务可能仍在运行。请刷新状态，不要重复提交。');
      throw error;
    } finally { clearTimeout(timer); }
  }
  function pendingValid(value) {
    return value && value.version === 1 && typeof value.url === 'string'
      && /^\/api\/console\/(register(?:\/resume)?|maintain|settings|jobs\/[A-Za-z0-9_-]+\/stop|logs\/cleanup)$/.test(value.url)
      && /^[A-Za-z0-9][A-Za-z0-9._:-]{19,127}$/.test(value.key) && Number.isSafeInteger(value.createdAt)
      && value.body && typeof value.body === 'object' && !Array.isArray(value.body)
      && JSON.stringify(value.body).length < 64000;
  }
  function persistPending(pending) {
    const encoded = pending ? JSON.stringify(pending) : null;
    try {
      if (encoded === null) sessionStorage.removeItem(PENDING_STORE); else sessionStorage.setItem(PENDING_STORE, encoded);
      if (sessionStorage.getItem(PENDING_STORE) !== encoded) throw new Error('persistence');
    } catch { state.storageError = true; throw new Error('无法安全保存操作回执，已阻止新写操作。请允许当前站点使用会话存储。'); }
    state.pending = pending;
    renderControls();
  }
  function mutationKey() {
    if (typeof window.crypto?.randomUUID === 'function') return 'idem_v1_' + window.crypto.randomUUID();
    if (typeof window.crypto?.getRandomValues !== 'function') throw new Error('当前浏览器不支持安全随机数，已阻止写操作。');
    return 'idem_v1_' + Array.from(window.crypto.getRandomValues(new Uint8Array(24)), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }
  function settingsRequestId() {
    if (typeof window.crypto?.randomUUID === 'function') return window.crypto.randomUUID();
    if (typeof window.crypto?.getRandomValues !== 'function') throw new Error('浏览器缺少安全随机数，无法安全保存设置。');
    const bytes = window.crypto.getRandomValues(new Uint8Array(16)); bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
  }
  async function reconcileSettings(pending) {
    const settings = await request('/api/console/settings');
    const expected = pending.body;
    const matches = expected.importProxy ? settings.importProxy?.lastRequestId === expected.importProxy.requestId : expected.registration
      ? settings.registration?.lastRequestId === expected.registration.requestId
      : expected.policy && Object.entries(expected.policy).every(([key, value]) => settings.policy?.[key] === value);
    if (!matches) throw new Error('尚不能确认本次配置已保存。旧版遗留记录或响应丢失都可能造成此状态，不能仅凭当前配置解除保护。不会重新发送密钥或覆盖配置；请按请求时间 ' + date(pending.createdAt) + ' 核对服务端操作日志后人工恢复。重新读取配置只更新表单，不会解除这条待核对记录。');
    persistPending(null);
    if (state.overview) state.overview.settings = settings;
    if (expected.importProxy) { state.proxyDirty = false; state.proxyList = null; state.proxyLoadAttempted = false; }
    else { state.registrationDirty = false; state.settingsDirty = false; state.registrationRevision = null; }
    renderSettings(); notice(expected.importProxy ? '已确认默认导入代理保存成功。仅影响新增账号。' : '已确认本次配置保存成功。密钥没有被重复提交。', 'success');
    return settings;
  }
  async function saveSettings(body) {
    if (writeBlock()) throw new Error(writeBlock());
    if (body.registration) body.registration.requestId = settingsRequestId();
    if (body.importProxy) body.importProxy.requestId = settingsRequestId();
    const safeBody = body.importProxy ? { confirm: true, importProxy: { revision: body.importProxy.revision, proxyId: body.importProxy.proxyId, requestId: body.importProxy.requestId } }
      : body.registration ? { revision: body.revision, registration: { revision: body.registration.revision, requestId: body.registration.requestId, changedKeys: Object.keys(body.registration.changes) } } : body;
    const pending = { version: 1, url: '/api/console/settings', body: safeBody, key: mutationKey(), createdAt: Date.now() };
    persistPending(pending); state.busy = true; renderControls();
    let writeAccepted = false;
    try {
      await request('/api/console/settings', { method: 'POST', expectedStatus: 200, body: JSON.stringify(body), headers: { 'Idempotency-Key': pending.key } });
      writeAccepted = true;
      return await reconcileSettings(pending);
    } catch (error) {
      if (error.definitive && !writeAccepted) persistPending(null);
      throw error;
    } finally {
      if (body.registration?.changes) for (const key of Object.keys(body.registration.changes)) delete body.registration.changes[key];
      state.busy = false; renderControls();
    }
  }
  async function mutate(url, body, { replay = false } = {}) {
    if (state.busy) throw new Error('正在提交操作，请稍候。');
    let pending = state.pending;
    if (pending && !replay) throw new Error('先核对上一条请求的结果，再开始新操作。');
    if (replay && !pending) throw new Error('当前没有待核对的请求。');
    if (!replay && writeBlock()) throw new Error(writeBlock());
    if (!pending) { pending = { version: 1, url, body, key: mutationKey(), createdAt: Date.now() }; persistPending(pending); }
    if (!pendingValid(pending) || Date.now() - pending.createdAt > MAX_REPLAY_AGE || pending.createdAt > Date.now() + 60000) throw new Error('待确认请求已超出安全核对时限或记录无效，请前往高级诊断核对后台任务；不会重新提交。');
    state.busy = true; renderControls();
    try {
      if (pending.url === '/api/console/settings') return await reconcileSettings(pending);
      const result = await request(pending.url, { method: 'POST', expectedStatus: 202, body: JSON.stringify(pending.body), headers: { 'Idempotency-Key': pending.key } });
      const stopRequest = /\/jobs\/[^/]+\/stop$/.test(pending.url);
      if (!/^job_[a-f0-9]{24}$/.test(String(result.jobId || '')) || (stopRequest ? !['stopping', 'succeeded', 'completed', 'failed', 'cancelled', 'canceled', 'interrupted', 'partial'].includes(result.status) : result.status !== 'queued')) throw new Error('任务回执不完整，结果尚未确认；请核对本次请求。');
      persistPending(null);
      notice(result.jobId ? '任务已交给服务器。你可以离开页面，回来后继续查看进度。' : '操作已完成。', 'success');
      await refresh();
      // Read-only progress view, never a browser-triggered follow-on mutation.
      if (!stopRequest) await openTaskDetail(result.jobId);
      return result;
    } catch (error) {
      if (error.definitive && !replay) persistPending(null);
      throw error;
    } finally { state.busy = false; renderControls(); }
  }
  function writeBlock() {
    if (state.storageError) return '会话存储不可用，已锁定写操作。';
    if (!state.connected || !state.overview) return '尚未连接服务，不能确认后台状态。';
    if (inventoryProblem()) return inventoryProblem();
    if (state.registrationReviewPending) return '注册人工对账回执尚未确认，请重新读取原任务核对；不会自动重发确认。';
    if (state.overview.reconciliation.total > 0) return '有 ' + state.overview.reconciliation.total + ' 个任务的外部结果尚未确认。请先查看相关任务并完成人工对账，期间禁止新写入。';
    if (state.overview.activeJobs.total > 0) return '后台仍有 ' + state.overview.activeJobs.total + ' 项活动任务，完成或停止后再提交新操作。';
    if (state.overview.readOnly) return '当前为只读模式，请在服务端启用写入后重试。';
    if (state.pending) return '上一条请求的结果尚未确认，请先核对。';
    if (state.busy) return '正在提交操作，请稍候。';
    return '';
  }
  function inventoryProblem() {
    if (!state.overview) return '尚未取得后台任务状态。';
    for (const key of ['reconciliation', 'activeJobs']) {
      const value = state.overview[key];
      if (!value || !Number.isSafeInteger(value.total) || value.total < 0 || !Number.isSafeInteger(value.returned)
          || value.returned < 0 || value.returned > value.total || typeof value.truncated !== 'boolean'
          || value.truncated !== (value.returned < value.total)) return '后台任务清单缺少完整性信息，已阻止新写入；请刷新或到高级诊断核对。';
      if (value.truncated) return '后台任务清单已被截断，尚不能确认全部执行与对账状态；已阻止新写入。';
    }
    if (Array.isArray(state.overview.jobs) && state.overview.jobs.filter((job) => ACTIVE.has(job.status)).length > state.overview.activeJobs.total) return '后台活动任务与计数不一致，已阻止新写入；请刷新核对。';
    return '';
  }
  function renderTaskSafety() {
    const problem = inventoryProblem();
    const holds = state.overview?.reconciliation?.total || 0;
    const active = state.overview?.activeJobs?.total || 0;
    const reviewPending = Boolean(state.registrationReviewPending);
    const show = Boolean(state.overview && (problem || holds || active || reviewPending));
    $('task-safety-banner').hidden = !show;
    if (!show) return;
    $('task-safety-banner').className = 'task-safety-banner' + (!problem && !holds ? ' running' : '');
    $('task-safety-title').textContent = problem ? '后台任务状态尚未核对完整' : reviewPending ? '注册人工对账回执待确认' : holds ? holds + ' 个任务需要人工对账' : '后台有 ' + active + ' 项活动任务';
    $('task-safety-message').textContent = problem ? problem + ' 查看状态、日志、连接检测和停止已知任务仍可使用。'
      : reviewPending ? '尚未确认原任务是否已解除阻挡。重新读取只核对服务端回执，不会自动提交或启动注册。'
      : holds ? '此前操作的外部结果尚不明确，服务端保留了安全阻挡，刷新或重新登录不会解除。同一注册流程可能包含主任务和执行步骤两条记录，不代表注册了两次。可在此核对注册任务；仍可停止已知任务和查看日志，其他类型请查看原任务详情。'
        : '任务在服务器上继续执行，暂不接受重复的新操作。点“查看相关任务”查看进度，需要终止时点击该任务的“停止”。';
    $('show-task-list').textContent = holds || reviewPending ? '查看并核对任务' : '查看相关任务';
  }
  function registrationReviewPendingValid(value) {
    return value?.version === 1 && JOB_ID.test(String(value.jobId)) && /^[a-f0-9]{64}$/.test(String(value.claimDigest))
      && /^[a-f0-9]{64}$/.test(String(value.contextDigest)) && Number.isSafeInteger(value.createdAt) && value.createdAt > 0;
  }
  function persistRegistrationReview(value) {
    const encoded = value ? JSON.stringify(value) : null;
    try {
      if (encoded === null) sessionStorage.removeItem(REVIEW_STORE); else sessionStorage.setItem(REVIEW_STORE, encoded);
      if (sessionStorage.getItem(REVIEW_STORE) !== encoded) throw new Error('persistence');
    } catch { state.storageError = true; throw new Error('无法保存人工对账回执，保持阻挡，未继续提交。'); }
    state.registrationReviewPending = value;
  }
  function registrationReviewValid(detail, id) {
    const context = detail?.targetContext, target = context?.targets?.[0];
    const checkedAt = Date.parse(target?.checkedAt), expiresAt = Date.parse(target?.expiresAt);
    return detail?.version === 1 && detail.id === id && ['registration', 'console_register'].includes(detail.type)
      && ['succeeded', 'partial', 'failed', 'interrupted'].includes(detail.status)
      && detail.reconciliationHold === true && detail.reconciliationResolved === false
      && /^[a-f0-9]{64}$/.test(String(detail.reconciliationClaimDigest)) && /^[a-f0-9]{64}$/.test(String(detail.reconciliationContextDigest))
      && context.available === true && context.coverage === 'exact_unknown_targets' && context.total === 1 && context.returned === 1 && context.truncated === false
      && Array.isArray(context.targets) && context.targets.length === 1 && target.kind === 'registration_manual_review'
      && JOB_ID.test(String(target.parentJobId)) && JOB_ID.test(String(target.childJobId)) && target.parentJobId !== target.childJobId
      && (detail.type === 'console_register' ? target.parentJobId === id : target.childJobId === id)
      && target.evidenceMode === 'manual_reconstructed' && /^[a-f0-9]{32}$/.test(String(target.evidenceId))
      && ['evidenceDigest', 'rootFingerprint', 'localStateDigest'].every(key => /^[a-f0-9]{64}$/.test(String(target[key])))
      && Number.isFinite(checkedAt) && Number.isFinite(expiresAt) && checkedAt <= Date.now() + 60000 && expiresAt > Date.now() && expiresAt > checkedAt
      && target.processScan === 'stopped' && target.originalRoot === 'manually_verified' && target.localRecords === 'reviewed_preserved'
      && target.remoteImport === 'not_reached' && target.smsOrder === 'terminal' && ['cancelled', 'completed', 'expired'].includes(target.smsStatus)
      && ['unknown', 'verified'].includes(target.smsSettlement);
  }
  function registrationReviewIssue() {
    if (!state.connected || !state.overview) return '尚未连接服务，保持阻挡。';
    if (state.storageError) return '会话回执无法保存，保持阻挡。';
    if (inventoryProblem()) return inventoryProblem();
    if (state.overview.readOnly !== false) return '当前只读模式，只能查看证据。';
    if (state.overview.activeJobs.total > 0) return '后台仍有活动任务，停止并核对后再确认。';
    if (state.busy || state.registrationReviewBusy || state.pending) return '另有请求正在处理或待确认，暂不提交对账。';
    if (!registrationReviewValid(state.registrationReview, state.registrationReviewJobId)) return '核对证据缺失、已过期或不完整，请重新读取；保持阻挡。';
    const pending = state.registrationReviewPending;
    if (pending && (pending.jobId !== state.registrationReview.id || pending.contextDigest !== state.registrationReview.reconciliationContextDigest
        || pending.claimDigest !== state.registrationReview.reconciliationClaimDigest)) return '原确认回执仍待核对，不能用变化后的证据覆盖旧请求。请核对原任务。';
    if (!$('registration-review-checked').checked) return '请先核对并勾选确认事项。';
    return '';
  }
  function renderRegistrationReviewControls() {
    const issue = registrationReviewIssue();
    $('registration-review-submit').disabled = Boolean(issue);
    $('registration-review-submit').title = issue;
    $('registration-review-hint').hidden = !state.registrationReview;
    $('registration-review-hint').textContent = issue || '仅确认当前这一条原任务；确认前服务端会再次复查证据与进程。';
    $('registration-review-submit').textContent = state.registrationReviewBusy ? '正在核对…' : state.registrationReviewPending ? '再次确认同一原任务' : '确认核对并解除阻挡';
    $('registration-review-refresh').disabled = state.registrationReviewBusy;
    $('registration-review-close').disabled = state.registrationReviewBusy;
    $('registration-review-checked').disabled = state.registrationReviewBusy || !registrationReviewValid(state.registrationReview, state.registrationReviewJobId);
    $('registration-review-dismiss').hidden = !state.registrationReviewOtherResolution;
    $('registration-review-dismiss').disabled = state.registrationReviewBusy || !state.connected || state.storageError;
  }
  function registrationResolvedElsewhere(job, pending) {
    const result = job?.result;
    return registrationReviewPendingValid(pending) && job?.id === pending.jobId && ['registration', 'console_register'].includes(job.type)
      && ['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status) && result?.reconciliationResolved === true
      && result.reconciliationHold === false && result.requiresReconciliation === false && result.futureOperationsUnblocked === true
      && result.retryAllowed === false && result.doNotRetry === true
      && result.reconciliationResolution === 'state_manually_reconciled' && result.reconciliationAcknowledgedBy === 'panel-admin'
      && result.reconciliationClaimDigest === pending.claimDigest && result.reconciliationBlockScope === 'none'
      && /^[a-f0-9]{64}$/.test(String(result.reconciliationReviewedContextDigest)) && result.reconciliationReviewedContextDigest !== pending.contextDigest;
  }
  async function dismissResolvedRegistrationReview() {
    const pending = state.registrationReviewPending, observed = state.registrationReviewOtherResolution;
    if (!pending || !observed || observed.jobId !== pending.jobId || state.registrationReviewBusy || !state.connected || state.storageError) throw new Error('原任务最终核对状态尚未确认，不能结束本地等待。');
    state.registrationReviewBusy = true; renderControls();
    try {
      const job = await request('/api/jobs/' + pending.jobId);
      if (!registrationResolvedElsewhere(job, pending) || job.result.reconciliationReviewedContextDigest !== observed.contextDigest
          || state.registrationReviewPending !== pending) throw new Error('原任务最终回执变化或不完整，保持本地阻挡，请重新读取。');
      if (!window.confirm('原任务 ' + pending.jobId + ' 已由另一次人工核对解除阻挡。\n这不代表上次丢失响应的请求成功。仅结束当前浏览器的本地等待，不重跑、不租号、不导入，也不再次发送解除请求。')) return;
      persistRegistrationReview(null); state.registrationReviewOtherResolution = null; state.registrationReview = null; state.registrationReviewJobId = null;
      $('registration-review-content').innerHTML = '<p class="muted">原任务已由另一次人工核对解除阻挡，已结束本地等待。未将上次丢失响应的请求记为成功，原任务也未重跑。</p>';
      reviewMessage('只清除了当前浏览器对旧确认的等待，没有发送解除请求；其他任务的阻挡仍保留。');
      await refresh();
    } catch (error) { state.registrationReviewOtherResolution = null; reviewMessage(errorText(error) + ' 本地回执仍保留，不会自动清除或重试。'); }
    finally { state.registrationReviewBusy = false; renderControls(); }
  }
  function reviewMessage(message) { $('registration-review-message').textContent = message; $('registration-review-message').hidden = !message; }
  function renderRegistrationReview(detail, job) {
    const target = detail.targetContext.targets[0];
    const checks = [
      ['进程与原运行目录', '进程已停止；管理员已核验原运行目录，服务端将在确认前再次复查。'],
      ['本地账号与产物', '已核对并保留本地记录。不会删除 token、账号或原任务，也不会把任务改为成功。'],
      ['远端导入', '原流程未到导入步骤；此次不会导入、重跑或租号。'],
      ['短信订单', '原订单已结束：' + ({ cancelled: '已取消', completed: '已完成', expired: '已过期' })[target.smsStatus] + '。' + (target.smsSettlement === 'verified' ? '费用记录已核对；不据此宣称退款。' : '费用结算仍未知；结束订单不代表已退款。')],
    ];
    $('registration-review-content').innerHTML = '<div class="detail-notice">同一注册流程的两条任务记录：主任务负责流程，执行步骤负责注册机。需分别确认；只解除当前这一条，其他阻挡仍保留。</div>'
      + detailRows([['当前确认', detail.type === 'console_register' ? '主任务' : '注册机执行步骤'], ['主任务 ID', target.parentJobId], ['执行步骤 ID', target.childJobId], ['原任务结果', STATUS_LABELS[detail.status] || '未知'], ['证据核验时间', date(target.checkedAt)], ['证据有效期至', date(target.expiresAt)]])
      + '<h3>原任务失败原因</h3><p class="detail-notice">' + escape(typeof job.error === 'string' ? job.error : job.error?.message || '原任务外部结果未能确认，请结合原任务日志核对。') + '</p>'
      + '<h3>已核验事项</h3><ul class="review-checks">' + checks.map(([label, text]) => '<li>' + tag('已核对', 'good') + '<div><strong>' + escape(label) + '</strong><p>' + escape(text) + '</p></div></li>').join('') + '</ul>';
    $('registration-review-confirmation').hidden = false;
  }
  async function openRegistrationReview(id = null) {
    if (state.registrationReviewBusy) return;
    if (id !== null && !JOB_ID.test(String(id))) throw new Error('人工对账任务 ID 无效。');
    const revision = ++state.registrationReviewRevision;
    state.registrationReview = null; state.registrationReviewJobId = id || state.registrationReviewPending?.jobId || null;
    state.registrationReviewOtherResolution = null;
    $('registration-review-checked').checked = false; $('registration-review-confirmation').hidden = true;
    $('registration-review-content').innerHTML = '<p class="muted">正在读取任务与核对证据…</p>'; reviewMessage('');
    if (!$('registration-review-dialog').open) $('registration-review-dialog').showModal();
    state.registrationReviewBusy = true; renderControls();
    try {
      const pending = state.registrationReviewPending;
      if (pending) {
        const job = await request('/api/jobs/' + pending.jobId);
        if (job?.id !== pending.jobId) throw new Error('原任务回执 ID 不一致，保持阻挡。');
        if (job.result?.reconciliationResolved === true && job.result?.reconciliationHold === false
            && job.result?.reconciliationReviewedContextDigest === pending.contextDigest) {
          persistRegistrationReview(null);
          state.registrationReviewJobId = null;
          reviewMessage('已从原任务确认上次对账成功。原任务未重跑；将继续显示其他仍待核对的任务。');
          await refresh();
        } else if (registrationResolvedElsewhere(job, pending)) {
          state.registrationReviewOtherResolution = { jobId: job.id, contextDigest: job.result.reconciliationReviewedContextDigest };
          $('registration-review-content').innerHTML = detailRows([['原任务 ID', job.id], ['原任务结果', STATUS_LABELS[job.status] || '未知']])
            + '<p class="detail-notice">原任务已由另一次人工核对解除阻挡，服务端明确禁止重跑。此回执不属于上次丢失响应的请求，不能把旧请求标记为成功。</p>';
          reviewMessage('旧本地回执仍保留。可明确选择“结束本地等待”；点击后将再次只读核验，不发送解除请求。');
          return;
        } else if (job.result?.reconciliationResolved === true) throw new Error('原任务的已确认回执与本次证据不一致，保持本地阻挡，请管理员核对。');
        else { state.registrationReviewJobId = pending.jobId; reviewMessage('上次确认结果仍待核对，不会自动重发。可再次读取原证据；仅在证据一致时，重新勾选后显式确认同一原任务。'); }
      }
      if (!state.registrationReviewJobId) {
        const list = await request('/api/jobs?limit=100');
        const inventory = list?.reconciliationHolds;
        if (!Array.isArray(list.jobs) || !inventory || !Number.isSafeInteger(inventory.total) || inventory.total < 0
            || inventory.returned !== inventory.total || inventory.truncated !== false) throw new Error('人工对账任务清单不完整，保持阻挡。');
        const held = list.jobs.filter(job => job.result?.reconciliationHold === true && job.result?.reconciliationResolved !== true);
        if (held.length !== inventory.total || new Set(held.map(job => job.id)).size !== held.length
            || held.some(job => !JOB_ID.test(String(job.id)))) throw new Error('人工对账任务与清单数量不一致，保持阻挡。');
        if (revision !== state.registrationReviewRevision) return;
        $('registration-review-content').innerHTML = held.length ? '<p class="muted">同一注册流程可能占两条任务记录，确认一条不会自动解除另一条。请选择原任务读取证据。</p>'
          + held.map(job => '<div class="child-job"><div><strong>' + escape(({ console_register: '注册流程主任务', registration: '注册机执行步骤' })[job.type] || '其他类型任务') + '</strong><p>' + escape(job.id) + '</p><p>' + escape(typeof job.error === 'string' ? job.error : job.error?.message || '原任务外部结果待核对') + '</p></div>'
            + (['registration', 'console_register'].includes(job.type) ? '<button type="button" class="button secondary" data-registration-review="' + escape(job.id) + '">读取核对证据</button>' : '<a class="text-button" href="/index.html">高级诊断</a>') + '</div>').join('')
          : '<p class="muted">当前没有待人工对账的任务。解除阻挡不会自动启动注册；需要时请另行提交新任务。</p>';
        return;
      }
      const detail = await request('/api/jobs/' + state.registrationReviewJobId + '/reconciliation');
      if (revision !== state.registrationReviewRevision) return;
      if (!registrationReviewValid(detail, state.registrationReviewJobId)) throw new Error('注册任务核对证据缺失、过期或不完整，保持阻挡。');
      const job = await request('/api/jobs/' + state.registrationReviewJobId);
      if (revision !== state.registrationReviewRevision) return;
      if (job?.id !== detail.id || job.type !== detail.type || job.status !== detail.status || job.result?.reconciliationHold !== true
          || job.result?.reconciliationResolved === true) throw new Error('原任务状态与核对证据已经变化，保持阻挡，请重新读取。');
      state.registrationReview = detail; renderRegistrationReview(detail, job);
    } catch (error) {
      if (revision !== state.registrationReviewRevision) return;
      $('registration-review-content').innerHTML = '<p class="muted">未能取得可确认的注册对账证据。不会自动解除或重新注册。</p>';
      reviewMessage(errorText(error));
    } finally { state.registrationReviewBusy = false; renderControls(); }
  }
  async function acknowledgeRegistrationReview() {
    const issue = registrationReviewIssue(); if (issue) throw new Error(issue);
    const detail = state.registrationReview;
    if (!window.confirm('仅解除原任务 ' + detail.id + ' 的阻挡？\n不会重跑、租号、导入，也不把失败改成成功；同一流程的其他任务仍需分别核对。')) return;
    const pending = state.registrationReviewPending || { version: 1, jobId: detail.id, claimDigest: detail.reconciliationClaimDigest, contextDigest: detail.reconciliationContextDigest, createdAt: Date.now() };
    persistRegistrationReview(pending); state.registrationReviewBusy = true; $('registration-review-checked').checked = false; renderControls();
    let accepted = false;
    try {
      await request('/api/jobs/' + pending.jobId + '/reconciliation/acknowledge', { method: 'POST', expectedStatus: 200,
        body: JSON.stringify({ jobId: pending.jobId, confirmation: '我已按强身份完成人工核对', resolution: 'state_manually_reconciled', claimDigest: pending.claimDigest, contextDigest: pending.contextDigest }) });
      accepted = true;
      // A successful HTTP response alone is not proof. Read the durable exact-context receipt.
      const job = await request('/api/jobs/' + pending.jobId);
      if (job?.id !== pending.jobId || job.result?.reconciliationResolved !== true || job.result?.reconciliationHold !== false
          || job.result?.reconciliationReviewedContextDigest !== pending.contextDigest) throw new Error('人工对账回执无法确认，保持本地阻挡；请重新读取原任务，勿新建注册。');
      persistRegistrationReview(null); state.registrationReview = null; state.registrationReviewJobId = null;
      $('registration-review-content').innerHTML = '<p class="muted">已确认当前任务解除阻挡，原失败结果和产物保持不变。重新读取可查看其余任务。</p>';
      $('registration-review-confirmation').hidden = true; reviewMessage('当前任务已核对。没有重跑、租号或导入；其他任务的阻挡不会被自动清除。'); await refresh();
    } catch (error) {
      state.registrationReview = null;
      const rejectedBeforeRelease = !accepted && error.status === 409 && error.writeOutcomeUnknown !== true && [
        'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE', 'JOB_RECONCILIATION_CONTEXT_INCOMPLETE', 'JOB_RECONCILIATION_CONTEXT_DIGEST_MISMATCH',
        'JOB_RECONCILIATION_TARGET_MISMATCH', 'JOB_RECONCILIATION_RESOLUTION_REQUIRES_MANUAL_RECONCILIATION', 'JOB_RECONCILIATION_DIGEST_MISMATCH',
      ].includes(error.code);
      if (rejectedBeforeRelease) {
        // These exact server conflicts are guaranteed to occur before release.
        // The durable server hold stays; discard only this rejected UI receipt.
        persistRegistrationReview(null);
        reviewMessage(errorText(error) + ' 服务端已在解除前拒绝，原阻挡保留。请重新读取并核验最新证据，再明确确认；不会自动提交。');
      } else reviewMessage(errorText(error) + ' 未确认解除结果，保持阻挡。请重新读取原任务；不会自动重发确认。');
    } finally { state.registrationReviewBusy = false; renderControls(); }
  }
  async function stopJob(jobId) {
    if (!/^job_[a-f0-9]{24}$/.test(String(jobId))) throw new Error('待停止任务 ID 无效。');
    if (state.stoppingJobs.has(jobId)) return;
    if (!state.overview?.jobs?.some((job) => job.id === jobId)) throw new Error('该任务不在已读取的清单中，请刷新后核对原任务。');
    state.stoppingJobs.add(jobId); renderControls();
    try {
      // The server makes stop idempotent by exact parent task ID. Do not use
      // or erase a pending register/import/settings receipt to request a stop.
      const result = await request('/api/console/jobs/' + encodeURIComponent(jobId) + '/stop', { method: 'POST', expectedStatus: 202, body: '{}', headers: { 'Idempotency-Key': mutationKey() } });
      if (result.jobId !== jobId || !['stopping', 'succeeded', 'completed', 'failed', 'cancelled', 'canceled', 'interrupted', 'partial'].includes(result.status)) throw new Error('停止回执无法确认。请刷新任务；再次停止仍只针对同一个任务 ID。');
      notice(result.status === 'stopping' ? '已请求停止该任务，正在结束当前步骤并核对结果。不会回滚已完成的操作。' : '该任务已经结束，无需再次停止。', 'success');
      await refresh();
    } catch (error) { throw new Error(errorText(error) + ' 可重新核对或停止同一个任务；不会新建注册任务。'); }
    finally { state.stoppingJobs.delete(jobId); renderControls(); }
  }
  function classification(account) { return CLASSIFICATION[account.classification] || ['需要核对', 'unknown', '人工核对']; }
  function accounts() { return Array.isArray(state.overview?.accounts) ? state.overview.accounts : []; }
  function filteredAccounts() {
    const query = $('account-search').value.toLowerCase();
    const filter = $('account-filter').value;
    const groups = { healthy: ['healthy', 'active'], new: ['new', 'never_imported'], refresh: ['refresh', 'refresh_needed', 'invalid', 'auth_invalid', 'expired'], verify: ['pending_verification'], quota: ['quota', 'quota_wait', 'rate_limited'], banned: ['banned', 'confirmed_banned'], review: ['review', 'needs_review', 'network_unknown', 'disabled', 'manual_disabled'] };
    return accounts().filter((account) => (filter === 'all' || groups[filter]?.includes(account.classification)) && (!query || [account.name, account.email, account.id].join(' ').toLowerCase().includes(query)));
  }
  function selectable(account) { return Number.isSafeInteger(account.id) && account.id > 0; }
  function continuationIssue(item) {
    const blocked = writeBlock();
    if (blocked) return blocked;
    const capabilities = state.overview?.capabilities || {};
    if (capabilities.comparisonAvailable === false) return '账号快照不完整，请先检测 Sub2API 连接。';
    if (!capabilities.registrationEnabled) return '账号续跑功能未启用，请检查服务端配置。';
    if (!capabilities.phase3Enabled) return '本地 Phase3 未启用，请检查服务端配置。';
    if (state.networkBusy) return '网络预检正在执行，请等待检测完成后再继续。';
    if (item?.eligible !== true) return item?.reason || '该记录尚未通过身份核验，不能继续。';
    const registration = state.overview?.settings?.registration;
    if (item.stage === 'phase3') {
      if (registration?.phase3Ready === true) return '';
      if (registration?.phase3Ready !== false) return '服务端尚未确认 Phase3 配置状态，请刷新后重试。';
      const issues = Array.isArray(registration.phase3Issues) ? registration.phase3Issues.filter((issue) => typeof issue === 'string').join('；') : '';
      return 'Phase3 配置不完整：' + (issues || '请到设置与检测补齐邮箱和 OAuth 配置') + '。';
    }
    if (item.stage !== 'phase2') return '续跑阶段无法确认，请刷新后重新选择。';
    return registration?.ready === true ? '' : '注册配置不完整，请到设置与检测查看原因。';
  }
  function proxySettingValid(value) {
    return value && Number.isSafeInteger(value.revision) && value.revision >= 0
      && (value.proxyId === null || Number.isSafeInteger(value.proxyId) && value.proxyId > 0)
      && value.configured === (value.proxyId !== null) && typeof value.endpointMatches === 'boolean';
  }
  function proxySaveIssue() {
    const blocked = writeBlock(); if (blocked) return blocked;
    if (state.proxyLoading) return '正在读取代理节点，请稍候。';
    if (state.proxyListError) return state.proxyListError;
    if (!state.proxyList || !Number.isSafeInteger(state.proxyRevision)) return '请先刷新节点列表，再选择默认代理。';
    const value = $('import-proxy-select').value;
    if (value === 'none') return '';
    const selected = state.proxyList.items.find((item) => String(item.id) === value);
    if (!selected) return '所选节点不在最新清单中，请重新选择；不会自动改为直连。';
    if (selected.eligible !== true || typeof selected.revision !== 'string' || !selected.revision) return selected.reason || '所选节点不可用于新增账号，请重新选择。';
    return '';
  }
  function defaultProxyIssue() {
    const setting = state.overview?.settings?.importProxy;
    if (!proxySettingValid(setting)) return '';
    if (setting.proxyId !== null && !setting.endpointMatches) return '默认代理属于另一 Sub2API 实例，请在设置中重新选择；不会自动直连。';
    if (setting.proxyId !== null && state.proxyList && !state.proxyListError) {
      const selected = state.proxyList.items.find((item) => item.id === setting.proxyId);
      if (!selected || selected.eligible !== true) return '默认代理已不可用，请在设置中重新选择；不会自动直连。';
    }
    return '';
  }
  function renderProxySetting() {
    const setting = state.overview?.settings?.importProxy;
    if (!proxySettingValid(setting)) { $('register-import-proxy').textContent = '默认导入代理：设置尚未确认'; return; }
    if (!state.proxyDirty) state.proxySettingsRevision = setting.revision;
    const selected = state.proxyList?.items?.find((item) => item.id === setting.proxyId);
    $('register-import-proxy').textContent = !setting.configured ? '新账号导入：未指定代理，沿用 Sub2API 网络配置'
      : defaultProxyIssue() || '新账号导入代理：' + (selected?.name || '节点 #' + setting.proxyId) + ' · 已有账号保持原代理';
  }
  async function loadProxies() {
    if (state.proxyLoading || !state.connected) return;
    state.proxyLoading = true; state.proxyLoadAttempted = true; state.proxyListError = ''; renderControls();
    const previous = state.proxyDirty ? $('import-proxy-select').value : null;
    try {
      const result = await request('/api/console/proxies');
      if (!Number.isSafeInteger(result.revision) || result.revision < 0 || !Array.isArray(result.items)
          || result.items.some((item) => !Number.isSafeInteger(item.id) || item.id <= 0 || typeof item.name !== 'string' || typeof item.eligible !== 'boolean')
          || new Set(result.items.map((item) => item.id)).size !== result.items.length
          || !(result.selectedProxyId === null || Number.isSafeInteger(result.selectedProxyId) && result.selectedProxyId > 0)) throw new Error('代理节点清单不完整，未允许保存。');
      state.proxyList = result; state.proxyRevision = result.revision;
      const value = previous ?? (result.selectedProxyId === null ? 'none' : String(result.selectedProxyId));
      const missing = value !== 'none' && !result.items.some((item) => String(item.id) === value);
      $('import-proxy-select').innerHTML = '<option value="none">未指定（沿用 Sub2API 网络配置）</option>'
        + (missing ? '<option value="' + escape(value) + '" disabled>所选节点 #' + escape(value) + ' 已不可用，请重新选择</option>' : '')
        + result.items.map((item) => '<option value="' + item.id + '"' + (item.eligible ? '' : ' disabled') + '>' + escape(item.name + ' · #' + item.id + (item.protocol ? ' · ' + item.protocol : '') + (!item.eligible ? ' · ' + (item.reason || '不可用') : '')) + '</option>').join('');
      $('import-proxy-select').value = value;
      renderProxySetting();
    } catch (error) { state.proxyListError = '代理列表读取失败：' + errorText(error) + ' 请刷新后重试，当前默认设置未改变。'; }
    finally { state.proxyLoading = false; renderControls(); }
  }
  async function saveImportProxy() {
    const issue = proxySaveIssue(); if (issue) throw new Error(issue);
    const value = $('import-proxy-select').value;
    const selected = value === 'none' ? null : state.proxyList.items.find((item) => String(item.id) === value);
    if (!window.confirm(selected ? '将新增账号的默认导入代理设为 ' + selected.name + '（#' + selected.id + '）？\n仅影响新增账号；已有账号回写 token 保留原代理，注册机网络通道不变。'
      : '确定不为新增账号指定代理？\n新增账号沿用 Sub2API 网络配置。已有账号的代理与注册机网络配置不变。')) return;
    await saveSettings({ confirm: true, importProxy: { revision: state.proxyRevision, proxyId: selected?.id ?? null, ...(selected ? { proxyRevision: selected.revision } : {}) } });
    await loadProxies();
  }
  function renderControls() {
    const blocked = writeBlock();
    const capabilities = state.overview?.capabilities || {};
    const comparisonIssue = capabilities.comparisonAvailable === false ? '账号快照不完整，请先检测 Sub2API 连接。' : '';
    const registrationIssue = blocked || comparisonIssue || defaultProxyIssue() || (state.networkBusy ? '网络预检正在执行，通常需要数十秒；完成后即可启动注册。' : '') || (!capabilities.registrationEnabled ? '注册功能未启用，请检查服务端配置。' : '') || (state.overview?.settings?.registration?.ready === false ? '注册配置不完整，请到设置与检测查看原因。' : '');
    $('start-register').disabled = Boolean(registrationIssue);
    $('register-hint').textContent = registrationIssue || '将按现有接码与邮箱配置执行；成功后自动首次导入。';
    $('maintain-all').disabled = Boolean(blocked || comparisonIssue || defaultProxyIssue() || !capabilities.sub2apiConfigured);
    $('maintain-selected').disabled = Boolean(blocked || comparisonIssue || !capabilities.sub2apiConfigured || state.selected.size === 0);
    $('selected-count').textContent = state.selected.size;
    $('maintain-hint').textContent = blocked || comparisonIssue || (!capabilities.sub2apiConfigured ? '尚未配置 Sub2API 管理连接。' : '一键维护检查全池并导入新账号；维护所选只处理选中的远端 ID，不导入范围外的账号。');
    const accountIssue = blocked || comparisonIssue || (!capabilities.sub2apiConfigured ? '尚未配置 Sub2API 管理连接。' : '');
    $('import-new').disabled = Boolean(accountIssue || defaultProxyIssue());
    $('import-new').title = accountIssue || defaultProxyIssue();
    $('test-selected').disabled = Boolean(accountIssue || !state.selected.size || state.selected.size > 100);
    $('test-selected-hint').textContent = accountIssue || (state.selected.size > 100 ? '单次最多测试 100 个账号，请缩小选择范围。' : state.selected.size ? '仅测试所选 ' + state.selected.size + ' 个远端账号；不会重新注册或获取 token。' : '先选择远端账号；不会重新注册或获取 token。');
    $('local-token-refresh').disabled = !state.connected || state.localTokensBusy;
    $('local-token-update').disabled = Boolean(accountIssue || state.localTokensBusy || !state.localSelected.size || state.localSelected.size > 100);
    $('local-token-hint').textContent = accountIssue || (state.localSelected.size ? '已核对 ' + state.localSelected.size + ' 项。只回写表中原 ID，随后测试；不租号、不重新登录、不新增账号。' : '请逐项核对原账号 ID、强身份与 token 版本，再勾选需要回写的记录。');
    $('settings-save').disabled = Boolean(blocked || !state.overview?.settings);
    $('registration-settings-save').disabled = Boolean(blocked || !state.overview?.settings?.registration?.revision);
    $('settings-hint').textContent = blocked;
    $('logs-cleanup').disabled = Boolean(blocked);
    $('check-network').disabled = state.networkBusy || !state.connected;
    $('settings-check-network').disabled = state.networkBusy || !state.connected;
    $('check-network').textContent = state.networkBusy ? '检测中…' : '检测连接';
    $('settings-check-network').textContent = state.networkBusy ? '检测中…' : '检测连接';
    const proxyIssue = proxySaveIssue();
    $('import-proxy-refresh').disabled = state.proxyLoading || !state.connected;
    $('import-proxy-refresh').textContent = state.proxyLoading ? '读取中…' : '刷新节点';
    $('import-proxy-select').disabled = state.proxyLoading || !state.proxyList || Boolean(blocked);
    $('import-proxy-save').disabled = Boolean(proxyIssue);
    $('import-proxy-save').title = proxyIssue;
    $('import-proxy-hint').textContent = proxyIssue || '保存后仅影响新增账号；已有账号的代理保持不变。';
    $('resolve-pending').disabled = state.busy || !state.connected || state.storageError;
    $('pending-banner').hidden = !state.pending && !state.storageError;
    $('mode-label').textContent = !state.connected ? '服务未连接' : state.overview?.readOnly ? '只读模式' : state.overview?.settings?.policy?.enabled ? '自动巡检开启' : '手动控制';
    document.querySelectorAll('[data-stop-job]').forEach((button) => { button.disabled = state.stoppingJobs.has(button.dataset.stopJob); });
    document.querySelectorAll('[data-resume-index]').forEach((button) => {
      const index = Number(button.dataset.resumeIndex), item = state.continuations[index], issue = continuationIssue(item);
      button.disabled = Boolean(issue); button.title = issue;
      const hint = $('continuation-hint-' + index);
      if (hint) hint.textContent = issue || (item.stage === 'phase3' ? '无需短信配置；启动前仅检测邮箱和 OAuth 通道，不重新租号。' : '沿用现有账号继续；启动前检查完整注册配置，不重新租号。');
    });
    renderTaskSafety();
    renderRegistrationReviewControls();
  }
  function renderMetrics() {
    const summary = state.overview?.summary || {};
    $('metric-total').textContent = number(summary.total);
    $('metric-healthy').textContent = number(summary.healthy);
    $('metric-attention').textContent = number(summary.refreshNeeded !== undefined && summary.needsReview !== undefined && summary.banned !== undefined ? summary.refreshNeeded + summary.needsReview + summary.banned + (Number.isFinite(summary.pendingVerification) ? summary.pendingVerification : 0) : undefined);
    $('metric-new').textContent = number(summary.neverImported);
  }
  function renderAccounts() {
    const all = accounts();
    const validIds = new Set(all.filter(selectable).map((account) => account.id));
    for (const id of state.selected) if (!validIds.has(id)) state.selected.delete(id);
    const rows = filteredAccounts();
    $('account-rows').innerHTML = rows.length ? rows.map((account) => {
      const [label, tone, next] = classification(account);
      const selected = state.selected.has(account.id);
      const id = selectable(account) ? account.id : '';
      return '<tr' + (selected ? ' class="selected"' : '') + '><td class="checkbox-cell"><input type="checkbox" data-account-id="' + id + '" aria-label="选择 ' + escape(account.name || '本地账号') + '"' + (selected ? ' checked' : '') + (!id ? ' disabled title="本地新账号由首次导入处理"' : '') + '></td><td><span class="account-name">' + escape(account.name || '本地待导入') + '</span><span class="account-email">' + escape(account.email || '未提供邮箱') + '</span></td><td>' + tag(label, tone) + '</td><td>' + escape(account.actionLabel || ACTION_LABELS[account.action] || next) + '</td><td>' + escape(date(account.lastProcessedAt)) + '</td><td><button type="button" class="text-button" data-account-detail="' + all.indexOf(account) + '">' + (id ? '#' + id + ' · 详情' : '本地详情') + '</button></td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty-cell">' + (all.length ? '没有符合筛选条件的账号' : '暂无账号记录；可以先注册或检查 Sub2API 连接') + '</td></tr>';
    const visible = rows.filter(selectable);
    const selected = visible.filter((account) => state.selected.has(account.id)).length;
    $('select-all').checked = visible.length > 0 && selected === visible.length;
    $('select-all').indeterminate = selected > 0 && selected < visible.length;
    $('select-all').disabled = visible.length === 0;
    $('account-count').textContent = '显示 ' + rows.length + ' / ' + all.length + ' 个账号 · 已选 ' + state.selected.size;
    renderControls();
  }
  function taskPresentation(job) {
    const summary = job.summary && typeof job.summary === 'object' ? job.summary : {};
    const noActivity = ['registered', 'imported', 'refreshed', 'deleted', 'tokensGenerated', 'tokensUpdated', 'tested', 'verified', 'testFailed']
      .every(key => summary[key] === 0);
    const noChanges = /maintain/.test(job.type) && ['succeeded', 'completed'].includes(job.status)
      && (summary.skipped > 0 || job.stage === 'no_changes') && summary.failed === 0 && noActivity;
    const allSkipped = noChanges && summary.skipped > 0;
    const running = ACTIVE.has(job.status);
    return { noChanges, allSkipped, running,
      label: allSkipped ? '全部跳过' : noChanges ? '未执行' : STATUS_LABELS[job.status] || '未知',
      tone: noChanges || running ? 'neutral' : ['succeeded', 'completed'].includes(job.status) ? 'good' : job.status === 'failed' ? 'bad' : 'unknown',
      stage: noChanges ? '本次未执行账号操作' : STAGES[job.stage] || job.stage || '等待任务报告' };
  }
  function taskCounters(job, detail = false) {
    const summary = job.summary && typeof job.summary === 'object' ? job.summary : {};
    const rows = [['registered', '注册成功'], ['tokensGenerated', '生成 token'], ['imported', detail ? '首次导入' : '导入'],
      ['tokensUpdated', detail ? '回写原账号' : '回写'], ['tested', '已提交测试'], ['verified', '测试通过'], ['testFailed', '测试未通过'],
      ['deleted', detail ? '删除记录' : '删除'], ['skipped', detail ? '跳过账号' : '跳过'],
      ['failed', /maintain/.test(job.type) ? '未完成流程' : '账号步骤失败'], ['removed', '清理文件']];
    if (summary.tokensUpdated === undefined) rows.push(['refreshed', '刷新完成']);
    // Keep a zero when it describes an attempted chain, not eight empty
    // counters for a task which never performed an account operation.
    return rows.filter(([key]) => Number.isFinite(summary[key]) && (summary[key] > 0
      || key === 'imported' && summary.registered > 0
      || key === 'tokensUpdated' && summary.tokensGenerated > 0
      || ['verified', 'testFailed'].includes(key) && summary.tested > 0))
      .map(([key, label]) => [label, summary[key]]);
  }
  function taskResultNote(job) {
    const presentation = taskPresentation(job);
    if (presentation.noChanges) return '本次未执行账号操作。' + (presentation.allSkipped ? '跳过原因见逐账号结果。' : '没有符合当前维护条件的账号。');
    const summary = job.summary || {};
    const items = Array.isArray(job.items) ? job.items : [];
    const pending = items.filter(item => item.status === 'failed' && item.phases?.tokenUpdated === true && item.phases?.tested === false).length;
    const notGenerated = items.filter(item => item.status === 'failed' && item.phases?.tokenGenerated === false && item.phases?.tokenUpdated === false).length;
    if (pending && pending + notGenerated === summary.failed) {
      return pending + ' 个已回写，待测试' + (notGenerated ? '；' + notGenerated + ' 个未生成 token' : '') + '。已回写的账号无需重新获取 token。';
    }
    if (summary.tokensUpdated > 0 && summary.tested === 0) {
      return summary.tokensUpdated + ' 个账号的 token 已回写，测试尚未开始；无需重新获取 token。';
    }
    return '';
  }
  function renderJobs() {
    const jobs = Array.isArray(state.overview?.jobs) ? state.overview.jobs : [];
    $('job-count').textContent = jobs.filter((job) => ACTIVE.has(job.status)).length + ' 个进行中';
    $('jobs').innerHTML = jobs.length ? jobs.slice(0, 20).map((job) => {
      const presentation = taskPresentation(job), running = presentation.running;
      const label = /resume/.test(job.type) ? '继续已有账号' : /register/.test(job.type) ? '注册任务' : /maintain|maintenance/.test(job.type) ? '账号维护' : /log_cleanup/.test(job.type) ? '日志清理' : '后台任务';
      const tone = presentation.tone;
      const progress = job.progress && Number.isFinite(job.progress.completed) && Number.isFinite(job.progress.total) ? ' · ' + job.progress.completed + ' / ' + job.progress.total : '';
      const counts = taskCounters(job).map(([label, value]) => label + ' ' + value).join(' · ');
      const stages = { queued: '等待调度', starting: '准备执行', planning: '核对账号与维护范围', checking_network: '检查网络通道', preflight: '连接预检', network_preflight: '连接预检',
        registering: '正在注册', init: '初始化注册流程', phase1_register: '手机号注册与短信验证', phase1_register_recovery: '恢复已有手机号注册',
        phase1_5_profile: '完成账号个人资料', phase2_bind_email: '绑定邮箱', phase2_resume: '继续邮箱绑定', phase3_email_oauth: '邮箱验证并获取 token',
        importing: '导入 Sub2API', importing_new: '导入从未加入的账号', maintenance: '正在维护', maintaining: '继续处理账号',
        refreshing: '本地重新授权', updating_token: '核验身份并回写原账号', verifying_account: '测试账号及恢复调度', removing_banned: '复核并删除确认封禁的记录',
        completed: '处理完成', stopped: '已停止', failed: '执行失败' };
      const description = typeof job.summary === 'string' ? job.summary : [presentation.stage, counts].filter(Boolean).join(' · ');
      const errorMessage = typeof job.error === 'string' ? job.error : typeof job.error?.message === 'string' ? job.error.message : '';
      const failureStage = typeof job.failureStage === 'string' && job.failureStage ? stages[job.failureStage] || '执行步骤' : '';
      const recovery = typeof job.recoveryMessage === 'string' ? job.recoveryMessage : '';
      const resultNote = taskResultNote(job);
      const details = (resultNote ? '<p class="job-detail">' + escape(resultNote) + '</p>' : '')
        + (failureStage ? '<p class="job-detail"><strong>失败阶段：</strong>' + escape(failureStage) + '</p>' : '')
        + (errorMessage ? '<p class="job-detail"><strong>失败原因：</strong>' + escape(errorMessage) + '</p>' : '')
        + (recovery ? '<p class="job-detail"><strong>后续处理：</strong>' + escape(recovery) + '</p>' : '');
      const symbol = icon(running ? 'refresh' : presentation.noChanges ? 'minus' : ['succeeded', 'completed'].includes(job.status) ? 'check' : ['failed', 'partial'].includes(job.status) ? 'alert' : 'minus');
      return '<div class="job-row"><span class="job-symbol" aria-hidden="true">' + symbol + '</span><div><p class="job-title">' + label + escape(progress) + '</p><p class="job-detail">' + escape(description) + '</p>' + details + '</div><div class="job-status">' + tag(presentation.label, tone) + '<span class="job-date">' + date(job.createdAt) + '</span></div><div class="job-actions"><button type="button" class="text-button" data-job-detail="' + escape(job.id) + '">详情</button><button type="button" class="text-button" data-job-logs="' + escape(job.id) + '">日志</button>' + (running ? '<button type="button" class="text-button" data-stop-job="' + escape(job.id) + '">停止</button>' : '') + '</div></div>';
    }).join('') : '<div class="empty-state">还没有任务。<br>开始一次注册，或到账号维护检查现有账号。</div>';
    $('account-jobs').innerHTML = $('jobs').innerHTML;
  }
  function detailRows(rows) { return '<dl class="detail-list">' + rows.map(([label, value]) => '<div><dt>' + escape(label) + '</dt><dd>' + escape(value ?? '—') + '</dd></div>').join('') + '</dl>'; }
  function taskProjection(job) {
    const result = job.result && typeof job.result === 'object' ? job.result : {};
    return { ...job, status: job.status === 'queued' && result.startedAt ? 'running' : job.status,
      stage: result.stage || job.stage, summary: result.summary || job.summary || {}, items: result.items || job.items || [],
      failureStage: result.failureStage || job.failureStage, recoveryMessage: result.recoveryMessage || job.recoveryMessage };
  }
  function failureDescription(item) {
    const categories = { network: '连接 / 代理问题', model_unavailable: '模型不可用', quota: '额度不足', rate_limited: '请求限流', authentication: '认证失败', account_status: '账号状态异常', upstream: '上游服务异常', unknown: '原因尚未确定' };
    return [categories[item.failureCategory], Number.isSafeInteger(item.upstreamStatus) && item.upstreamStatus >= 400 && item.upstreamStatus <= 599 ? 'HTTP ' + item.upstreamStatus : '', typeof item.message === 'string' ? item.message : ''].filter(Boolean).join(' · ');
  }
  function renderTaskAccount(item) {
    const phases = item.phases || {};
    const skipped = item.status === 'skipped';
    const pending = phases.tokenUpdated === true && phases.tested === false;
    const generatedOnly = phases.tokenGenerated === true && phases.tokenUpdated === false;
    const successfulSteps = [['tokenGenerated', '已生成 token'], ['tokenUpdated', '已回写原账号'], ['tested', '已提交测试'], ['verified', '测试通过']]
      .filter(([key]) => phases[key] === true).map(([, label]) => label).join(' · ');
    const label = skipped ? '已跳过' : phases.verified === true ? '测试通过' : pending ? '已回写，待测试'
      : generatedOnly ? '已生成，未回写' : item.status === 'failed' ? '本次失败' : '处理结果';
    const reasonCode = [item.reasonCode, item.code, item.message].find(code => typeof code === 'string' && Object.hasOwn(REASONS, code));
    let reason = reasonCode ? REASONS[reasonCode] : failureDescription(item) || item.reason || '';
    if (skipped && reasonCode === 'administrator_unscheduled') reason = '当时检测到调度关闭，本次未执行测试或修改调度。';
    if (skipped && /手动停用.*额度等待.*需核对/.test(reason)) reason = '本次未执行测试或修改调度；旧任务未记录具体跳过原因。';
    if (pending && item.code === 'CONSOLE_TEST_TARGET_CHANGED') reason = '测试前账号状态检查未通过，本次没有发送测试；已回写的 token 保留。';
    const currentPending = skipped && accounts().some(account => account.id === item.accountId && account.classification === 'pending_verification');
    const followup = pending ? '无需重新获取 token。再次维护会检查已回写结果，继续测试及恢复调度。'
      : currentPending ? '当前已识别为待测试恢复；再次维护可继续使用已回写的 token。' : '';
    const canSelectTest = !skipped && !generatedOnly && Number.isSafeInteger(item.accountId) && item.accountId > 0
      && (phases.tokenUpdated === true || phases.tested === true);
    return '<div class="task-account-result"><div class="task-account-heading"><strong>' + escape(item.accountName || (Number.isSafeInteger(item.accountId) ? '远端 #' + item.accountId : '本地账号')) + '</strong>'
      + tag(label, skipped ? 'neutral' : phases.verified === true ? 'good' : 'warn') + '</div>'
      + '<p>' + escape(skipped ? '本次未执行账号操作' : successfulSteps || (phases.tokenGenerated === false ? '未生成新 token' : '尚无已完成步骤')) + '</p>'
      + (reason ? '<p>' + escape(reason) + '</p>' : '') + (followup ? '<p>' + escape(followup) + '</p>' : '')
      + (canSelectTest ? '<button type="button" class="text-button" data-select-result-account="' + item.accountId + '">选中此账号，继续测试</button>' : '') + '</div>';
  }
  function renderTaskDetail() {
    const detail = state.taskDetail;
    if (!detail) return;
    const job = taskProjection(detail.job);
    $('task-dialog-title').textContent = /resume/.test(job.type) ? '已有账号续跑详情' : /register/.test(job.type) ? '注册任务详情' : /maintain/.test(job.type) ? '账号处理详情' : '任务详情';
    $('task-dialog-subtitle').textContent = job.id + ' · ' + date(job.createdAt);
    const error = typeof job.error === 'string' ? job.error : job.error?.message;
    const counters = taskCounters(job, true);
    const presentation = taskPresentation(job), resultNote = taskResultNote(job);
    const items = Array.isArray(job.items) ? job.items.slice(-100) : [];
    $('task-detail').innerHTML = '<div class="detail-status">' + tag(presentation.label, presentation.tone) + '<span>' + escape(presentation.stage) + '</span></div>'
      + (counters.length ? '<div class="step-grid' + (counters.length === 1 ? ' single-step' : '') + '">' + counters.map(([label, value]) => '<div><span>' + escape(label) + '</span><strong>' + number(value) + '</strong></div>').join('') + '</div>' : '<p class="muted">该任务尚未报告阶段成果，未报告不代表已完成。</p>')
      + (resultNote ? '<div class="detail-notice">' + escape(resultNote) + '</div>' : '')
      + (job.failureStage || error || job.recoveryMessage ? '<div class="detail-notice">' + (job.failureStage ? '<p><strong>未完成阶段：</strong>' + escape(STAGES[job.failureStage] || '执行步骤') + '</p>' : '') + (error ? '<p><strong>失败原因：</strong>' + escape(error) + '</p>' : '') + (job.recoveryMessage ? '<p>' + escape(job.recoveryMessage) + '</p>' : '') + '</div>' : '')
      + (items.length ? '<h3>逐账号结果</h3>' + items.map(renderTaskAccount).join('') : '')
      + (detail.children.length ? '<h3>关联执行步骤</h3>' + detail.children.map((child) => '<div class="child-job"><div><strong>' + escape(({ registration: '注册机执行', registration_resume: '已有账号续跑', phase3: '获取 token', token_import: '导入 / 回写', import: '导入 / 回写', account_test: '账号可用性测试', account_delete: '删除已确认封禁记录' })[child.type] || '后台执行步骤') + '</strong><p>' + escape(child.id) + '</p><p>' + escape(typeof child.error === 'string' ? child.error : child.error?.message || '') + '</p></div>' + tag(STATUS_LABELS[child.status] || '未知') + '<button type="button" class="text-button" data-job-logs="' + escape(child.id) + '">步骤日志</button></div>').join('') : '')
      + (detail.childNotice ? '<p class="muted small-copy">' + escape(detail.childNotice) + '</p>' : '');
    $('task-detail-actions').innerHTML = '<button type="button" class="button secondary" data-task-refresh="' + escape(job.id) + '">刷新详情</button><button type="button" class="button secondary" data-job-logs="' + escape(job.id) + '">查看日志</button>'
      + (/register|resume|maintain/.test(job.type) ? '<button type="button" class="button secondary" data-view-local-tokens>查看本地 token</button><button type="button" class="button secondary" data-view-continuations>查看可续跑账号</button>' : '')
      + (ACTIVE.has(job.status) && state.overview?.jobs?.some((item) => item.id === job.id) ? '<button type="button" class="button danger-outline" data-stop-job="' + escape(job.id) + '">停止任务</button>' : '');
    renderControls();
  }
  async function openTaskDetail(id, { quiet = false } = {}) {
    if (!JOB_ID.test(String(id))) { notice('任务 ID 无效，请刷新任务列表后重试。', 'error'); return; }
    const revision = ++state.taskDetailRevision;
    if (!quiet) { state.taskDetail = null; $('task-detail').innerHTML = '<p class="muted">正在读取任务与已完成步骤…</p>'; $('task-detail-actions').innerHTML = ''; $('task-dialog-title').textContent = '任务详情'; $('task-dialog-subtitle').textContent = id; if (!$('task-dialog').open) $('task-dialog').showModal(); }
    try {
      const job = await request('/api/jobs/' + encodeURIComponent(id));
      if (job?.id !== id) throw new Error('任务详情与请求 ID 不一致，未采用该响应。');
      const childIds = [...new Set((Array.isArray(job.result?.childJobIds) ? job.result.childJobIds : []).filter((value) => JOB_ID.test(String(value)) && value !== id))];
      let missing = 0;
      // Reads are bounded and parent-linked. A child response never causes a write.
      const children = (await Promise.all(childIds.slice(-12).map(async (childId) => {
        try { const child = await request('/api/jobs/' + encodeURIComponent(childId)); if (child?.id !== childId || child.payload?.parentJobId !== id) throw new Error('关联信息不一致'); return child; } catch { missing += 1; return null; }
      }))).filter(Boolean);
      if (revision !== state.taskDetailRevision) return;
      state.taskDetail = { job, children, childNotice: (childIds.length > 12 ? '仅显示最近 12 个执行步骤；其余请按任务查看日志。 ' : '') + (missing ? missing + ' 个步骤暂时无法核实关联，请刷新或查看原任务日志。' : '') };
      renderTaskDetail();
    } catch (error) {
      if (revision !== state.taskDetailRevision) return;
      // Acceptance was already confirmed. A failed GET must never resurrect a
      // mutation receipt, erase another receipt, or trigger a second submission.
      $('task-detail').innerHTML = '<div class="detail-notice">任务详情暂时无法读取：' + escape(errorText(error)) + '。已接受的任务仍在服务器运行，请刷新详情或查看日志。</div>';
      $('task-detail-actions').innerHTML = '<button type="button" class="button secondary" data-task-refresh="' + escape(id) + '">重新读取</button><button type="button" class="button secondary" data-job-logs="' + escape(id) + '">查看日志</button>';
    }
  }
  function openAccountDetail(index) {
    const account = accounts()[index]; if (!account) return;
    const [label, tone, next] = classification(account);
    $('account-dialog-title').textContent = account.name || '本地待导入账号';
    $('account-dialog-subtitle').textContent = account.email || '未提供邮箱';
    $('account-detail').innerHTML = '<div class="detail-status">' + tag(label, tone) + '</div>' + detailRows([
      ['远端 ID', selectable(account) ? '#' + account.id : '尚无远端记录'], ['下一动作', account.actionLabel || ACTION_LABELS[account.action] || next],
      ['判断依据', REASONS[account.reason] || account.reason || '暂无补充信息'], ['远端状态', account.status || '未知'],
      ['累计 token', number(account.usage?.totalTokens)], ['最近处理', date(account.lastProcessedAt)],
    ]) + '<p class="muted">已有本地 token 时优先核对并回写原 ID；仅需排查可用性时，独立测试不会重新登录。</p>';
    $('account-detail-actions').innerHTML = '<button type="button" class="button secondary" data-view-local-tokens>查看本地 token</button>' + (selectable(account) ? '<button type="button" class="button primary" data-select-result-account="' + account.id + '">选中此账号</button>' : '');
    if (!$('account-dialog').open) $('account-dialog').showModal();
  }
  function localTarget(item) {
    if (!item || item.eligible !== true || item.action !== 'update' || !Number.isSafeInteger(item.accountId) || item.accountId <= 0) return null;
    const keys = ['selectedKey', 'sourceContentHash', 'targetRevision', 'executionRevision'];
    if (keys.some((key) => typeof item[key] !== 'string' || !item[key] || item[key].length > 2048)) return null;
    return Object.fromEntries(['selectedKey', 'accountId', 'targetRevision', 'sourceContentHash', 'executionRevision'].map((key) => [key, item[key]]));
  }
  function renderLocalTokens() {
    $('local-token-list').hidden = !state.localTokensLoaded;
    $('local-token-confirmation').hidden = !state.localTokensLoaded || !state.localTokens.length;
    const labels = { update: '可回写原 ID', skip: '本次跳过', review: '需要核对', create: '从未导入' };
    $('local-token-list').innerHTML = state.localTokens.length ? state.localTokens.map((item, index) => {
      const target = localTarget(item), identity = item.identitySummary || {};
      return '<div class="local-token-row"><input type="checkbox" aria-label="确认回写原账号 ' + escape(item.accountId || '未核验') + '" data-local-token-index="' + index + '"' + (!target ? ' disabled' : '') + (state.localSelected.has(item.selectedKey) ? ' checked' : '') + '><div><strong>' + escape(item.accountName || item.email || '本地 token') + '</strong><span class="small-copy">' + escape(item.accountId ? '回写目标 #' + item.accountId : '没有已核验的远端目标') + '</span><p>' + escape(item.sourceLabel || '本地 token 文件') + '</p><p>' + escape(item.reason || REASONS[item.reasonCode] || '请核对强身份与目标账号') + '</p>'
        + (item.identityCompletion === 'account_id' ? '<p class="identity-warning">需补全远端 Account ID：仅依据已核验的相同 User ID，绝不按邮箱覆盖。</p>' : '')
        + '<details><summary>身份与版本依据</summary>' + detailRows([['匹配依据', item.matchedBy === 'user_id' ? '相同 User ID' : item.matchedBy === 'account_id' ? '相同 Account ID' : '尚未确认'], ['文件 Account ID', identity.sourceAccountId], ['远端 Account ID', identity.targetAccountId], ['文件 User ID', identity.sourceUserId], ['远端 User ID', identity.targetUserId], ['新 token 指纹', item.sourceFingerprint], ['现有 token 指纹', item.targetFingerprint]]) + '</details></div>' + tag(labels[item.action] || '需要核对', target ? 'good' : 'unknown') + '</div>';
    }).join('') : '<div class="empty-state">没有需要处理的本地 token。</div>';
    $('local-token-status').textContent = '本地成果 ' + state.localTokens.length + ' 项 · 可回写原账号 ' + state.localTokens.filter(localTarget).length + ' 项。可用账号默认跳过；仅邮箱相同不会放行。';
    renderControls();
  }
  async function readLocalTokens() {
    const result = await request('/api/console/local-tokens');
    if (!Array.isArray(result.items)) throw new Error('本地 token 预览不完整，未允许回写。');
    return result.items;
  }
  async function loadLocalTokens() {
    if (state.localTokensBusy) return;
    state.localTokensBusy = true; const revision = ++state.localTokensRevision; renderControls();
    try { const items = await readLocalTokens(); if (revision !== state.localTokensRevision) return; state.localTokens = items; state.localSelected.clear(); state.localTokensLoaded = true; renderLocalTokens(); }
    catch (error) { state.localSelected.clear(); $('local-token-status').textContent = errorText(error); notice(errorText(error), 'error'); }
    finally { state.localTokensBusy = false; renderControls(); }
  }
  async function updateLocalTokens() {
    if (writeBlock()) throw new Error(writeBlock());
    const selected = state.localTokens.filter((item) => state.localSelected.has(item.selectedKey));
    const targets = selected.map(localTarget);
    if (!targets.length || targets.length > 100 || targets.some((item) => !item) || targets.length !== state.localSelected.size || new Set(targets.map((item) => item.accountId)).size !== targets.length) throw new Error('请选择 1–100 个不同原账号的有效回写候选。');
    const fresh = await readLocalTokens();
    if (targets.some((target) => { const matches = fresh.filter((item) => item.selectedKey === target.selectedKey); return matches.length !== 1 || JSON.stringify(localTarget(matches[0])) !== JSON.stringify(target); })) {
      state.localTokens = fresh; state.localSelected.clear(); renderLocalTokens(); throw new Error('本地 token、远端身份或执行配置已变化。预览已更新，请重新逐项核对并选择，不会沿用旧确认。');
    }
    if (!window.confirm('将本地 token 回写到这 ' + targets.length + ' 个原账号？\n' + selected.map((item) => '#' + item.accountId + ' ' + (item.accountName || '') + (item.identityCompletion === 'account_id' ? '（按相同 User ID 补全 Account ID）' : '')).join('\n') + '\n\n只回写上述原 ID 并测试，不新增账号、不重新登录、不租号。目标或文件变化会拒绝执行。')) return;
    await mutate('/api/console/maintain', { accountIds: targets.map((item) => item.accountId), importNew: false, refreshInvalid: false, deleteBanned: false, localTokenTargets: targets });
    state.localSelected.clear(); renderLocalTokens();
  }
  function pendingVerificationPoolOnly() {
    return state.overview?.summary?.neverImported === 0
      && accounts().every(account => ['keep', 'wait', 'skip', 'review', 'verify'].includes(account.action));
  }
  async function testSelected({ accountIds = [...state.selected], pendingOnly = false, pendingPoolOnly = false } = {}) {
    if (writeBlock()) throw new Error(writeBlock());
    const ids = [...accountIds].sort((a, b) => a - b);
    if (!ids.length || ids.length > 100 || new Set(ids).size !== ids.length) throw new Error('请选择 1–100 个不同远端账号。');
    const overview = await request('/api/console/overview');
    if (!overview || !Array.isArray(overview.accounts) || !Array.isArray(overview.jobs) || typeof overview.readOnly !== 'boolean') throw new Error('最新账号快照不完整，未提交测试。');
    state.overview = overview; state.connected = true; renderAccounts(); renderJobs(); renderControls();
    if (writeBlock()) throw new Error(writeBlock());
    const targets = ids.map((id) => accounts().find((item) => item.id === id));
    if (targets.some((item) => !item || typeof item.targetRevision !== 'string' || !item.targetRevision || typeof item.executionRevision !== 'string' || !item.executionRevision)) throw new Error('所选账号身份或执行版本无法确认，请刷新后重新选择。');
    if (pendingOnly && targets.some(item => item.classification !== 'pending_verification' || item.action !== 'verify')
        || pendingPoolOnly && !pendingVerificationPoolOnly()) throw new Error('待处理账号状态已变化，列表已更新；请按最新状态执行维护。');
    const model = $('test-model').value;
    if (!window.confirm('仅测试 ' + ids.length + ' 个账号（ID：' + ids.join('、') + '）？\n模型：' + (model || state.overview.settings?.policy?.testModel || '维护策略默认模型') + '\n不会注册、租号或刷新 token。测试成功后，按服务端安全策略恢复状态与调度。')) return;
    await mutate('/api/console/maintain', { accountIds: ids, importNew: false, refreshInvalid: false, deleteBanned: false, testOnly: true,
      accountTargets: targets.map((item) => ({ accountId: item.id, targetRevision: item.targetRevision, executionRevision: item.executionRevision })), ...(model ? { modelId: model } : {}) });
  }
  function renderContinuations() {
    $('continuations-card').hidden = state.continuations.length === 0;
    const stages = { phase2: '继续绑定邮箱', phase3: '继续获取 token', registered: '继续绑定邮箱', email_bound: '继续获取 token' };
    $('continuations').innerHTML = state.continuations.map((item, index) => {
      const notes = [item.blockingRegistration === true ? '此记录阻挡新注册，优先继续' : '', item.repairEmail === true ? '本地两份资料已核验，续跑时补齐历史邮箱' : ''].filter(Boolean).join(' · ');
      const issue = continuationIssue(item);
      return '<div class="continuation-row"><div><strong>' + escape(item.email || item.phoneMasked || '已有账号记录') + '</strong><p>' + escape(stages[item.stage] || item.stage || '继续注册流程') + (item.reason ? ' · ' + escape(item.reason) : '') + '</p>' + (notes ? '<p>' + escape(notes) + '</p>' : '') + '<p id="continuation-hint-' + index + '">' + escape(issue) + '</p></div><button class="button secondary" type="button" data-resume-index="' + index + '"' + (issue ? ' disabled' : '') + '>继续此账号 →</button></div>';
    }).join('');
    renderControls();
  }
  async function loadContinuations() {
    try { const result = await request('/api/console/register/continuations'); if (!Array.isArray(result.items)) throw new Error('未完成账号列表格式无效'); state.continuations = result.items; renderContinuations(); }
    catch (error) { $('continuations-card').hidden = false; $('continuations').innerHTML = '<div class="empty-state">' + escape(errorText(error)) + '</div>'; }
  }
  function renderNetwork(network = state.overview?.network) {
    const channels = Array.isArray(network?.channels) ? network.channels : [];
    const icons = { sms: icon('phone'), email: icon('mail'), mail: icon('mail'), oauth: icon('arrow'), login: icon('arrow'), sub2api: icon('network') };
    const names = { sms: '短信接码通道', mail: '邮箱 API 通道', email: '邮箱 API 通道', oauth: '登录 / OAuth 通道', login: '登录 / OAuth 通道', sub2api: 'Sub2API · 目标服务' };
    const subchecks = channel => !Array.isArray(channel.checks) ? '' : channel.checks.slice(0, 4).map(check => '<p>'
      + escape(({ node_oauth: 'token 接口出口', browser: '浏览器登录' })[check.id] || '子通道') + '：'
      + escape(check.ok ? '通过' : check.message || '未通过，请检查通道') + '</p>').join('');
    const untested = { sms: '号码平台鉴权与可达性；不租号', mail: '邮箱鉴权与读取能力；不发送验证码', oauth: '浏览器登录与 token 接口出口', sub2api: '账号导入与测试所需的目标服务' };
    $('network-channels').innerHTML = channels.length ? channels.map((channel) => '<div class="network-item"><span class="channel-icon" aria-hidden="true">' + (icons[channel.id] || '↗') + '</span><div class="channel-copy"><strong>' + escape(channel.name || names[channel.id] || channel.id) + '</strong><p>' + escape(channel.message || (channel.ok ? '连接正常' : '检测未通过')) + '</p>' + subchecks(channel) + '</div>' + tag(channel.ok ? '已连通' + (Number.isFinite(channel.durationMs) ? ' · ' + channel.durationMs + ' ms' : '') : '需检查', channel.ok ? 'good' : 'warn') + '</div>').join('') : Object.entries(untested).map(([id, description]) => '<div class="network-item"><span class="channel-icon" aria-hidden="true">' + icons[id] + '</span><div class="channel-copy"><strong>' + names[id] + '</strong><p>' + description + '</p></div>' + tag('未检测', 'unknown') + '</div>').join('');
    $('network-updated').textContent = network?.checkedAt ? '最近检测 ' + date(network.checkedAt) + ' · 不租号、不发验证码' : '启动任务前按所需通道预检；检测不租号、不发验证码';
  }
  function fillSelect(id, items, selected) {
    const select = $(id);
    const initial = select.options[0].outerHTML;
    select.innerHTML = initial + items.map((item) => {
      const value = typeof item === 'object' ? item.id ?? item.value ?? item.code : item;
      const label = typeof item === 'object' ? item.name ?? item.label ?? value : item;
      return '<option value="' + escape(value) + '">' + escape(label) + '</option>';
    }).join('');
    if (selected !== undefined && Array.from(select.options).some((option) => option.value === String(selected))) select.value = String(selected);
  }
  function renderSettings() {
    const settings = state.overview?.settings;
    if (!settings) return;
    renderProxySetting();
    if (!state.settingsDirty) {
      state.settingsRevision = settings.revision;
      $('automatic-maintenance').checked = settings.policy?.enabled === true;
      $('maintenance-interval').value = settings.policy?.intervalMinutes ?? 60;
      $('log-retention').value = settings.policy?.logsRetentionDays ?? 30;
    }
    if (!state.cleanupDaysDirty) $('cleanup-days').value = settings.policy?.logsRetentionDays ?? 30;
    const registration = settings.registration || {};
    const country = $('register-country').value;
    fillSelect('register-country', Array.isArray(registration.countries) ? registration.countries : [], country || registration.fields?.find((field) => field.key === 'phoneCountryCode')?.value);
    const operators = registration.operators || registration.options?.operators || [];
    $('register-operator-options').innerHTML = (Array.isArray(operators) ? operators : []).map((item) => '<option value="' + escape(typeof item === 'object' ? item.id ?? item.value ?? item.code : item) + '">' + escape(typeof item === 'object' ? item.name ?? item.label ?? '' : item) + '</option>').join('');
    const capabilities = state.overview.capabilities || {};
    const values = [['注册引擎', capabilities.registrationEnabled ? '已启用' : '未启用'], ['本地重新授权', capabilities.phase3Enabled ? '已启用' : '未启用'], ['Sub2API 管理连接', capabilities.sub2apiConfigured ? '已配置' : '未配置'], ['新注册配置', registration.ready === true ? '检查通过' : registration.ready === false ? '需要补充' : '未检测'], ['Phase3 续跑配置', registration.phase3Ready === true ? '检查通过（不要求短信）' : registration.phase3Ready === false ? '需要补充' : '未检测']];
    $('environment-list').innerHTML = values.map(([key, value]) => '<div><dt>' + key + '</dt><dd>' + value + '</dd></div>').join('');
    if (Array.isArray(registration.issues) && registration.issues.length) $('environment-list').innerHTML += '<div><dt>待处理</dt><dd>' + registration.issues.map((issue) => escape(typeof issue === 'string' ? issue : issue.message || issue.code)).join('<br>') + '</dd></div>';
    if (!state.registrationDirty && state.registrationRevision !== registration.revision) {
      state.registrationRevision = registration.revision;
      state.registrationFields = Array.isArray(registration.fields) ? registration.fields : [];
      $('registration-fields').innerHTML = state.registrationFields.map((field, index) => {
        if (typeof field.key !== 'string' || typeof field.label !== 'string') return '';
        const name = 'registration-field-' + index;
        let input;
        if (!field.secret && Array.isArray(field.options)) {
          input = '<select id="' + name + '" data-registration-index="' + index + '">' + field.options.map((option) => { const value = typeof option === 'object' ? option.value ?? option.id : option; const label = typeof option === 'object' ? option.label ?? option.name ?? value : option; return '<option value="' + escape(value) + '"' + (String(field.value) === String(value) ? ' selected' : '') + '>' + escape(label) + '</option>'; }).join('') + '</select>';
        } else if (!field.secret && field.type === 'boolean') {
          input = '<select id="' + name + '" data-registration-index="' + index + '"><option value="false"' + (!field.value ? ' selected' : '') + '>关闭</option><option value="true"' + (field.value ? ' selected' : '') + '>开启</option></select>';
        } else {
          input = '<input id="' + name + '" data-registration-index="' + index + '" type="' + (field.secret ? 'password' : ['number', 'integer'].includes(field.type) ? 'number' : 'text') + '" autocomplete="off" value="' + (field.secret ? '' : escape(Array.isArray(field.value) ? field.value.join(', ') : field.value ?? '')) + '"' + (Number.isFinite(field.min) ? ' min="' + field.min + '"' : '') + (Number.isFinite(field.max) ? ' max="' + field.max + '"' : '') + ' placeholder="' + (field.secret ? field.configured ? '已配置 · 留空保持不变' : '尚未配置 · 输入新值' : field.type === 'domains' ? '多个域名用逗号分隔' : '未配置') + '">';
        }
        return '<label class="field" for="' + name + '">' + escape(field.label) + input + (field.secret ? '<small>敏感内容只用于本次保存，不会回显或存入浏览器。</small>' : '') + '</label>';
      }).join('') || '<div class="empty-state">当前没有可编辑的注册配置，请检查注册机目录。</div>';
    }
  }
  async function refresh() {
    if (state.refreshing) return;
    const reconnecting = !state.connected;
    state.refreshing = true;
    try {
      const overview = await request('/api/console/overview');
      if (!overview || !Array.isArray(overview.accounts) || !Array.isArray(overview.jobs) || typeof overview.readOnly !== 'boolean') throw new Error('状态响应不完整，写操作保持锁定。');
      state.overview = overview; state.connected = true;
      $('connection-label').innerHTML = '工作台已连接<span>任务在服务器上运行</span>';
      $('connection-dot').className = 'status-dot online';
      $('last-updated').textContent = '最近同步 ' + date(overview.generatedAt || new Date().toISOString());
      renderMetrics(); renderAccounts(); renderJobs(); renderNetwork(); renderSettings(); renderControls();
      if (overview.warning) notice(overview.warning);
      await loadContinuations();
      if (state.page === 'settings' && !state.proxyLoadAttempted) await loadProxies();
      if ($('task-dialog').open && state.taskDetail?.job?.id) await openTaskDetail(state.taskDetail.job.id, { quiet: true });
      // Direct links and page reloads reach showPage before authentication and
      // the first snapshot. Load logs after connecting, but leave pagination
      // alone during ordinary background status polling.
      if (reconnecting && state.connected && state.page === 'logs') await loadLogs();
    } catch (error) {
      state.connected = false;
      $('connection-label').innerHTML = '暂时无法连接<span>保留现有显示，不重复提交</span>';
      $('connection-dot').className = 'status-dot warning';
      notice(errorText(error), 'error'); renderControls();
    } finally { state.refreshing = false; }
  }
  function logQuery({ next = false } = {}) {
    const query = new URLSearchParams({ limit: '200' });
    for (const [id, key] of [['log-source', 'source'], ['log-level', 'level'], ['log-job', 'jobId'], ['log-query', 'q'], ['log-file', 'fileId']]) { const value = $(id).value; if (value && value !== 'all') query.set(key, value); }
    if (next && state.nextCursor) query.set('cursor', state.nextCursor);
    return query;
  }
  function renderLogs() {
    $('log-entries').innerHTML = state.logs.length ? state.logs.map((entry) => '<div class="log-line"><span class="log-time">' + escape(date(entry.time)) + '</span><span class="log-level ' + (entry.level === 'error' ? 'error' : entry.level === 'warn' ? 'warn' : '') + '">' + escape(String(entry.level || 'info').toUpperCase()) + '</span><span class="log-message">' + escape((entry.source ? '[' + entry.source + '] ' : '') + (entry.event ? entry.event + ' · ' : '') + (entry.message || '')) + '</span></div>').join('') : '<div class="log-empty">没有符合条件的日志记录</div>';
    $('log-count').textContent = '已显示 ' + state.logs.length + ' 条 · 敏感内容已脱敏';
    $('logs-more').hidden = !state.nextCursor;
  }
  async function loadLogs(next = false) {
    const revision = ++state.logRevision;
    $('logs-more').disabled = true;
    try {
      const result = await request('/api/console/logs?' + logQuery({ next }));
      if (revision !== state.logRevision) return;
      if (!Array.isArray(result.entries)) throw new Error('日志响应格式无效。');
      state.logs = next ? state.logs.concat(result.entries).slice(-4000) : result.entries;
      state.logFiles = Array.isArray(result.files) ? result.files : [];
      const fileId = $('log-file').value;
      fillSelect('log-file', state.logFiles.map((file) => ({ value: file.id, label: file.name + ' · ' + Math.ceil(file.bytes / 1024) + ' KB · ' + date(file.modifiedAt) + (file.active ? ' · 写入中' : '') })), fileId);
      const scope = result.searchScope;
      const partialScan = scope && Number.isSafeInteger(scope.scannedFiles) && scope.scannedFiles >= 0
        && Number.isSafeInteger(scope.matchingFiles) && scope.matchingFiles > scope.scannedFiles
        && Number.isSafeInteger(scope.omittedFiles) && scope.omittedFiles === scope.matchingFiles - scope.scannedFiles;
      $('log-storage').textContent = '日志文件 ' + state.logFiles.length + ' 个' + (Number.isFinite(result.totalBytes) ? ' · 合计 ' + (result.totalBytes / 1024 / 1024).toFixed(1) + ' MB' : '') + '。未选文件下载当前已加载记录；选定文件下载完整脱敏内容（上限 32 MB）。' + (typeof result.bindingNotice === 'string' ? ' ' + result.bindingNotice : '')
        + (partialScan ? ' 本次仅扫描 ' + scope.scannedFiles + ' / ' + scope.matchingFiles + ' 个匹配文件，较早日志请按文件查看。' : '');
      state.nextCursor = typeof result.nextCursor === 'string' ? result.nextCursor : null;
      renderLogs();
    } catch (error) { notice(errorText(error), 'error'); } finally { if (revision === state.logRevision) $('logs-more').disabled = false; }
  }
  function showPage() {
    const page = location.hash.slice(1);
    state.page = Object.hasOwn(PAGE_TITLES, page) ? page : 'register';
    for (const name of Object.keys(PAGE_TITLES)) $('page-' + name).hidden = name !== state.page;
    document.querySelectorAll('[data-page]').forEach((link) => { const active = link.dataset.page === state.page; link.classList.toggle('active', active); if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); });
    $('breadcrumb-title').textContent = PAGE_TITLES[state.page];
    document.title = PAGE_TITLES[state.page] + ' · 账号工作台';
    if (state.page === 'logs' && state.connected) loadLogs();
    if (state.page === 'settings' && state.connected && !state.proxyLoadAttempted) loadProxies();
  }
  async function preflight() {
    if (state.networkBusy) return;
    state.networkBusy = true; renderControls(); notice('正在按实际配置检测短信、邮箱与登录通道，不会租号或发送验证码。');
    try { const result = await request('/api/console/preflight', { method: 'POST', body: '{}' }); if (state.overview) state.overview.network = result; renderNetwork(result); notice(result.ok ? '网络预检通过；这只说明连接可用，不保证注册一定成功。' : '部分通道检测未通过，详细原因已显示。', result.ok ? 'success' : ''); }
    catch (error) { notice(errorText(error), 'error'); } finally { state.networkBusy = false; renderControls(); }
  }
  function report(task) { return Promise.resolve().then(task).catch((error) => notice(errorText(error), 'error')); }

  $('auth-dialog').addEventListener('cancel', (event) => event.preventDefault());
  $('auth-form').addEventListener('submit', (event) => { event.preventDefault(); report(async () => { try { saveToken($('admin-token').value); $('admin-token').value = ''; $('auth-dialog').close(); await refresh(); } catch (error) { $('auth-error').textContent = errorText(error); } }); });
  $('sign-out').addEventListener('click', () => { state.token = ''; try { sessionStorage.removeItem('panelToken'); } catch {} requestAuthentication(); });
  $('refresh').addEventListener('click', () => refresh());
  $('resolve-pending').addEventListener('click', () => report(() => mutate(null, null, { replay: true })));
  $('check-network').addEventListener('click', preflight); $('settings-check-network').addEventListener('click', preflight);
  $('register-form').addEventListener('submit', (event) => { event.preventDefault(); report(async () => {
    const count = Number($('register-count').value);
    if (!Number.isSafeInteger(count) || count < 1 || count > 100) throw new Error('注册数量须为 1–100 的整数。');
    if (!/^[A-Z]{2}$/.test($('register-country').value)) throw new Error('请先选择注册国家 / 地区；无法确认默认国家时不会自动租号。');
    if (!window.confirm('开始注册 ' + count + ' 个账号？\n将按现有注册配置执行接码、邮箱验证，并将成功的新账号自动导入 Sub2API。可能产生接码费用。')) return;
    const body = { count, autoImport: true }; if ($('register-country').value) body.country = $('register-country').value; if ($('register-operator').value) body.operator = $('register-operator').value;
    await mutate('/api/console/register', body);
  }); });
  async function maintain(selectedOnly) {
    const ids = selectedOnly ? [...state.selected].sort((a, b) => a - b) : null;
    if (selectedOnly && !ids.length) throw new Error('请先选择需要维护的远端账号。');
    const pendingTargets = ids ? ids.map(id => accounts().find(account => account.id === id))
      : accounts().filter(account => account.action === 'verify');
    if (pendingTargets.length && pendingTargets.every(account => account && selectable(account) && account.classification === 'pending_verification' && account.action === 'verify')
        && (ids || pendingVerificationPoolOnly())) {
      // Reuse one explicit test submission, including its fresh target proof.
      // Never turn mixed maintenance into hidden extra requests or expand IDs.
      return testSelected({ accountIds: pendingTargets.map(account => account.id), pendingOnly: true, pendingPoolOnly: !ids });
    }
    const scope = ids ? '所选 ' + ids.length + ' 个远端账号（ID：' + ids.join('、') + '）' : '全部账号';
    if (!window.confirm('维护' + scope + '？\n\n' + (ids ? '• 仅处理上述远端 ID，不导入其他新账号' : '• 导入从未加入过的新账号') + '\n• 仅失效 / 过期 token 重新授权，额度耗尽等待恢复\n• 明确确认封禁后，删除对应 Sub2API 记录，本地保留履历\n• 网络故障和原因不明的账号不会被删除\n\n重新授权可能发送验证码。')) return;
    await mutate('/api/console/maintain', { ...(ids ? { accountIds: ids } : {}), importNew: !ids, refreshInvalid: true, deleteBanned: true });
  }
  $('maintain-all').addEventListener('click', () => report(() => maintain(false)));
  $('maintain-selected').addEventListener('click', () => report(() => maintain(true)));
  $('local-token-refresh').addEventListener('click', loadLocalTokens);
  $('local-token-list').addEventListener('change', (event) => { const item = state.localTokens[Number(event.target.dataset.localTokenIndex)]; if (!localTarget(item)) return; if (event.target.checked) state.localSelected.add(item.selectedKey); else state.localSelected.delete(item.selectedKey); renderControls(); });
  $('local-token-update').addEventListener('click', () => report(updateLocalTokens));
  $('test-selected').addEventListener('click', () => report(testSelected));
  $('import-new').addEventListener('click', () => report(async () => { if (!window.confirm('仅导入从未加入过的新账号？\n将检查全部本地 token，不受表格选择影响。不刷新既有账号，不删除、不租号。已有远端账号的 token 请使用“回写原账号”。')) return; await mutate('/api/console/maintain', { importNew: true, refreshInvalid: false, deleteBanned: false }); }));
  $('account-search').addEventListener('input', renderAccounts); $('account-filter').addEventListener('change', renderAccounts);
  $('select-all').addEventListener('change', () => { for (const account of filteredAccounts().filter(selectable)) { if ($('select-all').checked) state.selected.add(account.id); else state.selected.delete(account.id); } renderAccounts(); });
  $('account-rows').addEventListener('change', (event) => { const id = Number(event.target.dataset.accountId); if (!Number.isSafeInteger(id) || id <= 0) return; if (event.target.checked) state.selected.add(id); else state.selected.delete(id); renderAccounts(); });
  $('account-rows').addEventListener('click', (event) => { const button = event.target.closest('[data-account-detail]'); if (button) openAccountDetail(Number(button.dataset.accountDetail)); });
  function closeDetails() { $('task-dialog').close(); $('account-dialog').close(); state.taskDetailRevision += 1; state.taskDetail = null; }
  function taskClick(event) {
    const stop = event.target.closest('[data-stop-job]'); const logs = event.target.closest('[data-job-logs]');
    const detail = event.target.closest('[data-job-detail]') || event.target.closest('[data-task-refresh]');
    if (detail) openTaskDetail(detail.dataset.jobDetail || detail.dataset.taskRefresh);
    if (logs) {
      closeDetails();
      // A task shortcut describes that task, not a stale file/search selection.
      $('log-source').value = 'all'; $('log-level').value = 'all'; $('log-file').value = ''; $('log-query').value = '';
      $('log-job').value = logs.dataset.jobLogs; state.nextCursor = null;
      location.hash = 'logs'; if (state.page === 'logs') loadLogs();
    }
    if (stop) report(async () => { if (window.confirm('停止这一个后台任务？\n已完成的注册或导入不会回滚，其他任务不受影响。')) await stopJob(stop.dataset.stopJob); });
    if (event.target.closest('[data-view-local-tokens]')) { closeDetails(); location.hash = 'accounts'; showPage(); loadLocalTokens(); $('local-token-card').scrollIntoView?.({ block: 'start' }); }
    if (event.target.closest('[data-view-continuations]')) { closeDetails(); location.hash = 'register'; showPage(); loadContinuations(); $('continuations-card').scrollIntoView?.({ block: 'start' }); }
    const select = event.target.closest('[data-select-result-account]');
    if (select) report(async () => { const id = Number(select.dataset.selectResultAccount); await refresh(); if (!accounts().some((account) => account.id === id && selectable(account))) throw new Error('该原账号不在当前快照中，未选择其他账号代替。'); state.selected = new Set([id]); $('account-search').value = ''; $('account-filter').value = 'all'; closeDetails(); location.hash = 'accounts'; showPage(); renderAccounts(); notice('已选中原账号 #' + id + '。需要验证时点击“只测试所选账号”，确认后才会执行。'); });
  }
  for (const id of ['jobs', 'account-jobs', 'task-dialog', 'account-dialog']) $(id).addEventListener('click', taskClick);
  $('task-dialog-close').addEventListener('click', closeDetails); $('account-dialog-close').addEventListener('click', closeDetails);
  $('task-dialog').addEventListener('cancel', () => { state.taskDetailRevision += 1; state.taskDetail = null; });
  $('show-task-list').addEventListener('click', () => { if (state.overview?.reconciliation?.total > 0 || state.registrationReviewPending) { report(() => openRegistrationReview()); return; } location.hash = 'register'; showPage(); $('task-list').scrollIntoView?.({ block: 'start' }); });
  $('registration-review-content').addEventListener('click', event => { const button = event.target.closest('[data-registration-review]'); if (button) report(() => openRegistrationReview(button.dataset.registrationReview)); });
  $('registration-review-refresh').addEventListener('click', () => report(() => openRegistrationReview(state.registrationReviewJobId)));
  $('registration-review-checked').addEventListener('change', renderRegistrationReviewControls);
  $('registration-review-submit').addEventListener('click', () => report(acknowledgeRegistrationReview));
  $('registration-review-dismiss').addEventListener('click', () => report(dismissResolvedRegistrationReview));
  $('registration-review-close').addEventListener('click', () => { if (!state.registrationReviewBusy) { state.registrationReviewRevision += 1; state.registrationReview = null; $('registration-review-dialog').close(); } });
  $('registration-review-dialog').addEventListener('cancel', event => { if (state.registrationReviewBusy) event.preventDefault(); else { state.registrationReviewRevision += 1; state.registrationReview = null; } });
  $('continuations').addEventListener('click', (event) => { const button = event.target.closest('[data-resume-index]'); if (!button) return; report(async () => { const item = state.continuations[Number(button.dataset.resumeIndex)], issue = continuationIssue(item); if (issue) throw new Error(issue); if (!window.confirm('继续 ' + (item.email || item.phoneMasked || '所选本地账号') + '？\n从已有记录继续绑定邮箱 / 获取 token，不重新租号。可能发送验证码；成功后自动导入。')) return; await mutate('/api/console/register/resume', { selectedKey: item.selectedKey, revision: item.revision, autoImport: true }); }); });
  for (const id of ['log-source', 'log-level', 'log-job', 'log-file']) $(id).addEventListener('change', () => loadLogs());
  $('log-query').addEventListener('search', () => loadLogs()); $('log-query').addEventListener('keydown', (event) => { if (event.key === 'Enter') loadLogs(); });
  $('logs-refresh').addEventListener('click', () => loadLogs()); $('logs-more').addEventListener('click', () => loadLogs(true));
  $('logs-download').addEventListener('click', () => report(async () => {
    let blob;
    if ($('log-file').value) {
      const fileId = $('log-file').value;
      if (!state.logFiles.some((file) => file.id === fileId)) throw new Error('所选日志文件已变化，请刷新列表。');
      const headers = new Headers(); if (state.token) headers.set('x-panel-token', state.token);
      const response = await fetch('/api/console/logs/download?' + new URLSearchParams({ fileId }), { headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
      if (!response.ok) throw new Error('日志下载失败（HTTP ' + response.status + '）。');
      blob = await response.blob(); if (blob.size > 32 * 1024 * 1024) throw new Error('日志过大，请按轮转文件下载。');
    } else {
      if (!state.logs.length) throw new Error('当前没有已加载的日志可下载。');
      blob = new Blob([state.logs.map((entry) => '[' + date(entry.time) + '] [' + String(entry.level || 'info') + '] [' + String(entry.source || '') + '] ' + String(entry.message || '')).join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
    }
    const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = 'register-studio-logs.txt'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }));
  $('logs-cleanup').addEventListener('click', () => report(async () => { const days = Number($('cleanup-days').value); if (!Number.isSafeInteger(days) || days < 1 || days > 365) throw new Error('保留天数须为 1–365 的整数。'); if (!window.confirm('清理 ' + days + ' 天以前的已结束任务日志？\n此操作不可恢复，不删除 token、账号或活动日志。')) return; await mutate('/api/console/logs/cleanup', { olderThanDays: days, confirm: true }); await loadLogs(); }));
  $('cleanup-days').addEventListener('input', () => { state.cleanupDaysDirty = true; });
  $('settings-form').addEventListener('input', () => { state.settingsDirty = true; });
  $('import-proxy-refresh').addEventListener('click', loadProxies);
  $('import-proxy-select').addEventListener('change', () => { state.proxyDirty = true; renderControls(); });
  $('import-proxy-form').addEventListener('submit', (event) => { event.preventDefault(); report(saveImportProxy); });
  $('settings-form').addEventListener('submit', (event) => { event.preventDefault(); report(async () => {
    const enabled = $('automatic-maintenance').checked; const interval = Number($('maintenance-interval').value); const days = Number($('log-retention').value);
    if (!Number.isSafeInteger(interval) || interval < 5 || interval > 1440 || !Number.isSafeInteger(days) || days < 1 || days > 365) throw new Error('巡检间隔须为 5–1440 分钟，日志保留须为 1–365 天。');
    if (enabled && !state.overview?.settings?.policy?.enabled && !window.confirm('开启自动巡检？\n服务器将按设定间隔自动导入新账号、重新授权失效账号，并删除已明确确认封禁的远端记录。关闭网页不会停止巡检。')) return;
    await saveSettings({ revision: state.settingsRevision, confirm: enabled, policy: { ...state.overview.settings.policy, enabled, intervalMinutes: interval, logsRetentionDays: days } });
    state.settingsDirty = false; renderSettings();
  }); });
  $('registration-settings-form').addEventListener('input', () => { state.registrationDirty = true; });
  $('settings-reload').addEventListener('click', () => report(async () => {
    if ((state.settingsDirty || state.registrationDirty || state.proxyDirty) && !window.confirm('重新读取配置会放弃未保存的修改，并清空新输入的密钥，是否继续？')) return;
    const settings = await request('/api/console/settings');
    if (!state.overview) throw new Error('工作台尚未完成首次同步。');
    state.overview.settings = settings; state.settingsDirty = false; state.registrationDirty = false; state.registrationRevision = null;
    state.proxyDirty = false; state.proxyList = null; state.proxyLoadAttempted = false; renderSettings();
    if (state.page === 'settings') await loadProxies();
    if (state.pending?.url === '/api/console/settings') notice('已重新读取服务端配置，但上次保存结果仍待核对。请使用“核对本次请求”；若仍无法确认，请按原请求时间核对服务端操作日志。重新读取不会解除待核对记录。');
    else notice('已重新读取服务端配置。', 'success');
  }));
  $('registration-settings-form').addEventListener('submit', (event) => { event.preventDefault(); report(async () => {
    const changes = {};
    for (let index = 0; index < state.registrationFields.length; index += 1) {
      const field = state.registrationFields[index]; const input = $('registration-field-' + index); if (!input) continue;
      let value = input.value;
      if (field.secret) { if (value !== '') changes[field.key] = value; input.value = ''; continue; }
      if (['number', 'integer'].includes(field.type) && value === '' && (field.value === '' || field.value === undefined)) continue;
      if (field.type === 'boolean') value = value === 'true'; else if (['number', 'integer'].includes(field.type)) value = Number(value); else if (field.type === 'domains') value = value.split(/[,，\s]+/).filter(Boolean);
      if (String(value) !== String(field.value ?? '')) changes[field.key] = value;
    }
    if (!Object.keys(changes).length) { notice('没有需要保存的配置变更。'); return; }
    await saveSettings({ revision: state.overview.settings.revision, registration: { revision: state.registrationRevision, changes } });
    state.registrationDirty = false; state.registrationRevision = null; renderSettings();
  }); });
  window.addEventListener('hashchange', showPage);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  try { const token = sessionStorage.getItem('panelToken'); if (validToken(token)) state.token = token; else if (token) sessionStorage.removeItem('panelToken'); } catch { /* Authentication can still work in memory. */ }
  try { const raw = sessionStorage.getItem(PENDING_STORE); if (raw !== null) { const pending = JSON.parse(raw); if (!pendingValid(pending)) throw new Error('invalid pending'); state.pending = pending; } } catch { state.storageError = true; notice('操作恢复记录无法读取。为防止重复执行，写操作已锁定，请到高级诊断核对。', 'error'); }
  try { const raw = sessionStorage.getItem(REVIEW_STORE); if (raw !== null) { const pending = JSON.parse(raw); if (!registrationReviewPendingValid(pending)) throw new Error('invalid review'); state.registrationReviewPending = pending; } } catch { state.storageError = true; notice('人工对账回执无法读取，保持操作阻挡。请管理员核对原任务，勿重新注册。', 'error'); }
  showPage(); renderControls(); refresh();
  state.pollTimer = setInterval(() => { if (!document.hidden && !$('auth-dialog').open) refresh(); }, 6000);
})();
