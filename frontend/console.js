'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  const PENDING_STORE = 'registerStudio.pending.v1';
  const MAX_REPLAY_AGE = 20 * 60 * 60 * 1000;
  const PAGE_TITLES = { register: '注册任务', accounts: '账号维护', logs: '日志中心', settings: '设置与检测' };
  const ACTIVE = new Set(['queued', 'pending', 'running', 'stopping', 'cancel_requested']);
  const STATUS_LABELS = { queued: '排队中', pending: '等待中', running: '进行中', stopping: '正在停止', cancel_requested: '正在停止', succeeded: '已完成', completed: '已完成', failed: '失败', cancelled: '已停止', canceled: '已停止', interrupted: '需核对', partial: '部分完成' };
  const CLASSIFICATION = {
    healthy: ['正常可用', 'good', '保持原样'], active: ['正常可用', 'good', '保持原样'],
    new: ['从未导入', 'neutral', '首次导入'], never_imported: ['从未导入', 'neutral', '首次导入'],
    refresh: ['需要授权', 'warn', '重新获取 token'], refresh_needed: ['需要授权', 'warn', '重新获取 token'],
    invalid: ['认证失效', 'warn', '重新获取 token'], auth_invalid: ['认证失效', 'warn', '重新获取 token'], expired: ['已过期', 'warn', '重新获取 token'],
    quota: ['额度耗尽', 'neutral', '等待恢复'], quota_wait: ['额度 / 冷却中', 'neutral', '等待恢复'], rate_limited: ['限流冷却', 'neutral', '等待恢复'],
    banned: ['确认封禁', 'bad', '删除远端记录'], confirmed_banned: ['确认封禁', 'bad', '删除远端记录'], disabled: ['手动停用', 'unknown', '保留停用'], manual_disabled: ['手动停用', 'unknown', '保留停用'],
    review: ['需要核对', 'unknown', '人工核对'], needs_review: ['需要核对', 'unknown', '人工核对'], network_unknown: ['原因待核对', 'unknown', '人工核对'], deleted: ['已删除', 'unknown', '不再导入'],
  };
  const ACTION_LABELS = { keep: '保持原样', wait: '等待恢复', refresh: '重新获取 token', delete: '删除远端记录', review: '人工核对', skip: '本次跳过', import: '首次导入' };
  const REASONS = { account_available: '账号可用，不更新现有 token', quota_or_cooldown: '额度耗尽或限流冷却，等待恢复', credential_expired_unavailable: '凭据已过期且账号不可用，需要重新授权', administrator_disabled: '管理员已停用账号，不自动启用', administrator_lifetime_expired: '管理员设定的账号有效期已到期，不是 OAuth token 过期；保留停用，不自动刷新或删除', administrator_unscheduled: '管理员已关闭调度，不自动启用', failure_requires_diagnosis: '目前不能确认失败原因，保留账号并等待核对', account_schema_unknown: '账号信息不完整或身份存在冲突', account_status_unknown: '远端状态未知', strong_identity_ambiguous: '强身份缺失或匹配不唯一，需要人工核对', lifecycle_requires_reconciliation: '导入或删除履历需要核对', outside_free_oauth_scope: '不属于 Free OAuth 账号，不自动处理', disabled_by_policy: '此动作已被维护策略关闭', never_imported: '未发现历史导入记录，可首次导入', confirmed_ban_deleted: '已确认封禁并删除远端记录，不会再次导入', invalid_grant: '重新授权凭据已失效', invalid_token: 'token 无效', token_expired: 'token 已过期', refresh_token_expired: '刷新凭据已过期', refresh_token_reused: '刷新凭据已经使用，需重新登录', refresh_token_revoked: '刷新凭据被撤销', refresh_token_missing: '缺少刷新凭据，需重新登录', refresh_reauthorization_required: '无法直接续期，需要本地重新授权', account_deactivated: '上游明确确认账号已停用', user_deactivated: '上游明确确认用户已停用', account_suspended: '上游明确确认账号被暂停', account_banned: '上游明确确认账号被封禁' };
  const state = { overview: null, connected: false, pending: null, storageError: false, busy: false, refreshing: false, page: 'register', selected: new Set(), stoppingJobs: new Set(), logs: [], logFiles: [], continuations: [], nextCursor: null, logRevision: 0, token: '', settingsDirty: false, settingsRevision: null, cleanupDaysDirty: false, registrationDirty: false, registrationRevision: null, registrationFields: [], networkBusy: false, pollTimer: null };

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
        error.definitive = response.status >= 400 && response.status < 500 && response.status !== 408 && response.status !== 409 && response.status !== 429;
        if (['REGISTRATION_SETTINGS_CHANGED', 'CONSOLE_SETTINGS_STALE'].includes(error.code)) error.definitive = true;
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
    const matches = expected.registration
      ? settings.registration?.lastRequestId === expected.registration.requestId
      : expected.policy && Object.entries(expected.policy).every(([key, value]) => settings.policy?.[key] === value);
    if (!matches) throw new Error('尚不能确认本次配置已保存。不会重新发送密钥或覆盖配置，请稍后再次核对或到高级诊断检查。');
    persistPending(null);
    if (state.overview) state.overview.settings = settings;
    state.registrationDirty = false; state.settingsDirty = false; state.registrationRevision = null;
    renderSettings(); notice('已确认本次配置保存成功。密钥没有被重复提交。', 'success');
    return settings;
  }
  async function saveSettings(body) {
    if (writeBlock()) throw new Error(writeBlock());
    if (body.registration) body.registration.requestId = settingsRequestId();
    const safeBody = body.registration ? { revision: body.revision, registration: { revision: body.registration.revision, requestId: body.registration.requestId, changedKeys: Object.keys(body.registration.changes) } } : body;
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
    if (state.overview.reconciliation.total > 0) return '有 ' + state.overview.reconciliation.total + ' 个任务的外部结果尚未确认。请到高级诊断完成人工对账，期间禁止新写入。';
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
    const show = Boolean(state.overview && (problem || holds || active));
    $('task-safety-banner').hidden = !show;
    if (!show) return;
    $('task-safety-banner').className = 'task-safety-banner' + (!problem && !holds ? ' running' : '');
    $('task-safety-title').textContent = problem ? '后台任务状态尚未核对完整' : holds ? holds + ' 个任务需要人工对账' : '后台有 ' + active + ' 项活动任务';
    $('task-safety-message').textContent = problem ? problem + ' 查看状态、日志、连接检测和停止已知任务仍可使用。'
      : holds ? '此前操作的外部结果尚不明确，服务端保留了安全阻挡。刷新或重新登录不会解除阻挡；请核对原账号 ID 和强身份后处理。仍可停止已知任务和查看日志。'
        : '任务在服务器上继续执行，暂不接受重复的新操作。需要终止时，请点击任务列表中的“停止”；旧版任务可在高级诊断查看。';
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
    const groups = { healthy: ['healthy', 'active'], new: ['new', 'never_imported'], refresh: ['refresh', 'refresh_needed', 'invalid', 'auth_invalid', 'expired'], quota: ['quota', 'quota_wait', 'rate_limited'], banned: ['banned', 'confirmed_banned'], review: ['review', 'needs_review', 'network_unknown', 'disabled', 'manual_disabled'] };
    return accounts().filter((account) => (filter === 'all' || groups[filter]?.includes(account.classification)) && (!query || [account.name, account.email, account.id].join(' ').toLowerCase().includes(query)));
  }
  function selectable(account) { return Number.isSafeInteger(account.id) && account.id > 0; }
  function renderControls() {
    const blocked = writeBlock();
    const capabilities = state.overview?.capabilities || {};
    const comparisonIssue = capabilities.comparisonAvailable === false ? '账号快照不完整，请先检测 Sub2API 连接。' : '';
    const registrationIssue = blocked || comparisonIssue || (state.networkBusy ? '网络预检正在执行，通常需要数十秒；完成后即可启动注册。' : '') || (!capabilities.registrationEnabled ? '注册功能未启用，请检查服务端配置。' : '') || (state.overview?.settings?.registration?.ready === false ? '注册配置不完整，请到设置与检测查看原因。' : '');
    $('start-register').disabled = Boolean(registrationIssue);
    $('register-hint').textContent = registrationIssue || '将按现有接码与邮箱配置执行；成功后自动首次导入。';
    $('maintain-all').disabled = Boolean(blocked || comparisonIssue || !capabilities.sub2apiConfigured);
    $('maintain-selected').disabled = Boolean(blocked || comparisonIssue || !capabilities.sub2apiConfigured || state.selected.size === 0);
    $('selected-count').textContent = state.selected.size;
    $('maintain-hint').textContent = blocked || comparisonIssue || (!capabilities.sub2apiConfigured ? '尚未配置 Sub2API 管理连接。' : '一键维护检查全池并导入新账号；维护所选只处理选中的远端 ID，不导入范围外的账号。');
    $('settings-save').disabled = Boolean(blocked || !state.overview?.settings);
    $('registration-settings-save').disabled = Boolean(blocked || !state.overview?.settings?.registration?.revision);
    $('settings-hint').textContent = blocked;
    $('logs-cleanup').disabled = Boolean(blocked);
    $('check-network').disabled = state.networkBusy || !state.connected;
    $('settings-check-network').disabled = state.networkBusy || !state.connected;
    $('check-network').textContent = state.networkBusy ? '检测中…' : '重新检测 ↗';
    $('settings-check-network').textContent = state.networkBusy ? '检测中…' : '检测连接 ↗';
    $('resolve-pending').disabled = state.busy || !state.connected || state.storageError;
    $('pending-banner').hidden = !state.pending && !state.storageError;
    $('mode-label').textContent = !state.connected ? '服务未连接' : state.overview?.readOnly ? '只读模式' : state.overview?.settings?.policy?.enabled ? '自动巡检开启' : '手动控制';
    document.querySelectorAll('[data-stop-job]').forEach((button) => { button.disabled = state.stoppingJobs.has(button.dataset.stopJob); });
    document.querySelectorAll('[data-resume-index]').forEach((button) => { button.disabled = Boolean(registrationIssue || !state.continuations[Number(button.dataset.resumeIndex)]?.eligible); });
    renderTaskSafety();
  }
  function renderMetrics() {
    const summary = state.overview?.summary || {};
    $('metric-total').textContent = number(summary.total);
    $('metric-healthy').textContent = number(summary.healthy);
    $('metric-attention').textContent = number(summary.refreshNeeded !== undefined && summary.needsReview !== undefined && summary.banned !== undefined ? summary.refreshNeeded + summary.needsReview + summary.banned : undefined);
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
      return '<tr' + (selected ? ' class="selected"' : '') + '><td class="checkbox-cell"><input type="checkbox" data-account-id="' + id + '" aria-label="选择 ' + escape(account.name || '本地账号') + '"' + (selected ? ' checked' : '') + (!id ? ' disabled title="本地新账号由一键维护处理"' : '') + '></td><td><span class="account-name">' + escape(account.name || '本地待导入') + '</span><span class="account-email">' + escape(account.email || '未提供邮箱') + '</span></td><td>' + tag(label, tone) + '</td><td>' + escape(account.actionLabel || ACTION_LABELS[account.action] || next) + '</td><td>' + escape(date(account.lastProcessedAt)) + '</td><td><details class="account-details"><summary>' + (id ? '#' + id : '本地记录') + '</summary><p>' + escape(REASONS[account.reason] || account.reason || '暂无补充信息') + '</p><p>远端状态：' + escape(account.status || '未知') + '</p>' + (account.usage?.totalTokens !== undefined ? '<p>累计 token：' + number(account.usage.totalTokens) + '</p>' : '') + '</details></td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty-cell">' + (all.length ? '没有符合筛选条件的账号' : '暂无账号记录；可以先注册或检查 Sub2API 连接') + '</td></tr>';
    const visible = rows.filter(selectable);
    const selected = visible.filter((account) => state.selected.has(account.id)).length;
    $('select-all').checked = visible.length > 0 && selected === visible.length;
    $('select-all').indeterminate = selected > 0 && selected < visible.length;
    $('select-all').disabled = visible.length === 0;
    $('account-count').textContent = '显示 ' + rows.length + ' / ' + all.length + ' 个账号 · 已选 ' + state.selected.size;
    renderControls();
  }
  function renderJobs() {
    const jobs = Array.isArray(state.overview?.jobs) ? state.overview.jobs : [];
    $('job-count').textContent = jobs.filter((job) => ACTIVE.has(job.status)).length + ' 个进行中';
    $('jobs').innerHTML = jobs.length ? jobs.slice(0, 20).map((job) => {
      const running = ACTIVE.has(job.status);
      const label = /resume/.test(job.type) ? '继续已有账号' : /register/.test(job.type) ? '注册任务' : /maintain|maintenance/.test(job.type) ? '账号维护' : /log_cleanup/.test(job.type) ? '日志清理' : '后台任务';
      const tone = running ? 'neutral' : ['succeeded', 'completed'].includes(job.status) ? 'good' : job.status === 'failed' ? 'bad' : 'unknown';
      const progress = job.progress && Number.isFinite(job.progress.completed) && Number.isFinite(job.progress.total) ? ' · ' + job.progress.completed + ' / ' + job.progress.total : '';
      const summaryLabels = { registered: '注册成功', imported: '导入', refreshed: '刷新', deleted: '删除', skipped: '跳过', failed: '失败', removed: '清理文件' };
      const counts = job.summary && typeof job.summary === 'object' ? Object.entries(summaryLabels).filter(([key]) => Number.isFinite(job.summary[key])).map(([key, label]) => label + ' ' + job.summary[key]).join(' · ') : '';
      const stages = { queued: '等待调度', starting: '准备执行', planning: '核对账号与维护范围', checking_network: '检查网络通道', preflight: '连接预检',
        registering: '正在注册', init: '初始化注册流程', phase1_register: '手机号注册与短信验证', phase1_register_recovery: '恢复已有手机号注册',
        phase1_5_profile: '完成账号个人资料', phase2_bind_email: '绑定邮箱', phase2_resume: '继续邮箱绑定', phase3_email_oauth: '邮箱验证并获取 token',
        importing: '导入 Sub2API', importing_new: '导入从未加入的账号', maintenance: '正在维护', maintaining: '继续处理账号',
        refreshing: '本地重新授权', updating_token: '核验身份并回写原账号', verifying_account: '测试账号及恢复调度', removing_banned: '复核并删除确认封禁的记录',
        completed: '处理完成', stopped: '已停止', failed: '执行失败' };
      const description = typeof job.summary === 'string' ? job.summary : typeof job.error === 'string' ? job.error : job.error?.message || [stages[job.stage] || job.stage, counts].filter(Boolean).join(' · ') || '等待任务报告';
      return '<div class="job-row"><span class="job-symbol" aria-hidden="true">' + (running ? '↻' : '✓') + '</span><div><p class="job-title">' + label + escape(progress) + '</p><p class="job-detail">' + escape(description) + '</p><p class="job-detail">' + escape(job.id) + '</p></div><div class="job-status">' + tag(STATUS_LABELS[job.status] || '未知', tone) + '<span class="job-date">' + date(job.createdAt) + '</span></div><div class="job-actions"><button type="button" class="text-button" data-job-logs="' + escape(job.id) + '">日志</button>' + (running ? '<button type="button" class="text-button" data-stop-job="' + escape(job.id) + '">停止</button>' : '') + '</div></div>';
    }).join('') : '<div class="empty-state">还没有任务。<br>开始一次注册，或到账号维护检查现有账号。</div>';
  }
  function renderContinuations() {
    $('continuations-card').hidden = state.continuations.length === 0;
    const stages = { phase2: '继续绑定邮箱', phase3: '继续获取 token', registered: '继续绑定邮箱', email_bound: '继续获取 token' };
    $('continuations').innerHTML = state.continuations.map((item, index) => '<div class="continuation-row"><div><strong>' + escape(item.email || item.phoneMasked || '已有账号记录') + '</strong><p>' + escape(stages[item.stage] || item.stage || '继续注册流程') + (item.reason ? ' · ' + escape(item.reason) : '') + '</p></div><button class="button secondary" type="button" data-resume-index="' + index + '"' + (!item.eligible ? ' disabled' : '') + '>继续此账号 →</button></div>').join('');
    renderControls();
  }
  async function loadContinuations() {
    try { const result = await request('/api/console/register/continuations'); if (!Array.isArray(result.items)) throw new Error('未完成账号列表格式无效'); state.continuations = result.items; renderContinuations(); }
    catch (error) { $('continuations-card').hidden = false; $('continuations').innerHTML = '<div class="empty-state">' + escape(errorText(error)) + '</div>'; }
  }
  function renderNetwork(network = state.overview?.network) {
    const channels = Array.isArray(network?.channels) ? network.channels : [];
    const icons = { sms: '▤', email: '✉', mail: '✉', oauth: '↗', login: '↗', sub2api: '⇄' };
    const names = { sms: '短信接码通道', mail: '邮箱 API 通道', email: '邮箱 API 通道', oauth: '登录 / OAuth 通道', login: '登录 / OAuth 通道', sub2api: 'Sub2API · 目标服务' };
    const subchecks = channel => !Array.isArray(channel.checks) ? '' : channel.checks.slice(0, 4).map(check => '<p>'
      + escape(({ node_oauth: 'token 接口出口', browser: '浏览器登录' })[check.id] || '子通道') + '：'
      + escape(check.ok ? '通过' : check.message || '未通过，请检查通道') + '</p>').join('');
    $('network-channels').innerHTML = channels.length ? channels.map((channel) => '<div class="network-item"><span class="channel-icon" aria-hidden="true">' + (icons[channel.id] || '↗') + '</span><div class="channel-copy"><strong>' + escape(channel.name || names[channel.id] || channel.id) + '</strong><p>' + escape(channel.message || (channel.ok ? '连接正常' : '检测未通过')) + '</p>' + subchecks(channel) + '</div>' + tag(channel.ok ? '已连通' + (Number.isFinite(channel.durationMs) ? ' · ' + channel.durationMs + ' ms' : '') : '需检查', channel.ok ? 'good' : 'warn') + '</div>').join('') : '<div class="empty-state compact">短信平台 · 邮箱 API · 登录 / OAuth<br>启动任务前将自动检测这三条通道。<br>现在也可以点击“重新检测”。</div>';
    $('network-updated').textContent = network?.checkedAt ? '最近检测 ' + date(network.checkedAt) + ' · 不租号、不发验证码' : '检测不会租号或发送验证码';
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
    const values = [['注册引擎', capabilities.registrationEnabled ? '已启用' : '未启用'], ['本地重新授权', capabilities.phase3Enabled ? '已启用' : '未启用'], ['Sub2API 管理连接', capabilities.sub2apiConfigured ? '已配置' : '未配置'], ['注册配置', registration.ready === true ? '检查通过' : registration.ready === false ? '需要补充' : '未检测']];
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
      $('log-storage').textContent = '日志文件 ' + state.logFiles.length + ' 个' + (Number.isFinite(result.totalBytes) ? ' · 合计 ' + (result.totalBytes / 1024 / 1024).toFixed(1) + ' MB' : '') + '。未选文件下载当前已加载记录；选定文件下载完整脱敏内容（上限 32 MB）。';
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
    document.title = PAGE_TITLES[state.page] + ' · Register Studio';
    if (state.page === 'logs' && state.connected) loadLogs();
  }
  async function preflight() {
    if (state.networkBusy) return;
    state.networkBusy = true; renderControls(); notice('正在按实际配置检测短信、邮箱与登录通道，不会租号或发送验证码。');
    try { const result = await request('/api/console/preflight', { method: 'POST', body: '{}' }); if (state.overview) state.overview.network = result; renderNetwork(result); notice(result.ok ? '网络预检通过；这只说明连接可用，不保证注册一定成功。' : '部分通道检测未通过，详细原因已显示。', result.ok ? 'success' : ''); }
    catch (error) { notice(errorText(error), 'error'); } finally { state.networkBusy = false; renderControls(); }
  }
  function report(task) { return Promise.resolve().then(task).catch((error) => notice(errorText(error), 'error')); }

  $('auth-dialog').addEventListener('cancel', (event) => event.preventDefault());
  $('auth-form').addEventListener('submit', (event) => { event.preventDefault(); report(async () => { try { saveToken($('admin-token').value); $('admin-token').value = ''; $('auth-dialog').close(); await refresh(); if (state.page === 'logs' && state.connected) await loadLogs(); } catch (error) { $('auth-error').textContent = errorText(error); } }); });
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
    const scope = ids ? '所选 ' + ids.length + ' 个远端账号（ID：' + ids.join('、') + '）' : '全部账号';
    if (!window.confirm('维护' + scope + '？\n\n' + (ids ? '• 仅处理上述远端 ID，不导入其他新账号' : '• 导入从未加入过的新账号') + '\n• 仅失效 / 过期 token 重新授权，额度耗尽等待恢复\n• 明确确认封禁后，删除对应 Sub2API 记录，本地保留履历\n• 网络故障和原因不明的账号不会被删除\n\n重新授权可能发送验证码。')) return;
    await mutate('/api/console/maintain', { ...(ids ? { accountIds: ids } : {}), importNew: !ids, refreshInvalid: true, deleteBanned: true });
  }
  $('maintain-all').addEventListener('click', () => report(() => maintain(false)));
  $('maintain-selected').addEventListener('click', () => report(() => maintain(true)));
  $('account-search').addEventListener('input', renderAccounts); $('account-filter').addEventListener('change', renderAccounts);
  $('select-all').addEventListener('change', () => { for (const account of filteredAccounts().filter(selectable)) { if ($('select-all').checked) state.selected.add(account.id); else state.selected.delete(account.id); } renderAccounts(); });
  $('account-rows').addEventListener('change', (event) => { const id = Number(event.target.dataset.accountId); if (!Number.isSafeInteger(id) || id <= 0) return; if (event.target.checked) state.selected.add(id); else state.selected.delete(id); renderAccounts(); });
  $('jobs').addEventListener('click', (event) => { const stop = event.target.closest('[data-stop-job]'); const logs = event.target.closest('[data-job-logs]'); if (logs) { $('log-job').value = logs.dataset.jobLogs; location.hash = 'logs'; if (state.page === 'logs') loadLogs(); } if (stop) report(async () => { if (window.confirm('停止这一个后台任务？\n已完成的注册或导入不会回滚，其他任务不受影响。')) await stopJob(stop.dataset.stopJob); }); });
  $('continuations').addEventListener('click', (event) => { const button = event.target.closest('[data-resume-index]'); if (!button) return; report(async () => { const item = state.continuations[Number(button.dataset.resumeIndex)]; if (!item?.eligible) throw new Error(item?.reason || '该记录不能继续'); if (!window.confirm('继续 ' + (item.email || item.phoneMasked || '所选本地账号') + '？\n从已有记录继续绑定邮箱 / 获取 token，不重新租号。可能发送验证码；成功后自动导入。')) return; await mutate('/api/console/register/resume', { selectedKey: item.selectedKey, revision: item.revision, autoImport: true }); }); });
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
  $('settings-form').addEventListener('submit', (event) => { event.preventDefault(); report(async () => {
    const enabled = $('automatic-maintenance').checked; const interval = Number($('maintenance-interval').value); const days = Number($('log-retention').value);
    if (!Number.isSafeInteger(interval) || interval < 5 || interval > 1440 || !Number.isSafeInteger(days) || days < 1 || days > 365) throw new Error('巡检间隔须为 5–1440 分钟，日志保留须为 1–365 天。');
    if (enabled && !state.overview?.settings?.policy?.enabled && !window.confirm('开启自动巡检？\n服务器将按设定间隔自动导入新账号、重新授权失效账号，并删除已明确确认封禁的远端记录。关闭网页不会停止巡检。')) return;
    await saveSettings({ revision: state.settingsRevision, confirm: enabled, policy: { ...state.overview.settings.policy, enabled, intervalMinutes: interval, logsRetentionDays: days } });
    state.settingsDirty = false; renderSettings();
  }); });
  $('registration-settings-form').addEventListener('input', () => { state.registrationDirty = true; });
  $('settings-reload').addEventListener('click', () => report(async () => {
    if ((state.settingsDirty || state.registrationDirty) && !window.confirm('重新读取配置会放弃未保存的修改，并清空新输入的密钥，是否继续？')) return;
    const settings = await request('/api/console/settings');
    if (!state.overview) throw new Error('工作台尚未完成首次同步。');
    state.overview.settings = settings; state.settingsDirty = false; state.registrationDirty = false; state.registrationRevision = null; renderSettings();
    notice('已重新读取服务端配置。', 'success');
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
  showPage(); renderControls(); refresh();
  state.pollTimer = setInterval(() => { if (!document.hidden && !$('auth-dialog').open) refresh(); }, 6000);
})();
