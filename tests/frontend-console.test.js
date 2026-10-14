const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'console.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'console.html'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'console.css'), 'utf8');
function harness() {
  const elements = new Map();
  const store = new Map();
  const calls = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { id, value: '', textContent: '', innerHTML: '', hidden: false, disabled: false, checked: false,
      options: [{ outerHTML: '<option value="">配置默认值</option>', value: '' }], dataset: {}, listeners: {}, classList: { toggle() {} },
      addEventListener(name, fn) { this.listeners[name] = fn; }, setAttribute() {}, removeAttribute() {}, focus() {},
      showModal() { this.open = true; }, close() { this.open = false; } });
    return elements.get(id);
  };
  const context = { console, Date, Headers, URLSearchParams, Uint8Array, AbortController,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {}, hidden: false },
    location: { hash: '#register' }, sessionStorage: { getItem: (key) => store.get(key) ?? null, setItem: (key, value) => store.set(key, value), removeItem: (key) => store.delete(key) },
    window: { crypto: { randomUUID: () => '12345678-1234-1234-1234-123456789012' }, confirm: () => true, addEventListener() {} },
    setInterval: () => 1, setTimeout: () => 1, clearTimeout() {},
    fetch: async (url, options) => { calls.push({ url, options }); return { ok: true, status: 200, text: async () => JSON.stringify({ readOnly: false, capabilities: { registrationEnabled: true, phase3Enabled: true, sub2apiConfigured: true }, accounts: [], jobs: [], reconciliation: { total: 0, returned: 0, truncated: false }, activeJobs: { total: 0, returned: 0, truncated: false }, summary: {}, settings: { revision: 'r1', policy: { enabled: false }, registration: { revision: 'g1', ready: true, phase3Ready: true, phase3Issues: [], fields: [] } } }) }; },
  };
  vm.createContext(context);
  const instrumented = source.replace('showPage(); renderControls(); refresh();', 'globalThis.harness = { state, validToken, pendingValid, persistPending, mutate, saveSettings, reconcileSettings, writeBlock, inventoryProblem, stopJob, preflight, filteredAccounts, renderAccounts, renderJobs, renderNetwork, renderSettings, renderControls, renderContinuations, request, date, escape, maintain, logQuery, loadLogs, refresh, openTaskDetail, renderTaskDetail, openAccountDetail, localTarget, renderLocalTokens, loadLocalTokens, updateLocalTokens, testSelected, loadProxies, saveImportProxy, renderProxySetting, proxySaveIssue, defaultProxyIssue };');
  vm.runInContext(instrumented, context);
  const api = context.harness;
  api.state.connected = true;
  api.state.overview = { readOnly: false, capabilities: { registrationEnabled: true, phase3Enabled: true, sub2apiConfigured: true }, accounts: [], jobs: [], reconciliation: { total: 0, returned: 0, truncated: false }, activeJobs: { total: 0, returned: 0, truncated: false }, summary: {}, settings: { revision: 'r1', policy: { enabled: false }, registration: { revision: 'g1', ready: true, phase3Ready: true, phase3Issues: [], fields: [] } } };
  return { context, api, element, store, calls };
}

test('console has four real pages, advanced diagnostics, no inline script or CDN', () => {
  for (const page of ['register', 'accounts', 'logs', 'settings']) assert.match(html, new RegExp('id="page-' + page + '"'));
  assert.match(html, /href="\/index.html"/);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>|\bonclick=|https?:\/\//);
  assert.match(css, /@media\(max-width:620px\)/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(html, /aria-live="polite"/);
});

test('console describes real engine and maintenance stages in Chinese', () => {
  const { api, element } = harness();
  for (const stage of ['checking_network', 'network_preflight', 'phase1_register', 'phase1_5_profile', 'phase2_bind_email', 'phase3_email_oauth',
    'planning', 'refreshing', 'updating_token', 'verifying_account', 'removing_banned', 'maintaining', 'importing_new']) {
    api.state.overview.jobs = [{ id: 'job_stage', type: 'console_register', status: 'running', stage, summary: {} }];
    api.renderJobs();
    assert.equal(element('jobs').innerHTML.includes(stage), false, 'Internal stage IDs are not user-facing instructions');
    assert.match(element('jobs').innerHTML, /[\u4e00-\u9fff]/);
  }
  api.state.overview.jobs = [{ id: 'job_preflight', type: 'console_resume', status: 'failed', stage: 'failed', failureStage: 'network_preflight', summary: {}, error: 'synthetic connection error' }];
  api.renderJobs(); assert.match(element('jobs').innerHTML, /失败阶段：<\/strong>连接预检/);
});

test('console failed import keeps successful registration counts visible with failure stage and recovery guidance', () => {
  const { api, element } = harness();
  api.state.overview.jobs = [{ id: 'job_import_fixture', type: 'console_register', status: 'failed', stage: 'failed',
    summary: { registered: 1, imported: 0, failed: 0 }, error: '目标服务连接失败', failureStage: 'importing', nextAction: 'import_existing',
    recoveryMessage: '注册已成功，不要重新注册；核对导入结果后处理现有 token。' }];
  api.renderJobs();
  const rendered = element('jobs').innerHTML;
  assert.match(rendered, /注册成功 1 · 导入 0 · 账号步骤失败 0/);
  assert.match(rendered, /失败阶段：<\/strong>导入 Sub2API/); assert.match(rendered, /失败原因：<\/strong>目标服务连接失败/);
  assert.match(rendered, /注册已成功，不要重新注册/); assert.match(rendered, /class="tag bad">失败/);
  assert.doesNotMatch(rendered, /import_existing|aria-hidden="true">✓/);
});

test('console job failure and recovery messages are escaped without hiding string summaries or bypassing holds', () => {
  const { api, element } = harness();
  api.state.overview.jobs = [{ id: 'job_unknown_fixture', type: 'console_register', status: 'failed', stage: 'failed',
    summary: '部分步骤已完成', error: { message: '<script>unknown fixture</script>' }, failureStage: '<img src=x>',
    recoveryMessage: '先核对外部结果 <script>recovery fixture</script>' }];
  api.state.overview.reconciliation = { total: 1, returned: 1, truncated: false };
  api.renderJobs(); api.renderControls();
  const rendered = element('jobs').innerHTML;
  assert.match(rendered, /部分步骤已完成/); assert.match(rendered, /失败阶段：<\/strong>执行步骤/);
  assert.match(rendered, /&lt;script&gt;unknown fixture/); assert.match(rendered, /先核对外部结果 &lt;script&gt;/);
  assert.doesNotMatch(rendered, /<script>|<img/);
  assert.equal(element('start-register').disabled, true); assert.match(api.writeBlock(), /人工对账/);
});

test('console distinguishes token transport from browser access without hiding a failed subchannel', () => {
  const { api, element } = harness();
  api.renderNetwork({ channels: [{ id: 'oauth', ok: false, checks: [
    { id: 'node_oauth', ok: true }, { id: 'browser', ok: false, message: '访问挑战 <script>unsafe</script>' },
  ] }] });
  assert.match(element('network-channels').innerHTML, /token 接口出口：通过/);
  assert.match(element('network-channels').innerHTML, /浏览器登录：访问挑战/);
  assert.match(element('network-channels').innerHTML, /需检查/);
  assert.doesNotMatch(element('network-channels').innerHTML, /<script>/);
});

test('console refuses non-ASCII, whitespace and short auth tokens before Headers', () => {
  const { api } = harness();
  assert.equal(api.validToken('a'.repeat(16)), true);
  for (const value of ['short', '中文'.repeat(20), ' '.repeat(16), 'a'.repeat(16) + '\n', 'a'.repeat(4097)]) assert.equal(api.validToken(value), false);
});

test('console fails closed for unknown, disconnected and read-only operation state', () => {
  const { api, element } = harness();
  for (const alter of [() => { api.state.connected = false; }, () => { api.state.overview.readOnly = true; }, () => { api.state.storageError = true; }]) {
    api.state.connected = true; api.state.overview.readOnly = false; api.state.storageError = false; alter(); api.renderControls();
    assert.ok(api.writeBlock()); assert.equal(element('start-register').disabled, true); assert.equal(element('maintain-all').disabled, true);
  }
});

test('console saves durable idempotency key before first mutation and reuses it after unknown response', async () => {
  const { context, api, calls, store } = harness();
  context.fetch = async (url, options) => { assert.ok(store.has('registerStudio.pending.v1')); calls.push({ url, options }); throw new Error('connection lost'); };
  await assert.rejects(api.mutate('/api/console/register', { count: 1, autoImport: true }), /connection lost/);
  const persisted = JSON.parse(store.get('registerStudio.pending.v1'));
  assert.equal(persisted.body.count, 1);
  await assert.rejects(api.mutate('/api/console/register', { count: 2, autoImport: true }), /上一条/);
  await assert.rejects(api.mutate(null, null, { replay: true }), /connection lost/);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.headers.get('Idempotency-Key'), calls[1].options.headers.get('Idempotency-Key'));
  assert.equal(calls[0].options.body, calls[1].options.body);
});

test('console does not replay expired pending mutation or an unknown successful receipt', async () => {
  const { context, api, calls } = harness();
  context.fetch = async (url, options) => { calls.push({ url, options }); return { ok: true, status: 200, text: async () => '{"ok":true}' }; };
  await assert.rejects(api.mutate('/api/console/register', { count: 1, autoImport: true }), /结果尚未确认/);
  assert.ok(api.state.pending);
  api.state.pending.createdAt = Date.now() - 21 * 60 * 60 * 1000;
  await assert.rejects(api.mutate(null, null, { replay: true }), /安全核对时限/);
  assert.equal(calls.length, 1);
});

test('console cannot submit if session persistence silently fails', async () => {
  const { context, api, calls } = harness();
  context.sessionStorage.setItem = () => {};
  await assert.rejects(api.mutate('/api/console/register', { count: 1, autoImport: true }), /无法安全保存/);
  assert.equal(calls.length, 0);
});

test('console selected maintenance freezes exact IDs with explicit deletion confirmation', async () => {
  const { context, api, calls } = harness();
  let confirmation;
  context.window.confirm = (message) => { confirmation = message; return false; };
  api.state.selected.add(187); api.state.selected.add(160);
  await api.maintain(true);
  assert.match(confirmation, /160、187/); assert.match(confirmation, /明确确认封禁/); assert.match(confirmation, /额度耗尽等待恢复/);
  assert.equal(calls.length, 0);
});

test('console filters account classes without losing or silently enlarging selection', () => {
  const { api, element } = harness();
  api.state.overview.accounts = [{ id: 1, name: 'free00001', classification: 'healthy' }, { id: 2, name: 'free00002', classification: 'quota_wait' }, { id: 3, name: 'free00003', classification: 'expired' }];
  api.state.selected.add(1); element('account-filter').value = 'refresh';
  assert.deepEqual(Array.from(api.filteredAccounts(), (account) => account.id), [3]);
  api.renderAccounts(); assert.equal(api.state.selected.has(1), true); assert.equal(api.state.selected.has(3), false);
});

test('console never treats unknown classification as healthy or unconfirmed ban', () => {
  const { api, element } = harness();
  api.state.overview.accounts = [{ id: 1, classification: 'unknown_failure', name: '<img src=x onerror=alert(1)>' }]; element('account-filter').value = 'all';
  api.renderAccounts(); assert.match(element('account-rows').innerHTML, /需要核对/); assert.doesNotMatch(element('account-rows').innerHTML, /<img/);
});

test('console escapes job and network messages and never fabricates network success', () => {
  const { api, element } = harness();
  api.state.overview.jobs = [{ id: 'job_1', type: 'register', status: 'failed', error: '<script>bad</script>' }]; api.renderJobs();
  assert.doesNotMatch(element('jobs').innerHTML, /<script>/);
  api.renderNetwork(null); assert.equal((element('network-channels').innerHTML.match(/未检测/g) || []).length, 4); assert.doesNotMatch(element('network-channels').innerHTML, /已连通/);
  assert.match(element('network-updated').textContent, /启动任务前按所需通道预检/);
  api.renderNetwork({ channels: [{ id: 'sms', name: '短信', ok: false, message: '<img src=x>' }] });
  assert.match(element('network-channels').innerHTML, /需检查/); assert.doesNotMatch(element('network-channels').innerHTML, /<img/);
});

test('console secret registration fields never echo even if server accidentally supplies a value', () => {
  const { api, element } = harness();
  api.state.overview.settings.registration.fields = [{ key: 'sms.key', label: '短信密钥', secret: true, configured: true, value: 'DO_NOT_ECHO_FIXTURE' }];
  api.renderSettings(); assert.doesNotMatch(element('registration-fields').innerHTML, /DO_NOT_ECHO_FIXTURE/); assert.match(element('registration-fields').innerHTML, /type="password"/);
});

test('console UI does not use localStorage or auto-submit queued work on polls', () => {
  assert.doesNotMatch(source, /localStorage/);
  assert.match(source, /setInterval\(\(\) => \{ if \(!document.hidden && !\$\('auth-dialog'\).open\) refresh\(\); \}, 6000\)/);
  assert.match(source, /MAX_REPLAY_AGE = 20/);
});

test('console config secrets never persist and an uncertain save is checked read-only by request ID', async () => {
  const { context, api, store, calls } = harness();
  const changes = { sms_key: 'TEST_SECRET_NO_STORAGE' };
  context.fetch = async (url, options) => { calls.push({ url, options }); throw new Error('response lost'); };
  await assert.rejects(api.saveSettings({ revision: 'r1', registration: { revision: 'g1', changes } }), /response lost/);
  assert.doesNotMatch(store.get('registerStudio.pending.v1'), /TEST_SECRET_NO_STORAGE/);
  assert.deepEqual(changes, {});
  const requestId = api.state.pending.body.registration.requestId;
  context.fetch = async (url, options) => {
    calls.push({ url, options }); assert.equal(options.method, undefined);
    return { ok: true, status: 200, text: async () => JSON.stringify({ revision: 'r2', policy: {}, registration: { revision: 'g2', fields: [], lastRequestId: requestId } }) };
  };
  await api.mutate(null, null, { replay: true });
  assert.equal(calls.length, 2); assert.equal(calls[1].url, '/api/console/settings'); assert.equal(api.state.pending, null);
});

test('console config version change alone cannot falsely confirm a secret write', async () => {
  const { context, api } = harness();
  context.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ revision: 'r2', registration: { revision: 'g2', lastRequestId: 'another-request' } }) });
  await assert.rejects(api.saveSettings({ revision: 'r1', registration: { revision: 'g1', changes: { key: 'FIXTURE' } } }), /尚不能确认/);
  assert.ok(api.state.pending);
});

test('console stop accepts stopping receipt without enqueueing a second task', async () => {
  const { context, api, calls } = harness();
  const jobId = 'job_' + 'a'.repeat(24);
  const originalFetch = context.fetch;
  context.fetch = async (url, options) => {
    if (url.includes('/stop')) { calls.push({ url, options }); return { ok: true, status: 202, text: async () => JSON.stringify({ jobId, status: 'stopping' }) }; }
    return originalFetch(url, options);
  };
  await api.mutate('/api/console/jobs/' + jobId + '/stop', {});
  assert.equal(api.state.pending, null);
  assert.equal(calls.filter((call) => call.options.method === 'POST').length, 1);
});

test('console selected maintenance never imports accounts outside selected IDs', async () => {
  const { context, api, calls } = harness();
  api.state.selected.add(160);
  context.fetch = async (url, options) => { calls.push({ url, options }); throw new Error('offline fixture'); };
  await assert.rejects(api.maintain(true), /offline fixture/);
  assert.deepEqual(JSON.parse(calls[0].options.body), { accountIds: [160], importNew: false, refreshInvalid: true, deleteBanned: true });
});

test('console models exact backend auth, ban and manual-disable classification', () => {
  const { api, element } = harness();
  api.state.overview.accounts = [{ id: 1, classification: 'auth_invalid' }, { id: 2, classification: 'confirmed_banned' }, { id: 3, classification: 'manual_disabled' }, { id: 4, classification: 'network_unknown' }];
  for (const [filter, ids] of [['refresh', [1]], ['banned', [2]], ['review', [3, 4]]]) { element('account-filter').value = filter; assert.deepEqual(Array.from(api.filteredAccounts(), (account) => account.id), ids); }
});

test('console unavailable snapshot blocks register and maintenance but still allows diagnosis', () => {
  const { api, element } = harness(); api.state.overview.capabilities.comparisonAvailable = false; api.renderControls();
  assert.equal(element('start-register').disabled, true); assert.equal(element('maintain-all').disabled, true); assert.equal(element('check-network').disabled, false);
});

test('console resumes frozen record with persistent idempotency and displays ineligible reason', async () => {
  const { context, api, calls, element } = harness();
  api.state.continuations = [{ selectedKey: 'username:1', revision: 'revision-1', stage: 'phase3', eligible: false, reason: '账号已停用' }];
  api.renderContinuations(); assert.match(element('continuations').innerHTML, /账号已停用/); assert.match(element('continuations').innerHTML, /disabled/);
  context.fetch = async (url, options) => { calls.push({ url, options }); throw new Error('lost receipt'); };
  await assert.rejects(api.mutate('/api/console/register/resume', { selectedKey: 'username:1', revision: 'revision-1', autoImport: true }), /lost receipt/);
  await assert.rejects(api.mutate(null, null, { replay: true }), /lost receipt/);
  assert.equal(calls[0].options.body, calls[1].options.body); assert.equal(calls[0].options.headers.get('Idempotency-Key'), calls[1].options.headers.get('Idempotency-Key'));
});

test('console marks verified legacy email repairs and blocking continuations without auto-submitting', () => {
  const { api, element, calls } = harness();
  api.state.continuations = [{ selectedKey: 'registration:accounts:0', revision: 'a'.repeat(64), stage: 'phase3',
    email: 'synthetic@example.test', eligible: true, repairEmail: true, blockingRegistration: true }];
  api.renderContinuations();
  assert.match(element('continuations').innerHTML, /本地两份资料已核验，续跑时补齐历史邮箱/);
  assert.match(element('continuations').innerHTML, /此记录阻挡新注册，优先继续/);
  assert.doesNotMatch(element('continuations').innerHTML, /disabled/); assert.equal(calls.length, 0);
  api.state.continuations[0].repairEmail = false; api.state.continuations[0].blockingRegistration = false;
  api.renderContinuations(); assert.doesNotMatch(element('continuations').innerHTML, /已核验|阻挡新注册/);
});

test('console Phase3 continuation uses explicit scoped readiness without requiring SMS configuration', async () => {
  const { api, context, element, calls } = harness();
  api.state.overview.settings.registration = { ready: false, issues: ['缺少短信 API Key'], phase3Ready: true, phase3Issues: [] };
  api.state.continuations = [
    { selectedKey: 'registration:accounts:0', revision: 'a'.repeat(64), stage: 'phase3', eligible: true },
    { selectedKey: 'registration:accounts:1', revision: 'b'.repeat(64), stage: 'phase2', eligible: true },
  ];
  const buttons = api.state.continuations.map((_, index) => ({ dataset: { resumeIndex: String(index) } }));
  context.document.querySelectorAll = selector => selector === '[data-resume-index]' ? buttons : [];
  api.renderContinuations();
  assert.equal(buttons[0].disabled, false); assert.equal(buttons[1].disabled, true); assert.equal(element('start-register').disabled, true);
  assert.match(element('continuation-hint-0').textContent, /无需短信配置/); assert.match(element('continuation-hint-1').textContent, /注册配置不完整/);
  assert.equal(calls.length, 0);
  context.fetch = async (url, options) => { calls.push({ url, options }); throw new Error('synthetic lost response'); };
  await element('continuations').listeners.click({ target: { closest: () => buttons[0] } });
  assert.deepEqual(JSON.parse(calls[0].options.body), { selectedKey: 'registration:accounts:0', revision: 'a'.repeat(64), autoImport: true });
  assert.equal(calls[0].url, '/api/console/register/resume');
});

test('console Phase3 continuation never infers readiness from full registration readiness or missing issues', async () => {
  for (const registration of [
    { ready: true }, { ready: true, phase3Ready: false, phase3Issues: ['缺少邮箱鉴权配置'] },
    { ready: false, phase3Ready: false, phase3Issues: ['OAuth 代理配置无效'] },
  ]) {
    const { api, context, element, calls } = harness();
    api.state.overview.settings.registration = registration;
    api.state.continuations = [{ selectedKey: 'registration:accounts:0', revision: 'a'.repeat(64), stage: 'phase3', eligible: true }];
    const button = { dataset: { resumeIndex: '0' } };
    context.document.querySelectorAll = selector => selector === '[data-resume-index]' ? [button] : [];
    api.renderContinuations(); assert.equal(button.disabled, true);
    assert.match(element('continuation-hint-0').textContent, registration.phase3Ready === false ? /Phase3 配置不完整/ : /尚未确认 Phase3 配置/);
    if (registration.phase3Issues) assert.ok(element('continuation-hint-0').textContent.includes(registration.phase3Issues[0]));
    await element('continuations').listeners.click({ target: { closest: () => button } }); assert.equal(calls.length, 0);
  }
});

test('console scoped Phase3 readiness preserves all write, identity and global task guards', () => {
  const blockers = [
    api => { api.state.connected = false; }, api => { api.state.storageError = true; }, api => { api.state.busy = true; },
    api => { api.state.pending = { url: '/api/console/settings' }; }, api => { api.state.networkBusy = true; },
    api => { api.state.overview.readOnly = true; }, api => { api.state.overview.reconciliation = { total: 1, returned: 1, truncated: false }; },
    api => { api.state.overview.activeJobs = { total: 1, returned: 1, truncated: false }; }, api => { delete api.state.overview.activeJobs; },
    api => { api.state.overview.capabilities.comparisonAvailable = false; }, api => { api.state.overview.capabilities.phase3Enabled = false; },
    api => { api.state.overview.capabilities.registrationEnabled = false; }, api => { api.state.continuations[0].eligible = false; },
  ];
  for (const block of blockers) {
    const { api, context, element } = harness();
    api.state.overview.settings.registration.ready = false;
    api.state.continuations = [{ stage: 'phase3', eligible: true }];
    const button = { dataset: { resumeIndex: '0' } };
    context.document.querySelectorAll = selector => selector === '[data-resume-index]' ? [button] : [];
    block(api); api.renderControls();
    assert.equal(button.disabled, true); assert.ok(button.title); assert.ok(element('continuation-hint-0').textContent);
  }
});

test('console log browsing and download use returned opaque file IDs not server paths', () => {
  const { api, element } = harness(); element('log-file').value = 'f'.repeat(32); element('log-source').value = 'panel';
  assert.equal(api.logQuery().get('fileId'), 'f'.repeat(32)); assert.equal(api.logQuery().get('source'), 'panel');
  assert.match(source, /state\.logFiles\.some\(\(file\) => file\.id === fileId\)/); assert.doesNotMatch(source, /download\?path=/);
});

test('console direct logs entry and reconnection load logs without resetting pagination on ordinary polls', async () => {
  const { api, context, calls } = harness();
  const overview = structuredClone(api.state.overview);
  api.state.connected = false; api.state.page = 'logs';
  context.fetch = async (url, options) => {
    calls.push({ url, options });
    const body = url === '/api/console/overview' ? overview : url.includes('/continuations') ? { items: [] }
      : { entries: [{ message: 'synthetic log' }], files: [], nextCursor: 'fixture-cursor' };
    return { ok: true, status: 200, text: async () => JSON.stringify(body) };
  };
  await api.refresh();
  assert.equal(calls.filter(call => call.url.startsWith('/api/console/logs?')).length, 1);
  assert.equal(api.state.logs.length, 1); assert.equal(api.state.nextCursor, 'fixture-cursor');
  await api.refresh();
  assert.equal(calls.filter(call => call.url.startsWith('/api/console/logs?')).length, 1);
  api.state.connected = false; await api.refresh();
  assert.equal(calls.filter(call => call.url.startsWith('/api/console/logs?')).length, 2);
  assert.ok(calls.every(call => call.options.method === undefined));
});

test('console task log shortcut clears previous file and search filters instead of hiding the chosen task', async () => {
  const { api, context, calls, element } = harness();
  api.state.page = 'logs'; api.state.nextCursor = 'old-file-cursor';
  for (const [id, value] of [['log-source', 'panel'], ['log-level', 'error'], ['log-file', 'old-file'], ['log-query', 'old-message']]) element(id).value = value;
  const jobId = 'job_' + 'a'.repeat(24);
  context.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, text: async () => JSON.stringify({ entries: [], files: [], nextCursor: null }) };
  };
  element('jobs').listeners.click({ target: { closest: selector => selector === '[data-job-logs]' ? { dataset: { jobLogs: jobId } } : null } });
  const query = new URL(calls[0].url, 'http://localhost').searchParams;
  assert.equal(query.get('jobId'), jobId);
  for (const key of ['fileId', 'source', 'level', 'q', 'cursor']) assert.equal(query.has(key), false, key);
  assert.equal(api.state.nextCursor, null);
});

test('console log binding gaps are shown as plain text and cleared when the next response has no notice', async () => {
  const { api, context, element } = harness();
  const bindingNotice = '未找到与该任务绑定的注册机日志。请清空任务筛选后按文件查看，不会按时间猜测归属。 <script>fixture</script>';
  let report = { entries: [], files: [], nextCursor: null, bindingNotice };
  context.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify(report) });
  await api.loadLogs();
  assert.ok(element('log-storage').textContent.endsWith(bindingNotice)); assert.equal(element('log-storage').innerHTML, '');
  report = { entries: [], files: [], nextCursor: null };
  await api.loadLogs(); assert.doesNotMatch(element('log-storage').textContent, /未找到与该任务|fixture/);
  report.bindingNotice = { message: 'wrong schema' };
  await api.loadLogs(); assert.doesNotMatch(element('log-storage').textContent, /object Object|wrong schema/);
});

test('console reports bounded log scan coverage without claiming all matching files were read', async () => {
  const { api, context, element } = harness();
  let searchScope = { scannedFiles: 8, matchingFiles: 12, omittedFiles: 4 };
  context.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ entries: [], files: [], nextCursor: null, searchScope }) });
  await api.loadLogs(); assert.match(element('log-storage').textContent, /本次仅扫描 8 \/ 12 个匹配文件，较早日志请按文件查看/);
  for (const scope of [{ scannedFiles: 8, matchingFiles: 8, omittedFiles: 0 }, { scannedFiles: 8, matchingFiles: 12, omittedFiles: 0 }, { scannedFiles: '8', matchingFiles: 12, omittedFiles: 4 }, null]) {
    searchScope = scope; await api.loadLogs(); assert.doesNotMatch(element('log-storage').textContent, /本次仅扫描/);
  }
});

test('console keeps policy edit revision frozen while background snapshots advance', () => {
  const { api } = harness();
  api.renderSettings(); assert.equal(api.state.settingsRevision, 'r1');
  api.state.settingsDirty = true; api.state.overview.settings.revision = 'r2'; api.renderSettings();
  assert.equal(api.state.settingsRevision, 'r1');
});

test('console rejected settings CAS can be corrected without an unknown-write deadlock', async () => {
  const { api, context } = harness();
  context.fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ error: 'CONSOLE_SETTINGS_STALE', message: 'settings changed' }) });
  await assert.rejects(api.saveSettings({ revision: 'r1', policy: { enabled: false } }), /settings changed/);
  assert.equal(api.state.pending, null);
});

test('console definite active-task settings conflict unlocks the rejected request and permits a later save', async () => {
  const { api, context, store, calls, element } = harness();
  const body = { revision: 'r1', policy: { enabled: false, intervalMinutes: 60 } };
  context.fetch = async (url, options) => {
    calls.push({ url, options });
    assert.ok(store.has('registerStudio.pending.v1'));
    return { ok: false, status: 409, text: async () => JSON.stringify({ error: 'CONSOLE_SETTINGS_ACTIVE_CONFLICT', message: '后台任务仍在执行，请先停止或等待完成后再修改设置' }) };
  };
  await assert.rejects(api.saveSettings(body), /后台任务仍在执行/);
  assert.equal(api.state.pending, null); assert.equal(store.has('registerStudio.pending.v1'), false);
  assert.equal(api.state.busy, false); assert.equal(element('settings-save').disabled, false);
  context.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, text: async () => JSON.stringify({ revision: 'r2', policy: body.policy, registration: { revision: 'g1', fields: [] } }) };
  };
  await api.saveSettings(body);
  assert.equal(api.state.pending, null); assert.equal(store.has('registerStudio.pending.v1'), false);
  assert.deepEqual(calls.map((call) => call.options.method || 'GET'), ['POST', 'POST', 'GET']);
  assert.equal(api.state.overview.settings.policy.intervalMinutes, 60);
});

test('console active-task settings rejection discards secret input without leaving a pending lock', async () => {
  const { api, context, store } = harness();
  const changes = { sms_key: 'SYNTHETIC_SECRET_NOT_FOR_STORAGE' };
  context.fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ code: 'CONSOLE_SETTINGS_ACTIVE_CONFLICT', message: '任务执行中' }) });
  await assert.rejects(api.saveSettings({ revision: 'r1', registration: { revision: 'g1', changes } }), /任务执行中/);
  assert.deepEqual(changes, {}); assert.equal(api.state.pending, null); assert.equal(store.has('registerStudio.pending.v1'), false);
});

test('console unknown settings conflicts and explicit unknown outcomes retain their original receipt', async () => {
  for (const response of [
    { error: 'CONSOLE_SETTINGS_OTHER_CONFLICT' },
    { error: 'CONSOLE_SETTINGS_WRITE_UNKNOWN' },
    { error: 'CONSOLE_SETTINGS_ACTIVE_CONFLICT', writeOutcomeUnknown: true },
  ]) {
    const { api, context, store, calls } = harness();
    context.fetch = async (url, options) => { calls.push({ url, options }); return { ok: false, status: 409, text: async () => JSON.stringify({ ...response, message: '保存结果未知' }) }; };
    await assert.rejects(api.saveSettings({ revision: 'r1', policy: { enabled: false, intervalMinutes: 60 } }), /保存结果未知/);
    const encoded = store.get('registerStudio.pending.v1'); assert.ok(encoded); assert.ok(api.writeBlock());
    context.fetch = async (url, options) => {
      calls.push({ url, options });
      return { ok: true, status: 200, text: async () => JSON.stringify({ revision: 'r1', policy: { enabled: false, intervalMinutes: 30 }, registration: { revision: 'g1', fields: [] } }) };
    };
    await assert.rejects(api.mutate(null, null, { replay: true }), /尚不能确认/);
    assert.equal(store.get('registerStudio.pending.v1'), encoded); assert.deepEqual(calls.map((call) => call.options.method || 'GET'), ['POST', 'GET']);
  }
});

test('console active-conflict exception cannot clear another operation or an accepted settings write', async () => {
  const { api, context, store } = harness();
  const conflict = () => ({ ok: false, status: 409, text: async () => JSON.stringify({ error: 'CONSOLE_SETTINGS_ACTIVE_CONFLICT', message: 'conflict fixture' }) });
  context.fetch = async () => conflict();
  await assert.rejects(api.mutate('/api/console/maintain', { importNew: true, refreshInvalid: true, deleteBanned: true }), /conflict fixture/);
  assert.ok(api.state.pending); assert.ok(store.has('registerStudio.pending.v1'));
  const other = harness();
  other.context.fetch = async (url, options) => options.method === 'POST' ? { ok: true, status: 200, text: async () => '{}' } : conflict();
  await assert.rejects(other.api.saveSettings({ revision: 'r1', policy: { enabled: false } }), /conflict fixture/);
  assert.ok(other.api.state.pending); assert.ok(other.store.has('registerStudio.pending.v1'));
});

test('console legacy settings pending stays read-only and reload explains that it does not resolve the receipt', async () => {
  const { api, context, store, calls, element } = harness();
  api.persistPending({ version: 1, url: '/api/console/settings', key: 'idem_v1_' + 'e'.repeat(32), createdAt: Date.now(), body: { revision: 'r1', policy: { intervalMinutes: 60 } } });
  const encoded = store.get('registerStudio.pending.v1');
  context.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, text: async () => JSON.stringify({ revision: 'r1', policy: { intervalMinutes: 30 }, registration: { revision: 'g1', fields: [] } }) };
  };
  await assert.rejects(api.mutate(null, null, { replay: true }), /请求时间.*核对服务端操作日志后人工恢复/);
  await element('settings-reload').listeners.click();
  assert.equal(store.get('registerStudio.pending.v1'), encoded); assert.ok(api.state.pending);
  assert.match(element('notice').textContent, /不会解除待核对记录/);
  assert.notEqual(element('notice').className, 'notice success');
  assert.equal(element('settings-save').disabled, true);
  assert.deepEqual(calls.map((call) => [call.url, call.options.method || 'GET']), [['/api/console/settings', 'GET'], ['/api/console/settings', 'GET']]);
});

test('console actual update action overrides classification label when identity requires review', () => {
  const { api, element } = harness(); element('account-filter').value = 'all';
  api.state.overview.accounts = [{ id: 42, classification: 'expired', action: 'review', reason: 'strong_identity_ambiguous' }];
  api.renderAccounts(); assert.match(element('account-rows').innerHTML, /<td>人工核对<\/td>/);
  api.openAccountDetail(0); assert.match(element('account-detail').innerHTML, /强身份缺失或匹配不唯一/);
});

test('console permission failure during uncertain receipt recovery cannot discard original key', async () => {
  const { api, context, store } = harness();
  context.fetch = async () => { throw new Error('receipt lost'); };
  await assert.rejects(api.mutate('/api/console/register', { count: 1, country: 'GB', autoImport: true }), /receipt lost/);
  const key = api.state.pending.key;
  context.fetch = async () => ({ ok: false, status: 403, text: async () => JSON.stringify({ error: 'write_disabled', message: 'read-only' }) });
  await assert.rejects(api.mutate(null, null, { replay: true }), /read-only/);
  assert.equal(api.state.pending.key, key); assert.ok(store.has('registerStudio.pending.v1'));
});

test('console preserves config recovery receipt if follow-up read loses authorization', async () => {
  const { api, context } = harness();
  context.fetch = async (url, options) => options.method === 'POST'
    ? { ok: true, status: 200, text: async () => '{}' }
    : { ok: false, status: 403, text: async () => JSON.stringify({ error: 'unauthorized', message: 'auth expired' }) };
  await assert.rejects(api.saveSettings({ revision: 'r1', policy: { enabled: false } }), /auth expired/);
  assert.ok(api.state.pending);
});

test('console distinguishes disabled writes from expired administrator authentication', async () => {
  const { api, context, element } = harness();
  context.fetch = async () => ({ ok: false, status: 403, text: async () => JSON.stringify({ error: 'write_disabled', message: 'writes disabled' }) });
  await assert.rejects(api.request('/api/console/register'), /writes disabled/);
  assert.notEqual(element('auth-dialog').open, true);
});

test('console reconciliation holds are visible and block all new writes but not read-only checks', () => {
  const { api, element } = harness();
  api.state.overview.reconciliation = { total: 2, returned: 2, truncated: false };
  api.renderControls();
  assert.match(api.writeBlock(), /2 个任务.*人工对账/);
  for (const id of ['start-register', 'maintain-all', 'settings-save', 'registration-settings-save', 'logs-cleanup']) assert.equal(element(id).disabled, true, id);
  assert.equal(element('task-safety-banner').hidden, false); assert.match(element('task-safety-title').textContent, /2 个任务需要人工对账/);
  assert.match(element('task-safety-message').textContent, /刷新或重新登录不会解除/);
  assert.equal(element('check-network').disabled, false); assert.equal(element('logs-refresh').disabled, false);
  assert.match(html, /id="task-safety-banner"[\s\S]*?href="\/index.html"/);
});

test('console incomplete, truncated or inconsistent task inventory fails closed', () => {
  for (const value of [undefined, { total: 0 }, { total: 1, returned: 0, truncated: true }, { total: 1, returned: 0, truncated: false }, { total: 0, returned: 1, truncated: false }, { total: '0', returned: 0, truncated: false }]) {
    for (const key of ['reconciliation', 'activeJobs']) {
      const { api, element } = harness(); api.state.overview[key] = value; api.renderControls();
      assert.ok(api.inventoryProblem()); assert.equal(element('start-register').disabled, true); assert.equal(element('task-safety-banner').hidden, false);
      assert.equal(element('check-network').disabled, false);
    }
  }
  const { api } = harness(); api.state.overview.jobs = [{ id: 'job_' + 'a'.repeat(24), status: 'running' }];
  assert.match(api.inventoryProblem(), /活动任务与计数不一致/);
});

test('console active task stops remain available in read-only mode with a global hold', async () => {
  const { api, context, calls, element } = harness();
  const jobId = 'job_' + 'a'.repeat(24);
  api.state.overview.jobs = [{ id: jobId, status: 'running' }];
  api.state.overview.readOnly = true;
  api.state.overview.reconciliation = { total: 1, returned: 1, truncated: false };
  api.state.overview.activeJobs = { total: 1, returned: 1, truncated: false };
  const stopButton = { dataset: { stopJob: jobId }, disabled: true };
  context.document.querySelectorAll = (selector) => selector === '[data-stop-job]' ? [stopButton] : [];
  api.renderControls(); assert.equal(stopButton.disabled, false); assert.equal(element('maintain-all').disabled, true);
  const originalFetch = context.fetch;
  context.fetch = async (url, options) => {
    if (url.endsWith('/stop')) { calls.push({ url, options }); return { ok: true, status: 202, text: async () => JSON.stringify({ jobId, status: 'stopping' }) }; }
    return originalFetch(url, options);
  };
  await api.stopJob(jobId);
  assert.equal(calls.filter((call) => call.options.method === 'POST').length, 1);
  assert.equal(api.state.pending, null);
});

test('console stop never replaces an uncertain submission receipt or requires writable session storage', async () => {
  const { api, context, store } = harness();
  const jobId = 'job_' + 'b'.repeat(24);
  api.state.overview.jobs = [{ id: jobId, status: 'running' }];
  const pending = { version: 1, url: '/api/console/register', key: 'idem_v1_' + 'c'.repeat(32), body: { count: 1, country: 'CL', autoImport: true }, createdAt: Date.now() };
  api.persistPending(pending);
  const encoded = store.get('registerStudio.pending.v1');
  api.state.storageError = true; api.state.busy = true;
  context.sessionStorage.setItem = () => { throw new Error('must not persist stop'); };
  const originalFetch = context.fetch;
  context.fetch = async (url, options) => url.endsWith('/stop') ? { ok: true, status: 202, text: async () => JSON.stringify({ jobId, status: 'stopping' }) } : originalFetch(url, options);
  await api.stopJob(jobId);
  assert.equal(store.get('registerStudio.pending.v1'), encoded); assert.equal(api.state.pending.key, pending.key);
});

test('console stopping rejects mismatched receipts and never retargets another task', async () => {
  const { api, context, calls } = harness(); const jobId = 'job_' + 'c'.repeat(24);
  api.state.overview.jobs = [{ id: jobId, status: 'running' }];
  context.fetch = async (url, options) => { calls.push({ url, options }); return { ok: true, status: 202, text: async () => JSON.stringify({ jobId: 'job_' + 'd'.repeat(24), status: 'stopping' }) }; };
  await assert.rejects(api.stopJob(jobId), /停止回执无法确认/);
  assert.equal(calls[0].url, '/api/console/jobs/' + jobId + '/stop'); assert.equal(api.state.stoppingJobs.size, 0);
  await assert.rejects(api.stopJob('job_' + 'e'.repeat(24)), /不在已读取的清单/); assert.equal(calls.length, 1);
});

test('console settings reload recovers stale edits only after explicit discard confirmation', async () => {
  const { api, context, element, calls } = harness(); api.state.settingsDirty = true; api.state.registrationDirty = true;
  context.window.confirm = () => false; await element('settings-reload').listeners.click(); assert.equal(calls.length, 0); assert.equal(api.state.settingsDirty, true);
  context.window.confirm = () => true;
  context.fetch = async (url, options) => { calls.push({ url, options }); return { ok: true, status: 200, text: async () => JSON.stringify({ revision: 'r2', policy: { enabled: false }, registration: { revision: 'g2', fields: [] } }) }; };
  await element('settings-reload').listeners.click(); assert.equal(calls[0].url, '/api/console/settings'); assert.equal(calls[0].options.method, undefined);
  assert.equal(api.state.settingsDirty, false); assert.equal(api.state.registrationDirty, false); assert.equal(api.state.settingsRevision, 'r2');
});

test('console retention policy initializes manual cleanup but does not overwrite an edited scope', () => {
  const { api, element } = harness(); api.state.overview.settings.policy.logsRetentionDays = 14;
  api.renderSettings(); assert.equal(element('cleanup-days').value, 14);
  element('cleanup-days').value = 7; element('cleanup-days').listeners.input(); api.renderSettings(); assert.equal(element('cleanup-days').value, 7);
  assert.match(html, /日志清理默认保留（天）/);
});

test('console only extends network preflight deadline and deduplicates both check controls', async () => {
  const { api, context, calls, element } = harness(); const deadlines = []; let finish;
  context.setTimeout = (fn, milliseconds) => { deadlines.push(milliseconds); return deadlines.length; };
  context.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url === '/api/console/preflight') await new Promise((resolve) => { finish = resolve; });
    return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, checkedAt: new Date().toISOString(), channels: [{ id: 'sms', ok: true, message: 'ok' }, { id: 'mail', ok: true, message: 'ok' }, { id: 'oauth', ok: true, message: 'ok' }] }) };
  };
  const first = api.preflight(); await api.preflight();
  assert.equal(calls.length, 1); assert.deepEqual(deadlines, [170000]);
  assert.equal(element('check-network').disabled, true); assert.equal(element('settings-check-network').disabled, true);
  assert.match(element('check-network').textContent, /检测中/); assert.equal(element('start-register').disabled, true);
  finish(); await first;
  assert.equal(api.state.networkBusy, false); assert.equal(element('check-network').disabled, false);
  assert.match(element('network-channels').innerHTML, /短信接码通道/); assert.match(element('network-channels').innerHTML, /邮箱 API 通道/);
  await api.request('/api/console/settings'); assert.deepEqual(deadlines, [170000, 45000]);
});

test('console distinguishes administrator account lifetime expiry from OAuth expiry', () => {
  const { api, element } = harness(); element('account-filter').value = 'all';
  api.state.overview.accounts = [{ id: 42, classification: 'manual_disabled', action: 'skip', reason: 'administrator_lifetime_expired' }];
  api.renderAccounts();
  api.openAccountDetail(0);
  assert.match(element('account-detail').innerHTML, /管理员设定的账号有效期已到期/);
  assert.match(element('account-detail').innerHTML, /不是 OAuth token 过期/);
  assert.match(element('account-detail').innerHTML, /不自动刷新或删除/);
  assert.match(element('account-rows').innerHTML, /<td>本次跳过<\/td>/);
});

test('console explains unclassified scheduling pauses and invalidated refresh credentials distinctly', () => {
  const { api, element } = harness(); element('account-filter').value = 'all';
  api.state.overview.accounts = [
    { id: 42, classification: 'network_unknown', action: 'review', reason: 'temporary_scheduling_pause' },
    { id: 43, classification: 'auth_invalid', action: 'refresh', reason: 'refresh_token_invalidated' },
  ];
  api.renderAccounts();
  api.openAccountDetail(0);
  assert.match(element('account-detail').innerHTML, /不能确认是额度耗尽/);
  assert.match(element('account-detail').innerHTML, /不自动登录或删除/);
  api.openAccountDetail(1);
  assert.match(element('account-detail').innerHTML, /刷新凭据已失效，需要本地重新授权/);
  assert.doesNotMatch(element('account-rows').innerHTML, /temporary_scheduling_pause|refresh_token_invalidated/);
});

const uiJobId = 'job_' + 'c'.repeat(24);
function localFixture(overrides = {}) {
  return { selectedKey: 'token:synthetic', accountId: 160, accountName: 'free00047', eligible: true, action: 'update',
    targetRevision: 'target-version-1', executionRevision: 'signed-plan-1', sourceContentHash: 'source-version-1',
    sourceLabel: 'tokens/synthetic.json', matchedBy: 'user_id', identityCompletion: 'account_id',
    reason: '相同 User ID，可补全 Account ID 并回写原账号', identitySummary: { sourceUserId: 'user-a…', targetUserId: 'user-a…' }, ...overrides };
}
function mockConsole(h, { localItems = [localFixture()], job = { id: uiJobId, type: 'console_maintain', status: 'queued', result: {} }, postError = null } = {}) {
  h.context.fetch = async (url, options = {}) => {
    h.calls.push({ url, options });
    if (options.method === 'POST' && postError) throw postError;
    const body = options.method === 'POST' ? { jobId: uiJobId, status: 'queued' }
      : url === '/api/console/overview' ? h.api.state.overview
        : url === '/api/console/local-tokens' ? { items: localItems }
          : url === '/api/console/register/continuations' ? { items: [] } : job;
    return { ok: true, status: options.method === 'POST' ? 202 : 200, text: async () => JSON.stringify(body) };
  };
}

test('console main workspace has native results, account detail and no primary advanced-page dependency', () => {
  for (const id of ['task-dialog', 'account-dialog', 'local-token-list', 'local-token-update', 'test-selected', 'import-new', 'account-jobs']) assert.match(html, new RegExp('id="' + id + '"'));
  assert.equal((html.match(/href="\/index.html"/g) || []).length, 1);
  assert.doesNotMatch(html.slice(0, html.indexOf('id="page-settings"')), /href="\/index.html"/);
});

test('console local-token preview explicitly separates identity completion from creation and escaping', async () => {
  const h = harness(); mockConsole(h, { localItems: [localFixture(), localFixture({ selectedKey: 'new', action: 'create', eligible: false, accountId: null, reason: '<script>unsafe</script>' })] });
  await h.api.loadLocalTokens();
  assert.match(h.element('local-token-list').innerHTML, /补全远端 Account ID/);
  assert.match(h.element('local-token-list').innerHTML, /回写目标 #160/);
  assert.match(h.element('local-token-list').innerHTML, /data-local-token-index="1" disabled/);
  assert.match(h.element('local-token-list').innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(h.element('local-token-list').innerHTML, /<script>/);
  assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
});

test('console local-token update freezes exact source target and signed execution version in durable receipt', async () => {
  const h = harness(); mockConsole(h); await h.api.loadLocalTokens(); h.api.state.localSelected.add('token:synthetic');
  let confirmed = ''; h.context.window.confirm = text => { confirmed = text; return true; };
  await h.api.updateLocalTokens();
  const writes = h.calls.filter(call => call.options.method === 'POST'); assert.equal(writes.length, 1);
  assert.deepEqual(JSON.parse(writes[0].options.body), { accountIds: [160], importNew: false, refreshInvalid: false, deleteBanned: false,
    localTokenTargets: [{ selectedKey: 'token:synthetic', accountId: 160, targetRevision: 'target-version-1', sourceContentHash: 'source-version-1', executionRevision: 'signed-plan-1' }] });
  assert.match(confirmed, /#160 free00047/); assert.match(confirmed, /不新增账号、不重新登录、不租号/);
  assert.equal(h.element('task-dialog').open, true); assert.equal(h.api.state.pending, null);
});

test('console local-token update never silently accepts changed source target or signed execution version', async () => {
  for (const field of ['sourceContentHash', 'targetRevision', 'executionRevision', 'accountId']) {
    const h = harness(); mockConsole(h); await h.api.loadLocalTokens(); h.api.state.localSelected.add('token:synthetic');
    mockConsole(h, { localItems: [localFixture({ [field]: field === 'accountId' ? 174 : 'changed' })] });
    await assert.rejects(h.api.updateLocalTokens(), /预览已更新/);
    assert.equal(h.api.state.localSelected.size, 0); assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
  }
});

test('console local-token duplicate targets and missing execution proof remain ineligible', async () => {
  const h = harness(); mockConsole(h, { localItems: [localFixture(), localFixture({ selectedKey: 'second' })] }); await h.api.loadLocalTokens();
  for (const key of ['token:synthetic', 'second']) h.api.state.localSelected.add(key);
  await assert.rejects(h.api.updateLocalTokens(), /不同原账号/); assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
  assert.equal(h.api.localTarget(localFixture({ executionRevision: '' })), null);
  assert.equal(h.api.localTarget(localFixture({ eligible: false })), null);
});

test('console local-token unknown result keeps original receipt and blocks all new workflow writes', async () => {
  const h = harness(); mockConsole(h); await h.api.loadLocalTokens(); h.api.state.localSelected.add('token:synthetic');
  mockConsole(h, { postError: new Error('response lost') }); await assert.rejects(h.api.updateLocalTokens(), /response lost/);
  const pending = JSON.parse(h.store.get('registerStudio.pending.v1'));
  assert.equal(pending.body.localTokenTargets[0].accountId, 160); assert.equal(pending.body.localTokenTargets[0].executionRevision, 'signed-plan-1');
  assert.equal(h.element('local-token-update').disabled, true); assert.equal(h.element('test-selected').disabled, true); assert.equal(h.element('import-new').disabled, true);
  await assert.rejects(h.api.testSelected(), /上一条请求/); assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 1);
});

test('console only-test uses fresh target revisions and never refreshes imports or deletes', async () => {
  const h = harness(); h.api.state.overview.accounts = [{ id: 160, targetRevision: 'fresh-target', executionRevision: 'fresh-execution' }];
  h.api.state.selected.add(160); h.api.state.refreshing = true; h.element('test-model').value = 'gpt-5.6-luna'; mockConsole(h);
  await h.api.testSelected();
  assert.equal(h.calls[0].url, '/api/console/overview', 'must independently read even if polling is already in flight');
  const writes = h.calls.filter(call => call.options.method === 'POST'); assert.equal(writes.length, 1);
  assert.deepEqual(JSON.parse(writes[0].options.body), { accountIds: [160], importNew: false, refreshInvalid: false, deleteBanned: false, testOnly: true,
    accountTargets: [{ accountId: 160, targetRevision: 'fresh-target', executionRevision: 'fresh-execution' }], modelId: 'gpt-5.6-luna' });
});

test('console only-test refuses absent identity revisions and global holds while reads stay available', async () => {
  for (const account of [{ id: 160 }, { id: 160, targetRevision: 'target' }]) {
    const h = harness(); h.api.state.overview.accounts = [account]; h.api.state.selected.add(160); mockConsole(h);
    await assert.rejects(h.api.testSelected(), /无法确认/); assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
  }
  const h = harness(); h.api.state.overview.reconciliation = { total: 1, returned: 1, truncated: false }; mockConsole(h);
  await assert.rejects(h.api.testSelected(), /人工对账/); await h.api.loadLocalTokens(); assert.ok(h.api.state.localTokensLoaded);
});

test('console task detail preserves successful writes when only-test fails and renders safe failure category', async () => {
  const h = harness(); mockConsole(h, { job: { id: uiJobId, type: 'console_maintain', status: 'partial', result: {
    stage: 'completed', summary: { tokensGenerated: 1, tokensUpdated: 1, tested: 1, verified: 0, testFailed: 1 },
    items: [{ accountId: 160, accountName: 'free00047', phases: { tokenGenerated: true, tokenUpdated: true, tested: true, verified: false }, failureCategory: 'model_unavailable', upstreamStatus: 403, message: '测试未通过，不代表导入失败' }],
  } } });
  await h.api.openTaskDetail(uiJobId);
  const text = h.element('task-detail').innerHTML;
  assert.match(text, /回写原账号<\/span><strong>1/); assert.match(text, /测试通过<\/span><strong>0/);
  assert.match(text, /模型不可用 · HTTP 403/); assert.match(text, /不代表导入失败/); assert.match(text, /data-select-result-account="160"/);
  assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
});

test('console task detail bounds child reads and never trusts unrelated children or raw payloads', async () => {
  const h = harness(); const childIds = Array.from({ length: 15 }, (_, index) => 'job_' + (index + 1).toString(16).padStart(24, '0'));
  h.context.fetch = async (url, options = {}) => { h.calls.push({ url, options }); const id = url.split('/').at(-1); return { ok: true, status: 200,
    text: async () => JSON.stringify(id === uiJobId ? { id, result: { childJobIds: ['../outside', ...childIds] } } : { id, payload: { parentJobId: 'job_' + 'f'.repeat(24), secret: 'NEVER_RENDER_PAYLOAD' }, error: 'UNRELATED_ERROR' }) }; };
  await h.api.openTaskDetail(uiJobId);
  assert.equal(h.calls.length, 13); assert.ok(h.calls.every(call => /^\/api\/jobs\/job_[a-f0-9]{24}$/.test(call.url)));
  assert.match(h.element('task-detail').innerHTML, /无法核实关联/); assert.doesNotMatch(h.element('task-detail').innerHTML, /NEVER_RENDER_PAYLOAD|UNRELATED_ERROR/);
});

test('console known acceptance is not changed to unknown if task detail GET fails', async () => {
  const h = harness(); mockConsole(h); const fetch = h.context.fetch;
  h.context.fetch = async (url, options) => { if (url.startsWith('/api/jobs/')) throw new Error('detail unavailable'); return fetch(url, options); };
  const result = await h.api.mutate('/api/console/maintain', { importNew: true, refreshInvalid: false, deleteBanned: false });
  assert.equal(result.jobId, uiJobId); assert.equal(h.api.state.pending, null); assert.equal(h.store.has('registerStudio.pending.v1'), false);
  assert.match(h.element('task-detail').innerHTML, /已接受的任务仍在服务器运行/); assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 1);
});

test('console task detail matches running parent projection and does not mistake attempts for confirmed tests', async () => {
  const h = harness(); mockConsole(h, { job: { id: uiJobId, type: 'console_maintain', status: 'queued', result: {
    startedAt: new Date().toISOString(), stage: 'verifying_account', summary: { tokensUpdated: 1, tested: 1, verified: 0 },
  } } });
  await h.api.openTaskDetail(uiJobId);
  assert.match(h.element('task-detail').innerHTML, /进行中/); assert.doesNotMatch(h.element('task-detail').innerHTML, /排队中/);
  assert.match(h.element('task-detail').innerHTML, /已提交测试<\/span><strong>1/);
  assert.match(h.element('task-detail').innerHTML, /测试通过<\/span><strong>0/);
});

function mockProxySettings(h, { proxyId = null, error = null, listError = false, receiptMismatch = false } = {}) {
  h.api.state.overview.settings.importProxy = { revision: 1, proxyId, configured: proxyId !== null, endpointMatches: true, lastRequestId: null };
  const items = [{ id: 7, name: '<unsafe>节点', protocol: 'socks5', eligible: true, status: 'active', revision: 'signed-node7' },
    { id: 9, name: '停用节点', protocol: 'http', eligible: false, status: 'disabled', revision: 'signed-node9', reason: '节点已停用' }];
  h.context.fetch = async (url, options = {}) => {
    h.calls.push({ url, options });
    if (url === '/api/console/proxies') {
      if (listError) throw new Error('list unavailable');
      return { ok: true, status: 200, text: async () => JSON.stringify({ revision: h.api.state.overview.settings.importProxy.revision, selectedProxyId: h.api.state.overview.settings.importProxy.proxyId, items }) };
    }
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      if (error) return { ok: false, status: error.status || 409, text: async () => JSON.stringify(error) };
      h.api.state.overview.settings.importProxy = { revision: body.importProxy.revision + 1, proxyId: body.importProxy.proxyId, configured: body.importProxy.proxyId !== null, endpointMatches: true, lastRequestId: receiptMismatch ? 'different-request' : body.importProxy.requestId };
    }
    return { ok: true, status: 200, text: async () => JSON.stringify(h.api.state.overview.settings) };
  };
  return items;
}

test('console uses local consistent SVG icons and one structured responsive stylesheet', () => {
  assert.match(html, /id="icon-accounts"/); assert.match(html, /id="icon-shield"/);
  assert.equal((css.match(/:root\s*\{/g) || []).length, 1);
  assert.doesNotMatch(html, /class="section-kicker"|class="policy-strip"/);
  for (const id of ['import-proxy-form', 'import-proxy-select', 'import-proxy-save', 'register-import-proxy']) assert.match(html, new RegExp('id="' + id + '"'));
  assert.match(html, /已有账号回写 token 时保留其原代理/);
});

test('console proxy selection escapes node labels and never treats enabled as connectivity proof', async () => {
  const h = harness(); mockProxySettings(h, { proxyId: 7 }); await h.api.loadProxies();
  assert.match(h.element('import-proxy-select').innerHTML, /&lt;unsafe&gt;/); assert.doesNotMatch(h.element('import-proxy-select').innerHTML, /<unsafe>|已连通/);
  assert.match(h.element('import-proxy-select').innerHTML, /value="9" disabled/);
  assert.equal(h.element('import-proxy-select').value, '7'); assert.equal(h.element('import-proxy-save').disabled, false);
  assert.match(h.element('register-import-proxy').textContent, /已有账号保持原代理/);
  assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
});

test('console independent import proxy save sends selected node proof with request identity and explicit confirmation', async () => {
  const h = harness(); mockProxySettings(h); await h.api.loadProxies(); h.element('import-proxy-select').value = '7';
  let confirmation; h.context.window.confirm = value => { confirmation = value; return true; };
  await h.api.saveImportProxy();
  const writes = h.calls.filter(call => call.options.method === 'POST'); assert.equal(writes.length, 1);
  const body = JSON.parse(writes[0].options.body);
  assert.deepEqual(body, { confirm: true, importProxy: { revision: 1, proxyId: 7, proxyRevision: 'signed-node7', requestId: '12345678-1234-1234-1234-123456789012' } });
  assert.match(confirmation, /#7/); assert.match(confirmation, /已有账号回写 token 保留原代理/); assert.match(confirmation, /注册机网络通道不变/);
  assert.equal(h.api.state.pending, null); assert.equal(h.api.state.overview.settings.importProxy.proxyId, 7);
});

test('console clearing default proxy is explicit null with no invented direct-connection guarantee', async () => {
  const h = harness(); mockProxySettings(h, { proxyId: 7 }); await h.api.loadProxies(); h.element('import-proxy-select').value = 'none';
  h.context.window.confirm = () => false; await h.api.saveImportProxy(); assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
  let confirmation; h.context.window.confirm = value => { confirmation = value; return true; }; await h.api.saveImportProxy();
  const body = JSON.parse(h.calls.find(call => call.options.method === 'POST').options.body);
  assert.equal(body.importProxy.proxyId, null); assert.equal(Object.hasOwn(body.importProxy, 'proxyRevision'), false);
  assert.match(confirmation, /沿用 Sub2API 网络配置/); assert.doesNotMatch(confirmation, /直连/);
});

test('console unknown proxy save keeps receipt without node proof and recovers only by original request ID', async () => {
  const h = harness(); mockProxySettings(h, { error: { error: 'PROXY_WRITE_UNKNOWN', message: 'unknown', writeOutcomeUnknown: true } });
  await h.api.loadProxies(); h.element('import-proxy-select').value = '7'; await assert.rejects(h.api.saveImportProxy(), /unknown/);
  const pending = JSON.parse(h.store.get('registerStudio.pending.v1'));
  assert.equal(pending.body.importProxy.proxyId, 7); assert.equal(Object.hasOwn(pending.body.importProxy, 'proxyRevision'), false);
  await assert.rejects(h.api.reconcileSettings(pending), /不能仅凭当前配置/);
  h.api.state.overview.settings.importProxy.proxyId = 7;
  await assert.rejects(h.api.reconcileSettings(pending), /不能仅凭当前配置/);
  h.api.state.overview.settings.importProxy.lastRequestId = pending.body.importProxy.requestId;
  await h.api.reconcileSettings(pending); assert.equal(h.api.state.pending, null);
  assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 1, 'read-only receipt recovery must not repost');
});

test('console recognized proxy prewrite rejections unlock but explicit unknown and unrecognized 409 retain safety', async () => {
  for (const code of ['CONSOLE_IMPORT_PROXY_SETTINGS_STALE', 'CONSOLE_IMPORT_PROXY_SETTINGS_INVALID', 'CONSOLE_IMPORT_PROXY_CHANGED', 'CONSOLE_IMPORT_PROXY_CHECK_FAILED']) {
    const h = harness(); mockProxySettings(h, { error: { error: code, message: 'rejected', status: code.endsWith('INVALID') ? 400 : 409 } }); await h.api.loadProxies(); h.element('import-proxy-select').value = '7';
    await assert.rejects(h.api.saveImportProxy(), /rejected/); assert.equal(h.api.state.pending, null, code);
  }
  for (const error of [{ error: 'UNRECOGNIZED_PROXY_CONFLICT', message: 'unknown' }, { error: 'CONSOLE_IMPORT_PROXY_CHANGED', message: 'unknown', writeOutcomeUnknown: true }, { error: 'CONSOLE_IMPORT_PROXY_CHECK_FAILED', message: 'unknown', writeOutcomeUnknown: true }, { error: 'CONSOLE_IMPORT_PROXY_CHECK_FAILED', message: 'unknown', status: 503 }]) {
    const h = harness(); mockProxySettings(h, { error }); await h.api.loadProxies(); h.element('import-proxy-select').value = '7';
    await assert.rejects(h.api.saveImportProxy(), /unknown/); assert.ok(h.api.state.pending);
  }
});

test('console unavailable or missing proxy never silently switches selection to no-proxy', async () => {
  const h = harness(); mockProxySettings(h, { proxyId: 81 }); await h.api.loadProxies();
  assert.equal(h.element('import-proxy-select').value, '81'); assert.equal(h.element('import-proxy-save').disabled, true);
  assert.match(h.element('import-proxy-select').innerHTML, /#81 已不可用/); assert.match(h.api.defaultProxyIssue(), /不会自动直连/);
  h.element('import-proxy-select').value = '9'; await assert.rejects(h.api.saveImportProxy(), /节点已停用/);
  mockProxySettings(h, { proxyId: 81, listError: true }); await h.api.loadProxies();
  assert.equal(h.element('import-proxy-save').disabled, true); assert.equal(h.element('import-proxy-select').value, '9');
  assert.match(h.element('import-proxy-hint').textContent, /当前默认设置未改变/);
  assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 0);
});

test('console default proxy endpoint mismatch blocks new imports not existing-account operations', async () => {
  const h = harness(); mockProxySettings(h, { proxyId: 7 }); h.api.state.overview.settings.importProxy.endpointMatches = false; h.api.state.selected.add(160);
  h.api.renderProxySetting(); h.api.renderControls();
  assert.match(h.element('register-import-proxy').textContent, /另一 Sub2API 实例/);
  assert.equal(h.element('start-register').disabled, true); assert.equal(h.element('import-new').disabled, true); assert.equal(h.element('maintain-all').disabled, true);
  assert.equal(h.element('maintain-selected').disabled, false); assert.equal(h.element('test-selected').disabled, false);
});

test('console proxy list reload retains explicit unsaved selection while advancing CAS proof', async () => {
  const h = harness(); mockProxySettings(h); await h.api.loadProxies(); h.element('import-proxy-select').value = '7'; h.api.state.proxyDirty = true;
  h.api.state.overview.settings.importProxy.revision = 2; await h.api.loadProxies();
  assert.equal(h.element('import-proxy-select').value, '7'); assert.equal(h.api.state.proxyRevision, 2);
});

test('console saving proxy independently preserves unsaved policy and registration edits', async () => {
  const h = harness(); mockProxySettings(h); await h.api.loadProxies();
  h.api.state.settingsDirty = true; h.api.state.registrationDirty = true; h.element('maintenance-interval').value = '95';
  h.element('import-proxy-select').value = '7'; await h.api.saveImportProxy();
  assert.equal(h.api.state.settingsDirty, true); assert.equal(h.api.state.registrationDirty, true);
  assert.equal(h.element('maintenance-interval').value, '95');
});

test('console prewrite proxy check exception never makes another endpoint or read definitive', async () => {
  const h = harness(); h.context.fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ error: 'CONSOLE_IMPORT_PROXY_CHECK_FAILED' }) });
  for (const [url, options] of [['/api/console/register', { method: 'POST', body: '{}' }], ['/api/console/settings', {}]]) {
    await assert.rejects(h.api.request(url, options), error => error.code === 'CONSOLE_IMPORT_PROXY_CHECK_FAILED' && error.definitive === false);
  }
});
