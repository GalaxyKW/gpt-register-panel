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
    fetch: async (url, options) => { calls.push({ url, options }); return { ok: true, status: 200, text: async () => JSON.stringify({ readOnly: false, capabilities: { registrationEnabled: true, sub2apiConfigured: true }, accounts: [], jobs: [], reconciliation: { total: 0, returned: 0, truncated: false }, activeJobs: { total: 0, returned: 0, truncated: false }, summary: {}, settings: { revision: 'r1', policy: { enabled: false }, registration: { revision: 'g1', ready: true, fields: [] } } }) }; },
  };
  vm.createContext(context);
  const instrumented = source.replace('showPage(); renderControls(); refresh();', 'globalThis.harness = { state, validToken, pendingValid, persistPending, mutate, saveSettings, reconcileSettings, writeBlock, inventoryProblem, stopJob, preflight, filteredAccounts, renderAccounts, renderJobs, renderNetwork, renderSettings, renderControls, renderContinuations, request, date, escape, maintain, logQuery };');
  vm.runInContext(instrumented, context);
  const api = context.harness;
  api.state.connected = true;
  api.state.overview = { readOnly: false, capabilities: { registrationEnabled: true, sub2apiConfigured: true }, accounts: [], jobs: [], reconciliation: { total: 0, returned: 0, truncated: false }, activeJobs: { total: 0, returned: 0, truncated: false }, summary: {}, settings: { revision: 'r1', policy: { enabled: false }, registration: { revision: 'g1', ready: true, fields: [] } } };
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
  for (const stage of ['checking_network', 'phase1_register', 'phase1_5_profile', 'phase2_bind_email', 'phase3_email_oauth',
    'planning', 'refreshing', 'updating_token', 'verifying_account', 'removing_banned', 'maintaining', 'importing_new']) {
    api.state.overview.jobs = [{ id: 'job_stage', type: 'console_register', status: 'running', stage, summary: {} }];
    api.renderJobs();
    assert.equal(element('jobs').innerHTML.includes(stage), false, 'Internal stage IDs are not user-facing instructions');
    assert.match(element('jobs').innerHTML, /[\u4e00-\u9fff]/);
  }
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
  api.renderNetwork(null); assert.match(element('network-channels').innerHTML, /启动任务前/); assert.doesNotMatch(element('network-channels').innerHTML, /已连通/);
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

test('console log browsing and download use returned opaque file IDs not server paths', () => {
  const { api, element } = harness(); element('log-file').value = 'f'.repeat(32); element('log-source').value = 'panel';
  assert.equal(api.logQuery().get('fileId'), 'f'.repeat(32)); assert.equal(api.logQuery().get('source'), 'panel');
  assert.match(source, /state\.logFiles\.some\(\(file\) => file\.id === fileId\)/); assert.doesNotMatch(source, /download\?path=/);
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

test('console actual update action overrides classification label when identity requires review', () => {
  const { api, element } = harness(); element('account-filter').value = 'all';
  api.state.overview.accounts = [{ id: 42, classification: 'expired', action: 'review', reason: 'strong_identity_ambiguous' }];
  api.renderAccounts(); assert.match(element('account-rows').innerHTML, /<td>人工核对<\/td>/); assert.match(element('account-rows').innerHTML, /强身份缺失或匹配不唯一/);
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
  assert.match(element('account-rows').innerHTML, /管理员设定的账号有效期已到期/);
  assert.match(element('account-rows').innerHTML, /不是 OAuth token 过期/);
  assert.match(element('account-rows').innerHTML, /不自动刷新或删除/);
  assert.match(element('account-rows').innerHTML, /<td>本次跳过<\/td>/);
});
