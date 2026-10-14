'use strict';
// Explicit, repeatable browser acceptance suite. No backend modules, .env,
// production accounts or real services are loaded. All writes hit this fixture.
// node tests/browser-console.cjs
// Optional: PANEL_TEST_CHROME_PATH, PANEL_TEST_PUPPETEER_PATH,
// PANEL_TEST_SCREENSHOT_DIR (synthetic data only).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const repository = path.resolve(__dirname, '..');
const token = 'synthetic-admin-token-only';
const jobId = 'job_' + 'a'.repeat(24);
const failedId = 'job_' + 'b'.repeat(24);
const fileId = 'f'.repeat(32);
const fixtureSecret = 'SYNTHETIC_SECRET_NOT_FOR_STORAGE';
const inventory = total => ({ total, returned: total, truncated: false });
function makeFixture() {
  return {
    settingsMode: 'ok', registerMode: 'ok', requests: [], receipts: new Map(), confirmations: [], continuations: [], detailJobs: new Map(),
    proxyMode: 'ok', proxyItems: [{ id: 7, name: '默认节点', protocol: 'socks5', status: 'active', revision: 'proxy7-proof', eligible: true, reason: '' },
      { id: 9, name: '停用节点', protocol: 'http', status: 'disabled', revision: 'proxy9-proof', eligible: false, reason: '节点已停用' }],
    localTokens: [{ selectedKey: 'token:synthetic', sourceContentHash: 'source-revision', accountId: 160, accountName: 'free00047', sourceLabel: 'tokens/synthetic.json',
      action: 'update', eligible: true, reason: '相同 User ID，可补全 Account ID 并回写原账号', matchedBy: 'user_id', identityCompletion: 'account_id',
      targetRevision: 'target-revision', executionRevision: 'signed-execution', sourceFingerprint: 'new-fingerprint', targetFingerprint: 'old-fingerprint',
      identitySummary: { sourceAccountId: 'account-synthetic…', targetAccountId: '', sourceUserId: 'user-synthetic…', targetUserId: 'user-synthetic…' } }],
    overview: {
      readOnly: false, capabilities: { registrationEnabled: true, phase3Enabled: true, sub2apiConfigured: true, comparisonAvailable: true },
      reconciliation: inventory(0), activeJobs: inventory(0),
      summary: { total: 3, healthy: 1, quotaWait: 1, refreshNeeded: 1, banned: 0, needsReview: 0, neverImported: 0 },
      accounts: [
        { id: 117, name: 'free00004', email: 'healthy@example.invalid', status: 'active', classification: 'healthy', targetRevision: 'target117', executionRevision: 'execution117' },
        { id: 160, name: 'free00047', email: 'expired@example.invalid', status: 'error', classification: 'expired', targetRevision: 'target160', executionRevision: 'execution160', reason: 'credential_expired_unavailable' },
        { id: 174, name: 'free00061', email: 'quota@example.invalid', status: 'active', classification: 'quota_wait', targetRevision: 'target174', executionRevision: 'execution174' },
      ],
      jobs: [{ id: failedId, type: 'console_register', status: 'failed', stage: 'failed', failureStage: 'importing',
        summary: { registered: 1, imported: 0, failed: 0 }, error: '合成场景：目标服务读取失败',
        recoveryMessage: '已获取 token，不要重新注册或租号；请先核对原任务。', createdAt: '2026-10-12T02:00:00Z' }],
      network: null,
      settings: { revision: 'r1', policy: { enabled: false, intervalMinutes: 60, logsRetentionDays: 30 },
        importProxy: { revision: 0, proxyId: null, configured: false, endpointMatches: true, lastRequestId: null },
        registration: { revision: 'g1', ready: true, phase3Ready: true, phase3Issues: [], issues: [],
          countries: [{ code: 'CL', name: '智利' }], fields: [
            { key: 'smsApiKey', label: '短信平台 API 密钥', type: 'string', secret: true, configured: true },
            { key: 'headless', label: '无头浏览器', type: 'boolean', value: true },
          ] } },
    },
  };
}
let fixture, origin, browser, currentCase = 'setup', currentStep = '';
const failures = [], externalRequests = [], completed = [];
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    const json = (body, status = 200) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
    if (url.pathname.startsWith('/api/')) {
      const entry = { method: req.method, pathname: url.pathname, query: url.searchParams, key: req.headers['idempotency-key'] };
      fixture.requests.push(entry);
      if (req.headers['x-panel-token'] !== token) return json({ error: 'unauthorized' }, 401);
      if (req.method === 'GET') {
        if (url.pathname === '/api/console/overview') return json(fixture.overview);
        if (url.pathname === '/api/console/settings') return json(fixture.overview.settings);
        if (url.pathname === '/api/console/proxies') {
          if (fixture.proxyMode === 'unavailable') return json({ error: 'PROXY_LIST_UNAVAILABLE', message: '节点列表暂时不可用' }, 503);
          return json({ revision: fixture.overview.settings.importProxy.revision, selectedProxyId: fixture.overview.settings.importProxy.proxyId, items: fixture.proxyItems });
        }
        if (url.pathname === '/api/console/register/continuations') return json({ items: fixture.continuations });
        if (url.pathname === '/api/console/local-tokens') return json({ snapshotVersion: 'snapshot-fixture', items: fixture.localTokens });
        if (/^\/api\/jobs\/job_[a-f0-9]{24}$/.test(url.pathname)) {
          const id = url.pathname.split('/').at(-1);
          return json(fixture.detailJobs.get(id) || fixture.overview.jobs.find(job => job.id === id) || { id, type: 'console_maintain', status: 'queued', result: { stage: 'queued', summary: {} } });
        }
        if (url.pathname === '/api/console/logs') return json({
          entries: [{ time: '2026-10-12T02:00:00Z', level: 'info', source: 'register', event: 'fixture', message: url.searchParams.has('cursor') ? '更早的合成日志' : '最新的合成日志' }],
          nextCursor: url.searchParams.has('cursor') ? null : 'older-fixture', totalBytes: 512,
          files: [{ id: fileId, source: 'register', name: 'synthetic-run.log', bytes: 512, modifiedAt: '2026-10-12T02:00:00Z', active: false }],
          searchScope: { scannedFiles: 8, matchingFiles: 12, omittedFiles: 4 },
          ...(url.searchParams.has('jobId') ? { bindingNotice: '未找到与该任务绑定的注册机日志。请按文件核对，不会按时间猜测归属。' } : {}),
        });
        if (url.pathname === '/api/console/logs/download' && url.searchParams.get('fileId') === fileId) {
          res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('synthetic log [redacted]\n');
        }
      }
      if (req.method === 'POST') {
        let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 65536) throw new Error('mock request too large'); }
        entry.body = JSON.parse(raw || '{}');
        if (url.pathname === '/api/console/settings') {
          if (fixture.settingsMode === 'active-conflict') return json({ error: 'CONSOLE_SETTINGS_ACTIVE_CONFLICT', message: '后台任务仍在执行' }, 409);
          if (fixture.settingsMode === 'unknown') return json({ error: 'CONSOLE_SETTINGS_OTHER_CONFLICT', message: '合成场景：保存结果未知' }, 409);
          if (entry.body.importProxy && ['stale', 'node-changed'].includes(fixture.proxyMode)) return json({ error: fixture.proxyMode === 'stale' ? 'CONSOLE_IMPORT_PROXY_SETTINGS_STALE' : 'CONSOLE_IMPORT_PROXY_CHANGED', message: '代理配置或节点已变化，请刷新后重新选择' }, 409);
          if (entry.body.policy) { fixture.overview.settings.policy = entry.body.policy; fixture.overview.settings.revision = 'r2'; }
          if (entry.body.registration) { fixture.overview.settings.registration.revision = 'g2'; fixture.overview.settings.registration.lastRequestId = entry.body.registration.requestId; }
          if (entry.body.importProxy) {
            const input = entry.body.importProxy;
            assert.equal(input.revision, fixture.overview.settings.importProxy.revision);
            assert.equal(entry.body.confirm, true);
            if (input.proxyId !== null) assert.equal(input.proxyRevision, fixture.proxyItems.find(item => item.id === input.proxyId).revision);
            fixture.overview.settings.importProxy = { revision: input.revision + 1, proxyId: input.proxyId, configured: input.proxyId !== null, endpointMatches: true, lastRequestId: input.requestId };
            if (fixture.proxyMode === 'lost-response') return json({ error: 'SETTINGS_WRITE_UNKNOWN', message: '代理设置保存结果未知', writeOutcomeUnknown: true }, 503);
          }
          return json(fixture.overview.settings);
        }
        if (url.pathname.endsWith('/stop')) {
          assert.equal(url.pathname, '/api/console/jobs/' + jobId + '/stop');
          fixture.overview.jobs.find(job => job.id === jobId).status = 'interrupted';
          fixture.overview.activeJobs = inventory(0); return json({ jobId, status: 'stopping' }, 202);
        }
        if (url.pathname === '/api/console/preflight') {
          await new Promise(resolve => setTimeout(resolve, 150));
          return json({ ok: false, checkedAt: new Date().toISOString(), channels: [
            { id: 'sms', ok: true, message: '合成鉴权通过' }, { id: 'mail', ok: true, message: '合成鉴权通过' },
            { id: 'oauth', ok: false, checks: [{ id: 'node_oauth', ok: true }, { id: 'browser', ok: false, message: '合成浏览器访问失败' }] },
          ] });
        }
        if (['/api/console/register', '/api/console/register/resume', '/api/console/maintain', '/api/console/logs/cleanup'].includes(url.pathname)) {
          assert.match(entry.key || '', /^idem_v1_/);
          const previous = fixture.receipts.get(entry.key);
          if (previous) { assert.deepEqual(entry.body, previous.body); return json(previous.receipt, 202); }
          const receipt = { jobId, status: 'queued' }; fixture.receipts.set(entry.key, { body: entry.body, receipt });
          if (fixture.registerMode === 'lost-response') {
            fixture.overview.jobs.unshift({ id: jobId, type: 'console_register', status: 'running', stage: 'registering', summary: {} });
            fixture.overview.activeJobs = inventory(1);
            // A relay can lose the upstream acceptance response and return 503.
            // Unlike destroying TCP, this is deterministic across Chromium's
            // automatic transport retries while preserving the unknown outcome.
            return json({ error: 'TEST_RECEIPT_UNAVAILABLE', message: '合成代理未取得任务回执，结果未知' }, 503);
          }
          return json(receipt, 202);
        }
      }
      failures.push('unhandled mock endpoint'); return json({ error: 'UNEXPECTED_TEST_ENDPOINT' }, 400);
    }
    const filename = url.pathname === '/' ? 'console.html' : url.pathname.slice(1);
    if (filename === 'favicon.ico') { res.writeHead(204); return res.end(); }
    if (!['console.html', 'console.css', 'console.js'].includes(filename)) { res.writeHead(404); return res.end(); }
    res.setHeader('content-type', filename.endsWith('.js') ? 'application/javascript' : filename.endsWith('.css') ? 'text/css' : 'text/html');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
    res.end(fs.readFileSync(path.join(repository, 'frontend', filename)));
  } catch (error) { failures.push('mock handler: ' + error.message); if (!res.headersSent) res.writeHead(500); res.end(); }
});
function writes(pathname) { return fixture.requests.filter(req => req.method === 'POST' && (!pathname || req.pathname === pathname)); }
async function waitText(page, selector, text) { currentStep = selector + ': ' + text; await page.waitForFunction((s, value) => document.querySelector(s)?.textContent.includes(value), {}, selector, text); }
async function setInput(page, selector, value) { await page.$eval(selector, (input, next) => { input.value = next; input.dispatchEvent(new Event('input', { bubbles: true })); }, value); }
async function assertReadableText(page, selectors) {
  const results = await page.evaluate(selectors => {
    const rgb = value => (value.match(/[\d.]+/g) || []).map(Number);
    const luminance = values => values.slice(0, 3).map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
    return selectors.map(selector => {
      const element = document.querySelector(selector); if (!element) return { selector, missing: true };
      const foreground = luminance(rgb(getComputedStyle(element).color)); let ancestor = element, background;
      while (ancestor) { const value = rgb(getComputedStyle(ancestor).backgroundColor); if (value.length === 3 || value[3] > .99) { background = luminance(value); break; } ancestor = ancestor.parentElement; }
      background ??= 1;
      return { selector, ratio: (Math.max(foreground, background) + .05) / (Math.min(foreground, background) + .05) };
    });
  }, selectors);
  for (const result of results) assert.ok(!result.missing && result.ratio >= 4.5, 'text contrast below 4.5: ' + result.selector);
}
async function navigate(page, name) {
  await page.click('[data-page="' + name + '"]'); await page.waitForFunction(name => !document.querySelector('#page-' + name).hidden, {}, name);
  assert.deepEqual(await page.$$eval('.nav-link.active', links => links.map(link => link.dataset.page)), [name], 'navigation must have exactly one active page');
}
async function closeTaskDetail(page) { await page.waitForFunction(() => document.querySelector('#task-dialog').open); await page.click('#task-dialog-close'); }
async function refresh(page) {
  const response = page.waitForResponse(response => response.url() === origin + '/api/console/register/continuations');
  await page.click('#refresh'); await response;
  await page.waitForFunction(() => document.querySelector('#connection-dot').classList.contains('online'));
}
async function testCase(name, body, { authenticated = true, hash = '' } = {}) {
  currentCase = name; currentStep = 'opening'; fixture = makeFixture();
  const context = await browser.createBrowserContext(); const page = await context.newPage();
  page.setDefaultTimeout(10000); page.on('pageerror', () => failures.push(name + ': page error'));
  await page.setRequestInterception(true);
  page.on('request', request => {
    if (new URL(request.url()).origin !== origin) { externalRequests.push('blocked external request'); return request.abort(); }
    return request.continue();
  });
  let acceptDialogs = true;
  page.on('dialog', dialog => { fixture.confirmations.push(dialog.message()); return acceptDialogs ? dialog.accept() : dialog.dismiss(); });
  if (authenticated) await page.evaluateOnNewDocument(value => sessionStorage.setItem('panelToken', value), token);
  try {
    await page.setViewport({ width: 1440, height: 1050 });
    await page.goto(origin + '/' + hash, { waitUntil: 'networkidle0' });
    if (authenticated) await waitText(page, '#metric-total', '3');
    await body(page, value => { acceptDialogs = value; });
    completed.push(name); console.log('ok - ' + name);
  } finally { await context.close(); }
}
async function main() {
  const modulePath = process.env.PANEL_TEST_PUPPETEER_PATH || require.resolve('puppeteer-core', { paths: [repository, path.resolve(repository, '../../gpt_register')] });
  const puppeteer = require(modulePath);
  const executablePath = process.env.PANEL_TEST_CHROME_PATH || ['/opt/google/chrome/chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].find(candidate => fs.existsSync(candidate));
  assert.ok(executablePath && fs.existsSync(executablePath), 'Chromium is required: set PANEL_TEST_CHROME_PATH; no browser means this acceptance suite fails');
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); origin = 'http://127.0.0.1:' + server.address().port;
  browser = await puppeteer.launch({ executablePath, headless: true, args: ['--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', ...(process.getuid?.() === 0 ? ['--no-sandbox'] : [])] });
  await testCase('login validation and direct logs after authentication', async page => {
    await page.waitForFunction(() => document.querySelector('#auth-dialog').open);
    await setInput(page, '#admin-token', '中文'.repeat(16)); await page.click('#auth-form button');
    await waitText(page, '#auth-error', '不能含空格、中文'); assert.equal(writes().length, 0);
    await setInput(page, '#admin-token', token); await page.click('#auth-form button');
    await page.waitForSelector('.log-line'); assert.equal(await page.$eval('#auth-dialog', el => el.open), false);
    assert.equal(await page.$eval('#admin-token', el => el.value), '');
  }, { authenticated: false, hash: '#logs' });
  await testCase('four pages desktop/mobile and truthful partial-failure statistics', async page => {
    for (const width of [1440, 390]) {
      await page.setViewport({ width, height: width === 390 ? 844 : 1050 });
      for (const section of ['register', 'accounts', 'logs', 'settings']) {
        await navigate(page, section);
        if (section === 'logs') await page.waitForSelector('.log-line');
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, section + ' horizontal overflow');
        await assertReadableText(page, ['#page-' + section + ' .page-description', ...({ register: ['.metric > span', '.channel-copy p', '#jobs .job-detail'], accounts: ['.account-email', '.accounts-table th'], logs: ['.log-time'], settings: ['.proxy-description', '.environment-list dt'] })[section]]);
        if (section === 'register') {
          const text = await page.$eval('#jobs', el => el.textContent);
          assert.match(text, /注册成功 1 · 导入 0 · 账号步骤失败 0/); assert.match(text, /失败阶段：导入 Sub2API/); assert.match(text, /不要重新注册或租号/);
        }
        if (process.env.PANEL_TEST_SCREENSHOT_DIR) {
          fs.mkdirSync(process.env.PANEL_TEST_SCREENSHOT_DIR, { recursive: true });
          await page.screenshot({ path: path.join(process.env.PANEL_TEST_SCREENSHOT_DIR, 'mock-' + width + '-' + section + '.png'), fullPage: true });
        }
      }
    }
    await navigate(page, 'register'); await page.focus('#refresh'); await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => { const style = getComputedStyle(document.activeElement); return style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) >= 2; }), true, 'keyboard focus must be visible');
    assert.equal(writes().length, 0);
  });
  await testCase('direct logs reload, pagination and task shortcut clear stale filters', async page => {
    await page.waitForSelector('.log-line'); await page.click('#logs-more'); await waitText(page, '#log-count', '2 条');
    await refresh(page); await waitText(page, '#log-count', '2 条');
    await page.reload({ waitUntil: 'networkidle0' }); await page.waitForSelector('.log-line'); await waitText(page, '#log-count', '1 条');
    await page.select('#log-source', 'panel'); await page.select('#log-level', 'error'); await page.select('#log-file', fileId); await setInput(page, '#log-query', 'old-message');
    await navigate(page, 'register'); await page.click('[data-job-logs="' + failedId + '"]');
    await waitText(page, '#log-storage', '未找到与该任务绑定');
    const last = fixture.requests.filter(req => req.pathname === '/api/console/logs').at(-1);
    assert.equal(last.query.get('jobId'), failedId);
    for (const key of ['source', 'level', 'fileId', 'q', 'cursor']) assert.equal(last.query.has(key), false, key);
    await waitText(page, '#log-storage', '本次仅扫描 8 / 12'); assert.equal(writes().length, 0);
  }, { hash: '#logs' });
  await testCase('selection survives filtering and confirmation cancels without writes', async (page, confirm) => {
    await navigate(page, 'accounts'); await page.click('#select-all'); await page.select('#account-filter', 'quota');
    assert.equal(await page.$eval('#selected-count', el => el.textContent), '3');
    confirm(false); await page.click('#maintain-selected'); assert.equal(writes().length, 0);
    confirm(true); await page.click('#maintain-selected'); await waitText(page, '#notice', '任务已交给服务器');
    assert.equal(writes().length, 1, 'cancelled confirmation must not submit, and accepted confirmation must submit only once');
    assert.deepEqual(writes('/api/console/maintain')[0].body, { accountIds: [117, 160, 174], importNew: false, refreshInvalid: true, deleteBanned: true });
  });
  await testCase('Phase3 scoped readiness and ineligible reasons remain enforced', async (page, confirm) => {
    fixture.overview.settings.registration.ready = false; fixture.overview.settings.registration.issues = ['缺少短信配置'];
    fixture.continuations = [
      { selectedKey: 'registration:accounts:0', revision: 'a'.repeat(64), stage: 'phase3', email: 'resume@example.invalid', eligible: true, repairEmail: true, blockingRegistration: true },
      { selectedKey: 'registration:accounts:1', revision: 'b'.repeat(64), stage: 'phase2', eligible: true, phoneMasked: '***1234' },
    ];
    await refresh(page); await page.waitForSelector('[data-resume-index="0"]');
    assert.equal(await page.$eval('[data-resume-index="0"]', el => el.disabled), false);
    assert.equal(await page.$eval('[data-resume-index="1"]', el => el.disabled), true);
    assert.equal(await page.$eval('#start-register', el => el.disabled), true);
    await waitText(page, '#continuation-hint-0', '无需短信配置'); await waitText(page, '#continuations', '本地两份资料已核验');
    confirm(false); await page.click('[data-resume-index="0"]'); assert.equal(writes().length, 0);
    confirm(true); await page.click('[data-resume-index="0"]'); await waitText(page, '#notice', '任务已交给服务器');
    assert.deepEqual(writes()[0].body, { selectedKey: fixture.continuations[0].selectedKey, revision: fixture.continuations[0].revision, autoImport: true });
    await closeTaskDetail(page);
    fixture.overview.settings.registration.phase3Ready = false; fixture.overview.settings.registration.phase3Issues = ['缺少邮箱鉴权配置'];
    await refresh(page); await waitText(page, '#continuation-hint-0', '缺少邮箱鉴权配置');
    assert.equal(await page.$eval('[data-resume-index="0"]', el => el.disabled), true);
    fixture.overview.settings.registration.phase3Ready = true; fixture.continuations[0].eligible = false; fixture.continuations[0].reason = '本地身份冲突';
    await refresh(page); await waitText(page, '#continuation-hint-0', '本地身份冲突'); assert.equal(writes().length, 1);
  });
  await testCase('lost receipt survives reload; exact stop and idempotent recovery never retarget', async page => {
    fixture.registerMode = 'lost-response'; await page.select('#register-country', 'CL'); await page.click('#start-register');
    currentStep = 'wait for durable pending';
    await page.waitForFunction(() => !document.querySelector('#pending-banner').hidden && !document.querySelector('#resolve-pending').disabled);
    const pending = await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')); assert.ok(pending);
    currentStep = 'reload shows running job'; await page.reload({ waitUntil: 'networkidle0' }); await page.waitForSelector('[data-stop-job]'); assert.equal(writes().length, 1);
    fixture.overview.readOnly = true; fixture.overview.reconciliation = inventory(1); await refresh(page);
    await waitText(page, '#task-safety-title', '人工对账'); assert.equal(await page.$eval('#start-register', el => el.disabled), true);
    await page.click('[data-stop-job]'); await waitText(page, '#notice', '已请求停止该任务');
    assert.equal(await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')), pending);
    assert.equal(writes('/api/console/jobs/' + jobId + '/stop').length, 1);
    fixture.overview.readOnly = false; fixture.overview.reconciliation = inventory(0); await refresh(page);
    await page.click('#resolve-pending'); await waitText(page, '#notice', '任务已交给服务器');
    const registration = writes('/api/console/register'); assert.equal(registration.length, 2);
    assert.equal(registration[0].key, registration[1].key); assert.deepEqual(registration[0].body, registration[1].body); assert.equal(fixture.receipts.size, 1);
    assert.equal(await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')), null);
  });
  await testCase('settings definite rejection unlocks; secrets and unknown results never replay', async page => {
    await navigate(page, 'settings'); fixture.settingsMode = 'active-conflict'; await setInput(page, '#maintenance-interval', '75'); await page.click('#settings-save');
    await waitText(page, '#notice', '后台任务仍在执行'); assert.equal(await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')), null);
    assert.equal(await page.$eval('#settings-save', el => el.disabled), false);
    fixture.settingsMode = 'ok'; await page.click('#settings-save'); await waitText(page, '#notice', '已确认本次配置保存成功'); assert.equal(fixture.overview.settings.policy.intervalMinutes, 75);
    const settingsWritesBeforeSecret = writes('/api/console/settings').length;
    const secretResponse = page.waitForResponse(response => response.url() === origin + '/api/console/settings'
      && response.request().method() === 'POST' && Boolean(JSON.parse(response.request().postData() || '{}').registration));
    await setInput(page, '#registration-field-0', fixtureSecret); await page.click('#registration-settings-save');
    assert.equal((await secretResponse).status(), 200, 'this secret save must receive its own acknowledgement');
    await waitText(page, '#notice', '已确认本次配置保存成功');
    await page.waitForFunction(() => document.querySelector('#registration-field-0').value === ''
      && sessionStorage.getItem('registerStudio.pending.v1') === null && !document.querySelector('#settings-save').disabled);
    const settingsWritesAfterSecret = writes('/api/console/settings');
    assert.equal(settingsWritesAfterSecret.length, settingsWritesBeforeSecret + 1);
    assert.equal(settingsWritesAfterSecret.at(-1).body.registration.changes.smsApiKey, fixtureSecret);
    assert.match(settingsWritesAfterSecret.at(-1).body.registration.requestId, /^[a-zA-Z0-9_-]{16,128}$/);
    assert.equal(await page.evaluate(value => JSON.stringify(Object.entries(sessionStorage)).includes(value), fixtureSecret), false);
    fixture.settingsMode = 'unknown'; await setInput(page, '#maintenance-interval', '90'); await page.click('#settings-save'); await waitText(page, '#notice', '保存结果未知');
    const count = writes().length, pending = await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')); assert.ok(pending);
    await page.reload({ waitUntil: 'networkidle0' }); await page.click('#resolve-pending'); await waitText(page, '#notice', '不能仅凭当前配置解除保护');
    await page.click('#settings-reload'); await waitText(page, '#notice', '不会解除待核对记录');
    assert.equal(writes().length, count); assert.equal(await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')), pending);
    assert.equal(await page.$eval('#settings-save', el => el.disabled), true);
  });
  await testCase('mock network preflight deduplicates clicks and displays failed browser subchannel', async page => {
    await page.click('#check-network'); await page.click('#check-network');
    await waitText(page, '#notice', '部分通道检测未通过'); assert.equal(writes('/api/console/preflight').length, 1);
    await waitText(page, '#network-channels', 'token 接口出口：通过'); await waitText(page, '#network-channels', '浏览器登录：合成浏览器访问失败');
  });
  await testCase('local token original-ID writeback checks stale proof and submits only frozen targets', async (page, confirm) => {
    await navigate(page, 'accounts'); await page.click('#local-token-refresh'); await waitText(page, '#local-token-list', '回写目标 #160');
    await waitText(page, '#local-token-list', '仅依据已核验的相同 User ID');
    await page.click('[data-local-token-index="0"]'); fixture.localTokens[0].executionRevision = 'changed-execution';
    await page.click('#local-token-update'); await waitText(page, '#notice', '预览已更新'); assert.equal(writes().length, 0);
    assert.equal(await page.$eval('[data-local-token-index="0"]', el => el.checked), false);
    await page.click('[data-local-token-index="0"]'); confirm(false); await page.click('#local-token-update'); assert.equal(writes().length, 0);
    confirm(true); await page.click('#local-token-update'); await waitText(page, '#notice', '任务已交给服务器');
    assert.equal(writes().length, 1);
    assert.deepEqual(writes()[0].body, { accountIds: [160], importNew: false, refreshInvalid: false, deleteBanned: false,
      localTokenTargets: [{ selectedKey: 'token:synthetic', accountId: 160, targetRevision: 'target-revision', sourceContentHash: 'source-revision', executionRevision: 'changed-execution' }] });
    await page.waitForFunction(() => document.querySelector('#task-dialog').open);
  });
  await testCase('main-console details keep token writeback success separate from failed model test on both viewports', async page => {
    fixture.detailJobs.set(failedId, { id: failedId, type: 'console_maintain', status: 'partial', createdAt: '2026-10-12T02:00:00Z', result: {
      stage: 'completed', summary: { tokensGenerated: 1, tokensUpdated: 1, tested: 1, verified: 0, testFailed: 1 },
      items: [{ accountId: 160, accountName: 'free00047', phases: { tokenGenerated: true, tokenUpdated: true, tested: true, verified: false }, failureCategory: 'model_unavailable', upstreamStatus: 403, message: '测试未通过，不代表 token 回写失败。请核对模型后只测试原账号。' }],
    } });
    for (const width of [1440, 390]) {
      await page.setViewport({ width, height: width === 390 ? 844 : 1050 }); await navigate(page, 'accounts');
      await page.click('#account-jobs [data-job-detail="' + failedId + '"]'); await waitText(page, '#task-detail', '不代表 token 回写失败');
      await waitText(page, '#task-detail', '回写原账号1'); await waitText(page, '#task-detail', '测试通过0'); await waitText(page, '#task-detail', '模型不可用 · HTTP 403');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
      assert.equal(await page.$eval('#task-dialog', dialog => { const box = dialog.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth + 1 && box.top >= 0 && box.bottom <= innerHeight + 1; }), true, 'task dialog must fit the viewport');
      if (process.env.PANEL_TEST_SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.PANEL_TEST_SCREENSHOT_DIR, 'mock-' + width + '-task-detail.png'), fullPage: false });
      await closeTaskDetail(page);
    }
    assert.equal(writes().length, 0);
  });
  await testCase('account detail selects exact original ID and only-test fetches fresh execution proof', async (page, confirm) => {
    await navigate(page, 'accounts'); await page.click('[data-account-detail="1"]'); await waitText(page, '#account-detail', '凭据已过期且账号不可用');
    await page.click('#account-dialog [data-select-result-account="160"]'); await waitText(page, '#notice', '已选中原账号 #160');
    assert.equal(writes().length, 0);
    fixture.overview.accounts[1].targetRevision = 'fresh-target160'; fixture.overview.accounts[1].executionRevision = 'fresh-execution160';
    await page.select('#test-model', 'gpt-5.6-luna'); confirm(false); await page.click('#test-selected'); assert.equal(writes().length, 0);
    confirm(true); await page.click('#test-selected'); await waitText(page, '#notice', '任务已交给服务器');
    assert.equal(writes().length, 1);
    assert.deepEqual(writes()[0].body, { accountIds: [160], importNew: false, refreshInvalid: false, deleteBanned: false, testOnly: true,
      accountTargets: [{ accountId: 160, targetRevision: 'fresh-target160', executionRevision: 'fresh-execution160' }], modelId: 'gpt-5.6-luna' });
    await page.waitForFunction(() => document.querySelector('#task-dialog').open);
  });
  await testCase('default import proxy requires confirmation and preserves unrelated policy edits', async (page, confirm) => {
    await page.setViewport({ width: 390, height: 844 });
    await navigate(page, 'settings'); await page.waitForFunction(() => !document.querySelector('#import-proxy-save').disabled);
    assert.equal(await page.$eval('#import-proxy-select option[value="9"]', option => option.disabled), true);
    await setInput(page, '#maintenance-interval', '95'); await page.select('#import-proxy-select', '7');
    if (process.env.PANEL_TEST_SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.PANEL_TEST_SCREENSHOT_DIR, 'mock-390-proxy-selected.png'), fullPage: true });
    confirm(false); await page.click('#import-proxy-save'); assert.equal(writes().length, 0);
    confirm(true); await page.click('#import-proxy-save'); await waitText(page, '#notice', '默认导入代理保存成功');
    assert.equal(writes().length, 1); const body = writes()[0].body;
    assert.equal(body.importProxy.proxyId, 7); assert.equal(body.importProxy.proxyRevision, 'proxy7-proof'); assert.equal(body.importProxy.revision, 0);
    assert.match(body.importProxy.requestId, /^[a-f0-9-]{36}$/); assert.equal(body.confirm, true); assert.equal(Object.hasOwn(body, 'policy'), false);
    assert.equal(await page.$eval('#maintenance-interval', input => input.value), '95');
    assert.match(fixture.confirmations.at(-1), /新增账号.*默认节点（#7）/); assert.match(fixture.confirmations.at(-1), /已有账号回写 token 保留原代理，注册机网络通道不变/);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, 'proxy settings has no page overflow');
    if (process.env.PANEL_TEST_SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.PANEL_TEST_SCREENSHOT_DIR, 'mock-390-proxy-saved.png'), fullPage: true });
    await navigate(page, 'register'); await waitText(page, '#register-import-proxy', '默认节点');
    assert.equal(await page.$eval('#register-import-proxy', el => el.textContent.includes('已连通')), false);
  });
  await testCase('proxy definite stale conflicts release only rejected receipt; missing nodes never fall back', async page => {
    await navigate(page, 'settings'); await page.waitForFunction(() => !document.querySelector('#import-proxy-save').disabled); await page.select('#import-proxy-select', '7');
    for (const mode of ['stale', 'node-changed']) {
      fixture.proxyMode = mode; const before = writes().length;
      const response = page.waitForResponse(response => response.url() === origin + '/api/console/settings' && response.request().method() === 'POST');
      await page.click('#import-proxy-save'); assert.equal((await response).status(), 409); await waitText(page, '#notice', '代理配置或节点已变化');
      await page.waitForFunction(() => !document.querySelector('#import-proxy-save').disabled);
      assert.equal(writes().length, before + 1); assert.equal(await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')), null);
    }
    fixture.proxyMode = 'ok'; fixture.overview.settings.importProxy = { revision: 2, proxyId: 81, configured: true, endpointMatches: true, lastRequestId: null };
    await page.reload({ waitUntil: 'networkidle0' }); await waitText(page, '#import-proxy-hint', '所选节点不在最新清单');
    assert.equal(await page.$eval('#import-proxy-select', el => el.value), '81'); assert.equal(await page.$eval('#import-proxy-save', el => el.disabled), true);
    const count = writes().length; fixture.proxyMode = 'unavailable'; await page.click('#import-proxy-refresh'); await waitText(page, '#import-proxy-hint', '列表读取失败');
    assert.equal(writes().length, count); assert.equal(await page.$eval('#import-proxy-select', el => el.value), '81');
  });
  await testCase('lost proxy save response reload recovers only own request ID without another POST', async page => {
    await navigate(page, 'settings'); await page.waitForFunction(() => !document.querySelector('#import-proxy-save').disabled);
    fixture.proxyMode = 'lost-response'; await page.select('#import-proxy-select', '7'); await page.click('#import-proxy-save'); await waitText(page, '#notice', '代理设置保存结果未知');
    const raw = await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')); const pending = JSON.parse(raw);
    assert.equal(pending.body.importProxy.proxyId, 7); assert.equal(Object.hasOwn(pending.body.importProxy, 'proxyRevision'), false);
    assert.equal(writes().length, 1); await page.reload({ waitUntil: 'networkidle0' }); assert.equal(writes().length, 1);
    await page.click('#resolve-pending'); await waitText(page, '#notice', '默认导入代理保存成功');
    assert.equal(writes().length, 1); assert.equal(await page.evaluate(() => sessionStorage.getItem('registerStudio.pending.v1')), null);
  });
  await testCase('clearing import proxy is explicit null and does not claim a direct network path', async (page, confirm) => {
    fixture.overview.settings.importProxy = { revision: 1, proxyId: 7, configured: true, endpointMatches: true, lastRequestId: null };
    await navigate(page, 'settings'); await page.waitForFunction(() => document.querySelector('#import-proxy-select').value === '7');
    await page.select('#import-proxy-select', 'none'); confirm(false); await page.click('#import-proxy-save'); assert.equal(writes().length, 0);
    confirm(true); await page.click('#import-proxy-save'); await waitText(page, '#notice', '默认导入代理保存成功');
    assert.equal(writes().length, 1); assert.equal(writes()[0].body.importProxy.proxyId, null); assert.equal(Object.hasOwn(writes()[0].body.importProxy, 'proxyRevision'), false);
    await navigate(page, 'register'); await waitText(page, '#register-import-proxy', '沿用 Sub2API 网络配置');
  });
  assert.deepEqual(failures, []); assert.deepEqual(externalRequests, []);
  console.log(JSON.stringify({ browserAcceptance: 'passed', scenarios: completed.length, viewports: ['1440x1050', '390x844'], productionRequests: 0, externalPageRequests: 0, pageErrors: 0 }));
}
main().catch(error => { console.error(JSON.stringify({ browserAcceptance: 'failed', scenario: currentCase, step: currentStep, reason: error.message, failures })); process.exitCode = 1; })
  .finally(async () => { if (browser) await browser.close(); if (server.listening) await new Promise(resolve => server.close(resolve)); });
