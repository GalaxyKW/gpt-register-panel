'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { normalizeRegistrationOptions, runEngineCommand, runRegistrationJob, runRegistrationResumeJob, listRegistrationContinuations, verifyRegistrationArtifacts, readRegistrationProtocol } = require('../backend/registrationWorker');
const { runNetworkPreflight } = require('../backend/networkPreflight');
const { runCommand } = require('../backend/phase3Worker');
const { readRegistrationSettings, updateRegistrationSettings } = require('../backend/registrationSettings');
const logger = { checkpoint: () => true };

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-registration-test-'));
  fs.mkdirSync(path.join(root, 'src')); fs.mkdirSync(path.join(root, 'tokens')); fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]', { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), '', { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'src/phoneCountryCatalog.js'), 'module.exports={DEFAULT_PHONE_COUNTRIES:[{isoCode:"US",name:"美国",heroSmsCountry:187}],normalizePhoneCountries:x=>x}', { mode: 0o600 });
  const config = { heroSmsApiKey: 'fixture-only-sms-secret', mailAdminToken: 'fixture-only-mail-secret', mailBaseUrl: 'https://mail.example.test', mailDomain: 'example.test', phoneCountryCode: 'US', proxyPassword: 'fixture-only-proxy-secret' };
  fs.writeFileSync(path.join(root, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, config };
}
function writeEvents(options, events) {
  const fd = options.extraFileDescriptors[3];
  fs.writeFileSync(fd, events.map((event, index) => JSON.stringify({ version: 1, sequence: index + 1, ...event })).join('\n') + '\n');
  return { code: 0, terminationConfirmed: true };
}
test('registration request accepts only bounded explicit arguments', () => {
  assert.deepEqual(normalizeRegistrationOptions({ count: 1, country: 'US' }), { count: 1, country: 'US', operator: '' });
  for (const options of [{ count: 0, country: 'US' }, { count: 101, country: 'US' }, { count: 1, country: 'XX;id' }, { count: 1, country: 'US', operator: 'a b' }, { count: 1, country: 'US', shell: 'anything' }]) assert.throws(() => normalizeRegistrationOptions(options), { code: 'REGISTRATION_OPTIONS_INVALID' });
});
test('settings never echo secrets and atomically overlay only explicitly saved fields', t => {
  const f = fixture(t); const original = fs.readFileSync(path.join(f.root, 'config.json'), 'utf8');
  const view = readRegistrationSettings({ rootDirectory: f.root });
  assert.equal(view.ready, true); assert.equal(JSON.stringify(view).includes('fixture-only'), false);
  const next = updateRegistrationSettings({ rootDirectory: f.root, revision: view.revision, changes: { mailAdminToken: 'fixture-only-replacement', mailDomain: 'new.example.test' } });
  assert.notEqual(next.revision, view.revision); assert.equal(JSON.stringify(next).includes('fixture-only'), false);
  assert.equal(fs.readFileSync(path.join(f.root, 'config.json'), 'utf8'), original);
  const overlay = JSON.parse(fs.readFileSync(path.join(f.root, 'config.panel.json')));
  assert.deepEqual(overlay.mailDomains, ['new.example.test']); assert.equal(Object.hasOwn(overlay, 'heroSmsApiKey'), false);
  assert.equal(fs.statSync(path.join(f.root, 'config.panel.json')).mode & 0o777, 0o600);
});
test('settings reject stale versions, executable/path edits and inline URL credentials', t => {
  const f = fixture(t); const view = readRegistrationSettings({ rootDirectory: f.root });
  assert.throws(() => updateRegistrationSettings({ rootDirectory: f.root, revision: '0'.repeat(64), changes: { proxyPort: 8080 } }), { code: 'REGISTRATION_SETTINGS_CHANGED' });
  for (const changes of [{ chromePath: '/tmp/anything' }, { tokenOutputDirs: ['/tmp/output'] }, { requireProxy: false }, { mailBaseUrl: 'https://user:pass@example.test' }, { mailAdminToken: '' }, { proxyPort: 65536 }]) assert.throws(() => updateRegistrationSettings({ rootDirectory: f.root, revision: view.revision, changes }));
  assert.equal(fs.existsSync(path.join(f.root, 'config.panel.json')), false);
});
test('settings refuse symlink overlay and redact legacy URL credentials', t => {
  const f = fixture(t); fs.writeFileSync(path.join(f.root, 'config.json'), JSON.stringify({ ...f.config, mailBaseUrl: 'https://user:fixture-only-password@example.test/?key=fixture-only-key' }));
  assert.equal(JSON.stringify(readRegistrationSettings({ rootDirectory: f.root })).includes('fixture-only'), false);
  fs.symlinkSync(path.join(f.root, 'config.json'), path.join(f.root, 'config.panel.json'));
  assert.throws(() => readRegistrationSettings({ rootDirectory: f.root }), { code: 'REGISTRATION_SETTINGS_UNSAFE' });
});
test('settings expose an opaque save receipt but never replay a completed request', t => {
  const f = fixture(t); const before = readRegistrationSettings({ rootDirectory: f.root }); const requestId = crypto.randomUUID();
  const saved = updateRegistrationSettings({ rootDirectory: f.root, revision: before.revision, requestId, changes: { proxyPort: 8081 } });
  assert.equal(saved.lastRequestId, requestId);
  assert.equal(readRegistrationSettings({ rootDirectory: f.root }).lastRequestId, requestId);
  assert.throws(() => updateRegistrationSettings({ rootDirectory: f.root, revision: saved.revision, requestId, changes: { proxyPort: 8082 } }), { code: 'REGISTRATION_SETTINGS_REQUEST_REPLAY' });
  assert.throws(() => updateRegistrationSettings({ rootDirectory: f.root, revision: saved.revision, requestId: 'invalid', changes: { proxyPort: 8082 } }), { code: 'REGISTRATION_SETTINGS_REQUEST_INVALID' });
});
test('fixed descriptor launcher isolates profile, environment, argv and result channel', async t => {
  const f = fixture(t); let profile;
  const result = await runEngineCommand({ logger, rootDirectory: f.root, arguments: ['--panel-network-preflight'], runner: async (command, args, options) => {
    assert.equal(command, '/proc/self/fd/4'); assert.equal(options.cwd, '/proc/self/fd/5');
    assert.deepEqual(args.slice(-2), ['--', '--panel-network-preflight']);
    assert.equal(options.env.GPT_REGISTER_PANEL_RESULT_FD, '6'); assert.equal(Object.hasOwn(options.env, 'SUB2API_ADMIN_API_KEY'), false);
    profile = options.env.GPT_REGISTER_PANEL_BROWSER_PROFILE;
    assert.equal(fs.statSync(profile).mode & 0o777, 0o700);
    return writeEvents(options, [{ type: 'completed', requestedCount: 1 }]);
  } });
  assert.equal(result.events.length, 1); assert.equal(fs.existsSync(profile), false);
});
test('cancel before spawn does not create an unknown-process reconciliation hold', async t => {
  const f = fixture(t); const controller = new AbortController(); controller.abort(); let spawned = false;
  await assert.rejects(runEngineCommand({ logger, rootDirectory: f.root, signal: controller.signal, arguments: ['--panel-network-preflight'], runner: async () => { spawned = true; } }), error => error.code === 'JOB_INTERRUPTED' && !error.requiresReconciliation);
  assert.equal(spawned, false);
  const late = new AbortController();
  await assert.rejects(runEngineCommand({ logger: { checkpoint: () => { late.abort(); return true; } }, rootDirectory: f.root, signal: late.signal, arguments: ['--panel-network-preflight'], runner: async () => { spawned = true; } }), error => error.code === 'JOB_INTERRUPTED' && !error.requiresReconciliation);
  assert.equal(spawned, false);
});
test('structured result parser rejects missing newline, order drift and oversized data', t => {
  const f = fixture(t); const file = path.join(f.root, 'fixture-result'); fs.writeFileSync(file, '{"version":1,"sequence":2,"type":"completed"}\n');
  const fd = fs.openSync(file, 'r+'); t.after(() => fs.closeSync(fd));
  assert.throws(() => readRegistrationProtocol(fd), { code: 'REGISTRATION_PROTOCOL_INVALID' });
  fs.writeFileSync(file, '{"version":1,"sequence":1,"type":"completed"}');
  assert.throws(() => readRegistrationProtocol(fd), { code: 'REGISTRATION_PROTOCOL_INVALID' });
  assert.deepEqual(readRegistrationProtocol(fd, true), []);
  fs.truncateSync(file, 1024 * 1024 + 1); assert.throws(() => readRegistrationProtocol(fd), { code: 'REGISTRATION_PROTOCOL_INVALID' });
});
test('preflight must prove all three channels and never treats exit failure as pass', async t => {
  const f = fixture(t);
  const channels = ['sms', 'mail', 'oauth'].map(id => ({ id, ok: true, code: 'OK', message: 'fixture' }));
  const result = await runNetworkPreflight({ logger, rootDirectory: f.root, runner: async (_, __, options) => writeEvents(options, [{ type: 'preflight_completed', result: { channels } }]) });
  assert.equal(result.ok, true);
  await assert.rejects(runNetworkPreflight({ logger, rootDirectory: f.root, runner: async (_, __, options) => writeEvents(options, [{ type: 'preflight_completed', result: { channels: channels.slice(1) } }]) }), { code: 'NETWORK_PREFLIGHT_INVALID' });
});
test('preflight preserves independent OAuth node and browser diagnostic results', async t => {
  const f = fixture(t);
  const channels = ['sms', 'mail'].map(id => ({ id, ok: true, code: 'OK' }));
  channels.push({ id: 'oauth', ok: false, code: 'OAUTH_CHANNEL_FAILED', checks: [
    { id: 'node_oauth', ok: true, code: 'OK', message: '只读交换接口可达', httpStatus: 405, durationMs: 10 },
    { id: 'browser', ok: false, code: 'BROWSER_CHALLENGE', message: '浏览器遇到访问挑战', httpStatus: 403, durationMs: 20, raw: 'fixture-only-private-payload' },
  ] });
  const result = await runNetworkPreflight({ logger, rootDirectory: f.root, runner: async (_, __, options) => writeEvents(options, [{ type: 'preflight_completed', result: { channels } }]) });
  assert.equal(result.ok, false);
  assert.deepEqual(result.channels[2].checks.map(check => [check.id, check.code, check.httpStatus, check.durationMs]), [['node_oauth', 'OK', 405, 10], ['browser', 'BROWSER_CHALLENGE', 403, 20]]);
  assert.equal(JSON.stringify(result).includes('fixture-only-private-payload'), false);
});
test('failed preflight prevents registration process launch', async t => {
  const f = fixture(t); let invoked = false;
  await assert.rejects(runRegistrationJob({ rootDirectory: f.root, options: { count: 1, country: 'US' }, preflight: async () => ({ ok: false }), runner: async () => { invoked = true; } }), { code: 'REGISTRATION_PREFLIGHT_FAILED' });
  assert.equal(invoked, false);
});
test('registration batch deadline scales with requested count but remains bounded to 24 hours', async t => {
  const f = fixture(t);
  for (const [count, expectedMinutes] of [[1, 30], [2, 60], [48, 1440], [100, 1440]]) {
    let calls = 0;
    await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count, country: 'US' }, preflight: async () => ({ ok: true }), runner: async (_, __, options) => {
      calls += 1; assert.equal(options.timeoutMs, expectedMinutes * 60 * 1000); assert.equal(options.registrationBatch, true);
      return writeEvents(options, [{ type: 'failed', code: 'FIXTURE_STOPPED' }]);
    } }), { code: 'FIXTURE_STOPPED' });
    assert.equal(calls, 1);
  }
});
test('supervised process timer keeps the Phase3 ceiling but permits bounded registration batches', async t => {
  const originalTimeout = global.setTimeout; const timers = [];
  global.setTimeout = function (callback, delay, ...args) { timers.push(delay); return originalTimeout(callback, delay, ...args); };
  t.after(() => { global.setTimeout = originalTimeout; });
  for (const [options, expectedHours] of [
    [{ timeoutMs: 48 * 60 * 60 * 1000 }, 2],
    [{ timeoutMs: 48 * 60 * 60 * 1000, registrationBatch: true }, 24],
    [{ timeoutMs: 3 * 60 * 60 * 1000, registrationBatch: true }, 3],
  ]) {
    timers.length = 0;
    const result = await runCommand(process.execPath, ['-e', 'process.exitCode=0'], options);
    assert.equal(result.terminationConfirmed, true);
    assert.equal(timers.includes(expectedHours * 60 * 60 * 1000), true);
    assert.equal(timers.includes(48 * 60 * 60 * 1000), false);
  }
});
function proofFixture() {
  const record = { relativePath: 'tokens/codex-fixture@example.test-free.json', contentHash: 'a'.repeat(64), parseStatus: 'ok', expiryStatus: 'valid', expiresAt: '2099-01-01T00:00:00Z', identityKeys: ['account:fixture-account', 'user:fixture-user'] };
  const event = { type: 'account_completed', completedCount: 1, artifacts: [{ selectedKey: 'token:tokens:' + record.relativePath, contentHash: record.contentHash }] };
  return { record, event };
}
test('only hash-bound new valid strong identities are accepted as registered output', () => {
  const { record, event } = proofFixture();
  assert.equal(verifyRegistrationArtifacts([event], { tokens: [] }, { tokens: [record] }, 1).length, 1);
  for (const changed of [{ contentHash: 'b'.repeat(64) }, { expiresAt: '2020-01-01T00:00:00Z' }, { identityKeys: ['email:fixture@example.test'] }, { historical: true }, { disabled: true }, { parseStatus: 'invalid' }]) assert.throws(() => verifyRegistrationArtifacts([event], { tokens: [] }, { tokens: [{ ...record, ...changed }] }, 1), { code: 'REGISTRATION_OUTPUT_INVALID' });
  assert.throws(() => verifyRegistrationArtifacts([event], { tokens: [record] }, { tokens: [record] }, 1), { code: 'REGISTRATION_OUTPUT_INVALID' });
});
test('stdout success and process exit zero alone cannot prove registration', async t => {
  const f = fixture(t);
  await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 1, country: 'US' }, preflight: async () => ({ ok: true }), runner: async (_, __, options) => ({ ...writeEvents(options, [{ type: 'completed', requestedCount: 1 }]), stdout: 'success' }) }), { code: 'REGISTRATION_INCOMPLETE' });
});
test('paid-account continuation is surfaced without rerunning or allocating another account', async t => {
  const f = fixture(t); let calls = 0;
  await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 1, country: 'US' }, preflight: async () => ({ ok: true }), runner: async (_, __, options) => {
    calls += 1; const result = writeEvents(options, [{ type: 'failed', code: 'BATCH_PENDING_PHASE2_CONTINUATION', nextAction: 'resume_phase2' }]);
    throw Object.assign(new Error('fixture'), { details: { ...result, code: 1 } });
  } }), error => error.code === 'BATCH_PENDING_PHASE2_CONTINUATION' && error.details.nextAction === 'resume_phase2');
  assert.equal(calls, 1);
});
test('real supervised child returns fd6 protocol and cleanup confirms process exit', async t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.root, 'index.js'), [
    "const fs = require('node:fs');",
    "if (!process.argv.includes('--panel-network-preflight')) throw new Error('wrong argv');",
    "fs.writeFileSync(6, JSON.stringify({ version: 1, sequence: 1, type: 'completed', requestedCount: 1 }) + '\\n');",
  ].join('\n'), { mode: 0o600 });
  const output = await runEngineCommand({ logger, rootDirectory: f.root, arguments: ['--panel-network-preflight'], timeoutMs: 5000 });
  assert.equal(output.processSummary.terminationConfirmed, true); assert.equal(output.events[0].type, 'completed');
});
test('full registration verifies a newly written artifact through the real supervised launcher', async t => {
  const f = fixture(t);
  const document = { email: 'fixture@example.test', chatgpt_account_id: 'fixture-new-account', chatgpt_user_id: 'fixture-new-user',
    access_token: crypto.randomBytes(24).toString('hex'), refresh_token: crypto.randomBytes(24).toString('hex'), expires_at: '2099-01-01T00:00:00Z', type: 'codex' };
  fs.writeFileSync(path.join(f.root, 'index.js'), [
    "const fs = require('node:fs'), crypto = require('node:crypto');",
    "if (!process.argv.includes('--country=US') || !process.argv.includes('--operator=')) throw new Error('wrong argv');",
    'const bytes = JSON.stringify(' + JSON.stringify(document) + ');',
    "fs.writeFileSync('tokens/new.json', bytes, {mode:0o600});",
    "const events = [{type:'started',requestedCount:1},{type:'account_completed',completedCount:1,artifacts:[{selectedKey:'token:tokens:tokens/new.json',contentHash:crypto.createHash('sha256').update(bytes).digest('hex')}]},{type:'completed',requestedCount:1}];",
    "fs.writeFileSync(6, events.map((event, index) => JSON.stringify({version:1,sequence:index+1,...event})).join('\\n')+'\\n');",
  ].join('\n'), { mode: 0o600 });
  const result = await runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 1, country: 'US' }, preflight: async () => ({ ok: true }) });
  assert.equal(result.completedCount, 1); assert.deepEqual(result.selectedKeys, ['token:tokens:tokens/new.json']);
  assert.equal(result.artifacts[0].identityKeys.includes('account:fixture-new-account'), true);
  assert.equal(JSON.stringify(result).includes(document.access_token), false);
});
test('unconfirmed process termination creates an explicit non-retryable reconciliation hold', async t => {
  const f = fixture(t); let retained;
  await assert.rejects(runEngineCommand({ logger, rootDirectory: f.root, arguments: ['--panel-network-preflight'], runner: async (_, __, options) => {
    retained = options.env.GPT_REGISTER_PANEL_BROWSER_PROFILE;
    return { code: null, terminationConfirmed: false };
  } }), error => error.requiresReconciliation === true && error.writeOutcomeUnknown === true && error.doNotRetry === true);
  assert.equal(fs.existsSync(retained), true);
  // This is an injected child: no process was launched and the exact private
  // fixture directory is safe to remove after verifying its identity above.
  fs.rmSync(retained, { recursive: true });
});
function continuationFixture(t, status = 'registered') {
  const f = fixture(t);
  f.account = { phone: '+15551234000', password: crypto.randomBytes(24).toString('hex'), smsActivationId: 'fixture-activation', status, email: status === 'registered' ? undefined : 'resume@example.test' };
  fs.writeFileSync(path.join(f.root, 'accounts.json'), JSON.stringify([f.account]), { mode: 0o600 });
  return f;
}
test('continuations use opaque revisions and mask phones without exposing credentials', t => {
  const f = continuationFixture(t); const result = listRegistrationContinuations({ rootDirectory: f.root });
  assert.equal(result.items.length, 1); assert.equal(result.items[0].stage, 'phase2'); assert.equal(result.items[0].eligible, true);
  assert.equal(result.items[0].phoneMasked, '***4000'); assert.equal(JSON.stringify(result).includes(f.account.password), false); assert.equal(JSON.stringify(result).includes(f.account.phone), false);
  fs.writeFileSync(path.join(f.root, 'accounts.json'), JSON.stringify([f.account, f.account]));
  assert.equal(listRegistrationContinuations({ rootDirectory: f.root }).items.every(item => !item.eligible), true);
});
test('continuation rejects stale complete-file bindings before any network or login', async t => {
  const f = continuationFixture(t); const { selectedKey, revision } = listRegistrationContinuations({ rootDirectory: f.root }).items[0];
  fs.writeFileSync(path.join(f.root, 'accounts.json'), JSON.stringify([{ ...f.account, name: 'changed' }]));
  let reached = false;
  await assert.rejects(runRegistrationResumeJob({ logger, rootDirectory: f.root, target: { selectedKey, revision }, preflight: async () => { reached = true; } }), { code: 'REGISTRATION_RESUME_TARGET_CHANGED' });
  assert.equal(reached, false);
});
test('resume launches exactly one fixed phase and delivers binding on a read-only fd7', async t => {
  const f = continuationFixture(t, 'oauth_phase3_failed'); const { selectedKey, revision } = listRegistrationContinuations({ rootDirectory: f.root }).items[0];
  let calls = 0;
  await assert.rejects(runRegistrationResumeJob({ logger, rootDirectory: f.root, target: { selectedKey, revision }, preflight: async () => ({ ok: true }), runner: async (_, args, options) => {
    calls += 1; assert.deepEqual(args.slice(-2), ['--panel-resume', '--phase3']);
    assert.equal(options.env.GPT_REGISTER_PANEL_RESUME_FD, '7');
    assert.equal(options.timeoutMs, 30 * 60 * 1000);
    assert.equal(options.registrationBatch, false);
    const fd = options.extraFileDescriptors[4];
    const binding = JSON.parse(fs.readFileSync(fd, 'utf8'));
    assert.equal(binding.index, 0); assert.equal(binding.stage, 'phase3'); assert.match(binding.fileHash, /^[a-f0-9]{64}$/);
    assert.equal(JSON.stringify(binding).includes(f.account.password), false);
    assert.throws(() => fs.writeSync(fd, 'unsafe'));
    return writeEvents(options, [{ type: 'failed', code: 'FIXTURE_LOGIN_FAILED' }]);
  } }), { code: 'FIXTURE_LOGIN_FAILED' });
  assert.equal(calls, 1);
});
test('resume accepts a validated token only for the exact selected account binding', async t => {
  const f = continuationFixture(t, 'oauth_phase3_failed'); const { selectedKey, revision } = listRegistrationContinuations({ rootDirectory: f.root }).items[0];
  const document = { email: 'resume@example.test', chatgpt_account_id: 'fixture-resume-account', chatgpt_user_id: 'fixture-resume-user',
    access_token: crypto.randomBytes(24).toString('hex'), refresh_token: crypto.randomBytes(24).toString('hex'), expires_at: '2099-01-01T00:00:00Z', type: 'codex' };
  const result = await runRegistrationResumeJob({ logger, rootDirectory: f.root, target: { selectedKey, revision }, preflight: async () => ({ ok: true }), runner: async (_, __, options) => {
    const bytes = JSON.stringify(document); fs.writeFileSync(path.join(f.root, 'tokens/resumed.json'), bytes, { mode: 0o600 });
    return writeEvents(options, [{ type: 'account_completed', completedCount: 1, artifacts: [{ selectedKey: 'token:tokens:tokens/resumed.json', contentHash: crypto.createHash('sha256').update(bytes).digest('hex') }] }, { type: 'completed', requestedCount: 1 }]);
  } });
  assert.equal(result.resumed, true); assert.equal(result.completedCount, 1);
});
const relatedEngineProtocol = path.resolve(__dirname, '../../../gpt_register/src/panelProtocol.js');
test('real child validates private fd7 against exact ledger bytes before any resume action', { skip: !fs.existsSync(relatedEngineProtocol) }, async t => {
  const f = continuationFixture(t); const bytes = fs.readFileSync(path.join(f.root, 'accounts.json'));
  const binding = { index: 0, stage: 'phase2', fileHash: crypto.createHash('sha256').update(bytes).digest('hex'), recordHash: crypto.createHash('sha256').update(JSON.stringify(f.account)).digest('hex') };
  // This extra cross-repository integration test is available when the engine
  // is checked out beside the panel; standalone panel CI uses the fake-engine
  // subprocess tests above and never resolves a production config or ledger.
  fs.writeFileSync(path.join(f.root, 'index.js'), [
    "const fs = require('node:fs');",
    'const {readResumeBinding}=require(' + JSON.stringify(relatedEngineProtocol) + ');',
    "const bound=readResumeBinding(process.cwd()+'/accounts.json');",
    "if(bound.index!==0||bound.stage!=='phase2')throw new Error('wrong binding');",
    "fs.writeFileSync(6,JSON.stringify({version:1,sequence:1,type:'completed',requestedCount:1})+'\\n');",
  ].join('\n'), { mode: 0o600 });
  const output = await runEngineCommand({ logger, rootDirectory: f.root, arguments: ['--panel-resume', '--phase2'], resumeBinding: binding });
  assert.equal(output.commandError, undefined); assert.equal(output.events[0].type, 'completed');
  fs.writeFileSync(path.join(f.root, 'accounts.json'), JSON.stringify([{ ...f.account, phone: '+15551234001' }]));
  const stale = await runEngineCommand({ logger, rootDirectory: f.root, arguments: ['--panel-resume', '--phase2'], resumeBinding: binding });
  assert.ok(stale.commandError); assert.equal(stale.events.length, 0);
});
