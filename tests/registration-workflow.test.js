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
test('controlled single registration accepts paired decimal SMS caps without changing legacy requests', () => {
  const base = { count: 1, country: 'US', operator: '' };
  assert.deepEqual(normalizeRegistrationOptions(base), base);
  for (const smsMaxPriceUsd of ['0.0001', '0.5', '0.5000', '0.9999', '1', '1.0000']) {
    const options = { ...base, smsMaxPriceUsd, smsMaxAcquisitions: 1 };
    assert.deepEqual(normalizeRegistrationOptions(options), options);
  }
});
test('controlled registration rejects incomplete caps, non-decimals, over-limit amounts and batches', () => {
  const base = { count: 1, country: 'US', smsMaxPriceUsd: '0.5', smsMaxAcquisitions: 1 };
  const invalid = [
    { count: 1, country: 'US', smsMaxPriceUsd: '0.5' }, { count: 1, country: 'US', smsMaxAcquisitions: 1 },
    { ...base, count: 2 }, { ...base, smsMaxPriceUsd: undefined }, { ...base, smsMaxAcquisitions: undefined },
    ...[0, 2, '1', 1.5, true, null].map(smsMaxAcquisitions => ({ ...base, smsMaxAcquisitions })),
    ...['', '0', '0.0000', '-0.1', '+0.1', '.5', '00.5', '1.', '1.0001', '2', '0.00001', '1e-1',
      ' 0.5', '0.5 ', '0.5\n', '0.5\r\n', '0.5\t', '0.5;id', 'Infinity', 'NaN', 0.5, null, true, {}]
      .map(smsMaxPriceUsd => ({ ...base, smsMaxPriceUsd })),
  ];
  for (const options of invalid) assert.throws(() => normalizeRegistrationOptions(options), { code: 'REGISTRATION_OPTIONS_INVALID' });
});
test('controlled SMS caps reach the fixed engine argv exactly once; legacy argv stays unchanged', async t => {
  const f = fixture(t);
  for (const caps of [{}, { smsMaxPriceUsd: '0.5000', smsMaxAcquisitions: 1 }]) {
    let launches = 0;
    await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root,
      options: { count: 1, country: 'US', operator: 'fixture_operator', ...caps }, preflight: async () => ({ ok: true }),
      runner: async (_, args, options) => {
        launches += 1;
        const expected = ['1', '--panel-register', '--country=US', '--operator=fixture_operator',
          ...(caps.smsMaxPriceUsd ? ['--sms-max-price-usd=0.5000', '--sms-max-acquisitions=1'] : [])];
        assert.deepEqual(args.slice(args.indexOf('--') + 1), expected);
        return writeEvents(options, [{ type: 'failed', code: 'FIXTURE_CONTROLLED_STOP' }]);
      } }), { code: 'FIXTURE_CONTROLLED_STOP' });
    assert.equal(launches, 1);
  }
});
test('invalid controlled registration does not run preflight or launch any engine', async t => {
  const f = fixture(t); let calls = 0;
  await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root,
    options: { count: 2, country: 'US', smsMaxPriceUsd: '0.5', smsMaxAcquisitions: 1 },
    preflight: async () => { calls += 1; }, runner: async () => { calls += 1; } }), { code: 'REGISTRATION_OPTIONS_INVALID' });
  assert.equal(calls, 0);
});
test('real supervised child receives both controlled SMS flags without shell interpretation', async t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.root, 'index.js'), [
    "const fs = require('node:fs');",
    "const prices = process.argv.filter(arg => arg.startsWith('--sms-max-price-usd='));",
    "const counts = process.argv.filter(arg => arg.startsWith('--sms-max-acquisitions='));",
    "if (prices.length !== 1 || prices[0] !== '--sms-max-price-usd=0.5000' || counts.length !== 1 || counts[0] !== '--sms-max-acquisitions=1') throw new Error('wrong controlled argv');",
    "fs.writeFileSync(6, JSON.stringify({version:1, sequence:1, type:'failed', code:'FIXTURE_CONTROLLED_ARGV_VERIFIED'}) + '\\n');",
  ].join('\n'), { mode: 0o600 });
  await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root,
    options: { count: 1, country: 'US', smsMaxPriceUsd: '0.5000', smsMaxAcquisitions: 1 },
    preflight: async () => ({ ok: true }) }), { code: 'FIXTURE_CONTROLLED_ARGV_VERIFIED' });
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
  const result = await runEngineCommand({ logger, jobId: 'job_' + 'a'.repeat(24), rootDirectory: f.root, arguments: ['--panel-network-preflight'], runner: async (command, args, options) => {
    assert.equal(options.jobId, 'job_' + 'a'.repeat(24));
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
for (const kind of ['rejected', 'invalid', 'cancelled']) {
  test('registration destination check ' + kind + ' after preflight prevents any engine launch', async t => {
    const f = fixture(t); const controller = new AbortController(); let launches = 0; const order = [];
    await assert.rejects(runRegistrationJob({ rootDirectory: f.root, options: { count: 1, country: 'US' },
      signal: controller.signal, preflight: async () => { order.push('preflight'); return { ok: true }; },
      beforeExecute: kind === 'invalid' ? {} : async () => {
        order.push('destination');
        if (kind === 'cancelled') controller.abort();
        else throw Object.assign(new Error('default proxy disabled'), { code: 'CONSOLE_IMPORT_PROXY_UNAVAILABLE' });
      }, runner: async () => { launches++; } }), { code: kind === 'invalid' ? 'REGISTRATION_DESTINATION_INVALID'
      : kind === 'cancelled' ? 'JOB_INTERRUPTED' : 'CONSOLE_IMPORT_PROXY_UNAVAILABLE' });
    assert.deepEqual(order, kind === 'invalid' ? ['preflight'] : ['preflight', 'destination']);
    assert.equal(launches, 0);
  });
}
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
for (const code of ['CREDENTIAL_INPUT_UNCONFIRMED', 'PASSWORD_INPUT_UNCONFIRMED',
  'CREDENTIAL_CONTEXT_CHANGED', 'CREDENTIAL_INPUT_CONTEXT_CHANGED', 'PHONE_COUNTRY_UNCONFIRMED',
  'PHONE_INPUT_UNCONFIRMED', 'PHONE_INPUT_INVALID', 'PHONE_INPUT_FORMAT_UNCONFIRMED']) {
  test('registration protocol presents ' + code + ' as current-form input failure without replay or raw engine text', async t => {
    const f = fixture(t); let calls = 0;
    await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 1, country: 'US' },
      preflight: async () => ({ ok: true }), runner: async (_, __, options) => {
        calls++;
        const result = writeEvents(options, [{ type: 'stage', stage: 'phase1_register' },
          { type: 'failed', code, message: 'fixture-only-private-engine-message', nextAction: 'retry_new_registration' }]);
        throw Object.assign(new Error('fixture-only-private-stderr'), { details: { ...result, code: 1 } });
      } }), error => {
      assert.equal(error.code, code);
      assert.match(error.message, /当前表单输入或页面上下文未通过确认，未继续主动提交/);
      assert.match(error.message, /已有订单、账号检查点及已生成 token/);
      assert.match(error.message, /不要重新租号/);
      assert.doesNotMatch(error.message, /网络|导入失败|全批未注册|fixture-only/);
      assert.equal(error.details.nextAction, null);
      assert.equal(error.details.completedCount, 0);
      assert.deepEqual(error.details.phases, [{ stage: 'phase1_register' }]);
      assert.equal(JSON.stringify(error.details).includes('fixture-only-private'), false);
      return true;
    });
    assert.equal(calls, 1);
  });
}
test('registration settlement safety stop preserves old-order uncertainty without claiming refund or retry', async t => {
  const f = fixture(t); let calls = 0;
  await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 1, country: 'US' },
    preflight: async () => ({ ok: true }), runner: async (_, __, options) => {
      calls++;
      return writeEvents(options, [{ type: 'failed', code: 'SMS_SETTLEMENT_WAIT_EXHAUSTED',
        message: 'fixture-only-private-order', nextAction: 'rent_again', refundConfirmed: true }]);
    } }), error => {
    assert.equal(error.code, 'SMS_SETTLEMENT_WAIT_EXHAUSTED');
    assert.match(error.message, /已有订单与账本保留待核对/);
    assert.match(error.message, /结算未确认不代表已退款/);
    assert.match(error.message, /未继续申请新号码/);
    assert.match(error.message, /不要重新租号/);
    assert.doesNotMatch(error.message, /当前表单|网络|导入失败|fixture-only/);
    assert.equal(error.details.nextAction, null);
    assert.equal(Object.hasOwn(error.details, 'refundConfirmed'), false);
    return true;
  });
  assert.equal(calls, 1);
});
test('unknown phone dispatch and unrecognized codes are never presented as unsubmitted input', async t => {
  const f = fixture(t);
  for (const code of ['PHONE_SUBMIT_RESULT_UNKNOWN', 'OAUTH_PHONE_SUBMIT_RESULT_UNKNOWN',
    'CREDENTIAL_INPUT_UNCONFIRMED_UNKNOWN', 'SMS_SETTLEMENT_WAIT_EXHAUSTED_UNKNOWN']) {
    await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 1, country: 'US' },
      preflight: async () => ({ ok: true }), runner: async (_, __, options) => writeEvents(options,
        [{ type: 'failed', code, message: '当前表单未提交，已退款，可以重新租号' }]) }), error => {
      assert.equal(error.code, code);
      assert.equal(error.message, '注册未完整完成，保留已落地账号与可验证产物');
      assert.doesNotMatch(error.message, /未提交|未继续主动提交|已退款|重新租号/);
      return true;
    });
  }
});
test('input failure after a verified batch artifact preserves that successful account and never claims whole batch unsubmitted', async t => {
  const f = fixture(t); let calls = 0;
  const document = { email: 'fixture-completed@example.test', chatgpt_account_id: 'fixture-completed-account',
    chatgpt_user_id: 'fixture-completed-user', access_token: crypto.randomBytes(24).toString('hex'),
    refresh_token: crypto.randomBytes(24).toString('hex'), expires_at: '2099-01-01T00:00:00Z', type: 'codex' };
  await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 2, country: 'US' },
    preflight: async () => ({ ok: true }), runner: async (_, __, options) => {
      calls++;
      const bytes = JSON.stringify(document); fs.writeFileSync(path.join(f.root, 'tokens/completed.json'), bytes, { mode: 0o600 });
      return writeEvents(options, [{ type: 'account_completed', completedCount: 1,
        artifacts: [{ selectedKey: 'token:tokens:tokens/completed.json', contentHash: crypto.createHash('sha256').update(bytes).digest('hex') }] },
      { type: 'stage', stage: 'phase1_register' }, { type: 'failed', code: 'CREDENTIAL_INPUT_UNCONFIRMED' }]);
    } }), error => {
    assert.equal(error.details.requestedCount, 2); assert.equal(error.details.completedCount, 1);
    assert.deepEqual(error.details.selectedKeys, ['token:tokens:tokens/completed.json']);
    assert.match(error.message, /当前表单输入/); assert.match(error.message, /已生成 token/);
    assert.doesNotMatch(error.message, /全批|未注册|未生成|全部失败/);
    assert.equal(JSON.stringify(error.details).includes(document.access_token), false);
    return true;
  });
  assert.equal(calls, 1);
  assert.equal(fs.existsSync(path.join(f.root, 'tokens/completed.json')), true);
});
test('interruption remains authoritative over an earlier unconfirmed-input event', async t => {
  const f = fixture(t);
  await assert.rejects(runRegistrationJob({ logger, rootDirectory: f.root, options: { count: 1, country: 'US' },
    preflight: async () => ({ ok: true }), runner: async (_, __, options) => {
      const result = writeEvents(options, [{ type: 'failed', code: 'CREDENTIAL_INPUT_UNCONFIRMED' }]);
      throw Object.assign(new Error('fixture cancellation'), { code: 'JOB_INTERRUPTED', details: result });
    } }), error => {
    assert.equal(error.code, 'JOB_INTERRUPTED');
    assert.doesNotMatch(error.message, /未继续主动提交/);
    return true;
  });
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
  if (f.account.email) fs.writeFileSync(path.join(f.root, 'username.json'), JSON.stringify([{ ...f.account }]), { mode: 0o600 });
  return f;
}
test('same-account resume projects fixed input and settlement failures without changing frozen ledgers or leasing anew', async t => {
  const f = continuationFixture(t, 'oauth_phase3_failed');
  const selected = listRegistrationContinuations({ rootDirectory: f.root }).items[0];
  const target = { selectedKey: selected.selectedKey, revision: selected.revision };
  const before = ['accounts.json', 'username.json'].map(name => fs.readFileSync(path.join(f.root, name), 'utf8'));
  for (const code of ['CREDENTIAL_INPUT_UNCONFIRMED', 'CREDENTIAL_INPUT_CONTEXT_CHANGED', 'PHONE_COUNTRY_UNCONFIRMED',
    'PHONE_INPUT_FORMAT_UNCONFIRMED', 'SMS_SETTLEMENT_WAIT_EXHAUSTED', 'PHONE_SUBMIT_RESULT_UNKNOWN']) {
    let calls = 0;
    await assert.rejects(runRegistrationResumeJob({ logger, rootDirectory: f.root, target,
      preflight: async () => ({ ok: true }), runner: async (_, args, options) => {
        calls++;
        assert.deepEqual(args.slice(-2), ['--panel-resume', '--phase3']);
        assert.equal(args.includes('--panel-register'), false);
        return writeEvents(options, [{ type: 'failed', code, message: 'fixture-only-private-resume', nextAction: 'rent_again' }]);
      } }), error => {
      assert.equal(error.code, code); assert.equal(error.details.nextAction, 'resume_account');
      assert.equal(error.details.resumed, true); assert.equal(error.details.completedCount, 0);
      if (code === 'SMS_SETTLEMENT_WAIT_EXHAUSTED') assert.match(error.message, /已有订单与账本保留待核对/);
      else if (code === 'PHONE_SUBMIT_RESULT_UNKNOWN') {
        assert.equal(error.message, '原账号续跑未完成，保留原检查点；未申请新号码');
        assert.doesNotMatch(error.message, /未继续主动提交/);
      } else assert.match(error.message, /当前表单输入或页面上下文未通过确认，未继续主动提交/);
      assert.doesNotMatch(error.message, /fixture-only/);
      return true;
    });
    assert.equal(calls, 1);
    assert.deepEqual(['accounts.json', 'username.json'].map(name => fs.readFileSync(path.join(f.root, name), 'utf8')), before);
  }
});
test('resume destination invalidated during preflight prevents engine launch without changing ledgers', async t => {
  const f = continuationFixture(t); const target = listRegistrationContinuations({ rootDirectory: f.root }).items[0];
  const before = fs.readFileSync(path.join(f.root, 'accounts.json')); let launches = 0; const order = [];
  await assert.rejects(runRegistrationResumeJob({ rootDirectory: f.root,
    target: { selectedKey: target.selectedKey, revision: target.revision },
    preflight: async () => { order.push('preflight'); return { ok: true }; },
    beforeExecute: async () => { order.push('destination'); throw Object.assign(new Error('proxy expired'), { code: 'CONSOLE_IMPORT_PROXY_UNAVAILABLE' }); },
    runner: async () => { launches++; } }), { code: 'CONSOLE_IMPORT_PROXY_UNAVAILABLE' });
  assert.deepEqual(order, ['preflight', 'destination']); assert.equal(launches, 0);
  assert.deepEqual(fs.readFileSync(path.join(f.root, 'accounts.json')), before);
});
test('continuations use opaque revisions and mask phones without exposing credentials', t => {
  const f = continuationFixture(t); const result = listRegistrationContinuations({ rootDirectory: f.root });
  assert.equal(result.items.length, 1); assert.equal(result.items[0].stage, 'phase2'); assert.equal(result.items[0].eligible, true);
  assert.equal(result.items[0].phoneMasked, '***4000'); assert.equal(JSON.stringify(result).includes(f.account.password), false); assert.equal(JSON.stringify(result).includes(f.account.phone), false);
  fs.writeFileSync(path.join(f.root, 'accounts.json'), JSON.stringify([f.account, f.account]));
  assert.equal(listRegistrationContinuations({ rootDirectory: f.root }).items.every(item => !item.eligible), true);
});
test('historical Phase3 blocker is projected from uniquely verified username without writing either ledger', t => {
  const f = continuationFixture(t, 'oauth_phase3_failed');
  const historical = { ...f.account, continuationRequired: true, continuationStage: 'phase3' }; delete historical.email;
  fs.writeFileSync(path.join(f.root, 'accounts.json'), JSON.stringify([historical]));
  const before = ['accounts.json', 'username.json'].map(name => fs.readFileSync(path.join(f.root, name), 'utf8'));
  const target = listRegistrationContinuations({ rootDirectory: f.root }).items[0];
  assert.equal(target.eligible, true); assert.equal(target.repairEmail, true); assert.equal(target.blockingRegistration, true); assert.equal(target.email, f.account.email);
  assert.equal(JSON.stringify(target).includes(f.account.password), false);
  assert.deepEqual(['accounts.json', 'username.json'].map(name => fs.readFileSync(path.join(f.root, name), 'utf8')), before);
  fs.writeFileSync(path.join(f.root, 'username.json'), JSON.stringify([{ ...f.account, password: 'different' }]));
  assert.equal(listRegistrationContinuations({ rootDirectory: f.root }).items[0].eligible, false);
});
test('Phase2 and Phase3 continuations reject legacy terminal aliases in either local ledger before preflight', async t => {
  const terminalVariants = [
    ...['disabled', 'deleted', 'deactivated', 'account_disabled', 'account_deleted', 'account_deactivated']
      .flatMap(status => [{ status }, { status: '  ' + status.toUpperCase() + ' \t' }]),
    { phase3Disposition: 'discard' }, { phase3Disposition: '  DiScArD \t' },
    { disabled: true }, { enabled: false }, { active: false },
  ];
  for (const status of ['registered', 'oauth_phase3_failed']) {
    const f = continuationFixture(t, status), account = { ...f.account }, username = { ...f.account, email: 'resume@example.test' };
    const accountsFile = path.join(f.root, 'accounts.json'), usernameFile = path.join(f.root, 'username.json');
    for (const change of terminalVariants) for (const [filename, record] of [[accountsFile, account], [usernameFile, username]]) {
      fs.writeFileSync(accountsFile, JSON.stringify([account])); fs.writeFileSync(usernameFile, JSON.stringify([username]));
      const selected = listRegistrationContinuations({ rootDirectory: f.root }).items[0]; assert.equal(selected.eligible, true);
      fs.writeFileSync(filename, JSON.stringify([{ ...record, ...change }]));
      const before = [accountsFile, usernameFile].map(file => fs.readFileSync(file, 'utf8'));
      assert.equal(listRegistrationContinuations({ rootDirectory: f.root }).items.some(item => item.eligible), false);
      let reached = false;
      await assert.rejects(runRegistrationResumeJob({ rootDirectory: f.root,
        target: { selectedKey: selected.selectedKey, revision: selected.revision },
        preflight: async () => { reached = true; }, runner: async () => { reached = true; },
      }), { code: 'REGISTRATION_RESUME_TARGET_CHANGED' });
      assert.equal(reached, false); assert.deepEqual([accountsFile, usernameFile].map(file => fs.readFileSync(file, 'utf8')), before);
    }
  }
});
test('Phase3 continuation binds both ledgers and rejects changed username before any preflight', async t => {
  const f = continuationFixture(t, 'oauth_phase3_failed');
  const target = listRegistrationContinuations({ rootDirectory: f.root }).items[0];
  fs.writeFileSync(path.join(f.root, 'username.json'), JSON.stringify([{ ...f.account, status: 'account_disabled' }]));
  let reached = false;
  await assert.rejects(runRegistrationResumeJob({ rootDirectory: f.root, target: { selectedKey: target.selectedKey, revision: target.revision }, preflight: async () => { reached = true; } }), { code: 'REGISTRATION_RESUME_TARGET_CHANGED' });
  assert.equal(reached, false);
});
test('Phase3 resume uses mail/OAuth-only preflight even when no SMS key is configured', async t => {
  const f = continuationFixture(t, 'oauth_phase3_failed'); delete f.config.heroSmsApiKey;
  fs.writeFileSync(path.join(f.root, 'config.json'), JSON.stringify(f.config));
  const target = listRegistrationContinuations({ rootDirectory: f.root }).items[0]; let probes = 0, launches = 0;
  await assert.rejects(runRegistrationResumeJob({ logger, rootDirectory: f.root, target: { selectedKey: target.selectedKey, revision: target.revision },
    preflight: async options => { probes += 1; assert.equal(options.scope, 'phase3'); return { ok: true }; },
    runner: async (_, __, options) => { launches += 1; const binding = JSON.parse(fs.readFileSync(options.extraFileDescriptors[4], 'utf8'));
      assert.match(binding.usernameFileHash, /^[a-f0-9]{64}$/); assert.match(binding.usernameRecordHash, /^[a-f0-9]{64}$/); assert.equal(binding.usernameIndex, 0);
      return writeEvents(options, [{ type: 'failed', code: 'FIXTURE_STOPPED_BEFORE_LOGIN' }]); },
  }), { code: 'FIXTURE_STOPPED_BEFORE_LOGIN' });
  assert.equal(probes, 1); assert.equal(launches, 1);
});
test('scoped preflight validates the exact required channels and fixed scope before spawn', async t => {
  const f = fixture(t); let called = 0;
  const runner = async (_, args, options) => { called += 1; assert.equal(args.includes('--preflight-scope=phase3'), true);
    return writeEvents(options, [{ type: 'preflight_completed', result: { scope: 'phase3', channels: ['mail', 'oauth'].map(id => ({ id, ok: true, code: 'OK' })) } }]); };
  assert.equal((await runNetworkPreflight({ logger, rootDirectory: f.root, scope: 'phase3', runner })).ok, true);
  await assert.rejects(runNetworkPreflight({ logger, rootDirectory: f.root, scope: 'skip', runner }), { code: 'NETWORK_PREFLIGHT_SCOPE_INVALID' });
  assert.equal(called, 1);
  await assert.rejects(runNetworkPreflight({ logger, rootDirectory: f.root, scope: 'registration', runner: async (_, __, options) => writeEvents(options, [{ type: 'preflight_completed', result: { channels: ['mail', 'oauth'].map(id => ({ id, ok: true, code: 'OK' })) } }]) }), { code: 'NETWORK_PREFLIGHT_INVALID' });
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
const relatedIdentityHelper = path.resolve(__dirname, '../../../gpt_register/src/continuationIdentity.js');
test('panel and engine enforce the exact same pure local identity mapping contract', { skip: !fs.existsSync(relatedIdentityHelper) }, () => {
  assert.equal(fs.readFileSync(relatedIdentityHelper, 'utf8'), fs.readFileSync(path.resolve(__dirname, '../backend/lib/registrationContinuationIdentity.js'), 'utf8'));
});
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
