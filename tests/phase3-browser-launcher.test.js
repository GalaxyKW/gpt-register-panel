'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
require('./test-isolation');
const { listLocalPhase3Targets, resolvePhase3Requests, runPhase3Job } = require('../backend/phase3Worker');

function fixture(t, body) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-browser-launcher-test-'));
  for (const dir of ['src', 'tokens', 'use_token']) fs.mkdirSync(path.join(root, dir), { mode: 0o700 });
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'browser-fixture@example.test', password: 'fixture-only', status: 'oauth_done' },
  ]), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'src/config.js'), "module.exports = { browserUserDataDir: '/proc/self/fd/5/browser-profile', tokenOutputDir: '/proc/self/fd/5/tokens' };", { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs'); const path = require('node:path');",
    "const config = require('./src/config');",
    "fs.writeFileSync(path.join(process.cwd(), 'observed.json'), JSON.stringify({profile:config.browserUserDataDir, output:config.tokenOutputDir, root:process.cwd()}));",
    body,
  ].join('\n'), { mode: 0o600 });
  const previous = {};
  for (const [key, value] of Object.entries({ GPT_REGISTER_ROOT: root, GPT_REGISTER_NODE_PATH: process.execPath,
    PANEL_PHASE3_ENABLED: '1', PANEL_PHASE3_TIMEOUT_MS: '30000', PANEL_PHASE3_KILL_GRACE_MS: '100' })) {
    previous[key] = process.env[key]; process.env[key] = value;
  }
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  const account = listLocalPhase3Targets().accounts[0];
  const resolved = resolvePhase3Requests([{ ...account, phone: account.phone || '', sourceMode: 'username' }]);
  assert.deepEqual(resolved.rejected, []);
  const target = resolved.eligible[0];
  const events = [];
  const args = { ...target, executionBinding: target.executionBinding, requireExecutionBinding: true,
    jobId: 'browser-launcher-fixture', db: { async startMutationJob() {}, async audit() {} },
    logger: { checkpoint() { return true; }, info(event) { events.push(event); }, warn(event) { events.push(event); }, error() {} } };
  return { root, args, events, observed: () => JSON.parse(fs.readFileSync(path.join(root, 'observed.json'), 'utf8')) };
}

test('descriptor launcher gives a grandchild a real private profile without changing pinned token paths', async (t) => {
  const child = "const fs=require('node:fs'); const p=process.argv[1]; fs.writeFileSync(p+'/grandchild-proof','ok');";
  const f = fixture(t, [
    "const {spawnSync}=require('node:child_process');",
    `const child=spawnSync(process.execPath,['-e',${JSON.stringify(child)},config.browserUserDataDir],{stdio:'ignore'});`,
    "if(child.status!==0)process.exitCode=17;",
    "fs.writeFileSync(path.join(process.cwd(),'proof.json'),JSON.stringify({exists:fs.existsSync(config.browserUserDataDir+'/grandchild-proof'),mode:fs.statSync(config.browserUserDataDir).mode & 0o777}));",
  ].join('\n'));
  await assert.rejects(runPhase3Job(f.args), { code: 'PHASE3_TOKEN_UNCHANGED' });
  const observed = f.observed();
  assert.doesNotMatch(observed.profile, /^\/proc\//);
  assert.equal(observed.output, '/proc/self/fd/5/tokens');
  assert.equal(observed.root, '/proc/self/fd/5');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.root, 'proof.json'))), { exists: true, mode: 0o700 });
  assert.equal(fs.existsSync(observed.profile), false);
  assert.ok(f.events.includes('phase3.browser_profile_removed'));
});

test('terminal bootstrap failure exits promptly and supervisor reaps a detached leaked browser helper', async (t) => {
  const helper = "process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);";
  const f = fixture(t, [
    "const {spawn}=require('node:child_process');",
    `const helper=spawn(process.execPath,['-e',${JSON.stringify(helper)}],{detached:true,stdio:'ignore'});`,
    "fs.writeFileSync(path.join(process.cwd(),'helper.pid'),String(helper.pid));",
    "process.exitCode=23;",
  ].join('\n'));
  const started = performance.now();
  await assert.rejects(runPhase3Job(f.args), (error) => {
    assert.equal(error.details?.terminationConfirmed, true);
    assert.equal(error.details?.code, 23);
    assert.notEqual(error.code, 'PHASE3_TIMEOUT');
    return true;
  });
  assert.ok(performance.now() - started < 15000, 'must not wait for the 30-second fixture timeout');
  const pid = Number(fs.readFileSync(path.join(f.root, 'helper.pid'), 'utf8'));
  const status = fs.existsSync('/proc/' + pid + '/stat') ? fs.readFileSync('/proc/' + pid + '/stat', 'utf8') : '';
  assert.ok(!status || /^\S+ \(.*\) [ZX] /.test(status), 'supervised helper must not remain live');
  assert.equal(fs.existsSync(f.observed().profile), false);
});

test('real child failure reaches the job as a fixed actionable hint without child output', async (t) => {
  const f = fixture(t, "console.error('[主程序] EMAIL_CODE_SUBMIT_NOT_DISPATCHED: synthetic-private-payload'); process.exitCode=1;");
  await assert.rejects(runPhase3Job(f.args), (error) => {
    assert.match(error.message, /未确认表单提交/);
    assert.match(error.message, /EMAIL_CODE_SUBMIT_NOT_DISPATCHED/);
    assert.equal(error.details?.terminationConfirmed, true);
    assert.equal(error.code, undefined);
    assert.equal(error.accountDisposition, undefined);
    assert.equal(JSON.stringify(error).includes('synthetic-private-payload'), false);
    return true;
  });
});
