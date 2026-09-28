'use strict';
// Optional integration check: uses the real BrowserService/dependencies, but
// never imports gpt_register config, usernames, tokens or its main program.
// Run inside the deployment sandbox with only loopback networking permitted.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const registerCode = path.resolve(process.argv[2] || '/mnt/nvme/gpt_register');
require('../test-isolation');
const { listLocalPhase3Targets, resolvePhase3Requests, runPhase3Job } = require('../../backend/phase3Worker');

async function check(mode) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-real-browser-smoke-'));
  let safeToRemove = true;
  try {
    for (const dir of ['src', 'tokens', 'use_token']) fs.mkdirSync(path.join(root, dir), { mode: 0o700 });
    for (const file of ['browserService.js', 'runLogger.js']) {
      fs.copyFileSync(path.join(registerCode, 'src', file), path.join(root, 'src', file));
      fs.chmodSync(path.join(root, 'src', file), 0o600);
    }
    fs.symlinkSync(path.join(registerCode, 'node_modules'), path.join(root, 'node_modules'));
    fs.writeFileSync(path.join(root, 'src/config.js'), "module.exports={browserUserDataDir:require('node:path').join(__dirname,'../browser-profile'),useChrome:true,chromePath:'/usr/bin/google-chrome',browserIncognito:true,browserClearChatGptSession:false};", { mode: 0o600 });
    fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
      { email: 'smoke@example.test', password: 'not-a-real-credential', status: 'oauth_done' },
    ]), { mode: 0o600 });
    const script = [
      "const fs=require('node:fs');const path=require('node:path');",
      "const {BrowserService}=require('./src/browserService');const config=require('./src/config');",
      '(async()=>{',
      " const browser=new BrowserService({host:'127.0.0.1',port:9,protocol:'http:'});",
      ' await browser.launch();',
      " await browser.page.setRequestInterception(true);browser.page.on('request',r=>r.abort());",
      " await browser.page.goto('about:blank');",
      ' const calculation=await browser.page.evaluate(()=>1+1);',
      " const pid=Number(fs.readFileSync(path.join(config.browserUserDataDir,'chrome.pid'),'utf8'));",
      " fs.writeFileSync(path.join(process.cwd(),'proof.json'),JSON.stringify({calculation,pid,profile:config.browserUserDataDir}));",
      mode === 'failure' ? ' process.exitCode=23;' : ' await browser.close();',
      '})().catch(()=>{process.exitCode=19;});',
    ].join('\n');
    fs.writeFileSync(path.join(root, 'index.js'), script, { mode: 0o600 });
    process.env.GPT_REGISTER_ROOT = root;
    process.env.GPT_REGISTER_NODE_PATH = process.execPath;
    process.env.PANEL_PHASE3_ENABLED = '1';
    process.env.PANEL_PHASE3_TIMEOUT_MS = '60000';
    const account = listLocalPhase3Targets().accounts[0];
    const resolved = resolvePhase3Requests([{ ...account, phone: '', sourceMode: 'username' }]);
    assert.deepEqual(resolved.rejected, []);
    const target = resolved.eligible[0];
    let failure;
    let processSummary;
    const started = performance.now();
    safeToRemove = false;
    try {
      await runPhase3Job({ ...target, executionBinding: target.executionBinding, requireExecutionBinding: true,
        jobId: 'real-browser-smoke-' + mode, db: { async startMutationJob() {}, async audit() {} },
        logger: { checkpoint() { return true; }, info(event, fields) {
          if (event === 'phase3.process_completed') processSummary = fields;
        }, warn() {}, error(event, fields) {
          if (event === 'phase3.process_failed') processSummary = fields;
        } } });
    } catch (error) { failure = error; }
    safeToRemove = processSummary?.terminationConfirmed === true;
    assert.equal(safeToRemove, true, 'process tree termination must be confirmed');
    assert.ok(failure, 'the blank-page check must not generate a token');
    if (mode === 'failure') assert.equal(failure.details?.code, 23);
    else assert.equal(failure.code, 'PHASE3_TOKEN_UNCHANGED');
    const proof = JSON.parse(fs.readFileSync(path.join(root, 'proof.json'), 'utf8'));
    assert.equal(proof.calculation, 2);
    assert.doesNotMatch(proof.profile, /^\/proc\//);
    assert.equal(fs.existsSync(proof.profile), false, 'only owned temporary profile should be removed');
    const status = fs.existsSync('/proc/' + proof.pid + '/stat') ? fs.readFileSync('/proc/' + proof.pid + '/stat', 'utf8') : '';
    assert.ok(!status || /^\S+ \(.*\) [ZX] /.test(status), 'Chrome must not remain live');
    assert.deepEqual(fs.readdirSync(path.join(root, 'tokens')), []);
    console.log(JSON.stringify({ mode, chromeConnected: true, emptyPageOnly: true,
      elapsedMs: Math.round(performance.now() - started), treeStopped: true, temporaryProfileRemoved: true }));
  } finally {
    if (safeToRemove) fs.rmSync(root, { recursive: true, force: true });
  }
}

(async () => { await check('success'); await check('failure'); })().catch((error) => {
  // Never dump browser output or environment; this check has no login secrets.
  console.error(JSON.stringify({ smokeFailed: true, code: /^[A-Z_0-9]+$/.test(error.code || '') ? error.code : 'CHECK_FAILED',
    assertion: error.name === 'AssertionError' ? error.message : undefined }));
  process.exitCode = 1;
});
