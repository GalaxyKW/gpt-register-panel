'use strict';

// Exercise the installed browser driver and real DOM/keyboard events without
// credentials or upstream traffic. A distinct loopback-only namespace is
// mandatory; all synthetic auth pages are answered by request interception.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assertLoopbackOnlyNetwork, copyBrowserSmokeSources } = require('./phase3-browser-smoke.cjs');
const emit = value => process.stdout.write(JSON.stringify(value) + '\n');
const registerCode = path.resolve(process.argv[2] || '/mnt/nvme/gpt_register');
const fixtureUrl = 'https://chatgpt.com/';
const localNumber = '091234567'; // Synthetic, never sent to an external service.

function fixtureBehavior(mode) {
  const input = document.querySelector('input');
  const form = document.querySelector('form');
  const country = document.querySelector('select');
  window.submissions = [];
  window.trustedInputs = 0;
  window.resetCount = 0;
  const prefixed = mode !== 'local' && mode !== 'local-formatted';
  input.value = prefixed ? '+56' : '';
  form.addEventListener('submit', event => {
    event.preventDefault();
    window.submissions.push({ value: input.value, country: country.value });
  });
  input.addEventListener('input', event => {
    if (event.isTrusted) window.trustedInputs++;
    let value = input.value;
    if (prefixed && !value.startsWith('+56')) { value = '+56'; window.resetCount++; }
    let digits = (prefixed ? value.slice(3) : value).replace(/ /g, '');
    if (mode === 'prefix-formatted' || mode === 'local-formatted') digits = digits.replace(/(\d{3})(?=\d)/g, '$1 ');
    input.value = (prefixed ? '+56' : '') + (prefixed && digits && mode === 'prefix-formatted' ? ' ' : '') + digits;
    // A controlled phone formatter can restore its prefix and reset the
    // caret to zero on every event. The former generic fill loses all digits.
    input.setSelectionRange(0, 0);
    if (mode === 'wrong-country-during-input' && event.isTrusted) country.value = 'US';
    if (mode === 'replaced-during-input' && event.isTrusted) input.replaceWith(input.cloneNode());
    if (mode === 'wrong-number' && digits.replace(/ /g, '').length === 9) input.value = '+56091234560';
    if (mode === 'double-country' && digits.replace(/ /g, '').length === 9) input.value = '+5656091234567';
    if (mode === 'unknown-prefix') input.value = '+1';
    if (mode === 'unsupported-format' && digits.replace(/ /g, '').length === 9) input.value += ' ext 9';
  });
}

function fixtureHtml(mode) {
  return '<!doctype html><meta charset="utf-8"><title>Offline phone fixture</title>'
    + '<form method="post"><label>Country<select name="country"><option value="CL">Chile (+56)</option>'
    + '<option value="US">United States (+1)</option></select></label>'
    + '<label>Phone<input type="tel" name="phoneNumberInput" autocomplete="tel"></label>'
    + '<button type="submit">Continue</button></form><script>('
    + fixtureBehavior.toString() + ')(' + JSON.stringify(mode) + ');</script>';
}

function readProcessIdentity(pid) {
  let value;
  try { value = fs.readFileSync('/proc/' + pid + '/stat', 'utf8'); }
  catch (error) { if (error.code === 'ENOENT' || error.code === 'ESRCH') return null; throw error; }
  const fields = value.slice(value.lastIndexOf(') ') + 2).trim().split(/\s+/);
  if (!/^[A-Z]$/.test(fields[0]) || !/^\d+$/.test(fields[1] || '') || !/^\d+$/.test(fields[19] || '')) {
    throw new Error('Cannot verify fixture browser process identity');
  }
  return { pid, parent: Number(fields[1]), state: fields[0], start: fields[19] };
}

function captureOwnedBrowserProcesses(root) {
  const profile = path.join(root, 'profile');
  const file = path.join(profile, 'chrome.pid');
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size < 32, 'fixture browser PID proof must be a regular bounded file');
  const text = fs.readFileSync(file, 'utf8').trim();
  assert.match(text, /^[1-9]\d*$/);
  const pid = Number(text);
  assert.ok(Number.isSafeInteger(pid) && pid > 1 && pid !== process.pid, 'fixture browser PID must be distinct');
  const browser = readProcessIdentity(pid);
  assert.ok(browser && !['Z', 'X'].includes(browser.state), 'fixture browser must be live when captured');
  const processes = [];
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^[1-9]\d*$/.test(entry)) continue;
    try { const item = readProcessIdentity(Number(entry)); if (item) processes.push(item); }
    catch { /* Unrelated processes need not be inspectable in the sandbox. */ }
  }
  const owned = new Map([[pid, browser]]);
  let added;
  do {
    added = false;
    for (const item of processes) if (!owned.has(item.pid) && owned.has(item.parent)) {
      owned.set(item.pid, item); added = true;
    }
  } while (added);
  // Verify the executable as well as ownership: Chrome can rewrite its
  // process title into one space-separated argv entry. This generated path
  // has no whitespace; only one exact profile argument is accepted. Nothing
  // from this inspection is ever interpreted or executed as a shell command.
  const bound = [...owned.values()].some(item => {
    try {
      const current = readProcessIdentity(item.pid);
      if (!current || current.start !== item.start || ['Z', 'X'].includes(current.state)) return false;
      if (fs.realpathSync('/proc/' + item.pid + '/exe') !== '/opt/google/chrome/chrome') return false;
      const args = fs.readFileSync('/proc/' + item.pid + '/cmdline', 'utf8').split(/[\0 ]+/);
      const profiles = args.filter(arg => arg.startsWith('--user-data-dir'));
      return profiles.length === 1 && profiles[0] === '--user-data-dir=' + profile;
    } catch { return false; }
  });
  assert.ok(bound, 'PID proof must own a real Chrome with this exact temporary profile');
  return [...owned.values()];
}

async function confirmBrowserStopped(identities) {
  if (!identities?.length) return false;
  const deadline = Date.now() + 2000;
  do {
    try {
      const live = identities.some(expected => {
        const current = readProcessIdentity(expected.pid);
        return current && current.start === expected.start && !['Z', 'X'].includes(current.state);
      });
      if (!live) return true;
    } catch { return false; }
    await new Promise(resolve => setTimeout(resolve, 50));
  } while (Date.now() < deadline);
  return false;
}

async function main() {
  assertLoopbackOnlyNetwork();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-phone-input-smoke-'));
  fs.mkdirSync(path.join(root, 'src'), { mode: 0o700 });
  copyBrowserSmokeSources(registerCode, root);
  fs.symlinkSync(path.join(registerCode, 'node_modules'), path.join(root, 'node_modules'));
  fs.writeFileSync(path.join(root, 'src/config.js'), 'module.exports={requireProxy:true,browserIncognito:true,browserClearChatGptSession:false};\n', { mode: 0o600 });
  const { BrowserService } = require(path.join(root, 'src/browserService.js'));
  const service = new BrowserService({ host: '127.0.0.1', port: 9, protocol: 'http:' }, {
    chromePath: '/usr/bin/google-chrome', userDataDir: path.join(root, 'profile'),
    incognito: true, clearChatGptSession: false,
  });
  let scenario = 'launch'; let mode = 'prefix'; let localPages = 0; let mutationRequests = 0; let passed = 0;
  let browserIdentities = null;
  // Production logger text is intentionally not emitted by this fixture.
  const savedConsole = {};
  for (const key of ['log', 'info', 'warn', 'error', 'debug']) { savedConsole[key] = console[key]; console[key] = () => {}; }
  try {
    await service.launch();
    browserIdentities = captureOwnedBrowserProcesses(root);
    const page = service.page;
    await page.setRequestInterception(true);
    page.on('request', request => {
      if (request.method() === 'GET' && request.isNavigationRequest() && request.url() === fixtureUrl) {
        localPages++;
        return request.respond({ status: 200, contentType: 'text/html', body: fixtureHtml(mode) });
      }
      if (request.method() !== 'GET') mutationRequests++;
      return request.abort();
    });
    async function prepare(name) {
      scenario = mode = name;
      await page.goto(fixtureUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
      // Use the production country selection path, not a cached fabricated
      // country object. Real subsequent DOM reads must confirm this choice.
      await service.selectCountry('56', 'Chile', 'CL');
      return service.uniqueVisibleInput('input[name="phoneNumberInput"]');
    }
    function success() { passed++; emit({ scenario, passed: true, externalRequestsAllowed: 0 }); }

    const old = await prepare('old-generic-prefix-regression');
    await assert.rejects(service.fillCredentialElement(old, localNumber, { field: 'phone.local_number' }), { code: 'CREDENTIAL_INPUT_UNCONFIRMED' });
    assert.equal(await old.evaluate(el => el.value), '+56');
    assert.deepEqual(await page.evaluate(() => window.submissions), []);
    success(); await old.dispose();

    for (const name of ['local', 'local-formatted', 'prefix', 'prefix-formatted']) {
      const input = await prepare(name);
      await service.fillPhoneElement(input, localNumber);
      assert.equal((await service.clickSubmitButton(input)).clicked, true);
      const submissions = await page.evaluate(() => window.submissions);
      assert.equal(submissions.length, 1);
      assert.equal(submissions[0].country, 'CL');
      assert.equal(submissions[0].value.replace(/ /g, ''), (name.startsWith('prefix') ? '+56' : '') + localNumber);
      assert.ok(await page.evaluate(() => window.trustedInputs >= 9));
      success(); await input.dispose();
    }
    for (const name of ['wrong-country-during-input', 'replaced-during-input', 'wrong-number', 'double-country', 'unknown-prefix', 'unsupported-format']) {
      const input = await prepare(name);
      await assert.rejects(service.fillPhoneElement(input, localNumber));
      assert.deepEqual(await page.evaluate(() => window.submissions), []);
      success(); await input.dispose();
    }
    for (const change of ['country', 'country-removed', 'number', 'format-only', 'input-replaced', 'form-replaced', 'before-dispatch-country', 'before-dispatch-number']) {
      const input = await prepare('prefix'); scenario = 'submit-rejects-' + change;
      await service.fillPhoneElement(input, localNumber);
      const tamper = async () => page.evaluate(kind => {
        const input = document.querySelector('input');
        if (kind.includes('country')) {
          if (kind === 'country-removed') document.querySelector('select').remove();
          else document.querySelector('select').value = 'US';
        } else if (kind.includes('number')) input.value = '+56091234560';
        else if (kind === 'format-only') input.value = input.value.replace('+56', '+56 ');
        else if (kind === 'input-replaced') input.replaceWith(input.cloneNode());
        else if (kind === 'form-replaced') {
          const other = document.createElement('form');
          other.addEventListener('submit', event => {
            event.preventDefault(); window.submissions.push({ unexpectedForm: true });
          });
          const button = document.querySelector('button').cloneNode(true);
          document.body.append(other); other.append(input, button);
        }
      }, change);
      if (change.startsWith('before-dispatch-')) {
        await assert.rejects(service.clickSubmitButton(input, { beforeDispatch: async () => { await tamper(); return true; } }));
      } else {
        await tamper(); await assert.rejects(service.clickSubmitButton(input));
      }
      assert.deepEqual(await page.evaluate(() => window.submissions), []);
      success(); await input.dispose();
    }
    assert.equal(mutationRequests, 0, 'no test may issue an upstream mutation, even intercepted');
    assert.equal(localPages, passed);
  } catch (error) {
    emit({ scenario, failed: true, code: /^[A-Z_]{1,80}$/.test(error.code || '') ? error.code : 'PHONE_BROWSER_CHECK_FAILED',
      sourceFrames: String(error.stack || '').split('\n').filter(line => /at .*BrowserService\.|at .*phone-input-browser-smoke\.cjs:\d+:\d+/.test(line)).map(line => line.trim()) });
    throw Object.assign(new Error('Offline phone browser regression failed'), { code: 'PHONE_BROWSER_CHECK_FAILED' });
  } finally {
    // BrowserService.close intentionally suppresses driver-close failures.
    // Capture this profile's current descendants before closing; never infer
    // process termination from that method merely returning. No signals are
    // sent here, and PID reuse is distinguished using kernel start time.
    try {
      try {
        const latest = captureOwnedBrowserProcesses(root);
        const merged = new Map((browserIdentities || []).map(item => [item.pid + ':' + item.start, item]));
        for (const item of latest) merged.set(item.pid + ':' + item.start, item);
        browserIdentities = [...merged.values()];
      } catch { browserIdentities = null; }
      await service.close();
      if (!await confirmBrowserStopped(browserIdentities)) {
        emit({ phoneBrowserCleanup: 'unconfirmed', fixtureRetained: true, fixtureDirectory: root });
        throw Object.assign(new Error('Fixture browser shutdown could not be confirmed; private profile retained'),
          { code: 'PHONE_BROWSER_CLEANUP_UNCONFIRMED' });
      }
      fs.rmSync(root, { recursive: true, force: true });
      emit({ phoneBrowserCleanup: 'confirmed', fixtureRemoved: true, ownedProcessCount: browserIdentities.length });
    }
    finally { for (const [key, value] of Object.entries(savedConsole)) console[key] = value; }
  }
  // Publish overall success only after cleanup has also been proven.
  emit({ phoneBrowserAcceptance: 'passed', scenarios: passed, deploymentDriver: true, productionRequests: 0 });
}

if (require.main === module) main().catch(error => {
  emit({ phoneBrowserAcceptance: 'failed', code: /^[A-Z_]{1,80}$/.test(error.code || '') ? error.code : 'PHONE_BROWSER_CHECK_FAILED' });
  process.exitCode = 1;
});
