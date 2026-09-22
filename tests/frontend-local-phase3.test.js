'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
require('./test-isolation');

const source = fs.readFileSync(path.join(__dirname, '../frontend/local-phase3.js'), 'utf8');
const appSource = fs.readFileSync(path.join(__dirname, '../frontend/app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
const revision = 'phase3-local-v1.' + 'A'.repeat(43);

function account(index = 0, extra = {}) {
  return { selectedKey: 'username:' + index, email: 'local' + index + '@example.test',
    phone: null, status: '', eligible: true, reason: null, phase3TargetRevision: revision, ...extra };
}
function listing(accounts = [account()]) {
  const eligible = accounts.filter((entry) => entry.eligible).length;
  return { accounts, summary: { total: accounts.length, eligible, ineligible: accounts.length - eligible },
    readOnly: false, capabilities: { phase3Enabled: true } };
}
function harness(overrides = {}) {
  const elements = {};
  const handlers = {};
  const notices = [];
  const context = {
    state: { snapshot: { readOnly: false }, jobInventoryVerified: true, selected: new Set(['sub2api:143']) },
    document: { querySelector(selector) {
      return elements[selector] ||= {
        open: false, dataset: {}, querySelectorAll: () => [],
        addEventListener(type, listener) { (handlers[selector + ':' + type] ||= []).push(listener); },
        showModal() { this.open = true; },
        close() { this.open = false; for (const listener of handlers[selector + ':close'] || []) listener(); },
      };
    } },
    window: { confirm: () => true },
    reconciliationWriteBlocked: () => false,
    reconciliationDisplayLooksLikeCredential: () => false,
    actionsLocked: () => Boolean(context.state.phase3RequestPending || context.state.localPhase3ListingPending),
    phase3CapabilityAvailable: () => true,
    updateActionState() { vm.runInContext('updateLocalPhase3ActionState();', context); },
    escapeHtml: (value) => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;'),
    showNotice: (...args) => notices.push(args),
    apiFetch: async () => ({ ok: true, json: async () => listing() }),
    mutationRejectionSummary: () => '',
    idempotentMutationFetch: async () => { throw new Error('must not mutate in this test'); },
    watchJobs: async () => {},
    loadSnapshot: async () => {},
    ...overrides,
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  return { context, elements, handlers, notices,
    run: (code) => vm.runInContext(code, context) };
}

test('local Phase3 inventory accepts nullable absent identities but requires an eligible revision', () => {
  const { run, context } = harness();
  context.sample = listing([account(), account(1, {
    email: null, phone: null, eligible: false, reason: 'phase3_account_invalid', phase3TargetRevision: null,
  })]);
  assert.equal(run('localPhase3ListingProblem(sample)'), '');
  for (const mutate of [
    (value) => { value.summary.total += 1; },
    (value) => { value.accounts[0].phase3TargetRevision = 'phase3-target-v1.' + 'A'.repeat(43); },
    (value) => { value.accounts[0].phone = '+1234'; },
    (value) => { value.accounts[0].selectedKey = 'sub2api:143'; },
    (value) => { value.accounts[0].selectedKey = 'username:01'; },
    (value) => { value.accounts[0].email = 'UPPER@example.test'; },
    (value) => { value.capabilities.phase3Enabled = 'true'; },
    (value) => { value.readOnly = 'false'; },
    (value) => { value.accounts[0].eligible = 'true'; },
  ]) {
    context.sample = listing(); mutate(context.sample);
    assert.match(run('localPhase3ListingProblem(sample)'), /禁止提交/);
  }
  context.sample = listing([account(0), account(1, { email: account(0).email })]);
  assert.match(run('localPhase3ListingProblem(sample)'), /禁止提交/);
});

test('local Phase3 selection is independent from remote rows and never silently drops invalid or oversized choices', () => {
  const { run, context } = harness();
  context.sample = listing([account(0), account(1, {
    eligible: false, reason: 'phase3_source_present', phase3TargetRevision: null,
  })]);
  run('localPhase3State.listing = sample; localPhase3State.selected = new Set(["username:0"]);');
  assert.deepEqual(JSON.parse(run('JSON.stringify(localPhase3Selection().targets)')), [{
    selectedKey: 'username:0', email: 'local0@example.test', phone: '', phase3TargetRevision: revision,
  }]);
  run('localPhase3State.selected.add("username:1");');
  assert.match(run('localPhase3Selection().problem'), /重新读取/);
  run('localPhase3State.selected = new Set(["sub2api:143"]);');
  assert.match(run('localPhase3Selection().problem'), /重新读取/);
  context.sample = listing(Array.from({ length: 101 }, (_, index) => account(index)));
  run('localPhase3State.listing = sample; localPhase3State.selected = new Set(sample.accounts.map(a => a.selectedKey));');
  assert.match(run('localPhase3Selection().problem'), /每批最多 100.*不会自动跳过/);
  assert.deepEqual([...context.state.selected], ['sub2api:143']);
  assert.match(run('localPhase3Reason("phase3_source_present")'), /已有活动 token/);
});

test('local Phase3 reads the local endpoint and rejects a response arriving after dialog cancellation', async () => {
  let resolveResponse;
  const { run, context, elements } = harness({ apiFetch: (url) => {
    assert.equal(url, '/api/phase3/local-accounts');
    return new Promise((resolve) => { resolveResponse = resolve; });
  } });
  const opening = run('openLocalPhase3Dialog()');
  assert.equal(context.state.localPhase3ListingPending, true);
  elements['#localPhase3Dialog'].close();
  resolveResponse({ ok: true, json: async () => listing() });
  await opening;
  assert.equal(context.state.localPhase3ListingPending, false);
  assert.equal(run('localPhase3State.listing'), null);
});

test('local Phase3 bounds rendered rows and page selection does not silently select hidden records', () => {
  const { run, context, handlers, elements } = harness();
  context.sample = listing(Array.from({ length: 142 }, (_, index) => account(index)));
  run('localPhase3State.listing = sample; renderLocalPhase3Rows();');
  assert.equal((elements['#localPhase3Rows'].innerHTML.match(/data-local-phase3-key=/g) || []).length, 100);
  elements['#localPhase3SelectAll'].checked = true;
  handlers['#localPhase3SelectAll:change'][0]();
  assert.equal(run('localPhase3State.selected.size'), 100);
  handlers['#localPhase3Next:click'][0]();
  assert.equal((elements['#localPhase3Rows'].innerHTML.match(/data-local-phase3-key=/g) || []).length, 42);
  assert.equal(elements['#localPhase3SelectAll'].checked, false);
  elements['#localPhase3SelectAll'].checked = true;
  handlers['#localPhase3SelectAll:change'][0]();
  assert.equal(run('localPhase3State.selected.size'), 142);
  assert.match(run('localPhase3Selection().problem'), /每批最多 100/);
  elements['#localPhase3SelectAll'].checked = false;
  handlers['#localPhase3SelectAll:change'][0]();
  assert.equal(run('localPhase3State.selected.size'), 100);
});

test('local Phase3 submits only confirmed local identities with revisions through existing idempotency', async () => {
  let submitted;
  let watched;
  const jobId = 'job_' + '1'.repeat(24);
  const { run, context, elements } = harness({
    idempotentMutationFetch: async (...args) => {
      submitted = args;
      return { response: { ok: true }, body: { jobIds: [jobId] } };
    },
    watchJobs: async (ids) => { watched = ids; context.state.job = { status: 'queued' }; },
  });
  await run('openLocalPhase3Dialog()');
  run('localPhase3State.selected.add("username:0");');
  await run('submitLocalPhase3({preventDefault() {}, submitter:{value:"confirm"}})');
  assert.equal(submitted[0], 'phase3');
  assert.equal(submitted[1], '/api/phase3/local');
  assert.deepEqual(JSON.parse(JSON.stringify(submitted[2])), {
    accounts: [{ selectedKey: 'username:0', email: 'local0@example.test', phone: '', phase3TargetRevision: revision }],
    selectedKeys: ['username:0'],
  });
  assert.deepEqual([...watched], [jobId]);
  assert.equal(elements['#localPhase3Dialog'].open, false);
  assert.equal(context.state.phase3RequestPending, true);
});

test('local Phase3 refuses read-only capabilities and unknown submission outcomes recheck task inventory', async () => {
  let writes = 0;
  let recovered;
  const { run, context, elements } = harness({
    idempotentMutationFetch: async () => { writes += 1; throw new Error('network'); },
    loadSnapshot: async (options) => { recovered = options; context.state.job = { status: 'unknown' }; },
  });
  await run('openLocalPhase3Dialog()');
  run('localPhase3State.selected.add("username:0"); localPhase3State.listing.readOnly = true;');
  await run('submitLocalPhase3({preventDefault() {}, submitter:{value:"confirm"}})');
  assert.equal(writes, 0);
  assert.match(elements['#localPhase3Error'].textContent, /未确认可写/);
  run('localPhase3State.listing.readOnly = false;');
  await run('submitLocalPhase3({preventDefault() {}, submitter:{value:"confirm"}})');
  assert.equal(writes, 1);
  assert.equal(recovered.resumeJobs, true);
  assert.equal(context.state.phase3RequestPending, true);
  assert.equal(elements['#localPhase3Confirm'].disabled, true);
});

test('local Phase3 verifies inventory after every rejected HTTP response and preserves unknown/running locks', async () => {
  for (const status of [400, 401, 403, 409, 429, 500, 503]) {
    for (const recoveredStatus of [null, 'running', 'unknown']) {
      let recoveries = 0;
      const { run, context } = harness({
        idempotentMutationFetch: async () => ({ response: { ok: false, status }, body: {} }),
        loadSnapshot: async (options) => {
          assert.equal(options.resumeJobs, true);
          assert.equal(context.state.phase3RequestPending, true);
          recoveries += 1;
          context.state.job = recoveredStatus ? { status: recoveredStatus } : null;
        },
      });
      await run('openLocalPhase3Dialog()');
      run('localPhase3State.selected.add("username:0");');
      await run('submitLocalPhase3({preventDefault() {}, submitter:{value:"confirm"}})');
      assert.equal(recoveries, 1, 'HTTP ' + status);
      assert.equal(context.state.phase3RequestPending, recoveredStatus !== null);
    }
  }
});

test('local Phase3 duplicate clicks do not duplicate admission and success first-poll does not clear watcher locks', async () => {
  for (const firstPollStatus of ['queued', 'running', 'unknown']) {
    let resolveSubmission;
    let writes = 0;
    let watched = 0;
    const { run, context, elements } = harness({
      idempotentMutationFetch: () => {
        writes += 1;
        return new Promise((resolve) => { resolveSubmission = resolve; });
      },
      watchJobs: async () => { watched += 1; context.state.job = { status: firstPollStatus }; },
    });
    await run('openLocalPhase3Dialog()');
    run('localPhase3State.selected.add("username:0");');
    const submitting = run('submitLocalPhase3({preventDefault() {}, submitter:{value:"confirm"}})');
    assert.equal(elements['#localPhase3Confirm'].disabled, true);
    assert.equal(elements['#localPhase3Cancel'].disabled, true);
    await run('submitLocalPhase3({preventDefault() {}, submitter:{value:"confirm"}})');
    assert.equal(writes, 1);
    resolveSubmission({ response: { ok: true }, body: { jobIds: ['job_' + '1'.repeat(24)] } });
    await submitting;
    assert.equal(watched, 1);
    assert.equal(context.state.phase3RequestPending, true, firstPollStatus);
  }
});

test('local Phase3 controls are independently labelled and its review targets cannot masquerade as token targets', () => {
  assert.match(html, /id="localPhase3Dialog"[^>]*aria-describedby="localPhase3Help"/);
  assert.match(html, /已有活动 token（即使过期）请从账号表发起 Phase 3/);
  assert.ok(html.indexOf('src="/app.js"') < html.indexOf('src="/local-phase3.js"'));
  const start = appSource.indexOf('function boundedReconciliationDisplay');
  const end = appSource.indexOf('function reconciliationTargetSetIsValid', start);
  const context = {};
  vm.createContext(context);
  vm.runInContext(appSource.slice(start, end), context);
  context.target = { sourceMode: 'username', usernameIndex: 0, email: 'local@example.test', phase3TargetRevision: revision };
  assert.equal(vm.runInContext('reconciliationTargetIsValid("phase3", target)', context), true);
  for (const extra of [
    { usernameIndex: -1 }, { usernameIndex: 100_000 }, { usernameIndex: '0' },
    { sourcePath: 'tokens/a.json' }, { remoteAccountId: 143 }, { sourceMode: 'token' },
    { phone: '+123' }, { email: 'UPPER@example.test' },
    { phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43) },
  ]) {
    context.modified = { ...context.target, ...extra };
    assert.equal(vm.runInContext('reconciliationTargetIsValid("phase3", modified)', context), false);
  }
  assert.match(appSource, /本地记录 username\.json #/);
});
