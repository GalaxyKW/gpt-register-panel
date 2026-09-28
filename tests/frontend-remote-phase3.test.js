'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
require('./test-isolation');

const source = fs.readFileSync(path.join(__dirname, '../frontend/remote-phase3.js'), 'utf8');
const localSource = fs.readFileSync(path.join(__dirname, '../frontend/local-phase3.js'), 'utf8');
const app = fs.readFileSync(path.join(__dirname, '../frontend/app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
const styles = fs.readFileSync(path.join(__dirname, '../frontend/styles.css'), 'utf8');
const targetRevision = 'account-test-v1.' + 'A'.repeat(43);
const phase3TargetRevision = 'phase3-local-v1.' + 'B'.repeat(43);
const jobId = 'job_' + 'a'.repeat(24);
const clone = (value) => JSON.parse(JSON.stringify(value));

function row(id = 124, extra = {}) {
  return { key: 'account:' + id, source: 'sub2api', accountId: id, accountName: 'free00124',
    targetRevision, platform: 'openai', type: 'oauth', status: 'error', availability: 'unavailable',
    remoteDetails: { email: 'login@example.test', chatgptAccountId: 'account-124', userId: 'user-124' }, ...extra };
}
function local(index = 0, extra = {}) {
  return { selectedKey: 'username:' + index, email: 'login@example.test', phone: null, status: '',
    eligible: true, reason: null, phase3TargetRevision, ...extra };
}
function listing(accounts = [local()]) {
  const eligible = accounts.filter((entry) => entry.eligible).length;
  return { accounts, summary: { total: accounts.length, eligible, ineligible: accounts.length - eligible },
    readOnly: false, capabilities: { phase3Enabled: true } };
}
function job(extra = {}) {
  return { id: jobId, type: 'phase3', status: 'succeeded', finishedAt: '2026-09-28T00:00:00Z',
    result: { remoteTarget: { accountId: 124, targetRevision, identityKeys: ['account:account-124'],
      targetDigest: 'd'.repeat(64), endpointDigest: 'e'.repeat(64) },
      tokenSource: 'tokens', tokenFile: 'tokens/new.json', tokenContentHash: 'c'.repeat(64) }, ...extra };
}
function plan(extra = {}) {
  return { version: 'snapshot-version', planIntentVersion: 'sync-plan-v1.' + 'D'.repeat(43),
    items: [{ action: 'update', reason: 'token_changed', accountId: 124, source: 'tokens',
      relativePath: 'tokens/new.json', conflictingVersions: false }], ...extra };
}
function harness(overrides = {}) {
  const elements = {};
  const handlers = {};
  const notices = [];
  const context = {
    state: { snapshot: { readOnly: false, rows: [row()] }, selected: new Set(['account:124']),
      selectionRevision: 3, jobInventoryVerified: true },
    document: { querySelector(selector) {
      return elements[selector] ||= { open: false, checked: false, dataset: {}, querySelectorAll: () => [],
        addEventListener(type, handler) { (handlers[selector + ':' + type] ||= []).push(handler); },
        showModal() { this.open = true; },
        close() { this.open = false; for (const handler of handlers[selector + ':close'] || []) handler(); },
      };
    } },
    window: { confirm: () => true },
    reconciliationWriteBlocked: () => false,
    reconciliationDisplayLooksLikeCredential: () => false,
    boundedReconciliationDisplay: (value, max = 256) => typeof value === 'string' && value.length <= max ? value : null,
    reconciliationSourcePath: (value) => typeof value === 'string'
      && /^(tokens|use_token)\/(?!.*(?:\.\.|\\)).+\.json$/.test(value) ? value : null,
    actionsLocked: () => Boolean(context.state.phase3RequestPending || context.state.localPhase3ListingPending
      || context.state.previewRequestPending || context.state.importRequestPending),
    phase3CapabilityAvailable: () => true,
    comparisonAvailable: () => true,
    hiddenSelectionProblem: () => '',
    selectedRowsFromSelection: () => context.state.snapshot.rows.filter((entry) => context.state.selected.has(entry.key)),
    updateActionState: () => vm.runInContext('if (typeof updateRemotePhase3Ui === "function") updateRemotePhase3Ui();', context),
    escapeHtml: (value) => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;'),
    formatDate: (value) => value,
    actionLabel: (value) => value,
    actionReasonLabel: (value) => value,
    showNotice: (...args) => notices.push(args),
    apiFetch: async () => ({ ok: true, json: async () => listing() }),
    idempotentMutationFetch: async () => { throw new Error('unexpected mutation'); },
    mutationRejectionSummary: () => '',
    watchJobs: async () => {},
    watchJob: async () => {},
    loadSnapshot: async () => {},
    jobNeedsReconciliation: (value) => value.result?.reconciliationHold === true
      || value.result?.requiresReconciliation === true || value.result?.writeOutcomeUnknown === true,
    importPlanContractProblem: (value) => Array.isArray(value?.items) ? '' : 'bad plan',
    validImportPlanIntentVersion: (value) => /^sync-plan-v1\.[A-Za-z0-9_-]{43}$/.test(String(value)),
    ...overrides,
  };
  vm.createContext(context);
  vm.runInContext(localSource, context);
  vm.runInContext(source, context);
  return { context, elements, handlers, notices, run: (code) => vm.runInContext(code, context) };
}

test('remote-only rows reach explicit local login mapping without requiring active tokens', async () => {
  const { run, elements } = harness();
  assert.equal(run('remotePhase3SelectionApplicable()'), true);
  await run('openRemotePhase3Dialog()');
  assert.equal(elements['#remotePhase3Dialog'].open, true);
  assert.equal(run('remotePhase3State.mappings.length'), 1);
  assert.equal(run('remotePhase3State.mappings[0].reason'), '');
  assert.match(run('remotePhase3ConfirmedTargets().problem'), /逐项确认/);
  assert.equal(elements['#remotePhase3Confirm'].disabled, true);
  run('remotePhase3State.confirmed.add(124); updateRemotePhase3Ui();');
  assert.equal(elements['#remotePhase3Confirm'].disabled, false);
  assert.match(elements['#remotePhase3Rows'].innerHTML, /邮箱仅作候选提示/);
  assert.deepEqual(clone(run('remotePhase3ConfirmedTargets().targets')), [{ selectedKey: 'username:0',
    email: 'login@example.test', phone: '', phase3TargetRevision, remoteTarget: { accountId: 124, targetRevision } }]);
});

function mappingBatchHarness(overrides = {}) {
  const rows = Array.from({ length: 22 }, (_, index) => row(124 + index, {
    remoteDetails: { email: 'login' + index + '@example.test', chatgptAccountId: index === 21 ? '' : 'account-' + index },
  }));
  const accounts = rows.map((entry, index) => local(index, { email: entry.remoteDetails.email }));
  const instance = harness({ apiFetch: async () => ({ ok: true, json: async () => listing(accounts) }), ...overrides });
  instance.context.state.snapshot.rows = rows;
  instance.context.state.selected = new Set(rows.map((entry) => entry.key));
  instance.change = (name, checked, dataset = {}) => {
    const target = instance.elements['#remotePhase3' + name];
    target.checked = checked;
    for (const handler of instance.handlers['#remotePhase3' + name + ':change'] || []) {
      handler({ target: { ...target, checked, dataset } });
    }
  };
  return instance;
}

test('screenshot regression: acknowledging one skip visibly explains the 21 unconfirmed mappings', async () => {
  let mutations = 0;
  const { run, elements, change } = mappingBatchHarness({
    idempotentMutationFetch: async () => { mutations += 1; throw new Error('must not submit'); },
  });
  await run('openRemotePhase3Dialog()');
  assert.match(elements['#remotePhase3SubmitStatus'].textContent, /还需确认 21.*还需明确确认本次跳过 1/s);
  change('SkipAcknowledged', true);
  assert.equal(elements['#remotePhase3Confirm'].disabled, true);
  assert.match(elements['#remotePhase3SubmitStatus'].textContent, /还需确认 21.*确认全部可执行映射/);
  assert.doesNotMatch(elements['#remotePhase3SubmitStatus'].textContent, /还需明确确认本次跳过/);
  assert.equal(elements['#remotePhase3ConfirmationProgress'].textContent, '已确认 0 / 21 个可执行映射');
  await run('submitRemotePhase3({preventDefault(){},submitter:{value:"confirm"}})');
  assert.equal(mutations, 0);
  change('ConfirmAll', true);
  assert.equal(elements['#remotePhase3Confirm'].disabled, false);
  assert.equal(elements['#remotePhase3SubmitStatus'].dataset.state, 'ready');
  assert.equal(elements['#remotePhase3Error'].hidden, true, 'corrected consent must not retain a stale validation error');
  assert.match(elements['#remotePhase3SubmitStatus'].textContent, /重新登录 21 个账号、跳过 1 个/);
  assert.match(elements['#remotePhase3Confirm'].textContent, /21 个/);
  assert.equal(run('remotePhase3ConfirmedTargets().targets.length'), 21);
  assert.equal(mutations, 0, 'bulk confirmation never submits');
});

test('bulk confirmation excludes skips, keeps skip consent separate, and reflects partial selections', async () => {
  const { run, elements, change } = mappingBatchHarness();
  await run('openRemotePhase3Dialog()');
  const inputs = Array.from({ length: 21 }, (_, index) => ({ dataset: { remotePhase3Id: String(124 + index) } }));
  elements['#remotePhase3Rows'].querySelectorAll = () => inputs;
  change('ConfirmAll', true);
  assert.equal(run('remotePhase3State.confirmed.size'), 21);
  assert.equal(run('remotePhase3State.confirmed.has(145)'), false);
  assert.equal(elements['#remotePhase3SkipAcknowledged'].checked, false);
  assert.equal(elements['#remotePhase3Confirm'].disabled, true);
  assert.match(elements['#remotePhase3SubmitStatus'].textContent, /跳过 1 个/);
  assert.ok(inputs.every((input) => input.checked));
  change('Rows', false, { remotePhase3Id: '124' });
  assert.equal(elements['#remotePhase3ConfirmAll'].checked, false);
  assert.equal(elements['#remotePhase3ConfirmAll'].indeterminate, true);
  assert.equal(inputs[0].checked, false);
  assert.match(elements['#remotePhase3ConfirmationProgress'].textContent, /20 \/ 21/);
  change('ConfirmAll', false);
  assert.equal(run('remotePhase3State.confirmed.size'), 0);
  assert.equal(elements['#remotePhase3ConfirmAll'].indeterminate, false);
  assert.ok(inputs.every((input) => !input.checked));
  change('ConfirmAll', true);
  change('SkipAcknowledged', true);
  assert.equal(elements['#remotePhase3Confirm'].disabled, false);
  change('Rows', false, { remotePhase3Id: '125' });
  assert.equal(elements['#remotePhase3Confirm'].disabled, true);
  assert.match(elements['#remotePhase3SubmitStatus'].textContent, /还需确认 1 个/);
});

test('bulk confirmation cannot bypass changed selections, task locks, loading or read-only state', async () => {
  const { run, context, elements, change } = mappingBatchHarness();
  await run('openRemotePhase3Dialog()');
  for (const [enable, disable, message] of [
    [() => { context.state.selectionRevision += 1; }, () => { context.state.selectionRevision -= 1; }, /已变化/],
    [() => { context.state.jobInventoryVerified = false; }, () => { context.state.jobInventoryVerified = true; }, /任务状态尚未核实/],
    [() => { context.state.snapshot.readOnly = true; }, () => { context.state.snapshot.readOnly = false; }, /未确认可写/],
    [() => { context.state.phase3RequestPending = true; }, () => { context.state.phase3RequestPending = false; }, /正在执行/],
    [() => run('remotePhase3State.loading = true'), () => run('remotePhase3State.loading = false'), /正在读取/],
    [() => run('remotePhase3State.submitting = true'), () => run('remotePhase3State.submitting = false'), /正在提交/],
  ]) {
    enable(); run('updateRemotePhase3Ui()');
    assert.equal(elements['#remotePhase3ConfirmAll'].disabled, true);
    assert.equal(elements['#remotePhase3Confirm'].disabled, true);
    assert.match(elements['#remotePhase3SubmitStatus'].textContent, message);
    change('ConfirmAll', true);
    assert.equal(run('remotePhase3State.confirmed.size'), 0);
    assert.equal(elements['#remotePhase3ConfirmAll'].checked, false);
    disable();
  }
  change('ConfirmAll', true); change('SkipAcknowledged', true);
  elements['#remotePhase3Dialog'].close();
  await run('openRemotePhase3Dialog()');
  assert.equal(run('remotePhase3State.confirmed.size'), 0);
  assert.equal(elements['#remotePhase3ConfirmAll'].checked, false);
  assert.equal(elements['#remotePhase3SkipAcknowledged'].checked, false);
});

test('mapping read failure and empty eligibility show actionable reasons without exposing errors', async () => {
  const failed = mappingBatchHarness({ apiFetch: async () => { throw new Error('private failure text'); } });
  await failed.run('openRemotePhase3Dialog()');
  assert.equal(failed.elements['#remotePhase3ConfirmAll'].disabled, true);
  assert.match(failed.elements['#remotePhase3SubmitStatus'].textContent, /未读取成功.*关闭后重新打开/);
  assert.doesNotMatch(failed.elements['#remotePhase3SubmitStatus'].textContent, /private/);
  const empty = mappingBatchHarness({ apiFetch: async () => ({ ok: true, json: async () => listing([]) }) });
  await empty.run('openRemotePhase3Dialog()');
  empty.change('ConfirmAll', true);
  assert.equal(empty.elements['#remotePhase3ConfirmAll'].disabled, true);
  assert.equal(empty.elements['#remotePhase3Confirm'].disabled, true);
  assert.match(empty.elements['#remotePhase3SubmitStatus'].textContent, /没有可安全执行/);
});

test('compact layouts avoid sticky toolbar obstruction and expose confirmation status to assistive technology', () => {
  assert.match(styles, /@media \(max-width: 980px\), \(max-height: 760px\)\s*\{\s*\.toolbar\s*\{\s*position: static;/);
  for (const id of ['remotePhase3SubmitStatus', 'remotePhase3RecoveryStatus']) {
    assert.match(html, new RegExp('id="' + id + '"[^>]+role="status"[^>]+aria-live="polite"'));
    assert.match(html, new RegExp('aria-describedby="' + id + '"'));
  }
});

test('missing identity, duplicate/missing candidates, unavailable records and available accounts remain explicit skips', () => {
  const { context, run } = harness();
  const cases = [
    [row(124, { remoteDetails: { email: 'login@example.test' } }), listing(), /强身份/],
    [row(), listing([]), /未找到/],
    [row(), listing([local(0, { eligible: false, reason: 'username_ambiguous', phase3TargetRevision: null }),
      local(1, { eligible: false, reason: 'username_ambiguous', phase3TargetRevision: null })]), /重复/],
    [row(), listing([local(0, { eligible: false, reason: 'username_password_missing', phase3TargetRevision: null })]), /密码/],
    [row(124, { availability: 'available' }), listing(), /并非明确不可用/],
    [row(124, { targetRevision: '' }), listing(), /凭证无效/],
  ];
  for (const [sampleRow, sampleListing, pattern] of cases) {
    context.sampleRow = sampleRow; context.sampleListing = sampleListing;
    const result = run('remotePhase3MappingPlan([sampleRow], sampleListing)');
    assert.equal(result.problem, ''); assert.match(result.mappings[0].reason, pattern);
  }
  context.sampleRows = [row(), row(126)]; context.sampleListing = listing();
  const repeated = run('remotePhase3MappingPlan(sampleRows, sampleListing)');
  assert.ok(repeated.mappings.every((entry) => /同一本地/.test(entry.reason)));
});

test('mixed nineteen-row selection requires explicit skip acknowledgement and never silently submits subset', async () => {
  const { context, run, elements } = harness();
  context.state.snapshot.rows.push(row(143, { remoteDetails: { email: 'other@example.test' } }));
  context.state.selected.add('account:143');
  await run('openRemotePhase3Dialog()');
  run('remotePhase3State.confirmed.add(124)');
  assert.match(run('remotePhase3ConfirmedTargets().problem'), /明确确认.*跳过/);
  elements['#remotePhase3SkipAcknowledged'].checked = true;
  assert.equal(run('remotePhase3ConfirmedTargets().targets.length'), 1);
  context.state.selectionRevision += 1;
  run('updateRemotePhase3Ui()');
  assert.equal(elements['#remotePhase3Confirm'].disabled, true);
  context.state.snapshot.rows = Array.from({ length: 101 }, (_, index) => row(index + 1));
  context.state.selected = new Set(context.state.snapshot.rows.map((entry) => entry.key));
  assert.match(run('remotePhase3SelectionProblem()'), /最多 100/);
});

test('mapping submission freezes exact remote IDs and uses existing idempotent local endpoint', async () => {
  let submitted; let watched;
  const { run } = harness({
    idempotentMutationFetch: async (...args) => {
      submitted = clone(args);
      return { response: { ok: true }, body: { jobIds: [jobId], rejected: [],
        remoteTargets: [{ accountId: 124, targetRevision }] } };
    }, watchJobs: async (ids) => { watched = clone(ids); },
  });
  await run('openRemotePhase3Dialog()');
  run('remotePhase3State.confirmed.add(124)');
  await run('submitRemotePhase3({preventDefault(){},submitter:{value:"confirm"}})');
  assert.equal(submitted[0], 'phase3'); assert.equal(submitted[1], '/api/phase3/local');
  assert.equal(submitted[2].remoteMappingConfirmed, true);
  assert.deepEqual(submitted[2].selectedKeys, ['username:0']);
  assert.deepEqual(submitted[2].accounts[0].remoteTarget, { accountId: 124, targetRevision });
  assert.deepEqual(watched, [jobId]);
});

test('partial or mismatched receipt stops and rechecks inventory, without echoing arbitrary errors', async () => {
  let writes = 0; let inventories = 0;
  const { run, elements } = harness({ idempotentMutationFetch: async () => {
    writes += 1;
    return { response: { ok: true }, body: { jobIds: [jobId], rejected: [], remoteTargets: [{ accountId: 266, targetRevision }] } };
  }, loadSnapshot: async () => { inventories += 1; }, watchJobs: () => assert.fail('must stop') });
  await run('openRemotePhase3Dialog()'); run('remotePhase3State.confirmed.add(124)');
  await run('submitRemotePhase3({preventDefault(){},submitter:{value:"confirm"}})');
  assert.equal(writes, 1); assert.equal(inventories, 1);
  assert.match(elements['#remotePhase3Error'].textContent, /停止后续提交/);
});

test('cancelled local read cannot repopulate stale mapping and authentication errors remain redacted', async () => {
  let resolve;
  const { run, elements } = harness({ apiFetch: () => new Promise((done) => { resolve = done; }) });
  const pending = run('openRemotePhase3Dialog()');
  elements['#remotePhase3Dialog'].close();
  resolve({ ok: true, json: async () => listing() });
  await pending;
  assert.equal(run('remotePhase3State.mappings.length'), 0);
  const failed = harness({ apiFetch: async () => { throw new Error('password=do-not-display'); } });
  await failed.run('openRemotePhase3Dialog()');
  assert.doesNotMatch(failed.elements['#remotePhase3Error'].textContent, /password|do-not-display/);
});

test('only verified successful job outputs are offered for recovery; unsafe paths and unknown outcomes fail closed', () => {
  const { context, run } = harness();
  context.sample = job();
  assert.equal(run('remotePhase3SuccessfulResult(sample).selectedKey'), 'token:tokens:tokens/new.json');
  for (const mutate of [
    (value) => { value.status = 'failed'; },
    (value) => { value.result.requiresReconciliation = true; },
    (value) => { value.result.writeOutcomeUnknown = true; },
    (value) => { value.result.tokenFile = '../tokens/new.json'; },
    (value) => { value.result.tokenFile = 'use_token/new.json'; },
    (value) => { value.result.tokenContentHash = 'bad'; },
    (value) => { value.result.remoteTarget.targetRevision = ''; },
    (value) => { value.result.remoteTarget.accountId = '124'; },
    (value) => { value.result.remoteTarget.targetDigest = ''; },
    (value) => { value.result.remoteTarget.endpointDigest = ''; },
    (value) => { value.result.remoteTarget.identityKeys = ['email:login@example.test']; },
  ]) {
    context.sample = job(); mutate(context.sample);
    assert.equal(run('remotePhase3SuccessfulResult(sample)'), null);
  }
});

test('targeted preview binds successful task IDs and import never degrades to ordinary import', async () => {
  const calls = []; let mutation;
  const { run, context, elements } = harness({ apiFetch: async (url, options) => {
    calls.push([url, options?.body ? JSON.parse(options.body) : null]);
    return { ok: true, json: async () => url.startsWith('/api/jobs?')
      ? { jobs: [{ id: jobId, type: 'phase3', status: 'succeeded', result: { summaryUnavailable: true } }] }
      : url.startsWith('/api/jobs/') ? job() : plan() };
  }, idempotentMutationFetch: async (...args) => {
    mutation = clone(args); return { response: { ok: true }, body: { jobId: 'job_' + 'e'.repeat(24) } };
  } });
  await run('openRemotePhase3Recovery()');
  assert.equal(run('remotePhase3State.recoveryJobs.length'), 1, 'summary-only inventory must load authenticated detail');
  assert.equal(run('remotePhase3State.recoverySelected.size'), 0);
  context.sampleJobId = jobId; run('remotePhase3State.recoverySelected.add(sampleJobId)');
  await run('previewRemotePhase3Import()');
  const preview = calls.find(([url]) => url === '/api/sync/preview')[1];
  assert.deepEqual(preview, { selectedKeys: ['token:tokens:tokens/new.json'],
    remoteTargets: [{ accountId: 124, targetRevision }], phase3JobIds: [jobId] });
  assert.equal(elements['#remotePhase3RecoveryImport'].disabled, false);
  await run('importRemotePhase3Tokens()');
  assert.equal(mutation[0], 'token_import'); assert.equal(mutation[1], '/api/sync/import');
  assert.deepEqual(mutation[2].phase3JobIds, [jobId]);
  assert.deepEqual(mutation[2].remoteTargets, [{ accountId: 124, targetRevision }]);
  assert.doesNotMatch(JSON.stringify(mutation[2]), /endpointDigest|targetDigest/);
  assert.ok(mutation[2].planIntentVersion);
  assert.deepEqual([...context.state.selected], ['account:124']);
});

test('targeted preview rejects creates, different IDs, paths, superseded copies and duplicate choices', () => {
  const { context, run } = harness();
  context.sampleJob = job();
  context.targets = [run('remotePhase3SuccessfulResult(sampleJob)')];
  for (const mutate of [
    (value) => { value.items[0].action = 'create'; },
    (value) => { value.items[0].accountId = 266; },
    (value) => { value.items[0].relativePath = 'tokens/other.json'; },
    (value) => { value.items[0].selectedSourceSuperseded = true; },
    (value) => { value.items = []; },
    (value) => { value.items.push({ ...value.items[0] }); },
  ]) {
    context.samplePlan = plan(); mutate(context.samplePlan);
    assert.notEqual(run('remotePhase3ImportPlanProblem(samplePlan, targets)'), '');
  }
  context.samplePlan = plan(); context.samplePlan.items[0].action = 'skip';
  context.samplePlan.items[0].reason = 'sub2api_available';
  assert.equal(run('remotePhase3ImportPlanProblem(samplePlan, targets)'), '');
});

test('write holds prevent mapping and recovery; UI integration preserves separate local workflow and same-origin scripts', async () => {
  let reads = 0;
  const { run, elements } = harness({ reconciliationWriteBlocked: () => true,
    apiFetch: async () => { reads += 1; throw new Error('must not read'); } });
  await run('openRemotePhase3Dialog()'); await run('openRemotePhase3Recovery()');
  assert.equal(reads, 0); assert.equal(elements['#remotePhase3RecoveryButton'].disabled, true);
  assert.match(app, /remotePhase3SelectionApplicable\(\)[\s\S]{0,120}openRemotePhase3Dialog/);
  assert.match(app, /remotePhase3 \? comparisonAvailable\(\) : phase3Targets.length > 0/);
  assert.match(html, /src="\/local-phase3\.js" defer><\/script>\s*<script src="\/remote-phase3\.js" defer>/);
  assert.match(html, /邮箱只用于列出登录候选，不代表身份已验证/);
  assert.match(html, /不新增账号/);
  assert.doesNotMatch(source, /\/accounts\/[^\n]+\/refresh/);
});
