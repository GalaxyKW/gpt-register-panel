const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
const styles = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'styles.css'), 'utf8');
const selectedKey = 'token:tokens:tokens/review.json';
const target = { selectedKey, accountId: 42, targetRevision: 'account-test-v1.' + 'A'.repeat(43), sourceContentHash: 'a'.repeat(64) };
const candidate = { ...target, accountName: 'free00042', identityCompletion: 'account_id' };
const clone = (value) => JSON.parse(JSON.stringify(value));

function section(start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, 'source section exists: ' + start);
  return source.slice(from, to);
}

function ordinaryPlan() {
  return { version: 'b'.repeat(64), planIntentVersion: 'sync-plan-v1.' + 'B'.repeat(43), selectedKeys: [selectedKey],
    items: [{ source: 'tokens', relativePath: 'tokens/review.json', action: 'conflict', reason: 'ambiguous_sub2api_identity' }],
    identityCompletionCandidates: [clone(candidate)] };
}

function reviewedPlan() {
  return { ...ordinaryPlan(), identityCompletionCandidates: [], identityCompletionConfirmed: true,
    identityCompletionTargets: [clone(target)],
    items: [{ source: 'tokens', relativePath: 'tokens/review.json', action: 'update', reason: 'token_changed', accountId: 42, identityCompletion: 'account_id' }] };
}

function harness() {
  const requests = [];
  const notices = [];
  const confirmations = [];
  const context = { state: { selected: new Set([selectedKey]), selectionRevision: 3, plan: ordinaryPlan(),
    snapshot: { readOnly: false }, identityCompletionBinding: null, previewRequestPending: false },
  elements: { identityCompletionReviewButton: {}, identityCompletionReview: {}, identityCompletionReviewHint: {} },
  Object, Set, JSON,
  actionsLocked: () => false,
  reconciliationWriteBlocked: () => false,
  comparisonAvailable: () => true,
  hiddenSelectionProblem: () => '',
  syncSelectionProblem: () => '',
  validImportPlanIntentVersion: (value) => /^sync-plan-v1\.[A-Za-z0-9_-]{43}$/.test(value),
  importPlanContractProblem: () => '',
  importGroupBindingProblem: () => '',
  effectivePlanAction: (item) => item.action,
  escapeHtml: (value) => String(value),
  showNotice: (message) => notices.push(message),
  updateActionState() {},
  renderPlan(plan) { context.state.plan = plan; if (!plan) context.state.identityCompletionBinding = null; },
  selectionStillCurrent(revision, keys) { return revision === context.state.selectionRevision
    && keys.length === context.state.selected.size && keys.every((key) => context.state.selected.has(key)); },
  window: { confirm(message) { confirmations.push(message); return true; } },
  async apiFetch(url, options) { requests.push({ url, body: JSON.parse(options.body) }); return { ok: true, async json() { return reviewedPlan(); } }; },
  };
  vm.createContext(context);
  vm.runInContext(section('function identityCompletionSourceKey', 'function planItemCreatesAccount')
    + '\n' + section('async function previewIdentityCompletion', "elements.previewButton.addEventListener('click', previewSelection);"), context);
  return { context, requests, notices, confirmations };
}

test('identity completion explicitly reviews every original ID before producing a bound preview', async () => {
  const { context, requests, confirmations } = harness();
  assert.equal(await context.previewIdentityCompletion(), true);
  assert.deepEqual(requests, [{ url: '/api/sync/preview', body: { selectedKeys: [selectedKey],
    identityCompletionConfirmed: true, identityCompletionTargets: [target] } }]);
  assert.match(confirmations[0], /#42/);
  assert.match(confirmations[0], /同 User ID/);
  assert.match(confirmations[0], /不新增.*不重新登录/);
  assert.deepEqual(clone(context.state.identityCompletionBinding), [target]);
  assert.equal(context.identityCompletionPlanProblem(context.state.plan), '');
});

test('identity completion never silently drops a mixed or duplicate selection', async () => {
  for (const modify of [
    (ctx) => { ctx.state.selected.add('token:tokens:tokens/other.json'); ctx.state.plan.selectedKeys.push('token:tokens:tokens/other.json'); },
    (ctx) => { ctx.state.plan.identityCompletionCandidates.push(clone(candidate)); },
    (ctx) => { ctx.state.plan.identityCompletionCandidates[0].selectedKey = 'token:tokens:tokens/other.json'; },
  ]) {
    const { context, requests, notices } = harness();
    modify(context);
    assert.equal(await context.previewIdentityCompletion(), false);
    assert.equal(requests.length, 0);
    assert.ok(notices.length > 0);
  }
});

test('identity completion rejects mismatched ID, revision, hash, path, action and marker responses', async () => {
  for (const alter of [
    (plan) => { delete plan.identityCompletionConfirmed; },
    (plan) => { plan.identityCompletionTargets[0].accountId = 43; },
    (plan) => { plan.identityCompletionTargets[0].targetRevision = 'account-test-v1.' + 'C'.repeat(43); },
    (plan) => { plan.identityCompletionTargets[0].sourceContentHash = 'c'.repeat(64); },
    (plan) => { plan.items[0].accountId = 43; },
    (plan) => { plan.items[0].relativePath = 'tokens/other.json'; },
    (plan) => { plan.items[0].action = 'create'; },
    (plan) => { delete plan.items[0].identityCompletion; },
    (plan) => { plan.items[0].identityCompletion = 'user_id'; },
    (plan) => { plan.items[0].selectedSourceSuperseded = true; },
    (plan) => { plan.remoteTargets = [{ accountId: 42 }]; },
    (plan) => { plan.phase3JobIds = ['job_other']; },
    (plan) => { plan.identityCompletionCandidates = [clone(candidate)]; },
  ]) {
    const { context } = harness();
    context.apiFetch = async () => ({ ok: true, json: async () => { const result = reviewedPlan(); alter(result); return result; } });
    assert.equal(await context.previewIdentityCompletion(), false);
    assert.equal(context.state.plan, null);
    assert.equal(context.state.identityCompletionBinding, null);
  }
});

test('identity completion respects locks, read-only, reconciliation, comparison and hidden selection', async () => {
  for (const block of [
    (ctx) => { ctx.actionsLocked = () => true; },
    (ctx) => { ctx.state.snapshot.readOnly = true; },
    (ctx) => { delete ctx.state.snapshot.readOnly; },
    (ctx) => { ctx.reconciliationWriteBlocked = () => true; },
    (ctx) => { ctx.comparisonAvailable = () => false; },
    (ctx) => { ctx.hiddenSelectionProblem = () => 'hidden'; },
    (ctx) => { ctx.state.selectionRevision += 1; ctx.state.selected.clear(); },
  ]) {
    const { context, requests } = harness(); block(context);
    assert.equal(await context.previewIdentityCompletion(), false);
    assert.equal(requests.length, 0);
  }
});

test('identity completion discards responses after a selection revision changes', async () => {
  const { context } = harness();
  context.apiFetch = async () => { context.state.selectionRevision += 1; return { ok: true, json: async () => reviewedPlan() }; };
  assert.equal(await context.previewIdentityCompletion(), false);
  assert.equal(context.state.plan, null);
  assert.equal(context.state.identityCompletionBinding, null);
});

test('identity completion discards responses overtaken by a snapshot refresh', async () => {
  for (const refresh of [
    (ctx) => { ctx.state.snapshotRequestSequence = 5; },
    (ctx) => { ctx.state.snapshot = { readOnly: false }; },
  ]) {
    const { context } = harness();
    context.apiFetch = async () => { refresh(context); return { ok: true, json: async () => reviewedPlan() }; };
    assert.equal(await context.previewIdentityCompletion(), false);
    assert.equal(context.state.plan, null);
    assert.equal(context.state.identityCompletionBinding, null);
  }
});

test('identity completion rechecks task locks and the reviewed selection after final confirmation', async () => {
  for (const change of [
    (ctx) => { ctx.state.selectionRevision += 1; },
    (ctx) => { ctx.actionsLocked = () => true; },
    (ctx) => { ctx.state.plan = ordinaryPlan(); },
  ]) {
    const { context } = harness();
    await context.previewIdentityCompletion();
    let handler;
    let requests = 0;
    context.elements.importButton = { addEventListener(event, callback) { handler = callback; } };
    context.idempotentMutationFetch = async () => { requests += 1; };
    context.window.confirm = () => { change(context); return true; };
    vm.runInContext(section("elements.importButton.addEventListener('click'", "elements.phase3Button.addEventListener('click'"), context);
    await handler();
    assert.equal(requests, 0);
  }
});

test('identity completion cannot downgrade a reviewed preview to ordinary import', async () => {
  const { context } = harness();
  await context.previewIdentityCompletion();
  const downgraded = ordinaryPlan(); downgraded.items = reviewedPlan().items;
  assert.match(context.identityCompletionPlanProblem(downgraded), /身份补全/);
  context.state.identityCompletionBinding = null;
  assert.match(context.identityCompletionPlanProblem(reviewedPlan()), /身份补全/);
  assert.equal(context.identityCompletionPlanProblem(ordinaryPlan()), '');
});

test('identity completion import submits original frozen hash and revision without Phase3 fields', async () => {
  const { context, confirmations } = harness();
  await context.previewIdentityCompletion();
  let handler;
  let submitted;
  context.elements.importButton = { addEventListener(event, callback) { handler = callback; } };
  context.idempotentMutationFetch = async (kind, url, body) => { submitted = { kind, url, body }; return { response: { ok: true }, body: { jobId: 'job_review' } }; };
  context.watchJob = async () => {};
  vm.runInContext(section("elements.importButton.addEventListener('click'", "elements.phase3Button.addEventListener('click'"), context);
  await handler();
  assert.deepEqual(clone(submitted.body), { snapshotVersion: 'b'.repeat(64), planIntentVersion: 'sync-plan-v1.' + 'B'.repeat(43),
    selectedKeys: [selectedKey], identityCompletionConfirmed: true, identityCompletionTargets: [target] });
  assert.match(confirmations.at(-1), /#42/);
  assert.doesNotMatch(JSON.stringify(submitted.body), /phase3JobIds|remoteTargets/);
});

test('identity completion explanation and action fit desktop and mobile without changing row identity', () => {
  assert.match(html, /id="identityCompletionReviewButton"[^>]*aria-describedby="identityCompletionReviewHint"/);
  assert.match(html, /id="identityCompletionReviewHint"[^>]*aria-live="polite"/);
  assert.match(styles, /\.identity-completion-review\s*\{[^}]*flex-wrap:\s*wrap/s);
  assert.match(styles, /\.identity-completion-review[^}]*overflow-wrap:\s*anywhere/s);
  const { context } = harness();
  const before = JSON.stringify(context.state.plan.items);
  context.updateIdentityCompletionReview();
  assert.equal(context.elements.identityCompletionReviewButton.disabled, false);
  assert.match(context.elements.identityCompletionReviewHint.textContent, /仅补缺失 Account ID/);
  assert.equal(JSON.stringify(context.state.plan.items), before);
});
