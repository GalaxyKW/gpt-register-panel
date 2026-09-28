'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
require('./test-isolation');

const source = fs.readFileSync(path.join(__dirname, '../frontend/remote-phase3.js'), 'utf8');
const revision = 'account-test-v1.' + 'A'.repeat(43);

function entry(index, accountId = index, tokenFile = 'tokens/recovery-' + index + '.json') {
  const id = 'job_' + index.toString(16).padStart(24, '0');
  return { job: { id, finishedAt: '2026-09-28T00:00:00Z' }, target: {
    jobId: id, selectedKey: 'token:tokens:' + tokenFile, tokenSource: 'tokens', tokenFile,
    remoteTarget: { accountId, targetRevision: revision },
  } };
}

function plan(entries, action = 'update') {
  return { version: 'snapshot-version', planIntentVersion: 'sync-plan-v1.' + 'B'.repeat(43),
    items: entries.map(({ target }) => ({ action, accountId: target.remoteTarget.accountId,
      source: target.tokenSource, relativePath: target.tokenFile, reason: 'fixture-reason' })) };
}

function harness() {
  const elements = {};
  const handlers = {};
  let reads = 0;
  let writes = 0;
  const context = {
    state: { snapshot: { readOnly: false }, jobInventoryVerified: true },
    document: { querySelector(selector) {
      return elements[selector] ||= { open: false, checked: false, dataset: {}, hidden: true,
        querySelectorAll: () => [], addEventListener(type, handler) { handlers[selector + ':' + type] = handler; },
      };
    } },
    window: { confirm: () => true },
    reconciliationWriteBlocked: () => Boolean(context.hold),
    actionsLocked: () => Boolean(context.state.importRequestPending || context.state.previewRequestPending
      || context.state.localPhase3ListingPending),
    phase3CapabilityAvailable: () => true,
    comparisonAvailable: () => true,
    updateActionState: () => vm.runInContext('updateRemotePhase3Ui()', context),
    importPlanContractProblem: (value) => Array.isArray(value?.items) ? '' : '预览格式无效',
    validImportPlanIntentVersion: (value) => /^sync-plan-v1\.[A-Za-z0-9_-]{43}$/.test(String(value)),
    escapeHtml: (value) => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;'),
    formatDate: (value) => value,
    apiFetch: async () => { reads += 1; throw new Error('unexpected read'); },
    idempotentMutationFetch: async () => { writes += 1; throw new Error('unexpected mutation'); },
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  elements['#remotePhase3RecoveryDialog'].open = true;
  const run = (code) => vm.runInContext(code, context);
  const install = (jobs, selected = jobs.map(({ job }) => job.id)) => {
    context.sampleJobs = jobs;
    context.sampleSelected = selected;
    run('remotePhase3State.recoveryJobs = sampleJobs; remotePhase3State.recoverySelected = new Set(sampleSelected); updateRemotePhase3Ui();');
  };
  const setPlan = (value) => {
    context.samplePlan = value;
    run('remotePhase3State.recoveryPlan = samplePlan; remotePhase3State.recoveryBinding = {}; updateRemotePhase3Ui();');
  };
  const change = (id, checked) => handlers['#remotePhase3RecoveryRows:change']({
    target: { dataset: { remotePhase3Job: id }, checked },
  });
  return { run, context, elements, install, setPlan, change, reads: () => reads, writes: () => writes };
}

test('recovery explains empty inventory and missing selection without hover', () => {
  const h = harness();
  h.install([]);
  assert.equal(h.elements['#remotePhase3RecoveryPreview'].disabled, true);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /没有可核验的成功任务/);
  h.install([entry(1)], []);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /先勾选/);
  assert.match(h.elements['#remotePhase3RecoveryImport'].title, /先勾选/);
  assert.equal(h.elements['#remotePhase3RecoveryStatus'].dataset.state, 'blocked');
});

test('duplicate remote IDs are blocked before requests and correction clears only stale choice errors', async () => {
  const h = harness();
  const jobs = [entry(1, 124), entry(2, 124)];
  h.install(jobs);
  assert.equal(h.elements['#remotePhase3RecoveryPreview'].disabled, true);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /同一远端 ID/);
  await h.run('previewRemotePhase3Import()');
  assert.equal(h.reads(), 0);
  assert.equal(h.elements['#remotePhase3RecoveryError'].hidden, false);
  h.setPlan(plan([jobs[0]]));
  h.change(jobs[1].job.id, false);
  assert.equal(h.elements['#remotePhase3RecoveryError'].hidden, true);
  assert.equal(h.elements['#remotePhase3RecoveryPreview'].disabled, false);
  assert.equal(h.elements['#remotePhase3RecoveryImport'].disabled, true);
  assert.equal(h.run('remotePhase3State.recoveryPlan'), null);
  assert.equal(h.run('remotePhase3State.recoveryBinding'), null);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /已选 1.*先点击/);
});

test('duplicate token files, unknown selections and selections above 100 fail closed with distinct reasons', async () => {
  const h = harness();
  for (const [jobs, selected, reason] of [
    [[entry(1, 124, 'tokens/same.json'), entry(2, 126, 'tokens/same.json')], null, /同一新 token 文件/],
    [[entry(1)], ['job_' + 'f'.repeat(24)], /不在当前清单/],
    [Array.from({ length: 101 }, (_, index) => entry(index + 1)), null, /最多回写 100/],
  ]) {
    h.install(jobs, selected || jobs.map(({ job }) => job.id));
    assert.equal(h.elements['#remotePhase3RecoveryPreview'].disabled, true);
    assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, reason);
    await h.run('previewRemotePhase3Import()');
    await h.run('importRemotePhase3Tokens()');
  }
  assert.equal(h.reads(), 0);
  assert.equal(h.writes(), 0);
});

test('all-skip recovery plan explains no update without inventing availability', async () => {
  const h = harness();
  const jobs = [entry(1), entry(2)];
  h.install(jobs);
  h.setPlan(plan(jobs, 'skip'));
  assert.equal(h.elements['#remotePhase3RecoveryPreview'].disabled, false);
  assert.equal(h.elements['#remotePhase3RecoveryImport'].disabled, true);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /全部跳过.*无需更新.*每一项/);
  assert.doesNotMatch(h.elements['#remotePhase3RecoveryStatus'].textContent, /可用/);
  assert.match(h.elements['#remotePhase3RecoveryImport'].title, /全部跳过/);
  await h.run('importRemotePhase3Tokens()');
  assert.equal(h.writes(), 0);
});

test('recovery plan readiness requires original IDs and shows update and skip counts', async () => {
  const h = harness();
  const jobs = [entry(1), entry(2)];
  h.install(jobs);
  const preview = plan(jobs);
  preview.items[1].action = 'skip';
  h.setPlan(preview);
  assert.equal(h.elements['#remotePhase3RecoveryImport'].disabled, false);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /更新 1 个，跳过 1 个/);
  assert.equal(h.elements['#remotePhase3RecoveryStatus'].dataset.state, 'ready');
  preview.items[0].accountId = 266;
  h.setPlan(preview);
  assert.equal(h.elements['#remotePhase3RecoveryImport'].disabled, true);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /其他 ID/);
  await h.run('importRemotePhase3Tokens()');
  assert.equal(h.writes(), 0);
});

test('selection change preserves unknown submission errors and never removes a reconciliation lock', () => {
  const h = harness();
  const jobs = [entry(1), entry(2)];
  h.install(jobs);
  h.run("remotePhase3Error('回写提交结果无法确认，后台可能已执行', true); remotePhase3Elements.RecoveryError.dataset.kind = 'submission';");
  h.change(jobs[1].job.id, false);
  assert.equal(h.elements['#remotePhase3RecoveryError'].hidden, false);
  assert.match(h.elements['#remotePhase3RecoveryError'].textContent, /结果无法确认/);
  h.context.hold = true;
  h.run('updateRemotePhase3Ui()');
  h.change(jobs[0].job.id, false);
  assert.equal(h.run('remotePhase3State.recoverySelected.size'), 1);
  assert.equal(h.elements['#remotePhase3RecoveryPreview'].disabled, true);
  assert.equal(h.elements['#remotePhase3RecoveryImport'].disabled, true);
  assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, /人工对账/);
  assert.equal(h.context.hold, true);
});

test('read, preview and import busy states stay visible and keep the existing close guard', () => {
  const h = harness();
  h.install([entry(1)]);
  for (const [flag, reason] of [
    ['localPhase3ListingPending', /读取并核验/],
    ['previewRequestPending', /回写预览/],
    ['importRequestPending', /提交定向回写/],
  ]) {
    h.context.state[flag] = true;
    h.run('remotePhase3State.recoveryBusy = true; updateRemotePhase3Ui();');
    assert.match(h.elements['#remotePhase3RecoveryStatus'].textContent, reason);
    assert.equal(h.elements['#remotePhase3RecoveryStatus'].dataset.state, 'busy');
    assert.equal(h.elements['#remotePhase3RecoveryPreview'].disabled, true);
    assert.equal(h.elements['#remotePhase3RecoveryImport'].disabled, true);
    assert.equal(h.elements['#remotePhase3RecoveryClose'].disabled, true);
    h.context.state[flag] = false;
  }
});
