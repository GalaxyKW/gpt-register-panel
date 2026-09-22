'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
require('./test-isolation');

const helper = fs.readFileSync(path.join(__dirname, '../frontend/account-test-batch.js'), 'utf8');
const source = fs.readFileSync(path.join(__dirname, '../frontend/account-test-batch-ui.js'), 'utf8');
const app = fs.readFileSync(path.join(__dirname, '../frontend/app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
const jobId = (index) => 'job_' + index.toString(16).padStart(24, '0');

function row(id, extra = {}) {
  return { key: 'sub2api:' + id, accountId: id, platform: 'openai', type: 'oauth', status: 'active',
    targetRevision: 'account-test-v1.' + String(id).padStart(43, 'a'), ...extra };
}
function successfulJob(id, ids) {
  return { id, type: 'account_test', status: 'succeeded', error: null,
    payload: { accountIds: ids, modelId: 'gpt-5.6-luna' },
    result: { jobStatus: 'succeeded', model: 'gpt-5.6-luna', requested: ids.length,
      succeeded: ids.length, attemptedCount: ids.length,
      failed: 0, skipped: 0, reconciliationCount: 0, notAttemptedCount: 0,
      reconciliationNotAttemptedCount: 0, timeoutCount: 0, interruptedCount: 0,
      requiresReconciliation: false, executionStarted: true, executionComplete: true, stopReason: null,
      results: ids.map((accountId) => ({ accountId, status: 'succeeded', testSuccess: true, code: 'account_test_succeeded' })) } };
}
function harness(rows, overrides = {}) {
  const nodes = {};
  const events = {};
  const requests = [];
  const submissions = [];
  const jobs = new Map();
  const notices = [];
  let recoveries = 0;
  const context = {
    AbortController,
    state: { snapshot: { readOnly: false, rows }, selected: new Set(rows.map((item) => item.key)),
      jobInventoryVerified: true, selectionRevision: 1, snapshotRequestsPending: 0 },
    elements: Object.fromEntries(['searchInput', 'statusFilter', 'availabilityFilter', 'sourceFilter',
      'diffFilter', 'historicalToggle', 'refreshButton', 'accountTestModelSelect', 'notice'].map((name) => [name, { value: 'gpt-5.6-luna' }])),
    document: { querySelector(selector) {
      return nodes[selector] ||= {
        open: false, checked: false,
        showModal() { this.open = true; },
        close() { this.open = false; for (const handler of events[selector + ':close'] || []) handler(); },
        addEventListener(name, handler) { (events[selector + ':' + name] ||= []).push(handler); },
      };
    } },
    window: { setTimeout: (callback) => setTimeout(callback, 0), clearTimeout },
    actionsLocked: () => Boolean(context.state.accountTestBatchPending || context.state.accountTestRequestPending),
    activeJobPending: () => ['queued', 'running', 'unknown'].includes(context.state.job?.status),
    comparisonAvailable: () => true,
    reconciliationWriteBlocked: () => false,
    jobNeedsReconciliation: (job) => job?.result?.requiresReconciliation === true,
    hiddenSelectionProblem: () => '',
    selectedRowsFromSelection: () => context.state.snapshot.rows.filter((item) => context.state.selected.has(item.key)),
    selectionStillCurrent: (revision, keys) => revision === context.state.selectionRevision
      && keys.length === context.state.selected.size && keys.every((key) => context.state.selected.has(key)),
    normalizeAccountTestModel: (model) => model || '',
    accountTestModelLabel: (model) => model,
    escapeHtml: (value) => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;'),
    showNotice: (...args) => { notices.push(args); context.elements.notice.textContent = args[0]; },
    updateActionState() { vm.runInContext('updateAccountTestBatchUi();', context); },
    renderJob() {},
    terminalJob: (status) => ['succeeded', 'partial', 'failed', 'interrupted'].includes(status),
    apiFetch: async (url) => {
      requests.push(url);
      let body;
      if (url === '/api/jobs?limit=200') body = { jobs: [], activeJobs: { total: 0, returned: 0, truncated: false },
        reconciliationHolds: { total: 0, returned: 0, truncated: false } };
      else if (url === '/api/snapshot?withSub2api=1') body = { readOnly: false, sub2api: { readStatus: 'ok' },
        diff: { comparisonStatus: 'complete' }, rows };
      else if (url.startsWith('/api/jobs/')) body = jobs.get(url.slice('/api/jobs/'.length));
      else throw new Error('unexpected read URL');
      return { ok: true, json: async () => body };
    },
    idempotentMutationFetch: async (workflow, url, body) => {
      assert.equal(workflow, 'account_test');
      assert.equal(url, '/api/account-tests');
      submissions.push(body);
      const id = jobId(submissions.length);
      const ids = body.targets.map((target) => target.accountId);
      jobs.set(id, successfulJob(id, ids));
      return { response: { ok: true }, body: { status: 'queued', jobId: id, accountIds: ids, rejected: [] } };
    },
    loadSnapshot: async (options) => {
      assert.equal(options.resumeJobs, true);
      recoveries += 1;
      context.state.jobInventoryVerified = true;
      context.state.snapshotRefreshPending = false;
      context.state.accountTestRequestPending = false;
      context.state.job = null;
      return true;
    },
    ...overrides,
  };
  vm.createContext(context);
  vm.runInContext(helper + '\n' + source, context);
  return { context, nodes, events, requests, submissions, jobs, notices,
    run: (code) => vm.runInContext(code, context), recoveries: () => recoveries };
}
const submit = 'submitAccountTestBatchConfirmation({preventDefault() {}, submitter:{value:"confirm"}})';
async function until(condition) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (condition()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error('test condition not reached');
}

test('batch UI confirms 141 eligible and one missing-identity skip without deleting or silently excluding', async () => {
  const rows = Array.from({ length: 141 }, (_, index) => row(index + 1))
    .concat(row(143, { targetRevision: null, remoteDetails: { chatgptAccountId: '', userId: '' } }));
  const { run, nodes, submissions, requests, recoveries, context } = harness(rows);
  await run('openAccountTestBatchDialog()');
  assert.match(nodes['#accountTestBatchSummary'].textContent, /测试 141 个 · 跳过 1 个 · 2 批/);
  assert.match(nodes['#accountTestBatchSkipped'].innerHTML, /Sub2API #143.*缺少 accountId \/ userId 强身份/);
  assert.equal(nodes['#accountTestBatchConfirm'].disabled, true);
  await run(submit);
  assert.equal(submissions.length, 0);
  assert.match(nodes['#accountTestBatchError'].textContent, /明确确认/);
  nodes['#accountTestBatchSkipAcknowledged'].checked = true;
  await run(submit);
  assert.deepEqual(submissions.map((body) => body.targets.length), [100, 41]);
  assert.equal(submissions.some((body) => body.targets.some((target) => target.accountId === 143)), false);
  assert.ok(submissions.every((body) => body.modelId === 'gpt-5.6-luna'));
  assert.equal(requests.filter((url) => url === '/api/snapshot?withSub2api=1').length, 2);
  assert.equal(requests.some((url) => /delete|includeHistorical|filter/.test(url)), false);
  assert.equal(recoveries(), 1);
  assert.equal(context.state.accountTestBatchPending, false);
  assert.match(nodes['#accountTestBatchProgress'].textContent, /完成：141 个，2 批/);
});

test('batch UI keeps the 1000 selection ceiling and rejects duplicate IDs or all-ineligible selections', () => {
  const { run, context, nodes } = harness([row(143, { targetRevision: null })]);
  assert.match(nodes['#accountTestBatchSelectionHint'].textContent, /#143.*缺少 accountId/);
  context.rows = [row(1), row(1, { key: 'token:tokens:tokens/one.json' })];
  assert.match(run('accountTestBatchSelection(rows).problem'), /只保留其中一行/);
  context.rows = Array.from({ length: 1001 }, (_, index) => row(index + 1));
  assert.match(run('accountTestBatchSelection(rows).problem'), /最多核对 1000/);
  delete context.PanelAccountTestBatch;
  assert.match(run('accountTestBatchActionProblem()'), /组件未加载/);
});

test('batch UI validates unchanged selection and model before using an earlier confirmation', async () => {
  for (const change of [
    (context) => { context.state.selectionRevision += 1; },
    (context) => { context.elements.accountTestModelSelect.value = 'gpt-5.6-terra'; },
  ]) {
    const { run, context, nodes, submissions } = harness([row(1)]);
    await run('openAccountTestBatchDialog()');
    change(context);
    await run(submit);
    assert.equal(submissions.length, 0);
    assert.match(nodes['#accountTestBatchError'].textContent, /已变化/);
  }
});

test('batch UI waits through queued and running states before submitting the next batch', async () => {
  const state = harness(Array.from({ length: 101 }, (_, index) => row(index + 1)));
  const read = state.context.apiFetch;
  let firstJobReads = 0;
  state.context.apiFetch = async (url, options) => {
    if (url === '/api/jobs/' + jobId(1)) {
      firstJobReads += 1;
      assert.equal(state.submissions.length, 1);
      if (firstJobReads < 3) return { ok: true, json: async () => ({ id: jobId(1), type: 'account_test',
        status: firstJobReads === 1 ? 'queued' : 'running' }) };
    }
    return read(url, options);
  };
  await state.run('openAccountTestBatchDialog()');
  await state.run(submit);
  assert.equal(firstJobReads, 3);
  assert.deepEqual(state.submissions.map((body) => body.targets.length), [100, 1]);
});

test('batch UI stops on failed, partial, reconciliation or unknown jobs and never automatically retries', async () => {
  for (const status of ['failed', 'partial', 'unknown', 'hold', 'http-error']) {
    const state = harness(Array.from({ length: 101 }, (_, index) => row(index + 1)));
    const read = state.context.apiFetch;
    state.context.apiFetch = async (url, options) => {
      if (url === '/api/jobs/' + jobId(1)) {
        if (status === 'http-error') return { ok: false, json: async () => ({}) };
        const job = state.jobs.get(jobId(1));
        if (status === 'hold') job.result.reconciliationHold = true;
        else job.status = status;
        return { ok: true, json: async () => job };
      }
      return read(url, options);
    };
    await state.run('openAccountTestBatchDialog()');
    await state.run(submit);
    assert.equal(state.submissions.length, 1, status);
    assert.equal(state.recoveries(), 1, status);
    assert.match(state.nodes['#accountTestBatchProgress'].textContent, /已停止后续批次/);
  }
});

test('batch UI verifies every remaining original revision and stops when a later target changes', async () => {
  const state = harness(Array.from({ length: 101 }, (_, index) => row(index + 1)));
  const read = state.context.apiFetch;
  let snapshots = 0;
  state.context.apiFetch = async (url, options) => {
    const response = await read(url, options);
    if (url === '/api/snapshot?withSub2api=1' && ++snapshots === 2) {
      const body = await response.json();
      return { ok: true, json: async () => ({ ...body, rows: body.rows.map((item) => item.accountId === 101
        ? { ...item, targetRevision: 'account-test-v1.' + 'Z'.repeat(43) } : item) }) };
    }
    return response;
  };
  await state.run('openAccountTestBatchDialog()');
  await state.run(submit);
  assert.equal(state.submissions.length, 1);
  assert.equal(snapshots, 2);
  assert.match(state.nodes['#accountTestBatchProgress'].textContent, /不会自动替换目标/);
});

test('stopping during submission waits for the in-flight mutation before recovery or unlocking', async () => {
  const state = harness(Array.from({ length: 101 }, (_, index) => row(index + 1)));
  let resolveSubmission;
  let writes = 0;
  let recovered = 0;
  state.context.idempotentMutationFetch = async () => {
    writes += 1;
    return new Promise((resolve) => { resolveSubmission = resolve; });
  };
  state.context.loadSnapshot = async () => {
    recovered += 1;
    assert.equal(state.context.state.accountTestBatchPending, true);
    state.context.state.accountTestRequestPending = true;
    state.context.state.job = { id: jobId(1), status: 'running', type: 'account_test' };
    return true;
  };
  await state.run('openAccountTestBatchDialog()');
  const running = state.run(submit);
  await until(() => writes === 1);
  assert.equal(state.context.elements.searchInput.disabled, true);
  assert.equal(state.context.elements.refreshButton.disabled, true);
  await state.run(submit);
  assert.equal(writes, 1);
  state.events['#accountTestBatchStop:click'][0]();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(recovered, 0);
  assert.equal(state.context.state.accountTestBatchPending, true);
  resolveSubmission({ response: { ok: true }, body: { status: 'queued', jobId: jobId(1),
    accountIds: Array.from({ length: 100 }, (_, index) => index + 1), rejected: [] } });
  await running;
  assert.equal(writes, 1);
  assert.equal(recovered, 1);
  assert.equal(state.context.state.accountTestBatchPending, false);
  assert.equal(state.context.state.accountTestRequestPending, true);
  assert.match(state.nodes['#accountTestBatchProgress'].textContent, /不会被取消|仍有任务执行/);
});

test('batch recovery failure never unlocks actions based on the old snapshot', async () => {
  const state = harness([row(1)], { loadSnapshot: async () => { throw new Error('unavailable'); } });
  await state.run('openAccountTestBatchDialog()');
  await state.run(submit);
  assert.equal(state.context.state.jobInventoryVerified, false);
  assert.equal(state.context.state.snapshotRefreshPending, true);
  assert.match(state.nodes['#accountTestBatchProgress'].textContent, /保持锁定/);
});

test('batch completion preserves a newly discovered reconciliation warning instead of replacing it with success', async () => {
  for (const held of [true, false]) {
    const state = harness([row(1)]);
    state.context.reconciliationWriteBlocked = () => (state.context.state.reconciliationHolds?.total || 0) > 0;
    state.context.loadSnapshot = async () => {
      state.context.state.jobInventoryVerified = true;
      state.context.state.snapshotRefreshPending = false;
      state.context.state.reconciliationHolds = { total: held ? 1 : 0 };
      state.context.state.job = { id: jobId(2), type: 'phase3', status: 'failed',
        result: { requiresReconciliation: true, reconciliationHold: held } };
      state.context.showNotice('其他任务需人工核对', 'notice-warning');
      return true;
    };
    await state.run('openAccountTestBatchDialog()');
    await state.run(submit);
    assert.equal(state.submissions.length, 1);
    assert.match(state.nodes['#accountTestBatchProgress'].textContent, /分批测试完成：1 个/);
    assert.match(state.nodes['#accountTestBatchProgress'].textContent, /存在待人工核对任务/);
    assert.match(state.nodes['#accountTestBatchProgress'].textContent,
      held ? /写操作保持锁定/ : /不要重复提交待核对任务/);
    assert.equal(state.notices.at(-1)[1], 'notice-warning');
    assert.match(state.notices.at(-1)[0], /待人工核对/);
  }
});

test('batch UI non-2xx admission and partly accepted receipts stop before any later batch and recover inventory', async () => {
  for (const mode of [400, 409, 500, 'partial', 'lost-response']) {
    let writes = 0;
    const state = harness(Array.from({ length: 101 }, (_, index) => row(index + 1)));
    state.context.idempotentMutationFetch = async (_workflow, _url, body) => {
      writes += 1;
      if (mode === 'lost-response') throw new Error('connection lost');
      return { response: { ok: mode === 'partial', status: mode }, body: {
        status: 'queued', jobId: jobId(1), accountIds: body.targets.slice(0, 99).map((target) => target.accountId),
        rejected: [{ accountId: 100, code: 'account_test_already_running' }],
      } };
    };
    await state.run('openAccountTestBatchDialog()');
    await state.run(submit);
    assert.equal(writes, 1, String(mode));
    assert.equal(state.recoveries(), 1, String(mode));
    assert.match(state.nodes['#accountTestBatchProgress'].textContent, /已停止后续批次/);
  }
});

test('stopping while polling never cancels the submitted server job and does not send another batch', async () => {
  const state = harness(Array.from({ length: 101 }, (_, index) => row(index + 1)));
  const read = state.context.apiFetch;
  let polling = false;
  state.context.apiFetch = async (url, options) => {
    if (url === '/api/jobs/' + jobId(1)) {
      polling = true;
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new Error('read cancelled')), { once: true });
      });
    }
    return read(url, options);
  };
  state.context.loadSnapshot = async () => {
    state.context.state.job = { id: jobId(1), type: 'account_test', status: 'running' };
    state.context.state.accountTestRequestPending = true;
    return true;
  };
  await state.run('openAccountTestBatchDialog()');
  const running = state.run(submit);
  await until(() => polling);
  state.events['#accountTestBatchStop:click'][0]();
  await running;
  assert.equal(state.submissions.length, 1);
  assert.equal(state.context.state.accountTestRequestPending, true);
  assert.match(state.nodes['#accountTestBatchProgress'].textContent, /后台仍有任务执行/);
  assert.equal(state.requests.some((url) => /cancel|delete/.test(url)), false);
  // A fresh page only installs controls. It cannot reconstruct or automatically
  // continue this in-memory plan; ordinary task recovery owns the running job.
  const refreshed = harness([row(101)]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(refreshed.submissions.length, 0);
  assert.equal(refreshed.run('accountTestBatchUi.plan'), null);
});

test('batch status follows later watcher recovery to idle instead of retaining stale lock messages', async () => {
  for (const initialStatus of ['unknown', 'running']) {
    const state = harness([row(1)]);
    state.context.loadSnapshot = async () => {
      state.context.state.job = { id: jobId(1), type: 'account_test', status: initialStatus };
      state.context.state.jobInventoryVerified = initialStatus !== 'unknown';
      state.context.state.snapshotRefreshPending = true;
      return false;
    };
    await state.run('openAccountTestBatchDialog()');
    await state.run(submit);
    assert.match(state.nodes['#accountTestBatchProgress'].textContent, /后台仍有任务执行/);
    assert.match(state.nodes['#accountTestBatchProgress'].textContent, /操作保持锁定/);
    state.context.state.job = null;
    state.context.state.jobInventoryVerified = true;
    state.context.state.snapshotRefreshPending = false;
    state.context.state.accountTestRequestPending = false;
    state.run('updateAccountTestBatchUi();');
    assert.match(state.nodes['#accountTestBatchProgress'].textContent, /分批测试完成/);
    assert.doesNotMatch(state.nodes['#accountTestBatchProgress'].textContent, /保持锁定|仍有任务|尚未核验/);
    assert.equal(state.notices.at(-1)[1], 'notice-info');
    assert.doesNotMatch(state.context.elements.notice.textContent, /保持锁定|仍有任务|尚未核验/);
    const noticeCount = state.notices.length;
    state.run('updateAccountTestBatchUi(); updateAccountTestBatchUi();');
    assert.equal(state.notices.length, noticeCount);
  }
});

test('batch dynamic summary does not overwrite a newer operation notice when its watcher finishes', async () => {
  const state = harness([row(1)]);
  state.context.loadSnapshot = async () => {
    state.context.state.job = { id: jobId(1), type: 'account_test', status: 'running' };
    return true;
  };
  await state.run('openAccountTestBatchDialog()');
  await state.run(submit);
  state.context.showNotice('另一项操作的最新说明', 'notice-warning');
  state.context.state.job = null;
  state.context.state.accountTestRequestPending = false;
  const noticeCount = state.notices.length;
  state.run('updateAccountTestBatchUi();');
  assert.doesNotMatch(state.nodes['#accountTestBatchProgress'].textContent, /仍有任务/);
  assert.equal(state.context.elements.notice.textContent, '另一项操作的最新说明');
  assert.equal(state.notices.length, noticeCount);
});

test('batch UI script load and existing action wiring preserve the original single-request limit', () => {
  assert.ok(html.indexOf('src="/account-test-batch.js"') < html.indexOf('src="/app.js"'));
  assert.ok(html.indexOf('src="/account-test-batch-ui.js"') > html.indexOf('src="/app.js"'));
  assert.match(app, /if \(typeof openAccountTestBatchDialog === 'function'\)/);
  assert.match(app, /function actionRequestPending\(\)[\s\S]*state\.accountTestBatchPending/);
  assert.match(app, /function accountTestTargetsFromRows\(rows\) \{\s*const maximumSelection = 100;/);
  assert.match(html, /刷新或关闭页面也会停止未提交批次/);
  assert.doesNotMatch(source, /sessionStorage|localStorage|\/cancel|\/delete/);
});
