'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
require('./test-isolation');

const {
  listLocalPhase3Targets, resolvePhase3Requests, runPhase3Job,
} = require('../backend/phase3Worker');
const {
  canonicalLocalPhase3Target, createLocalPhase3TargetRevisionIssuer,
} = require('../backend/phase3TargetRevision');
const {
  normalizeLocalPhase3SelectedKey, normalizePhase3SelectedKey,
} = require('../backend/lib/phase3Identity');

const EMAIL = 'local-recovery@example.test';

function record(extra = {}) {
  return { email: EMAIL, phone: '+1 (234) 567', password: 'fixture-password', status: 'oauth_done', ...extra };
}

function fixture(t, records = [record()], script = '') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-panel-local-recovery-'));
  fs.mkdirSync(path.join(root, 'tokens'), { mode: 0o700 });
  fs.mkdirSync(path.join(root, 'use_token'), { mode: 0o700 });
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify(records), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), script, { mode: 0o600 });
  const previous = {};
  for (const [key, value] of Object.entries({
    GPT_REGISTER_ROOT: root, GPT_REGISTER_NODE_PATH: process.execPath, PANEL_PHASE3_ENABLED: '1',
  })) {
    previous[key] = process.env[key];
    process.env[key] = value;
  }
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  return root;
}

function localRequest(account = listLocalPhase3Targets().accounts[0], extra = {}) {
  return { originalIndex: 0, sourceMode: 'username', selectedKey: account.selectedKey,
    email: account.email, phone: account.phone || '', phase3TargetRevision: account.phase3TargetRevision,
    ...extra };
}

function boundTarget(request = localRequest()) {
  const resolved = resolvePhase3Requests([request]);
  assert.deepEqual(resolved.rejected, []);
  assert.equal(resolved.eligible.length, 1);
  return resolved.eligible[0];
}

function workerArgs(target, extra = {}) {
  return { ...target, executionBinding: target.executionBinding, requireExecutionBinding: true,
    db: { async startMutationJob() {}, async audit() {} }, jobId: 'local-recovery-fixture',
    logger: { checkpoint() { return true; }, info() {}, warn() {}, error() {} }, ...extra };
}

function tokenScript(outputs = [{ filename: 'recovered.json', account: 'recovered-account', user: 'recovered-user' }], extra = '') {
  return [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `if (!process.argv.includes('--email=${EMAIL}') || process.argv.some((arg) => arg.startsWith('--phone='))) throw new Error('wrong selection mode');`,
    `for (const output of ${JSON.stringify(outputs)}) {`,
    " const token = { email: " + JSON.stringify(EMAIL) + ", access_token: 'fixture-access-' + output.filename,",
    "  refresh_token: 'fixture-refresh', expires_at: new Date(Date.now() + 3600000).toISOString(),",
    '  chatgpt_account_id: output.account, chatgpt_user_id: output.user };',
    " fs.writeFileSync(path.join(process.cwd(), 'tokens', output.filename), JSON.stringify(token), { mode: 0o600 });",
    '}', extra,
  ].join('\n');
}

test('local Phase3 selection and revision namespace cannot authorize a token target', () => {
  assert.equal(normalizeLocalPhase3SelectedKey('username:0'), 'username:0');
  for (const value of ['username:00', 'username:-1', 'username:9007199254740992', 'username:1 ', 'token:tokens:tokens/a.json']) {
    assert.equal(normalizeLocalPhase3SelectedKey(value), null);
  }
  assert.equal(normalizePhase3SelectedKey('username:0'), null);
  const issuer = createLocalPhase3TargetRevisionIssuer(Buffer.alloc(32, 3));
  const evidence = { usernameContentHash: 'a'.repeat(64),
    username: { index: 0, email: EMAIL, phone: '', status: 'oauth_done', hasPassword: true } };
  const revision = issuer.issue(evidence);
  assert.match(revision, /^phase3-local-v1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(issuer.matches(revision, evidence), true);
  assert.equal(issuer.matches(revision, { ...evidence, usernameContentHash: 'b'.repeat(64) }), false);
  assert.equal(issuer.matches(revision, { ...evidence, username: { ...evidence.username, index: 1 } }), false);
  assert.equal(issuer.matches(revision.replace('local', 'target'), evidence), false);
  assert.equal(canonicalLocalPhase3Target({ ...evidence,
    username: { ...evidence.username, email: '', phone: '123' } }), null);
});

test('local Phase3 lists credentials without token and never serializes secret or digest fields', (t) => {
  fixture(t);
  const listing = listLocalPhase3Targets();
  assert.deepEqual(listing.summary, { total: 1, eligible: 1, ineligible: 0 });
  assert.equal(listing.accounts[0].selectedKey, 'username:0');
  const target = boundTarget();
  assert.equal(target.executionBinding.version, 2);
  assert.equal(target.executionBinding.sourceMode, 'username');
  assert.equal(Object.hasOwn(target.executionBinding, 'token'), false);
  for (const data of [listing, target]) {
    const serialized = JSON.stringify(data);
    for (const marker of ['fixture-password', 'executionBinding', 'contentHash', 'passwordDigest']) {
      assert.equal(serialized.includes(marker), false);
    }
  }
});

test('local Phase3 refuses duplicate identities including incomplete and disabled rows', (t) => {
  fixture(t, [
    record(), record({ password: undefined, phone: '999' }),
    record({ email: 'phone-duplicate@example.test', phone: '1234567' }),
    record({ email: 'terminal@example.test', phone: null, status: 'account_deleted' }),
    record({ email: 'password-missing@example.test', phone: null, password: '' }),
    record({ email: 'discard@example.test', phone: null, phase3Disposition: ' DISCARD ' }),
    record({ email: 'disabled@example.test', phone: null, disabled: true }),
  ]);
  const listing = listLocalPhase3Targets();
  assert.equal(listing.summary.eligible, 0);
  assert.deepEqual(listing.accounts.map((item) => item.reason), [
    'phase3_account_ambiguous', 'phase3_account_ambiguous', 'phase3_account_ambiguous',
    'phase3_account_terminal', 'phase3_password_missing', 'phase3_account_terminal', 'phase3_account_terminal',
  ]);
  assert.equal(listing.accounts.every((item) => item.phase3TargetRevision === null), true);
});

test('local Phase3 listing rejects malformed or incomplete source ledgers as a whole', (t) => {
  const root = fixture(t);
  for (const invalid of [
    record({ email: '' }), record({ password: 'bad\nvalue' }),
    record({ phone: 'abc' }), record({ status: { invalid: true } }), null,
  ]) {
    fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([invalid]));
    assert.throws(() => listLocalPhase3Targets(),
      (error) => error.code === 'GPT_REGISTER_USERNAME_INVALID');
  }
});

test('local Phase3 admission rejects forged, stale, cross-mode, and mismatched selections', (t) => {
  const root = fixture(t);
  const request = localRequest();
  for (const extra of [
    { phase3TargetRevision: 'phase3-local-v1.' + 'A'.repeat(43) },
    { phase3TargetRevision: request.phase3TargetRevision.replace('local', 'target') },
    { selectedKey: 'username:9' }, { email: 'other@example.test' },
    { sourceMode: undefined }, { sourceMode: 'token' }, { sourceMode: 'invalid' },
  ]) {
    const result = resolvePhase3Requests([{ ...request, ...extra }]);
    assert.equal(result.eligible.length, 0);
    assert.equal(result.rejected.length, 1);
  }
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([record({ password: 'different-fixture' })]));
  assert.equal(resolvePhase3Requests([request]).rejected[0].error, 'phase3_target_revision_changed');
});

test('local Phase3 cannot borrow a historical token as execution authority', (t) => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, 'tokens', 'old_codex-fixture.json'), JSON.stringify({
    email: EMAIL, access_token: 'historical-fixture', chatgpt_account_id: 'historical-account',
  }), { mode: 0o600 });
  const request = localRequest();
  const target = boundTarget(request);
  assert.equal(Object.hasOwn(target.executionBinding, 'token'), false);
  assert.equal(resolvePhase3Requests([{ ...request, sourceMode: undefined,
    selectedKey: 'token:tokens:tokens/old_codex-fixture.json' }]).eligible.length, 0);
});

test('local Phase3 executes without active tokens and chooses email when phone formatting differs', async (t) => {
  const root = fixture(t, [record()], tokenScript());
  const events = [];
  const result = await runPhase3Job(workerArgs(boundTarget(), {
    logger: { checkpoint() { return true; },
      info(event, fields) { events.push({ event, fields }); }, warn() {}, error() {} },
  }));
  assert.equal(result.email, EMAIL);
  assert.equal(result.tokenFile, 'tokens/recovered.json');
  assert.equal(fs.existsSync(path.join(root, result.tokenFile)), true);
  for (const event of ['phase3.queued', 'phase3.started', 'phase3.account_resolved', 'phase3.completed']) {
    assert.equal(events.find((item) => item.event === event)?.fields.sourceMode, 'username');
  }
});

test('local Phase3 queued credentials and duplicate additions are revalidated before spawn', async (t) => {
  const root = fixture(t, [record()], tokenScript());
  const target = boundTarget();
  const usernamePath = path.join(root, 'username.json');
  for (const records of [
    [record({ password: 'changed-fixture' })],
    [record(), record({ password: undefined, phone: '999' })],
    [record({ status: 'account_disabled' })],
  ]) {
    fs.writeFileSync(usernamePath, JSON.stringify(records));
    await assert.rejects(runPhase3Job(workerArgs(target)),
      (error) => error.code === 'PHASE3_USERNAME_BINDING_CHANGED');
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'recovered.json')), false);
  }
});

test('local Phase3 worker refuses unsigned, relabeled, or cross-mode bindings before spawn', async (t) => {
  const root = fixture(t, [record()], tokenScript());
  const target = boundTarget();
  for (const extra of [
    { executionBinding: null, requireExecutionBinding: false },
    { executionBinding: { ...target.executionBinding, proof: 'a'.repeat(64) } },
    { executionBinding: { ...target.executionBinding, selectedKey: 'username:1' } },
    { sourceMode: 'token' },
    { executionBinding: { version: 1, username: target.executionBinding.username } },
  ]) {
    await assert.rejects(runPhase3Job(workerArgs(target, extra)),
      (error) => error.code === 'PHASE3_EXECUTION_BINDING_INVALID');
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'recovered.json')), false);
  }
});

test('local Phase3 requires strong, mutually consistent output identities', async (t) => {
  const root = fixture(t);
  for (const outputs of [
    [{ filename: 'weak.json' }],
    [{ filename: 'first.json', account: 'first' }, { filename: 'second.json', account: 'second' }],
  ]) {
    fs.writeFileSync(path.join(root, 'index.js'), tokenScript(outputs));
    await assert.rejects(runPhase3Job(workerArgs(boundTarget())),
      (error) => error.code === 'PHASE3_TOKEN_IDENTITY_MISMATCH'
        && error.requiresReconciliation === true && error.doNotRetry === true);
    for (const output of outputs) fs.unlinkSync(path.join(root, 'tokens', output.filename));
  }
});

test('local Phase3 excludes existing active tokens and rejects tokens created while queued', async (t) => {
  const root = fixture(t, [record()], tokenScript());
  const target = boundTarget();
  fs.writeFileSync(path.join(root, 'tokens', 'recovered.json'), JSON.stringify({
    email: EMAIL, access_token: 'old-weak-fixture',
  }), { mode: 0o600 });
  const listing = listLocalPhase3Targets();
  assert.equal(listing.accounts[0].eligible, false);
  assert.equal(listing.accounts[0].reason, 'phase3_source_present');
  assert.equal(resolvePhase3Requests([localRequest(listing.accounts[0])]).rejected[0].error,
    'phase3_source_present');
  await assert.rejects(runPhase3Job(workerArgs(target)),
    (error) => error.code === 'PHASE3_USERNAME_BINDING_CHANGED');
});

test('local Phase3 refuses a child rewrite of historical credentials even for the same email', async (t) => {
  const root = fixture(t, [record()], tokenScript([
    { filename: 'recovered.json', account: 'recovered-account' },
    { filename: 'old_codex-fixture.json', account: 'recovered-account' },
  ]));
  fs.writeFileSync(path.join(root, 'tokens', 'old_codex-fixture.json'), JSON.stringify({
    email: EMAIL, access_token: 'old-weak-fixture',
  }), { mode: 0o600 });
  await assert.rejects(runPhase3Job(workerArgs(boundTarget())),
    (error) => error.code === 'PHASE3_TOKEN_SCOPE_VIOLATION' && error.requiresReconciliation === true);
});

test('local Phase3 keeps password resets unresolved without a reviewed original strong identity', async (t) => {
  const reset = [
    "const file = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(file, 'utf8'));",
    "records[0].password = 'changed-fixture';",
    "fs.writeFileSync(file, JSON.stringify(records));",
  ].join('\n');
  fixture(t, [record()], tokenScript(undefined, reset));
  await assert.rejects(runPhase3Job(workerArgs(boundTarget())),
    (error) => error.requiresReconciliation === true
      && error.reconciliationReason === 'phase3_password_reset_unconfirmed');
});

test('local Phase3 preserves terminal disposition persistence and prevents subsequent recovery', async (t) => {
  const script = [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const file = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(file, 'utf8'));",
    "records[0].status = 'account_deactivated';",
    "records[0].phase3Disposition = 'discard';",
    'records[0].phase3LastAttemptAt = new Date().toISOString();',
    "records[0].phase3LastErrorCode = 'ACCOUNT_DEACTIVATED';",
    'records[0].phase3Retryable = false;',
    "fs.writeFileSync(file, JSON.stringify(records));",
    'process.exitCode = 1;',
  ].join('\n');
  const root = fixture(t, [record()], script);
  await assert.rejects(runPhase3Job(workerArgs(boundTarget())),
    (error) => error.code === 'ACCOUNT_DEACTIVATED' && error.dispositionPersisted === true);
  const stored = JSON.parse(fs.readFileSync(path.join(root, 'username.json'), 'utf8'))[0];
  assert.equal(stored.status, 'account_deleted');
  assert.equal(stored.phase3Disposition, 'discard');
  assert.equal(listLocalPhase3Targets().accounts[0].reason, 'phase3_account_terminal');
});

test('local Phase3 jobs remain serial and bind individual rows across preceding ledger updates', async (t) => {
  const secondEmail = 'second-recovery@example.test';
  const script = [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const email = process.argv.find((arg) => arg.startsWith('--email=')).slice(8);",
    "const orderPath = path.join(process.cwd(), 'order.txt');",
    "fs.appendFileSync(orderPath, email + ':start\\n');",
    'setTimeout(() => {',
    " const file = path.join(process.cwd(), 'username.json');",
    " const records = JSON.parse(fs.readFileSync(file, 'utf8'));",
    ' const record = records.find((item) => item.email === email);',
    ' record.phase3LastAttemptAt = new Date().toISOString();',
    " fs.writeFileSync(file, JSON.stringify(records));",
    " fs.writeFileSync(path.join(process.cwd(), 'tokens', email.split('@')[0] + '.json'), JSON.stringify({",
    "  email, access_token: 'fixture-' + email, chatgpt_account_id: 'account-' + email,",
    " }), { mode: 0o600 });",
    " fs.appendFileSync(orderPath, email + ':end\\n');",
    '}, 25);',
  ].join('\n');
  const root = fixture(t, [record(), record({ email: secondEmail, phone: '7654321' })], script);
  const targets = resolvePhase3Requests(listLocalPhase3Targets().accounts.map((account, index) => (
    localRequest(account, { originalIndex: index })
  )));
  assert.deepEqual(targets.rejected, []);
  const first = runPhase3Job(workerArgs(targets.eligible[0], { jobId: 'local-queue-first' }));
  await assert.rejects(runPhase3Job(workerArgs(targets.eligible[0])),
    (error) => error.code === 'PHASE3_DUPLICATE');
  const second = runPhase3Job(workerArgs(targets.eligible[1], { jobId: 'local-queue-second' }));
  const completed = await Promise.all([first, second]);
  assert.equal(completed.length, 2);
  assert.deepEqual(fs.readFileSync(path.join(root, 'order.txt'), 'utf8').trim().split('\n'), [
    EMAIL + ':start', EMAIL + ':end', secondEmail + ':start', secondEmail + ':end',
  ]);
});
