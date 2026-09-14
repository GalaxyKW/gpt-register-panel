const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { PanelDb } = require('../backend/db');
const {
  buildImportPlan,
  buildImportPlanIntentVersion,
  buildOAuthUpdatePayload,
  buildCodexSessionDocument,
  buildCodexImportIdempotencyKey,
  collectCandidates,
  executeImport: executeImportWithAuditCheckpoint,
  executeImportPlanItem: executeImportPlanItemWithAuditCheckpoint,
  importPlanSummary,
  buildSnapshot,
  confirmedSub2ApiRead,
  snapshotVersion,
  importPlanIntentVersionsEqual,
  resolveGroupIds,
  resolveImportGroupBinding,
  writeBackup,
  assertBackupCoversUpdateTargets,
} = require('../backend/sync');
const {
  PHASE3_TERMINATION_MAX_TOTAL_MS,
  canonicalPhase3Keys,
  classifyPhase3ProcessError,
  comparePhase3TokenFreshness,
  findUsernameEntry,
  phase3TerminationBudget,
  resolvePhase3Requests,
  sanitizeLog,
  runCommand,
  runPhase3Job,
  getActivePhase3Job,
} = require('../backend/phase3Worker');
const { getAccountAvailability } = require('../backend/accountAvailability');
const { buildDiff, toSafeDiff, identitiesCompatible } = require('../backend/diff');
const { Sub2ApiAdminClient } = require('../backend/adapters/sub2apiAdmin');
const { tokenFingerprint } = require('../backend/lib/token');
const { withControlPlaneLock } = require('../backend/taskCoordinator');

const successfulCheckpointLogger = Object.freeze({
  checkpoint() { return true; },
});

function executeImport(options = {}) {
  return executeImportWithAuditCheckpoint({
    logger: successfulCheckpointLogger,
    ...options,
  });
}

function executeImportPlanItem(options = {}) {
  return executeImportPlanItemWithAuditCheckpoint({
    logger: successfulCheckpointLogger,
    ...options,
  });
}

function importPlanIntentForSnapshot(snapshot, selectedKeys, groupBinding = null) {
  const plan = buildImportPlan(
    snapshot._internal.sources,
    snapshot._internal.accounts,
    selectedKeys,
  );
  return buildImportPlanIntentVersion(snapshot.version, selectedKeys, plan, groupBinding);
}

function processIsRunning(pid) {
  if (process.platform !== 'linux' || !Number.isSafeInteger(pid) || pid <= 1) return false;
  try {
    const stat = fs.readFileSync('/proc/' + String(pid) + '/stat', 'utf8');
    const commandEnd = stat.lastIndexOf(')');
    const state = commandEnd < 0 ? '' : stat.slice(commandEnd + 2).trim().split(/\s+/)[0];
    return !['Z', 'X'].includes(state);
  } catch {
    return false;
  }
}

function killTestProcess(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) return;
  try { process.kill(pid, 'SIGKILL'); } catch {}
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-m2-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  const access = ['header', Buffer.from(JSON.stringify({
    sub: 'u-1',
    email: 'one@example.test',
    'https://api.openai.com/auth': { chatgpt_account_id: 'a-1', chatgpt_user_id: 'u-1' },
  })).toString('base64url'), 'signature'].join('.');
  fs.writeFileSync(path.join(root, 'tokens', 'one.json'), JSON.stringify({
    access_token: access,
    refresh_token: 'refresh-one',
    email: 'one@example.test',
  }));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'one@example.test', password: 'hidden', createdAt: '2026-08-11T01:00:00.000Z' },
  ]));
  return { root, access };
}

test('import plan assigns five-digit free names and never exposes raw token', () => {
  const { root, access } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const plan = buildImportPlan(sources, [{
    id: 1,
    name: 'free00129',
    identityKeys: ['email:existing@example.test'],
    tokenFingerprints: {},
  }]);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].accountName, 'free00130');
  assert.equal(plan[0].action, 'create');
  const safe = importPlanSummary(plan);
  assert.equal(JSON.stringify(safe).includes(access), false);
  assert.equal(safe.items[0].fingerprints.access.length, 16);
});

test('five-digit free name capacity fails closed instead of emitting a sixth digit', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const plan = buildImportPlan(sources, [{
    id: 99999,
    name: 'free99999',
    identityKeys: ['user:other-user'],
    tokenFingerprints: {},
  }]);
  assert.equal(plan[0].action, 'conflict');
  assert.equal(plan[0].reason, 'free_name_exhausted');
  assert.equal(plan[0].accountName, null);
});

test('noncanonical free-like names neither consume numbering capacity nor hide casefold collisions', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const unrelated = (id, name) => ({
    id,
    name,
    identityKeys: ['user:unrelated-' + String(id)],
    tokenFingerprints: {},
  });
  const ignored = [
    unrelated(1, 'free100000'),
    unrelated(2, 'free000001'),
    unrelated(3, 'FREE99999'),
    unrelated(4, ' free99998 '),
  ];
  const plan = buildImportPlan(sources, ignored);
  assert.equal(plan[0].action, 'create');
  assert.equal(plan[0].accountName, 'free00001');

  for (const occupiedName of ['FREE00001', ' free00001 ']) {
    const conflict = buildImportPlan(sources, [unrelated(5, occupiedName)])[0];
    assert.equal(conflict.action, 'conflict');
    assert.equal(conflict.reason, 'free_name_conflict');
    assert.equal(conflict.accountName, 'free00001');
  }
});

test('import plan ignores historical old_codex backups', () => {
  const { root } = fixture();
  fs.renameSync(
    path.join(root, 'tokens', 'one.json'),
    path.join(root, 'tokens', 'old_codex-one.json'),
  );
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const plan = buildImportPlan(sources, []);
  assert.equal(plan.length, 0);
});

test('snapshot CAS distinguishes omitted, failed, and confirmed-empty remote reads', () => {
  const base = {
    sources: {
      tokens: [],
      usernameContentHash: null,
      usernameMtimeMs: 0,
      usernameSize: 0,
    },
    accounts: [],
  };
  const omitted = snapshotVersion({ ...base, sub2apiRead: false, apiError: null });
  const failed = snapshotVersion({ ...base, sub2apiRead: false, apiError: 'redacted failure' });
  const confirmedEmpty = snapshotVersion({ ...base, sub2apiRead: true, apiError: null });
  assert.equal(new Set([omitted, failed, confirmedEmpty]).size, 3);
  assert.equal(confirmedSub2ApiRead({ ...base, sub2apiRead: false, apiError: null }), false);
  assert.equal(confirmedSub2ApiRead({ ...base, sub2apiRead: false, apiError: 'redacted failure' }), false);
  assert.equal(confirmedSub2ApiRead({ ...base, sub2apiRead: true, apiError: null }), true);
  assert.equal(confirmedSub2ApiRead({
    _internal: { ...base, sub2apiRead: true, apiError: null },
    sub2api: { apiError: 'inconsistent public failure' },
  }), false);

  const account = {
    id: 1,
    tokenFingerprints: { access: 'same-fingerprint', refresh: null },
    credentialPresence: { access: 'present', refresh: 'unknown', id: 'unknown' },
  };
  const unknownPresence = snapshotVersion({ ...base, accounts: [account] });
  const absentPresence = snapshotVersion({
    ...base,
    accounts: [{
      ...account,
      credentialPresence: { ...account.credentialPresence, refresh: 'absent' },
    }],
  });
  assert.notEqual(unknownPresence, absentPresence);
});

test('snapshot distinguishes unavailable Sub2API reads from a confirmed empty account list', async () => {
  const { root } = fixture();
  const omitted = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
    rootDirectory: root,
    readSub2Api: false,
  });
  assert.equal(omitted.sub2api.readStatus, 'omitted');
  assert.equal(omitted.sub2api.accountCount, null);
  assert.equal(omitted.diff.comparisonStatus, 'unavailable');
  assert.equal(omitted.rows[0].diffKind, 'remote_unknown');
  assert.equal(omitted.rows[0].availability, 'unknown');
  assert.equal(omitted.rows[0].availabilityReason, 'sub2api_not_read');
  assert.equal(omitted.rows[0].status, '未知');

  const failed = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
    rootDirectory: root,
    readSub2Api: true,
    client: {
      async listAccounts() { throw new Error('simulated remote failure'); },
    },
  });
  assert.equal(failed.sub2api.readStatus, 'failed');
  assert.equal(failed.sub2api.accountCount, null);
  assert.equal(failed.diff.comparisonStatus, 'unavailable');
  assert.equal(failed.rows[0].diffKind, 'remote_unknown');
  assert.equal(failed.rows[0].availability, 'unknown');
  assert.equal(failed.rows[0].availabilityReason, 'sub2api_read_failed');
  assert.equal(failed.diff.counts.token_only, undefined);
  assert.equal(failed.rows.some((row) => row.availability === 'not_present'), false);

  const confirmedEmpty = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
    rootDirectory: root,
    readSub2Api: true,
    client: {
      async listAccounts() { return []; },
    },
  });
  assert.equal(confirmedEmpty.sub2api.readStatus, 'ok');
  assert.equal(confirmedEmpty.sub2api.accountCount, 0);
  assert.equal(confirmedEmpty.diff.comparisonStatus, 'complete');
  assert.equal(confirmedEmpty.rows[0].diffKind, 'token_only');
  assert.equal(confirmedEmpty.rows[0].availability, 'not_present');
  assert.equal(confirmedEmpty.rows[0].availabilityReason, 'not_in_sub2api');
});

test('snapshot propagates shutdown cancellation instead of downgrading it to a remote read error', async () => {
  const { root } = fixture();
  const controller = new AbortController();
  await assert.rejects(
    buildSnapshot(new URLSearchParams('withSub2api=1'), {
      rootDirectory: root,
      readSub2Api: true,
      signal: controller.signal,
      client: {
        async listAccounts(options) {
          assert.equal(options.signal, controller.signal);
          assert.equal(options.requireTotal, true);
          assert.equal(options.requirePaginationMetadata, true);
          controller.abort();
          const error = new Error('stopped');
          error.code = 'JOB_INTERRUPTED';
          throw error;
        },
      },
    }),
    (error) => error.code === 'JOB_INTERRUPTED',
  );
});

test('unavailable remote comparison preserves local duplicate-token facts', () => {
  const token = {
    source: 'tokens',
    parseStatus: 'ok',
    identityKeys: ['account:workspace-1', 'user:user-1'],
    fingerprints: { access: 'fingerprint-1' },
  };
  const diff = buildDiff([
    { ...token, relativePath: 'tokens/one.json', fileName: 'one.json' },
    { ...token, relativePath: 'tokens/two.json', fileName: 'two.json' },
  ], [], { sub2apiReadStatus: 'failed' });
  assert.equal(diff.comparisonStatus, 'unavailable');
  assert.deepEqual(diff.items.map((item) => item.kind), ['duplicate_identity', 'duplicate_identity']);
  assert.equal(diff.items.every((item) => item.availability === 'unknown'), true);
  assert.equal(diff.items.every((item) => item.availabilityReason === 'sub2api_read_failed'), true);
  assert.equal(diff.items.every((item) => item.decisionAction === null), true);
  assert.equal(diff.items.every((item) => item.decisionReason === 'sub2api_read_failed'), true);
});

test('unavailable remote comparisons expose no import action', () => {
  const token = {
    source: 'tokens',
    relativePath: 'tokens/unavailable.json',
    fileName: 'unavailable.json',
    parseStatus: 'ok',
    identityKeys: ['account:unavailable-account', 'user:unavailable-user'],
    fingerprints: { access: 'fingerprint-1' },
    expiryStatus: 'missing',
  };
  for (const [readStatus, expectedReason] of [
    ['failed', 'sub2api_read_failed'],
    ['omitted', 'sub2api_not_read'],
  ]) {
    const item = buildDiff([token], [], { sub2apiReadStatus: readStatus }).items[0];
    assert.equal(item.kind, 'remote_unknown');
    assert.equal(item.observedKind, 'remote_unknown');
    assert.equal(item.decisionAction, null);
    assert.equal(item.decisionReason, expectedReason);
  }
});

test('PanelDb persists jobs and audit rows in an independent SQLite file', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const job = await db.createJob('preview', { selectedKeys: ['x'] }, 'tester');
  await db.updateJob(job.id, { status: 'succeeded', result: { count: 1 } });
  await db.audit({ jobId: job.id, actor: 'tester', action: 'preview', targetKey: 'email:x', result: 'ok' });
  assert.equal((await db.getJob(job.id)).status, 'succeeded');
  assert.equal((await db.listAudit(10)).length, 1);
  assert.equal(fs.statSync(file).mode & 0o077, 0);
  const pending = await db.createJob('token_import', { selectedKeys: ['y'] }, 'tester');
  const secondLiveDb = new PanelDb(file);
  assert.equal((await secondLiveDb.getJob(pending.id)).status, 'queued');
  await db.updateJob(pending.id, { status: 'failed', error: 'test cleanup' });
});

test('phase3 worker matches only records with a password and redacts logs', () => {
  const { root } = fixture();
  const previous = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    assert.equal(findUsernameEntry({ email: 'ONE@example.test' }).email, 'one@example.test');
    assert.deepEqual(
      canonicalPhase3Keys({ email: 'ONE@example.test' }).sort(),
      ['email:one@example.test'],
    );
    assert.throws(() => findUsernameEntry({ email: 'missing@example.test' }), /未找到/);
    assert.equal(sanitizeLog('access_token=secret refresh_token:secret2 Bearer abc.def').includes('secret'), false);
  } finally {
    if (previous === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous;
  }
});

test('phase3 username reads enforce a non-overridable hard size limit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-username-limit-'));
  const usernameFile = path.join(root, 'username.json');
  fs.writeFileSync(usernameFile, '[]\n');
  fs.truncateSync(usernameFile, 32 * 1024 * 1024 + 1);
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    maximum: process.env.GPT_REGISTER_USERNAME_MAX_BYTES,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_USERNAME_MAX_BYTES = String(Number.MAX_SAFE_INTEGER);
  try {
    assert.throws(
      () => findUsernameEntry({ email: 'bounded@example.test' }),
      (error) => error.code === 'PHASE3_USERNAME_TOO_LARGE',
    );
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.maximum === undefined) delete process.env.GPT_REGISTER_USERNAME_MAX_BYTES;
    else process.env.GPT_REGISTER_USERNAME_MAX_BYTES = previous.maximum;
  }
});

test('username record limits are shared by snapshots and Phase3 and remain hard-capped', () => {
  const {
    readGptRegisterSources,
    usernameRecordLimit,
  } = require('../backend/adapters/gptRegisterFs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-username-record-limit-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'record-limit@example.test', password: 'hidden' },
    {},
    {},
    {},
  ]));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    maximum: process.env.GPT_REGISTER_USERNAME_MAX_RECORDS,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_USERNAME_MAX_RECORDS = '3';
  try {
    assert.equal(usernameRecordLimit(Number.MAX_SAFE_INTEGER), 100_000);
    assert.throws(
      () => readGptRegisterSources({ rootDirectory: root }),
      (error) => error.code === 'GPT_REGISTER_USERNAME_RECORD_LIMIT',
    );
    assert.throws(
      () => findUsernameEntry({ email: 'record-limit@example.test' }),
      (error) => error.code === 'GPT_REGISTER_USERNAME_RECORD_LIMIT',
    );
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.maximum === undefined) delete process.env.GPT_REGISTER_USERNAME_MAX_RECORDS;
    else process.env.GPT_REGISTER_USERNAME_MAX_RECORDS = previous.maximum;
  }
});

test('phase3 jobs run serially, run the main-gated entrypoint, and reject duplicates', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'queue-one@example.test', phone: '138-0000', password: 'hidden' },
    { email: 'queue-two@example.test', password: 'hidden' },
  ]));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const email = (process.argv.find((arg) => arg.startsWith('--email=')) || '').slice(8);",
    'if (require.main === module) {',
    "  setTimeout(() => fs.writeFileSync(path.join(process.cwd(), 'tokens', 'codex-' + email + '.json'), JSON.stringify({ access_token: 'access-' + email, email })), 80);",
    '}',
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  const updates = [];
  const events = [];
  const db = {
    async startMutationJob(id) { updates.push({ id, patch: { status: 'running' } }); },
    async updateJob(id, patch) { updates.push({ id, patch }); },
    async audit() { throw new Error('simulated audit storage failure'); },
  };
  const logger = {
    checkpoint() { return true; },
    info(event, fields) { events.push({ event, fields }); },
    warn(event, fields) { events.push({ event, fields }); },
    error(event, fields) { events.push({ event, fields }); },
  };
  try {
    assert.deepEqual(
      canonicalPhase3Keys({ email: 'queue-one@example.test' }).sort(),
      ['email:queue-one@example.test', 'phone:1380000'],
    );
    const first = runPhase3Job({
      email: 'queue-one@example.test',
      db,
      jobId: 'job-one',
      logger,
      async persistSuccess(result) {
        events.push({ event: 'phase3.terminal_persisted', fields: { email: result.email } });
      },
    });
    assert.equal(getActivePhase3Job({ email: 'queue-one@example.test' }).jobId, 'job-one');
    await assert.rejects(
      runPhase3Job({ email: 'queue-one@example.test', db, jobId: 'job-duplicate', logger }),
      (error) => error.code === 'PHASE3_DUPLICATE',
    );
    await assert.rejects(
      runPhase3Job({ phone: '+1380000', db, jobId: 'job-phone-duplicate', logger }),
      (error) => error.code === 'PHASE3_DUPLICATE',
    );
    const second = runPhase3Job({
      email: 'queue-two@example.test',
      db,
      jobId: 'job-two',
      logger,
      async persistSuccess(result) {
        events.push({ event: 'phase3.terminal_persisted', fields: { email: result.email } });
      },
    });
    const [firstResult, secondResult] = await Promise.all([first, second]);
    assert.equal(firstResult.email, 'queue-one@example.test');
    assert.equal(secondResult.email, 'queue-two@example.test');
    assert.equal(getActivePhase3Job({ email: 'queue-one@example.test' }), null);
    assert.equal(getActivePhase3Job({ email: 'queue-two@example.test' }), null);
    assert.deepEqual(updates.map((item) => item.id), ['job-one', 'job-two']);
    assert.equal(events.filter((item) => item.event === 'phase3.started_after_queue').length, 2);
    assert.equal(events.filter((item) => item.event === 'phase3.audit_failed_after_success').length, 2);
    for (const email of ['queue-one@example.test', 'queue-two@example.test']) {
      const terminalIndex = events.findIndex((item) => (
        item.event === 'phase3.terminal_persisted' && item.fields.email === email
      ));
      const auditFailureIndex = events.findIndex((item) => (
        item.event === 'phase3.audit_failed_after_success' && item.fields.email === email
      ));
      assert.equal(terminalIndex >= 0 && terminalIndex < auditFailureIndex, true);
    }
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('phase3 refuses a selected token path that changes account while queued', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-token-binding-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
    email: 'bound-token@example.test',
    password: 'original-password-secret',
  }]));
  const selectedKey = 'token:tokens:tokens/bound.json';
  const tokenPath = path.join(root, 'tokens', 'bound.json');
  fs.writeFileSync(tokenPath, JSON.stringify({
    access_token: 'original-token-secret',
    email: 'bound-token@example.test',
  }));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "fs.writeFileSync(path.join(process.cwd(), 'phase3-executed'), 'yes');",
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  try {
    const snapshot = await buildSnapshot(new URLSearchParams(), {
      rootDirectory: root,
      readSub2Api: false,
    });
    const phase3TargetRevision = snapshot.rows.find((row) => row.key === selectedKey)
      ?.phase3TargetRevision;
    const resolved = resolvePhase3Requests([{
      originalIndex: 0,
      email: 'bound-token@example.test',
      phone: '',
      selectedKey,
      phase3TargetRevision,
    }]);
    assert.equal(resolved.eligible.length, 1);
    const target = resolved.eligible[0];
    assert.equal(JSON.stringify(target).includes('executionBinding'), false);
    assert.equal(JSON.stringify(target).includes('original-password-secret'), false);
    assert.equal(JSON.stringify(target).includes('original-token-secret'), false);

    fs.writeFileSync(tokenPath, JSON.stringify({
      access_token: 'replacement-token-secret',
      email: 'different-account@example.test',
    }));
    let failure = null;
    try {
      await runPhase3Job({
        ...target,
        executionBinding: target.executionBinding,
        jobId: 'phase3-token-binding-change',
        db: { async startMutationJob() {} },
      });
    } catch (error) {
      failure = error;
    }
    assert.equal(failure?.code, 'PHASE3_SOURCE_BINDING_CHANGED');
    assert.equal(fs.existsSync(path.join(root, 'phase3-executed')), false);
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('phase3 refuses a same-email username record replacement while queued', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-username-binding-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  const usernamePath = path.join(root, 'username.json');
  fs.writeFileSync(usernamePath, JSON.stringify([{
    email: 'bound-username@example.test',
    phone: '138-0000',
    password: 'original-password-secret',
  }]));
  const selectedKey = 'token:tokens:tokens/bound.json';
  fs.writeFileSync(path.join(root, 'tokens', 'bound.json'), JSON.stringify({
    access_token: 'bound-token-secret',
    email: 'bound-username@example.test',
  }));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "fs.writeFileSync(path.join(process.cwd(), 'phase3-executed'), 'yes');",
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  try {
    const snapshot = await buildSnapshot(new URLSearchParams(), {
      rootDirectory: root,
      readSub2Api: false,
    });
    const phase3TargetRevision = snapshot.rows.find((row) => row.key === selectedKey)
      ?.phase3TargetRevision;
    const resolved = resolvePhase3Requests([{
      originalIndex: 0,
      email: 'bound-username@example.test',
      phone: '1380000',
      selectedKey,
      phase3TargetRevision,
    }]);
    assert.equal(resolved.eligible.length, 1);
    const target = resolved.eligible[0];
    fs.writeFileSync(usernamePath, JSON.stringify([{
      email: 'bound-username@example.test',
      phone: '138-0000',
      password: 'replacement-password-secret',
    }]));
    let failure = null;
    try {
      await runPhase3Job({
        ...target,
        executionBinding: target.executionBinding,
        jobId: 'phase3-username-binding-change',
        db: { async startMutationJob() {} },
      });
    } catch (error) {
      failure = error;
    }
    assert.equal(failure?.code, 'PHASE3_USERNAME_BINDING_CHANGED');
    assert.equal(fs.existsSync(path.join(root, 'phase3-executed')), false);
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('phase3 admission rejects an old UI revision after same-path token or username replacement', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-ui-binding-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  const tokenPath = path.join(root, 'tokens', 'same-path.json');
  const usernamePath = path.join(root, 'username.json');
  const selectedKey = 'token:tokens:tokens/same-path.json';
  fs.writeFileSync(usernamePath, JSON.stringify([{
    email: 'ui-bound@example.test',
    phone: '13800001234',
    password: 'first-password-secret',
    status: 'oauth_done',
  }]));
  fs.writeFileSync(tokenPath, JSON.stringify({
    access_token: 'first-access-secret',
    email: 'ui-bound@example.test',
    chatgpt_account_id: 'workspace-one',
    chatgpt_user_id: 'user-one',
  }));
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    const firstSnapshot = await buildSnapshot(new URLSearchParams(), {
      rootDirectory: root,
      readSub2Api: false,
    });
    const firstRow = firstSnapshot.rows.find((row) => row.key === selectedKey);
    assert.match(firstRow?.phase3TargetRevision, /^phase3-target-v1\.[A-Za-z0-9_-]{43}$/);

    // Preserve source/path/email while replacing both the credential bytes and
    // a strong identity. The old page must not authorize this unseen token.
    fs.writeFileSync(tokenPath, JSON.stringify({
      access_token: 'replacement-access-secret',
      email: 'ui-bound@example.test',
      chatgpt_account_id: 'workspace-two',
      chatgpt_user_id: 'user-two',
    }));
    const tokenChanged = resolvePhase3Requests([{
      originalIndex: 0,
      email: 'ui-bound@example.test',
      phone: '13800001234',
      selectedKey,
      phase3TargetRevision: firstRow.phase3TargetRevision,
    }]);
    assert.equal(tokenChanged.eligible.length, 0);
    assert.equal(tokenChanged.rejected[0].error, 'phase3_target_revision_changed');

    const secondSnapshot = await buildSnapshot(new URLSearchParams(), {
      rootDirectory: root,
      readSub2Api: false,
    });
    const secondRow = secondSnapshot.rows.find((row) => row.key === selectedKey);
    fs.writeFileSync(usernamePath, JSON.stringify([{
      email: 'ui-bound@example.test',
      phone: '13800001234',
      password: 'replacement-password-secret',
      status: 'oauth_done',
    }]));
    const usernameChanged = resolvePhase3Requests([{
      originalIndex: 0,
      email: 'ui-bound@example.test',
      phone: '13800001234',
      selectedKey,
      phase3TargetRevision: secondRow.phase3TargetRevision,
    }]);
    assert.equal(usernameChanged.eligible.length, 0);
    assert.equal(usernameChanged.rejected[0].error, 'phase3_target_revision_changed');
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('phase3 resolver revalidates lossy identity and token selection input', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-input-boundary-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
    email: 'strict-input@example.test',
    phone: '138-0000',
    password: 'test-password',
    status: 'oauth_done',
  }]));
  fs.writeFileSync(path.join(root, 'tokens', 'strict.json'), JSON.stringify({
    access_token: 'test-access-value',
    email: 'strict-input@example.test',
  }));
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    const snapshot = await buildSnapshot(new URLSearchParams(), {
      rootDirectory: root,
      readSub2Api: false,
    });
    const selectedKey = 'token:tokens:tokens/strict.json';
    const revision = snapshot.rows.find((row) => row.key === selectedKey)
      ?.phase3TargetRevision;
    assert.match(revision, /^phase3-target-v1\.[A-Za-z0-9_-]{43}$/);
    for (const request of [
      {
        email: 'strict-input@example.test',
        phone: '138letters0000',
        selectedKey,
      },
      {
        email: 'strict-input@example.test',
        phone: '138-0000',
        selectedKey: selectedKey + ' ',
      },
    ]) {
      const resolved = resolvePhase3Requests([{
        originalIndex: 0,
        phase3TargetRevision: revision,
        ...request,
      }]);
      assert.equal(resolved.eligible.length, 0);
      assert.equal(resolved.rejected[0].error, 'phase3_request_invalid');
    }
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('Phase3 aborts promptly from its private queue without starting queued work', async () => {
  let markEntered;
  let releaseBlocker;
  const entered = new Promise((resolve) => { markEntered = resolve; });
  const blockerReleased = new Promise((resolve) => { releaseBlocker = resolve; });
  const blocker = withControlPlaneLock(async () => {
    markEntered();
    await blockerReleased;
  });
  await entered;

  const firstController = new AbortController();
  const secondController = new AbortController();
  const updates = [];
  const db = {
    async updateJob(id, patch) { updates.push({ id, patch }); },
  };
  const first = runPhase3Job({
    email: 'lock-wait-one@example.test',
    canonicalKeys: ['email:lock-wait-one@example.test'],
    db,
    jobId: 'phase3-lock-wait-one',
    signal: firstController.signal,
  });
  // Let the first job occupy the Phase3 queue while it waits for the global lock.
  await new Promise((resolve) => setImmediate(resolve));
  const second = runPhase3Job({
    email: 'lock-wait-two@example.test',
    canonicalKeys: ['email:lock-wait-two@example.test'],
    db,
    jobId: 'phase3-lock-wait-two',
    signal: secondController.signal,
  });

  secondController.abort();
  const outcome = await Promise.race([
    second.then(
      () => ({ resolved: true }),
      (error) => ({ error }),
    ),
    new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), 500)),
  ]);
  const secondActiveAfterAbort = getActivePhase3Job({
    email: 'lock-wait-two@example.test',
  });

  firstController.abort();
  releaseBlocker();
  await blocker;
  await Promise.allSettled([first, second]);

  assert.equal(outcome.timedOut, undefined);
  assert.equal(outcome.error?.code, 'JOB_INTERRUPTED');
  assert.equal(secondActiveAfterAbort, null);
  assert.deepEqual(updates, []);
});

test('Phase3 shutdown preserves success when a valid token was already published', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-shutdown-token-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'shutdown-token@example.test', password: 'hidden' },
  ]));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const email = (process.argv.find((arg) => arg.startsWith('--email=')) || '').slice(8);",
    "fs.writeFileSync(path.join(process.cwd(), 'tokens', 'shutdown.json'), JSON.stringify({ access_token: 'published-before-stop', email }));",
    "process.on('SIGTERM', () => {});",
    'setInterval(() => {}, 1000);',
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
    grace: process.env.PANEL_PHASE3_KILL_GRACE_MS,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  process.env.PANEL_PHASE3_KILL_GRACE_MS = '100';
  const controller = new AbortController();
  const order = [];
  try {
    const running = runPhase3Job({
      email: 'shutdown-token@example.test',
      db: {
        async startMutationJob() {},
        async updateJob() {},
        async audit() { order.push('audit'); },
      },
      jobId: 'job-shutdown-token',
      logger: successfulCheckpointLogger,
      signal: controller.signal,
      async persistSuccess() { order.push('terminal'); },
    });
    const tokenPath = path.join(root, 'tokens', 'shutdown.json');
    for (let attempt = 0; !fs.existsSync(tokenPath) && attempt < 200; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(fs.existsSync(tokenPath), true);
    controller.abort();
    const result = await running;
    assert.equal(result.interruptedAfterToken, true);
    assert.deepEqual(order, ['terminal', 'audit']);
  } finally {
    controller.abort();
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
    if (previous.grace === undefined) delete process.env.PANEL_PHASE3_KILL_GRACE_MS;
    else process.env.PANEL_PHASE3_KILL_GRACE_MS = previous.grace;
  }
});

test('Phase3 preserves a valid freshest token after a confirmed non-zero process exit', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-nonzero-token-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'nonzero-token@example.test', password: 'hidden' },
  ]));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const email = 'nonzero-token@example.test';",
    'const write = (name, document, timestamp) => {',
    "  const file = path.join(process.cwd(), 'tokens', name);",
    '  fs.writeFileSync(file, JSON.stringify({ ...document, email }));',
    '  fs.utimesSync(file, new Date(timestamp), new Date(timestamp));',
    '};',
    "write('expired.json', { access_token: 'expired', expires_at: '2020-01-01T00:00:00.000Z' }, '2099-01-01T00:00:00.000Z');",
    "write('invalid-expiry.json', { access_token: 'invalid', expires_at: 'not-a-date' }, '2099-01-02T00:00:00.000Z');",
    "write('disabled.json', { access_token: 'disabled', expires_at: '2099-01-01T00:00:00.000Z', disabled: true }, '2099-01-03T00:00:00.000Z');",
    "write('shorter.json', { access_token: 'shorter', refresh_token: 'shorter-refresh', expires_at: '2098-01-01T00:00:00.000Z', last_refresh: '2090-01-01T00:00:00.000Z' }, '2099-01-04T00:00:00.000Z');",
    "write('freshest.json', { access_token: 'freshest', refresh_token: 'freshest-refresh', expires_at: '2099-01-01T00:00:00.000Z', last_refresh: '2020-01-01T00:00:00.000Z' }, '2020-01-01T00:00:00.000Z');",
    'process.exitCode = 7;',
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  try {
    const result = await runPhase3Job({
      email: 'nonzero-token@example.test',
      jobId: 'nonzero-token-job',
      db: { async audit() {}, async startMutationJob() {}, async updateJob() {} },
      logger: successfulCheckpointLogger,
    });
    assert.equal(result.tokenFile, 'tokens/freshest.json');
    assert.equal(result.processEndedWithError, true);
    assert.equal(result.processErrorCode, 'PHASE3_PROCESS_FAILED');
    assert.equal(result.process.code, 7);
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('Phase3 requires reconciliation when postflight token sources become unavailable', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-postflight-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'postflight@example.test', password: 'hidden' },
  ]));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "fs.renameSync(path.join(process.cwd(), 'use_token'), path.join(process.cwd(), 'use_token-moved'));",
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  try {
    await assert.rejects(
      runPhase3Job({
        email: 'postflight@example.test',
        jobId: 'postflight-unknown-job',
        db: { async audit() {}, async startMutationJob() {}, async updateJob() {} },
        logger: successfulCheckpointLogger,
      }),
      (error) => error.code === 'PHASE3_TOKEN_POSTFLIGHT_UNKNOWN'
        && error.writeOutcomeUnknown === true
        && error.requiresReconciliation === true
        && error.retryAllowed === false
        && error.doNotRetry === true
        && error.reconciliationScope === 'phase3_token_output'
        && error.reconciliationReason === 'phase3_postflight_source_unavailable',
    );
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('Phase3 supervision failure remains primary when the child also records discard', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-supervision-code-'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
    email: 'supervision-discard@example.test',
    password: 'hidden',
    status: 'account_deactivated',
    phase3Disposition: 'discard',
    phase3LastErrorCode: 'ACCOUNT_DEACTIVATED',
  }]));
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    const error = new Error('process tree remains');
    error.code = 'PHASE3_TERMINATION_UNCONFIRMED';
    error.details = {
      terminationConfirmed: false,
      remainingDescendantCount: 1,
      stderr: 'untrusted child output',
    };
    classifyPhase3ProcessError(error, {
      index: 0,
      email: 'supervision-discard@example.test',
      phone: '',
    });
    assert.equal(error.code, 'PHASE3_TERMINATION_UNCONFIRMED');
    assert.equal(error.dispositionCode, 'ACCOUNT_DEACTIVATED');
    assert.equal(error.accountDisposition, 'discard');
    assert.equal(error.retryable, false);
    assert.equal(error.details.phase3.code, 'ACCOUNT_DEACTIVATED');
    assert.equal(Object.hasOwn(error.details, 'stderr'), false);
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('phase3 pins one source tree while preserving cwd, __dirname, and relative require semantics', async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-pinned-'));
  const root = path.join(parent, 'register');
  const movedRoot = root + '-moved';
  fs.mkdirSync(root, { mode: 0o700 });
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'pinned@example.test', password: 'hidden', status: 'oauth_done' },
  ]));
  fs.writeFileSync(path.join(root, 'src', 'early.js'), [
    "const fs = require('node:fs');",
    "module.exports = { value: 'early-original', directory: __dirname, ino: fs.statSync(__dirname).ino };",
  ].join('\n'));
  fs.writeFileSync(path.join(root, 'src', 'late.js'), [
    "const fs = require('node:fs');",
    "module.exports = { value: 'late-original', directory: __dirname, ino: fs.statSync(__dirname).ino };",
  ].join('\n'));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const early = require('./src/early');",
    'const pinned = process.cwd();',
    'const original = fs.realpathSync(pinned);',
    "const moved = original + '-moved';",
    'const rootBefore = fs.statSync(pinned);',
    'const dirnameBefore = fs.statSync(__dirname);',
    'fs.renameSync(original, moved);',
    'fs.mkdirSync(original, { mode: 0o700 });',
    "fs.mkdirSync(path.join(original, 'tokens'));",
    "fs.mkdirSync(path.join(original, 'use_token'));",
    "fs.mkdirSync(path.join(original, 'src'));",
    "fs.writeFileSync(path.join(original, 'username.json'), JSON.stringify([{ email: 'pinned@example.test', password: 'replacement' }]));",
    "fs.writeFileSync(path.join(original, 'tokens', 'forged.json'), JSON.stringify({ access_token: 'forged-token', email: 'pinned@example.test' }));",
    "fs.writeFileSync(path.join(original, 'src', 'late.js'), \"module.exports = { value: 'late-replacement', ino: 0 };\\n\");",
    "const late = require('./src/late');",
    'const cwdAfter = process.cwd();',
    "fs.writeFileSync(path.join(cwdAfter, 'tokens', 'real.json'), JSON.stringify({ access_token: 'real-token', email: 'pinned@example.test' }));",
    "fs.writeFileSync(path.join(cwdAfter, 'semantics.json'), JSON.stringify({",
    '  rootIno: rootBefore.ino,',
    '  dirnameIno: dirnameBefore.ino,',
    '  cwdAfterIno: fs.statSync(cwdAfter).ino,',
    '  sourceIno: fs.statSync(path.join(cwdAfter, \"src\")).ino,',
    '  early,',
    '  late,',
    '}));',
    "fs.writeSync(1, 'unlabelled-worker-secret-value\\n');",
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  const events = [];
  const logger = {
    checkpoint() { return true; },
    info(event, fields) { events.push({ event, fields }); },
    warn(event, fields) { events.push({ event, fields }); },
    error(event, fields) { events.push({ event, fields }); },
  };
  try {
    const result = await runPhase3Job({
      email: 'pinned@example.test',
      jobId: 'pinned-job',
      db: { async audit() {}, async startMutationJob() {}, async updateJob() {} },
      logger,
    });
    assert.equal(result.tokenFile, 'tokens/real.json');
    const semantics = JSON.parse(fs.readFileSync(path.join(movedRoot, 'semantics.json'), 'utf8'));
    assert.equal(semantics.dirnameIno, semantics.rootIno);
    assert.equal(semantics.cwdAfterIno, semantics.rootIno);
    assert.equal(semantics.early.value, 'early-original');
    assert.equal(semantics.late.value, 'late-original');
    assert.equal(semantics.early.ino, semantics.sourceIno);
    assert.equal(semantics.late.ino, semantics.sourceIno);
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'real.json')), false);
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'forged.json')), true);
    const persistedSurface = JSON.stringify({ result, events });
    assert.equal(persistedSurface.includes('unlabelled-worker-secret-value'), false);
    assert.equal(Object.hasOwn(result.process, 'stdout'), false);
    assert.equal(Object.hasOwn(result.process, 'stderr'), false);
    assert.equal(result.process.stdoutBytes > 0, true);
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('phase3 executes the validated index inode even when its path is replaced before launch', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-index-pin-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'index-pin@example.test', password: 'hidden' },
  ]), { mode: 0o600 });
  const originalSource = [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'if (require.main === module) {',
    "  fs.writeFileSync(path.join(process.cwd(), 'entrypoint.json'), JSON.stringify({ isMain: true, filename: __filename, dirname: __dirname }));",
    "  fs.writeFileSync(path.join(process.cwd(), 'tokens', 'original.json'), JSON.stringify({ access_token: 'descriptor-bound-token', email: 'index-pin@example.test' }));",
    '}',
  ].join('\n');
  const replacementSource = [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "fs.writeFileSync(path.join(process.cwd(), 'tokens', 'replacement.json'), JSON.stringify({ access_token: 'replacement-token', email: 'index-pin@example.test' }));",
  ].join('\n');
  fs.writeFileSync(path.join(root, 'index.js'), originalSource, { mode: 0o600 });

  // The wrapper runs only after phase3Worker has opened and validated index.js.
  // It replaces that path, then forwards the already inherited script, Node
  // and root fds to the real Node launcher to make the race deterministic.
  const nodeWrapper = path.join(root, 'node-wrapper');
  fs.writeFileSync(nodeWrapper, [
    '#!' + process.execPath,
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const { spawnSync } = require('node:child_process');",
    "const script = path.join(process.cwd(), 'index.js');",
    "fs.renameSync(script, script + '.validated');",
    `fs.writeFileSync(script, ${JSON.stringify(replacementSource)}, { mode: 0o600 });`,
    'const result = spawnSync(process.execPath, process.argv.slice(2), {',
    '  cwd: process.cwd(),',
    '  env: process.env,',
    "  stdio: ['ignore', 'inherit', 'inherit', 3, 4, 5],",
    '});',
    'if (result.error) throw result.error;',
    'process.exit(result.status === null ? 1 : result.status);',
  ].join('\n'), { mode: 0o700 });
  fs.chmodSync(nodeWrapper, 0o700);

  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = nodeWrapper;
  process.env.PANEL_PHASE3_ENABLED = '1';
  try {
    const result = await runPhase3Job({
      email: 'index-pin@example.test',
      jobId: 'index-pin-job',
      db: { async audit() {}, async startMutationJob() {}, async updateJob() {} },
      logger: successfulCheckpointLogger,
    });
    assert.equal(result.tokenFile, 'tokens/original.json');
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'replacement.json')), false);
    assert.equal(fs.readFileSync(path.join(root, 'index.js'), 'utf8'), replacementSource);
    assert.equal(fs.readFileSync(path.join(root, 'index.js.validated'), 'utf8'), originalSource);
    const entrypoint = JSON.parse(fs.readFileSync(path.join(root, 'entrypoint.json'), 'utf8'));
    assert.equal(entrypoint.isMain, true);
    assert.equal(entrypoint.filename, '/proc/self/fd/5/index.js');
    assert.equal(entrypoint.dirname, path.dirname(entrypoint.filename));
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('gpt_register snapshots reject group/world-writable roots, directories, and JSON files', () => {
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const makeRoot = () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-untrusted-source-'));
    fs.mkdirSync(path.join(root, 'tokens'));
    fs.mkdirSync(path.join(root, 'use_token'));
    fs.writeFileSync(path.join(root, 'username.json'), '[]\n', { mode: 0o600 });
    fs.writeFileSync(path.join(root, 'tokens', 'one.json'), JSON.stringify({
      access_token: 'opaque-test-token',
      email: 'permissions@example.test',
    }), { mode: 0o600 });
    return root;
  };
  for (const mutate of [
    (root) => fs.chmodSync(root, 0o777),
    (root) => fs.chmodSync(path.join(root, 'tokens'), 0o777),
    (root) => fs.chmodSync(path.join(root, 'username.json'), 0o666),
    (root) => fs.chmodSync(path.join(root, 'tokens', 'one.json'), 0o666),
  ]) {
    const root = makeRoot();
    mutate(root);
    assert.throws(
      () => readGptRegisterSources({ rootDirectory: root }),
      (error) => error.code === 'GPT_REGISTER_PATH_PERMISSIONS_INVALID',
    );
  }
});

test('phase3 refuses writable index.js and node executables before spawning', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-path-mode-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'mode@example.test', password: 'hidden' },
  ]), { mode: 0o600 });
  const marker = path.join(root, 'spawned');
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    `fs.writeFileSync(${JSON.stringify(marker)}, 'spawned');`,
  ].join('\n'), { mode: 0o666 });
  fs.chmodSync(path.join(root, 'index.js'), 0o666);
  const fakeNode = path.join(root, 'fake-node');
  fs.writeFileSync(fakeNode, '#!/bin/sh\nexit 1\n', { mode: 0o777 });
  fs.chmodSync(fakeNode, 0o777);
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  const run = () => runPhase3Job({
    email: 'mode@example.test',
    db: { async audit() {}, async updateJob() {} },
  });
  try {
    await assert.rejects(run(), (error) => error.code === 'PHASE3_PATH_PERMISSIONS_INVALID');
    assert.equal(fs.existsSync(marker), false);
    fs.chmodSync(path.join(root, 'index.js'), 0o600);
    process.env.GPT_REGISTER_NODE_PATH = fakeNode;
    await assert.rejects(run(), (error) => error.code === 'PHASE3_PATH_PERMISSIONS_INVALID');
    assert.equal(fs.existsSync(marker), false);
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('phase3 termination budgets leave a fixed reconciliation window before server shutdown', () => {
  const maximum = phase3TerminationBudget({
    terminationGraceMs: Number.MAX_SAFE_INTEGER,
    terminationHardDeadlineMs: Number.MAX_SAFE_INTEGER,
  });
  assert.equal(maximum.totalMs, PHASE3_TERMINATION_MAX_TOTAL_MS);
  assert.equal(maximum.totalMs, 5000);
  assert.equal(maximum.totalMs < 10_000, true);

  const minimum = phase3TerminationBudget({
    terminationGraceMs: 1,
    terminationHardDeadlineMs: 1,
  });
  assert.deepEqual(minimum, { graceMs: 100, finalWaitMs: 100, totalMs: 200 });
});

test('phase3 cleans a same-group helper before reporting successful command completion', async () => {
  let keeperPid = null;
  try {
    const result = await runCommand('/bin/sh', ['-c', [
      "(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &",
      'echo keeper_pid=$!',
      'exit 0',
    ].join('\n')], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 5000,
      terminationGraceMs: 100,
      terminationHardDeadlineMs: 100,
      maxOutputBytes: 4096,
    });
    keeperPid = Number(result.stdout.match(/keeper_pid=(\d+)/)?.[1]);
    assert.equal(Number.isSafeInteger(keeperPid) && keeperPid > 1, true);
    assert.equal(result.code, 0);
    assert.equal(result.observedSignal, null);
    assert.equal(result.requestedSignal, 'SIGKILL');
    assert.equal(result.terminationConfirmed, true);
    assert.equal(result.remainingDescendantCount, 0);
    assert.equal(processIsRunning(keeperPid), false);
  } finally {
    if (processIsRunning(keeperPid)) killTestProcess(keeperPid);
  }
});

test('phase3 starts cleanup at leader exit when a helper keeps inherited output pipes open', async () => {
  let keeperPid = null;
  const startedAt = Date.now();
  try {
    const result = await runCommand('/bin/sh', ['-c', [
      "(trap '' TERM; exec /bin/sleep 30) &",
      'echo keeper_pid=$!',
      'exit 0',
    ].join('\n')], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 10_000,
      terminationGraceMs: 100,
      terminationHardDeadlineMs: 100,
      maxOutputBytes: 4096,
    });
    keeperPid = Number(result.stdout.match(/keeper_pid=(\d+)/)?.[1]);
    assert.equal(Number.isSafeInteger(keeperPid) && keeperPid > 1, true);
    assert.equal(result.code, 0);
    assert.equal(result.terminationConfirmed, true);
    assert.equal(result.remainingDescendantCount, 0);
    assert.equal(processIsRunning(keeperPid), false);
    assert.equal(Date.now() - startedAt < 3000, true);
  } finally {
    if (processIsRunning(keeperPid)) killTestProcess(keeperPid);
  }
});

test('phase3 cleans a same-group helper before reporting a nonzero command exit', async () => {
  let keeperPid = null;
  try {
    let failure;
    try {
      await runCommand('/bin/sh', ['-c', [
        "(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &",
        'echo keeper_pid=$!',
        'exit 7',
      ].join('\n')], {
        cwd: os.tmpdir(),
        env: { PATH: process.env.PATH || '' },
        timeoutMs: 5000,
        terminationGraceMs: 100,
        terminationHardDeadlineMs: 100,
        maxOutputBytes: 4096,
      });
      assert.fail('runCommand should reject a nonzero exit');
    } catch (error) {
      failure = error;
    }
    keeperPid = Number(failure?.details?.stdout?.match(/keeper_pid=(\d+)/)?.[1]);
    assert.equal(Number.isSafeInteger(keeperPid) && keeperPid > 1, true);
    assert.equal(failure?.details?.code, 7);
    assert.equal(failure?.details?.terminationConfirmed, true);
    assert.equal(failure?.details?.remainingDescendantCount, 0);
    assert.equal(processIsRunning(keeperPid), false);
  } finally {
    if (processIsRunning(keeperPid)) killTestProcess(keeperPid);
  }
});

test('phase3 supervision marker catches a fast setsid helper before successful completion', async () => {
  let keeperPid = null;
  try {
    const result = await runCommand('/bin/sh', ['-c', [
      "(/usr/bin/setsid /bin/sh -c \"trap '' TERM; exec /bin/sleep 30\") </dev/null >/dev/null 2>&1 &",
      'echo keeper_pid=$!',
      'exit 0',
    ].join('\n')], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 5000,
      terminationGraceMs: 100,
      terminationHardDeadlineMs: 100,
      maxOutputBytes: 4096,
    });
    keeperPid = Number(result.stdout.match(/keeper_pid=(\d+)/)?.[1]);
    assert.equal(Number.isSafeInteger(keeperPid) && keeperPid > 1, true);
    assert.equal(result.terminationConfirmed, true);
    assert.equal(result.remainingDescendantCount, 0);
    assert.equal(processIsRunning(keeperPid), false);
  } finally {
    if (processIsRunning(keeperPid)) killTestProcess(keeperPid);
  }
});

test('phase3 supervision marker is never exposed through captured process output', async () => {
  const result = await runCommand('/bin/sh', ['-c', 'printf %s "$GPT_REGISTER_PANEL_SUPERVISION_ID"'], {
    cwd: os.tmpdir(),
    env: { PATH: process.env.PATH || '' },
    timeoutMs: 5000,
    maxOutputBytes: 4096,
  });
  assert.equal(result.stdout, '[REDACTED]');
  assert.equal(/[a-f0-9]{48}/.test(result.stdout), false);
});

test('phase3 supervision never signals an unmarked process in the same cgroup', async () => {
  const unrelated = spawn('/bin/sleep', ['30'], {
    detached: true,
    env: { PATH: process.env.PATH || '' },
    stdio: 'ignore',
  });
  const unrelatedClosed = new Promise((resolve) => unrelated.once('close', resolve));
  try {
    assert.equal(Number.isSafeInteger(unrelated.pid) && unrelated.pid > 1, true);
    const result = await runCommand('/bin/sh', ['-c', [
      "(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &",
      'echo keeper_pid=$!',
      'exit 0',
    ].join('\n')], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 5000,
      terminationGraceMs: 100,
      terminationHardDeadlineMs: 100,
      maxOutputBytes: 4096,
    });
    assert.equal(result.terminationConfirmed, true);
    assert.equal(processIsRunning(unrelated.pid), true);
  } finally {
    if (processIsRunning(unrelated.pid)) killTestProcess(unrelated.pid);
    await Promise.race([
      unrelatedClosed,
      new Promise((resolve) => setTimeout(resolve, 500)),
    ]);
  }
});

test('phase3 abort cleans a reparented setsid helper before reporting interruption', async () => {
  const controller = new AbortController();
  let keeperPid = null;
  try {
    const running = runCommand('/bin/sh', ['-c', [
      '(',
      "  /usr/bin/setsid /bin/sh -c \"trap '' TERM; exec /bin/sleep 30\" </dev/null >/dev/null 2>&1 &",
      '  echo keeper_pid=$!',
      ')',
      "trap '' TERM",
      'while :; do /bin/sleep 1; done',
    ].join('\n')], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 5000,
      terminationGraceMs: 100,
      terminationHardDeadlineMs: 100,
      maxOutputBytes: 4096,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 300);
    let failure;
    try {
      await running;
      assert.fail('runCommand should reject after shutdown cancellation');
    } catch (error) {
      failure = error;
    }
    keeperPid = Number(failure?.details?.stdout?.match(/keeper_pid=(\d+)/)?.[1]);
    assert.equal(Number.isSafeInteger(keeperPid) && keeperPid > 1, true);
    assert.equal(failure?.code, 'JOB_INTERRUPTED');
    assert.equal(failure?.details?.terminationConfirmed, true);
    assert.equal(failure?.details?.remainingDescendantCount, 0);
    assert.equal(processIsRunning(keeperPid), false);
  } finally {
    controller.abort();
    if (processIsRunning(keeperPid)) killTestProcess(keeperPid);
  }
});

test('phase3 timeout waits for a SIGTERM-resistant child to be killed and closed', async () => {
  const startedAt = Date.now();
  await assert.rejects(
    runCommand(process.execPath, ['-e', [
      "process.on('SIGTERM', () => {});",
      'setInterval(() => {}, 1000);',
    ].join('\n')], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 1000,
      terminationGraceMs: 100,
      maxOutputBytes: 4096,
    }),
    (error) => error.code === 'PHASE3_TIMEOUT'
      && error.details?.requestedSignal === 'SIGKILL'
      && error.details?.observedSignal === 'SIGKILL'
      && error.details?.signal === error.details?.observedSignal
      && error.details?.terminationConfirmed === true
      && error.details?.remainingDescendantCount === 0,
  );
  const durationMs = Date.now() - startedAt;
  assert.equal(durationMs >= 1000, true);
  assert.equal(durationMs < 5000, true);

  const descendantStartedAt = Date.now();
  await assert.rejects(
    runCommand('/bin/sh', ['-c', "(trap '' TERM; while :; do /bin/sleep 1; done) & trap 'exit 0' TERM; wait"], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 1000,
      terminationGraceMs: 100,
      maxOutputBytes: 4096,
    }),
    (error) => error.code === 'PHASE3_TIMEOUT',
  );
  assert.equal(Date.now() - descendantStartedAt < 5000, true);
});

test('phase3 timeout kills an escaped detached descendant before releasing the job', async () => {
  const script = [
    '( /usr/bin/setsid /bin/sh -c "trap \'\' TERM; exec /bin/sleep 10" &',
    '  echo keeper_pid=$!;',
    '  /bin/sleep 0.3',
    ') &',
    "trap '' TERM",
    'while :; do /bin/sleep 1; done',
  ].join('\n');
  const startedAt = Date.now();
  let failure;
  try {
    await runCommand('/bin/sh', ['-c', script], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 1000,
      terminationGraceMs: 100,
      terminationHardDeadlineMs: 100,
      maxOutputBytes: 4096,
    });
    assert.fail('runCommand should reject after the timeout');
  } catch (error) {
    failure = error;
  }
  const keeperPid = Number(failure?.details?.stdout?.match(/keeper_pid=(\d+)/)?.[1]);
  assert.equal(
    Number.isSafeInteger(keeperPid) && keeperPid > 1,
    true,
    JSON.stringify(failure?.details || {}),
  );
  let keeperStillRunning = false;
  if (process.platform !== 'win32') {
    try {
      const stat = fs.readFileSync('/proc/' + String(keeperPid) + '/stat', 'utf8');
      const commandEnd = stat.lastIndexOf(')');
      const state = commandEnd < 0 ? '' : stat.slice(commandEnd + 2).trim().split(/\s+/)[0];
      keeperStillRunning = !['Z', 'X'].includes(state);
    } catch {}
  }
  if (keeperStillRunning) {
    try { process.kill(-keeperPid, 'SIGKILL'); } catch {}
    try { process.kill(keeperPid, 'SIGKILL'); } catch {}
  }
  assert.equal(keeperStillRunning, false);
  assert.equal(failure?.code, 'PHASE3_TIMEOUT');
  assert.equal(failure?.details?.signal, 'SIGKILL');
  assert.equal(failure?.details?.requestedSignal, 'SIGKILL');
  assert.equal(failure?.details?.observedSignal, 'SIGKILL');
  assert.equal(failure?.details?.terminationConfirmed, true);
  assert.equal(failure?.details?.remainingDescendantCount, 0);
  assert.equal(failure?.details?.forcedClose, false);
  assert.equal(Date.now() - startedAt >= 1000, true);
  assert.equal(Date.now() - startedAt < 3000, true);
});

test('phase3 output is continuously drained, bounded, and redacted after chunk assembly', async () => {
  const splitSecret = await runCommand('/bin/sh', ['-c', [
    "printf 'Authorization: Bea'",
    "printf 'rer boundary-secret-value'",
  ].join('; ')], {
    cwd: os.tmpdir(),
    env: { PATH: process.env.PATH || '' },
    timeoutMs: 5000,
    maxOutputBytes: 4096,
  });
  assert.equal(splitSecret.stdout.includes('boundary-secret-value'), false);
  assert.match(splitSecret.stdout, /\[redacted\]/);

  await assert.rejects(
    runCommand('/bin/sh', ['-c', "trap '' TERM; exec /usr/bin/yes x"], {
      cwd: os.tmpdir(),
      env: { PATH: process.env.PATH || '' },
      timeoutMs: 5000,
      terminationGraceMs: 100,
      maxOutputBytes: 1024,
    }),
    (error) => error.code === 'PHASE3_OUTPUT_LIMIT'
      && error.details?.signal === 'SIGKILL'
      && Buffer.byteLength(error.details.stdout) < 2048,
  );
});

test('phase3 persists a discard disposition when the account is deactivated', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-discard-'));
  const movedRoot = root + '-moved';
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'discard@example.test', password: 'hidden', status: 'oauth_done' },
  ]));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const file = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(file, 'utf8'));",
    "records[0].status = 'account_deactivated';",
    "records[0].phase3Disposition = 'discard';",
    "records[0].phase3LastAttemptAt = new Date().toISOString();",
    "records[0].phase3LastErrorCode = 'ACCOUNT_DEACTIVATED';",
    "records[0].phase3Retryable = false;",
    "fs.writeFileSync(file, JSON.stringify(records, null, 2));",
    'const original = fs.realpathSync(process.cwd());',
    "fs.renameSync(original, original + '-moved');",
    'fs.mkdirSync(original, { mode: 0o700 });',
    "fs.mkdirSync(path.join(original, 'tokens'));",
    "fs.mkdirSync(path.join(original, 'use_token'));",
    "fs.writeFileSync(path.join(original, 'username.json'), JSON.stringify([{ email: 'discard@example.test', password: 'replacement', status: 'manual_replacement' }]));",
    "fs.writeSync(2, 'unlabelled-discard-secret\\n');",
    "process.stderr.write('ACCOUNT_DEACTIVATED\\n');",
    'process.exitCode = 1;',
  ].join('\n'));
  const previous = {
    root: process.env.GPT_REGISTER_ROOT,
    node: process.env.GPT_REGISTER_NODE_PATH,
    enabled: process.env.PANEL_PHASE3_ENABLED,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.GPT_REGISTER_NODE_PATH = process.execPath;
  process.env.PANEL_PHASE3_ENABLED = '1';
  const events = [];
  const logger = {
    checkpoint() { return true; },
    info(event, fields) { events.push({ event, fields }); },
    warn(event, fields) { events.push({ event, fields }); },
    error(event, fields) { events.push({ event, fields }); },
  };
  try {
    let failure;
    await assert.rejects(
      runPhase3Job({
        email: 'discard@example.test',
        jobId: 'discard-job',
        db: { async audit() {}, async startMutationJob() {}, async updateJob() {} },
        logger,
      }),
      (error) => {
        failure = error;
        return error.code === 'ACCOUNT_DEACTIVATED' && error.accountDisposition === 'discard';
      },
    );
    assert.equal(JSON.stringify(failure.details).includes('unlabelled-discard-secret'), false);
    assert.equal(Object.hasOwn(failure.details, 'stdout'), false);
    assert.equal(Object.hasOwn(failure.details, 'stderr'), false);
    assert.equal(JSON.stringify(events).includes('unlabelled-discard-secret'), false);
    const records = JSON.parse(fs.readFileSync(path.join(movedRoot, 'username.json'), 'utf8'));
    assert.equal(records[0].status, 'account_deleted');
    assert.equal(records[0].phase3Disposition, 'discard');
    assert.equal(records[0].phase3LastErrorCode, 'ACCOUNT_DEACTIVATED');
    const replacement = JSON.parse(fs.readFileSync(path.join(root, 'username.json'), 'utf8'));
    assert.equal(replacement[0].status, 'manual_replacement');
  } finally {
    if (previous.root === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous.root;
    if (previous.node === undefined) delete process.env.GPT_REGISTER_NODE_PATH;
    else process.env.GPT_REGISTER_NODE_PATH = previous.node;
    if (previous.enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
    else process.env.PANEL_PHASE3_ENABLED = previous.enabled;
  }
});

test('snapshot maps Sub2API historical and current-window stats to rows', async () => {
  const { root } = fixture();
  const opaqueAccountError = 'opaque-snapshot-account-error-a82f41';
  const opaqueStatsError = 'opaque-snapshot-stats-error-c3905e';
  const fakeClient = {
    async listAccounts() {
      return [{
        id: 42,
        name: 'free00042',
        platform: 'openai',
        type: 'oauth',
        status: 'active',
        errorMessage: opaqueAccountError,
        email: 'one@example.test',
        identityKeys: ['account:a-1', 'user:u-1', 'email:one@example.test'],
        tokenFingerprints: {},
      }];
    },
    async getBatchTableUsageStats() {
      return { stats: { '42': {
        historical: { totalTokens: 1234, requests: 12 },
        current: { totalTokens: 55, requests: 2 },
      } }, errors: {
        '42': { code: 'UPSTREAM', message: opaqueStatsError },
      } };
    },
  };
  const snapshot = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
    rootDirectory: root,
    readSub2Api: true,
    client: fakeClient,
  });
  const row = snapshot.rows.find((item) => item.accountId === 42);
  assert.equal(row.usage.historical.totalTokens, 1234);
  assert.equal(row.usage.current.totalTokens, 55);
  const account = snapshot.sub2api.accounts.find((item) => item.id === 42);
  assert.equal(account.errorMessage, 'Sub2API 已报告账号错误（详情已隐藏）');
  assert.equal(account.usageError, 'Sub2API 账号统计读取失败（详情已隐藏）');
  assert.equal(JSON.stringify(snapshot).includes(opaqueAccountError), false);
  assert.equal(JSON.stringify(snapshot).includes(opaqueStatsError), false);
});

test('snapshot replaces an opaque Sub2API read failure before returning or logging it', async () => {
  const { root } = fixture();
  const opaqueFailure = 'opaque-snapshot-read-failure-18f7d3';
  const records = [];
  const logger = Object.fromEntries(['info', 'warn', 'error'].map((level) => [
    level,
    (event, fields) => records.push({ level, event, fields }),
  ]));
  const snapshot = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
    rootDirectory: root,
    readSub2Api: true,
    logger,
    client: {
      async listAccounts() {
        throw new Error(opaqueFailure);
      },
    },
  });

  assert.equal(snapshot.sub2api.readStatus, 'failed');
  assert.equal(snapshot.sub2api.apiError, 'Sub2API 管理 API 账号读取失败');
  assert.equal(JSON.stringify(snapshot).includes(opaqueFailure), false);
  assert.equal(JSON.stringify(records).includes(opaqueFailure), false);
});

test('import plan never updates an available Sub2API account', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 9,
    name: 'free00009',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: 'different-access', refresh: 'different-refresh' },
  };
  const plan = buildImportPlan(sources, [account]);
  assert.equal(plan[0].action, 'skip');
  assert.equal(plan[0].reason, 'sub2api_available');

  account.tokenFingerprints = { ...token.fingerprints };
  account.credentialPresence = { access: 'present', refresh: 'present', id: 'unknown' };
  const matchingPlan = buildImportPlan(sources, [account]);
  assert.equal(matchingPlan[0].action, 'skip');
  assert.equal(matchingPlan[0].reason, 'sub2api_available');
});

test('import plan skips an explicitly disabled source token', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  token.disabled = true;
  const plan = buildImportPlan(sources, []);
  assert.equal(plan[0].action, 'skip');
  assert.equal(plan[0].reason, 'source_disabled');
});

test('import plan updates only an unavailable account with a fresh source token', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 10,
    name: 'free00010',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: 'different-access', refresh: 'different-refresh' },
  };
  const plan = buildImportPlan(sources, [account]);
  assert.equal(plan[0].action, 'update');
  assert.equal(plan[0].reason, 'token_changed');
});

test('import plan updates when a source refresh fingerprint cannot be verified remotely', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 11,
    name: 'free00011',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: token.identityKeys,
    credentialPresence: { access: 'present', refresh: 'present', id: 'unknown' },
    tokenFingerprints: { access: token.fingerprints.access, refresh: null },
  };
  const plan = buildImportPlan(sources, [account]);
  assert.equal(plan[0].action, 'update');
  assert.equal(plan[0].reason, 'token_changed');

  account.tokenFingerprints.refresh = token.fingerprints.refresh;
  const matchingPlan = buildImportPlan(sources, [account]);
  assert.equal(matchingPlan[0].action, 'skip');
  assert.equal(matchingPlan[0].reason, 'already_in_sync');
});

test('diff decision metadata and import planner share policy reasons without changing observed kinds', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const loaded = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const source = loaded.tokens.find((item) => item.parseStatus === 'ok');
  const baseAccount = {
    id: 12,
    name: 'free00012',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    schedulable: false,
    identityKeys: source.identityKeys,
    tokenFingerprints: { ...source.fingerprints },
    credentialPresence: { access: 'present', refresh: 'present', id: 'unknown' },
  };

  const assertSharedDecision = ({ record = source, account = baseAccount, usernames = loaded.usernames }, expected) => {
    // Raw credentials are intentionally non-enumerable on source records, so
    // preserve the fixture's private value when a scenario clones metadata.
    const planRecord = record.raw ? record : { ...record, raw: source.raw };
    const sources = { ...loaded, tokens: [planRecord], usernames };
    const diff = buildDiff(sources.tokens, [account], { usernames });
    const item = diff.items.find((candidate) => candidate.token);
    const plan = buildImportPlan(sources, [account]);
    assert.equal(plan.length, 1);
    assert.equal(item.kind, expected.observedKind);
    assert.equal(item.observedKind, expected.observedKind);
    assert.equal(item.decisionAction, expected.action);
    assert.equal(item.decisionReason, expected.reason);
    assert.equal(plan[0].action, expected.action);
    assert.equal(plan[0].reason, expected.reason);
    const safeItem = toSafeDiff(diff).items.find((candidate) => candidate.token);
    assert.equal(safeItem.observedKind, expected.observedKind);
    assert.equal(safeItem.decisionAction, expected.action);
    assert.equal(safeItem.decisionReason, expected.reason);
  };

  assertSharedDecision({ record: { ...source, disabled: true } }, {
    observedKind: 'in_sync',
    action: 'skip',
    reason: 'source_disabled',
  });
  assertSharedDecision({ account: { ...baseAccount, schemaValid: false } }, {
    observedKind: 'in_sync',
    action: 'conflict',
    reason: 'sub2api_account_schema_invalid',
  });
  assertSharedDecision({
    usernames: [{ ...loaded.usernames[0], status: 'account_disabled' }],
  }, {
    observedKind: 'in_sync',
    action: 'skip',
    reason: 'source_account_terminal',
  });
  assertSharedDecision({
    account: {
      ...baseAccount,
      status: 'active',
      schedulable: true,
      tokenFingerprints: { access: 'different-access', refresh: 'different-refresh' },
    },
  }, {
    observedKind: 'token_changed',
    action: 'skip',
    reason: 'sub2api_available',
  });
  assertSharedDecision({
    account: {
      ...baseAccount,
      tokenFingerprints: { access: source.fingerprints.access, refresh: null },
      credentialPresence: { access: 'present', refresh: 'absent', id: 'unknown' },
    },
  }, {
    observedKind: 'missing_refresh_token',
    action: 'update',
    reason: 'missing_refresh_token',
  });
});

test('no-remote and ambiguous diff decisions match planner blockers when they are determinable', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const loaded = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const source = loaded.tokens.find((item) => item.parseStatus === 'ok');
  const cloneSource = (changes = {}) => ({ ...source, raw: source.raw, ...changes });
  const assertDecision = ({ record, usernames = [], accounts = [] }, expected) => {
    const sources = { ...loaded, tokens: [record], usernames };
    const diffItem = buildDiff(sources.tokens, accounts, { usernames }).items.find((item) => item.token);
    const planItem = buildImportPlan(sources, accounts)[0];
    assert.equal(diffItem.decisionAction, expected.action);
    assert.equal(diffItem.decisionReason, expected.reason);
    assert.equal(planItem.action, expected.action);
    assert.equal(planItem.reason, expected.reason);
  };

  assertDecision({
    record: cloneSource(),
    usernames: [{ email: source.email, status: 'account_deleted' }],
  }, { action: 'skip', reason: 'source_account_terminal' });
  assertDecision({
    record: cloneSource({ expiryStatus: 'invalid', expiresAt: null }),
  }, { action: 'skip', reason: 'source_expiry_invalid' });
  assertDecision({
    record: cloneSource({ disabled: true }),
  }, { action: 'skip', reason: 'source_disabled' });
  assertDecision({
    record: cloneSource({ expiryStatus: 'valid', expiresAt: '2020-01-01T00:00:00.000Z' }),
  }, { action: 'skip', reason: 'source_token_expired' });
  assertDecision({
    record: cloneSource({
      accountId: '',
      userId: '',
      identityKeys: ['email:' + source.email],
    }),
  }, { action: 'conflict', reason: 'source_identity_insufficient' });

  const duplicateAccounts = [21, 22].map((id) => ({
    id,
    name: 'free000' + id,
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    schedulable: false,
    identityKeys: source.identityKeys,
    tokenFingerprints: { ...source.fingerprints },
  }));
  assertDecision({ record: cloneSource(), accounts: duplicateAccounts }, {
    action: 'conflict',
    reason: 'multiple_sub2api_accounts',
  });

  const first = cloneSource({
    relativePath: 'tokens/ambiguous-one.json',
    fileName: 'ambiguous-one.json',
    identityKeys: ['account:a-1', 'user:ambiguous-one'],
  });
  const second = cloneSource({
    relativePath: 'tokens/ambiguous-two.json',
    fileName: 'ambiguous-two.json',
    identityKeys: ['account:a-1', 'user:ambiguous-two'],
  });
  const partialRemote = {
    id: 23,
    name: 'free00023',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    schedulable: false,
    identityKeys: ['account:a-1'],
    tokenFingerprints: { ...source.fingerprints },
  };
  const ambiguousDiff = buildDiff([first, second], [partialRemote]);
  assert.equal(ambiguousDiff.items.length, 2);
  for (const item of ambiguousDiff.items) {
    assert.equal(item.kind, 'mapping_conflict');
    assert.equal(item.observedKind, 'mapping_conflict');
    assert.equal(item.decisionAction, 'conflict');
    assert.equal(item.decisionReason, 'ambiguous_sub2api_identity');
  }
  const ambiguousPlan = buildImportPlan({
    ...loaded,
    tokens: [first, second],
    usernames: [],
  }, [partialRemote]);
  assert.deepEqual(ambiguousPlan.map((item) => item.action), ['conflict', 'conflict']);
  assert.deepEqual(ambiguousPlan.map((item) => item.reason), [
    'ambiguous_sub2api_identity',
    'ambiguous_sub2api_identity',
  ]);
});

test('aggregated strong identity refuses a partial remote even when the freshest source matches it', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-duplicate-source-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  const makeAccess = (userId, includeAccount) => [
    'header',
    Buffer.from(JSON.stringify({
      sub: userId,
      email: 'duplicate@example.test',
      ...(includeAccount ? {
        'https://api.openai.com/auth': {
          chatgpt_account_id: 'account-fresh',
          chatgpt_user_id: userId,
        },
      } : {}),
    })).toString('base64url'),
    'signature',
  ].join('.');
  fs.writeFileSync(path.join(root, 'tokens', 'fresh.json'), JSON.stringify({
    access_token: makeAccess('fresh-user', true),
    refresh_token: 'refresh-fresh',
    email: 'duplicate@example.test',
    expired: '2099-08-27T00:00:00.000Z',
    last_refresh: '2099-08-20T00:00:00.000Z',
  }));
  fs.writeFileSync(path.join(root, 'use_token', 'old.json'), JSON.stringify({
    access_token: makeAccess('fresh-user', false),
    refresh_token: 'refresh-old',
    email: 'duplicate@example.test',
    expired: '2020-08-21T00:00:00.000Z',
    last_refresh: '2020-08-14T00:00:00.000Z',
  }));
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const accounts = [{
    id: 77,
    name: 'free00077',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: ['user:fresh-user', 'email:duplicate@example.test'],
    tokenFingerprints: { access: 'different-access', refresh: 'different-refresh' },
  }];
  const plan = buildImportPlan(sources, accounts);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].action, 'conflict');
  assert.equal(plan[0].reason, 'ambiguous_sub2api_identity');
  assert.equal(plan[0].source, 'tokens');
  assert.equal(plan[0].relativePath, 'tokens/fresh.json');
  assert.equal(plan[0].duplicateSource, true);
  assert.equal(plan.some((item) => item.relativePath === 'use_token/old.json'), false);

  const oldKey = 'token:use_token:use_token/old.json';
  const selectedOld = importPlanSummary(buildImportPlan(sources, accounts, [oldKey]));
  assert.equal(selectedOld.items.length, 1);
  assert.equal(selectedOld.items[0].relativePath, 'tokens/fresh.json');
  assert.equal(selectedOld.items[0].sourceVersionCount, 2);
  assert.deepEqual(selectedOld.items[0].selectedSourcePaths, ['use_token/old.json']);
  assert.deepEqual(selectedOld.items[0].selectedSupersededPaths, ['use_token/old.json']);
  assert.equal(selectedOld.items[0].selectedSourceSuperseded, true);
  assert.equal(JSON.stringify(selectedOld).includes('refresh-fresh'), false);
  assert.equal(JSON.stringify(selectedOld).includes('refresh-old'), false);

  const freshKey = 'token:tokens:tokens/fresh.json';
  const selectedFresh = importPlanSummary(buildImportPlan(sources, accounts, [freshKey]));
  assert.equal(selectedFresh.items[0].relativePath, 'tokens/fresh.json');
  assert.deepEqual(selectedFresh.items[0].selectedSupersededPaths, []);
  assert.equal(selectedFresh.items[0].selectedSourceSuperseded, false);
});

test('sync selection accepts only explicit token row keys', () => {
  const token = syntheticToken('tokens/numeric-account.json', ['account:77'], {
    accountId: '77',
  });
  const unrelatedRemote = {
    id: 77,
    name: 'free00077',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys: ['account:unrelated-account'],
    tokenFingerprints: { access: 'unrelated-fingerprint' },
  };
  const sources = { tokens: [token], usernames: [] };

  for (const key of ['account:77', 'user:untrusted-alias']) {
    let selectionError;
    assert.throws(
      () => buildImportPlan(sources, [unrelatedRemote], [key]),
      (error) => {
        selectionError = error;
        return error.code === 'IMPORT_SELECTION_MISMATCH'
          && error.unknownSelectionCount === 1;
      },
    );
    assert.equal(selectionError.message.includes(key), false);
  }
  const selected = buildImportPlan(
    sources,
    [unrelatedRemote],
    ['token:tokens:tokens/numeric-account.json'],
  );
  assert.equal(selected.length, 1);
  assert.equal(selected[0].relativePath, 'tokens/numeric-account.json');
  assert.equal(selected[0].action, 'create');
});

test('sync rejects a mixed selection instead of silently importing its covered subset', () => {
  const token = syntheticToken('tokens/covered.json', ['account:covered'], {
    accountId: 'covered',
  });
  const validKey = 'token:tokens:tokens/covered.json';
  const secretMarker = 'token:tokens:tokens/credential-marker.json';
  let selectionError;
  assert.throws(
    () => buildImportPlan(
      { tokens: [token], usernames: [] },
      [],
      [validKey, secretMarker],
    ),
    (error) => {
      selectionError = error;
      return error.code === 'IMPORT_SELECTION_MISMATCH'
        && error.unknownSelectionCount === 1;
    },
  );
  assert.equal(selectionError.message.includes(secretMarker), false);
  assert.equal(JSON.stringify(selectionError).includes(secretMarker), false);
});

test('sync selection and plan intent preserve exact keys and bind every executable decision', () => {
  const first = syntheticToken(
    'tokens/intent-one.json',
    ['account:intent-one-account', 'user:intent-one-user'],
  );
  const second = syntheticToken(
    'tokens/intent-two.json',
    ['account:intent-two-account', 'user:intent-two-user'],
  );
  const sources = { tokens: [first, second], usernames: [] };
  const firstKey = 'token:tokens:tokens/intent-one.json';
  const secondKey = 'token:tokens:tokens/intent-two.json';
  for (const invalidSelection of [
    [' ' + firstKey],
    [firstKey + ' '],
    ['', firstKey],
    [firstKey, firstKey],
  ]) {
    assert.throws(
      () => buildImportPlan(sources, [], invalidSelection),
      (error) => error.code === 'IMPORT_SELECTION_INVALID',
    );
  }

  const snapshot = 'a'.repeat(64);
  const firstSelectionPlan = buildImportPlan(sources, [], [firstKey]);
  const groupBinding = { mode: 'explicit', groupIds: [9, 7] };
  assert.throws(
    () => buildImportPlanIntentVersion(snapshot, [firstKey], firstSelectionPlan),
    (error) => error.code === 'IMPORT_GROUP_BINDING_REQUIRED',
  );
  const firstIntent = buildImportPlanIntentVersion(
    snapshot,
    [firstKey],
    firstSelectionPlan,
    groupBinding,
  );
  assert.match(firstIntent, /^sync-plan-v1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(
    firstIntent,
    buildImportPlanIntentVersion(
      snapshot,
      [firstKey],
      firstSelectionPlan,
      { mode: 'explicit', groupIds: [7, 9, 7] },
    ),
  );
  assert.notEqual(
    firstIntent,
    buildImportPlanIntentVersion(
      snapshot,
      [firstKey],
      firstSelectionPlan,
      { mode: 'explicit', groupIds: [7, 10] },
    ),
  );
  assert.notEqual(
    firstIntent,
    buildImportPlanIntentVersion(
      snapshot,
      [firstKey],
      firstSelectionPlan,
      { mode: 'sub2api_default', groupIds: [11] },
    ),
  );
  assert.equal(importPlanIntentVersionsEqual(firstIntent, firstIntent), true);
  assert.equal(importPlanIntentVersionsEqual(firstIntent, firstIntent.slice(0, -1) + '!'), false);

  const changedSelectionIntent = buildImportPlanIntentVersion(
    snapshot,
    [secondKey],
    buildImportPlan(sources, [], [secondKey]),
    groupBinding,
  );
  assert.notEqual(changedSelectionIntent, firstIntent);

  const winnerIdentity = ['account:intent-winner-account', 'user:intent-winner-user'];
  const older = syntheticToken('tokens/intent-old.json', winnerIdentity, {
    mtimeMs: 1,
    expiresAt: '2098-01-01T00:00:00.000Z',
  });
  const newer = syntheticToken('use_token/intent-new.json', winnerIdentity, {
    source: 'use_token',
    mtimeMs: 2,
    expiresAt: '2099-01-01T00:00:00.000Z',
  });
  const selectedOlderKey = 'token:tokens:tokens/intent-old.json';
  const newerWins = buildImportPlan(
    { tokens: [older, newer], usernames: [] },
    [],
    [selectedOlderKey],
  );
  const olderWins = buildImportPlan(
    {
      tokens: [
        { ...older, expiresAt: '2100-01-01T00:00:00.000Z' },
        newer,
      ],
      usernames: [],
    },
    [],
    [selectedOlderKey],
  );
  assert.notEqual(newerWins[0].key, olderWins[0].key);
  assert.notEqual(
    buildImportPlanIntentVersion(snapshot, [selectedOlderKey], newerWins, groupBinding),
    buildImportPlanIntentVersion(snapshot, [selectedOlderKey], olderWins, groupBinding),
  );

  const unavailableTarget = {
    id: 801,
    name: 'free00801',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    schemaValid: true,
    identityKeys: first.identityKeys,
    tokenFingerprints: { access: 'different' },
    credentialPresence: { access: 'present', refresh: 'unknown', id: 'unknown' },
  };
  const updatePlan = buildImportPlan(sources, [unavailableTarget], [firstKey]);
  const retargetedPlan = buildImportPlan(
    sources,
    [{ ...unavailableTarget, id: 802, name: 'free00802' }],
    [firstKey],
  );
  assert.equal(updatePlan[0].action, 'update');
  assert.equal(retargetedPlan[0].action, 'update');
  assert.notEqual(
    buildImportPlanIntentVersion(snapshot, [firstKey], updatePlan),
    buildImportPlanIntentVersion(snapshot, [firstKey], retargetedPlan),
  );
  assert.notEqual(
    buildImportPlanIntentVersion(snapshot, [firstKey], updatePlan),
    buildImportPlanIntentVersion(snapshot, [firstKey], firstSelectionPlan, groupBinding),
  );
});

test('treats expired active Sub2API accounts as unavailable for replacement', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 88,
    name: 'free00088',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    expiresAt: '2020-01-01T00:00:00.000Z',
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: 'old-access' },
  };
  assert.equal(getAccountAvailability(account, Date.parse('2026-01-01T00:00:00.000Z')).key, 'unavailable');
  assert.equal(buildImportPlan(sources, [account])[0].action, 'update');
  assert.equal(getAccountAvailability({ ...account, autoPauseOnExpired: false }, Date.parse('2026-01-01T00:00:00.000Z')).key, 'available');
  assert.equal(getAccountAvailability({
    ...account,
    expiresAt: null,
    credentialExpiresAt: '2020-01-01T00:00:00.000Z',
    credentialExpiryStatus: 'valid',
  }, Date.parse('2026-01-01T00:00:00.000Z')).key, 'available');
});

test('unknown Sub2API state fails closed and is never planned as an update', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const base = {
    id: 89,
    name: 'free00089',
    platform: 'openai',
    type: 'oauth',
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: 'old-access' },
  };
  const missingStatus = { ...base, schedulable: true };
  assert.deepEqual(getAccountAvailability(missingStatus), {
    key: 'unknown',
    reason: 'sub2api_status_missing',
  });
  const plan = buildImportPlan(sources, [missingStatus]);
  assert.equal(plan[0].action, 'skip');
  assert.equal(plan[0].reason, 'sub2api_status_missing');

  assert.equal(getAccountAvailability({
    ...base,
    status: 'active',
    schedulable: true,
    expiresAt: 'not-a-date',
  }).key, 'unknown');
  assert.equal(getAccountAvailability({ ...base, status: 'active' }).key, 'unknown');
});

test('does not match contradictory strong identities even with the same email', () => {
  assert.equal(identitiesCompatible(
    ['account:source-a', 'email:shared@example.test'],
    ['account:source-b', 'email:shared@example.test'],
  ), false);
  assert.equal(identitiesCompatible(
    ['account:source-a', 'email:old@example.test'],
    ['account:source-a', 'email:new@example.test'],
  ), true);
  assert.equal(identitiesCompatible(
    ['account:source-a', 'user:user-a', 'email:shared@example.test'],
    ['email:shared@example.test'],
  ), false);
  assert.equal(identitiesCompatible(
    ['email:shared@example.test'],
    ['email:shared@example.test'],
  ), true);
});

function syntheticToken(relativePath, identityKeys, options = {}) {
  return {
    source: options.source || 'tokens',
    relativePath,
    fileName: path.basename(relativePath),
    mtimeMs: options.mtimeMs || 1,
    parseStatus: 'ok',
    expiryStatus: options.expiryStatus || 'valid',
    expiresAt: options.expiresAt === undefined ? '2099-01-01T00:00:00.000Z' : options.expiresAt,
    lastRefresh: options.lastRefresh || null,
    disabled: false,
    email: options.email || '',
    accountId: options.accountId || '',
    userId: options.userId || '',
    identityKeys,
    fingerprints: {
      access: options.accessFingerprint || ('access-' + relativePath),
      refresh: options.refreshFingerprint || null,
    },
    raw: {
      access_token: options.accessToken || ('opaque-' + relativePath),
      ...(options.refreshToken ? { refresh_token: options.refreshToken } : {}),
    },
  };
}

test('natural path ties have a strict order and select the same token after input reversal', () => {
  const identityKeys = ['account:natural-order-account', 'user:natural-order-user'];
  const upper = syntheticToken('tokens/A2.json', identityKeys, {
    accessFingerprint: 'upper-natural-fingerprint',
  });
  const lower = syntheticToken('tokens/a02.json', identityKeys, {
    accessFingerprint: 'lower-natural-fingerprint',
  });
  assert.equal(
    upper.relativePath.localeCompare(
      lower.relativePath,
      'en',
      { numeric: true, sensitivity: 'base' },
    ),
    0,
  );

  const forward = collectCandidates({ tokens: [lower, upper] })[0];
  const reversed = collectCandidates({ tokens: [upper, lower] })[0];
  assert.equal(forward.record.relativePath, 'tokens/A2.json');
  assert.equal(reversed.record.relativePath, forward.record.relativePath);
  assert.deepEqual(
    reversed.records.map((record) => record.relativePath),
    forward.records.map((record) => record.relativePath),
  );
  assert.equal(
    buildImportPlan({ tokens: [lower, upper], usernames: [] }, [])[0].fingerprints.access,
    buildImportPlan({ tokens: [upper, lower], usernames: [] }, [])[0].fingerprints.access,
  );
  assert.equal(comparePhase3TokenFreshness(upper, lower) < 0, true);
  assert.equal(comparePhase3TokenFreshness(lower, upper) > 0, true);
});

test('new account numbering uses a locale-independent natural source order', () => {
  const token10 = syntheticToken(
    'tokens/account10.json',
    ['account:stable-order-10', 'user:stable-user-10'],
  );
  const token2 = syntheticToken(
    'tokens/account2.json',
    ['account:stable-order-2', 'user:stable-user-2'],
  );
  const originalLocaleCompare = String.prototype.localeCompare;
  String.prototype.localeCompare = function localeComparisonForbidden() {
    throw new Error('persisted import order must not depend on localeCompare');
  };
  try {
    for (const tokens of [[token10, token2], [token2, token10]]) {
      const plan = buildImportPlan({ tokens, usernames: [] }, []);
      assert.deepEqual(
        plan.map((item) => [item.relativePath, item.accountName]),
        [
          ['tokens/account2.json', 'free00001'],
          ['tokens/account10.json', 'free00002'],
        ],
      );
    }
  } finally {
    String.prototype.localeCompare = originalLocaleCompare;
  }
});

test('create preflight requires a canonical name and rejects casefold-equivalent occupancy', async () => {
  const identityKeys = ['account:create-name-account', 'user:create-name-user'];
  const source = syntheticToken('tokens/create-name.json', identityKeys);
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  let reads = 0;
  let writes = 0;

  await assert.rejects(
    executeImportPlanItem({
      item: { ...item, accountName: 'FREE00001' },
      client: {
        async listAccounts() { reads += 1; return []; },
        async importCodexSession() { writes += 1; },
      },
    }),
    (error) => error.code === 'SUB2API_CREATE_NAME_INVALID',
  );
  assert.equal(reads, 0);
  assert.equal(writes, 0);

  await assert.rejects(
    executeImportPlanItem({
      item,
      client: {
        async listAccounts() {
          reads += 1;
          return [{
            id: 12,
            name: ' FREE00001 ',
            identityKeys: ['account:unrelated-name-account', 'user:unrelated-name-user'],
          }];
        },
        async importCodexSession() { writes += 1; },
      },
    }),
    (error) => error.code === 'SUB2API_CREATE_NAME_CONFLICT',
  );
  assert.equal(reads, 1);
  assert.equal(writes, 0);
});

test('create preflight rejects a truncated strict account page before dispatching a write', async () => {
  const identityKeys = ['account:truncated-page-account', 'user:truncated-page-user'];
  const source = syntheticToken('tokens/truncated-page.json', identityKeys, {
    accountId: 'truncated-page-account',
    userId: 'truncated-page-user',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const client = new Sub2ApiAdminClient({
    baseUrl: 'http://127.0.0.1:18080',
    apiKey: 'test-only-key',
  });
  let writeCalls = 0;
  client.request = async (method, pathname) => {
    if (method === 'GET' && pathname.startsWith('/api/v1/admin/accounts?')) {
      return {
        items: [{ id: 999, name: 'free00999' }],
        total: 2,
        page: 1,
        page_size: 200,
        pages: 1,
      };
    }
    writeCalls += 1;
    throw new Error('write must not be dispatched after a truncated preflight page');
  };

  await assert.rejects(
    executeImportPlanItem({ client, item }),
    (error) => error.code === 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
  );
  assert.equal(writeCalls, 0);
});

test('Codex create documents use the current expiry field and cross-job stable secret-free keys', () => {
  const accessSecret = 'access-secret-must-not-enter-header';
  const refreshSecret = 'refresh-secret-must-not-enter-header';
  const source = syntheticToken(
    'tokens/idempotent.json',
    ['user:idempotent-user', 'account:idempotent-account', 'email:hidden@example.test'],
    {
      accountId: 'idempotent-account',
      userId: 'idempotent-user',
      email: 'hidden@example.test',
      accessToken: accessSecret,
      refreshToken: refreshSecret,
      accessFingerprint: 'access-fingerprint-a',
      refreshFingerprint: 'refresh-fingerprint-a',
      expiresAt: '2099-02-03T04:05:06.000Z',
    },
  );
  source.contentHash = '1'.repeat(64);
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const document = buildCodexSessionDocument(item);
  assert.equal(document.expires_at, '2099-02-03T04:05:06.000Z');
  assert.equal(Object.hasOwn(document, 'expired'), false);

  const context = { jobId: 'durable-job-123' };
  const first = buildCodexImportIdempotencyKey(item, context);
  const retry = buildCodexImportIdempotencyKey(item, { jobId: 'different-job-456' });
  assert.equal(first, retry);
  assert.equal(buildCodexImportIdempotencyKey({
    ...item,
    sourceIdentityKeys: [
      'email:changed-but-not-authoritative@example.test',
      'account:idempotent-account',
      'user:idempotent-user',
    ],
  }, context), first);
  assert.match(first, /^gptreg-create-v2-[a-f0-9]{64}$/);
  assert.equal(first.length <= 128, true);
  assert.match(first, /^[\x21-\x7e]+$/);
  for (const secret of [accessSecret, refreshSecret, source.email, source.accountId, source.userId]) {
    assert.equal(first.includes(secret), false);
  }

  const changedCredential = {
    ...item,
    _record: { ...item._record, contentHash: '2'.repeat(64) },
  };
  assert.notEqual(buildCodexImportIdempotencyKey(changedCredential, context), first);
  assert.notEqual(buildCodexImportIdempotencyKey(
    { ...item, accountName: 'free09999' },
    context,
  ), first);
  assert.notEqual(buildCodexImportIdempotencyKey(
    { ...item, relativePath: 'tokens/another.json' },
    context,
  ), first);
  assert.notEqual(buildCodexImportIdempotencyKey({
    ...item,
    sourceIdentityKeys: ['account:another-account', 'user:idempotent-user'],
  }, context), first);
  assert.equal(buildCodexImportIdempotencyKey(item, { jobId: 'another-job' }), first);
});

test('candidate grouping merges partial versions but keeps different workspace users separate', () => {
  const complete = syntheticToken(
    'tokens/complete.json',
    ['account:workspace-a', 'user:user-a', 'email:same@example.test'],
    { accountId: 'workspace-a', userId: 'user-a', email: 'same@example.test', mtimeMs: 2 },
  );
  const userOnly = syntheticToken(
    'use_token/user-only.json',
    ['user:user-a', 'email:same@example.test'],
    { source: 'use_token', userId: 'user-a', email: 'same@example.test', mtimeMs: 1 },
  );
  const merged = collectCandidates({ tokens: [userOnly, complete] });
  assert.equal(merged.length, 1);
  assert.equal(merged[0].records.length, 2);
  assert.equal(buildImportPlan({ tokens: [userOnly, complete], usernames: [] }, []).length, 1);

  const firstUser = syntheticToken(
    'tokens/user-one.json',
    ['account:shared-workspace', 'user:user-one'],
    { accountId: 'shared-workspace', userId: 'user-one' },
  );
  const secondUser = syntheticToken(
    'tokens/user-two.json',
    ['account:shared-workspace', 'user:user-two'],
    { accountId: 'shared-workspace', userId: 'user-two' },
  );
  assert.equal(collectCandidates({ tokens: [firstUser, secondUser] }).length, 2);
  assert.deepEqual(
    buildImportPlan({ tokens: [secondUser, firstUser], usernames: [] }, []).map((item) => item.action),
    ['create', 'create'],
  );

  const firstWorkspace = syntheticToken(
    'tokens/workspace-one.json',
    ['account:workspace-one', 'user:shared-user'],
    { accountId: 'workspace-one', userId: 'shared-user' },
  );
  const secondWorkspace = syntheticToken(
    'tokens/workspace-two.json',
    ['account:workspace-two', 'user:shared-user'],
    { accountId: 'workspace-two', userId: 'shared-user' },
  );
  assert.equal(collectCandidates({ tokens: [firstWorkspace, secondWorkspace] }).length, 2);
  assert.deepEqual(
    buildImportPlan({ tokens: [secondWorkspace, firstWorkspace], usernames: [] }, [])
      .map((item) => item.action),
    ['create', 'create'],
  );
});

test('ambiguous partial strong identities fail closed instead of creating duplicates', () => {
  const firstUser = syntheticToken(
    'tokens/user-one.json',
    ['account:shared-workspace', 'user:user-one'],
    { accountId: 'shared-workspace', userId: 'user-one' },
  );
  const secondUser = syntheticToken(
    'tokens/user-two.json',
    ['account:shared-workspace', 'user:user-two'],
    { accountId: 'shared-workspace', userId: 'user-two' },
  );
  const accountOnly = syntheticToken(
    'use_token/account-only.json',
    ['account:shared-workspace'],
    { source: 'use_token', accountId: 'shared-workspace' },
  );
  const plan = buildImportPlan({ tokens: [firstUser, accountOnly, secondUser], usernames: [] }, []);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].action, 'conflict');
  assert.equal(plan[0].reason, 'conflicting_strong_identity');
});

test('contradictory source identities cannot compete for one partial remote identity', () => {
  const firstUser = syntheticToken(
    'tokens/user-one.json',
    ['account:shared-workspace', 'user:user-one'],
    { accountId: 'shared-workspace', userId: 'user-one', mtimeMs: 1 },
  );
  const secondUser = syntheticToken(
    'tokens/user-two.json',
    ['account:shared-workspace', 'user:user-two'],
    { accountId: 'shared-workspace', userId: 'user-two', mtimeMs: 2 },
  );
  const partialRemote = {
    id: 41,
    name: 'free00041',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    schemaValid: true,
    accountId: 'shared-workspace',
    userId: '',
    identityKeys: ['account:shared-workspace'],
    tokenFingerprints: {},
  };

  const plan = buildImportPlan(
    { tokens: [firstUser, secondUser], usernames: [] },
    [partialRemote],
  );
  assert.equal(plan.length, 2);
  assert.deepEqual(plan.map((item) => item.action), ['conflict', 'conflict']);
  assert.deepEqual(plan.map((item) => item.reason), [
    'ambiguous_sub2api_identity',
    'ambiguous_sub2api_identity',
  ]);
});

test('strong source selects the correct remote ID and ignores an email-only legacy row', () => {
  const token = syntheticToken(
    'tokens/current.json',
    ['account:account-a', 'user:user-a', 'email:shared@example.test'],
    { accountId: 'account-a', userId: 'user-a', email: 'shared@example.test' },
  );
  const plan = buildImportPlan({ tokens: [token], usernames: [] }, [
    {
      id: 264,
      name: 'free00006',
      platform: 'openai',
      type: 'oauth',
      status: 'error',
      schedulable: false,
      identityKeys: ['email:shared@example.test'],
      tokenFingerprints: { access: 'legacy' },
    },
    {
      id: 266,
      name: 'free00007',
      platform: 'openai',
      type: 'oauth',
      status: 'error',
      schedulable: false,
      identityKeys: ['account:account-a', 'user:user-a', 'email:shared@example.test'],
      tokenFingerprints: { access: 'old' },
    },
  ]);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].action, 'update');
  assert.equal(plan[0].accountId, 266);
});

test('standard UUID identities match case-insensitively without creating a duplicate', () => {
  const accountUuidUpper = '{123E4567-E89B-12D3-A456-426614174000}';
  const userUuidUpper = '123E4567-E89B-12D3-A456-426614174001';
  const token = syntheticToken(
    'tokens/uuid.json',
    ['account:' + accountUuidUpper, 'user:' + userUuidUpper],
    { accountId: accountUuidUpper, userId: userUuidUpper },
  );
  const plan = buildImportPlan({ tokens: [token], usernames: [] }, [{
    id: 267,
    name: 'free00267',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: [
      'account:123e4567-e89b-12d3-a456-426614174000',
      'user:123e4567-e89b-12d3-a456-426614174001',
    ],
    tokenFingerprints: { access: 'old' },
  }]);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].action, 'update');
  assert.equal(plan[0].accountId, 267);
});

test('group resolution accepts only one exact safe match', async () => {
  const previousIds = process.env.SUB2API_GROUP_IDS;
  const previousName = process.env.SUB2API_GROUP_NAME;
  try {
    const createPlan = [{ action: 'create' }];
    let unnecessaryReads = 0;
    delete process.env.SUB2API_GROUP_IDS;
    process.env.SUB2API_GROUP_NAME = '';
    assert.deepEqual(await resolveImportGroupBinding({
      async listGroups() {
        unnecessaryReads += 1;
        return [{ id: 11, name: 'openai-default', platform: 'openai' }];
      },
    }, createPlan), {
      mode: 'sub2api_default',
      groupIds: [11],
    });
    assert.equal(unnecessaryReads, 1);
    assert.deepEqual(await resolveImportGroupBinding({
      async listGroups() { unnecessaryReads += 1; return []; },
    }, [{ action: 'update' }]), {
      mode: 'not_applicable',
      groupIds: [],
    });
    assert.equal(unnecessaryReads, 1);

    delete process.env.SUB2API_GROUP_IDS;
    process.env.SUB2API_GROUP_NAME = 'share';
    assert.deepEqual(await resolveGroupIds({
      async listGroups() {
        return [
          { id: 3, name: 'share', platform: 'openai' },
          { id: 4, name: 'share-beta', platform: 'openai' },
          { id: 5, slug: 'not-share', platform: 'openai' },
          { id: 12, name: 'share', platform: 'anthropic' },
        ];
      },
    }), [3]);
    await assert.rejects(
      resolveGroupIds({
        async listGroups() {
          return [
            { id: 3, name: 'share', platform: 'openai' },
            { id: 6, code: 'SHARE', platform: 'openai' },
          ];
        },
      }),
      (error) => error.code === 'SUB2API_GROUP_AMBIGUOUS',
    );
    await assert.rejects(
      resolveGroupIds({
        async listGroups() { return [{ id: true, name: 'share', platform: 'openai' }]; },
      }),
      (error) => error.code === 'SUB2API_GROUP_NOT_FOUND',
    );
    const opaqueGroupFailure = 'opaque-group-read-failure-87c2d4';
    await assert.rejects(
      resolveGroupIds({ async listGroups() { throw new Error(opaqueGroupFailure); } }),
      (error) => error.code === 'SUB2API_GROUP_RESOLVE_FAILED'
        && error.message === '读取 Sub2API 分组失败'
        && !error.message.includes(opaqueGroupFailure),
    );

    process.env.SUB2API_GROUP_IDS = '9, 7,9';
    assert.deepEqual(await resolveGroupIds({ async listGroups() { throw new Error('unused'); } }), [7, 9]);
    assert.deepEqual(await resolveImportGroupBinding({
      async listGroups() { throw new Error('unused'); },
    }, createPlan), {
      mode: 'explicit',
      groupIds: [7, 9],
    });
    process.env.SUB2API_GROUP_IDS = '7,unsafe';
    await assert.rejects(
      resolveGroupIds({ async listGroups() { throw new Error('unused'); } }),
      (error) => error.code === 'SUB2API_GROUP_CONFIG_INVALID',
    );
  } finally {
    if (previousIds === undefined) delete process.env.SUB2API_GROUP_IDS;
    else process.env.SUB2API_GROUP_IDS = previousIds;
    if (previousName === undefined) delete process.env.SUB2API_GROUP_NAME;
    else process.env.SUB2API_GROUP_NAME = previousName;
  }
});

test('import rejects a named-group retarget before starting the job, backup, or write', async () => {
  const { root } = fixture();
  const previous = new Map([
    ['GPT_REGISTER_ROOT', process.env.GPT_REGISTER_ROOT],
    ['PANEL_WRITE_ENABLED', process.env.PANEL_WRITE_ENABLED],
    ['SUB2API_BASE_URL', process.env.SUB2API_BASE_URL],
    ['SUB2API_ADMIN_API_KEY', process.env.SUB2API_ADMIN_API_KEY],
    ['SUB2API_GROUP_IDS', process.env.SUB2API_GROUP_IDS],
    ['SUB2API_GROUP_NAME', process.env.SUB2API_GROUP_NAME],
  ]);
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.SUB2API_BASE_URL = 'http://127.0.0.1:18080';
  process.env.SUB2API_ADMIN_API_KEY = 'test-only-key';
  delete process.env.SUB2API_GROUP_IDS;
  process.env.SUB2API_GROUP_NAME = 'share';
  try {
    const previewClient = {
      async listAccounts() { return []; },
      async listGroups() { return [{ id: 7, name: 'share', platform: 'openai' }]; },
    };
    const preview = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
      rootDirectory: root,
      includeRaw: true,
      includeInternal: true,
      requireCompleteSources: true,
      client: previewClient,
    });
    const plan = buildImportPlan(preview._internal.sources, [], []);
    assert.equal(plan.length, 1);
    assert.equal(plan[0].action, 'create');
    const selectedKeys = [plan[0].key];
    const previewBinding = await resolveImportGroupBinding(previewClient, plan);
    assert.deepEqual(previewBinding, { mode: 'explicit', groupIds: [7] });
    const planIntentVersion = buildImportPlanIntentVersion(
      preview.version,
      selectedKeys,
      buildImportPlan(preview._internal.sources, [], selectedKeys),
      previewBinding,
    );

    let started = 0;
    let backups = 0;
    let writes = 0;
    let groupReads = 0;
    await assert.rejects(
      executeImport({
        snapshotVersion: preview.version,
        planIntentVersion,
        selectedKeys,
        actor: 'tester',
        jobId: 'group-retarget-job',
        db: {
          async startMutationJob() { started += 1; },
        },
        client: {
          async listAccounts() { return []; },
          async listGroups() {
            groupReads += 1;
            return [{ id: 8, name: 'share', platform: 'openai' }];
          },
          async exportAccounts() { backups += 1; return { accounts: [] }; },
          async importCodexSession() { writes += 1; },
          async applyOAuthCredentials() { writes += 1; },
        },
      }),
      (error) => error.code === 'IMPORT_PLAN_STALE',
    );
    assert.equal(groupReads, 1);
    assert.equal(started, 0);
    assert.equal(backups, 0);
    assert.equal(writes, 0);
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('OAuth update payload preserves refresh metadata without exposing it in summaries', () => {
  const accessToken = [
    'header',
    Buffer.from(JSON.stringify({
      'https://api.openai.com/auth': {
        chatgpt_plan_type: 'free',
        poid: 'organization-a',
      },
    })).toString('base64url'),
    'signature',
  ].join('.');
  const source = syntheticToken('tokens/refresh.json', ['account:account-a', 'user:user-a'], {
    accountId: 'account-a',
    userId: 'user-a',
    accessToken,
    refreshToken: 'refresh-value',
  });
  source.raw.client_id = 'untrusted-client-id';
  source.raw.scope = 'x'.repeat(5000);
  source.raw.token_type = 'Bearer\nunsafe';
  source.raw.organization_id = 'y'.repeat(513);
  const payload = buildOAuthUpdatePayload({
    _raw: source.raw,
    _record: source,
    email: source.email,
    expiresAt: source.expiresAt,
  });
  assert.equal(payload.credentials.refresh_token, 'refresh-value');
  assert.equal(typeof payload.credentials.client_id, 'string');
  assert.equal(payload.credentials.client_id.length > 0, true);
  assert.notEqual(payload.credentials.client_id, 'untrusted-client-id');
  assert.equal(Object.hasOwn(payload.credentials, 'scope'), false);
  assert.equal(Object.hasOwn(payload.credentials, 'token_type'), false);
  assert.equal(payload.credentials.plan_type, 'free');
  assert.equal(payload.credentials.organization_id, 'organization-a');
  assert.match(payload.extra.access_token_sha256, /^[a-f0-9]{64}$/);
  assert.match(payload.extra.refresh_token_sha256, /^[a-f0-9]{64}$/);
  assert.notEqual(payload.extra.access_token_sha256, payload.extra.refresh_token_sha256);
});

test('OAuth payload uses the same canonical token aliases as source validation', () => {
  const source = syntheticToken('tokens/camel-alias.json', ['account:alias-account'], {
    accountId: 'alias-account',
    accessToken: 'placeholder-access',
  });
  source.raw.access_token = '   ';
  source.raw.accessToken = 'camel-access-value';
  source.raw.refresh_token = '';
  source.raw.refreshToken = 'camel-refresh-value';
  source.raw.id_token = null;
  source.raw.idToken = 'camel-id-value';

  const payload = buildOAuthUpdatePayload({
    _raw: source.raw,
    _record: source,
    email: source.email,
    expiresAt: source.expiresAt,
  });
  assert.equal(payload.credentials.access_token, 'camel-access-value');
  assert.equal(payload.credentials.refresh_token, 'camel-refresh-value');
  assert.equal(payload.credentials.id_token, 'camel-id-value');

  source.raw.access_token = 'different-access-value';
  assert.throws(
    () => buildOAuthUpdatePayload({ _raw: source.raw, _record: source }),
    (error) => error.code === 'SOURCE_CREDENTIAL_SCHEMA_INVALID',
  );
});

test('update preflight refuses the remote write when its audit checkpoint is unavailable', async () => {
  const identityKeys = ['account:audit-update-account', 'user:audit-update-user'];
  const source = syntheticToken('tokens/audit-update.json', identityKeys, {
    accountId: 'audit-update-account',
    userId: 'audit-update-user',
    accessFingerprint: 'audit-update-new-fingerprint',
    accessToken: 'audit-update-secret-value',
  });
  const before = {
    id: 812,
    name: 'free00812',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys,
    tokenFingerprints: { access: 'audit-update-old-fingerprint' },
  };
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [before])[0];
  assert.equal(item.action, 'update');

  for (const mode of ['missing', 'failed']) {
    let preflightReads = 0;
    let writeCalls = 0;
    let checkpoint = null;
    const logger = mode === 'missing' ? {} : {
      checkpoint(event, fields) {
        assert.equal(preflightReads, 1, 'checkpoint must run after the final target preflight');
        checkpoint = { event, fields };
        return false;
      },
    };
    await assert.rejects(
      executeImportPlanItem({
        client: {
          async getAccount() {
            preflightReads += 1;
            return before;
          },
          async applyOAuthCredentials() {
            writeCalls += 1;
          },
        },
        item,
        logger,
        context: { jobId: 'audit-update-job', actor: 'tester' },
      }),
      (error) => error.code === 'AUDIT_LOG_UNAVAILABLE',
    );
    assert.equal(preflightReads, 1);
    assert.equal(writeCalls, 0);
    if (mode === 'failed') {
      assert.equal(checkpoint.event, 'import.oauth_update_checkpoint');
      assert.deepEqual(Object.keys(checkpoint.fields).sort(), [
        'accountId',
        'accountName',
        'action',
        'actor',
        'afterFingerprint',
        'beforeFingerprint',
        'jobId',
        'relativePath',
        'source',
      ]);
      assert.equal(JSON.stringify(checkpoint.fields).includes(source.raw.access_token), false);
    }
  }
});

test('create preflight refuses the remote write when its audit checkpoint is unavailable', async () => {
  const identityKeys = ['account:audit-create-account', 'user:audit-create-user'];
  const source = syntheticToken('tokens/audit-create.json', identityKeys, {
    accountId: 'audit-create-account',
    userId: 'audit-create-user',
    accessFingerprint: 'audit-create-fingerprint',
    accessToken: 'audit-create-secret-value',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  assert.equal(item.action, 'create');

  for (const mode of ['missing', 'failed']) {
    let preflightReads = 0;
    let writeCalls = 0;
    let checkpoint = null;
    const logger = mode === 'missing' ? {} : {
      checkpoint(event, fields) {
        assert.equal(preflightReads, 1, 'checkpoint must run after the final create preflight');
        checkpoint = { event, fields };
        return false;
      },
    };
    await assert.rejects(
      executeImportPlanItem({
        client: {
          async listAccounts() {
            preflightReads += 1;
            return [];
          },
          async importCodexSession() {
            writeCalls += 1;
          },
        },
        item,
        logger,
        context: { jobId: 'audit-create-job', actor: 'tester' },
      }),
      (error) => error.code === 'AUDIT_LOG_UNAVAILABLE',
    );
    assert.equal(preflightReads, 1);
    assert.equal(writeCalls, 0);
    if (mode === 'failed') {
      assert.equal(checkpoint.event, 'import.codex_create_checkpoint');
      assert.deepEqual(Object.keys(checkpoint.fields).sort(), [
        'accountId',
        'accountName',
        'action',
        'actor',
        'afterFingerprint',
        'beforeFingerprint',
        'jobId',
        'relativePath',
        'source',
      ]);
      assert.equal(JSON.stringify(checkpoint.fields).includes(source.raw.access_token), false);
    }
  }
});

test('update plan uses the ID-scoped OAuth endpoint and rechecks availability', async () => {
  const identityKeys = ['account:account-a', 'user:user-a', 'email:update@example.test'];
  const source = syntheticToken('tokens/update.json', identityKeys, {
    accountId: 'account-a',
    userId: 'user-a',
    email: 'update@example.test',
    accessFingerprint: 'new-fingerprint',
    accessToken: 'new-access-value',
  });
  const before = {
    id: 12,
    name: 'free00012',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys,
    tokenFingerprints: { access: 'old-fingerprint' },
  };
  const after = {
    ...before,
    status: 'active',
    schedulable: true,
    tokenFingerprints: { access: source.fingerprints.access },
  };
  const planItem = buildImportPlan({ tokens: [source], usernames: [] }, [before])[0];
  let reads = 0;
  let genericCalls = 0;
  const applied = [];
  const client = {
    async getAccount(id) {
      assert.equal(id, 12);
      reads += 1;
      return reads === 1 ? before : after;
    },
    async applyOAuthCredentials(id, payload) {
      applied.push({ id, payload });
      return after;
    },
    async importCodexSession() {
      genericCalls += 1;
      throw new Error('update must not use generic import');
    },
  };
  const outcome = await executeImportPlanItem({ client, item: planItem });
  assert.equal(outcome.skipped, false);
  assert.equal(outcome.verification.accountId, 12);
  assert.equal(applied.length, 1);
  assert.equal(applied[0].id, 12);
  assert.equal(Object.hasOwn(applied[0].payload.credentials, 'refresh_token'), false);
  assert.equal(typeof applied[0].payload.credentials.client_id, 'string');
  assert.equal(applied[0].payload.credentials.client_id.length > 0, true);
  assert.match(applied[0].payload.extra.access_token_sha256, /^[a-f0-9]{64}$/);
  assert.equal(genericCalls, 0);

  const availableClient = {
    async getAccount() { return { ...before, status: 'active', schedulable: true }; },
    async applyOAuthCredentials() { throw new Error('available target must be skipped'); },
  };
  const skipped = await executeImportPlanItem({ client: availableClient, item: planItem });
  assert.equal(skipped.skipped, true);
  assert.equal(skipped.reason, 'sub2api_available');

  let unknownUpdateCalls = 0;
  const unknownClient = {
    async getAccount() { return { ...before, status: '', statusKnown: false, schedulable: true }; },
    async applyOAuthCredentials() { unknownUpdateCalls += 1; },
  };
  const unknown = await executeImportPlanItem({ client: unknownClient, item: planItem });
  assert.equal(unknown.skipped, true);
  assert.equal(unknown.reason, 'sub2api_status_missing');
  assert.equal(unknownUpdateCalls, 0);

  let identityUpdateCalls = 0;
  const changedIdentityClient = {
    async getAccount() {
      return { ...before, identityKeys: ['account:different-account', 'user:different-user'] };
    },
    async applyOAuthCredentials() { identityUpdateCalls += 1; },
  };
  await assert.rejects(
    executeImportPlanItem({ client: changedIdentityClient, item: planItem }),
    (error) => error.code === 'SUB2API_TARGET_IDENTITY_MISMATCH',
  );
  assert.equal(identityUpdateCalls, 0);
});

test('update preflight does not treat matching access with an unverified refresh as synchronized', async () => {
  const identityKeys = ['account:refresh-account', 'user:refresh-user'];
  const source = syntheticToken('tokens/refresh-update.json', identityKeys, {
    accountId: 'refresh-account',
    userId: 'refresh-user',
    accessFingerprint: 'same-access-fingerprint',
    refreshFingerprint: 'new-refresh-fingerprint',
    accessToken: 'same-access-value',
    refreshToken: 'new-refresh-value',
  });
  const before = {
    id: 120,
    name: 'free00120',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys,
    tokenFingerprints: { access: source.fingerprints.access, refresh: null },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'unknown' },
  };
  const after = {
    ...before,
    tokenFingerprints: { ...source.fingerprints },
    credentialPresence: { access: 'present', refresh: 'present', id: 'unknown' },
  };
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [before])[0];
  assert.equal(item.action, 'update');
  let reads = 0;
  let mutations = 0;
  const outcome = await executeImportPlanItem({
    item,
    client: {
      async getAccount() {
        reads += 1;
        return reads === 1 ? before : after;
      },
      async applyOAuthCredentials(id, payload) {
        assert.equal(id, 120);
        assert.equal(payload.credentials.refresh_token, 'new-refresh-value');
        assert.match(payload.extra.refresh_token_sha256, /^[a-f0-9]{64}$/);
        mutations += 1;
      },
    },
  });
  assert.equal(outcome.skipped, false);
  assert.equal(mutations, 1);

  const raced = await executeImportPlanItem({
    item,
    client: {
      async getAccount() { return after; },
      async applyOAuthCredentials() { throw new Error('already synchronized target must not be mutated'); },
    },
  });
  assert.equal(raced.skipped, true);
  assert.equal(raced.reason, 'already_in_sync');
});

test('import plan rejects incomplete strong identity coverage in either direction', () => {
  const accountOnlySource = syntheticToken(
    'tokens/account-only.json',
    ['account:shared-account'],
    { accountId: 'shared-account', accessFingerprint: 'new-fingerprint' },
  );
  const plannedRemote = {
    id: 13,
    name: 'free00013',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: ['account:shared-account', 'user:planned-user'],
    tokenFingerprints: { access: 'old-fingerprint' },
  };
  const sourceMissingUser = buildImportPlan(
    { tokens: [accountOnlySource], usernames: [] },
    [plannedRemote],
  )[0];
  assert.equal(sourceMissingUser.action, 'conflict');
  assert.equal(sourceMissingUser.reason, 'ambiguous_sub2api_identity');
  assert.equal(sourceMissingUser.accountId, null);

  const completeSource = syntheticToken(
    'tokens/complete.json',
    ['account:shared-account', 'user:planned-user'],
    {
      accountId: 'shared-account',
      userId: 'planned-user',
      accessFingerprint: 'new-complete-fingerprint',
    },
  );
  const remoteMissingUser = buildImportPlan(
    { tokens: [completeSource], usernames: [] },
    [{ ...plannedRemote, userId: '', identityKeys: ['account:shared-account'] }],
  )[0];
  assert.equal(remoteMissingUser.action, 'conflict');
  assert.equal(remoteMissingUser.reason, 'ambiguous_sub2api_identity');
  assert.equal(remoteMissingUser.accountId, null);
});

test('final update preflight rejects a remote that loses a source identity dimension', async () => {
  const source = syntheticToken(
    'tokens/complete-preflight.json',
    ['account:preflight-account', 'user:preflight-user'],
    {
      accountId: 'preflight-account',
      userId: 'preflight-user',
      accessFingerprint: 'preflight-new-fingerprint',
    },
  );
  const before = {
    id: 121,
    name: 'free00121',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    accountId: 'preflight-account',
    userId: 'preflight-user',
    identityKeys: ['account:preflight-account', 'user:preflight-user'],
    tokenFingerprints: { access: 'preflight-old-fingerprint' },
  };
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [before])[0];
  assert.equal(item.action, 'update');
  let mutations = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      client: {
        async getAccount() {
          return {
            ...before,
            userId: '',
            identityKeys: ['account:preflight-account'],
          };
        },
        async applyOAuthCredentials() { mutations += 1; },
      },
    }),
    (error) => error.code === 'SUB2API_TARGET_IDENTITY_MISMATCH',
  );
  assert.equal(mutations, 0);
});

test('update preflight rejects a strong identity dimension added after planning', async () => {
  const source = syntheticToken(
    'tokens/planned-account-only.json',
    ['account:planned-account-only'],
    { accountId: 'planned-account-only', accessFingerprint: 'planned-new-fingerprint' },
  );
  const planned = {
    id: 122,
    name: 'free00122',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    accountId: 'planned-account-only',
    identityKeys: ['account:planned-account-only'],
    tokenFingerprints: { access: 'planned-old-fingerprint' },
  };
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [planned])[0];
  let mutations = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      client: {
        async getAccount() {
          return {
            ...planned,
            userId: 'identity-added-after-plan',
            identityKeys: [
              'account:planned-account-only',
              'user:identity-added-after-plan',
            ],
          };
        },
        async applyOAuthCredentials() { mutations += 1; },
      },
    }),
    (error) => error.code === 'SUB2API_TARGET_IDENTITY_MISMATCH',
  );
  assert.equal(mutations, 0);
});

test('aggregated source dimensions do not authorize an update to a partial remote', () => {
  const freshest = syntheticToken(
    'tokens/freshest-partial.json',
    ['account:aggregate-account'],
    {
      accountId: 'aggregate-account',
      accessFingerprint: 'aggregate-new-fingerprint',
      mtimeMs: 20,
    },
  );
  const older = syntheticToken(
    'use_token/older-complete.json',
    ['account:aggregate-account', 'user:aggregate-user'],
    {
      source: 'use_token',
      accountId: 'aggregate-account',
      userId: 'aggregate-user',
      accessFingerprint: 'aggregate-old-fingerprint',
      mtimeMs: 10,
    },
  );
  const before = {
    id: 123,
    name: 'free00123',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    accountId: 'aggregate-account',
    identityKeys: ['account:aggregate-account'],
    tokenFingerprints: { access: 'remote-old-fingerprint' },
  };
  const candidate = collectCandidates({ tokens: [freshest, older] })[0];
  assert.deepEqual(candidate.sourceIdentityKeys, ['account:aggregate-account']);
  assert.deepEqual(candidate.groupIdentityKeys, [
    'account:aggregate-account',
    'user:aggregate-user',
  ]);
  const plan = buildImportPlan({ tokens: [freshest, older], usernames: [] }, [before]);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].relativePath, freshest.relativePath);
  assert.deepEqual(plan[0].sourceIdentityKeys, ['account:aggregate-account']);
  assert.equal(plan[0].action, 'conflict');
  assert.equal(plan[0].reason, 'ambiguous_sub2api_identity');
  assert.equal(plan[0].accountId, null);

  const payload = buildOAuthUpdatePayload({ ...plan[0], _verifiedAccount: before });
  assert.equal(payload.credentials.chatgpt_account_id, 'aggregate-account');
  assert.equal(Object.hasOwn(payload.credentials, 'chatgpt_user_id'), false);
});

test('an older token cannot lend a missing strong identity to the freshest winner', () => {
  const freshest = syntheticToken(
    'tokens/freshest-user-only.json',
    ['user:winner-user'],
    {
      userId: 'winner-user',
      accessFingerprint: 'winner-new-fingerprint',
      accessToken: 'winner-test-access',
      mtimeMs: 20,
    },
  );
  const older = syntheticToken(
    'use_token/older-workspace.json',
    ['account:old-workspace', 'user:winner-user'],
    {
      source: 'use_token',
      accountId: 'old-workspace',
      userId: 'winner-user',
      accessFingerprint: 'older-fingerprint',
      mtimeMs: 10,
    },
  );
  const remote = {
    id: 124,
    name: 'free00124',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    accountId: 'old-workspace',
    userId: 'winner-user',
    identityKeys: ['account:old-workspace', 'user:winner-user'],
    tokenFingerprints: { access: 'remote-fingerprint' },
    credentialPresence: { access: 'present', refresh: 'unknown', id: 'unknown' },
  };

  const candidate = collectCandidates({ tokens: [freshest, older] })[0];
  assert.deepEqual(candidate.sourceIdentityKeys, ['user:winner-user']);
  assert.deepEqual(candidate.groupIdentityKeys, [
    'account:old-workspace',
    'user:winner-user',
  ]);
  assert.equal(candidate.identityKey, 'user:winner-user');

  const item = buildImportPlan({ tokens: [freshest, older], usernames: [] }, [remote])[0];
  assert.equal(item.relativePath, freshest.relativePath);
  assert.equal(item.action, 'conflict');
  assert.equal(item.reason, 'ambiguous_sub2api_identity');
  assert.equal(item.accountId, null);

  const payload = buildOAuthUpdatePayload({ ...item, _verifiedAccount: remote });
  assert.equal(Object.hasOwn(payload.credentials, 'chatgpt_account_id'), false);
  assert.equal(payload.credentials.chatgpt_user_id, 'winner-user');
});

test('source token changes after remote preflight block every mutation', async () => {
  const runScenario = async (changeSource) => {
    const { root } = fixture();
    const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
    const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
    const token = sources.tokens.find((item) => item.parseStatus === 'ok');
    const before = {
      id: 90,
      name: 'free00090',
      platform: 'openai',
      type: 'oauth',
      status: 'error',
      schedulable: false,
      identityKeys: token.identityKeys,
      tokenFingerprints: { access: 'old-fingerprint' },
    };
    const item = buildImportPlan(sources, [before])[0];
    let changed = false;
    let mutations = 0;
    const client = {
      async getAccount() {
        if (!changed) {
          changed = true;
          changeSource(root);
        }
        return before;
      },
      async applyOAuthCredentials() { mutations += 1; },
    };
    await assert.rejects(
      executeImportPlanItem({ client, item, sourceRoot: root }),
      (error) => error.code === 'SOURCE_TOKEN_CHANGED',
    );
    assert.equal(mutations, 0);
  };

  await runScenario((root) => {
    fs.writeFileSync(path.join(root, 'tokens', 'one.json'), JSON.stringify({
      access_token: 'replacement-access',
      refresh_token: 'replacement-refresh',
      account_id: 'a-1',
      user_id: 'u-1',
      email: 'one@example.test',
      type: 'codex',
    }));
  });

  await runScenario((root) => {
    fs.writeFileSync(path.join(root, 'use_token', 'new-winner.json'), JSON.stringify({
      access_token: 'newer-access',
      refresh_token: 'newer-refresh',
      account_id: 'a-1',
      user_id: 'u-1',
      email: 'one@example.test',
      last_refresh: '2099-01-01T00:00:00.000Z',
      type: 'codex',
    }));
  });
});

test('final remote preflight skips a target that becomes available before mutation', async () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const before = {
    id: 91,
    name: 'free00091',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: 'old-fingerprint' },
  };
  const available = { ...before, status: 'active', schedulable: true };
  const item = buildImportPlan(sources, [before])[0];
  let reads = 0;
  let mutations = 0;
  const outcome = await executeImportPlanItem({
    sourceRoot: root,
    item,
    client: {
      async getAccount() {
        reads += 1;
        return reads === 1 ? before : available;
      },
      async applyOAuthCredentials() { mutations += 1; },
    },
  });
  assert.equal(reads, 2);
  assert.equal(mutations, 0);
  assert.equal(outcome.skipped, true);
  assert.equal(outcome.reason, 'sub2api_available');
});

test('update preflight evaluates transient availability after the account GET resolves', async () => {
  const beforeReset = Date.parse('2030-01-01T00:00:00.000Z');
  const resetAt = '2030-01-01T00:00:01.000Z';
  const afterReset = Date.parse('2030-01-01T00:00:02.000Z');
  let currentTime = beforeReset;
  const identityKeys = ['account:clock-account', 'user:clock-user'];
  const source = syntheticToken('tokens/clock.json', identityKeys, {
    accountId: 'clock-account',
    userId: 'clock-user',
    accessFingerprint: 'clock-new-fingerprint',
    accessToken: 'clock-test-access',
  });
  const planned = {
    id: 125,
    name: 'free00125',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    identityKeys,
    tokenFingerprints: { access: 'clock-old-fingerprint' },
    credentialPresence: { access: 'present', refresh: 'unknown', id: 'unknown' },
  };
  const current = {
    ...planned,
    status: 'active',
    schedulable: true,
    rateLimitResetAt: resetAt,
    rateLimitResetStatus: 'valid',
  };
  const afterWrite = {
    ...current,
    tokenFingerprints: { access: source.fingerprints.access },
  };
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [planned])[0];
  assert.equal(item.action, 'update');
  let reads = 0;
  let writes = 0;
  const outcome = await executeImportPlanItem({
    item,
    now: () => currentTime,
    client: {
      async getAccount() {
        reads += 1;
        if (reads === 1) {
          currentTime = afterReset;
          return current;
        }
        return afterWrite;
      },
      async applyOAuthCredentials() { writes += 1; },
    },
  });
  assert.equal(reads, 1);
  assert.equal(writes, 0);
  assert.equal(outcome.skipped, true);
  assert.equal(outcome.reason, 'sub2api_available');
});

test('import plan items pass one cancellation signal through update and create requests', async () => {
  const controller = new AbortController();
  const signal = controller.signal;
  const updateIdentity = ['account:signal-update-account', 'user:signal-update-user'];
  const updateSource = syntheticToken('tokens/signal-update.json', updateIdentity, {
    accountId: 'signal-update-account',
    userId: 'signal-update-user',
    accessFingerprint: 'signal-update-new-fingerprint',
  });
  const updateBefore = {
    id: 301,
    name: 'free00301',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: updateIdentity,
    tokenFingerprints: { access: 'signal-update-old-fingerprint' },
  };
  const updateAfter = {
    ...updateBefore,
    tokenFingerprints: { access: updateSource.fingerprints.access },
  };
  const updateItem = buildImportPlan(
    { tokens: [updateSource], usernames: [] },
    [updateBefore],
  )[0];
  let updateReads = 0;
  let updateWrites = 0;
  await executeImportPlanItem({
    item: updateItem,
    signal,
    client: {
      async getAccount(id, options) {
        assert.equal(id, 301);
        assert.equal(options.signal, signal);
        updateReads += 1;
        return updateReads === 1 ? updateBefore : updateAfter;
      },
      async applyOAuthCredentials(id, payload, options) {
        assert.equal(id, 301);
        assert.equal(typeof payload.credentials.access_token, 'string');
        assert.equal(options.signal, signal);
        updateWrites += 1;
        return updateAfter;
      },
    },
  });
  assert.equal(updateReads, 2);
  assert.equal(updateWrites, 1);

  const createIdentity = ['account:signal-create-account', 'user:signal-create-user'];
  const createSource = syntheticToken('tokens/signal-create.json', createIdentity, {
    accountId: 'signal-create-account',
    userId: 'signal-create-user',
    accessFingerprint: 'signal-create-fingerprint',
  });
  const createItem = buildImportPlan({ tokens: [createSource], usernames: [] }, [])[0];
  const createdAccount = {
    id: 302,
    name: createItem.accountName,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys: createIdentity,
    tokenFingerprints: { ...createSource.fingerprints },
  };
  let createLists = 0;
  let createWrites = 0;
  let createReads = 0;
  await executeImportPlanItem({
    item: createItem,
    signal,
    context: { jobId: 'signal-create-job' },
    client: {
      async listAccounts(options) {
        assert.equal(options.signal, signal);
        assert.equal(options.requireTotal, true);
        assert.equal(options.requirePaginationMetadata, true);
        createLists += 1;
        return createLists === 1 ? [] : [createdAccount];
      },
      async importCodexSession(payload, options) {
        assert.equal(payload.update_existing, false);
        assert.equal(options.signal, signal);
        createWrites += 1;
        return {
          total: 1,
          created: 1,
          updated: 0,
          skipped: 0,
          failed: 0,
          items: [{ index: 0, action: 'created', account_id: 302 }],
        };
      },
      async getAccount(id, options) {
        assert.equal(id, 302);
        assert.equal(options.signal, signal);
        createReads += 1;
        return createdAccount;
      },
    },
  });
  assert.equal(createLists, 2);
  assert.equal(createWrites, 1);
  assert.equal(createReads, 1);
});

test('create cancellation after the POST starts no postflight request', async () => {
  const identityKeys = ['account:cancel-create-account', 'user:cancel-create-user'];
  const source = syntheticToken('tokens/cancel-create.json', identityKeys, {
    accountId: 'cancel-create-account',
    userId: 'cancel-create-user',
    accessFingerprint: 'cancel-create-fingerprint',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const controller = new AbortController();
  let listCalls = 0;
  let importCalls = 0;
  let postflightReads = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      signal: controller.signal,
      client: {
        async listAccounts(options) {
          assert.equal(options.signal, controller.signal);
          listCalls += 1;
          return [];
        },
        async importCodexSession(payload, options) {
          assert.equal(payload.update_existing, false);
          assert.equal(options.signal, controller.signal);
          importCalls += 1;
          controller.abort();
          return {
            total: 1,
            created: 1,
            updated: 0,
            skipped: 0,
            failed: 0,
            items: [{ index: 0, action: 'created', account_id: 303 }],
          };
        },
        async getAccount() {
          postflightReads += 1;
          throw new Error('postflight must not start after cancellation');
        },
      },
    }),
    (error) => error.code === 'JOB_INTERRUPTED'
      && error.writeOutcomeUnknown === true
      && error.requiresReconciliation === true,
  );
  assert.equal(listCalls, 1);
  assert.equal(importCalls, 1);
  assert.equal(postflightReads, 0);
});

test('update postflight failure requires reconciliation without retrying the mutation', async () => {
  const identityKeys = ['account:update-postflight-account', 'user:update-postflight-user'];
  const source = syntheticToken('tokens/update-postflight.json', identityKeys, {
    accountId: 'update-postflight-account',
    userId: 'update-postflight-user',
    accessFingerprint: 'update-postflight-new-fingerprint',
  });
  const before = {
    id: 304,
    name: 'free00304',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys,
    tokenFingerprints: { access: 'update-postflight-old-fingerprint' },
  };
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [before])[0];
  let reads = 0;
  let writes = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      client: {
        async getAccount() {
          reads += 1;
          if (reads === 1) return before;
          throw new Error('simulated update postflight failure');
        },
        async applyOAuthCredentials() {
          writes += 1;
          return { ...before, tokenFingerprints: { access: source.fingerprints.access } };
        },
      },
    }),
    (error) => error.requiresReconciliation === true
      && error.writeOutcomeUnknown === true,
  );
  assert.equal(writes, 1);
  assert.equal(reads, 4);
});

test('token import returns reconciliation details and never starts the next account', async () => {
  const { root } = fixture();
  const secondAccess = [
    'header',
    Buffer.from(JSON.stringify({
      sub: 'u-2',
      email: 'two@example.test',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'a-2',
        chatgpt_user_id: 'u-2',
      },
    })).toString('base64url'),
    'signature',
  ].join('.');
  fs.writeFileSync(path.join(root, 'tokens', 'two.json'), JSON.stringify({
    access_token: secondAccess,
    refresh_token: 'fixture-refresh-two',
    email: 'two@example.test',
  }));
  const backupRoot = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-import-abort-')),
    'backups',
  );
  fs.mkdirSync(backupRoot, { mode: 0o700 });
  const environment = {
    root: process.env.GPT_REGISTER_ROOT,
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    baseUrl: process.env.SUB2API_BASE_URL,
    apiKey: process.env.SUB2API_ADMIN_API_KEY,
    groupIds: process.env.SUB2API_GROUP_IDS,
    backupDirectory: process.env.PANEL_BACKUP_DIR,
  };
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.SUB2API_BASE_URL = 'http://127.0.0.1:18080';
  process.env.SUB2API_ADMIN_API_KEY = 'test-only-key';
  process.env.SUB2API_GROUP_IDS = '7';
  process.env.PANEL_BACKUP_DIR = backupRoot;
  try {
    const preview = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
      rootDirectory: root,
      includeRaw: true,
      includeInternal: true,
      client: { async listAccounts() { return []; } },
    });
    const selectedKeys = buildImportPlan(preview._internal.sources, [], [])
      .map((item) => item.key);
    assert.equal(selectedKeys.length, 2);
    const planIntentVersion = importPlanIntentForSnapshot(preview, selectedKeys, {
      mode: 'explicit',
      groupIds: [7],
    });

    const controller = new AbortController();
    let importCalls = 0;
    let postflightReads = 0;
    let importTerminalPersisted = false;
    let followerObservedImportTerminal = false;
    const audits = [];
    const client = {
      async listAccounts(options) {
        assert.equal(options.signal, controller.signal);
        return [];
      },
      async exportAccounts(ids, options) {
        assert.deepEqual(ids, []);
        assert.equal(options.signal, controller.signal);
        return { accounts: [] };
      },
      async importCodexSession(payload, options) {
        assert.equal(payload.update_existing, false);
        assert.equal(options.signal, controller.signal);
        importCalls += 1;
        controller.abort();
        return {
          total: 1,
          created: 1,
          updated: 0,
          skipped: 0,
          failed: 0,
          items: [{ index: 0, action: 'created', account_id: 401 }],
        };
      },
      async getAccount() {
        postflightReads += 1;
        throw new Error('postflight must not run after cancellation');
      },
    };
    const importRun = executeImport({
      snapshotVersion: preview.version,
      planIntentVersion,
      selectedKeys,
      actor: 'tester',
      db: {
        async startMutationJob() {},
        async updateJob() {},
        async audit(entry) { audits.push(entry); },
        async saveLink() {},
      },
      jobId: 'token-import-abort-job',
      signal: controller.signal,
      client,
      async persistResult(value) {
        assert.equal(value.requiresReconciliation, true);
        importTerminalPersisted = true;
      },
    });
    const importFollower = withControlPlaneLock(() => {
      followerObservedImportTerminal = importTerminalPersisted;
    });
    const result = await importRun;
    await importFollower;
    assert.equal(followerObservedImportTerminal, true);
    assert.equal(importCalls, 1);
    assert.equal(postflightReads, 0);
    assert.equal(result.halted, true);
    assert.equal(result.requiresReconciliation, true);
    assert.equal(result.reconciliationCount, 1);
    assert.equal(result.attempted, 1);
    assert.equal(result.failed, 1);
    assert.equal(result.imported[0].outcome, 'requires_reconciliation');
    assert.equal(result.imported[0].code, 'JOB_INTERRUPTED');
    assert.equal(result.imported[0].writeOutcomeUnknown, true);
    assert.equal(result.notAttemptedCount, 1);
    assert.equal(result.notAttempted[0].outcome, 'not_attempted');
    const reconciliationAudit = audits.find((entry) => entry.result === 'requires_reconciliation');
    assert.ok(reconciliationAudit);
    assert.equal(reconciliationAudit.afterFingerprint, null);

    const postflightController = new AbortController();
    let postflightImportCalls = 0;
    let failedPostflightReads = 0;
    const postflightResult = await executeImport({
      snapshotVersion: preview.version,
      planIntentVersion,
      selectedKeys,
      actor: 'tester',
      db: {
        async startMutationJob() {},
        async updateJob() {},
        async audit() {},
        async saveLink() {},
      },
      jobId: 'token-import-postflight-failure-job',
      signal: postflightController.signal,
      client: {
        async listAccounts(options) {
          assert.equal(options.signal, postflightController.signal);
          return [];
        },
        async exportAccounts(ids, options) {
          assert.deepEqual(ids, []);
          assert.equal(options.signal, postflightController.signal);
          return { accounts: [] };
        },
        async importCodexSession(payload, options) {
          assert.equal(payload.update_existing, false);
          assert.equal(options.signal, postflightController.signal);
          postflightImportCalls += 1;
          return {
            total: 1,
            created: 1,
            updated: 0,
            skipped: 0,
            failed: 0,
            items: [{ index: 0, action: 'created', account_id: 402 }],
          };
        },
        async getAccount(id, options) {
          assert.equal(id, 402);
          assert.equal(options.signal, postflightController.signal);
          failedPostflightReads += 1;
          throw new Error('simulated postflight read failure');
        },
      },
    });
    assert.equal(postflightImportCalls, 1);
    assert.equal(failedPostflightReads, 3);
    assert.equal(postflightResult.requiresReconciliation, true);
    assert.equal(postflightResult.imported[0].outcome, 'requires_reconciliation');
    assert.equal(postflightResult.notAttemptedCount, 1);
    assert.equal(postflightResult.notAttempted[0].outcome, 'not_attempted');
  } finally {
    for (const [name, value] of [
      ['GPT_REGISTER_ROOT', environment.root],
      ['PANEL_WRITE_ENABLED', environment.writeEnabled],
      ['SUB2API_BASE_URL', environment.baseUrl],
      ['SUB2API_ADMIN_API_KEY', environment.apiKey],
      ['SUB2API_GROUP_IDS', environment.groupIds],
      ['PANEL_BACKUP_DIR', environment.backupDirectory],
    ]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('import rejects a time-only plan change before marking the job running or writing remotely', async () => {
  const { root } = fixture();
  const previous = new Map([
    ['GPT_REGISTER_ROOT', process.env.GPT_REGISTER_ROOT],
    ['PANEL_WRITE_ENABLED', process.env.PANEL_WRITE_ENABLED],
    ['SUB2API_BASE_URL', process.env.SUB2API_BASE_URL],
    ['SUB2API_ADMIN_API_KEY', process.env.SUB2API_ADMIN_API_KEY],
  ]);
  const originalNow = Date.now;
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.SUB2API_BASE_URL = 'http://127.0.0.1:18080';
  process.env.SUB2API_ADMIN_API_KEY = 'test-only-key';
  try {
    const beforeExpiry = Date.parse('2029-12-31T23:59:00.000Z');
    const afterExpiry = Date.parse('2030-01-01T00:01:00.000Z');
    const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
    const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
    const token = sources.tokens.find((item) => item.parseStatus === 'ok');
    const remote = {
      id: 803,
      name: 'free00803',
      platform: 'openai',
      type: 'oauth',
      status: 'active',
      statusKnown: true,
      schedulable: true,
      schedulableKnown: true,
      schemaValid: true,
      autoPauseOnExpired: true,
      expiresAt: '2030-01-01T00:00:00.000Z',
      expiryStatus: 'valid',
      identityKeys: token.identityKeys,
      tokenFingerprints: { access: 'different-access' },
      credentialPresence: { access: 'present', refresh: 'unknown', id: 'unknown' },
      groupIds: [],
    };
    Date.now = () => beforeExpiry;
    const preview = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
      rootDirectory: root,
      includeRaw: true,
      includeInternal: true,
      requireCompleteSources: true,
      client: { async listAccounts() { return [remote]; } },
    });
    const unfilteredPlan = buildImportPlan(
      preview._internal.sources,
      preview._internal.accounts,
      [],
    );
    const selectedKeys = [unfilteredPlan[0].key];
    const previewPlan = buildImportPlan(
      preview._internal.sources,
      preview._internal.accounts,
      selectedKeys,
    );
    assert.equal(previewPlan[0].action, 'skip');
    assert.equal(previewPlan[0].reason, 'sub2api_available');
    const planIntentVersion = buildImportPlanIntentVersion(
      preview.version,
      selectedKeys,
      previewPlan,
    );

    Date.now = () => afterExpiry;
    let started = 0;
    let backups = 0;
    let writes = 0;
    await assert.rejects(
      executeImport({
        snapshotVersion: preview.version,
        planIntentVersion,
        selectedKeys,
        actor: 'tester',
        jobId: 'time-plan-stale-job',
        db: {
          async startMutationJob() { started += 1; },
        },
        client: {
          async listAccounts() { return [remote]; },
          async exportAccounts() { backups += 1; return { accounts: [], proxies: [] }; },
          async applyOAuthCredentials() { writes += 1; },
          async importCodexSession() { writes += 1; },
        },
      }),
      (error) => error.code === 'IMPORT_PLAN_STALE',
    );
    assert.equal(started, 0);
    assert.equal(backups, 0);
    assert.equal(writes, 0);
  } finally {
    Date.now = originalNow;
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('create verification consumes the nested Codex import account ID', async () => {
  const identityKeys = ['account:new-account', 'user:new-user'];
  const source = syntheticToken('tokens/new.json', identityKeys, {
    accountId: 'new-account',
    userId: 'new-user',
    accessFingerprint: 'new-create-fp',
    refreshFingerprint: 'new-create-refresh-fp',
    refreshToken: 'new-create-refresh-value',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  source.raw.credentials = { access_token: 'nested-import-value' };
  source.raw.unknown = { credential: 'nested-unknown-value' };
  let genericCalls = 0;
  let importPayload = null;
  let importOptions = null;
  let listCalls = 0;
  const createdAccount = {
    id: 42,
    name: item.accountName,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys,
    tokenFingerprints: { ...source.fingerprints },
    credentialPresence: { access: 'present', refresh: 'present', id: 'unknown' },
  };
  const client = {
    async listAccounts(options) {
      listCalls += 1;
      if (listCalls > 1) {
        assert.equal(options.sortBy, 'id');
        assert.equal(options.sortOrder, 'asc');
        assert.equal(Object.hasOwn(options, 'platform'), false);
        assert.equal(Object.hasOwn(options, 'type'), false);
      }
      return listCalls === 1 ? [] : [createdAccount];
    },
    async importCodexSession(payload, options) {
      genericCalls += 1;
      importPayload = payload;
      importOptions = options;
      return {
        total: 1,
        created: 1,
        updated: 0,
        skipped: 0,
        failed: 0,
        items: [{ index: 0, action: 'created', account_id: 42 }],
      };
    },
    async getAccount(id) {
      assert.equal(id, 42);
      return createdAccount;
    },
    async applyOAuthCredentials() { throw new Error('create must not use ID-scoped update'); },
  };
  const outcome = await executeImportPlanItem({
    client,
    item,
    groups: [3],
    context: { jobId: 'create-verification-job' },
  });
  assert.equal(genericCalls, 1);
  assert.equal(listCalls, 2);
  assert.equal(importPayload.update_existing, false);
  assert.equal(importPayload.content.includes('nested-import-value'), false);
  assert.equal(importPayload.content.includes('nested-unknown-value'), false);
  const importDocument = JSON.parse(importPayload.content);
  assert.equal(importDocument.expires_at, source.expiresAt);
  assert.equal(Object.hasOwn(importDocument, 'expired'), false);
  assert.match(importPayload.extra.refresh_token_sha256, /^[a-f0-9]{64}$/);
  assert.match(importOptions.idempotencyKey, /^gptreg-create-v2-[a-f0-9]{64}$/);
  assert.equal(importOptions.idempotencyKey.includes(source.raw.access_token), false);
  assert.equal(importOptions.idempotencyKey.includes(source.raw.refresh_token), false);
  assert.equal(outcome.result.accountId, 42);
  assert.equal(outcome.verification.accountId, 42);

  await assert.rejects(
    executeImportPlanItem({
      client: {
        async listAccounts() { return []; },
        async importCodexSession(payload) {
          assert.equal(payload.update_existing, false);
          // Even a buggy or concurrently raced remote must not be accepted as
          // a successful create when it reports that an existing row changed.
          return {
            total: 1,
            created: 0,
            updated: 1,
            skipped: 0,
            failed: 0,
            items: [{ index: 0, action: 'updated', account_id: 99 }],
          };
        },
      },
      item,
      groups: [3],
    }),
    (error) => error.code === 'SUB2API_CREATE_ACTION_MISMATCH',
  );

  await assert.rejects(
    executeImportPlanItem({
      client: {
        async listAccounts() { return []; },
        async importCodexSession() {
          return {
            total: 2,
            created: 1,
            updated: 0,
            skipped: 0,
            failed: 0,
            items: [{ index: 0, action: 'created', account_id: 43 }],
          };
        },
      },
      item,
    }),
    (error) => error.code === 'SUB2API_CREATE_ACTION_MISMATCH',
  );

  await assert.rejects(
    executeImportPlanItem({
      client: {
        async listAccounts() {
          return [{
            id: 44,
            name: 'free00044',
            platform: 'openai',
            type: 'oauth',
            status: 'active',
            schedulable: true,
            identityKeys: ['account:unrelated', 'user:unrelated'],
            tokenFingerprints: { access: 'unrelated' },
          }];
        },
        async importCodexSession() {
          return {
            total: 1,
            created: 1,
            updated: 0,
            skipped: 0,
            failed: 0,
            items: [{ index: 0, action: 'created', account_id: 44 }],
          };
        },
      },
      item,
    }),
    (error) => error.code === 'SUB2API_CREATE_ACTION_MISMATCH',
  );
});

test('create responses require exact numeric counters, one raw item, and consistent ids', async () => {
  const identityKeys = ['account:strict-create-account', 'user:strict-create-user'];
  const source = syntheticToken('tokens/strict-create.json', identityKeys, {
    accountId: 'strict-create-account',
    userId: 'strict-create-user',
    accessFingerprint: 'strict-create-fingerprint',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const valid = {
    total: 1,
    created: 1,
    updated: 0,
    skipped: 0,
    failed: 0,
    items: [{ index: 0, action: 'created', account_id: 501 }],
  };
  const malformedResults = [
    { ...valid, total: undefined },
    { ...valid, created: '1' },
    { ...valid, failed: false },
    { ...valid, items: [null, ...valid.items] },
    { ...valid, items: [{ ...valid.items[0], account_id: '501' }] },
    { ...valid, account_id: 502 },
    { ...valid, accountId: '501' },
    { ...valid, items: [{ ...valid.items[0], accountId: 502 }] },
  ];
  for (const result of malformedResults) {
    await assert.rejects(
      executeImportPlanItem({
        item,
        client: {
          async listAccounts() { return []; },
          async importCodexSession() { return result; },
          async getAccount() { throw new Error('strict validation must precede postflight'); },
        },
      }),
      (error) => error.code === 'SUB2API_CREATE_ACTION_MISMATCH'
        && error.requiresReconciliation === true
        && error.writeOutcomeUnknown === true,
    );
  }
});

test('create postflight retries only bounded complete reads and never retries the write', async () => {
  const identityKeys = ['account:retry-create-account', 'user:retry-create-user'];
  const source = syntheticToken('tokens/retry-create.json', identityKeys, {
    accountId: 'retry-create-account',
    userId: 'retry-create-user',
    accessFingerprint: 'retry-create-fingerprint',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const account = {
    id: 511,
    name: item.accountName,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys,
    tokenFingerprints: { ...source.fingerprints },
  };
  const controller = new AbortController();
  let writeCalls = 0;
  let detailReads = 0;
  let completeLists = 0;
  let listCalls = 0;
  const outcome = await executeImportPlanItem({
    item,
    signal: controller.signal,
    client: {
      async listAccounts(options) {
        assert.equal(options.signal, controller.signal);
        assert.equal(options.requireTotal, true);
        assert.equal(options.requirePaginationMetadata, true);
        listCalls += 1;
        if (listCalls === 1) return [];
        completeLists += 1;
        if (completeLists < 3) throw new Error('temporary complete-list failure');
        return [account];
      },
      async importCodexSession(payload, options) {
        assert.equal(options.signal, controller.signal);
        writeCalls += 1;
        return {
          total: 1,
          created: 1,
          updated: 0,
          skipped: 0,
          failed: 0,
          items: [{ index: 0, action: 'created', account_id: 511 }],
        };
      },
      async getAccount(id, options) {
        assert.equal(id, 511);
        assert.equal(options.signal, controller.signal);
        detailReads += 1;
        if (detailReads < 3) throw new Error('temporary detail failure');
        return account;
      },
    },
  });
  assert.equal(outcome.verification.accountId, 511);
  assert.equal(writeCalls, 1);
  assert.equal(detailReads, 3);
  assert.equal(completeLists, 3);
});

test('create postflight fails closed on a concurrent duplicate strong identity', async () => {
  const identityKeys = ['account:race-account', 'user:race-user'];
  const source = syntheticToken('tokens/race-identity.json', identityKeys, {
    accountId: 'race-account',
    userId: 'race-user',
    accessFingerprint: 'race-create-fingerprint',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const created = {
    id: 51,
    name: item.accountName,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys,
    tokenFingerprints: { ...source.fingerprints },
  };
  let listCalls = 0;
  let importCalls = 0;
  let deletionCalls = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      context: { jobId: 'identity-race-job' },
      client: {
        async listAccounts() {
          listCalls += 1;
          return listCalls === 1
            ? []
            : [created, { ...created, id: 52, name: 'free00052' }];
        },
        async importCodexSession(payload, options) {
          importCalls += 1;
          assert.equal(payload.update_existing, false);
          assert.match(options.idempotencyKey, /^gptreg-create-v2-/);
          return {
            total: 1,
            created: 1,
            updated: 0,
            skipped: 0,
            failed: 0,
            items: [{ index: 0, action: 'created', account_id: 51 }],
          };
        },
        async getAccount() { return created; },
        async deleteAccount() { deletionCalls += 1; },
      },
    }),
    (error) => error.code === 'SUB2API_CREATE_RACE_IDENTITY_CONFLICT',
  );
  assert.equal(listCalls, 2);
  assert.equal(importCalls, 1);
  assert.equal(deletionCalls, 0);
});

test('create postflight fails closed when the allocated free name is no longer unique', async () => {
  const identityKeys = ['account:name-race-account', 'user:name-race-user'];
  const source = syntheticToken('tokens/race-name.json', identityKeys, {
    accountId: 'name-race-account',
    userId: 'name-race-user',
    accessFingerprint: 'name-race-create-fingerprint',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const created = {
    id: 61,
    name: item.accountName,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys,
    tokenFingerprints: { ...source.fingerprints },
  };
  let listCalls = 0;
  let importCalls = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      context: { jobId: 'name-race-job' },
      client: {
        async listAccounts() {
          listCalls += 1;
          return listCalls === 1
            ? []
            : [
                created,
                {
                  ...created,
                  id: 62,
                  name: item.accountName.toUpperCase(),
                  platform: 'anthropic',
                  type: 'apikey',
                  identityKeys: ['account:unrelated-account', 'user:unrelated-user'],
                },
              ];
        },
        async importCodexSession() {
          importCalls += 1;
          return {
            total: 1,
            created: 1,
            updated: 0,
            skipped: 0,
            failed: 0,
            items: [{ index: 0, action: 'created', account_id: 61 }],
          };
        },
        async getAccount() { return created; },
      },
    }),
    (error) => error.code === 'SUB2API_CREATE_RACE_NAME_CONFLICT',
  );
  assert.equal(listCalls, 2);
  assert.equal(importCalls, 1);
});

test('create verification rejects malformed or non-OpenAI OAuth target rows', async () => {
  const identityKeys = ['account:kind-account', 'user:kind-user'];
  const source = syntheticToken('tokens/create-kind.json', identityKeys, {
    accountId: 'kind-account',
    userId: 'kind-user',
    accessFingerprint: 'kind-create-fingerprint',
  });
  const item = buildImportPlan({ tokens: [source], usernames: [] }, [])[0];
  const baseAccount = {
    id: 71,
    name: item.accountName,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    identityKeys,
    tokenFingerprints: { ...source.fingerprints },
  };
  for (const { replacement, expectedCode } of [
    {
      replacement: { ...baseAccount, type: 'apikey' },
      expectedCode: 'SUB2API_TARGET_KIND_MISMATCH',
    },
    {
      replacement: { ...baseAccount, schemaValid: false },
      expectedCode: 'SUB2API_TARGET_SCHEMA_INVALID',
    },
  ]) {
    let listCalls = 0;
    let importCalls = 0;
    await assert.rejects(
      executeImportPlanItem({
        item,
        context: { jobId: 'create-target-schema-job-' + expectedCode },
        client: {
          async listAccounts() {
            listCalls += 1;
            return [];
          },
          async importCodexSession() {
            importCalls += 1;
            return {
              total: 1,
              created: 1,
              updated: 0,
              skipped: 0,
              failed: 0,
              items: [{ index: 0, action: 'created', account_id: 71 }],
            };
          },
          async getAccount() { return replacement; },
        },
      }),
      (error) => error.code === expectedCode,
    );
    assert.equal(listCalls, 1);
    assert.equal(importCalls, 1);
  }
});

test('credential backups require a private directory and enforce file retention', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backups-'));
  const backupDir = path.join(root, 'private');
  fs.mkdirSync(backupDir, { mode: 0o700 });
  const previous = {
    directory: process.env.PANEL_BACKUP_DIR,
    files: process.env.PANEL_BACKUP_MAX_FILES,
    bytes: process.env.PANEL_BACKUP_MAX_TOTAL_BYTES,
  };
  process.env.PANEL_BACKUP_DIR = backupDir;
  process.env.PANEL_BACKUP_MAX_FILES = '2';
  process.env.PANEL_BACKUP_MAX_TOTAL_BYTES = String(1024 * 1024);
  try {
    for (let index = 0; index < 3; index += 1) {
      const filePath = writeBackup({ index, credentials: 'fake-backup-value-' + index });
      assert.equal(path.dirname(filePath), backupDir);
      assert.equal(fs.statSync(filePath).mode & 0o077, 0);
    }
    assert.equal(fs.readdirSync(backupDir).filter((name) => name.endsWith('.json')).length, 2);
    fs.chmodSync(backupDir, 0o777);
    assert.throws(
      () => writeBackup({ index: 4 }),
      (error) => error.code === 'SUB2API_BACKUP_PERMISSIONS_INVALID',
    );
  } finally {
    fs.chmodSync(backupDir, 0o700);
    for (const [key, value] of Object.entries(previous)) {
      const name = {
        directory: 'PANEL_BACKUP_DIR',
        files: 'PANEL_BACKUP_MAX_FILES',
        bytes: 'PANEL_BACKUP_MAX_TOTAL_BYTES',
      }[key];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('credential backup pruning stops before deletion when its bounded scan is exhausted', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backup-scan-'));
  const backupDir = path.join(root, 'private');
  fs.mkdirSync(backupDir, { mode: 0o700 });
  const oldName = 'sub2api-2000-01-01T00-00-00-000Z-old.json';
  const oldPath = path.join(backupDir, oldName);
  fs.writeFileSync(oldPath, '{}', { mode: 0o600 });
  const previous = new Map([
    ['PANEL_BACKUP_DIR', process.env.PANEL_BACKUP_DIR],
    ['PANEL_BACKUP_MAX_FILES', process.env.PANEL_BACKUP_MAX_FILES],
    ['PANEL_BACKUP_MAX_TOTAL_BYTES', process.env.PANEL_BACKUP_MAX_TOTAL_BYTES],
  ]);
  const originalOpendirSync = fs.opendirSync;
  let fakeDirectoryClosed = false;
  process.env.PANEL_BACKUP_DIR = backupDir;
  process.env.PANEL_BACKUP_MAX_FILES = '1';
  process.env.PANEL_BACKUP_MAX_TOTAL_BYTES = String(1024 * 1024);
  fs.opendirSync = function boundedBackupDirectoryScan(directoryPath, ...args) {
    const text = String(directoryPath);
    if (text === backupDir || text.startsWith('/proc/self/fd/')) {
      let reads = 0;
      return {
        readSync() {
          reads += 1;
          return reads <= 20_001 ? { name: 'unrelated-entry-' + reads } : null;
        },
        closeSync() { fakeDirectoryClosed = true; },
      };
    }
    return originalOpendirSync.call(fs, directoryPath, ...args);
  };
  try {
    assert.throws(
      () => writeBackup({ accounts: [], proxies: [] }),
      (error) => error.code === 'SUB2API_BACKUP_SCAN_LIMIT_EXCEEDED',
    );
  } finally {
    fs.opendirSync = originalOpendirSync;
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
  assert.equal(fakeDirectoryClosed, true);
  assert.equal(fs.existsSync(oldPath), true);
  assert.equal(fs.readdirSync(backupDir).filter((name) => name.endsWith('.json')).length, 2);
});

test('a durably published credential backup survives post-retention fsync failure', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backup-fsync-'));
  const backupDir = path.join(root, 'private');
  fs.mkdirSync(backupDir, { mode: 0o700 });
  const previousDirectory = process.env.PANEL_BACKUP_DIR;
  const originalFsyncSync = fs.fsyncSync;
  let directoryFsyncs = 0;
  process.env.PANEL_BACKUP_DIR = backupDir;
  fs.fsyncSync = function failPostRetentionFsync(descriptor) {
    if (fs.fstatSync(descriptor).isDirectory()) {
      directoryFsyncs += 1;
      if (directoryFsyncs === 2) {
        const error = new Error('simulated backup directory fsync failure');
        error.code = 'EIO';
        throw error;
      }
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    assert.throws(
      () => writeBackup({ accounts: [], proxies: [] }),
      (error) => error.code === 'EIO',
    );
  } finally {
    fs.fsyncSync = originalFsyncSync;
    if (previousDirectory === undefined) delete process.env.PANEL_BACKUP_DIR;
    else process.env.PANEL_BACKUP_DIR = previousDirectory;
  }
  assert.equal(directoryFsyncs, 2);
  assert.equal(fs.readdirSync(backupDir).filter((name) => name.endsWith('.json')).length, 1);
});

test('credential backup retention reports deletion failure and keeps the fresh backup', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backup-unlink-'));
  const backupDir = path.join(root, 'private');
  fs.mkdirSync(backupDir, { mode: 0o700 });
  const oldName = 'sub2api-2000-01-01T00-00-00-000Z-old.json';
  const oldPath = path.join(backupDir, oldName);
  fs.writeFileSync(oldPath, '{}', { mode: 0o600 });
  const previous = new Map([
    ['PANEL_BACKUP_DIR', process.env.PANEL_BACKUP_DIR],
    ['PANEL_BACKUP_MAX_FILES', process.env.PANEL_BACKUP_MAX_FILES],
    ['PANEL_BACKUP_MAX_TOTAL_BYTES', process.env.PANEL_BACKUP_MAX_TOTAL_BYTES],
  ]);
  const originalUnlinkSync = fs.unlinkSync;
  process.env.PANEL_BACKUP_DIR = backupDir;
  process.env.PANEL_BACKUP_MAX_FILES = '1';
  process.env.PANEL_BACKUP_MAX_TOTAL_BYTES = String(1024 * 1024);
  fs.unlinkSync = function failOldBackupDeletion(filePath, ...args) {
    if (path.basename(String(filePath)) === oldName) {
      const error = new Error('simulated old backup deletion failure');
      error.code = 'EACCES';
      throw error;
    }
    return originalUnlinkSync.call(fs, filePath, ...args);
  };
  try {
    assert.throws(
      () => writeBackup({ accounts: [], proxies: [] }),
      (error) => error.code === 'SUB2API_BACKUP_RETENTION_FAILED',
    );
  } finally {
    fs.unlinkSync = originalUnlinkSync;
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
  assert.equal(fs.existsSync(oldPath), true);
  assert.equal(fs.readdirSync(backupDir).filter((name) => name.endsWith('.json')).length, 2);
});

test('credential backup retention rechecks limits after cleanup', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backup-recheck-'));
  const backupDir = path.join(root, 'private');
  fs.mkdirSync(backupDir, { mode: 0o700 });
  const oldName = 'sub2api-2000-01-01T00-00-00-000Z-old.json';
  const injectedName = 'sub2api-2099-01-01T00-00-00-000Z-concurrent.json';
  const oldPath = path.join(backupDir, oldName);
  const injectedPath = path.join(backupDir, injectedName);
  fs.writeFileSync(oldPath, '{}', { mode: 0o600 });
  const previous = new Map([
    ['PANEL_BACKUP_DIR', process.env.PANEL_BACKUP_DIR],
    ['PANEL_BACKUP_MAX_FILES', process.env.PANEL_BACKUP_MAX_FILES],
    ['PANEL_BACKUP_MAX_TOTAL_BYTES', process.env.PANEL_BACKUP_MAX_TOTAL_BYTES],
  ]);
  const originalUnlinkSync = fs.unlinkSync;
  process.env.PANEL_BACKUP_DIR = backupDir;
  process.env.PANEL_BACKUP_MAX_FILES = '1';
  process.env.PANEL_BACKUP_MAX_TOTAL_BYTES = String(1024 * 1024);
  fs.unlinkSync = function injectAfterOldBackupDeletion(filePath, ...args) {
    const result = originalUnlinkSync.call(fs, filePath, ...args);
    if (path.basename(String(filePath)) === oldName) {
      fs.writeFileSync(injectedPath, '{}', { mode: 0o600 });
    }
    return result;
  };
  try {
    assert.throws(
      () => writeBackup({ accounts: [], proxies: [] }),
      (error) => error.code === 'SUB2API_BACKUP_RETENTION_FAILED',
    );
  } finally {
    fs.unlinkSync = originalUnlinkSync;
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
  assert.equal(fs.existsSync(oldPath), false);
  assert.equal(fs.existsSync(injectedPath), true);
  assert.equal(fs.readdirSync(backupDir).filter((name) => name.endsWith('.json')).length, 2);
});

test('credential backup size preflight never deletes an existing backup', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backup-preflight-'));
  const backupDir = path.join(root, 'private');
  fs.mkdirSync(backupDir, { mode: 0o700 });
  const oldName = 'sub2api-2000-01-01T00-00-00-000Z-old.json';
  const oldPath = path.join(backupDir, oldName);
  fs.writeFileSync(oldPath, '{}', { mode: 0o600 });
  const previous = new Map([
    ['PANEL_BACKUP_DIR', process.env.PANEL_BACKUP_DIR],
    ['PANEL_BACKUP_MAX_FILES', process.env.PANEL_BACKUP_MAX_FILES],
    ['PANEL_BACKUP_MAX_TOTAL_BYTES', process.env.PANEL_BACKUP_MAX_TOTAL_BYTES],
  ]);
  process.env.PANEL_BACKUP_DIR = backupDir;
  process.env.PANEL_BACKUP_MAX_FILES = '1';
  process.env.PANEL_BACKUP_MAX_TOTAL_BYTES = String(1024 * 1024);
  try {
    assert.throws(
      () => writeBackup({ padding: 'x'.repeat(1024 * 1024) }),
      (error) => error.code === 'SUB2API_BACKUP_LIMIT_EXCEEDED',
    );
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
  assert.equal(fs.existsSync(oldPath), true);
  assert.deepEqual(fs.readdirSync(backupDir), [oldName]);
});

test('credential backups uniquely cover every update target with restorable identity and tokens', () => {
  const oldAccess = 'test-only-backup-old-access';
  const oldRefresh = 'test-only-backup-old-refresh';
  const plannedAccount = {
    id: 412,
    name: 'free00412',
    platform: 'openai',
    type: 'oauth',
    identityKeys: ['account:backup-account-412', 'user:backup-user-412'],
    tokenFingerprints: {
      access: tokenFingerprint(oldAccess),
      refresh: tokenFingerprint(oldRefresh),
      id: null,
    },
    credentialPresence: { access: 'present', refresh: 'present', id: 'absent' },
  };
  const item = {
    action: 'update',
    accountId: 412,
    accountName: plannedAccount.name,
    _account: plannedAccount,
  };
  const backupAccount = () => ({
    name: plannedAccount.name,
    platform: 'openai',
    type: 'oauth',
    credentials: {
      chatgpt_account_id: 'backup-account-412',
      chatgpt_user_id: 'backup-user-412',
      access_token: oldAccess,
      refresh_token: oldRefresh,
    },
  });
  const payload = () => ({ accounts: [backupAccount()], proxies: [] });

  assert.deepEqual(assertBackupCoversUpdateTargets(payload(), [item]), {
    updateTargetCount: 1,
  });
  assert.deepEqual(assertBackupCoversUpdateTargets({ accounts: [], proxies: [] }, [{ action: 'create' }]), {
    updateTargetCount: 0,
  });

  const malformedPayloads = [
    { accounts: [], proxies: [] },
    { accounts: [{ ...backupAccount(), name: 'free00413' }], proxies: [] },
    {
      accounts: [{
        ...backupAccount(),
        credentials: { ...backupAccount().credentials, chatgpt_user_id: undefined },
      }],
      proxies: [],
    },
    {
      accounts: [{
        ...backupAccount(),
        credentials: { ...backupAccount().credentials, access_token: 'replacement-access' },
      }],
      proxies: [],
    },
    {
      accounts: [{
        ...backupAccount(),
        credentials: { ...backupAccount().credentials, refresh_token: undefined },
      }],
      proxies: [],
    },
    { accounts: [backupAccount(), backupAccount()], proxies: [] },
    {
      accounts: [{
        ...backupAccount(),
        credentials: { ...backupAccount().credentials, account_id: 'contradictory-account' },
      }],
      proxies: [],
    },
    { accounts: [{ ...backupAccount(), type: 'api_key' }], proxies: [] },
  ];
  for (const exported of malformedPayloads) {
    assert.throws(
      () => assertBackupCoversUpdateTargets(exported, [item]),
      (error) => error.code === 'SUB2API_BACKUP_COVERAGE_INVALID'
        && !error.message.includes(oldAccess)
        && !error.message.includes(oldRefresh),
    );
  }

  assert.throws(
    () => assertBackupCoversUpdateTargets(payload(), [item, { ...item }]),
    (error) => error.code === 'SUB2API_BACKUP_COVERAGE_INVALID',
  );
});

test('token import rejects an uncovered update backup before any remote write', async () => {
  const { root } = fixture();
  const backupRoot = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backup-coverage-')),
    'backups',
  );
  fs.mkdirSync(backupRoot, { mode: 0o700 });
  const remote = {
    id: 413,
    name: 'free00413',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    schemaValid: true,
    accountId: 'a-1',
    userId: 'u-1',
    identityKeys: ['account:a-1', 'user:u-1', 'email:one@example.test'],
    tokenFingerprints: {
      access: tokenFingerprint('test-only-older-remote-access'),
      refresh: tokenFingerprint('test-only-older-remote-refresh'),
      id: null,
    },
    credentialPresence: { access: 'present', refresh: 'present', id: 'absent' },
  };
  const previous = new Map([
    ['GPT_REGISTER_ROOT', process.env.GPT_REGISTER_ROOT],
    ['PANEL_WRITE_ENABLED', process.env.PANEL_WRITE_ENABLED],
    ['PANEL_ALLOW_UNBACKED_WRITES', process.env.PANEL_ALLOW_UNBACKED_WRITES],
    ['SUB2API_BASE_URL', process.env.SUB2API_BASE_URL],
    ['SUB2API_ADMIN_API_KEY', process.env.SUB2API_ADMIN_API_KEY],
    ['PANEL_BACKUP_DIR', process.env.PANEL_BACKUP_DIR],
  ]);
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  delete process.env.PANEL_ALLOW_UNBACKED_WRITES;
  process.env.SUB2API_BASE_URL = 'http://127.0.0.1:18080';
  process.env.SUB2API_ADMIN_API_KEY = 'test-only-key';
  process.env.PANEL_BACKUP_DIR = backupRoot;
  try {
    const preview = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
      rootDirectory: root,
      includeRaw: true,
      includeInternal: true,
      client: { async listAccounts() { return [remote]; } },
    });
    const plan = buildImportPlan(preview._internal.sources, [remote]);
    assert.equal(plan.length, 1);
    assert.equal(plan[0].action, 'update');
    const selectedKeys = [plan[0].key];
    const planIntentVersion = importPlanIntentForSnapshot(preview, selectedKeys);
    let remoteWrites = 0;
    await assert.rejects(
      executeImport({
        snapshotVersion: preview.version,
        planIntentVersion,
        selectedKeys,
        actor: 'tester',
        jobId: 'backup-coverage-job',
        db: { async startMutationJob() {} },
        client: {
          async listAccounts() { return [remote]; },
          async exportAccounts() { return { accounts: [], proxies: [] }; },
          async applyOAuthCredentials() { remoteWrites += 1; },
          async importCodexSession() { remoteWrites += 1; },
        },
      }),
      (error) => error.code === 'SUB2API_BACKUP_FAILED'
        && error.causeCode === 'SUB2API_BACKUP_COVERAGE_INVALID',
    );
    assert.equal(remoteWrites, 0);
    assert.deepEqual(fs.readdirSync(backupRoot), []);
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('token import checkpoints the credential backup before creating any backup file', async () => {
  const { root } = fixture();
  const backupRoot = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-backup-checkpoint-')),
    'backups',
  );
  fs.mkdirSync(backupRoot, { mode: 0o700 });
  const previous = new Map([
    ['GPT_REGISTER_ROOT', process.env.GPT_REGISTER_ROOT],
    ['PANEL_WRITE_ENABLED', process.env.PANEL_WRITE_ENABLED],
    ['PANEL_ALLOW_UNBACKED_WRITES', process.env.PANEL_ALLOW_UNBACKED_WRITES],
    ['SUB2API_BASE_URL', process.env.SUB2API_BASE_URL],
    ['SUB2API_ADMIN_API_KEY', process.env.SUB2API_ADMIN_API_KEY],
    ['SUB2API_GROUP_IDS', process.env.SUB2API_GROUP_IDS],
    ['PANEL_BACKUP_DIR', process.env.PANEL_BACKUP_DIR],
  ]);
  process.env.GPT_REGISTER_ROOT = root;
  process.env.PANEL_WRITE_ENABLED = '1';
  delete process.env.PANEL_ALLOW_UNBACKED_WRITES;
  process.env.SUB2API_BASE_URL = 'http://127.0.0.1:18080';
  process.env.SUB2API_ADMIN_API_KEY = 'test-only-key';
  process.env.SUB2API_GROUP_IDS = '7';
  process.env.PANEL_BACKUP_DIR = backupRoot;
  try {
    const preview = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
      rootDirectory: root,
      includeRaw: true,
      includeInternal: true,
      client: { async listAccounts() { return []; } },
    });
    const plan = buildImportPlan(preview._internal.sources, []);
    assert.equal(plan.length, 1);
    assert.equal(plan[0].action, 'create');
    const selectedKeys = [plan[0].key];
    const planIntentVersion = importPlanIntentForSnapshot(preview, selectedKeys, {
      mode: 'explicit',
      groupIds: [7],
    });
    const checkpoints = [];
    let remoteWrites = 0;
    await assert.rejects(
      executeImport({
        snapshotVersion: preview.version,
        planIntentVersion,
        selectedKeys,
        actor: 'tester',
        jobId: 'backup-checkpoint-job',
        db: { async startMutationJob() {} },
        logger: {
          checkpoint(event, fields) {
            checkpoints.push({ event, fields });
            return event !== 'import.credential_backup_checkpoint';
          },
        },
        client: {
          async listAccounts() { return []; },
          async exportAccounts() { return { accounts: [], proxies: [] }; },
          async applyOAuthCredentials() { remoteWrites += 1; },
          async importCodexSession() { remoteWrites += 1; },
        },
      }),
      (error) => error.code === 'SUB2API_BACKUP_FAILED'
        && error.causeCode === 'AUDIT_LOG_UNAVAILABLE',
    );
    assert.deepEqual(checkpoints, [{
      event: 'import.credential_backup_checkpoint',
      fields: {
        jobId: 'backup-checkpoint-job',
        actor: 'tester',
        updateTargetCount: 0,
      },
    }]);
    assert.equal(remoteWrites, 0);
    assert.deepEqual(fs.readdirSync(backupRoot), []);
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});
