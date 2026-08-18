const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { PanelDb } = require('../backend/db');
const { buildImportPlan, importPlanSummary, buildSnapshot } = require('../backend/sync');
const { findUsernameEntry, sanitizeLog, runPhase3Job, getActivePhase3Job } = require('../backend/phase3Worker');

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

test('PanelDb persists jobs and audit rows in an independent SQLite file', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const job = await db.createJob('preview', { selectedKeys: ['x'] }, 'tester');
  await db.updateJob(job.id, { status: 'succeeded', result: { count: 1 } });
  await db.audit({ jobId: job.id, actor: 'tester', action: 'preview', targetKey: 'email:x', result: 'ok' });
  assert.equal((await db.getJob(job.id)).status, 'succeeded');
  assert.equal((await db.listAudit(10)).length, 1);
  assert.equal(fs.statSync(file).mode & 0o077, 0);
});

test('phase3 worker matches only records with a password and redacts logs', () => {
  const { root } = fixture();
  const previous = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    assert.equal(findUsernameEntry({ email: 'ONE@example.test' }).email, 'one@example.test');
    assert.throws(() => findUsernameEntry({ email: 'missing@example.test' }), /未找到/);
    assert.equal(sanitizeLog('access_token=secret refresh_token:secret2 Bearer abc.def').includes('secret'), false);
  } finally {
    if (previous === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previous;
  }
});

test('phase3 jobs run serially and reject duplicate account submissions', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'queue-one@example.test', password: 'hidden' },
    { email: 'queue-two@example.test', password: 'hidden' },
  ]));
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const email = (process.argv.find((arg) => arg.startsWith('--email=')) || '').slice(8);",
    "setTimeout(() => fs.writeFileSync(path.join(process.cwd(), 'tokens', 'codex-' + email + '.json'), JSON.stringify({ access_token: 'access-' + email, email })), 80);",
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
    async updateJob(id, patch) { updates.push({ id, patch }); },
    async audit() {},
  };
  const logger = {
    info(event, fields) { events.push({ event, fields }); },
    warn(event, fields) { events.push({ event, fields }); },
    error(event, fields) { events.push({ event, fields }); },
  };
  try {
    const first = runPhase3Job({ email: 'queue-one@example.test', db, jobId: 'job-one', logger });
    assert.equal(getActivePhase3Job({ email: 'queue-one@example.test' }).jobId, 'job-one');
    await assert.rejects(
      runPhase3Job({ email: 'queue-one@example.test', db, jobId: 'job-duplicate', logger }),
      (error) => error.code === 'PHASE3_DUPLICATE',
    );
    const second = runPhase3Job({ email: 'queue-two@example.test', db, jobId: 'job-two', logger });
    const [firstResult, secondResult] = await Promise.all([first, second]);
    assert.equal(firstResult.email, 'queue-one@example.test');
    assert.equal(secondResult.email, 'queue-two@example.test');
    assert.equal(getActivePhase3Job({ email: 'queue-one@example.test' }), null);
    assert.equal(getActivePhase3Job({ email: 'queue-two@example.test' }), null);
    assert.deepEqual(updates.map((item) => item.id), ['job-one', 'job-two']);
    assert.equal(events.filter((item) => item.event === 'phase3.started_after_queue').length, 2);
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
  const fakeClient = {
    async listAccounts() {
      return [{
        id: 42,
        name: 'free00042',
        platform: 'openai',
        type: 'oauth',
        status: 'active',
        email: 'one@example.test',
        identityKeys: ['email:one@example.test'],
        tokenFingerprints: {},
      }];
    },
    async getBatchTableUsageStats() {
      return { stats: { '42': {
        historical: { totalTokens: 1234, requests: 12 },
        current: { totalTokens: 55, requests: 2 },
      } }, errors: {} };
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
});

test('import plan never updates an available Sub2API account', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 9,
    name: 'free00009',
    status: 'active',
    schedulable: true,
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: 'different-access', refresh: 'different-refresh' },
  };
  const plan = buildImportPlan(sources, [account]);
  assert.equal(plan[0].action, 'skip');
  assert.equal(plan[0].reason, 'sub2api_available');
});

test('import plan updates only an unavailable account with a fresh source token', () => {
  const { root } = fixture();
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 10,
    name: 'free00010',
    status: 'error',
    schedulable: false,
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: 'different-access', refresh: 'different-refresh' },
  };
  const plan = buildImportPlan(sources, [account]);
  assert.equal(plan[0].action, 'update');
  assert.equal(plan[0].reason, 'token_changed');
});

test('import plan writes only the freshest candidate when one account has duplicate sources', () => {
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
    access_token: makeAccess('old-user', false),
    refresh_token: 'refresh-old',
    email: 'duplicate@example.test',
    expired: '2020-08-21T00:00:00.000Z',
    last_refresh: '2020-08-14T00:00:00.000Z',
  }));
  const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const plan = buildImportPlan(sources, [{
    id: 77,
    name: 'free00077',
    status: 'error',
    schedulable: false,
    identityKeys: ['email:duplicate@example.test'],
    tokenFingerprints: { access: 'different-access', refresh: 'different-refresh' },
  }]);
  const updates = plan.filter((item) => item.action === 'update');
  const superseded = plan.filter((item) => item.reason === 'superseded_by_newer_source');
  assert.equal(updates.length, 1);
  assert.equal(updates[0].source, 'tokens');
  assert.equal(updates[0].relativePath, 'tokens/fresh.json');
  assert.equal(superseded.length, 1);
  assert.equal(superseded[0].source, 'use_token');
  assert.equal(superseded[0].supersededBy, 'tokens/fresh.json');
});
