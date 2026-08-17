const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { PanelDb } = require('../backend/db');
const { buildImportPlan, importPlanSummary } = require('../backend/sync');
const { findUsernameEntry, sanitizeLog } = require('../backend/phase3Worker');

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
