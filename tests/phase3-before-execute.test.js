'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runPhase3Job } = require('../backend/phase3Worker');
const { withControlPlaneLock } = require('../backend/taskCoordinator');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-phase3-before-execute-'));
  for (const directory of ['tokens', 'use_token']) fs.mkdirSync(path.join(root, directory));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{ email: 'before-execute@example.test', password: 'synthetic-only', status: 'oauth_done' }]), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), "require('node:fs').writeFileSync('spawn-proof','started');", { mode: 0o600 });
  const previous = { GPT_REGISTER_ROOT: process.env.GPT_REGISTER_ROOT, GPT_REGISTER_NODE_PATH: process.env.GPT_REGISTER_NODE_PATH, PANEL_PHASE3_ENABLED: process.env.PANEL_PHASE3_ENABLED };
  Object.assign(process.env, { GPT_REGISTER_ROOT: root, GPT_REGISTER_NODE_PATH: process.execPath, PANEL_PHASE3_ENABLED: '1' });
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } fs.rmSync(root, { recursive: true }); });
  const order = [];
  const args = { email: 'before-execute@example.test', jobId: 'before-execute-fixture',
    db: { async startMutationJob() { order.push('claim'); }, async audit() {} },
    logger: { checkpoint() { order.push('spawn-checkpoint'); return true; }, info() {}, warn() {}, error() {} } };
  return { root, args, order };
}
test('server-only execution check rejects inside lease, persists failure and never spawns', async t => {
  const f = fixture(t); let entered, release;
  const ready = new Promise(resolve => { entered = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  const running = runPhase3Job({ ...f.args, beforeExecute: async () => { f.order.push('check'); entered(); await gate; throw Object.assign(new Error('target became quota-limited'), { code: 'MAINTENANCE_TARGET_CHANGED' }); },
    persistFailure: async error => { assert.equal(error.code, 'MAINTENANCE_TARGET_CHANGED'); f.order.push('persist'); } });
  const rejected = assert.rejects(running, { code: 'MAINTENANCE_TARGET_CHANGED' });
  await ready;
  const follower = withControlPlaneLock(() => { f.order.push('follower'); });
  assert.deepEqual(f.order, ['claim', 'check']); release();
  await rejected; await follower;
  assert.deepEqual(f.order, ['claim', 'check', 'persist', 'follower']);
  assert.equal(fs.existsSync(path.join(f.root, 'spawn-proof')), false);
});
test('allowed execution check runs after claim and before subprocess audit/spawn', async t => {
  const f = fixture(t);
  await assert.rejects(runPhase3Job({ ...f.args, beforeExecute: async () => { f.order.push('check'); } }), { code: 'PHASE3_TOKEN_UNCHANGED' });
  assert.deepEqual(f.order.slice(0, 3), ['claim', 'check', 'spawn-checkpoint']);
  assert.equal(fs.existsSync(path.join(f.root, 'spawn-proof')), true);
});
