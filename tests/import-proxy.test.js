'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const proxy = require('../backend/importProxy');
const sync = require('../backend/sync');
const { PanelDb } = require('../backend/db');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { normalizeTokenDocument } = require('../backend/lib/token');

function fixture() {
  const node = { id: 2, name: 'fixture', protocol: 'http', status: 'active', expiresAt: null,
    fallbackMode: 'none', backupProxyId: null, revision: 'proxy-v1.' + 'a'.repeat(43) };
  const state = { revision: 1, settings: { proxyId: 2, endpointDigest: null, lastRequestId: crypto.randomUUID() } };
  const remote = []; const calls = { writes: 0, proxy: 0, payload: null, key: null };
  const client = { baseUrl: 'http://127.0.0.1:19001',
    async getProxy() { calls.proxy++; return { ...node }; },
    async listAccounts() { return remote.map(safeAccount); },
    async getAccount(id) { return safeAccount(remote.find(item => item.id === id)); },
    async importCodexSession(payload, options) {
      calls.writes++; calls.payload = payload; calls.key = options.idempotencyKey;
      remote.push({ id: 1, name: payload.name, platform: 'openai', type: 'oauth', status: 'active',
        schedulable: true, group_ids: payload.group_ids, proxy_id: payload.proxy_id ?? null,
        credentials: JSON.parse(payload.content) });
      return { total: 1, created: 1, updated: 0, skipped: 0, failed: 0,
        items: [{ index: 1, account_id: 1, action: 'created' }] };
    },
  };
  state.settings.endpointDigest = proxy.endpointDigest(client);
  const db = { getImportProxySettings: async () => structuredClone(state) };
  const token = normalizeTokenDocument({ source: 'tokens', relativePath: 'tokens/proxy.json',
    fileName: 'proxy.json', contentHash: 'a'.repeat(64), mtimeMs: 1, includeRaw: true,
    data: { chatgpt_account_id: 'fixture-account', chatgpt_user_id: 'fixture-user', plan_type: 'free',
      access_token: 'fixture-new-access', refresh_token: 'fixture-new-refresh', expires_at: '2099-01-01T00:00:00.000Z' } });
  const sources = { tokens: [token], usernames: [] };
  const item = sync.buildImportPlan(sources, [])[0];
  assert.equal(item.action, 'create');
  async function binding() { return proxy.resolveImportProxyBinding(db, client, [item]); }
  async function execute(proxyBinding) { return sync.executeImportPlanItem({ client, db, item, proxyBinding,
    groups: [1], createPolicy: sync.resolveImportCreatePolicy([item]), logger: { checkpoint: () => true } }); }
  return { node, state, remote, calls, client, db, token, sources, item, binding, execute };
}

test('default import proxy persists with independent CAS and opaque save receipt', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'import-proxy-db-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'panel.sqlite'); const db = new PanelDb(file);
  assert.deepEqual(await db.getImportProxySettings(), { revision: 0, settings: proxy.DEFAULT_IMPORT_PROXY });
  const value = { proxyId: 2, endpointDigest: 'a'.repeat(64), lastRequestId: crypto.randomUUID() };
  await db.saveImportProxySettings(value, { expectedRevision: 0 });
  const second = new PanelDb(file);
  assert.deepEqual(await second.getImportProxySettings(), { revision: 1, settings: value });
  const policy = await second.getConsoleSettings();
  await second.saveConsoleSettings(policy.settings, { expectedRevision: policy.revision });
  assert.deepEqual(await db.getImportProxySettings(), { revision: 1, settings: value });
  await assert.rejects(db.saveImportProxySettings({ ...value, lastRequestId: crypto.randomUUID() }, { expectedRevision: 0 }), { code: 'CONSOLE_IMPORT_PROXY_SETTINGS_STALE' });
  await assert.rejects(db.saveImportProxySettings(value, { expectedRevision: 1 }), { code: 'CONSOLE_IMPORT_PROXY_SETTINGS_STALE' });
  await second.saveImportProxySettings({ ...proxy.DEFAULT_IMPORT_PROXY, lastRequestId: crypto.randomUUID() }, { expectedRevision: 1 });
  assert.equal((await db.getImportProxySettings()).settings.proxyId, null);
});

test('persisted proxy settings and task bindings reject missing or ambiguous values', () => {
  for (const value of [{}, null, { proxyId: 0, endpointDigest: null, lastRequestId: null },
    { proxyId: null, endpointDigest: 'a'.repeat(64), lastRequestId: null },
    { proxyId: 2, endpointDigest: 'a'.repeat(64), lastRequestId: 'not-a-uuid' },
    { proxyId: 2, endpointDigest: ['a'.repeat(64)], lastRequestId: crypto.randomUUID() },
    { proxyId: 2, endpointDigest: 'a'.repeat(64), lastRequestId: [crypto.randomUUID()] }]) {
    assert.throws(() => proxy.normalizeStoredImportProxy(value), { code: 'CONSOLE_IMPORT_PROXY_SETTINGS_INVALID' });
  }
  for (const value of [null, {}, { mode: 'selected', proxyId: 2 }]) {
    assert.throws(() => proxy.normalizeImportProxyBinding(value), { code: 'CONSOLE_IMPORT_PROXY_BINDING_INVALID' });
  }
});

test('selected proxy applies only to create payload and is verified in detail and complete list', async () => {
  const f = fixture(); const binding = await f.binding(); const output = await f.execute(binding);
  assert.equal(output.verification.accountId, 1); assert.equal(f.calls.payload.proxy_id, 2);
  assert.equal(f.calls.payload.update_existing, false); assert.equal(f.calls.writes, 1);
  assert.equal(f.calls.proxy >= 4, true);
  const frozen = sync.resolveImportExecutionBinding(f.client, [f.item], { importProxy: binding });
  assert.deepEqual(frozen.importProxy, binding);
  assert.notEqual(sync.buildCodexImportIdempotencyKey(f.item), sync.buildCodexImportIdempotencyKey(f.item, undefined, binding));
  assert.equal(sync.buildCodexImportIdempotencyKey(f.item, undefined, binding), sync.buildCodexImportIdempotencyKey(f.item, undefined, { ...binding, nodeRevision: 'proxy-v1.' + 'b'.repeat(43) }));
});

for (const kind of ['disabled', 'expired', 'invalid_expiry', 'changed', 'missing', 'endpoint']) {
  test('create refuses ' + kind + ' default node before any write without direct fallback', async () => {
    const f = fixture(); const binding = await f.binding();
    if (kind === 'disabled') f.node.status = 'disabled';
    if (kind === 'expired') { f.node.expiresAt = '2000-01-01T00:00:00Z'; f.node.fallbackMode = 'direct'; }
    if (kind === 'invalid_expiry') f.node.expiresAt = 'not-a-date';
    if (kind === 'changed') f.node.revision = 'proxy-v1.' + 'b'.repeat(43);
    if (kind === 'missing') f.client.getProxy = async () => { throw new Error('fixture-secret-server-response'); };
    if (kind === 'endpoint') f.client.baseUrl = 'http://127.0.0.1:19002';
    await assert.rejects(f.execute(binding), error => error.code.startsWith('CONSOLE_IMPORT_PROXY_') && !error.message.includes('fixture-secret'));
    assert.equal(f.calls.writes, 0);
  });
}

test('unconfigured binding is also frozen and never silently adopts a later default', async () => {
  const f = fixture(); const configured = structuredClone(f.state);
  f.state.settings = { ...proxy.DEFAULT_IMPORT_PROXY };
  const binding = await f.binding(); assert.equal(binding, undefined);
  f.state.settings = configured.settings;
  await assert.rejects(f.execute(binding), { code: 'CONSOLE_IMPORT_PROXY_CHANGED' });
  assert.equal(f.calls.writes, 0);
  f.state.settings = { ...proxy.DEFAULT_IMPORT_PROXY };
  await f.execute(undefined); assert.equal(Object.hasOwn(f.calls.payload, 'proxy_id'), false);
});

for (const kind of ['detail_proxy', 'list_proxy', 'node_after_write', 'node_during_final_read']) {
  test('post-write ' + kind + ' drift creates a reconciliation hold rather than false success', async () => {
    const f = fixture(); const binding = await f.binding();
    const write = f.client.importCodexSession; const list = f.client.listAccounts;
    f.client.importCodexSession = async (...args) => {
      const result = await write(...args);
      if (kind === 'detail_proxy') f.remote[0].proxy_id = null;
      if (kind === 'node_after_write') f.node.status = 'disabled';
      return result;
    };
    f.client.listAccounts = async () => {
      if (f.calls.writes && kind === 'list_proxy') f.remote[0].proxy_id = 3;
      if (f.calls.writes && kind === 'node_during_final_read') f.node.revision = 'proxy-v1.' + 'c'.repeat(43);
      return list();
    };
    await assert.rejects(f.execute(binding), error => error.requiresReconciliation === true
      && error.code === (kind.endsWith('proxy') ? 'SUB2API_IMPORT_PROXY_MISMATCH'
        : kind === 'node_after_write' ? 'CONSOLE_IMPORT_PROXY_UNAVAILABLE' : 'CONSOLE_IMPORT_PROXY_CHANGED'));
    assert.equal(f.calls.writes, 1);
  });
}

test('update ignores invalid default but preserves original account proxy', async () => {
  const f = fixture(); f.node.status = 'disabled';
  const raw = { id: 1, name: 'free00001', platform: 'openai', type: 'oauth', status: 'error', schedulable: false,
    proxy_id: 7, credentials: { ...f.token.raw, access_token: 'fixture-old-access' } };
  f.remote.push(raw); const item = sync.buildImportPlan(f.sources, [safeAccount(raw)])[0];
  assert.equal(item.action, 'update'); assert.equal(await proxy.resolveImportProxyBinding(f.db, f.client, [item]), undefined);
  f.client.applyOAuthCredentials = async (_, payload) => { f.calls.writes++; assert.equal(Object.hasOwn(payload, 'proxy_id'), false); raw.credentials = payload.credentials; };
  await sync.executeImportPlanItem({ client: f.client, db: f.db, item, logger: { checkpoint: () => true } });
  assert.equal(raw.proxy_id, 7); assert.equal(f.calls.proxy, 0); assert.equal(f.calls.writes, 1);
});

for (const timing of ['before', 'after']) {
  test('existing account proxy drift ' + timing + ' the update is never silently accepted', async () => {
    const f = fixture();
    const raw = { id: 1, name: 'free00001', platform: 'openai', type: 'oauth', status: 'error', schedulable: false,
      proxy_id: 7, credentials: { ...f.token.raw, access_token: 'fixture-old-access' } };
    f.remote.push(raw); const item = sync.buildImportPlan(f.sources, [safeAccount(raw)])[0];
    if (timing === 'before') raw.proxy_id = null;
    f.client.applyOAuthCredentials = async (_, payload) => { f.calls.writes++; raw.credentials = payload.credentials; raw.proxy_id = null; };
    await assert.rejects(sync.executeImportPlanItem({ client: f.client, db: f.db, item, logger: { checkpoint: () => true } }),
      error => timing === 'before' ? !error.requiresReconciliation
        : error.requiresReconciliation === true && error.code === 'SUB2API_IMPORT_PROXY_MISMATCH');
    assert.equal(f.calls.writes, timing === 'before' ? 0 : 1); assert.equal(f.calls.proxy, 0);
  });
}

test('source file replaced during final proxy lookup is rejected before remote create', async t => {
  const f = fixture(); const root = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-source-race-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'tokens')); fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), '[]', { mode: 0o600 });
  const file = path.join(root, 'tokens', 'proxy.json');
  fs.writeFileSync(file, JSON.stringify(f.token.raw), { mode: 0o600 });
  const sources = require('../backend/adapters/gptRegisterFs').readGptRegisterSources({ rootDirectory: root, includeRaw: true, strictCompleteSnapshot: true });
  const item = sync.buildImportPlan(sources, [])[0]; const binding = await f.binding();
  f.client.getProxy = async () => {
    fs.writeFileSync(file, JSON.stringify({ ...f.token.raw, access_token: 'fixture-replaced-during-proxy-read' }));
    return { ...f.node };
  };
  await assert.rejects(sync.executeImportPlanItem({ client: f.client, db: f.db, item, proxyBinding: binding,
    sourceRoot: root, groups: [1], createPolicy: sync.resolveImportCreatePolicy([item]), logger: { checkpoint: () => true } }), { code: 'SOURCE_TOKEN_CHANGED' });
  assert.equal(f.calls.writes, 0);
});

test('proxy resolver preserves cancellation instead of misreporting unavailable configuration', async () => {
  const f = fixture(); const controller = new AbortController();
  f.client.getProxy = async () => { controller.abort(); throw new Error('fixture-only-abort'); };
  await assert.rejects(proxy.resolveImportProxyBinding(f.db, f.client, [f.item], { signal: controller.signal }), { code: 'JOB_INTERRUPTED' });
  assert.equal(f.calls.writes, 0);
});
