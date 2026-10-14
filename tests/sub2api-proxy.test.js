'use strict';
require('./test-isolation');
const assert = require('node:assert/strict');
const test = require('node:test');
const { Sub2ApiAdminClient, safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { safeProxy, accountProxyState } = require('../backend/lib/sub2apiProxy');
const { accountTestTargetDigest, accountTestOwnershipDigest } = require('../backend/accountTargetRevision');
const { runAccountTestJobNow, accountTestTargetBaseline } = require('../backend/accountTestWorker');

const endpoint = 'http://127.0.0.1:8080';
function proxy(changes = {}) {
  return { id: 2, name: '合成节点', protocol: 'http', status: 'active', host: 'fixture-proxy.invalid', port: 8081,
    username: 'fixture-user-secret', password: 'fixture-password-secret', expires_at: null,
    created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
    fallback_mode: 'none', backup_proxy_id: null, ...changes };
}
function account(changes = {}) {
  return { id: 47, name: 'free00047', platform: 'openai', type: 'oauth', status: 'active', schedulable: true,
    credentials: { chatgpt_account_id: 'fixture-account-47', chatgpt_user_id: 'fixture-user-47', access_token: 'fixture-access' },
    proxy_id: 2, ...changes };
}

test('proxy adapter returns only sanitized metadata and opaque endpoint-bound review proof', async t => {
  const logs = []; const calls = [];
  const logger = Object.fromEntries(['info', 'warn', 'error'].map(level => [level, (event, data) => logs.push({ event, data })]));
  const client = new Sub2ApiAdminClient({ baseUrl: endpoint, apiKey: 'fixture-key', logger });
  const oldFetch = global.fetch; t.after(() => { global.fetch = oldFetch; });
  global.fetch = async (url, options) => {
    calls.push({ url: String(url), method: options.method, redirect: options.redirect });
    return new Response(JSON.stringify({ code: 0, data: String(url).endsWith('/all') ? [proxy()] : proxy() }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  };
  const rows = await client.listProxies(); const detail = await client.getProxy(2);
  assert.deepEqual(rows, [detail]);
  assert.deepEqual(Object.keys(detail).sort(), ['id', 'name', 'protocol', 'status', 'expiresAt', 'fallbackMode', 'backupProxyId', 'revision'].sort());
  assert.match(detail.revision, /^proxy-v1\.[A-Za-z0-9_-]{43}$/);
  for (const marker of ['fixture-user-secret', 'fixture-password-secret', 'fixture-proxy.invalid']) {
    assert.equal(JSON.stringify({ rows, logs }).includes(marker), false);
  }
  assert.deepEqual(calls, [
    { url: endpoint + '/api/v1/admin/proxies/all', method: 'GET', redirect: 'error' },
    { url: endpoint + '/api/v1/admin/proxies/2', method: 'GET', redirect: 'error' },
  ]);
});

test('proxy review proof changes for every routing credential lifetime and endpoint change', () => {
  const original = safeProxy(proxy(), endpoint);
  assert.equal(safeProxy(proxy(), endpoint + '/').revision, original.revision);
  for (const change of [{ id: 3 }, { name: 'changed' }, { protocol: 'socks5h' }, { host: 'changed.invalid' }, { port: 1080 },
    { username: 'changed' }, { password: 'changed' }, { status: 'inactive' }, { expires_at: '2027-01-01T00:00:00Z' },
    { fallback_mode: 'direct' }, { fallback_mode: 'proxy', backup_proxy_id: 3 }, { updated_at: '2026-10-02T00:00:00Z' }]) {
    assert.notEqual(safeProxy(proxy(change), endpoint).revision, original.revision);
  }
  assert.notEqual(safeProxy(proxy(), 'http://127.0.0.1:8082').revision, original.revision);
  assert.equal(safeProxy(proxy({ expires_at: '2020-01-01T00:00:00Z' }), endpoint).expiresAt, '2020-01-01T00:00:00.000Z');
  const expired = safeProxy(proxy({ status: 'expired', expires_at: '2020-01-01T00:00:00Z' }), endpoint);
  assert.equal(expired.status, 'expired', 'expiry sweeper status is valid metadata, not an eligible node');
  assert.notEqual(expired.revision, original.revision);
});

test('proxy schema rejects malformed IDs protocols dates and duplicate list entries without raw diagnostics', async () => {
  for (const change of [{ id: '2' }, { id: 0 }, { id: 1.1 }, { id: Number.MAX_SAFE_INTEGER + 1 },
    { protocol: 'file' }, { status: 'unknown' }, { host: '' }, { name: 'unsafe\nname' }, { port: '8080' }, { port: 65536 },
    { password: {} }, { expires_at: 'invalid fixture-password-secret' }, { expires_at: 1790000000 },
    { fallback_mode: 'unknown' }, { backup_proxy_id: 0 }]) {
    assert.throws(() => safeProxy(proxy(change), endpoint), error => error.code === 'SUB2API_PROXY_SCHEMA_INVALID'
      && !error.message.includes('fixture-password-secret'));
  }
  const client = new Sub2ApiAdminClient({ baseUrl: endpoint, apiKey: 'fixture-key' });
  for (const response of [{ items: [proxy()] }, null, [proxy(), proxy()], Array(10001).fill(proxy())]) {
    client.request = async () => response;
    await assert.rejects(client.listProxies(), { code: 'SUB2API_PROXY_SCHEMA_INVALID' });
  }
  client.request = async () => proxy({ id: 3 });
  await assert.rejects(client.getProxy(2), { code: 'SUB2API_PROXY_SCHEMA_INVALID' });
  let called = false; client.request = async () => { called = true; };
  await assert.rejects(client.getProxy('2'), { code: 'SUB2API_PROXY_SCHEMA_INVALID' });
  assert.equal(called, false);
});

test('proxy names redact credential-like labels and exact connection secrets', () => {
  const row = safeProxy(proxy({ name: 'node fixture-password-secret Bearer abcdefghijklmnopqrstuvwxyz' }), endpoint);
  assert.equal(row.name.includes('fixture-password-secret'), false);
  assert.equal(row.name.includes('abcdefghijklmnopqrstuvwxyz'), false);
  assert.equal(safeProxy(proxy({ name: 'node abc', password: 'abc' }), endpoint).name.includes('abc'), false);
});

test('account proxy evidence distinguishes bound direct missing and malformed response fields', () => {
  assert.deepEqual(accountProxyState(safeAccount(account())), { known: true, id: 2 });
  assert.deepEqual(accountProxyState(safeAccount(account({ proxy_id: null }))), { known: true, id: null });
  const missing = account(); delete missing.proxy_id;
  assert.deepEqual(accountProxyState(safeAccount(missing)), { known: false, id: null });
  for (const value of ['2', 0, -1, false, {}, 1.2]) {
    const row = safeAccount(account({ proxy_id: value }));
    assert.equal(row.schemaValid, false); assert.equal(row.proxyIdKnown, false);
    assert.equal(accountProxyState(row), null);
  }
});

test('account target and ownership signatures bind proxy changes including known versus omitted', () => {
  const before = safeAccount(account());
  const missing = account(); delete missing.proxy_id;
  for (const after of [safeAccount(account({ proxy_id: 3 })), safeAccount(account({ proxy_id: null })), safeAccount(missing)]) {
    assert.notEqual(accountTestTargetDigest(before), accountTestTargetDigest(after));
    assert.notEqual(accountTestOwnershipDigest(before), accountTestOwnershipDigest(after));
  }
});

test('account test with a proxy changed during the request requires reconciliation without scheduling writes', async () => {
  const before = safeAccount(account()); const changed = safeAccount(account({ proxy_id: 3 }));
  let reads = 0; let writes = 0;
  const logger = { checkpoint() { return true; }, info() {}, warn() {}, error() {} };
  const result = await runAccountTestJobNow({ accountIds: [47], targetBaselines: [accountTestTargetBaseline(before)], logger,
    client: { async listAccounts() { return [before]; }, async getAccount() { return ++reads === 1 ? before : changed; },
      async testAccount() { return { success: true }; }, async setSchedulable() { writes += 1; } } });
  assert.equal(result.requiresReconciliation, true);
  assert.equal(writes, 0);
});
