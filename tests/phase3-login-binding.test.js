'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
require('./test-isolation');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { resolvePhase3LoginBinding, matchesPhase3LoginBinding } = require('../backend/phase3LoginBinding');

function jwt(payload) {
  return [Buffer.from('{"alg":"RS256"}').toString('base64url'), Buffer.from(JSON.stringify(payload)).toString('base64url'),
    'fixture-signature'].join('.');
}
function fixture(options = {}) {
  const email = 'login-binding@example.test';
  const auth = { chatgpt_account_id: 'login-binding-account', chatgpt_user_id: 'login-binding-user' };
  const access = { sub: 'auth0|fixture-user', exp: 1, 'https://api.openai.com/auth': auth,
    'https://api.openai.com/profile': { email }, ...options.access };
  const id = { sub: 'auth0|fixture-user', email, 'https://api.openai.com/auth': auth, ...options.id };
  const raw = { id: 47, name: 'free00047', platform: 'openai', type: 'oauth', status: 'error', schedulable: false,
    group_ids: [1], updated_at: '2026-01-01T00:00:00.123456Z',
    credentials: { email, ...auth, plan_type: 'free', access_token: jwt(access), id_token: jwt(id),
      refresh_token: 'fixture-only-refresh', ...options.credentials } };
  const account = safeAccount(raw), calls = [];
  const client = { baseUrl: 'http://127.0.0.1:9',
    async exportAccounts(ids, args) { calls.push({ ids, includeProxies: args.includeProxies });
      const exported = structuredClone(raw); delete exported.id;
      return { accounts: [exported], proxies: [] }; },
    async getAccount(id) { calls.push({ get: id }); return safeAccount(raw); },
  };
  const args = { account, loginEmail: email, client };
  return { raw, account, client, args, calls, email };
}

test('stored expired JWT claims bind the original ID to a login without retaining credentials', async () => {
  const f = fixture();
  const proof = await resolvePhase3LoginBinding(f.args);
  assert.equal(proof.source, 'stored_oauth_claims');
  assert.equal(proof.accountId, 47);
  assert.equal(proof.updatedAt, f.account.updatedAt);
  assert.equal(matchesPhase3LoginBinding(proof, f.args), true);
  assert.deepEqual(f.calls, [{ ids: [47], includeProxies: false }, { get: 47 }]);
  for (const secret of [f.email, f.raw.credentials.access_token, f.raw.credentials.id_token, f.raw.credentials.refresh_token]) {
    assert.equal(JSON.stringify(proof).includes(secret), false);
  }
  assert.equal(Object.isFrozen(proof), true);
});

test('an access JWT can supply the login claim without an id token', async () => {
  const f = fixture({ credentials: { id_token: '' } });
  assert.ok(await resolvePhase3LoginBinding(f.args));
});

for (const [label, options] of [
  ['administrator email without JWT email', { access: { 'https://api.openai.com/profile': undefined }, id: { email: undefined } }],
  ['another JWT email', { access: { 'https://api.openai.com/profile': { email: 'different@example.test' } } }],
  ['conflicting id email', { id: { email: 'different@example.test' } }],
  ['conflicting claim identity', { id: { 'https://api.openai.com/auth': { chatgpt_account_id: 'other-account', chatgpt_user_id: 'login-binding-user' } } }],
  ['incomplete claim identity', { access: { 'https://api.openai.com/auth': {} }, id: { 'https://api.openai.com/auth': {} } }],
  ['conflicting token subjects', { id: { sub: 'auth0|another-subject' } }],
  ['invalid profile shape', { access: { 'https://api.openai.com/profile': [] } }],
  ['opaque access credential', { credentials: { access_token: 'fixture-opaque-access' } }],
  ['malformed id token', { credentials: { id_token: 'fixture-invalid-id' } }],
]) test('login association refuses ' + label, async () => {
  const f = fixture(options);
  assert.equal(await resolvePhase3LoginBinding(f.args), null);
});

for (const [label, change] of [
  ['other ID', data => { data.accounts[0].id = 48; }],
  ['other name', data => { data.accounts[0].name = 'free00048'; }],
  ['other type', data => { data.accounts[0].type = 'apikey'; }],
  ['other identity', data => { data.accounts[0].credentials.chatgpt_user_id = 'other-user'; }],
  ['changed access credential', data => { data.accounts[0].credentials.access_token += 'changed'; }],
  ['changed refresh credential', data => { data.accounts[0].credentials.refresh_token += 'changed'; }],
  ['changed id credential', data => { data.accounts[0].credentials.id_token += 'changed'; }],
  ['unexpected second account', data => { data.accounts.push(structuredClone(data.accounts[0])); }],
  ['unexpected proxy export', data => { data.proxies.push({ id: 1 }); }],
]) test('export cannot bind ' + label, async () => {
  const f = fixture(), original = f.client.exportAccounts;
  f.client.exportAccounts = async (...args) => { const data = await original(...args); change(data); return data; };
  await assert.rejects(resolvePhase3LoginBinding(f.args), error => /^PHASE3_LOGIN_BINDING_(?:TARGET_CHANGED|EXPORT_INVALID)$/.test(error.code));
});

test('stale import-time hashes do not replace the exported current credential fingerprints', async () => {
  const f = fixture(), original = f.client.exportAccounts;
  f.client.exportAccounts = async (...args) => { const data = await original(...args);
    data.accounts[0].extra = { access_token_sha256: 'a'.repeat(64), refresh_token_sha256: 'b'.repeat(64) };
    return data; };
  assert.ok(await resolvePhase3LoginBinding(f.args));
});

for (const [label, change] of [
  ['name', f => { f.raw.name = 'free99999'; }],
  ['credential', f => { f.raw.credentials.refresh_token += 'changed'; }],
  ['group', f => { f.raw.group_ids = [2]; }],
  ['updated_at', f => { f.raw.updated_at = '2026-01-02T00:00:00Z'; }],
  ['endpoint', f => { f.client.baseUrl = 'http://127.0.0.1:10'; }],
]) test('fresh read rejects a concurrent change to ' + label, async () => {
  const f = fixture();
  f.client.getAccount = async () => { change(f); return safeAccount(f.raw); };
  await assert.rejects(resolvePhase3LoginBinding(f.args), { code: 'PHASE3_LOGIN_BINDING_TARGET_CHANGED' });
});

test('saved proof binds login, full target, source and field shape', async () => {
  const f = fixture(), proof = await resolvePhase3LoginBinding(f.args);
  assert.equal(matchesPhase3LoginBinding(proof, { ...f.args, loginEmail: 'other@example.test' }), false);
  for (const change of [{ source: 'email_match' }, { accountId: 99 }, { accountName: 'free00099' },
    { endpointDigest: 'a'.repeat(64) }, { targetDigest: 'b'.repeat(64) }, { extra: true },
    { identityKeys: [] }, { fingerprints: { ...proof.fingerprints, extra: 'unexpected' } }]) {
    assert.equal(matchesPhase3LoginBinding({ ...proof, ...change }, f.args), false);
  }
});

test('unavailable optional export returns no proof, while invalid responses never leak upstream prose', async () => {
  for (const error of [Object.assign(new Error('synthetic-private-body'), { code: 'SUB2API_TIMEOUT' }),
    Object.assign(new Error('synthetic-private-body'), { code: 'SUB2API_REQUEST_REJECTED', upstreamStatus: 403 })]) {
    const f = fixture(); f.client.exportAccounts = async () => { throw error; };
    assert.equal(await resolvePhase3LoginBinding(f.args), null);
  }
  const f = fixture(); f.client.exportAccounts = async () => { throw new Error('synthetic-private-body'); };
  await assert.rejects(resolvePhase3LoginBinding(f.args), error => {
    assert.equal(error.code, 'PHASE3_LOGIN_BINDING_EXPORT_INVALID');
    assert.equal(error.message.includes('synthetic-private'), false); return true;
  });
});
