'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
require('./test-isolation');

const { accountTestTargetRevision } = require('../backend/accountTargetRevision');
const {
  validateRemoteTarget, validateBoundRemoteTarget,
  bindRemotePhase3Targets, assertRemotePhase3TargetCurrent, remotePhase3EndpointDigest,
} = require('../backend/remotePhase3');
const {
  listLocalPhase3Targets, resolvePhase3Requests, runPhase3Job,
} = require('../backend/phase3Worker');
const { withControlPlaneLock } = require('../backend/taskCoordinator');
const { redactValue } = require('../backend/logger');
const {
  canCompleteAccountIdentity, remotePhase3OutputIdentityMatches,
} = require('../backend/identityCompletion');

const EMAIL = 'remote-phase3@example.test';
const BASE_URL = 'https://remote-phase3.example.test/admin';
const endpointClient = { baseUrl: BASE_URL };
const logger = { checkpoint() { return true; }, info() {}, warn() {}, error() {} };

function account(extra = {}) {
  return {
    id: 19, name: 'free00019', platform: 'openai', type: 'oauth', status: 'error',
    schedulable: false, schemaValid: true,
    accountId: 'bound-workspace', userId: 'bound-user',
    identityKeys: ['account:bound-workspace', 'user:bound-user', 'email:' + EMAIL],
    tokenFingerprints: { access: 'a'.repeat(64), refresh: 'b'.repeat(64) },
    credentialPresence: { access: 'present', refresh: 'present', id: 'absent' },
    ...extra,
  };
}

function remoteSelection(value = account()) {
  return { accountId: value.id, targetRevision: accountTestTargetRevision(value) };
}

function binding(value = account()) {
  return bindRemotePhase3Targets([{ sourceMode: 'username', remoteTarget: remoteSelection(value) }], [value], endpointClient)[0].remoteTarget;
}

function fixture(t, output = { account: 'bound-workspace', user: 'bound-user' }, extraScript = '', remoteAccount = account()) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-remote-phase3-'));
  fs.mkdirSync(path.join(root, 'tokens'), { mode: 0o700 });
  fs.mkdirSync(path.join(root, 'use_token'), { mode: 0o700 });
  const record = { email: EMAIL, password: 'remote-phase3-fixture-password', status: 'oauth_done' };
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([record]), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'index.js'), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `if (!process.argv.includes('--email=${EMAIL}')) throw new Error('wrong selection');`,
    `const output = ${JSON.stringify(output)};`,
    "fs.writeFileSync(path.join(process.cwd(), 'tokens', 'bound.json'), JSON.stringify({",
    ` email: '${EMAIL}', chatgpt_account_id: output.account, chatgpt_user_id: output.user,`,
    " access_token: 'remote-phase3-fixture-access', refresh_token: 'remote-phase3-fixture-refresh',",
    ' expires_at: new Date(Date.now() + 3600000).toISOString()',
    '}), { mode: 0o600 });',
    extraScript,
  ].join('\n'), { mode: 0o600 });
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
  const target = listLocalPhase3Targets().accounts[0];
  const resolved = resolvePhase3Requests([{
    sourceMode: 'username', email: target.email, phone: '', selectedKey: target.selectedKey,
    phase3TargetRevision: target.phase3TargetRevision, remoteTarget: remoteSelection(remoteAccount),
  }]);
  assert.deepEqual(resolved.rejected, []);
  bindRemotePhase3Targets(resolved.eligible, [remoteAccount], endpointClient);
  const request = resolved.eligible[0];
  let reads = 0;
  const args = {
    ...request, executionBinding: request.executionBinding, requireExecutionBinding: true,
    logger, jobId: 'remote-phase3-fixture',
    db: { async startMutationJob() {}, async audit() {} },
    remoteClientFactory: () => ({ baseUrl: BASE_URL,
      async getAccount(id) { reads += 1; assert.equal(id, 19); return remoteAccount; } }),
  };
  return { root, record, args, readCount: () => reads };
}

test('account identity completion accepts only a canonical user-only to same-user account addition', () => {
  const userOnly = ['user:bound-user'];
  const complete = ['account:bound-workspace', 'user:bound-user'];
  assert.equal(canCompleteAccountIdentity(userOnly, complete), true);
  assert.equal(canCompleteAccountIdentity(
    [...userOnly, 'email:old@example.test'], [...complete, 'email:new@example.test'],
  ), true, 'email is not identity evidence');
  assert.equal(canCompleteAccountIdentity(userOnly, [...complete].reverse()), true);
  assert.equal(canCompleteAccountIdentity(complete, complete), false);
  assert.equal(remotePhase3OutputIdentityMatches(complete, complete), true);
  assert.equal(remotePhase3OutputIdentityMatches(userOnly, userOnly), true);
  assert.equal(remotePhase3OutputIdentityMatches(userOnly, complete), true);
  for (const [expected, actual] of [
    [['email:same@example.test'], [...complete, 'email:same@example.test']],
    [userOnly, ['account:bound-workspace']],
    [userOnly, ['account:bound-workspace', 'user:changed-user']],
    [['account:bound-workspace'], complete],
    [complete, ['account:changed-workspace', 'user:bound-user']],
    [complete, userOnly],
  ]) {
    assert.equal(canCompleteAccountIdentity(expected, actual), false);
    assert.equal(remotePhase3OutputIdentityMatches(expected, actual), false);
  }
});

test('account identity completion rejects malformed duplicate and unknown fields without invoking accessors', () => {
  const userOnly = ['user:bound-user'];
  const complete = ['account:bound-workspace', 'user:bound-user'];
  let reads = 0;
  const accessor = [];
  Object.defineProperty(accessor, '0', { enumerable: true, get() { reads += 1; return 'user:bound-user'; } });
  const invalid = [
    null, {}, 'user:bound-user', [], new Array(1), accessor,
    ['user:bound-user', 'user:bound-user'],
    ['user:bound-user', 'user:other-user'],
    ['account:bound-workspace', 'account:bound-workspace', 'user:bound-user'],
    ['user:bound-user', 'organization:unknown'],
    ['user:bound-user', 'email:a@example.test', 'email:a@example.test'],
    ['user:bound-user', 'email:invalid-email'],
    ['User:bound-user'], ['user: bound-user'], ['user:bound-user '], ['user:bound-user\n'],
    ['user:'], ['user:' + 'x'.repeat(513)], ['user:bound\u200b-user'],
    ['user:{123e4567-e89b-12d3-a456-426614174000}'],
    ['user:123E4567-E89B-12D3-A456-426614174000'],
  ];
  for (const keys of invalid) {
    assert.equal(canCompleteAccountIdentity(keys, complete), false);
    assert.equal(canCompleteAccountIdentity(userOnly, keys), false);
    assert.equal(remotePhase3OutputIdentityMatches(keys, keys), false);
    assert.equal(remotePhase3OutputIdentityMatches(userOnly, keys), false);
  }
  assert.equal(reads, 0);
});

test('remote Phase3 validates exact bounded IDs, versions and strong-only identity bindings', () => {
  const selection = remoteSelection();
  assert.deepEqual(validateRemoteTarget(selection), selection);
  assert.equal(validateRemoteTarget(undefined), null);
  for (const value of [[], true, {}, { ...selection, accountId: '19' },
    { ...selection, accountId: 0 }, { ...selection, accountId: Number.MAX_SAFE_INTEGER + 1 },
    { ...selection, targetRevision: 'invalid' }, { ...selection, targetRevision: selection.targetRevision + '\n' },
    { ...selection, identityKeys: ['account:forged'] },
    Object.create(selection)]) {
    assert.throws(() => validateRemoteTarget(value));
  }
  const bound = binding();
  assert.deepEqual(bound.identityKeys, ['account:bound-workspace', 'user:bound-user']);
  assert.equal(Object.isFrozen(bound), true);
  assert.match(bound.endpointDigest, /^[a-f0-9]{64}$/);
  for (const endpointDigest of [undefined, null, '', 'a'.repeat(64) + '\n', 'A'.repeat(64), 'a'.repeat(63)]) {
    assert.throws(() => validateBoundRemoteTarget({ ...bound, endpointDigest }),
      (error) => error.code === 'PHASE3_REMOTE_BINDING_INVALID');
  }
  for (const keys of [[], new Array(1), ['email:' + EMAIL], ['account:a', 'account:b'],
    ['user:a', 'account:b', 'user:c'], ['account:a\n'], ['account: bad'], ['account:' + 'x'.repeat(513)]]) {
    assert.throws(() => validateBoundRemoteTarget({ ...bound, identityKeys: keys }));
  }
  assert.throws(() => validateBoundRemoteTarget({ ...bound, credentials: 'must-not-persist' }));
  assert.throws(() => validateRemoteTarget({ get accountId() { throw new Error('getter executed'); },
    targetRevision: selection.targetRevision }), (error) => error.code === 'PHASE3_REMOTE_TARGET_INVALID');
});

test('remote Phase3 admission blocks missing identity, duplicates, missing rows and available accounts', () => {
  const selection = remoteSelection();
  const request = () => ({ sourceMode: 'username', remoteTarget: selection });
  for (const rows of [[], [account(), account()], [account({ accountId: '', userId: '', identityKeys: ['email:' + EMAIL] })]]) {
    assert.throws(() => bindRemotePhase3Targets([request()], rows, endpointClient));
  }
  const first = request();
  assert.throws(() => bindRemotePhase3Targets([first, request()], [account()], endpointClient),
    (error) => error.code === 'PHASE3_REMOTE_DUPLICATE');
  assert.deepEqual(first.remoteTarget, selection);
  const available = account({ status: 'active', schedulable: true });
  assert.throws(() => binding(available), (error) => error.code === 'PHASE3_REMOTE_NOT_UNAVAILABLE');
  assert.throws(() => bindRemotePhase3Targets([{ ...request(), sourceMode: 'token' }], [account()], endpointClient),
    (error) => error.code === 'PHASE3_REMOTE_SOURCE_INVALID');
});

test('remote Phase3 requires a client and binds its canonical instance without exposing its URL', () => {
  const digest = remotePhase3EndpointDigest(endpointClient);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(remotePhase3EndpointDigest({ baseUrl: 'https://REMOTE-PHASE3.example.test:443/admin' }), digest);
  for (const baseUrl of ['https://other.example.test/admin', BASE_URL + '/',
    'http://remote-phase3.example.test/admin', 'https://remote-phase3.example.test:444/admin']) {
    assert.notEqual(remotePhase3EndpointDigest({ baseUrl }), digest);
  }
  for (const client of [undefined, null, {}, { baseUrl: '' }, { baseUrl: 'not-a-url' },
    { baseUrl: 'file:///tmp/sub2api' }, { baseUrl: BASE_URL + '?account=19' },
    { baseUrl: BASE_URL, baseOrigin: 'https://other.example.test' }]) {
    assert.throws(() => remotePhase3EndpointDigest(client),
      (error) => error.code === 'PHASE3_REMOTE_ENDPOINT_INVALID');
  }
  assert.throws(() => bindRemotePhase3Targets([
    { sourceMode: 'username', remoteTarget: remoteSelection() },
  ], [account()]), (error) => error.code === 'PHASE3_REMOTE_ENDPOINT_INVALID');
  assert.equal(JSON.stringify(binding()).includes('remote-phase3.example.test'), false);
});

test('remote Phase3 signed target detects credential, status and strong-identity changes', () => {
  const bound = binding();
  for (const current of [account({ status: 'active', schedulable: true }),
    account({ tokenFingerprints: { access: 'c'.repeat(64) } }),
    account({ accountId: 'other', identityKeys: ['account:other', 'user:bound-user'] }),
    account({ groupIds: [2] })]) {
    assert.throws(() => assertRemotePhase3TargetCurrent(bound, current),
      (error) => error.code === 'PHASE3_REMOTE_TARGET_CHANGED');
  }
  assert.throws(() => assertRemotePhase3TargetCurrent(bound, account({ id: 20 })),
    (error) => error.code === 'PHASE3_REMOTE_NOT_FOUND');
  const forged = { ...bound, identityKeys: ['account:other', 'user:bound-user'] };
  assert.throws(() => assertRemotePhase3TargetCurrent(forged, account()),
    (error) => error.code === 'PHASE3_REMOTE_TARGET_CHANGED');
});

test('remote Phase3 performs only two read checks and returns hash-bound output for original ID', async (t) => {
  const { root, args, readCount } = fixture(t);
  let persisted;
  const result = await runPhase3Job({ ...args, persistSuccess(value) { persisted = value; } });
  assert.equal(readCount(), 2);
  assert.equal(result.remoteTarget.accountId, 19);
  assert.deepEqual(result.remoteTarget, binding());
  assert.equal(result.tokenSource, 'tokens');
  assert.equal(result.tokenFile, 'tokens/bound.json');
  assert.equal(result.tokenContentHash, crypto.createHash('sha256')
    .update(fs.readFileSync(path.join(root, result.tokenFile))).digest('hex'));
  assert.equal(persisted, result);
  assert.doesNotMatch(JSON.stringify(result), /fixture-access|fixture-refresh|fixture-password|email:remote-phase3/);
  assert.deepEqual(redactValue(result), result);
});

test('remote Phase3 refuses same-email output with a different or incomplete strong identity', async (t) => {
  for (const [label, output] of [['other-account', { account: 'other', user: 'bound-user' }],
    ['other-user', { account: 'bound-workspace', user: 'other' }],
    ['missing-user', { account: 'bound-workspace' }]]) {
    await t.test(label, async (subtest) => {
      const { args } = fixture(subtest, output);
      let success = false;
      await assert.rejects(runPhase3Job({ ...args, persistSuccess() { success = true; } }),
        (error) => error.code === 'PHASE3_TOKEN_IDENTITY_MISMATCH'
          && error.requiresReconciliation === true && error.doNotRetry === true);
      assert.equal(success, false);
    });
  }
});

test('remote Phase3 accepts a new account identity only for a bound user-only target with the same user', async (t) => {
  const before = account({
    accountId: '', identityKeys: ['user:bound-user', 'email:' + EMAIL],
  });
  const { args, root, readCount } = fixture(t,
    { account: 'newly-observed-workspace', user: 'bound-user' }, '', before);
  let persisted = null;
  const result = await runPhase3Job({ ...args, persistSuccess(value) { persisted = value; } });
  assert.equal(readCount(), 2);
  assert.deepEqual(result.remoteTarget, binding(before));
  assert.deepEqual(result.remoteTarget.identityKeys, ['user:bound-user']);
  assert.equal(result.remoteTarget.accountId, 19);
  assert.equal(result.tokenFile, 'tokens/bound.json');
  assert.equal(result.tokenContentHash, crypto.createHash('sha256')
    .update(fs.readFileSync(path.join(root, result.tokenFile))).digest('hex'));
  assert.equal(persisted, result);
  assert.equal(before.accountId, '', 'Phase3 must not mutate or automatically import into the remote account');
  assert.doesNotMatch(JSON.stringify(result), /fixture-access|fixture-refresh|fixture-password/);
});

test('remote Phase3 identity completion refuses changed or missing users and reverse account-only completion', async (t) => {
  const userOnly = account({ accountId: '', identityKeys: ['user:bound-user', 'email:' + EMAIL] });
  const accountOnly = account({ userId: '', identityKeys: ['account:bound-workspace', 'email:' + EMAIL] });
  for (const [label, before, output] of [
    ['changed-user', userOnly, { account: 'newly-observed-workspace', user: 'other-user' }],
    ['missing-user', userOnly, { account: 'newly-observed-workspace' }],
    ['email-only', userOnly, {}],
    ['existing-account-conflict', account(), { account: 'other-workspace', user: 'bound-user' }],
    ['account-only-add-user', accountOnly, { account: 'bound-workspace', user: 'bound-user' }],
  ]) {
    await t.test(label, async (subtest) => {
      const { args } = fixture(subtest, output, '', before);
      let persisted = false;
      await assert.rejects(runPhase3Job({ ...args, persistSuccess() { persisted = true; } }),
        (error) => error.code === 'PHASE3_TOKEN_IDENTITY_MISMATCH'
          && error.requiresReconciliation === true && error.doNotRetry === true);
      assert.equal(persisted, false);
    });
  }
});

test('remote Phase3 identity completion does not relax concurrent remote target revision checks', async (t) => {
  const before = account({ accountId: '', identityKeys: ['user:bound-user', 'email:' + EMAIL] });
  const { root, args } = fixture(t,
    { account: 'newly-observed-workspace', user: 'bound-user' }, '', before);
  let reads = 0;
  await assert.rejects(runPhase3Job({ ...args,
    remoteClientFactory: () => ({ baseUrl: BASE_URL, async getAccount() {
      reads += 1;
      return reads === 1 ? before : account({ accountId: 'newly-observed-workspace',
        identityKeys: ['account:newly-observed-workspace', 'user:bound-user', 'email:' + EMAIL] });
    } }),
  }), (error) => error.code === 'PHASE3_REMOTE_TARGET_CHANGED');
  assert.equal(reads, 2);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});

test('remote Phase3 validates queued remote state before spawning any local process', async (t) => {
  const { root, args } = fixture(t);
  let release;
  let entered;
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const blocker = withControlPlaneLock(async () => { entered(); await gate; });
  await enteredPromise;
  let current = account();
  const execution = runPhase3Job({ ...args,
    remoteClientFactory: () => ({ baseUrl: BASE_URL, async getAccount() { return current; } }) });
  const rejection = assert.rejects(execution, (error) => error.code === 'PHASE3_REMOTE_TARGET_CHANGED');
  current = account({ status: 'active', schedulable: true });
  release();
  await blocker;
  await rejection;
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});

test('remote Phase3 rejects another instance before reading its identical ID and strong identity', async (t) => {
  const { root, args } = fixture(t);
  let reads = 0;
  await assert.rejects(runPhase3Job({ ...args,
    remoteClientFactory: () => ({ baseUrl: 'https://other-instance.example.test/admin',
      async getAccount() { reads += 1; return account(); } }),
  }), (error) => error.code === 'PHASE3_REMOTE_ENDPOINT_CHANGED' && !error.requiresReconciliation);
  assert.equal(reads, 0);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});

test('remote Phase3 refuses a client endpoint switch during the final read before spawning', async (t) => {
  const { root, args } = fixture(t);
  let reads = 0;
  const client = { baseUrl: BASE_URL, async getAccount() {
    if (++reads === 2) client.baseUrl = 'https://other-instance.example.test/admin';
    return account();
  } };
  await assert.rejects(runPhase3Job({ ...args, remoteClientFactory: () => client }),
    (error) => error.code === 'PHASE3_REMOTE_ENDPOINT_CHANGED' && !error.requiresReconciliation);
  assert.equal(reads, 2);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});

test('remote Phase3 refuses remote changes during local preflight without process execution', async (t) => {
  const { root, args } = fixture(t);
  let reads = 0;
  await assert.rejects(runPhase3Job({ ...args,
    remoteClientFactory: () => ({ baseUrl: BASE_URL, async getAccount() {
      reads += 1;
      return reads === 1 ? account() : account({ tokenFingerprints: { access: 'd'.repeat(64) } });
    } }),
  }), (error) => error.code === 'PHASE3_REMOTE_TARGET_CHANGED');
  assert.equal(reads, 2);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});

test('remote Phase3 refuses local ledger changes during final remote read', async (t) => {
  const { root, record, args } = fixture(t);
  let reads = 0;
  await assert.rejects(runPhase3Job({ ...args,
    remoteClientFactory: () => ({ baseUrl: BASE_URL, async getAccount() {
      if (++reads === 2) fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
        { ...record, password: 'concurrent-fixture-change' },
      ]));
      return account();
    } }),
  }), (error) => error.code === 'PHASE3_LOCAL_BASELINE_CHANGED');
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});

test('remote Phase3 read failures are fixed messages without leaked upstream credentials', async (t) => {
  const { root, args } = fixture(t);
  await assert.rejects(runPhase3Job({ ...args,
    remoteClientFactory: () => ({ baseUrl: BASE_URL, async getAccount() { throw new Error('fixture-upstream-secret'); } }),
  }), (error) => error.code === 'PHASE3_REMOTE_READ_FAILED'
    && !error.message.includes('fixture-upstream-secret') && !error.requiresReconciliation);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});

test('remote Phase3 can verify a password reset only with matching remote output identity', async (t) => {
  const script = [
    "const filename = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(filename, 'utf8'));",
    "records[0].password = 'new-remote-fixture-password';",
    "fs.writeFileSync(filename, JSON.stringify(records));",
  ].join('\n');
  const { args } = fixture(t, { account: 'bound-workspace', user: 'bound-user' }, script);
  const result = await runPhase3Job(args);
  assert.equal(result.remoteTarget.accountId, 19);
});

test('remote Phase3 cannot validate a same-email password reset for a different account', async (t) => {
  const script = [
    "const filename = path.join(process.cwd(), 'username.json');",
    "const records = JSON.parse(fs.readFileSync(filename, 'utf8'));",
    "records[0].password = 'different-account-fixture-password';",
    "fs.writeFileSync(filename, JSON.stringify(records));",
  ].join('\n');
  const { args } = fixture(t, { account: 'other-workspace', user: 'bound-user' }, script);
  await assert.rejects(runPhase3Job(args), (error) => error.code === 'PHASE3_TOKEN_IDENTITY_MISMATCH'
    && error.requiresReconciliation === true && error.doNotRetry === true);
});

test('remote Phase3 rejects token files introduced during the final remote read', async (t) => {
  const { root, args } = fixture(t);
  let reads = 0;
  await assert.rejects(runPhase3Job({ ...args,
    remoteClientFactory: () => ({ baseUrl: BASE_URL, async getAccount() {
      if (++reads === 2) fs.writeFileSync(path.join(root, 'tokens', 'concurrent.json'), JSON.stringify({
        email: 'unrelated@example.test', access_token: 'concurrent-fixture', chatgpt_account_id: 'unrelated',
      }));
      return account();
    } }),
  }), (error) => error.code === 'PHASE3_LOCAL_BASELINE_CHANGED');
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'bound.json')), false);
});
