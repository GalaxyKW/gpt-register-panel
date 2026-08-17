const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
const { buildIdentityKeys, tokenFingerprint } = require('../backend/lib/token');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { buildDiff } = require('../backend/diff');

function makeJwt(payload) {
  return [
    'header',
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    'signature',
  ].join('.');
}

function fixtureRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    {
      email: 'Example@Email.test',
      password: 'must-not-be-returned',
      status: 'oauth_done',
      createdAt: '2026-08-11T10:00:00.000Z',
    },
  ]));
  const accessToken = makeJwt({
    sub: 'user-1',
    exp: Math.floor(Date.now() / 1000) + 3600,
    email: 'Example@Email.test',
    'https://api.openai.com/auth': {
      chatgpt_account_id: 'account-1',
      chatgpt_user_id: 'user-1',
    },
  });
  fs.writeFileSync(path.join(root, 'tokens', 'b.json'), JSON.stringify({
    access_token: accessToken,
    refresh_token: 'refresh-1',
    email: 'Example@Email.test',
    expired: '2099-01-01T00:00:00.000Z',
  }));
  fs.writeFileSync(path.join(root, 'tokens', 'a.json'), '.not-json');
  return { root };
}

test('reads token directories in deterministic order and redacts username passwords', () => {
  const fixture = fixtureRoot();
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  assert.deepEqual(sources.tokens.map((item) => item.fileName), ['a.json', 'b.json']);
  assert.equal(sources.summary.validTokenCount, 1);
  assert.equal(sources.summary.invalidTokenCount, 1);
  assert.equal(sources.usernames[0].email, 'example@email.test');
  assert.equal(sources.usernames[0].hasPassword, true);
  assert.equal(Object.prototype.hasOwnProperty.call(sources.usernames[0], 'password'), false);
  const serialized = JSON.stringify(sources);
  assert.equal(serialized.includes('must-not-be-returned'), false);
  assert.equal(serialized.includes('refresh-1'), false);
});

test('matches a Sub2API account by stable identity and detects changed tokens', () => {
  const fixture = fixtureRoot();
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 17,
    name: 'free00001',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    email: token.email,
    accountId: token.accountId,
    userId: token.userId,
    identityKeys: buildIdentityKeys(token),
    tokenFingerprints: { ...token.fingerprints },
    extra: { access_token_sha256: token.fingerprints.access + '0000000000000000' },
    groupIds: [3],
  };
  let diff = buildDiff(sources.tokens, [account], { nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  assert.equal(diff.counts.in_sync, 1);
  assert.equal(diff.counts.invalid_file, 1);
  account.tokenFingerprints.access = tokenFingerprint('different');
  diff = buildDiff(sources.tokens, [account], { nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  assert.equal(diff.counts.token_changed, 1);
});

test('flags duplicate identities and Sub2API-only accounts', () => {
  const fixture = fixtureRoot();
  fs.copyFileSync(
    path.join(fixture.root, 'tokens', 'b.json'),
    path.join(fixture.root, 'use_token', 'c.json'),
  );
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  const account = {
    id: 18,
    name: 'free00002',
    platform: 'openai',
    type: 'oauth',
    status: 'paused',
    email: 'not-in-token@example.test',
    accountId: 'account-2',
    userId: 'user-2',
    identityKeys: buildIdentityKeys({
      accountId: 'account-2',
      userId: 'user-2',
      email: 'not-in-token@example.test',
    }),
    tokenFingerprints: {},
    groupIds: [],
  };
  const diff = buildDiff(sources.tokens, [account]);
  assert.equal(diff.counts.duplicate_identity, 2);
  assert.equal(diff.counts.sub2api_only, 1);
});

test('uses Sub2API stored access token fingerprint without reading raw credentials', () => {
  const safe = safeAccount({
    id: 19,
    name: 'free00003',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    credentials: {
      email: 'fingerprint@example.test',
      chatgpt_account_id: 'account-3',
    },
    extra: {
      access_token_sha256: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    },
  });
  assert.equal(safe.tokenFingerprints.access, '1234567890abcdef');
  assert.equal(Object.prototype.hasOwnProperty.call(safe, 'credentials'), false);
});
