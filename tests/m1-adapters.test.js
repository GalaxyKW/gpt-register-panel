const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const { readGptRegisterSources, isHistoricalTokenFile } = require('../backend/adapters/gptRegisterFs');
const { buildIdentityKeys, tokenFingerprint } = require('../backend/lib/token');
const {
  Sub2ApiAdminClient,
  safeAccount,
  normalizeUsageStats,
  normalizeTableUsageStats,
} = require('../backend/adapters/sub2apiAdmin');
const { buildDiff } = require('../backend/diff');
const { buildRows, rowFromDiffItem } = require('../backend/view');
const { buildImportPlan } = require('../backend/sync');

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
  assert.match(sources.tokens.find((item) => item.parseStatus === 'ok').contentHash, /^[a-f0-9]{64}$/);
  assert.match(sources.usernameContentHash, /^[a-f0-9]{64}$/);
  assert.equal(sources.usernames[0].email, 'example@email.test');
  assert.equal(sources.usernames[0].hasPassword, true);
  assert.equal(Object.prototype.hasOwnProperty.call(sources.usernames[0], 'password'), false);
  const serialized = JSON.stringify(sources);
  assert.equal(serialized.includes('must-not-be-returned'), false);
  assert.equal(serialized.includes('refresh-1'), false);
});

test('safe username summaries never pass nested source values through', () => {
  const fixture = fixtureRoot();
  fs.writeFileSync(path.join(fixture.root, 'username.json'), JSON.stringify([{
    email: 'safe@example.test',
    password: { access_token: 'nested-password-value' },
    createdAt: { access_token: 'nested-created-value' },
    name: 'credential=nested-name-value',
    status: { access_token: 'nested-status-value' },
  }]));
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  assert.equal(sources.usernames[0].createdAt, null);
  assert.equal(sources.usernames[0].hasPassword, false);
  assert.equal(sources.usernames[0].status, '');
  const serialized = JSON.stringify(sources);
  for (const secret of [
    'nested-password-value',
    'nested-created-value',
    'nested-name-value',
    'nested-status-value',
  ]) assert.equal(serialized.includes(secret), false);
});

test('token reads pin the verified directory and reject a parent replacement race', () => {
  const fixture = fixtureRoot();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-outside-'));
  const tokenDirectory = path.join(fixture.root, 'tokens');
  const savedDirectory = path.join(fixture.root, 'tokens-original');
  fs.writeFileSync(path.join(outside, 'b.json'), JSON.stringify({
    access_token: 'outside-access-value',
    refresh_token: 'outside-refresh-value',
    account_id: 'outside-account',
    email: 'outside@example.test',
  }));
  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = function guardedOpen(target, ...args) {
    if (!swapped && typeof target === 'string' && /\/b\.json$/.test(target)) {
      swapped = true;
      fs.renameSync(tokenDirectory, savedDirectory);
      fs.symlinkSync(outside, tokenDirectory, 'dir');
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    const sources = readGptRegisterSources({ rootDirectory: fixture.root, includeRaw: true });
    const raced = sources.tokens.find((item) => item.fileName === 'b.json');
    assert.equal(raced.parseStatus, 'invalid');
    assert.equal(JSON.stringify(sources).includes('outside-access-value'), false);
    assert.equal(JSON.stringify(sources).includes('outside-account'), false);
  } finally {
    fs.openSync = originalOpenSync;
    if (swapped) {
      fs.unlinkSync(tokenDirectory);
      fs.renameSync(savedDirectory, tokenDirectory);
    }
  }
});

test('token reads reject a final symlink without reading its target', () => {
  const fixture = fixtureRoot();
  const outsideFile = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-token-link-')),
    'outside.json',
  );
  fs.writeFileSync(outsideFile, JSON.stringify({
    access_token: 'linked-access-value',
    refresh_token: 'linked-refresh-value',
    account_id: 'linked-account',
  }));
  fs.symlinkSync(outsideFile, path.join(fixture.root, 'tokens', 'linked.json'));
  const sources = readGptRegisterSources({ rootDirectory: fixture.root, includeRaw: true });
  const linked = sources.tokens.find((item) => item.fileName === 'linked.json');
  assert.equal(linked.parseStatus, 'invalid');
  assert.equal(JSON.stringify(sources).includes('linked-access-value'), false);
  assert.equal(JSON.stringify(sources).includes('linked-account'), false);
});

test('source JSON size limits are enforced before parsing', () => {
  const fixture = fixtureRoot();
  fs.writeFileSync(
    path.join(fixture.root, 'tokens', 'oversized.json'),
    JSON.stringify({ access_token: 'x'.repeat(2048), account_id: 'oversized-account' }),
  );
  const sources = readGptRegisterSources({
    rootDirectory: fixture.root,
    includeRaw: true,
    tokenMaxBytes: 1024,
  });
  const oversized = sources.tokens.find((item) => item.fileName === 'oversized.json');
  assert.equal(oversized.parseStatus, 'invalid');
  assert.match(oversized.parseError, /大小上限/);

  fs.writeFileSync(path.join(fixture.root, 'username.json'), JSON.stringify([
    { email: 'large@example.test', password: 'x'.repeat(2048) },
  ]));
  assert.throws(
    () => readGptRegisterSources({ rootDirectory: fixture.root, usernameMaxBytes: 1024 }),
    (error) => error.code === 'GPT_REGISTER_FILE_TOO_LARGE',
  );
});

test('token scans enforce aggregate file limits and reject hard-linked sources', () => {
  const fixture = fixtureRoot();
  assert.throws(
    () => readGptRegisterSources({ rootDirectory: fixture.root, tokenMaxFiles: 1 }),
    (error) => error.code === 'GPT_REGISTER_SOURCE_LIMIT',
  );

  const largePath = path.join(fixture.root, 'tokens', 'aggregate-large.json');
  fs.writeFileSync(largePath, JSON.stringify({
    access_token: 'x'.repeat(2048),
    account_id: 'aggregate-account',
  }));
  assert.throws(
    () => readGptRegisterSources({ rootDirectory: fixture.root, tokenTotalMaxBytes: 1024 }),
    (error) => error.code === 'GPT_REGISTER_SOURCE_LIMIT',
  );

  fs.unlinkSync(largePath);
  const originalPath = path.join(fixture.root, 'tokens', 'hardlink-source.json');
  const linkedPath = path.join(fixture.root, 'tokens', 'hardlink-alias.json');
  fs.writeFileSync(originalPath, JSON.stringify({
    access_token: 'hardlink-secret-value',
    account_id: 'hardlink-account',
  }));
  fs.linkSync(originalPath, linkedPath);
  const sources = readGptRegisterSources({ rootDirectory: fixture.root, includeRaw: true });
  for (const name of ['hardlink-source.json', 'hardlink-alias.json']) {
    assert.equal(sources.tokens.find((item) => item.fileName === name).parseStatus, 'invalid');
  }
  assert.equal(JSON.stringify(sources).includes('hardlink-secret-value'), false);
});

test('malformed token JSON reports a stable error without parser input fragments', () => {
  const fixture = fixtureRoot();
  fs.writeFileSync(
    path.join(fixture.root, 'tokens', 'malformed.json'),
    '{"access_token":"parser-secret-value",',
  );
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  const malformed = sources.tokens.find((item) => item.fileName === 'malformed.json');
  assert.equal(malformed.parseStatus, 'invalid');
  assert.equal(malformed.parseError, 'token JSON 无效');
  assert.equal(JSON.stringify(malformed).includes('parser-secret-value'), false);
});

test('write-plan source reads reject malformed username JSON', () => {
  const fixture = fixtureRoot();
  fs.writeFileSync(path.join(fixture.root, 'username.json'), '{invalid');
  const diagnostic = readGptRegisterSources({ rootDirectory: fixture.root });
  assert.deepEqual(diagnostic.usernames, []);
  assert.throws(
    () => readGptRegisterSources({ rootDirectory: fixture.root, includeRaw: true }),
    (error) => error.code === 'GPT_REGISTER_USERNAME_INVALID',
  );
});

test('username reads reject replacement of the fixed gpt_register root', () => {
  const fixture = fixtureRoot();
  const parent = path.dirname(fixture.root);
  const savedRoot = path.join(parent, path.basename(fixture.root) + '-original');
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-username-outside-'));
  fs.mkdirSync(path.join(outside, 'tokens'));
  fs.mkdirSync(path.join(outside, 'use_token'));
  fs.writeFileSync(path.join(outside, 'username.json'), JSON.stringify([
    { email: 'outside@example.test', password: 'outside-password-value' },
  ]));
  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = function guardedOpen(target, ...args) {
    if (!swapped && typeof target === 'string' && /\/username\.json$/.test(target)) {
      swapped = true;
      fs.renameSync(fixture.root, savedRoot);
      fs.symlinkSync(outside, fixture.root, 'dir');
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    assert.throws(
      () => readGptRegisterSources({ rootDirectory: fixture.root, includeRaw: true }),
      (error) => error.code === 'GPT_REGISTER_PATH_INVALID'
        && !String(error.message).includes('outside-password-value'),
    );
  } finally {
    fs.openSync = originalOpenSync;
    if (swapped) {
      fs.unlinkSync(fixture.root);
      fs.renameSync(savedRoot, fixture.root);
    }
  }
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

test('shared workspace or user IDs with a contradictory second dimension are not duplicates', () => {
  const base = {
    source: 'tokens',
    parseStatus: 'ok',
    expiryStatus: 'missing',
    fingerprints: { access: 'fingerprint' },
  };
  const sameWorkspace = buildDiff([
    { ...base, relativePath: 'tokens/u1.json', identityKeys: ['account:workspace-a', 'user:user-1'] },
    { ...base, relativePath: 'tokens/u2.json', identityKeys: ['account:workspace-a', 'user:user-2'] },
  ], []);
  assert.equal(sameWorkspace.counts.duplicate_identity || 0, 0);
  assert.equal(sameWorkspace.counts.token_only, 2);

  const sameUser = buildDiff([
    { ...base, relativePath: 'tokens/a1.json', identityKeys: ['account:workspace-1', 'user:user-a'] },
    { ...base, relativePath: 'tokens/a2.json', identityKeys: ['account:workspace-2', 'user:user-a'] },
  ], []);
  assert.equal(sameUser.counts.duplicate_identity || 0, 0);
  assert.equal(sameUser.counts.token_only, 2);
});

test('partial remote identities cannot collapse distinct source rows onto one selection key', () => {
  const tokens = [
    {
      source: 'tokens',
      relativePath: 'tokens/u1.json',
      fileName: 'u1.json',
      parseStatus: 'ok',
      expiryStatus: 'missing',
      identityKeys: ['account:workspace', 'user:u1', 'email:shared@example.test'],
      fingerprints: { access: tokenFingerprint('u1') },
    },
    {
      source: 'tokens',
      relativePath: 'tokens/u2.json',
      fileName: 'u2.json',
      parseStatus: 'ok',
      expiryStatus: 'missing',
      identityKeys: ['account:workspace', 'user:u2', 'email:shared@example.test'],
      fingerprints: { access: tokenFingerprint('u2') },
    },
  ];
  const account = {
    id: 266,
    name: 'free00006',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    identityKeys: ['account:workspace', 'email:shared@example.test'],
    tokenFingerprints: { access: tokenFingerprint('remote') },
  };
  const diff = buildDiff(tokens, [account]);
  const rows = buildRows(diff);

  assert.equal(diff.counts.mapping_conflict, 2);
  assert.equal(diff.counts.token_changed || 0, 0);
  assert.deepEqual(rows.map((row) => row.key).sort(), [
    'token:tokens:tokens/u1.json',
    'token:tokens:tokens/u2.json',
  ]);
  assert.equal(new Set(rows.map((row) => row.key)).size, 2);
  assert.equal(rows.every((row) => row.accountId === null), true);
  assert.equal(rows.every((row) => row.issues.includes('ambiguous_sub2api_identity')), true);

  const plan = buildImportPlan({
    tokens: tokens.map((token) => ({
      ...token,
      raw: {},
    })),
    usernames: [],
  }, [account], ['token:tokens:tokens/u1.json']);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].relativePath, 'tokens/u1.json');
  assert.equal(plan[0].action, 'conflict');
  assert.equal(plan[0].reason, 'ambiguous_sub2api_identity');

  const remoteOnlyRows = buildRows(buildDiff([], [account]));
  assert.equal(remoteOnlyRows.length, 1);
  assert.equal(remoteOnlyRows[0].key, 'account:266');
  assert.equal(remoteOnlyRows[0].accountId, 266);
});

test('classifies old_codex files as hidden historical backups', () => {
  const fixture = fixtureRoot();
  fs.copyFileSync(
    path.join(fixture.root, 'tokens', 'b.json'),
    path.join(fixture.root, 'tokens', 'old_codex-b.json'),
  );
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  const token = sources.tokens.find((item) => item.fileName === 'b.json');
  const historical = sources.tokens.find((item) => item.fileName === 'old_codex-b.json');
  const account = {
    id: 19,
    name: 'free00019',
    status: 'active',
    identityKeys: token.identityKeys,
    tokenFingerprints: token.fingerprints,
  };
  assert.equal(isHistoricalTokenFile('old_codex-b.json'), true);
  assert.equal(isHistoricalTokenFile('codex-b.json'), false);
  assert.equal(historical.historical, true);
  assert.equal(sources.summary.historicalTokenCount, 1);
  assert.equal(sources.summary.activeTokenCount, 2);
  let diff = buildDiff(sources.tokens, [account]);
  assert.equal(diff.counts.in_sync, 1);
  assert.equal(diff.counts.historical_backup, undefined);
  diff = buildDiff(sources.tokens, [account], { includeHistorical: true });
  assert.equal(diff.counts.in_sync, 1);
  assert.equal(diff.counts.historical_backup, 1);
});

test('links duplicate source rows to their unique Sub2API account', () => {
  const fixture = fixtureRoot();
  fs.copyFileSync(
    path.join(fixture.root, 'tokens', 'b.json'),
    path.join(fixture.root, 'use_token', 'c.json'),
  );
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const account = {
    id: 23,
    name: 'free00023',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    email: token.email,
    accountId: token.accountId,
    userId: token.userId,
    identityKeys: buildIdentityKeys(token),
    tokenFingerprints: { access: token.fingerprints.access },
    groupIds: [],
  };
  const diff = buildDiff(sources.tokens, [account]);
  const duplicates = diff.items.filter((item) => item.kind === 'duplicate_identity');
  assert.equal(duplicates.length, 2);
  assert.equal(diff.counts.sub2api_only || 0, 0);
  assert.deepEqual(duplicates.map((item) => item.account?.id), [23, 23]);
  assert.notEqual(duplicates[0].relativePath, duplicates[1].relativePath);
});

test('uses Sub2API stored token fingerprints and credential-presence metadata without reading raw credentials', () => {
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
    credentials_status: {
      has_access_token: true,
      has_refresh_token: true,
    },
    extra: {
      access_token_sha256: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      refresh_token_sha256: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    },
  });
  assert.equal(safe.tokenFingerprints.access, '1234567890abcdef');
  assert.equal(safe.tokenFingerprints.refresh, 'abcdef1234567890');
  assert.deepEqual(safe.credentialPresence, {
    access: 'present',
    refresh: 'present',
    id: 'absent',
  });
  assert.equal(Object.prototype.hasOwnProperty.call(safe, 'credentials'), false);
});

test('credential-presence metadata is tri-state and malformed metadata fails closed', () => {
  const absent = safeAccount({
    id: 190,
    credentials_status: { has_access_token: true },
    extra: { access_token_sha256: '1'.repeat(64) },
  });
  assert.equal(absent.schemaValid, true);
  assert.deepEqual(absent.credentialPresence, {
    access: 'present',
    refresh: 'absent',
    id: 'absent',
  });

  const legacy = safeAccount({ id: 191 });
  assert.deepEqual(legacy.credentialPresence, {
    access: 'unknown',
    refresh: 'unknown',
    id: 'unknown',
  });

  const supportedProviderKeys = safeAccount({
    id: 192,
    credentials_status: {
      has_clearTextPassword: true,
      'has_sso-rw': true,
    },
  });
  assert.equal(supportedProviderKeys.schemaValid, true);

  for (const credentialsStatus of [
    [],
    { has_refresh_token: 'true' },
    { refresh_token: true },
    { '': true },
    { ['has_' + 'a'.repeat(129)]: true },
    { 'has_access\ntoken': true },
  ]) {
    const malformed = safeAccount({ id: 192, credentials_status: credentialsStatus });
    assert.equal(malformed.schemaValid, false);
    assert.equal(malformed.credentialPresence.refresh, 'unknown');
  }

  const contradictory = safeAccount({
    id: 193,
    credentials_status: { has_access_token: true },
    extra: {
      access_token_sha256: '2'.repeat(64),
      refresh_token_sha256: '3'.repeat(64),
    },
  });
  assert.equal(contradictory.schemaValid, false);
  assert.equal(contradictory.credentialsStatusConflict, true);
});

test('diff requires a matching remote refresh fingerprint when the source can refresh', () => {
  const fixture = fixtureRoot();
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const base = {
    id: 194,
    name: 'free00194',
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: token.fingerprints.access, refresh: null },
  };
  let diff = buildDiff(sources.tokens, [{
    ...base,
    credentialPresence: { access: 'present', refresh: 'absent', id: 'unknown' },
  }]);
  assert.equal(diff.counts.missing_refresh_token, 1);

  diff = buildDiff(sources.tokens, [{
    ...base,
    credentialPresence: { access: 'present', refresh: 'present', id: 'unknown' },
  }]);
  assert.equal(diff.counts.token_changed, 1);

  diff = buildDiff(sources.tokens, [{
    ...base,
    tokenFingerprints: { ...token.fingerprints },
    credentialPresence: { access: 'present', refresh: 'present', id: 'unknown' },
  }]);
  assert.equal(diff.counts.in_sync, 1);
});

test('diff does not claim a refresh token is missing when the source has none', () => {
  const token = {
    source: 'tokens',
    relativePath: 'tokens/access-only.json',
    fileName: 'access-only.json',
    parseStatus: 'ok',
    identityKeys: ['account:access-only-account'],
    fingerprints: { access: 'same-access-fingerprint', refresh: null },
    expiryStatus: 'missing',
  };
  const account = {
    id: 195,
    identityKeys: token.identityKeys,
    tokenFingerprints: { access: token.fingerprints.access, refresh: null },
  };
  for (const refresh of ['unknown', 'absent']) {
    const diff = buildDiff([token], [{
      ...account,
      credentialPresence: { access: 'present', refresh, id: 'unknown' },
    }]);
    assert.equal(diff.counts.in_sync, 1);
    assert.equal(diff.counts.missing_refresh_token, undefined);
  }
});

test('preserves explicit zero usage values and rejects invalid account ids', () => {
  const usage = normalizeUsageStats({ requests: 0, tokens: 0, input_tokens: 12, output_tokens: 30 });
  assert.equal(usage.requests, 0);
  assert.equal(usage.totalTokens, 0);
  const partial = normalizeUsageStats({ requests: 3, input_tokens: 12 });
  assert.equal(partial.requests, 3);
  assert.equal(partial.inputTokens, 12);
  assert.equal(partial.outputTokens, null);
  assert.equal(partial.totalTokens, 12);
  assert.equal(partial.cost, null);
  const malformed = normalizeUsageStats({ requests: '', total_tokens: 'not-a-number' });
  assert.equal(malformed.requests, null);
  assert.equal(malformed.totalTokens, null);
  assert.equal(safeAccount({ id: 'not-a-number', name: 'bad' }), null);
  assert.equal(safeAccount({ id: true, name: 'boolean-id' }), null);
});

test('Sub2API account listing fails closed on malformed and duplicate account ids', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  client.request = async () => ({
    items: [
      { id: 1, name: 'free00001' },
      { id: true, name: 'invalid-id' },
    ],
    total: 2,
  });
  await assert.rejects(
    client.listAccounts(),
    (error) => error.code === 'SUB2API_ACCOUNTS_SCHEMA_INVALID',
  );

  client.request = async () => ({
    items: [
      { id: 1, name: 'free00001' },
      { id: '1', name: 'free99999' },
    ],
    total: 2,
  });
  await assert.rejects(
    client.listAccounts(),
    (error) => error.code === 'SUB2API_ACCOUNT_ID_DUPLICATE',
  );
});

test('Sub2API account listing follows server-capped pages and rejects incomplete totals', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  let calls = 0;
  client.request = async (method, pathname) => {
    calls += 1;
    assert.equal(method, 'GET');
    const page = Number(new URL(pathname, 'http://sub2api.test').searchParams.get('page'));
    return page === 1
      ? { items: [{ id: 1 }, { id: 2 }], total: 3 }
      : { items: [{ id: 3 }], total: 3 };
  };
  const accounts = await client.listAccounts({ pageSize: 200 });
  assert.deepEqual(accounts.map((account) => account.id), [1, 2, 3]);
  assert.equal(calls, 2);

  client.request = async (method, pathname) => {
    const page = Number(new URL(pathname, 'http://sub2api.test').searchParams.get('page'));
    return page === 1
      ? { items: [{ id: 1 }, { id: 2 }], total: 3 }
      : { items: [], total: 3 };
  };
  await assert.rejects(
    client.listAccounts({ pageSize: 200 }),
    (error) => error.code === 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
  );
});

test('safe accounts preserve unknown status and malformed expiry metadata', () => {
  const safe = safeAccount({
    id: 22,
    status: 'active',
    schedulable: true,
    expires_at: 'not-a-date',
    credentials: { expires_at: 'also-not-a-date' },
  });
  assert.equal(safe.statusKnown, true);
  assert.equal(safe.schedulableKnown, true);
  assert.equal(safe.expiryStatus, 'invalid');
  assert.equal(safe.credentialExpiryStatus, 'invalid');
  assert.equal(safe.expiresAt, null);
  assert.equal(safe.credentialExpiresAt, null);
  assert.equal(safe.schemaValid, false);

  const missing = safeAccount({ id: 23 });
  assert.equal(missing.statusKnown, false);
  assert.equal(missing.schedulableKnown, false);
  assert.equal(missing.schedulable, null);
  const row = rowFromDiffItem({ kind: 'sub2api_only', token: null, account: missing, issues: [] });
  assert.equal(row.schedulable, null);
  assert.equal(row.availability, 'unknown');
});

test('safe accounts fail closed on conflicting aliases, fingerprints, and boolean metadata', () => {
  const conflictingIdentity = safeAccount({
    id: 24,
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    account_id: 'workspace-two',
    credentials: {
      account_id: 'workspace-one',
      user_id: 'user-one',
      access_token: 'remote-access-secret',
    },
    extra: { access_token_sha256: '0'.repeat(64) },
    auto_pause_on_expired: 'false',
    expires_at: '2099-01-01T00:00:00.000Z',
    expiresAt: '2098-01-01T00:00:00.000Z',
  });
  assert.equal(conflictingIdentity.schemaValid, false);
  assert.equal(conflictingIdentity.identityConflict, true);
  assert.equal(conflictingIdentity.fingerprintConflict, true);
  assert.equal(conflictingIdentity.autoPauseOnExpired, null);
  assert.equal(conflictingIdentity.expiryStatus, 'invalid');
  assert.equal(conflictingIdentity.tokenFingerprints.access, null);
  const row = rowFromDiffItem({
    kind: 'sub2api_only',
    token: null,
    account: conflictingIdentity,
    issues: [],
  });
  assert.equal(row.availability, 'unknown');
  assert.equal(JSON.stringify(conflictingIdentity).includes('remote-access-secret'), false);
});

test('preserves nested usage shape and does not turn missing stats into zero', () => {
  const nested = safeAccount({
    id: 20,
    name: 'free00020',
    usage: {
      historical: { total_tokens: 100, requests: 2 },
      current: { total_tokens: 4, requests: 1 },
    },
  });
  assert.equal(nested.usage.historical.totalTokens, 100);
  assert.equal(nested.usage.current.totalTokens, 4);
  assert.equal(safeAccount({ id: 21, usage: { historical: null, current: null } }).usage, null);
  assert.equal(normalizeTableUsageStats({ history: null, today: null }), null);
});

test('a strong token never maps to an email-only legacy account', () => {
  const fixture = fixtureRoot();
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  const token = sources.tokens.find((item) => item.parseStatus === 'ok');
  const legacy = {
    id: 264,
    name: 'free00006',
    status: 'error',
    identityKeys: ['email:' + token.email],
    tokenFingerprints: { access: 'legacy' },
  };
  const current = {
    id: 266,
    name: 'free00007',
    status: 'active',
    identityKeys: token.identityKeys,
    tokenFingerprints: token.fingerprints,
  };
  const diff = buildDiff(sources.tokens, [legacy, current]);
  const sourceRow = diff.items.find((item) => item.token?.relativePath === token.relativePath);
  const legacyRow = diff.items.find((item) => item.account?.id === 264);
  assert.equal(sourceRow.account.id, 266);
  assert.equal(sourceRow.kind, 'in_sync');
  assert.equal(legacyRow.kind, 'sub2api_only');
});

test('duplicate remote strong identities are conflicts, not ordinary remote-only rows', () => {
  const identityKeys = ['account:duplicate-account', 'user:duplicate-user'];
  const diff = buildDiff([], [
    { id: 31, name: 'free00031', identityKeys, tokenFingerprints: {} },
    { id: 32, name: 'free00032', identityKeys, tokenFingerprints: {} },
  ]);
  assert.equal(diff.counts.mapping_conflict, 2);
  assert.equal(diff.counts.sub2api_only || 0, 0);
  assert.deepEqual(diff.items.map((item) => item.account.id), [31, 32]);
});

test('Sub2API account errors are redacted and OAuth update responses stay credential-free', async () => {
  const safe = safeAccount({
    id: 40,
    name: 'free00040',
    status: 'error',
    error_message: 'Bearer abc.def.ghi access_token=do-not-return',
    temp_unschedulable_reason: 'credential=temp-reason-value',
    platform: { access_token: 'nested-platform-value' },
    type: { access_token: 'nested-type-value' },
  });
  assert.equal(safe.errorMessage.includes('abc.def.ghi'), false);
  assert.equal(safe.errorMessage.includes('do-not-return'), false);
  assert.equal(safe.tempUnschedulableReason.includes('temp-reason-value'), false);
  assert.equal(safe.platform, '');
  assert.equal(safe.type, '');
  assert.equal(JSON.stringify(safe).includes('nested-platform-value'), false);
  assert.equal(JSON.stringify(safe).includes('nested-type-value'), false);

  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  client.request = async () => ({
    id: 41,
    name: 'free00041',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
    credentials: {
      access_token: 'remote-secret',
      email: 'safe@example.test',
      chatgpt_account_id: 'safe-account',
    },
  });
  const updated = await client.applyOAuthCredentials(41, { type: 'oauth', credentials: {} });
  assert.equal(updated.id, 41);
  assert.equal(Object.hasOwn(updated, 'credentials'), false);
  assert.equal(JSON.stringify(updated).includes('remote-secret'), false);

  client.request = async () => ({ id: 42, status: 'error', schedulable: false });
  await assert.rejects(
    client.getAccount(41),
    (error) => error.code === 'SUB2API_ACCOUNT_RESPONSE_MISMATCH',
  );
  await assert.rejects(
    client.applyOAuthCredentials(41, { type: 'oauth', credentials: {} }),
    (error) => error.code === 'SUB2API_CREDENTIALS_RESPONSE_MISMATCH',
  );

  client.request = async () => ({
    id: 41,
    name: 'free00041',
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
  });
  const scheduled = await client.setSchedulable(41, true);
  assert.equal(scheduled.id, 41);
  assert.equal(scheduled.schedulable, true);
  assert.equal(Object.hasOwn(scheduled, 'credentials'), false);
  assert.equal(JSON.stringify(scheduled).includes('remote-secret'), false);

  client.request = async () => ({
    id: 42,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
  });
  await assert.rejects(
    client.setSchedulable(41, true),
    (error) => error.code === 'SUB2API_SCHEDULABLE_RESPONSE_MISMATCH',
  );

  client.request = async () => ({
    id: 41,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: false,
  });
  await assert.rejects(
    client.setSchedulable(41, true),
    (error) => error.code === 'SUB2API_SCHEDULABLE_RESPONSE_MISMATCH',
  );
  await assert.rejects(
    client.setSchedulable(true, true),
    (error) => error.code === 'SUB2API_SCHEDULABLE_ID_INVALID',
  );
  await assert.rejects(
    client.setSchedulable(41, 'true'),
    (error) => error.code === 'SUB2API_SCHEDULABLE_VALUE_INVALID',
  );
});

test('Sub2API base URL rejects query strings and fragments', () => {
  assert.throws(
    () => new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080?target=other', apiKey: 'test-key' }),
    /查询参数/,
  );
  assert.throws(
    () => new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080/#fragment', apiKey: 'test-key' }),
    /查询参数/,
  );
});

test('Sub2API permits plaintext HTTP only for loopback unless explicitly overridden', () => {
  const previous = process.env.SUB2API_ALLOW_INSECURE_HTTP;
  delete process.env.SUB2API_ALLOW_INSECURE_HTTP;
  try {
    assert.doesNotThrow(
      () => new Sub2ApiAdminClient({ baseUrl: 'http://127.12.34.56:8080', apiKey: 'test-key' }),
    );
    assert.doesNotThrow(
      () => new Sub2ApiAdminClient({ baseUrl: 'http://[::1]:8080', apiKey: 'test-key' }),
    );
    assert.throws(
      () => new Sub2ApiAdminClient({ baseUrl: 'http://192.0.2.10:8080', apiKey: 'test-key' }),
      (error) => error.code === 'SUB2API_INSECURE_HTTP',
    );
    assert.doesNotThrow(
      () => new Sub2ApiAdminClient({
        baseUrl: 'http://192.0.2.10:8080',
        apiKey: 'test-key',
        allowInsecureHttp: true,
      }),
    );
  } finally {
    if (previous === undefined) delete process.env.SUB2API_ALLOW_INSECURE_HTTP;
    else process.env.SUB2API_ALLOW_INSECURE_HTTP = previous;
  }
});

test('Sub2API request errors are redacted before leaving the adapter', async () => {
  const originalFetch = global.fetch;
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  try {
    global.fetch = async () => ({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      body: null,
      async text() {
        return JSON.stringify({
          success: false,
          message: 'error_message=Bearer remote.header.value; access_token=remote-access-value',
        });
      },
    });
    await assert.rejects(
      client.request('GET', '/api/v1/admin/accounts/1'),
      (error) => !error.message.includes('remote.header.value')
        && !error.message.includes('remote-access-value'),
    );

    global.fetch = async () => {
      throw new Error('credential=network-credential-value Bearer network.header.value');
    };
    await assert.rejects(
      client.request('GET', '/api/v1/admin/accounts/1'),
      (error) => !error.message.includes('network-credential-value')
        && !error.message.includes('network.header.value'),
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test('Sub2API Codex imports require a bounded printable idempotency key only', async () => {
  const originalFetch = global.fetch;
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  let fetchCalls = 0;
  let capturedHeaders = null;
  try {
    global.fetch = async (url, options) => {
      fetchCalls += 1;
      assert.equal(url, 'http://127.0.0.1:8080/api/v1/admin/accounts/import/codex-session');
      capturedHeaders = options.headers;
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        body: null,
        async text() {
          return JSON.stringify({
            success: true,
            data: {
              total: 1,
              created: 1,
              updated: 0,
              skipped: 0,
              failed: 0,
              items: [{ action: 'created', account_id: 41 }],
            },
          });
        },
      };
    };

    await assert.rejects(
      client.importCodexSession({ content: '{}' }),
      (error) => error.code === 'SUB2API_IDEMPOTENCY_KEY_INVALID',
    );
    for (const idempotencyKey of [
      '',
      'contains space',
      'contains\nnewline',
      '不是-ascii',
      'x'.repeat(129),
    ]) {
      await assert.rejects(
        client.importCodexSession({ content: '{}' }, { idempotencyKey }),
        (error) => error.code === 'SUB2API_IDEMPOTENCY_KEY_INVALID',
      );
    }
    assert.equal(fetchCalls, 0);

    const idempotencyKey = 'gptreg-create-v1-' + 'a'.repeat(64);
    const result = await client.importCodexSession(
      { content: '{}' },
      {
        idempotencyKey,
        headers: { 'x-untrusted-header': 'must-not-cross-boundary' },
      },
    );
    assert.equal(result.created, 1);
    assert.equal(fetchCalls, 1);
    assert.equal(capturedHeaders['Idempotency-Key'], idempotencyKey);
    assert.equal(Object.hasOwn(capturedHeaders, 'x-untrusted-header'), false);
  } finally {
    global.fetch = originalFetch;
  }
});

test('Sub2API batch-stat errors leave the adapter only after redaction', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  client.request = async () => JSON.parse(
    '{"stats":{"1":{"historical":{"requests":1}},"2":{"historical":{"requests":99}},'
      + '"__proto__":{"historical":{"requests":100}}},'
      + '"errors":{"1":{"message":"Bearer stats.header.value access_token=stats-access-value"},'
      + '"2":"unexpected-account-error","__proto__":"prototype-error"}}',
  );
  const result = await client.getBatchTableUsageStats([1]);
  assert.equal(result.errors['1'].includes('stats.header.value'), false);
  assert.equal(result.errors['1'].includes('stats-access-value'), false);
  assert.deepEqual(Object.keys(result.stats), ['1']);
  assert.deepEqual(Object.keys(result.errors), ['1']);
  assert.equal(Object.getPrototypeOf(result.stats), null);
  assert.equal(Object.getPrototypeOf(result.errors), null);
  assert.equal(result.stats.__proto__, undefined);
  assert.equal(result.errors.__proto__, undefined);
});

test('Sub2API timeouts are hard-bounded and request serialization clears its timer', async () => {
  const client = new Sub2ApiAdminClient({
    baseUrl: 'http://127.0.0.1:8080',
    apiKey: 'test-key',
    timeoutMs: Number.MAX_SAFE_INTEGER,
    testTimeoutMs: Number.MAX_SAFE_INTEGER,
  });
  assert.equal(client.timeoutMs, 120000);
  assert.equal(client.testTimeoutMs, 600000);

  const originalFetch = global.fetch;
  const originalSetTimeout = global.setTimeout;
  const originalClearTimeout = global.clearTimeout;
  let requestTimer = null;
  let requestTimerCleared = false;
  let fetchCalled = false;
  try {
    global.setTimeout = (callback, delay) => {
      requestTimer = originalSetTimeout(callback, delay);
      return requestTimer;
    };
    global.clearTimeout = (timer) => {
      if (timer === requestTimer) requestTimerCleared = true;
      return originalClearTimeout(timer);
    };
    global.fetch = async () => {
      fetchCalled = true;
      throw new Error('fetch must not run');
    };
    const circular = {};
    circular.self = circular;
    await assert.rejects(client.request('POST', '/api/v1/admin/accounts/import', circular));
    assert.equal(fetchCalled, false);
    assert.equal(requestTimerCleared, true);
  } finally {
    global.fetch = originalFetch;
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
    if (requestTimer) originalClearTimeout(requestTimer);
  }
});

test('Sub2API model values are bounded and cannot carry credential text', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  client.request = async () => ({
    models: [
      'gpt-5.6-luna',
      'Bearer model.header.value',
      'credential=model-credential-value',
      'model\nwith-control',
      'x'.repeat(257),
      { id: { access_token: 'nested-model-value' } },
    ],
  });
  const models = await client.getAvailableModels(1);
  assert.equal(models.includes('gpt-5.6-luna'), true);
  assert.equal(models.includes('model with-control'), true);
  assert.equal(models.length, 2);
  assert.equal(JSON.stringify(models).includes('model.header.value'), false);
  assert.equal(JSON.stringify(models).includes('model-credential-value'), false);
  assert.equal(JSON.stringify(models).includes('nested-model-value'), false);

  const originalFetch = global.fetch;
  try {
    global.fetch = async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      body: null,
      async text() {
        return 'data: ' + JSON.stringify({
          type: 'test_complete',
          success: true,
          model: 'gpt-5',
        }) + '\n\n';
      },
    });
    await assert.rejects(
      client.testAccount(1, { modelId: 'gpt-5.6-luna' }),
      (error) => error.code === 'SUB2API_TEST_MODEL_MISMATCH',
    );

    global.fetch = async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      body: null,
      async text() {
        return 'data: ' + JSON.stringify({
          type: 'test_complete',
          success: true,
          model: 'credential=sse-model-value',
        }) + '\n\n';
      },
    });
    const tested = await client.testAccount(1);
    assert.equal(tested.success, true);
    assert.equal(tested.model, null);
    assert.equal(JSON.stringify(tested).includes('sse-model-value'), false);
  } finally {
    global.fetch = originalFetch;
  }
});
