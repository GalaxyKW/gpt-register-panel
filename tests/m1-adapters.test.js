const assert = require('node:assert/strict');
const crypto = require('node:crypto');
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
const { buildRows, filterRows, rowFromDiffItem } = require('../backend/view');
const { buildImportPlan, buildSnapshot, safeErrorMessage } = require('../backend/sync');

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

test('case-insensitive filename ties have a stable total order', () => {
  const fixture = fixtureRoot();
  fs.writeFileSync(path.join(fixture.root, 'tokens', 'A.json'), JSON.stringify({
    access_token: 'uppercase-token',
    email: 'uppercase@example.test',
  }));
  const sources = readGptRegisterSources({ rootDirectory: fixture.root });
  assert.deepEqual(
    sources.tokens.filter((item) => item.source === 'tokens').map((item) => item.fileName),
    ['A.json', 'a.json', 'b.json'],
  );
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
  assert.throws(
    () => readGptRegisterSources({
      rootDirectory: fixture.root,
      includeRaw: true,
      tokenMaxBytes: 1024,
      strictCompleteSnapshot: true,
    }),
    (error) => error.code === 'GPT_REGISTER_FILE_TOO_LARGE',
  );

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
  assert.throws(
    () => readGptRegisterSources({
      rootDirectory: fixture.root,
      includeRaw: true,
      strictCompleteSnapshot: true,
    }),
    (error) => error.code === 'GPT_REGISTER_PATH_INVALID',
  );
});

test('token directory scans bound all entries independently from JSON files', () => {
  const fixture = fixtureRoot();
  fs.writeFileSync(path.join(fixture.root, 'tokens', 'ignored-one.txt'), 'ignored');
  fs.writeFileSync(path.join(fixture.root, 'tokens', 'ignored-two.txt'), 'ignored');
  assert.throws(
    () => readGptRegisterSources({
      rootDirectory: fixture.root,
      tokenMaxDirectoryEntries: 3,
    }),
    (error) => error.code === 'GPT_REGISTER_SOURCE_LIMIT'
      && /目录项数量/.test(error.message),
  );
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
    () => readGptRegisterSources({
      rootDirectory: fixture.root,
      includeRaw: true,
      strictCompleteSnapshot: true,
    }),
    (error) => error.code === 'GPT_REGISTER_USERNAME_INVALID',
  );
});

test('complete source snapshots reject malformed username identity and terminal fields', () => {
  const fixture = fixtureRoot();
  for (const record of [
    { email: { access_token: 'nested-email-secret' }, password: 'present', status: 'oauth_done' },
    { email: 'valid@example.test', password: 'present', status: { value: 'account_deleted' } },
    { email: 'valid@example.test', password: { value: 'nested-password-secret' }, status: 'oauth_done' },
    { email: 'del\u007f@example.test', password: 'present', status: 'oauth_done' },
    { email: 'valid@example.test', phone: '138\n0000', password: 'present', status: 'oauth_done' },
    { email: 'valid@example.test', name: 'display\tname', password: 'present', status: 'oauth_done' },
    { email: 'valid@example.test', password: 'password-lure\r\nnext', status: 'oauth_done' },
    { email: 'valid@example.test', password: 'present', status: 'oauth_done\n' },
  ]) {
    fs.writeFileSync(path.join(fixture.root, 'username.json'), JSON.stringify([record]));
    assert.throws(
      () => readGptRegisterSources({
        rootDirectory: fixture.root,
        includeRaw: true,
        strictCompleteSnapshot: true,
      }),
      (error) => {
        assert.equal(error.code, 'GPT_REGISTER_USERNAME_INVALID');
        for (const lure of ['nested-', 'password-lure']) {
          assert.equal(String(error.message).includes(lure), false);
          assert.equal(safeErrorMessage(error).includes(lure), false);
        }
        return true;
      },
    );
  }
});

test('complete source snapshots reject every missing required source explicitly', () => {
  for (const missing of ['tokens', 'use_token', 'username.json']) {
    const fixture = fixtureRoot();
    const target = path.join(fixture.root, missing);
    if (missing.endsWith('.json')) fs.unlinkSync(target);
    else fs.rmSync(target, { recursive: true });

    const diagnostic = readGptRegisterSources({ rootDirectory: fixture.root });
    assert.ok(diagnostic);
    assert.throws(
      () => readGptRegisterSources({
        rootDirectory: fixture.root,
        includeRaw: true,
        strictCompleteSnapshot: true,
      }),
      (error) => error.code === 'GPT_REGISTER_SOURCE_MISSING'
        && JSON.stringify(error.missingSources) === JSON.stringify([missing]),
      missing,
    );
  }
});

test('a missing root reports only the fixed required-source allowlist', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-missing-root-'));
  const missingRoot = path.join(parent, 'credential=must-not-be-reported');
  assert.throws(
    () => readGptRegisterSources({
      rootDirectory: missingRoot,
      includeRaw: true,
      strictCompleteSnapshot: true,
    }),
    (error) => {
      assert.equal(error.code, 'GPT_REGISTER_SOURCE_MISSING');
      assert.deepEqual(error.missingSources, ['tokens', 'use_token', 'username.json']);
      assert.equal(JSON.stringify(error.missingSources).includes('must-not-be-reported'), false);
      assert.equal(String(error.message).includes('must-not-be-reported'), false);
      assert.equal(safeErrorMessage(error).includes('must-not-be-reported'), false);
      return true;
    },
  );
});

test('write-plan snapshots stop before any remote read when a required source is missing', async () => {
  const fixture = fixtureRoot();
  fs.unlinkSync(path.join(fixture.root, 'username.json'));
  let remoteReads = 0;
  await assert.rejects(
    buildSnapshot(new URLSearchParams('withSub2api=1'), {
      rootDirectory: fixture.root,
      includeRaw: true,
      requireCompleteSources: true,
      client: {
        async listAccounts() {
          remoteReads += 1;
          return [];
        },
      },
    }),
    (error) => error.code === 'GPT_REGISTER_SOURCE_MISSING',
  );
  assert.equal(remoteReads, 0);
});

test('complete source snapshots reject unreadable token identities instead of using an older file', () => {
  const fixture = fixtureRoot();
  const original = path.join(fixture.root, 'tokens', 'unreadable.json');
  const alias = path.join(fixture.root, 'tokens', 'unreadable-alias.json');
  fs.writeFileSync(original, JSON.stringify({
    access_token: 'must-not-appear',
    account_id: 'same-account-as-an-older-file',
  }));
  fs.linkSync(original, alias);

  const diagnostic = readGptRegisterSources({ rootDirectory: fixture.root });
  assert.equal(
    diagnostic.tokens.filter((item) => item.fileName.startsWith('unreadable')).length,
    2,
  );
  assert.throws(
    () => readGptRegisterSources({
      rootDirectory: fixture.root,
      includeRaw: true,
      strictCompleteSnapshot: true,
    }),
    (error) => error.code === 'GPT_REGISTER_PATH_INVALID',
  );
  assert.equal(JSON.stringify(diagnostic).includes('must-not-appear'), false);
});

test('complete source snapshots detect token directory changes during enumeration', () => {
  const fixture = fixtureRoot();
  const tokenDirectory = path.join(fixture.root, 'tokens');
  const originalOpendirSync = fs.opendirSync;
  let tokenReads = 0;
  fs.opendirSync = function changingOpendir(target, ...args) {
    const result = originalOpendirSync.call(fs, target, ...args);
    let realTarget = '';
    try { realTarget = fs.realpathSync(String(target)); } catch {}
    if (realTarget !== tokenDirectory || ++tokenReads !== 1) return result;
    let changed = false;
    return {
      readSync() {
        const entry = result.readSync();
        if (!entry && !changed) {
          changed = true;
          fs.writeFileSync(path.join(tokenDirectory, 'appeared-during-scan.json'), JSON.stringify({
            access_token: 'late-token-must-not-appear',
            account_id: 'late-account',
          }));
        }
        return entry;
      },
      closeSync() {
        return result.closeSync();
      },
    };
  };
  try {
    assert.throws(
      () => readGptRegisterSources({
        rootDirectory: fixture.root,
        includeRaw: true,
        strictCompleteSnapshot: true,
      }),
      (error) => error.code === 'GPT_REGISTER_SOURCE_CHANGED',
    );
  } finally {
    fs.opendirSync = originalOpendirSync;
  }
});

test('a JSON disappearing after enumeration is source-changed, not source-missing', () => {
  const fixture = fixtureRoot();
  const targetPath = path.join(fixture.root, 'tokens', 'a.json');
  const originalLstatSync = fs.lstatSync;
  let injected = false;
  fs.lstatSync = function disappearingEnumeratedFile(target, ...args) {
    let realTarget = '';
    try { realTarget = fs.realpathSync(String(target)); } catch {}
    if (!injected && String(target).startsWith('/proc/self/fd/') && realTarget === targetPath) {
      injected = true;
      const error = new Error('simulated enumerated file disappearance');
      error.code = 'ENOENT';
      throw error;
    }
    return originalLstatSync.call(fs, target, ...args);
  };
  try {
    assert.throws(
      () => readGptRegisterSources({
        rootDirectory: fixture.root,
        includeRaw: true,
        strictCompleteSnapshot: true,
      }),
      (error) => error.code === 'GPT_REGISTER_SOURCE_CHANGED'
        && error.missingSources === undefined,
    );
    assert.equal(injected, true);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
});

test('a verified source path disappearing while opening stays path-invalid', () => {
  const fixture = fixtureRoot();
  const tokenDirectory = path.join(fixture.root, 'tokens');
  const originalOpenSync = fs.openSync;
  let injected = false;
  fs.openSync = function disappearingSourceOpen(target, ...args) {
    let realTarget = '';
    try { realTarget = fs.realpathSync(String(target)); } catch {}
    if (!injected && realTarget === tokenDirectory) {
      injected = true;
      const error = new Error('simulated source open race');
      error.code = 'ENOENT';
      throw error;
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    assert.throws(
      () => readGptRegisterSources({
        rootDirectory: fixture.root,
        includeRaw: true,
        strictCompleteSnapshot: true,
      }),
      (error) => error.code === 'GPT_REGISTER_PATH_INVALID'
        && error.missingSources === undefined,
    );
    assert.equal(injected, true);
  } finally {
    fs.openSync = originalOpenSync;
  }
});

test('every strict token manifest pass uses the bounded iterator', () => {
  const fixture = fixtureRoot();
  const tokenDirectories = new Set([
    path.join(fixture.root, 'tokens'),
    path.join(fixture.root, 'use_token'),
  ]);
  const originalReaddirSync = fs.readdirSync;
  const originalOpendirSync = fs.opendirSync;
  let boundedPasses = 0;
  fs.readdirSync = function rejectingUnboundedTokenRead(target, ...args) {
    let realTarget = '';
    try { realTarget = fs.realpathSync(String(target)); } catch {}
    if (tokenDirectories.has(realTarget)) throw new Error('unbounded token directory read');
    return originalReaddirSync.call(fs, target, ...args);
  };
  fs.opendirSync = function countingBoundedTokenRead(target, ...args) {
    let realTarget = '';
    try { realTarget = fs.realpathSync(String(target)); } catch {}
    if (tokenDirectories.has(realTarget)) boundedPasses += 1;
    return originalOpendirSync.call(fs, target, ...args);
  };
  try {
    const sources = readGptRegisterSources({
      rootDirectory: fixture.root,
      includeRaw: true,
      strictCompleteSnapshot: true,
    });
    assert.equal(sources.summary.tokenCount, 2);
    assert.equal(boundedPasses, 8);
  } finally {
    fs.readdirSync = originalReaddirSync;
    fs.opendirSync = originalOpendirSync;
  }
});

test('complete source snapshots reject changes between different source reads', () => {
  const fixture = fixtureRoot();
  const changingPath = path.join(fixture.root, 'use_token', 'cross-source.json');
  fs.writeFileSync(changingPath, JSON.stringify({
    access_token: 'initial-cross-source-token',
    email: 'cross-source@example.test',
  }));
  const triggerPath = path.join(fixture.root, 'tokens', 'a.json');
  const originalReadSync = fs.readSync;
  let changed = false;
  fs.readSync = function changingRead(descriptor, ...args) {
    const count = originalReadSync.call(fs, descriptor, ...args);
    let descriptorPath = '';
    try { descriptorPath = fs.realpathSync('/proc/self/fd/' + descriptor); } catch {}
    if (!changed && descriptorPath === triggerPath) {
      changed = true;
      fs.writeFileSync(changingPath, JSON.stringify({
        access_token: 'changed-cross-source-token',
        email: 'cross-source@example.test',
      }));
    }
    return count;
  };
  try {
    assert.throws(
      () => readGptRegisterSources({
        rootDirectory: fixture.root,
        includeRaw: true,
        strictCompleteSnapshot: true,
      }),
      (error) => error.code === 'GPT_REGISTER_SOURCE_CHANGED',
    );
    assert.equal(changed, true);
  } finally {
    fs.readSync = originalReadSync;
  }
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

test('token rows join one username phone without changing sync identity', () => {
  const token = {
    source: 'tokens',
    relativePath: 'tokens/email-only.json',
    fileName: 'email-only.json',
    email: ' Source@Example.test ',
    parseStatus: 'ok',
    expiryStatus: 'missing',
    identityKeys: ['email:source@example.test'],
    fingerprints: { access: tokenFingerprint('synthetic-access') },
    raw: {},
  };
  const usernames = [{
    email: 'source@example.test',
    phone: '+86 138-0013-8000',
    hasPassword: true,
    status: 'oauth_done',
  }];
  const rows = buildRows({
    items: [{ kind: 'token_only', token, account: null, issues: [] }],
  }, { usernames });

  assert.equal(rows[0].usernameMatch, 'unique');
  assert.equal(rows[0].phone, '+86 138-0013-8000');
  assert.equal(rows[0].phase3Email, 'source@example.test');
  assert.equal(rows[0].phase3Eligible, true);
  assert.deepEqual(filterRows(rows, { search: '13800138000' }).map((row) => row.key), [rows[0].key]);
  assert.equal(Object.prototype.hasOwnProperty.call(rows[0], 'identityKeys'), false);

  const plan = buildImportPlan({ tokens: [token], usernames }, [], [rows[0].key]);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].action, 'conflict');
  assert.equal(plan[0].reason, 'source_identity_insufficient');
});

test('username phone joins fail closed for ambiguous, missing, passwordless, and terminal accounts', () => {
  const token = {
    source: 'tokens',
    relativePath: 'tokens/phase3.json',
    fileName: 'phase3.json',
    email: 'phase3@example.test',
    identityKeys: ['account:workspace-one', 'email:phase3@example.test'],
    fingerprints: {},
  };
  const item = { kind: 'token_only', token, account: null, issues: [] };
  const rowFor = (usernames) => buildRows({ items: [item] }, { usernames })[0];

  const ambiguous = rowFor([
    { email: token.email, phone: '15550000001', hasPassword: true, status: 'oauth_done' },
    { email: token.email.toUpperCase(), phone: '15550000002', hasPassword: true, status: 'oauth_done' },
  ]);
  assert.equal(ambiguous.usernameMatch, 'ambiguous');
  assert.equal(ambiguous.phone, '');
  assert.equal(ambiguous.phase3Eligible, false);
  assert.equal(ambiguous.phase3Reason, 'username_ambiguous');

  const missing = rowFor([]);
  assert.equal(missing.usernameMatch, 'missing');
  assert.equal(missing.phase3Eligible, false);
  assert.equal(missing.phase3Reason, 'username_missing');

  const passwordless = rowFor([{
    email: token.email,
    phone: '15550000003',
    hasPassword: false,
    status: 'oauth_done',
  }]);
  assert.equal(passwordless.phone, '15550000003');
  assert.equal(passwordless.phase3Eligible, false);
  assert.equal(passwordless.phase3Reason, 'username_password_missing');

  for (const status of ['account_deleted', 'account_deactivated', 'account_disabled']) {
    const terminal = rowFor([{ email: token.email, hasPassword: true, status }]);
    assert.equal(terminal.phase3Eligible, false);
    assert.equal(terminal.phase3Reason, 'username_terminal');
  }
});

test('remote-only rows never inherit username phone by email', () => {
  const rows = buildRows({
    items: [{
      kind: 'sub2api_only',
      token: null,
      account: { id: 8, email: 'shared@example.test', status: 'error' },
      issues: [],
    }],
  }, {
    usernames: [{
      email: 'shared@example.test',
      phone: '15550000008',
      hasPassword: true,
      status: 'oauth_done',
    }],
  });
  assert.equal(rows[0].phone, '');
  assert.equal(rows[0].phase3Email, '');
  assert.equal(rows[0].phase3Eligible, false);
  assert.equal(rows[0].usernameMatch, 'not_applicable');
});

test('snapshot rows receive safe username phone and Phase3 eligibility', async () => {
  const fixture = fixtureRoot();
  fs.writeFileSync(path.join(fixture.root, 'username.json'), JSON.stringify([{
    email: 'example@email.test',
    phone: '+86 138-0013-8000',
    password: 'fixture-only',
    status: 'oauth_done',
  }]));
  const snapshot = await buildSnapshot(new URLSearchParams(), {
    rootDirectory: fixture.root,
    readSub2Api: false,
  });
  const row = snapshot.rows.find((item) => item.fileName === 'b.json');
  assert.equal(row.phone, '+86 138-0013-8000');
  assert.equal(row.phase3Email, 'example@email.test');
  assert.equal(row.phase3Eligible, true);
  assert.match(row.phase3TargetRevision, /^phase3-target-v1\.[A-Za-z0-9_-]{43}$/);
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

test('safe accounts reject secret-like and confusing strong identities without exposing them', () => {
  const dangerousValues = [
    'Bearer identity-leak-marker',
    'eyJhbGciOiJIUzI1NiJ9.identityleakmarker.signaturemarker',
    'sk-proj-identity-leak-marker-1234567890',
    'credential:identity-leak-marker',
    'account-safe\u202eidentity-leak-marker',
    'opaque1'.repeat(16),
  ];
  dangerousValues.forEach((dangerous, index) => {
    const input = index % 2 === 0
      ? { account_id: dangerous }
      : { user_id: dangerous };
    const safe = safeAccount({
      id: 200 + index,
      email: 'fallback@example.test',
      ...input,
    });
    const serialized = JSON.stringify(safe);
    assert.equal(safe.schemaValid, false);
    assert.equal(safe.accountId, '');
    assert.equal(safe.userId, '');
    assert.deepEqual(safe.identityKeys, ['email:fallback@example.test']);
    assert.equal(serialized.includes(dangerous), false);
    assert.equal(serialized.includes('identity-leak-marker'), false);
  });
});

test('safe accounts accept only lossless safe-integer numeric strong identities', () => {
  const maximum = Number.MAX_SAFE_INTEGER;
  const safe = safeAccount({
    id: 206,
    account_id: maximum,
    accountId: String(maximum),
    user_id: 42,
  });
  assert.equal(safe.schemaValid, true);
  assert.equal(safe.accountId, String(maximum));
  assert.equal(safe.userId, '42');
  assert.deepEqual(safe.identityKeys, [
    'account:' + String(maximum),
    'user:42',
  ]);

  for (const unsafeValue of [maximum + 1, 1.5, -0]) {
    const unsafe = safeAccount({ id: 207, account_id: unsafeValue });
    assert.equal(unsafe.schemaValid, false);
    assert.equal(unsafe.accountId, '');
    assert.deepEqual(unsafe.identityKeys, []);
  }

  const canonical = safeAccount({
    id: 208,
    credentials: {
      chatgpt_account_id: '{123E4567-E89B-12D3-A456-426614174000}',
      chatgpt_user_id: 'user-real_123',
    },
  });
  assert.equal(canonical.schemaValid, true);
  assert.equal(canonical.accountId, '123e4567-e89b-12d3-a456-426614174000');
  assert.equal(canonical.userId, 'user-real_123');
});

test('safe accounts fail closed for malformed or contradictory group metadata', () => {
  const valid = safeAccount({
    id: 212,
    group_ids: [9, 3, 9],
    groupIds: ['3', '9'],
    groups: [{ id: 9 }, 3],
    account_groups: [{ group_id: 3 }, { group_id: 9 }],
  });
  assert.equal(valid.schemaValid, true);
  assert.deepEqual(valid.groupIds, [3, 9]);

  const malformedGroups = [
    { group_ids: 3 },
    { group_ids: [0] },
    { group_ids: [-1] },
    { group_ids: [1.5] },
    { group_ids: [Number.MAX_SAFE_INTEGER + 1] },
    { group_ids: [' 3'] },
    { group_ids: [{}] },
    { groups: [{}] },
    { account_groups: [{}] },
    { group_ids: [3], groupIds: [4] },
    { group_ids: [3], groups: [{ id: 4 }] },
    { group_ids: [3], account_groups: [{ group_id: 4 }] },
  ];
  for (const metadata of malformedGroups) {
    const account = safeAccount({ id: 213, ...metadata });
    assert.equal(account.schemaValid, false);
    assert.deepEqual(account.groupIds, []);
  }
});

test('stored token fingerprints require exact full SHA-256 values', () => {
  for (const length of [16, 17, 63, 65]) {
    const malformed = safeAccount({
      id: 209,
      extra: { access_token_sha256: 'a'.repeat(length) },
    });
    assert.equal(malformed.schemaValid, false);
    assert.equal(malformed.fingerprintConflict, true);
    assert.equal(malformed.tokenFingerprints.access, null);
  }

  const rawCredential = 'test-only-remote-access-value';
  const digest = crypto.createHash('sha256').update(rawCredential).digest('hex');
  const wrongDigest = digest.slice(0, -1) + (digest.endsWith('0') ? '1' : '0');
  const mismatch = safeAccount({
    id: 210,
    credentials: { access_token: rawCredential },
    extra: { access_token_sha256: wrongDigest },
  });
  assert.equal(mismatch.schemaValid, false);
  assert.equal(mismatch.fingerprintConflict, true);
  assert.equal(mismatch.tokenFingerprints.access, null);
  assert.equal(JSON.stringify(mismatch).includes(rawCredential), false);
});

test('full fingerprint alias conflicts cannot collapse into the same short fingerprint', () => {
  const prefix = '0123456789abcdef';
  const account = safeAccount({
    id: 211,
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    credentials: {
      account_id: 'workspace-fingerprint-conflict',
      access_token_sha256: prefix + 'a'.repeat(48),
    },
    credentials_status: { has_access_token: true },
    extra: { access_token_sha256: prefix + 'b'.repeat(48) },
  });
  assert.equal(account.schemaValid, false);
  assert.equal(account.fingerprintConflict, true);
  assert.equal(account.tokenFingerprints.access, null);

  const diff = buildDiff([{
    source: 'tokens',
    relativePath: 'tokens/fingerprint-conflict.json',
    fileName: 'fingerprint-conflict.json',
    parseStatus: 'ok',
    expiryStatus: 'missing',
    identityKeys: ['account:workspace-fingerprint-conflict'],
    fingerprints: { access: prefix, refresh: null },
  }], [account]);
  assert.equal(diff.counts.in_sync, undefined);
  assert.equal(diff.counts.token_changed, 1);
  assert.equal(diff.items[0].decisionReason, 'sub2api_account_schema_invalid');
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

test('Sub2API account listing rejects coercible non-integer pagination totals', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  for (const total of [true, false, [], {}, ' 1', '1 ', '01', '-0', '1.0', 1.5]) {
    client.request = async () => ({ items: [{ id: 1 }], total });
    await assert.rejects(
      client.listAccounts({ requireTotal: true }),
      (error) => error.code === 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
      'unexpectedly accepted total=' + JSON.stringify(total),
    );
  }

  for (const total of [1, '1']) {
    client.request = async () => ({
      items: [{ id: 1 }],
      total,
      page: 1,
      page_size: 200,
      pages: 1,
    });
    assert.deepEqual(
      (await client.listAccounts({
        requireTotal: true,
        requirePaginationMetadata: true,
      })).map((account) => account.id),
      [1],
    );
  }
});

test('Sub2API strict account pagination validates the canonical envelope before trusting rows', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  client.request = async (method, pathname) => {
    assert.equal(method, 'GET');
    const page = Number(new URL(pathname, 'http://sub2api.test').searchParams.get('page'));
    return page === 1
      ? {
          items: [{ id: 1 }, { id: 2 }],
          total: 3,
          page: 1,
          page_size: 2,
          pages: 2,
        }
      : {
          items: [{ id: 3 }],
          total: 3,
          page: 2,
          page_size: 2,
          pages: 2,
        };
  };
  assert.deepEqual(
    (await client.listAccounts({
      pageSize: 2,
      requireTotal: true,
      requirePaginationMetadata: true,
    })).map((account) => account.id),
    [1, 2, 3],
  );

  const invalidResponses = [
    {
      value: {
        items: [{ id: 1 }],
        accounts: [{ id: 2 }],
        total: 1,
        page: 1,
        page_size: 200,
        pages: 1,
      },
      code: 'SUB2API_ACCOUNTS_SCHEMA_INVALID',
    },
    {
      value: {
        items: [],
        total: 0,
        pagination: { total: 1 },
        page: 1,
        page_size: 200,
        pages: 1,
      },
      code: 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    },
    {
      value: {
        items: [],
        total: 0,
        pagination: { total: 0, page: 1, page_size: 200, pages: 1 },
        page: 1,
        page_size: 200,
        pages: 1,
      },
      code: 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    },
    {
      value: {
        items: [],
        total: 0,
        page: 1,
        page_size: 200,
        pageSize: 200,
        pages: 1,
        totalPages: 1,
      },
      code: 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    },
    {
      value: { items: [], total: 0, page: 1, page_size: 200 },
      code: 'SUB2API_ACCOUNTS_PAGINATION_REQUIRED',
    },
    {
      value: { items: [], total: 0, page_size: 200, pages: 1 },
      code: 'SUB2API_ACCOUNTS_PAGINATION_REQUIRED',
    },
    {
      value: { items: [], total: 0, page: 1, pages: 1 },
      code: 'SUB2API_ACCOUNTS_PAGINATION_REQUIRED',
    },
    {
      value: { items: [], total: 0, page: 2, page_size: 200, pages: 1 },
      code: 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    },
    {
      value: { items: [], total: 0, page: 1, page_size: 200, pages: 2 },
      code: 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    },
    {
      value: { items: [], total: 0, page: 1, page_size: '200', pages: 1 },
      code: 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    },
    {
      value: { items: [{ id: 1 }], total: 2, page: 1, page_size: 200, pages: 1 },
      code: 'SUB2API_ACCOUNTS_PAGINATION_INVALID',
    },
  ];
  for (const { value, code } of invalidResponses) {
    client.request = async () => value;
    await assert.rejects(
      client.listAccounts({ requireTotal: true, requirePaginationMetadata: true }),
      (error) => error.code === code,
    );
  }

  for (const pageSize of [
    0,
    -1,
    1.5,
    1001,
    '200',
    true,
    null,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.MAX_SAFE_INTEGER,
  ]) {
    await assert.rejects(
      client.listAccounts({ pageSize }),
      (error) => error.code === 'SUB2API_ACCOUNTS_PAGE_SIZE_INVALID',
    );
  }

  client.request = async () => ({
    items: [],
    total: 0,
    page: 1,
    page_size: 200,
    pages: 1,
  });
  assert.deepEqual(await client.listAccounts({
    requireTotal: true,
    requirePaginationMetadata: true,
  }), []);
});

test('Sub2API account exports require a complete supported backup envelope', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  const validPayloads = [
    { accounts: [], proxies: [] },
    { type: '', version: 0, accounts: [], proxies: [] },
    { type: 'sub2api-data', version: 1, accounts: [{}], proxies: [{}] },
    { type: 'sub2api-bundle', version: 1, accounts: [], proxies: [] },
  ];
  for (const payload of validPayloads) {
    client.request = async () => payload;
    assert.equal(await client.exportAccounts(), payload);
  }

  const secretMarker = 'Bearer export-response-must-not-leak';
  const invalidPayloads = [
    null,
    [],
    {},
    { accounts: [] },
    { proxies: [] },
    { accounts: {}, proxies: [] },
    { accounts: [], proxies: {} },
    { accounts: [], proxies: [], type: secretMarker },
    { accounts: [], proxies: [], type: null },
    { accounts: [], proxies: [], version: 2 },
    { accounts: [], proxies: [], version: '1' },
    new Date(),
    Object.assign(Object.create(null), { accounts: [], proxies: [] }),
  ];
  for (const payload of invalidPayloads) {
    client.request = async () => payload;
    await assert.rejects(
      client.exportAccounts(),
      (error) => error.code === 'SUB2API_EXPORT_SCHEMA_INVALID'
        && !error.message.includes(secretMarker),
    );
  }
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

test('email-only source and remote identities remain separate non-operational rows', () => {
  const email = 'shared-weak@example.test';
  const token = {
    source: 'tokens',
    relativePath: 'tokens/weak.json',
    fileName: 'weak.json',
    parseStatus: 'ok',
    expiryStatus: 'missing',
    email,
    identityKeys: ['email:' + email],
    fingerprints: { access: tokenFingerprint('same-synthetic-access') },
  };
  const account = {
    id: 270,
    name: 'free00270',
    email,
    identityKeys: ['email:' + email],
    tokenFingerprints: { access: token.fingerprints.access },
  };

  const diff = buildDiff([token], [account]);
  assert.equal(diff.counts.token_only, 1);
  assert.equal(diff.counts.sub2api_only, 1);
  assert.equal(diff.counts.in_sync || 0, 0);
  const tokenItem = diff.items.find((item) => item.token);
  const remoteItem = diff.items.find((item) => !item.token);
  assert.equal(tokenItem.account, null);
  assert.equal(remoteItem.account.id, 270);

  const rows = buildRows(diff);
  const tokenRow = rows.find((row) => row.relativePath === token.relativePath);
  const remoteRow = rows.find((row) => row.key === 'account:270');
  assert.equal(tokenRow.key, 'token:tokens:tokens/weak.json');
  assert.equal(tokenRow.accountId, null);
  assert.equal(remoteRow.accountId, 270);
});

test('email overlap never bridges a weak identity to a strong identity in either direction', () => {
  const email = 'shared-strength@example.test';
  const baseToken = {
    source: 'tokens',
    relativePath: 'tokens/identity-strength.json',
    fileName: 'identity-strength.json',
    parseStatus: 'ok',
    expiryStatus: 'missing',
    email,
    fingerprints: { access: tokenFingerprint('synthetic-access') },
  };
  const baseAccount = {
    id: 271,
    name: 'free00271',
    email,
    tokenFingerprints: { access: baseToken.fingerprints.access },
  };
  const weakToken = { ...baseToken, identityKeys: ['email:' + email] };
  const strongToken = {
    ...baseToken,
    accountId: 'workspace-271',
    userId: 'user-271',
    identityKeys: ['account:workspace-271', 'user:user-271', 'email:' + email],
  };
  const weakAccount = { ...baseAccount, identityKeys: ['email:' + email] };
  const strongAccount = {
    ...baseAccount,
    accountId: 'workspace-271',
    userId: 'user-271',
    identityKeys: ['account:workspace-271', 'user:user-271', 'email:' + email],
  };

  const weakSourceDiff = buildDiff([weakToken], [strongAccount]);
  assert.equal(weakSourceDiff.counts.token_only, 1);
  assert.equal(weakSourceDiff.counts.sub2api_only, 1);
  assert.equal(weakSourceDiff.items.find((item) => item.token).account, null);

  const weakRemoteDiff = buildDiff([strongToken], [weakAccount]);
  assert.equal(weakRemoteDiff.counts.mapping_conflict, 1);
  assert.equal(weakRemoteDiff.counts.sub2api_only || 0, 0);
  const weakRemoteItem = weakRemoteDiff.items.find((item) => item.token);
  assert.equal(weakRemoteItem.account, null);
  assert.equal(weakRemoteItem.decisionReason, 'ambiguous_sub2api_identity');
});

test('historical email-only tokens never acquire a remote account id', () => {
  const email = 'historical-weak@example.test';
  const token = {
    source: 'tokens',
    relativePath: 'tokens/old_codex-weak.json',
    fileName: 'old_codex-weak.json',
    historical: true,
    parseStatus: 'ok',
    expiryStatus: 'missing',
    email,
    identityKeys: ['email:' + email],
    fingerprints: { access: tokenFingerprint('historical-synthetic-access') },
  };
  const account = {
    id: 272,
    name: 'free00272',
    email,
    identityKeys: ['email:' + email],
    tokenFingerprints: { access: token.fingerprints.access },
  };

  const diff = buildDiff([token], [account], { includeHistorical: true });
  assert.equal(diff.counts.historical_backup, 1);
  assert.equal(diff.counts.sub2api_only, 1);
  const historical = diff.items.find((item) => item.kind === 'historical_backup');
  assert.equal(historical.account, null);
  const row = buildRows(diff).find((item) => item.relativePath === token.relativePath);
  assert.equal(row.accountId, null);
  assert.equal(row.key, 'token:tokens:tokens/old_codex-weak.json');
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

  let schedulerRequest = null;
  client.request = async (...args) => {
    schedulerRequest = args;
    return {
      id: 41,
      name: 'free00041',
      platform: 'openai',
      type: 'oauth',
      status: 'active',
      schedulable: true,
    };
  };
  const schedulerController = new AbortController();
  const scheduled = await client.setSchedulable(41, true, {
    signal: schedulerController.signal,
  });
  assert.equal(scheduled.id, 41);
  assert.equal(scheduled.schedulable, true);
  assert.equal(Object.hasOwn(scheduled, 'credentials'), false);
  assert.equal(JSON.stringify(scheduled).includes('remote-secret'), false);
  assert.equal(schedulerRequest[0], 'POST');
  assert.equal(schedulerRequest[3].signal, schedulerController.signal);
  assert.equal(schedulerRequest[3].writeOperation, true);

  client.request = async () => ({
    id: 42,
    platform: 'openai',
    type: 'oauth',
    status: 'active',
    schedulable: true,
  });
  await assert.rejects(
    client.setSchedulable(41, true),
    (error) => error.code === 'SUB2API_SCHEDULABLE_RESPONSE_MISMATCH'
      && error.writeOutcomeUnknown === true
      && error.requiresReconciliation === true
      && error.writeOutcomeReason === 'response_mismatch',
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
    (error) => error.code === 'SUB2API_SCHEDULABLE_RESPONSE_MISMATCH'
      && error.writeOutcomeUnknown === true
      && error.requiresReconciliation === true
      && error.writeOutcomeReason === 'response_mismatch',
  );
  client.request = async () => ({ unexpected: true });
  await assert.rejects(
    client.setSchedulable(41, true),
    (error) => error.code === 'SUB2API_SCHEDULABLE_SCHEMA_INVALID'
      && error.writeOutcomeUnknown === true
      && error.requiresReconciliation === true
      && error.writeOutcomeReason === 'response_schema',
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
      headers: new Headers({ 'content-type': 'application/json' }),
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

test('Sub2API credentials reject control characters before fetch and never echo configured values', async () => {
  const originalFetch = global.fetch;
  let fetchCalls = 0;
  global.fetch = async () => {
    fetchCalls += 1;
    throw new Error('fetch must not run');
  };
  try {
    for (const credentials of [
      { apiKey: 'prefix\r\ncredential-control-marker' },
      { apiKey: '', jwt: 'prefix\u0000credential-control-marker' },
      { apiKey: 'prefix credential-control-marker' },
      { apiKey: '', jwt: 'prefix\u0085credential-control-marker' },
    ]) {
      assert.throws(
        () => new Sub2ApiAdminClient({
          baseUrl: 'http://127.0.0.1:8080',
          ...credentials,
        }),
        (error) => error.code === 'SUB2API_CREDENTIAL_INVALID'
          && !error.message.includes('credential-control-marker'),
      );
    }
    assert.equal(fetchCalls, 0);

    const opaqueCredential = 'plainOpaqueValue123456789';
    const client = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: opaqueCredential,
    });
    global.fetch = async () => {
      throw new Error('transport reflected ' + opaqueCredential);
    };
    await assert.rejects(
      client.request('GET', '/api/v1/admin/accounts/1'),
      (error) => error.code === 'SUB2API_TRANSPORT_ERROR'
        && !error.message.includes(opaqueCredential),
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test('Sub2API JSON requests require a JSON media type and fatal UTF-8 decoding', async () => {
  const originalFetch = global.fetch;
  const client = new Sub2ApiAdminClient({
    baseUrl: 'http://127.0.0.1:8080',
    apiKey: 'test-key',
  });
  try {
    global.fetch = async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers({ 'content-type': 'text/html' }),
      body: null,
      async text() { return '{"code":0,"data":{}}'; },
    });
    await assert.rejects(
      client.request('GET', '/api/v1/admin/accounts'),
      (error) => error.code === 'SUB2API_RESPONSE_CONTENT_TYPE_INVALID',
    );

    global.fetch = async () => new Response(
      Uint8Array.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
    await assert.rejects(
      client.request('GET', '/api/v1/admin/accounts'),
      (error) => error.code === 'SUB2API_RESPONSE_UTF8_INVALID',
    );

    global.fetch = async () => new Response(
      JSON.stringify({ code: 0, data: { accepted: true } }),
      { status: 200, headers: { 'content-type': 'application/problem+json; charset=utf-8' } },
    );
    assert.deepEqual(await client.request('GET', '/api/v1/admin/accounts'), { accepted: true });
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
        headers: new Headers({ 'content-type': 'application/json; charset=utf-8' }),
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

test('Sub2API write requests distinguish pre-dispatch failures from unknown remote outcomes', async () => {
  const originalFetch = global.fetch;
  const idempotencyKey = 'gptreg-create-v1-' + 'b'.repeat(64);
  const response = (text, overrides = {}) => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Headers({ 'content-type': 'application/json' }),
    body: null,
    async text() { return text; },
    ...overrides,
  });
  try {
    const scenarios = [
      {
        code: 'SUB2API_TRANSPORT_ERROR',
        reason: 'transport',
        fetch: async () => { throw new Error('connection reset'); },
      },
      {
        code: 'SUB2API_EMPTY_RESPONSE',
        reason: 'empty_response',
        fetch: async () => response(''),
      },
      {
        code: 'SUB2API_INVALID_JSON',
        reason: 'invalid_json',
        fetch: async () => response('{invalid'),
      },
      {
        code: 'SUB2API_IMPORT_SCHEMA_INVALID',
        reason: 'response_schema',
        fetch: async () => response(JSON.stringify({ success: true, data: null })),
      },
      {
        code: 'SUB2API_RESPONSE_TOO_LARGE',
        reason: 'response_too_large',
        fetch: async () => response('x'.repeat(1025)),
      },
      {
        code: 'SUB2API_RESPONSE_CONTENT_TYPE_INVALID',
        reason: 'invalid_content_type',
        fetch: async () => response(
          JSON.stringify({ code: 0, data: {} }),
          { headers: new Headers({ 'content-type': 'text/plain' }) },
        ),
      },
      {
        code: 'SUB2API_RESPONSE_UTF8_INVALID',
        reason: 'invalid_utf8',
        fetch: async () => new Response(
          Uint8Array.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      },
      {
        code: 'SUB2API_REQUEST_REJECTED',
        reason: 'response_rejected',
        fetch: async () => response(
          JSON.stringify({ success: false, message: 'write rejected' }),
          { ok: false, status: 500, statusText: 'Server Error' },
        ),
      },
      {
        code: 'SUB2API_REQUEST_REJECTED',
        reason: 'response_rejected',
        fetch: async () => response(JSON.stringify({ success: false, message: 'business rejection' })),
      },
    ];
    for (const scenario of scenarios) {
      global.fetch = scenario.fetch;
      const client = new Sub2ApiAdminClient({
        baseUrl: 'http://127.0.0.1:8080',
        apiKey: 'test-key',
        maxResponseBytes: 1024,
      });
      await assert.rejects(
        client.importCodexSession({ content: '{}' }, { idempotencyKey }),
        (error) => error.code === scenario.code
          && error.writeOutcomeUnknown === true
          && error.requiresReconciliation === true
          && error.writeOutcomeReason === scenario.reason,
      );
    }

    global.fetch = async () => response(JSON.stringify({
      success: true,
      data: { unexpected: true },
    }));
    const applyClient = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: 'test-key',
    });
    await assert.rejects(
      applyClient.applyOAuthCredentials(41, { type: 'oauth', credentials: {} }),
      (error) => error.code === 'SUB2API_CREDENTIALS_SCHEMA_INVALID'
        && error.writeOutcomeUnknown === true
        && error.requiresReconciliation === true,
    );

    global.fetch = async (url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const error = new Error('aborted');
        error.name = 'AbortError';
        reject(error);
      }, { once: true });
    });
    const timeoutClient = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: 'test-key',
      timeoutMs: 5,
    });
    await assert.rejects(
      timeoutClient.importCodexSession({ content: '{}' }, { idempotencyKey }),
      (error) => error.code === 'SUB2API_TIMEOUT'
        && error.writeOutcomeUnknown === true
        && error.writeOutcomeReason === 'timeout',
    );

    const runningAbort = new AbortController();
    const abortedWrite = timeoutClient.importCodexSession(
      { content: '{}' },
      { idempotencyKey, signal: runningAbort.signal },
    );
    runningAbort.abort();
    await assert.rejects(
      abortedWrite,
      (error) => error.code === 'JOB_INTERRUPTED'
        && error.writeOutcomeUnknown === true
        && error.writeOutcomeReason === 'external_abort',
    );

    let fetchCalls = 0;
    global.fetch = async () => {
      fetchCalls += 1;
      throw new Error('fetch must not run');
    };
    const preAborted = new AbortController();
    preAborted.abort();
    await assert.rejects(
      timeoutClient.importCodexSession(
        { content: '{}' },
        { idempotencyKey, signal: preAborted.signal },
      ),
      (error) => error.code === 'JOB_INTERRUPTED'
        && error.writeOutcomeUnknown !== true
        && error.requiresReconciliation !== true,
    );
    const circularPayload = { content: '{}' };
    circularPayload.circular = circularPayload;
    await assert.rejects(
      timeoutClient.importCodexSession(circularPayload, { idempotencyKey }),
      (error) => error.code === 'SUB2API_REQUEST_SERIALIZATION_FAILED'
        && error.writeOutcomeUnknown !== true
        && error.requiresReconciliation !== true,
    );
    await assert.rejects(
      timeoutClient.applyOAuthCredentials(0, { type: 'oauth', credentials: {} }),
      (error) => error.code === 'SUB2API_CREDENTIALS_ID_INVALID'
        && error.writeOutcomeUnknown !== true,
    );
    assert.equal(fetchCalls, 0);

    global.fetch = async () => response(
      JSON.stringify({ success: false, message: 'read rejected' }),
      { ok: false, status: 503, statusText: 'Unavailable' },
    );
    await assert.rejects(
      timeoutClient.request('GET', '/api/v1/admin/accounts'),
      (error) => error.code === 'SUB2API_REQUEST_REJECTED'
        && error.writeOutcomeUnknown !== true
        && error.requiresReconciliation !== true,
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test('Sub2API strict postflight listings require a total on every page', async () => {
  const client = new Sub2ApiAdminClient({
    baseUrl: 'http://127.0.0.1:8080',
    apiKey: 'test-key',
  });
  client.request = async () => ({ items: [] });
  await assert.rejects(
    client.listAccounts({ requireTotal: true }),
    (error) => error.code === 'SUB2API_ACCOUNTS_TOTAL_REQUIRED',
  );
  client.request = async () => ({ items: [], page: 1, page_size: 200, pages: 1 });
  await assert.rejects(
    client.listAccounts({ requirePaginationMetadata: true }),
    (error) => error.code === 'SUB2API_ACCOUNTS_TOTAL_REQUIRED',
  );
  client.request = async () => ({
    items: [],
    total: 0,
    page: 1,
    page_size: 200,
    pages: 1,
  });
  assert.deepEqual(await client.listAccounts({
    requireTotal: true,
    requirePaginationMetadata: true,
  }), []);
});

test('Sub2API batch-stat envelopes are complete and errors leave only after redaction', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  client.request = async () => ({
    stats: { 1: { historical: { requests: 1 } } },
    errors: { 2: 'Bearer stats.header.value access_token=stats-access-value' },
  });
  const result = await client.getBatchTableUsageStats([1, 2]);
  assert.equal(result.errors['2'].includes('stats.header.value'), false);
  assert.equal(result.errors['2'].includes('stats-access-value'), false);
  assert.deepEqual(Object.keys(result.stats), ['1']);
  assert.deepEqual(Object.keys(result.errors), ['2']);
  assert.equal(Object.getPrototypeOf(result.stats), null);
  assert.equal(Object.getPrototypeOf(result.errors), null);
  assert.equal(result.stats.__proto__, undefined);
  assert.equal(result.errors.__proto__, undefined);
});

test('Sub2API today-stat batches require the canonical complete stats envelope', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  client.request = async () => ({
    stats: {
      1: { requests: 0, tokens: 0, cost: 0 },
      2: { requests: 2, tokens: 3, cost: 0.1 },
    },
  });
  const result = await client.getBatchTodayStats([1, 2]);
  assert.deepEqual(Object.keys(result), ['1', '2']);
  assert.equal(result['1'].requests, 0);
  assert.equal(result['2'].totalTokens, 3);

  for (const malformed of [
    {},
    { stats: [] },
    { stats: { 1: { requests: 1 } } },
    { stats: { 1: { requests: 1 }, 2: [] } },
    { stats: { 1: { requests: 1 }, 2: { requests: 2 }, 3: { requests: 3 } } },
    { 1: { requests: 1 }, 2: { requests: 2 } },
  ]) {
    client.request = async () => malformed;
    await assert.rejects(
      client.getBatchTodayStats([1, 2]),
      (error) => error.code === 'SUB2API_STATS_SCHEMA_INVALID',
    );
  }
});

test('Sub2API table-stat batches reject malformed, overlapping, and incomplete results', async () => {
  const client = new Sub2ApiAdminClient({ baseUrl: 'http://127.0.0.1:8080', apiKey: 'test-key' });
  for (const malformed of [
    {},
    { stats: {}, errors: [] },
    { stats: [], errors: {} },
    { stats: { 1: { historical: { requests: 1 } } }, errors: {} },
    {
      stats: { 1: { historical: { requests: 1 } } },
      errors: { 1: 'overlap', 2: 'failed' },
    },
    {
      stats: { 1: { historical: { requests: 1 } }, 3: { historical: { requests: 3 } } },
      errors: { 2: 'failed' },
    },
    {
      stats: { 1: { historical: { requests: 1 } } },
      errors: { 2: { message: 'not the server string contract' } },
    },
    { stats: { 1: [] }, errors: { 2: 'failed' } },
  ]) {
    client.request = async () => malformed;
    await assert.rejects(
      client.getBatchTableUsageStats([1, 2]),
      (error) => error.code === 'SUB2API_STATS_SCHEMA_INVALID',
    );
  }
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
      headers: new Headers({ 'content-type': 'text/event-stream' }),
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
      (error) => error.code === 'SUB2API_TEST_MODEL_MISMATCH'
        && error.requiresReconciliation === true
        && error.reconciliationScope === 'test'
        && error.testOutcomeUnknown !== true
        && error.testSuccess === true
        && error.testSuccessKnown === true,
    );

    global.fetch = async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers({ 'content-type': 'text/event-stream' }),
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

test('Sub2API account tests distinguish pre-dispatch interruption from unknown side effects', async () => {
  const originalFetch = global.fetch;
  const response = (body, overrides = {}) => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Headers({ 'content-type': 'text/event-stream' }),
    body: null,
    async text() { return body; },
    ...overrides,
  });
  const assertUnknown = (error, code, reason) => error.code === code
    && error.requiresReconciliation === true
    && error.testOutcomeUnknown === true
    && error.reconciliationScope === 'test'
    && error.reconciliationReason === reason;
  try {
    const client = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: 'test-key',
      maxResponseBytes: 1024,
      testTimeoutMs: 10_000,
    });

    let fetchCalls = 0;
    global.fetch = async () => {
      fetchCalls += 1;
      throw new Error('fetch must not run');
    };
    const preAborted = new AbortController();
    preAborted.abort();
    await assert.rejects(
      client.testAccount(1, { signal: preAborted.signal }),
      (error) => error.code === 'JOB_INTERRUPTED'
        && error.requiresReconciliation !== true
        && error.testOutcomeUnknown !== true,
    );
    assert.equal(fetchCalls, 0);

    global.fetch = async () => { throw new Error('Bearer transport-secret'); };
    await assert.rejects(
      client.testAccount(1),
      (error) => assertUnknown(error, 'SUB2API_TEST_TRANSPORT_ERROR', 'transport')
        && !error.message.includes('transport-secret'),
    );

    const runningAbort = new AbortController();
    global.fetch = async (url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const error = new Error('aborted');
        error.name = 'AbortError';
        reject(error);
      }, { once: true });
    });
    const interrupted = client.testAccount(1, { signal: runningAbort.signal });
    runningAbort.abort();
    await assert.rejects(
      interrupted,
      (error) => assertUnknown(error, 'JOB_INTERRUPTED', 'external_abort'),
    );

    const timeoutClient = new Sub2ApiAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      apiKey: 'test-key',
      maxResponseBytes: 1024,
      testTimeoutMs: 5,
    });
    global.fetch = async (url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const error = new Error('aborted');
        error.name = 'AbortError';
        reject(error);
      }, { once: true });
    });
    await assert.rejects(
      timeoutClient.testAccount(1),
      (error) => assertUnknown(error, 'SUB2API_TEST_TIMEOUT', 'timeout'),
    );

    const invalidResponses = [
      {
        body: 'x'.repeat(1025),
        code: 'SUB2API_TEST_RESPONSE_TOO_LARGE',
        reason: 'response_too_large',
      },
      { body: '', code: 'SUB2API_TEST_RESPONSE_INVALID', reason: 'empty_response' },
      {
        body: 'data: {not-json}\n\n',
        code: 'SUB2API_TEST_RESPONSE_INVALID',
        reason: 'malformed_json',
      },
      {
        body: 'data: {"type":"status","text":"running"}\n\n',
        code: 'SUB2API_TEST_RESPONSE_INVALID',
        reason: 'missing_terminal',
      },
    ];
    for (const scenario of invalidResponses) {
      global.fetch = async () => response(scenario.body);
      await assert.rejects(
        client.testAccount(1),
        (error) => assertUnknown(error, scenario.code, scenario.reason),
      );
    }

    global.fetch = async () => response('upstream unavailable', {
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
    });
    await assert.rejects(
      client.testAccount(1),
      (error) => assertUnknown(error, 'SUB2API_TEST_REQUEST_REJECTED', 'response_rejected'),
    );

    global.fetch = async () => response(
      'data: {"type":"error","error":"Bearer must-not-be-returned"}\n\n',
    );
    const explicitFailure = await client.testAccount(1);
    assert.equal(explicitFailure.success, false);
    assert.equal(explicitFailure.message, 'Sub2API 返回失败测试结果');
    assert.equal(JSON.stringify(explicitFailure).includes('must-not-be-returned'), false);
  } finally {
    global.fetch = originalFetch;
  }
});
