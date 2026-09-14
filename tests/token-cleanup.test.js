const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const {
  CONFIRMATION,
  listExpiredTokens,
  deleteExpiredTokens,
  moveToQuarantine,
  claimSourcePath,
  recoverTokenCleanupClaims,
} = require('../backend/tokenCleanup');
const { buildImportPlan, compareTokenRecordFreshness } = require('../backend/sync');
const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
const { currentProcessOwner } = require('../backend/taskCoordinator');

function jwt({ user = 'cleanup-user', email = 'cleanup@example.test', suffix = '' } = {}) {
  return [
    'header',
    Buffer.from(JSON.stringify({ sub: user, email })).toString('base64url'),
    'signature' + suffix,
  ].join('.');
}

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-cleanup-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  return root;
}

function waitForClaimChild(child, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('claim child timed out')), timeoutMs);
    child.once('message', (message) => {
      if (message?.type !== 'claimed') return;
      clearTimeout(timer);
      resolve(message);
    });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code && code !== 0) {
        clearTimeout(timer);
        reject(new Error('claim child exited with ' + code));
      }
    });
  });
}

test('fresh valid token wins over a newer expired duplicate', () => {
  const root = makeRoot();
  fs.writeFileSync(path.join(root, 'tokens', 'valid.json'), JSON.stringify({
    access_token: jwt(),
    refresh_token: 'refresh-valid',
    email: 'cleanup@example.test',
    expired: '2099-01-01T00:00:00.000Z',
  }));
  fs.writeFileSync(path.join(root, 'use_token', 'expired.json'), JSON.stringify({
    access_token: jwt({ suffix: '-expired' }),
    refresh_token: 'refresh-expired',
    email: 'cleanup@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const nowMs = Date.parse('2026-01-01T00:00:00.000Z');
  fs.utimesSync(path.join(root, 'tokens', 'valid.json'), new Date(nowMs - 100000), new Date(nowMs - 100000));
  fs.utimesSync(path.join(root, 'use_token', 'expired.json'), new Date(nowMs), new Date(nowMs));
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const plan = buildImportPlan(sources, [{
    id: 5,
    name: 'free00005',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    schedulable: false,
    identityKeys: ['user:cleanup-user', 'email:cleanup@example.test'],
    tokenFingerprints: { access: 'different' },
  }]);
  assert.equal(compareTokenRecordFreshness(
    sources.tokens.find((item) => item.relativePath === 'tokens/valid.json'),
    sources.tokens.find((item) => item.relativePath === 'use_token/expired.json'),
    nowMs,
  ) < 0, true);
  assert.equal(plan.filter((item) => item.action === 'update').length, 1);
  assert.equal(plan.find((item) => item.action === 'update').relativePath, 'tokens/valid.json');
  assert.equal(plan.some((item) => item.reason === 'duplicate_token_versions'), false);
});

test('invalid expiry cannot hide a usable duplicate token', () => {
  const root = makeRoot();
  fs.writeFileSync(path.join(root, 'tokens', 'usable.json'), JSON.stringify({
    access_token: jwt(),
    refresh_token: 'refresh-usable',
    email: 'cleanup@example.test',
  }));
  fs.writeFileSync(path.join(root, 'use_token', 'invalid-expiry.json'), JSON.stringify({
    access_token: jwt({ suffix: '-invalid' }),
    refresh_token: 'refresh-invalid',
    email: 'cleanup@example.test',
    expired: 'not-a-date',
    last_refresh: '2099-01-01T00:00:00.000Z',
  }));
  const futureMtime = new Date('2098-01-01T00:00:00.000Z');
  fs.utimesSync(path.join(root, 'use_token', 'invalid-expiry.json'), futureMtime, futureMtime);
  const sources = readGptRegisterSources({ rootDirectory: root, includeRaw: true });
  const plan = buildImportPlan(sources, []);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].action, 'create');
  assert.equal(plan[0].relativePath, 'tokens/usable.json');
});

test('later expiry wins before refresh-token presence, then refresh time and mtime break ties', () => {
  const base = {
    source: 'tokens',
    parseStatus: 'ok',
    expiryStatus: 'valid',
    disabled: false,
    identityKeys: ['user:ordering-user'],
    raw: { access_token: 'opaque' },
  };
  const earlierWithRefresh = {
    ...base,
    relativePath: 'tokens/earlier.json',
    expiresAt: '2098-01-01T00:00:00.000Z',
    lastRefresh: '2099-01-01T00:00:00.000Z',
    mtimeMs: 100,
    fingerprints: { access: 'earlier', refresh: 'present' },
  };
  const laterAccessOnly = {
    ...base,
    relativePath: 'tokens/later.json',
    expiresAt: '2099-01-01T00:00:00.000Z',
    lastRefresh: '2026-01-01T00:00:00.000Z',
    mtimeMs: 1,
    fingerprints: { access: 'later', refresh: null },
  };
  assert.equal(compareTokenRecordFreshness(earlierWithRefresh, laterAccessOnly) > 0, true);
  assert.equal(
    buildImportPlan({ tokens: [earlierWithRefresh, laterAccessOnly], usernames: [] }, [])[0].relativePath,
    'tokens/later.json',
  );

  const refreshTieWinner = { ...laterAccessOnly, relativePath: 'tokens/refresh-new.json', lastRefresh: '2097-01-01T00:00:00.000Z' };
  const refreshTieLoser = { ...laterAccessOnly, relativePath: 'tokens/refresh-old.json', lastRefresh: '2096-01-01T00:00:00.000Z', mtimeMs: 999 };
  assert.equal(compareTokenRecordFreshness(refreshTieWinner, refreshTieLoser) < 0, true);
  const mtimeWinner = { ...refreshTieWinner, relativePath: 'tokens/mtime-new.json', mtimeMs: 2 };
  const mtimeLoser = { ...refreshTieWinner, relativePath: 'tokens/mtime-old.json', mtimeMs: 1 };
  assert.equal(compareTokenRecordFreshness(mtimeWinner, mtimeLoser) < 0, true);
});

test('expired token cleanup is scoped, versioned, and does not expose credentials', () => {
  const root = makeRoot();
  const expired = { access_token: jwt(), refresh_token: 'secret-refresh', email: 'old@example.test', expired: '2020-01-01T00:00:00.000Z' };
  fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify(expired));
  fs.writeFileSync(path.join(root, 'use_token', 'expired.json'), JSON.stringify({ ...expired, email: 'old2@example.test' }));
  fs.writeFileSync(path.join(root, 'tokens', 'active.json'), JSON.stringify({ ...expired, expired: '2099-01-01T00:00:00.000Z' }));
  fs.writeFileSync(path.join(root, 'tokens', 'invalid.json'), '{broken');
  fs.writeFileSync(path.join(root, 'tokens', 'unknown.json'), JSON.stringify({ access_token: jwt(), email: 'unknown@example.test' }));
  const listing = listExpiredTokens({ rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  assert.equal(listing.count, 2);
  assert.equal(JSON.stringify(listing).includes('secret-refresh'), false);
  assert.equal(listing.items.every((item) => Object.hasOwn(item, 'relativePath')), true);
  assert.throws(
    () => deleteExpiredTokens({ rootDirectory: root, expectedVersion: '0'.repeat(64), confirmation: CONFIRMATION }),
    (error) => error.code === 'TOKEN_CLEANUP_STALE',
  );
  const result = deleteExpiredTokens({
    rootDirectory: root,
    expectedVersion: listing.version,
    confirmation: CONFIRMATION,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.equal(result.count, 2);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'expired.json')), false);
  assert.equal(fs.existsSync(path.join(root, 'use_token', 'expired.json')), false);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'active.json')), true);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'invalid.json')), true);
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'unknown.json')), true);
});

test('cleanup mutation guard runs before recovering an abandoned claim', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'guarded.json');
  const content = JSON.stringify({
    access_token: jwt({ suffix: '-guarded' }),
    email: 'guarded@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  });
  const contentHash = crypto.createHash('sha256').update(content).digest('hex');
  const encodedName = Buffer.from(path.basename(sourcePath), 'utf8').toString('base64url');
  const claimPath = path.join(
    path.dirname(sourcePath),
    '.panel-token-cleanup-claim-v1-999999-0-' + contentHash + '-' + encodedName + '-0123456789abcdef',
  );
  fs.writeFileSync(claimPath, content, { mode: 0o600 });
  let guardCalls = 0;
  const guardError = new Error('audit checkpoint unavailable');
  guardError.code = 'AUDIT_LOG_UNAVAILABLE';

  assert.throws(
    () => deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: '0'.repeat(64),
      confirmation: CONFIRMATION,
      beforeMutation() {
        guardCalls += 1;
        throw guardError;
      },
    }),
    (error) => error === guardError,
  );
  assert.equal(guardCalls, 1);
  assert.equal(fs.existsSync(claimPath), true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
});

test('cleanup refuses a source that becomes writable by other users after listing', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired-permissions.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-permission-race' }),
    email: 'permission-race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }), { mode: 0o600 });
  const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };
  const listing = listExpiredTokens(options);
  assert.equal(listing.count, 1);

  const originalOpenSync = fs.openSync;
  let sourceOpens = 0;
  fs.openSync = function changePermissionsBeforeCleanup(target, ...args) {
    if (String(target) === sourcePath) {
      sourceOpens += 1;
      if (sourceOpens === 2) fs.chmodSync(sourcePath, 0o666);
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    const result = deleteExpiredTokens({
      ...options,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
    });
    assert.equal(result.count, 0);
    assert.equal(result.skipped.length, 1);
    assert.equal(result.skipped[0].reason, 'file_unavailable');
    assert.equal(fs.existsSync(sourcePath), true);
  } finally {
    fs.openSync = originalOpenSync;
    fs.chmodSync(sourcePath, 0o600);
  }
});

test('cleanup opens the final source path nonblocking before checking its file type', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired-nonblocking.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-nonblocking-open' }),
    email: 'nonblocking-open@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const originalOpenSync = fs.openSync;
  let verifiedFinalOpen = false;
  fs.openSync = function requireNonblockingFinalOpen(target, flags, ...args) {
    if (String(target) === sourcePath) {
      verifiedFinalOpen = true;
      assert.notEqual(flags & fs.constants.O_NONBLOCK, 0);
    }
    return originalOpenSync.call(fs, target, flags, ...args);
  };
  try {
    const listing = listExpiredTokens({
      rootDirectory: root,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    });
    assert.equal(verifiedFinalOpen, true);
    assert.equal(listing.count, 1);
  } finally {
    fs.openSync = originalOpenSync;
  }
});

test('test isolation discards an inherited production quarantine path', () => {
  const root = makeRoot();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-inherited-quarantine-'));
  fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify({
    access_token: jwt({ suffix: '-isolated-quarantine' }),
    email: 'isolated-quarantine@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const isolationModule = require.resolve('./test-isolation');
  const cleanupModule = require.resolve('../backend/tokenCleanup');
  const childSource = [
    "const { CONFIRMATION, listExpiredTokens, deleteExpiredTokens } = require(process.argv[1]);",
    'const root = process.argv[2];',
    "const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };",
    'const listing = listExpiredTokens(options);',
    'const result = deleteExpiredTokens({',
    '  ...options,',
    '  expectedVersion: listing.version,',
    '  confirmation: CONFIRMATION,',
    '});',
    'process.stdout.write(JSON.stringify({',
    '  count: result.count,',
    '  quarantinePath: result.deleted[0]?.quarantinePath || null,',
    "  inheritedQuarantinePresent: Object.hasOwn(process.env, 'PANEL_TOKEN_QUARANTINE_DIR'),",
    '}));',
  ].join('\n');
  const child = spawnSync(process.execPath, ['--require', isolationModule, '-e', childSource, cleanupModule, root], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PANEL_TOKEN_QUARANTINE_DIR: outside,
    },
  });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.inheritedQuarantinePresent, false);
  assert.equal(result.count, 1);
  assert.equal(fs.readdirSync(outside).length, 0);
  assert.equal(fs.existsSync(path.join(
    root,
    '.panel-quarantine',
    'expired-tokens',
    result.quarantinePath,
  )), true);
});

test('cleanup listing never combines stale expiry metadata with replacement bytes', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'replaced.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-expired-before-list-race' }),
    email: 'list-race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const replacement = {
    access_token: jwt({ suffix: '-active-after-list-race' }),
    email: 'list-race@example.test',
    expired: '2099-01-01T00:00:00.000Z',
  };
  const originalOpenSync = fs.openSync;
  let replaced = false;
  fs.openSync = function replaceBeforeCleanupSnapshot(filePath, ...args) {
    if (!replaced && filePath === sourcePath) {
      replaced = true;
      fs.writeFileSync(sourcePath, JSON.stringify(replacement));
    }
    return originalOpenSync(filePath, ...args);
  };
  try {
    const listing = listExpiredTokens({
      rootDirectory: root,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    });
    assert.equal(replaced, true);
    assert.equal(listing.count, 0);
    assert.deepEqual(JSON.parse(fs.readFileSync(sourcePath, 'utf8')), replacement);
  } finally {
    fs.openSync = originalOpenSync;
  }
});

test('expired token cleanup atomically claims the source before validating a replacement', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  const displacedPath = path.join(root, 'tokens', 'expired-before-race.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-old' }),
    email: 'race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const listing = listExpiredTokens({ rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  const freshDocument = {
    access_token: jwt({ suffix: '-fresh' }),
    email: 'race@example.test',
    expired: '2099-01-01T00:00:00.000Z',
  };
  const originalRenameSync = fs.renameSync;
  let injected = false;
  fs.renameSync = function renameWithReplacement(from, to) {
    if (!injected
        && from === sourcePath
        && path.basename(to).startsWith('.panel-token-cleanup-claim-')) {
      injected = true;
      originalRenameSync(from, displacedPath);
      fs.writeFileSync(sourcePath, JSON.stringify(freshDocument));
    }
    return originalRenameSync(from, to);
  };
  try {
    const result = deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    });
    assert.equal(injected, true);
    assert.equal(result.count, 0);
    assert.equal(result.skipped[0].reason, 'file_changed');
    assert.deepEqual(JSON.parse(fs.readFileSync(sourcePath, 'utf8')), freshDocument);
    assert.equal(fs.existsSync(displacedPath), true);
    const quarantineRoot = path.join(root, '.panel-quarantine', 'expired-tokens');
    assert.deepEqual(fs.readdirSync(quarantineRoot), []);
  } finally {
    fs.renameSync = originalRenameSync;
  }
});

test('a dead cleanup process leaves a self-describing claim that the next delete recovers', async () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-recoverable-claim' }),
    email: 'recoverable@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const listing = listExpiredTokens({ rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  const cleanupModule = require.resolve('../backend/tokenCleanup');
  const childSource = [
    "const { claimSourcePath } = require(process.argv[1]);",
    'const claimed = claimSourcePath(process.argv[2], process.argv[3]);',
    "process.send({ type: 'claimed', name: require('node:path').basename(claimed) }, () => process.disconnect());",
  ].join('\n');
  const child = spawn(process.execPath, [
    '-e',
    childSource,
    cleanupModule,
    sourcePath,
    listing._internalItems[0].contentHash,
  ], {
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  const claimed = await waitForClaimChild(child);
  if (child.exitCode === null && child.signalCode === null) {
    await new Promise((resolve) => child.once('exit', resolve));
  }
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.existsSync(path.join(root, 'tokens', claimed.name)), true);

  const result = deleteExpiredTokens({
    rootDirectory: root,
    expectedVersion: listing.version,
    confirmation: CONFIRMATION,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.equal(result.count, 1);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.readdirSync(path.join(root, 'tokens')).some((name) => name.startsWith('.panel-token-cleanup-claim-')), false);
});

test('cleanup claim recovery binds a live PID to the current system boot', (context) => {
  const owner = currentProcessOwner();
  if (!owner.processBootId) {
    context.skip('Linux boot_id is unavailable');
    return;
  }
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'boot-bound.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-boot-bound-claim' }),
    email: 'boot-bound@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const listing = listExpiredTokens({
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  const claimedPath = claimSourcePath(sourcePath, listing._internalItems[0].contentHash);
  const prefix = '.panel-token-cleanup-claim-v2-';
  const parts = path.basename(claimedPath).slice(prefix.length).split('.');
  assert.equal(parts.length, 6);
  const alternateHex = owner.processBootId.replace(/-/g, '').toLowerCase()
    === '00000000000000000000000000000000'
    ? '11111111111111111111111111111111'
    : '00000000000000000000000000000000';
  parts[2] = Buffer.from(alternateHex, 'hex').toString('base64url');
  const staleClaimPath = path.join(path.dirname(claimedPath), prefix + parts.join('.'));
  fs.renameSync(claimedPath, staleClaimPath);

  assert.deepEqual(recoverTokenCleanupClaims(root), ['tokens/boot-bound.json']);
  assert.equal(fs.existsSync(sourcePath), true);
  assert.equal(fs.existsSync(staleClaimPath), false);
});

test('cross-filesystem cleanup never unlinks a newly reusable original source path', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-cross-device' }),
    email: 'cross-device@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const listing = listExpiredTokens({ rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  const originalLinkSync = fs.linkSync;
  const originalUnlinkSync = fs.unlinkSync;
  const unlinkedPaths = [];
  let forcedCrossDevice = false;
  fs.linkSync = function linkWithCrossDeviceFallback(from, to) {
    if (!forcedCrossDevice
        && path.basename(from).startsWith('.panel-token-cleanup-claim-')
        && path.basename(to) === 'expired.json') {
      forcedCrossDevice = true;
      const error = new Error('simulated cross-device link');
      error.code = 'EXDEV';
      throw error;
    }
    return originalLinkSync(from, to);
  };
  fs.unlinkSync = function recordUnlink(filePath) {
    unlinkedPaths.push(filePath);
    return originalUnlinkSync(filePath);
  };
  try {
    const result = deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    });
    assert.equal(forcedCrossDevice, true);
    assert.equal(result.count, 1);
    assert.equal(fs.existsSync(sourcePath), false);
    assert.equal(unlinkedPaths.includes(sourcePath), false);
    assert.equal(fs.existsSync(path.join(
      root,
      '.panel-quarantine',
      'expired-tokens',
      result.deleted[0].quarantinePath,
    )), true);
  } finally {
    fs.linkSync = originalLinkSync;
    fs.unlinkSync = originalUnlinkSync;
  }
});

test('cross-filesystem quarantine refuses oversized files without leaving a partial target', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'oversized.json');
  const targetDirectory = path.join(root, 'quarantine-target');
  const targetPath = path.join(targetDirectory, 'oversized.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'x');
  fs.truncateSync(sourcePath, 16 * 1024 * 1024 + 1);
  const originalLinkSync = fs.linkSync;
  let forcedCrossDevice = false;
  fs.linkSync = function forceCrossDevice(from, to) {
    if (!forcedCrossDevice && from === sourcePath && to === targetPath) {
      forcedCrossDevice = true;
      const error = new Error('simulated cross-device link');
      error.code = 'EXDEV';
      throw error;
    }
    return originalLinkSync(from, to);
  };
  try {
    assert.throws(
      () => moveToQuarantine(sourcePath, targetPath),
      (error) => error.code === 'TOKEN_CLEANUP_FILE_TOO_LARGE',
    );
    assert.equal(forcedCrossDevice, true);
    assert.equal(fs.existsSync(sourcePath), true);
    assert.equal(fs.existsSync(targetPath), false);
    assert.deepEqual(fs.readdirSync(targetDirectory), []);
  } finally {
    fs.linkSync = originalLinkSync;
  }
});

test('same-filesystem cleanup rechecks the published target inode before removing its claim', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt({ suffix: '-target-replacement' }),
    email: 'target-replacement@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const listing = listExpiredTokens({ rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  const originalLstatSync = fs.lstatSync;
  const originalRenameSync = fs.renameSync;
  let targetChecks = 0;
  let replacementPath = null;
  fs.lstatSync = function replacePublishedTarget(filePath) {
    const normalized = String(filePath);
    if (normalized.includes(path.join('.panel-quarantine', 'expired-tokens'))
        && path.basename(normalized) === 'expired.json') {
      targetChecks += 1;
      if (targetChecks === 2) {
        replacementPath = normalized;
        originalRenameSync(normalized, normalized + '.original-link');
        fs.writeFileSync(normalized, 'unrelated replacement');
      }
    }
    return originalLstatSync(filePath);
  };
  try {
    const result = deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    });
    assert.equal(targetChecks >= 2, true);
    assert.equal(result.count, 0);
    assert.equal(fs.existsSync(sourcePath), true);
    assert.equal(fs.readFileSync(replacementPath, 'utf8'), 'unrelated replacement');
  } finally {
    fs.lstatSync = originalLstatSync;
  }
});

test('expired token cleanup rejects a symlinked quarantine parent', () => {
  const root = makeRoot();
  fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify({
    access_token: jwt(),
    email: 'symlink@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-outside-'));
  const linkedParent = path.join(root, 'linked-quarantine');
  fs.symlinkSync(outside, linkedParent, 'dir');
  const listing = listExpiredTokens({ rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  assert.throws(
    () => deleteExpiredTokens({
      rootDirectory: root,
      quarantineDirectory: path.join(linkedParent, 'expired-tokens'),
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    }),
    (error) => error.code === 'TOKEN_CLEANUP_PATH_INVALID',
  );
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'expired.json')), true);
  assert.equal(fs.readdirSync(outside).length, 0);
});

test('expired token cleanup rejects a quarantine directory readable or writable by other users', () => {
  const root = makeRoot();
  fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify({
    access_token: jwt({ suffix: '-unsafe-quarantine' }),
    email: 'unsafe-quarantine@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const quarantine = path.join(root, 'unsafe-quarantine');
  fs.mkdirSync(quarantine, { mode: 0o700 });
  fs.chmodSync(quarantine, 0o777);
  const listing = listExpiredTokens({
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.throws(
    () => deleteExpiredTokens({
      rootDirectory: root,
      quarantineDirectory: quarantine,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    }),
    (error) => error.code === 'TOKEN_CLEANUP_PATH_INVALID',
  );
  assert.equal(fs.existsSync(path.join(root, 'tokens', 'expired.json')), true);
  assert.deepEqual(fs.readdirSync(quarantine), []);
});
