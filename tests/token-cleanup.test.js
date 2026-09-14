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
  compareCleanupPaths,
  listExpiredTokens,
  deleteExpiredTokens,
  moveToQuarantine,
  claimSourcePath,
  recoverTokenCleanupClaims,
  restoreClaimedPath,
  versionForItems,
} = require('../backend/tokenCleanup');
const { buildImportPlan, compareTokenRecordFreshness } = require('../backend/sync');
const { readGptRegisterSources } = require('../backend/adapters/gptRegisterFs');
const { currentProcessOwner } = require('../backend/taskCoordinator');

function jwt(email, { user = 'cleanup-user', suffix = '' } = {}) {
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

function operationPathEquals(actualPath, expectedPath) {
  const actual = String(actualPath);
  if (actual === expectedPath) return true;
  try {
    return path.join(fs.realpathSync(path.dirname(actual)), path.basename(actual)) === expectedPath;
  } catch {
    return false;
  }
}

function operationDirectory(filePath) {
  try { return fs.realpathSync(String(filePath)); } catch { return path.resolve(String(filePath)); }
}

function deadClaimPath(directory, originalFileName, content, nonce = '0123456789abcdef') {
  const contentHash = crypto.createHash('sha256').update(content).digest('hex');
  const encodedName = Buffer.from(originalFileName, 'utf8').toString('base64url');
  const claimPath = path.join(
    directory,
    '.panel-token-cleanup-claim-v1-999999-0-' + contentHash + '-' + encodedName + '-' + nonce,
  );
  fs.writeFileSync(claimPath, content, { mode: 0o600 });
  return claimPath;
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
    access_token: jwt('cleanup@example.test'),
    refresh_token: 'refresh-valid',
    email: 'cleanup@example.test',
    expired: '2099-01-01T00:00:00.000Z',
  }));
  fs.writeFileSync(path.join(root, 'use_token', 'expired.json'), JSON.stringify({
    access_token: jwt('cleanup@example.test', { suffix: '-expired' }),
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
    access_token: jwt('cleanup@example.test'),
    refresh_token: 'refresh-usable',
    email: 'cleanup@example.test',
  }));
  fs.writeFileSync(path.join(root, 'use_token', 'invalid-expiry.json'), JSON.stringify({
    access_token: jwt('cleanup@example.test', { suffix: '-invalid' }),
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
  const expired = { access_token: jwt('old@example.test'), refresh_token: 'secret-refresh', email: 'old@example.test', expired: '2020-01-01T00:00:00.000Z' };
  fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify(expired));
  fs.writeFileSync(path.join(root, 'use_token', 'expired.json'), JSON.stringify({
    ...expired,
    access_token: jwt('old2@example.test'),
    email: 'old2@example.test',
  }));
  fs.writeFileSync(path.join(root, 'tokens', 'active.json'), JSON.stringify({ ...expired, expired: '2099-01-01T00:00:00.000Z' }));
  fs.writeFileSync(path.join(root, 'tokens', 'invalid.json'), '{broken');
  fs.writeFileSync(path.join(root, 'tokens', 'unknown.json'), JSON.stringify({ access_token: jwt('unknown@example.test'), email: 'unknown@example.test' }));
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

test('expired token listing uses a strict total path order and an order-independent version', () => {
  const root = makeRoot();
  const lowerPath = path.join(root, 'tokens', 'a1.json');
  const upperPath = path.join(root, 'tokens', 'A01.json');
  const document = (suffix) => JSON.stringify({
    access_token: jwt('ordering-' + suffix + '@example.test', {
      user: 'ordering-' + suffix,
      suffix: '-' + suffix,
    }),
    email: 'ordering-' + suffix + '@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  });
  // Create the lowercase path first so a stable sort with the old comparator
  // would preserve the wrong insertion order when the natural comparison ties.
  fs.writeFileSync(lowerPath, document('lower'), { mode: 0o600 });
  fs.writeFileSync(upperPath, document('upper'), { mode: 0o600 });
  assert.equal('tokens/a1.json'.localeCompare(
    'tokens/A01.json',
    'en',
    { numeric: true, sensitivity: 'base' },
  ), 0);
  assert.equal(compareCleanupPaths('tokens/A01.json', 'tokens/a1.json') < 0, true);
  const malformedLeft = 'tokens/malformed-\ud800.json';
  const malformedRight = 'tokens/malformed-\ud801.json';
  assert.equal(Buffer.compare(Buffer.from(malformedLeft), Buffer.from(malformedRight)), 0);
  const originalLocaleCompare = String.prototype.localeCompare;
  String.prototype.localeCompare = function forceMalformedLocaleTie(other, ...args) {
    const current = String(this);
    const alternate = String(other);
    if ((current === malformedLeft && alternate === malformedRight)
        || (current === malformedRight && alternate === malformedLeft)) return 0;
    return originalLocaleCompare.call(current, alternate, ...args);
  };
  try {
    assert.equal(compareCleanupPaths(malformedLeft, malformedRight) < 0, true);
    assert.equal(compareCleanupPaths(malformedRight, malformedLeft) > 0, true);
  } finally {
    String.prototype.localeCompare = originalLocaleCompare;
  }

  const listing = listExpiredTokens({
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.deepEqual(
    listing.items.map((item) => item.relativePath),
    ['tokens/A01.json', 'tokens/a1.json'],
  );
  assert.equal(
    versionForItems([...listing._internalItems].reverse()),
    listing.version,
  );
});

test('cleanup scan reports an abandoned claim without changing it and ordinary deletion stays read-only', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'guarded.json');
  const content = JSON.stringify({
    access_token: jwt('guarded@example.test', { suffix: '-guarded' }),
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
  const claimBefore = fs.lstatSync(claimPath);
  const namesBefore = fs.readdirSync(path.dirname(claimPath)).sort();
  const scan = listExpiredTokens({
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  const claimAfterScan = fs.lstatSync(claimPath);
  assert.equal(scan.recoveryRequired, true);
  assert.equal(scan.claimCount, 1);
  assert.equal(scan.claimCountTruncated, false);
  assert.equal(scan.count, 0);
  assert.equal(JSON.stringify(scan).includes(path.basename(claimPath)), false);
  assert.equal(claimAfterScan.dev, claimBefore.dev);
  assert.equal(claimAfterScan.ino, claimBefore.ino);
  assert.deepEqual(fs.readdirSync(path.dirname(claimPath)).sort(), namesBefore);

  let guardCalls = 0;
  assert.throws(
    () => deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: '0'.repeat(64),
      confirmation: CONFIRMATION,
      beforeMutation() {
        guardCalls += 1;
      },
    }),
    (error) => error.code === 'TOKEN_CLEANUP_STALE',
  );
  assert.equal(guardCalls, 0);
  assert.equal(fs.lstatSync(claimPath).ino, claimBefore.ino);
  assert.deepEqual(fs.readdirSync(path.dirname(claimPath)).sort(), namesBefore);

  assert.throws(
    () => deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: scan.version,
      confirmation: CONFIRMATION,
      beforeMutation() {
        guardCalls += 1;
      },
    }),
    (error) => error.code === 'TOKEN_CLEANUP_RECOVERY_REQUIRED'
      && error.recoveryRequired === true
      && error.claimCount === 1
      && error.claimCountTruncated === false
      && error.retryAllowed === false
      && error.doNotRetry === true,
  );
  assert.equal(guardCalls, 0);
  assert.equal(fs.existsSync(claimPath), true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.lstatSync(claimPath).ino, claimBefore.ino);
  assert.deepEqual(fs.readdirSync(path.dirname(claimPath)).sort(), namesBefore);
  assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
});

test('cleanup scan fail-closes on malformed claims and bounds public claim metadata', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  for (let index = 0; index < 1001; index += 1) {
    fs.writeFileSync(
      path.join(directory, '.panel-token-cleanup-claim-malformed-' + String(index).padStart(4, '0')),
      'opaque-' + index,
      { mode: 0o600 },
    );
  }
  const listing = listExpiredTokens({
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.equal(listing.recoveryRequired, true);
  assert.equal(listing.claimCount, 1000);
  assert.equal(listing.claimCountTruncated, true);
  assert.equal(JSON.stringify(listing).includes('malformed-0000'), false);
  assert.throws(
    () => deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
    }),
    (error) => error.code === 'TOKEN_CLEANUP_RECOVERY_REQUIRED'
      && error.claimCount === 1000
      && error.claimCountTruncated === true
      && error.blockedBeforeStart === true
      && error.executionOutcome === 'not_started',
  );
  assert.equal(fs.readdirSync(directory).length, 1001);
  assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
});

test('cleanup claim inspection and recovery stream directory entries without unbounded reads', () => {
  const root = makeRoot();
  const tokenDirectories = new Set([
    path.join(root, 'tokens'),
    path.join(root, 'use_token'),
  ]);
  const originalReaddirSync = fs.readdirSync;
  const originalOpendirSync = fs.opendirSync;
  let boundedPasses = 0;
  fs.readdirSync = function rejectUnboundedCleanupRead(target, ...args) {
    let realTarget = '';
    try { realTarget = fs.realpathSync(String(target)); } catch {}
    if (tokenDirectories.has(realTarget)) throw new Error('unbounded cleanup directory read');
    return originalReaddirSync.call(fs, target, ...args);
  };
  fs.opendirSync = function countBoundedCleanupRead(target, ...args) {
    let realTarget = '';
    try { realTarget = fs.realpathSync(String(target)); } catch {}
    if (tokenDirectories.has(realTarget)) boundedPasses += 1;
    return originalOpendirSync.call(fs, target, ...args);
  };
  try {
    const listing = listExpiredTokens({
      rootDirectory: root,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    });
    assert.equal(listing.recoveryRequired, false);
    assert.deepEqual(recoverTokenCleanupClaims(root), []);
  } finally {
    fs.readdirSync = originalReaddirSync;
    fs.opendirSync = originalOpendirSync;
  }
  assert.equal(boundedPasses >= 6, true);
});

test('cleanup claim scans fail closed when a directory exceeds the bounded entry limit', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  fs.writeFileSync(path.join(directory, 'ordinary-a.txt'), 'a', { mode: 0o600 });
  fs.writeFileSync(path.join(directory, 'ordinary-b.txt'), 'b', { mode: 0o600 });
  const previousLimit = process.env.GPT_REGISTER_TOKEN_MAX_DIRECTORY_ENTRIES;
  process.env.GPT_REGISTER_TOKEN_MAX_DIRECTORY_ENTRIES = '1';
  try {
    for (const operation of [
      () => listExpiredTokens({ rootDirectory: root }),
      () => recoverTokenCleanupClaims(root),
    ]) {
      assert.throws(
        operation,
        (error) => error.code === 'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT'
          && error.recoveryRequired === true
          && error.requiresReconciliation === true
          && error.reconciliationReason === 'directory_entry_limit_exceeded'
          && error.blockedBeforeStart === true
          && error.executionOutcome === 'not_started'
          && error.retryAllowed === false
          && error.doNotRetry === true,
      );
    }
  } finally {
    if (previousLimit === undefined) {
      delete process.env.GPT_REGISTER_TOKEN_MAX_DIRECTORY_ENTRIES;
    } else {
      process.env.GPT_REGISTER_TOKEN_MAX_DIRECTORY_ENTRIES = previousLimit;
    }
  }
  assert.equal(fs.existsSync(path.join(root, '.panel-quarantine')), false);
});

test('claim recovery rejects malformed prefixed entries before restoring valid claims', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const validClaim = deadClaimPath(
    directory,
    'valid-before-malformed.json',
    JSON.stringify({ marker: 'valid-before-malformed' }),
  );
  const malformedContent = JSON.stringify({ marker: 'noncanonical-name-encoding' });
  const malformedHash = crypto.createHash('sha256').update(malformedContent).digest('hex');
  const canonicalName = Buffer.from('ab.json', 'utf8').toString('base64url');
  const noncanonicalName = canonicalName.slice(0, -1) + 'h';
  assert.equal(Buffer.from(noncanonicalName, 'base64url').toString('utf8'), 'ab.json');
  assert.notEqual(noncanonicalName, canonicalName);
  const malformedClaim = path.join(
    directory,
    '.panel-token-cleanup-claim-v1-999999-0-' + malformedHash
      + '-' + noncanonicalName + '-0123456789abcdef',
  );
  fs.writeFileSync(malformedClaim, malformedContent, { mode: 0o600 });

  assert.throws(
    () => recoverTokenCleanupClaims(root),
    (error) => error.code === 'TOKEN_CLEANUP_RECOVERY_INVALID_CLAIM'
      && error.recoveryReason === 'claim_name_invalid'
      && error.recoveryRequired === true
      && error.requiresReconciliation === true
      && error.blockedBeforeStart === true
      && error.executionOutcome === 'not_started'
      && error.retryAllowed === false
      && error.doNotRetry === true,
  );
  assert.equal(fs.existsSync(path.join(directory, 'valid-before-malformed.json')), false);
  assert.equal(fs.existsSync(validClaim), true);
  assert.equal(fs.existsSync(malformedClaim), true);
});

test('claim recovery bounds the number of staged claims before any restoration', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  let firstClaim;
  for (let index = 0; index < 1001; index += 1) {
    const fileName = 'bounded-' + String(index).padStart(4, '0') + '.json';
    const claimPath = deadClaimPath(directory, fileName, JSON.stringify({ index }));
    if (index === 0) firstClaim = claimPath;
  }
  assert.throws(
    () => recoverTokenCleanupClaims(root),
    (error) => error.code === 'TOKEN_CLEANUP_CLAIM_SCAN_LIMIT'
      && error.reconciliationReason === 'recoverable_claim_limit_exceeded'
      && error.blockedBeforeStart === true,
  );
  assert.equal(fs.existsSync(path.join(directory, 'bounded-0000.json')), false);
  assert.equal(fs.existsSync(firstClaim), true);
});

test('cleanup refuses a source that becomes writable by other users after listing', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired-permissions.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt('permission-race@example.test', { suffix: '-permission-race' }),
    email: 'permission-race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }), { mode: 0o600 });
  const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };
  const listing = listExpiredTokens(options);
  assert.equal(listing.count, 1);

  const originalOpenSync = fs.openSync;
  let sourceOpens = 0;
  fs.openSync = function changePermissionsBeforeCleanup(target, ...args) {
    if (String(target).startsWith('/proc/self/fd/')
        && path.basename(String(target)) === path.basename(sourcePath)
        && fs.existsSync(path.join(root, '.panel-quarantine', 'expired-tokens'))) {
      sourceOpens += 1;
      if (sourceOpens === 1) fs.chmodSync(sourcePath, 0o666);
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
    access_token: jwt('nonblocking-open@example.test', { suffix: '-nonblocking-open' }),
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
    access_token: jwt('isolated-quarantine@example.test', { suffix: '-isolated-quarantine' }),
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
    "require('node:fs').writeSync(1, JSON.stringify({",
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
    access_token: jwt('list-race@example.test', { suffix: '-expired-before-list-race' }),
    email: 'list-race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const replacement = {
    access_token: jwt('list-race@example.test', { suffix: '-active-after-list-race' }),
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
    access_token: jwt('race@example.test', { suffix: '-old' }),
    email: 'race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }));
  const listing = listExpiredTokens({ rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') });
  const freshDocument = {
    access_token: jwt('race@example.test', { suffix: '-fresh' }),
    email: 'race@example.test',
    expired: '2099-01-01T00:00:00.000Z',
  };
  const originalRenameSync = fs.renameSync;
  let injected = false;
  fs.renameSync = function renameWithReplacement(from, to) {
    if (!injected
        && operationPathEquals(from, sourcePath)
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
    const [emptyBatch] = fs.readdirSync(quarantineRoot);
    assert.deepEqual(fs.readdirSync(path.join(quarantineRoot, emptyBatch, 'tokens')), []);
  } finally {
    fs.renameSync = originalRenameSync;
  }
});

test('a dead cleanup process requires an explicit pinned recovery before a later delete', async () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt('recoverable@example.test', { suffix: '-recoverable-claim' }),
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
  const claimPath = path.join(root, 'tokens', claimed.name);
  assert.equal(fs.existsSync(claimPath), true);
  const claimBefore = fs.lstatSync(claimPath);
  const strandedListing = listExpiredTokens({
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.equal(strandedListing.recoveryRequired, true);
  assert.equal(strandedListing.claimCount, 1);
  assert.throws(
    () => deleteExpiredTokens({
      rootDirectory: root,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
      nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
    }),
    (error) => error.code === 'TOKEN_CLEANUP_STALE',
  );
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.lstatSync(claimPath).ino, claimBefore.ino);

  const originalLinkSync = fs.linkSync;
  let pinnedRecoveryObserved = false;
  fs.linkSync = function observePinnedRecovery(from, to) {
    if (!pinnedRecoveryObserved && path.basename(String(from)).startsWith('.panel-token-cleanup-claim-')) {
      pinnedRecoveryObserved = String(from).startsWith('/proc/self/fd/')
        && String(to).startsWith('/proc/self/fd/');
    }
    return originalLinkSync.call(fs, from, to);
  };
  try {
    assert.deepEqual(recoverTokenCleanupClaims(root), ['tokens/expired.json']);
  } finally {
    fs.linkSync = originalLinkSync;
  }
  assert.equal(pinnedRecoveryObserved, true);
  assert.equal(fs.existsSync(sourcePath), true);
  const recoveredListing = listExpiredTokens({
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.equal(recoveredListing.recoveryRequired, false);
  assert.equal(recoveredListing.claimCount, 0);
  const result = deleteExpiredTokens({
    rootDirectory: root,
    expectedVersion: recoveredListing.version,
    confirmation: CONFIRMATION,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  });
  assert.equal(result.count, 1);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.readdirSync(path.join(root, 'tokens')).some((name) => name.startsWith('.panel-token-cleanup-claim-')), false);
});

test('claim recovery completes its conflict preflight before restoring any earlier claim', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const firstContent = JSON.stringify({ marker: 'first-claim' });
  const laterContent = JSON.stringify({ marker: 'later-claim' });
  const firstClaim = deadClaimPath(directory, 'a-first.json', firstContent);
  const laterClaim = deadClaimPath(
    directory,
    'z-later.json',
    laterContent,
    'fedcba9876543210',
  );
  const firstSource = path.join(directory, 'a-first.json');
  const laterSource = path.join(directory, 'z-later.json');
  fs.writeFileSync(laterSource, JSON.stringify({ marker: 'new-file' }), { mode: 0o600 });

  assert.throws(
    () => recoverTokenCleanupClaims(root),
    (error) => error.code === 'TOKEN_CLEANUP_RECOVERY_CONFLICT'
      && error.recoveryReason === 'original_path_occupied',
  );
  assert.equal(fs.existsSync(firstSource), false);
  assert.equal(fs.existsSync(firstClaim), true);
  assert.equal(fs.existsSync(laterClaim), true);
  assert.deepEqual(JSON.parse(fs.readFileSync(laterSource, 'utf8')), { marker: 'new-file' });
});

test('claim recovery rejects duplicate claims for one original before changing either', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const content = JSON.stringify({ marker: 'duplicate-claim' });
  const firstClaim = deadClaimPath(directory, 'same.json', content);
  const secondClaim = deadClaimPath(
    directory,
    'same.json',
    content,
    '1111111111111111',
  );
  const sourcePath = path.join(directory, 'same.json');

  assert.throws(
    () => recoverTokenCleanupClaims(root),
    (error) => error.code === 'TOKEN_CLEANUP_RECOVERY_CONFLICT'
      && error.recoveryReason === 'duplicate_claims',
  );
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.existsSync(firstClaim), true);
  assert.equal(fs.existsSync(secondClaim), true);
});

test('claim recovery fails closed on a dead claim hash mismatch before restoring earlier claims', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const firstContent = JSON.stringify({ marker: 'valid-earlier-claim' });
  const invalidContent = JSON.stringify({ marker: 'invalid-later-claim' });
  const firstClaim = deadClaimPath(directory, 'a-valid.json', firstContent);
  const invalidClaim = deadClaimPath(directory, 'z-invalid.json', invalidContent);
  const firstSource = path.join(directory, 'a-valid.json');
  fs.writeFileSync(invalidClaim, JSON.stringify({ marker: 'changed-after-claim' }), { mode: 0o600 });

  let failure;
  assert.throws(
    () => recoverTokenCleanupClaims(root),
    (error) => {
      failure = error;
      return error.code === 'TOKEN_CLEANUP_RECOVERY_INVALID_CLAIM'
        && error.recoveryReason === 'claim_content_hash_mismatch';
    },
  );
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(fs.existsSync(firstSource), false);
  assert.equal(fs.existsSync(firstClaim), true);
  assert.equal(fs.existsSync(invalidClaim), true);
});

test('claim recovery fails closed on an unreadable dead claim before restoring earlier claims', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const firstContent = JSON.stringify({ marker: 'valid-earlier-claim' });
  const invalidContent = JSON.stringify({ marker: 'non-regular-later-claim' });
  const firstClaim = deadClaimPath(directory, 'a-valid.json', firstContent);
  const invalidClaim = deadClaimPath(directory, 'z-invalid.json', invalidContent);
  const firstSource = path.join(directory, 'a-valid.json');
  fs.unlinkSync(invalidClaim);
  fs.mkdirSync(invalidClaim, { mode: 0o700 });

  let failure;
  assert.throws(
    () => recoverTokenCleanupClaims(root),
    (error) => {
      failure = error;
      return error.code === 'TOKEN_CLEANUP_RECOVERY_INVALID_CLAIM'
        && error.recoveryReason === 'claim_snapshot_unavailable';
    },
  );
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(fs.existsSync(firstSource), false);
  assert.equal(fs.existsSync(firstClaim), true);
  assert.equal(fs.lstatSync(invalidClaim).isDirectory(), true);
});

test('claim restore removes only its own mismatched hard link', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const claimPath = path.join(directory, 'claim.json');
  const sourcePath = path.join(directory, 'restored.json');
  fs.writeFileSync(claimPath, 'claim-content', { mode: 0o600 });
  const originalLstatSync = fs.lstatSync;
  let sourceStats = 0;
  fs.lstatSync = function reportOneMismatchedSource(filePath) {
    const stat = originalLstatSync.call(fs, filePath);
    if (filePath === sourcePath && sourceStats++ === 0) {
      return new Proxy(stat, {
        get(target, property) {
          if (property === 'ino') return Number(target.ino) + 1;
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    }
    return stat;
  };
  try {
    assert.equal(restoreClaimedPath(claimPath, sourcePath), false);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.existsSync(claimPath), true);

  const replacementClaim = path.join(directory, 'replacement-claim.json');
  const replacementSource = path.join(directory, 'replacement-source.json');
  const displacedLink = replacementSource + '.created-link';
  fs.writeFileSync(replacementClaim, 'original-claim', { mode: 0o600 });
  let replaced = false;
  fs.lstatSync = function replaceCreatedSource(filePath) {
    if (!replaced && filePath === replacementSource) {
      replaced = true;
      fs.renameSync(replacementSource, displacedLink);
      fs.writeFileSync(replacementSource, 'unrelated-replacement', { mode: 0o600 });
    }
    return originalLstatSync.call(fs, filePath);
  };
  let replacementFailure;
  try {
    assert.throws(
      () => restoreClaimedPath(replacementClaim, replacementSource),
      (error) => {
        replacementFailure = error;
        return error.code === 'TOKEN_CLEANUP_RESTORE_OUTCOME_UNKNOWN';
      },
    );
  } finally {
    fs.lstatSync = originalLstatSync;
  }
  assert.equal(replacementFailure.requiresReconciliation, true);
  assert.equal(replacementFailure.doNotRetry, true);
  assert.equal(replaced, true);
  assert.equal(fs.readFileSync(replacementSource, 'utf8'), 'unrelated-replacement');
  assert.equal(fs.readFileSync(displacedLink, 'utf8'), 'original-claim');
  assert.equal(fs.existsSync(replacementClaim), true);
});

test('claim restore cleans its created source link after a transient claim lstat error', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const claimPath = path.join(directory, 'transient-claim.json');
  const sourcePath = path.join(directory, 'transient-source.json');
  fs.writeFileSync(claimPath, 'recoverable-content', { mode: 0o600 });
  const originalLstatSync = fs.lstatSync;
  const originalUnlinkSync = fs.unlinkSync;
  let rejectClaimUnlink = true;
  let injectClaimLstat = false;
  fs.unlinkSync = function rejectOneClaimUnlink(filePath) {
    if (filePath === claimPath && rejectClaimUnlink) {
      rejectClaimUnlink = false;
      injectClaimLstat = true;
      const error = new Error('simulated claim unlink failure');
      error.code = 'EACCES';
      throw error;
    }
    return originalUnlinkSync.call(fs, filePath);
  };
  fs.lstatSync = function rejectOneClaimLstat(filePath) {
    if (filePath === claimPath && injectClaimLstat) {
      injectClaimLstat = false;
      const error = new Error('simulated claim stat failure');
      error.code = 'EIO';
      throw error;
    }
    return originalLstatSync.call(fs, filePath);
  };
  try {
    assert.equal(restoreClaimedPath(claimPath, sourcePath), false);
  } finally {
    fs.lstatSync = originalLstatSync;
    fs.unlinkSync = originalUnlinkSync;
  }
  assert.equal(rejectClaimUnlink, false);
  assert.equal(injectClaimLstat, false);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.existsSync(claimPath), true);
  assert.equal(fs.readFileSync(claimPath, 'utf8'), 'recoverable-content');
});

test('claim restore removes its hard link when the first source lstat throws', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const claimPath = path.join(directory, 'source-stat-claim.json');
  const sourcePath = path.join(directory, 'source-stat-restored.json');
  fs.writeFileSync(claimPath, 'recoverable-content', { mode: 0o600 });
  const originalLstatSync = fs.lstatSync;
  let injectSourceLstat = true;
  fs.lstatSync = function rejectOneSourceLstat(filePath) {
    if (filePath === sourcePath && injectSourceLstat) {
      injectSourceLstat = false;
      const error = new Error('simulated source stat failure');
      error.code = 'EIO';
      throw error;
    }
    return originalLstatSync.call(fs, filePath);
  };
  try {
    assert.equal(restoreClaimedPath(claimPath, sourcePath), false);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
  assert.equal(injectSourceLstat, false);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.existsSync(claimPath), true);
  assert.equal(fs.readFileSync(claimPath, 'utf8'), 'recoverable-content');
});

test('claim creation and restoration expose post-rename fsync ambiguity', () => {
  const root = makeRoot();
  const directory = path.join(root, 'tokens');
  const sourcePath = path.join(directory, 'claim-fsync.json');
  const content = JSON.stringify({ marker: 'claim-fsync' });
  const contentHash = crypto.createHash('sha256').update(content).digest('hex');
  fs.writeFileSync(sourcePath, content, { mode: 0o600 });
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  const openedPaths = new Map();
  let failClaimFsync = true;
  fs.openSync = function trackPath(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (typeof filePath === 'string') openedPaths.set(descriptor, path.resolve(filePath));
    return descriptor;
  };
  fs.closeSync = function forgetPath(descriptor) {
    openedPaths.delete(descriptor);
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function rejectSelectedDirectorySync(descriptor) {
    const names = openedPaths.get(descriptor) === directory
      ? fs.readdirSync(directory)
      : [];
    const hasClaim = names.some((name) => name.startsWith('.panel-token-cleanup-claim-'));
    if (failClaimFsync && hasClaim && !fs.existsSync(sourcePath)) {
      failClaimFsync = false;
      const error = new Error('simulated claim directory flush failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  let claimFailure;
  try {
    assert.throws(
      () => claimSourcePath(sourcePath, contentHash),
      (error) => {
        claimFailure = error;
        return error.code === 'TOKEN_CLEANUP_CLAIM_OUTCOME_UNKNOWN';
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
  }
  const [claimName] = fs.readdirSync(directory);
  const claimPath = path.join(directory, claimName);
  assert.equal(claimFailure.writeOutcomeUnknown, true);
  assert.equal(claimFailure.doNotRetry, true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.match(claimName, /^\.panel-token-cleanup-claim-/);

  const restoredPath = path.join(directory, 'restored-fsync.json');
  const restoreOpenedPaths = new Map();
  fs.openSync = function trackRestorePath(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (typeof filePath === 'string') restoreOpenedPaths.set(descriptor, path.resolve(filePath));
    return descriptor;
  };
  fs.closeSync = function forgetRestorePath(descriptor) {
    restoreOpenedPaths.delete(descriptor);
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function rejectRestoreDirectorySync(descriptor) {
    if (restoreOpenedPaths.get(descriptor) === directory
        && fs.existsSync(restoredPath)
        && !fs.existsSync(claimPath)) {
      const error = new Error('simulated restore directory flush failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  let restoreFailure;
  try {
    assert.throws(
      () => restoreClaimedPath(claimPath, restoredPath),
      (error) => {
        restoreFailure = error;
        return error.code === 'TOKEN_CLEANUP_RESTORE_OUTCOME_UNKNOWN';
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(restoreFailure.writeOutcomeUnknown, true);
  assert.equal(restoreFailure.requiresReconciliation, true);
  assert.equal(restoreFailure.retryAllowed, false);
  assert.equal(restoreFailure.doNotRetry, true);
  assert.equal(fs.existsSync(restoredPath), true);
  assert.equal(fs.existsSync(claimPath), false);
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
    access_token: jwt('boot-bound@example.test', { suffix: '-boot-bound-claim' }),
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
    access_token: jwt('cross-device@example.test', { suffix: '-cross-device' }),
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

test('cleanup fails closed when a claimed file cannot be restored or quarantined', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired-recovery-failure.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt('claimed-recovery-failure@example.test', {
      suffix: '-claimed-recovery-failure',
    }),
    email: 'claimed-recovery-failure@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }), { mode: 0o600 });
  const options = {
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  };
  const listing = listExpiredTokens(options);
  assert.equal(listing.count, 1);

  const originalOpenSync = fs.openSync;
  const originalLinkSync = fs.linkSync;
  let snapshotFailureInjected = false;
  let restoreFailureInjected = false;
  let fallbackFailureInjected = false;
  fs.openSync = function failFirstClaimSnapshot(filePath, ...args) {
    if (!snapshotFailureInjected
        && path.basename(String(filePath)).startsWith('.panel-token-cleanup-claim-')) {
      snapshotFailureInjected = true;
      const error = new Error('simulated claimed snapshot failure');
      error.code = 'EIO';
      throw error;
    }
    return originalOpenSync.call(fs, filePath, ...args);
  };
  fs.linkSync = function failClaimRecovery(from, to) {
    if (path.basename(String(from)).startsWith('.panel-token-cleanup-claim-')) {
      const error = new Error('simulated ordinary claim recovery failure');
      if (operationPathEquals(to, sourcePath)) {
        restoreFailureInjected = true;
        error.code = 'EACCES';
      } else {
        fallbackFailureInjected = true;
        error.code = 'EPERM';
      }
      throw error;
    }
    return originalLinkSync.call(fs, from, to);
  };

  let failure;
  try {
    assert.throws(
      () => deleteExpiredTokens({
        ...options,
        expectedVersion: listing.version,
        confirmation: CONFIRMATION,
      }),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_CLAIM_RECOVERY_OUTCOME_UNKNOWN';
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.linkSync = originalLinkSync;
  }

  assert.equal(snapshotFailureInjected, true);
  assert.equal(restoreFailureInjected, true);
  assert.equal(fallbackFailureInjected, true);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(failure.outcome, 'unknown');
  assert.equal(failure.reconciliationScope, 'expired_token_cleanup');
  assert.equal(failure.reconciliationReason, 'token_claim_recovery_outcome_unknown');
  assert.equal(failure.causeCode, 'EPERM');
  assert.deepEqual(failure.currentItem, {
    source: 'tokens',
    relativePath: 'tokens/expired-recovery-failure.json',
  });
  assert.equal(failure.completedCount, 0);
  assert.equal(failure.skippedCount, 0);
  assert.equal(Object.hasOwn(failure.currentItem, 'email'), false);
  assert.equal(Object.hasOwn(failure.currentItem, 'fingerprint'), false);
  assert.equal(failure.message.includes('simulated'), false);
  assert.equal(fs.existsSync(sourcePath), false);
  const remainingClaims = fs.readdirSync(path.join(root, 'tokens')).filter(
    (name) => name.startsWith('.panel-token-cleanup-claim-'),
  );
  assert.equal(remainingClaims.length, 1);
});

test('cleanup reports an unknown outcome instead of file_unavailable after source unlink', () => {
  const root = makeRoot();
  const tokensDirectory = path.join(root, 'tokens');
  const sourcePath = path.join(tokensDirectory, 'expired-unknown.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt('move-outcome-unknown@example.test', { suffix: '-move-outcome-unknown' }),
    email: 'move-outcome-unknown@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }), { mode: 0o600 });
  const options = {
    rootDirectory: root,
    nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
  };
  const listing = listExpiredTokens(options);
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  const openedDirectories = new Map();
  let injected = false;
  fs.openSync = function trackOpenedDirectory(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (typeof filePath === 'string') {
      openedDirectories.set(descriptor, operationDirectory(filePath));
    }
    return descriptor;
  };
  fs.closeSync = function forgetOpenedDirectory(descriptor) {
    openedDirectories.delete(descriptor);
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function failAfterClaimUnlink(descriptor) {
    if (!injected
        && openedDirectories.get(descriptor) === tokensDirectory
        && fs.readdirSync(tokensDirectory).length === 0) {
      injected = true;
      const error = new Error('simulated directory flush failure');
      error.code = 'ENOTSUP';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  let failure;
  try {
    assert.throws(
      () => deleteExpiredTokens({
        ...options,
        expectedVersion: listing.version,
        confirmation: CONFIRMATION,
      }),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN';
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
  }

  assert.equal(injected, true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(failure.reconciliationReason, 'quarantine_move_outcome_unknown');
  assert.deepEqual(failure.currentItem, {
    source: 'tokens',
    relativePath: 'tokens/expired-unknown.json',
  });
  assert.equal(failure.completedCount, 0);
  assert.notEqual(failure.message, 'file_unavailable');
  assert.equal(fs.existsSync(path.join(
    root,
    '.panel-quarantine',
    'expired-tokens',
    failure.quarantinePath,
  )), true);
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

test('same-filesystem target rollback becomes unknown when its directory flush fails', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'rollback-source.json');
  const targetDirectory = path.join(root, 'quarantine-target');
  const targetPath = path.join(targetDirectory, 'rollback-target.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'rollback-content', { mode: 0o600 });
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFchmodSync = fs.fchmodSync;
  const originalFsyncSync = fs.fsyncSync;
  const openedPaths = new Map();
  let operationFailureInjected = false;
  let rollbackFlushFailureInjected = false;
  fs.openSync = function trackRollbackPath(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (typeof filePath === 'string') openedPaths.set(descriptor, path.resolve(filePath));
    return descriptor;
  };
  fs.closeSync = function forgetRollbackPath(descriptor) {
    openedPaths.delete(descriptor);
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fchmodSync = function failPublishedTargetPermissionChange() {
    operationFailureInjected = true;
    const error = new Error('simulated target operation failure');
    error.code = 'EIO';
    throw error;
  };
  fs.fsyncSync = function failRollbackDirectoryFlush(descriptor) {
    if (!rollbackFlushFailureInjected
        && openedPaths.get(descriptor) === targetDirectory
        && !fs.existsSync(targetPath)) {
      rollbackFlushFailureInjected = true;
      const error = new Error('simulated rollback directory flush failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  let failure;
  try {
    assert.throws(
      () => moveToQuarantine(sourcePath, targetPath),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
          && error.reconciliationReason === 'quarantine_rollback_outcome_unknown';
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fchmodSync = originalFchmodSync;
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(operationFailureInjected, true);
  assert.equal(rollbackFlushFailureInjected, true);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(fs.existsSync(sourcePath), true);
  assert.equal(fs.existsSync(targetPath), false);
});

test('cross-filesystem published target rollback becomes unknown when its flush fails', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'published-source.json');
  const targetDirectory = path.join(root, 'quarantine-target');
  const targetPath = path.join(targetDirectory, 'published-target.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'published-content', { mode: 0o600 });
  const originalLinkSync = fs.linkSync;
  const originalLstatSync = fs.lstatSync;
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  const openedPaths = new Map();
  let forcedCrossDevice = false;
  let sourceCheckFailureInjected = false;
  let rollbackFlushFailureInjected = false;
  fs.linkSync = function forceCrossDeviceOnce(from, to) {
    if (!forcedCrossDevice && from === sourcePath && to === targetPath) {
      forcedCrossDevice = true;
      const error = new Error('simulated cross-device link');
      error.code = 'EXDEV';
      throw error;
    }
    return originalLinkSync.call(fs, from, to);
  };
  fs.lstatSync = function failSourceCheckAfterPublish(filePath) {
    if (!sourceCheckFailureInjected
        && forcedCrossDevice
        && filePath === sourcePath
        && fs.existsSync(targetPath)) {
      sourceCheckFailureInjected = true;
      const error = new Error('simulated source recheck failure');
      error.code = 'EIO';
      throw error;
    }
    return originalLstatSync.call(fs, filePath);
  };
  fs.openSync = function trackPublishedRollbackPath(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (typeof filePath === 'string') openedPaths.set(descriptor, path.resolve(filePath));
    return descriptor;
  };
  fs.closeSync = function forgetPublishedRollbackPath(descriptor) {
    openedPaths.delete(descriptor);
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function failPublishedRollbackFlush(descriptor) {
    if (!rollbackFlushFailureInjected
        && openedPaths.get(descriptor) === targetDirectory
        && !fs.existsSync(targetPath)) {
      rollbackFlushFailureInjected = true;
      const error = new Error('simulated published rollback flush failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  let failure;
  try {
    assert.throws(
      () => moveToQuarantine(sourcePath, targetPath),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
          && error.reconciliationReason === 'quarantine_rollback_outcome_unknown';
      },
    );
  } finally {
    fs.linkSync = originalLinkSync;
    fs.lstatSync = originalLstatSync;
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(forcedCrossDevice, true);
  assert.equal(sourceCheckFailureInjected, true);
  assert.equal(rollbackFlushFailureInjected, true);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(fs.existsSync(sourcePath), true);
  assert.equal(fs.existsSync(targetPath), false);
  assert.deepEqual(fs.readdirSync(targetDirectory), []);
});

test('cross-filesystem temporary target rollback becomes unknown when its flush fails', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'temporary-source.json');
  const targetDirectory = path.join(root, 'quarantine-target');
  const targetPath = path.join(targetDirectory, 'temporary-target.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'temporary-content', { mode: 0o600 });
  const originalLinkSync = fs.linkSync;
  const originalWriteSync = fs.writeSync;
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  const openedPaths = new Map();
  let forcedCrossDevice = false;
  let copyFailureInjected = false;
  let rollbackFlushFailureInjected = false;
  fs.linkSync = function forceCrossDeviceOnce(from, to) {
    if (!forcedCrossDevice && from === sourcePath && to === targetPath) {
      forcedCrossDevice = true;
      const error = new Error('simulated cross-device link');
      error.code = 'EXDEV';
      throw error;
    }
    return originalLinkSync.call(fs, from, to);
  };
  fs.writeSync = function failTemporaryCopy() {
    copyFailureInjected = true;
    const error = new Error('simulated temporary copy failure');
    error.code = 'EIO';
    throw error;
  };
  fs.openSync = function trackTemporaryRollbackPath(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (typeof filePath === 'string') openedPaths.set(descriptor, path.resolve(filePath));
    return descriptor;
  };
  fs.closeSync = function forgetTemporaryRollbackPath(descriptor) {
    openedPaths.delete(descriptor);
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function failTemporaryRollbackFlush(descriptor) {
    if (!rollbackFlushFailureInjected
        && openedPaths.get(descriptor) === targetDirectory
        && fs.readdirSync(targetDirectory).length === 0) {
      rollbackFlushFailureInjected = true;
      const error = new Error('simulated temporary rollback flush failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  let failure;
  try {
    assert.throws(
      () => moveToQuarantine(sourcePath, targetPath),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
          && error.reconciliationReason === 'quarantine_rollback_outcome_unknown';
      },
    );
  } finally {
    fs.linkSync = originalLinkSync;
    fs.writeSync = originalWriteSync;
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(forcedCrossDevice, true);
  assert.equal(copyFailureInjected, true);
  assert.equal(rollbackFlushFailureInjected, true);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.retryAllowed, false);
  assert.equal(failure.doNotRetry, true);
  assert.equal(fs.existsSync(sourcePath), true);
  assert.equal(fs.existsSync(targetPath), false);
  assert.deepEqual(fs.readdirSync(targetDirectory), []);
});

test('same-filesystem cleanup reports unknown when the published target identity changes', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'expired.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt('target-replacement@example.test', { suffix: '-target-replacement' }),
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
    const resolvedParent = operationDirectory(path.dirname(normalized));
    if (resolvedParent.includes(path.join('.panel-quarantine', 'expired-tokens'))
        && path.basename(normalized) === 'expired.json') {
      targetChecks += 1;
      if (targetChecks === 2) {
        replacementPath = fs.realpathSync(normalized);
        originalRenameSync(normalized, normalized + '.original-link');
        fs.writeFileSync(normalized, 'unrelated replacement');
      }
    }
    return originalLstatSync(filePath);
  };
  let failure;
  try {
    assert.throws(
      () => deleteExpiredTokens({
        rootDirectory: root,
        expectedVersion: listing.version,
        confirmation: CONFIRMATION,
        nowMs: Date.parse('2026-01-01T00:00:00.000Z'),
      }),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
          && error.reconciliationReason === 'quarantine_rollback_outcome_unknown';
      },
    );
    assert.equal(targetChecks >= 2, true);
    assert.equal(failure.requiresReconciliation, true);
    assert.equal(failure.doNotRetry, true);
    assert.equal(fs.existsSync(sourcePath), false);
    assert.equal(fs.readFileSync(replacementPath, 'utf8'), 'unrelated replacement');
    assert.equal(fs.existsSync(replacementPath + '.original-link'), true);
    assert.equal(fs.readdirSync(path.join(root, 'tokens')).some(
      (name) => name.startsWith('.panel-token-cleanup-claim-'),
    ), true);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
});

test('cleanup fsyncs every newly-created quarantine parent before the first claim', () => {
  const root = makeRoot();
  const expired = (suffix) => JSON.stringify({
    access_token: jwt('durable-' + suffix + '@example.test', {
      user: 'durable-' + suffix,
      suffix: '-durable-' + suffix,
    }),
    email: 'durable-' + suffix + '@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  });
  fs.writeFileSync(path.join(root, 'tokens', 'one.json'), expired('one'), { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'use_token', 'two.json'), expired('two'), { mode: 0o600 });
  const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };
  const listing = listExpiredTokens(options);
  const originalMkdirSync = fs.mkdirSync;
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  const originalRenameSync = fs.renameSync;
  const originalLinkSync = fs.linkSync;
  const opened = new Map();
  const created = [];
  const fsynced = new Set();
  let firstClaimChecked = false;
  let pinnedTargetUsed = false;
  fs.mkdirSync = function trackCreatedDirectory(directory, ...args) {
    const result = originalMkdirSync.call(fs, directory, ...args);
    created.push(fs.realpathSync(directory));
    return result;
  };
  fs.openSync = function trackOpenedDirectory(directory, ...args) {
    const fd = originalOpenSync.call(fs, directory, ...args);
    if (typeof directory === 'string') opened.set(fd, operationDirectory(directory));
    return fd;
  };
  fs.closeSync = function forgetOpenedDirectory(fd) {
    opened.delete(fd);
    return originalCloseSync.call(fs, fd);
  };
  fs.fsyncSync = function trackDirectoryFsync(fd) {
    if (opened.has(fd)) fsynced.add(opened.get(fd));
    return originalFsyncSync.call(fs, fd);
  };
  fs.renameSync = function inspectFirstClaim(from, to) {
    if (!firstClaimChecked && path.basename(String(to)).startsWith('.panel-token-cleanup-claim-')) {
      firstClaimChecked = true;
      assert.equal(String(from).startsWith('/proc/self/fd/'), true);
      const quarantine = path.join(root, '.panel-quarantine', 'expired-tokens');
      const [batchName] = fs.readdirSync(quarantine);
      const batch = path.join(quarantine, batchName);
      const required = [
        path.join(root, '.panel-quarantine'),
        quarantine,
        batch,
        path.join(batch, 'tokens'),
        path.join(batch, 'use_token'),
      ];
      for (const directory of required) {
        const stat = fs.lstatSync(directory);
        assert.equal(stat.isDirectory() && !stat.isSymbolicLink(), true);
        if (typeof process.getuid === 'function') assert.equal(stat.uid, process.getuid());
        assert.equal(stat.mode & 0o077, 0);
      }
      for (const directory of created) assert.equal(fsynced.has(path.dirname(directory)), true);
    }
    return originalRenameSync.call(fs, from, to);
  };
  fs.linkSync = function requirePinnedQuarantineTarget(from, to) {
    if (['one.json', 'two.json'].includes(path.basename(String(to)))) {
      pinnedTargetUsed = pinnedTargetUsed || String(to).startsWith('/proc/self/fd/');
    }
    return originalLinkSync.call(fs, from, to);
  };
  try {
    const result = deleteExpiredTokens({
      ...options,
      expectedVersion: listing.version,
      confirmation: CONFIRMATION,
    });
    assert.equal(result.count, 2);
  } finally {
    fs.mkdirSync = originalMkdirSync;
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
    fs.renameSync = originalRenameSync;
    fs.linkSync = originalLinkSync;
  }
  assert.equal(firstClaimChecked, true);
  assert.equal(pinnedTargetUsed, true);
});

test('cleanup fails before claiming when any new quarantine parent cannot be fsynced', () => {
  const cases = [
    { layer: 'root', code: 'EIO' },
    { layer: 'quarantine', code: 'EINVAL' },
    { layer: 'expired', code: 'ENOTSUP' },
    { layer: 'batch', code: 'EIO' },
  ];
  for (const scenario of cases) {
    const root = makeRoot();
    const sourcePath = path.join(root, 'tokens', 'expired-' + scenario.layer + '.json');
    fs.writeFileSync(sourcePath, JSON.stringify({
      access_token: jwt('fsync-' + scenario.layer + '@example.test', {
        suffix: '-fsync-' + scenario.layer,
      }),
      email: 'fsync-' + scenario.layer + '@example.test',
      expired: '2020-01-01T00:00:00.000Z',
    }), { mode: 0o600 });
    const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };
    const listing = listExpiredTokens(options);
    const originalOpenSync = fs.openSync;
    const originalCloseSync = fs.closeSync;
    const originalFsyncSync = fs.fsyncSync;
    const originalRenameSync = fs.renameSync;
    const opened = new Map();
    const quarantineBase = path.join(root, '.panel-quarantine');
    const expiredRoot = path.join(quarantineBase, 'expired-tokens');
    let injected = false;
    let claims = 0;
    fs.openSync = function trackOpenedDirectory(directory, ...args) {
      const fd = originalOpenSync.call(fs, directory, ...args);
      if (typeof directory === 'string') opened.set(fd, operationDirectory(directory));
      return fd;
    };
    fs.closeSync = function forgetOpenedDirectory(fd) {
      opened.delete(fd);
      return originalCloseSync.call(fs, fd);
    };
    fs.fsyncSync = function failSelectedParent(fd) {
      const directory = opened.get(fd);
      const matches = scenario.layer === 'root'
        ? directory === root && fs.existsSync(quarantineBase)
        : scenario.layer === 'quarantine'
          ? directory === quarantineBase && fs.existsSync(expiredRoot)
          : scenario.layer === 'expired'
            ? directory === expiredRoot && fs.readdirSync(expiredRoot).length > 0
            : path.dirname(directory || '') === expiredRoot
              && fs.existsSync(path.join(directory, 'tokens'));
      if (!injected && matches) {
        injected = true;
        const error = new Error('simulated strict directory fsync failure');
        error.code = scenario.code;
        throw error;
      }
      return originalFsyncSync.call(fs, fd);
    };
    fs.renameSync = function countClaims(from, to) {
      if (path.basename(String(to)).startsWith('.panel-token-cleanup-claim-')) claims += 1;
      return originalRenameSync.call(fs, from, to);
    };
    try {
      assert.throws(
        () => deleteExpiredTokens({
          ...options,
          expectedVersion: listing.version,
          confirmation: CONFIRMATION,
        }),
        (error) => error.code === (['EINVAL', 'ENOTSUP'].includes(scenario.code)
          ? 'TOKEN_CLEANUP_DIRECTORY_FSYNC_UNSUPPORTED'
          : 'TOKEN_CLEANUP_PATH_INVALID'),
      );
    } finally {
      fs.openSync = originalOpenSync;
      fs.closeSync = originalCloseSync;
      fs.fsyncSync = originalFsyncSync;
      fs.renameSync = originalRenameSync;
    }
    assert.equal(injected, true, scenario.layer);
    assert.equal(claims, 0, scenario.layer);
    assert.equal(fs.existsSync(sourcePath), true, scenario.layer);
    assert.equal(fs.readdirSync(path.join(root, 'tokens')).some(
      (name) => name.startsWith('.panel-token-cleanup-claim-'),
    ), false, scenario.layer);
  }
});

test('cleanup detects quarantine path replacement and restores its pinned source claim', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'replacement-race.json');
  const document = JSON.stringify({
    access_token: jwt('directory-replacement-race@example.test', {
      suffix: '-directory-replacement-race',
    }),
    email: 'directory-replacement-race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  });
  fs.writeFileSync(sourcePath, document, { mode: 0o600 });
  const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };
  const listing = listExpiredTokens(options);
  const originalRenameSync = fs.renameSync;
  let injected = false;
  let replacementDirectory = null;
  let displacedDirectory = null;
  fs.renameSync = function replaceQuarantineDirectory(from, to) {
    if (!injected && path.basename(String(to)).startsWith('.panel-token-cleanup-claim-')) {
      const quarantine = path.join(root, '.panel-quarantine', 'expired-tokens');
      const [batchName] = fs.readdirSync(quarantine);
      replacementDirectory = path.join(quarantine, batchName, 'tokens');
      displacedDirectory = replacementDirectory + '.displaced';
      originalRenameSync(replacementDirectory, displacedDirectory);
      fs.mkdirSync(replacementDirectory, { mode: 0o700 });
      injected = true;
    }
    return originalRenameSync.call(fs, from, to);
  };
  try {
    assert.throws(
      () => deleteExpiredTokens({
        ...options,
        expectedVersion: listing.version,
        confirmation: CONFIRMATION,
      }),
      (error) => error.code === 'TOKEN_CLEANUP_PATH_INVALID'
        && error.cleanupInfrastructureInvalid === true,
    );
  } finally {
    fs.renameSync = originalRenameSync;
  }
  assert.equal(injected, true);
  assert.equal(fs.readFileSync(sourcePath, 'utf8'), document);
  assert.deepEqual(fs.readdirSync(replacementDirectory), []);
  assert.deepEqual(fs.readdirSync(displacedDirectory), []);
  assert.equal(fs.readdirSync(path.join(root, 'tokens')).some(
    (name) => name.startsWith('.panel-token-cleanup-claim-'),
  ), false);
});

test('expired token cleanup rejects a symlinked quarantine parent', () => {
  const root = makeRoot();
  fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify({
    access_token: jwt('symlink@example.test'),
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
    access_token: jwt('unsafe-quarantine@example.test', { suffix: '-unsafe-quarantine' }),
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

test('cleanup source and root pins reject group/world writable directories', () => {
  for (const relativeDirectory of ['', 'tokens', 'use_token']) {
    const root = makeRoot();
    const unsafeDirectory = path.join(root, relativeDirectory);
    const originalMode = fs.statSync(unsafeDirectory).mode & 0o777;
    fs.chmodSync(unsafeDirectory, 0o777);
    try {
      assert.throws(
        () => listExpiredTokens({ rootDirectory: root }),
        (error) => error.code === 'TOKEN_CLEANUP_PATH_INVALID'
          && error.cleanupInfrastructureInvalid === true,
        relativeDirectory || 'root',
      );
    } finally {
      fs.chmodSync(unsafeDirectory, originalMode);
    }
  }
});

test('same-filesystem quarantine fsyncs the target inode before and after source unlink', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'durable-source.json');
  const targetDirectory = path.join(root, 'durable-target');
  const targetPath = path.join(targetDirectory, 'durable-target.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'durable-content', { mode: 0o600 });
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  const originalUnlinkSync = fs.unlinkSync;
  let targetDescriptor = null;
  let targetFsyncs = 0;
  let fsyncsObservedBeforeUnlink = 0;
  fs.openSync = function trackTargetDescriptor(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (filePath === targetPath) targetDescriptor = descriptor;
    return descriptor;
  };
  fs.closeSync = function forgetTargetDescriptor(descriptor) {
    if (descriptor === targetDescriptor) targetDescriptor = null;
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function trackTargetFsync(descriptor) {
    if (descriptor === targetDescriptor) targetFsyncs += 1;
    return originalFsyncSync.call(fs, descriptor);
  };
  fs.unlinkSync = function inspectSourceUnlink(filePath) {
    if (filePath === sourcePath) fsyncsObservedBeforeUnlink = targetFsyncs;
    return originalUnlinkSync.call(fs, filePath);
  };
  try {
    moveToQuarantine(sourcePath, targetPath);
  } finally {
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
    fs.unlinkSync = originalUnlinkSync;
  }
  assert.equal(fsyncsObservedBeforeUnlink >= 1, true);
  assert.equal(targetFsyncs >= 2, true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.readFileSync(targetPath, 'utf8'), 'durable-content');
});

test('same-filesystem quarantine rolls back when target inode fsync fails before unlink', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'pre-unlink-fsync-source.json');
  const targetDirectory = path.join(root, 'pre-unlink-fsync-target');
  const targetPath = path.join(targetDirectory, 'pre-unlink-fsync-target.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'pre-unlink-fsync-content', { mode: 0o600 });
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  let targetDescriptor = null;
  let injected = false;
  fs.openSync = function trackTargetDescriptor(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (filePath === targetPath) targetDescriptor = descriptor;
    return descriptor;
  };
  fs.closeSync = function forgetTargetDescriptor(descriptor) {
    if (descriptor === targetDescriptor) targetDescriptor = null;
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function failTargetFsync(descriptor) {
    if (!injected && descriptor === targetDescriptor) {
      injected = true;
      const error = new Error('simulated target inode fsync failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  try {
    assert.throws(
      () => moveToQuarantine(sourcePath, targetPath),
      (error) => error.code === 'EIO',
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(injected, true);
  assert.equal(fs.existsSync(sourcePath), true);
  assert.equal(fs.existsSync(targetPath), false);
});

test('same-filesystem quarantine reports unknown when target fsync fails after unlink', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'post-unlink-fsync-source.json');
  const targetDirectory = path.join(root, 'post-unlink-fsync-target');
  const targetPath = path.join(targetDirectory, 'post-unlink-fsync-target.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'post-unlink-fsync-content', { mode: 0o600 });
  const originalOpenSync = fs.openSync;
  const originalCloseSync = fs.closeSync;
  const originalFsyncSync = fs.fsyncSync;
  let targetDescriptor = null;
  let targetFsyncs = 0;
  fs.openSync = function trackTargetDescriptor(filePath, ...args) {
    const descriptor = originalOpenSync.call(fs, filePath, ...args);
    if (filePath === targetPath) targetDescriptor = descriptor;
    return descriptor;
  };
  fs.closeSync = function forgetTargetDescriptor(descriptor) {
    if (descriptor === targetDescriptor) targetDescriptor = null;
    return originalCloseSync.call(fs, descriptor);
  };
  fs.fsyncSync = function failSecondTargetFsync(descriptor) {
    if (descriptor === targetDescriptor) {
      targetFsyncs += 1;
      if (targetFsyncs === 2) {
        const error = new Error('simulated post-unlink target fsync failure');
        error.code = 'EIO';
        throw error;
      }
    }
    return originalFsyncSync.call(fs, descriptor);
  };
  let failure;
  try {
    assert.throws(
      () => moveToQuarantine(sourcePath, targetPath),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
          && error.causeCode === 'EIO';
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.closeSync = originalCloseSync;
    fs.fsyncSync = originalFsyncSync;
  }
  assert.equal(targetFsyncs, 2);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.readFileSync(targetPath, 'utf8'), 'post-unlink-fsync-content');
});

test('cleanup revalidates the published target after source unlink', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'post-unlink-source.json');
  const targetDirectory = path.join(root, 'post-unlink-target');
  const targetPath = path.join(targetDirectory, 'post-unlink-target.json');
  const displacedPath = targetPath + '.displaced';
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'post-unlink-content', { mode: 0o600 });
  let failure;
  assert.throws(
    () => moveToQuarantine(sourcePath, targetPath, {
      afterSourceUnlink() {
        fs.renameSync(targetPath, displacedPath);
        fs.writeFileSync(targetPath, 'unrelated-replacement', { mode: 0o600 });
      },
    }),
    (error) => {
      failure = error;
      return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
        && error.reconciliationReason === 'quarantine_move_outcome_unknown';
    },
  );
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.readFileSync(displacedPath, 'utf8'), 'post-unlink-content');
  assert.equal(fs.readFileSync(targetPath, 'utf8'), 'unrelated-replacement');
});

test('cleanup reports unknown when the quarantined inode gains another hard link', () => {
  const root = makeRoot();
  const sourcePath = path.join(root, 'tokens', 'post-unlink-link-source.json');
  const targetDirectory = path.join(root, 'post-unlink-link-target');
  const targetPath = path.join(targetDirectory, 'post-unlink-link-target.json');
  const unexpectedLink = path.join(targetDirectory, 'unexpected-alias.json');
  fs.mkdirSync(targetDirectory);
  fs.writeFileSync(sourcePath, 'post-unlink-link-content', { mode: 0o600 });
  let failure;
  assert.throws(
    () => moveToQuarantine(sourcePath, targetPath, {
      afterSourceUnlink() {
        fs.linkSync(targetPath, unexpectedLink);
      },
    }),
    (error) => {
      failure = error;
      return error.code === 'TOKEN_CLEANUP_MOVE_OUTCOME_UNKNOWN'
        && error.reconciliationReason === 'quarantine_move_outcome_unknown';
    },
  );
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.readFileSync(targetPath, 'utf8'), 'post-unlink-link-content');
  assert.equal(fs.readFileSync(unexpectedLink, 'utf8'), 'post-unlink-link-content');
});

test('cleanup leaves a claim for reconciliation when a source pin becomes unsafe', () => {
  const root = makeRoot();
  const tokensDirectory = path.join(root, 'tokens');
  const sourcePath = path.join(tokensDirectory, 'source-pin-race.json');
  fs.writeFileSync(sourcePath, JSON.stringify({
    access_token: jwt('source-pin-race@example.test', { suffix: '-source-pin-race' }),
    email: 'source-pin-race@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  }), { mode: 0o600 });
  const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };
  const listing = listExpiredTokens(options);
  const originalLinkSync = fs.linkSync;
  let permissionsChanged = false;
  fs.linkSync = function makeSourceDirectoryUnsafe(from, to) {
    const result = originalLinkSync.call(fs, from, to);
    if (!permissionsChanged
        && path.basename(String(from)).startsWith('.panel-token-cleanup-claim-')) {
      permissionsChanged = true;
      fs.chmodSync(tokensDirectory, 0o777);
    }
    return result;
  };
  let failure;
  try {
    assert.throws(
      () => deleteExpiredTokens({
        ...options,
        expectedVersion: listing.version,
        confirmation: CONFIRMATION,
      }),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_CLAIM_RECOVERY_OUTCOME_UNKNOWN';
      },
    );
  } finally {
    fs.linkSync = originalLinkSync;
    fs.chmodSync(tokensDirectory, 0o755);
  }
  assert.equal(permissionsChanged, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.causeCode, 'TOKEN_CLEANUP_PATH_INVALID');
  assert.equal(fs.existsSync(sourcePath), false);
  assert.equal(fs.readdirSync(tokensDirectory).some(
    (name) => name.startsWith('.panel-token-cleanup-claim-'),
  ), true);
});

test('cleanup preserves completed progress when a later per-item pin check fails', () => {
  const root = makeRoot();
  const tokensDirectory = path.join(root, 'tokens');
  const firstPath = path.join(tokensDirectory, 'a-first.json');
  const secondPath = path.join(tokensDirectory, 'b-second.json');
  const expired = (name) => JSON.stringify({
    access_token: jwt(name + '@example.test', { user: name, suffix: '-' + name }),
    email: name + '@example.test',
    expired: '2020-01-01T00:00:00.000Z',
  });
  fs.writeFileSync(firstPath, expired('completed-first'), { mode: 0o600 });
  fs.writeFileSync(secondPath, expired('pending-second'), { mode: 0o600 });
  const options = { rootDirectory: root, nowMs: Date.parse('2026-01-01T00:00:00.000Z') };
  const listing = listExpiredTokens(options);
  const originalRelative = path.relative;
  let permissionsChanged = false;
  path.relative = function makeSourceUnsafeAfterFirstResult(from, to) {
    const result = originalRelative.call(path, from, to);
    if (!permissionsChanged
        && String(from).includes(path.join('.panel-quarantine', 'expired-tokens'))
        && path.basename(String(to)) === path.basename(firstPath)) {
      permissionsChanged = true;
      fs.chmodSync(tokensDirectory, 0o777);
    }
    return result;
  };
  let failure;
  try {
    assert.throws(
      () => deleteExpiredTokens({
        ...options,
        expectedVersion: listing.version,
        confirmation: CONFIRMATION,
      }),
      (error) => {
        failure = error;
        return error.code === 'TOKEN_CLEANUP_PATH_INVALID';
      },
    );
  } finally {
    path.relative = originalRelative;
    fs.chmodSync(tokensDirectory, 0o755);
  }
  assert.equal(permissionsChanged, true);
  assert.equal(failure.requiresReconciliation, true);
  assert.equal(failure.writeOutcomeUnknown, true);
  assert.equal(failure.completedCount, 1);
  assert.equal(failure.skippedCount, 0);
  assert.deepEqual(failure.currentItem, {
    source: 'tokens',
    relativePath: 'tokens/b-second.json',
  });
  assert.equal(fs.existsSync(firstPath), false);
  assert.equal(fs.existsSync(secondPath), true);
});
