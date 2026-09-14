const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

require('./test-isolation');

const { filterRows, rowFromDiffItem } = require('../backend/view');

const frontendSource = fs.readFileSync(
  path.resolve(__dirname, '..', 'frontend', 'app.js'),
  'utf8',
);
const htmlSource = fs.readFileSync(
  path.resolve(__dirname, '..', 'frontend', 'index.html'),
  'utf8',
);

function sourceSection(startMarker, endMarker) {
  const start = frontendSource.indexOf(startMarker);
  const end = frontendSource.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, startMarker + ' missing');
  assert.notEqual(end, -1, endMarker + ' missing');
  return frontendSource.slice(start, end);
}

test('view rows preserve separate safe gpt_register and Sub2API facts', () => {
  const sourceAccess = '1111111111111111';
  const remoteAccess = '2222222222222222';
  const row = rowFromDiffItem({
    kind: 'token_changed',
    issues: [],
    token: {
      source: 'tokens',
      relativePath: 'tokens/local.json',
      fileName: 'local.json',
      email: 'local@example.test',
      accountId: 'local-workspace',
      userId: 'local-user',
      expiresAt: '2098-01-01T00:00:00.000Z',
      lastRefresh: '2097-12-01T00:00:00.000Z',
      mtimeMs: 123456,
      fingerprints: { access: sourceAccess, refresh: '3333333333333333' },
      raw: { access_token: 'must-not-leak-local-access-token' },
    },
    account: {
      id: 266,
      name: 'free00006',
      email: 'remote@example.test',
      accountId: 'remote-workspace',
      userId: 'remote-user',
      credentialExpiresAt: '2099-01-01T00:00:00.000Z',
      expiresAt: '2100-01-01T00:00:00.000Z',
      tokenFingerprints: { access: remoteAccess, refresh: null },
      status: 'error',
      credentials: { access_token: 'must-not-leak-remote-access-token' },
    },
  });

  assert.deepEqual(row.sourceDetails, {
    email: 'local@example.test',
    chatgptAccountId: 'local-workspace',
    userId: 'local-user',
    expiresAt: '2098-01-01T00:00:00.000Z',
    lastRefresh: '2097-12-01T00:00:00.000Z',
    mtimeMs: 123456,
    fingerprints: {
      access: sourceAccess,
      refresh: '3333333333333333',
      id: null,
    },
    relativePath: 'tokens/local.json',
    fileName: 'local.json',
  });
  assert.deepEqual(row.remoteDetails, {
    id: 266,
    name: 'free00006',
    email: 'remote@example.test',
    chatgptAccountId: 'remote-workspace',
    userId: 'remote-user',
    credentialExpiresAt: '2099-01-01T00:00:00.000Z',
    accountExpiresAt: '2100-01-01T00:00:00.000Z',
    fingerprints: { access: remoteAccess, refresh: null, id: null },
  });
  // Legacy aliases remain present for a frontend/backend rolling upgrade.
  assert.equal(row.accountId, 266);
  assert.equal(row.email, 'remote@example.test');
  assert.equal(JSON.stringify(row).includes('must-not-leak'), false);
  assert.deepEqual(filterRows([row], { search: 'local-workspace' }), [row]);
  assert.deepEqual(filterRows([row], { search: '266' }), [row]);
});

test('view rows use null for the side that does not exist', () => {
  const sourceOnly = rowFromDiffItem({
    kind: 'token_only',
    issues: [],
    token: {
      source: 'tokens',
      relativePath: 'tokens/source-only.json',
      fingerprints: {},
    },
    account: null,
  });
  const remoteOnly = rowFromDiffItem({
    kind: 'sub2api_only',
    issues: [],
    token: null,
    account: { id: 27, name: 'free00027', tokenFingerprints: {} },
  });
  assert.equal(sourceOnly.remoteDetails, null);
  assert.equal(sourceOnly.sourceDetails.relativePath, 'tokens/source-only.json');
  assert.equal(remoteOnly.sourceDetails, null);
  assert.equal(remoteOnly.remoteDetails.id, 27);
  assert.equal(remoteOnly.schedulable, null);
  assert.equal(remoteOnly.schedulableKnown, false);
});

test('view rows preserve the three-state Sub2API scheduler contract', () => {
  const enabled = rowFromDiffItem({
    kind: 'sub2api_only',
    issues: [],
    token: null,
    account: { id: 31, schedulable: true, schedulableKnown: true },
  });
  const disabled = rowFromDiffItem({
    kind: 'sub2api_only',
    issues: [],
    token: null,
    account: { id: 32, schedulable: false, schedulableKnown: true },
  });
  const unknown = rowFromDiffItem({
    kind: 'sub2api_only',
    issues: [],
    token: null,
    account: { id: 33, schedulable: true, schedulableKnown: false },
  });
  const malformedKnownFlag = rowFromDiffItem({
    kind: 'sub2api_only',
    issues: [],
    token: null,
    account: { id: 34, schedulable: true, schedulableKnown: 'true' },
  });

  assert.deepEqual(
    [enabled.schedulable, enabled.schedulableKnown],
    [true, true],
  );
  assert.deepEqual(
    [disabled.schedulable, disabled.schedulableKnown],
    [false, true],
  );
  assert.deepEqual(
    [unknown.schedulable, unknown.schedulableKnown],
    [null, false],
  );
  assert.deepEqual(
    [malformedKnownFlag.schedulable, malformedKnownFlag.schedulableKnown],
    [null, false],
  );
});

test('frontend renders both sides, full-value differences, and the numeric remote id', () => {
  const primitives = sourceSection('function escapeHtml', 'function finiteNumber');
  const sideRenderers = sourceSection('function rowSideData', 'function renderRows');
  const context = {};
  vm.runInNewContext(primitives + '\n' + sideRenderers + `
    const row = {
      accountId: 266,
      sourceDetails: {
        email: 'local@example.test',
        chatgptAccountId: 'workspace-local',
        userId: 'user-local',
        expiresAt: '2098-01-01T00:00:00.000Z',
        fingerprints: { access: 'aaaaaaaa11111111', refresh: 'cccccccc11111111' },
        relativePath: 'tokens/local.json',
      },
      remoteDetails: {
        id: 266,
        name: 'free00006',
        email: 'remote@example.test',
        chatgptAccountId: 'workspace-remote',
        userId: 'user-remote',
        credentialExpiresAt: '2099-01-01T00:00:00.000Z',
        accountExpiresAt: '2100-01-01T00:00:00.000Z',
        // The visible prefixes match; comparison must still use the complete fingerprints.
        fingerprints: { access: 'aaaaaaaa22222222', refresh: 'cccccccc11111111' },
      },
    };
    const sides = rowSideData(row);
    result = {
      account: renderAccountSummary(row, sides, 'free00006'),
      email: renderEmailComparison(row, sides, ''),
      identity: renderIdentityComparison(row, sides),
      expiry: renderExpiryComparison(row, sides),
      fingerprints: renderFingerprintComparison(row, sides),
    };
  `, context);

  assert.match(context.result.account, /Sub2API ID #266/);
  assert.match(context.result.account, /文件 tokens\/local\.json/);
  assert.match(context.result.email, /local@example\.test/);
  assert.match(context.result.email, /remote@example\.test/);
  assert.match(context.result.identity, /workspace-local/);
  assert.match(context.result.identity, /workspace-remote/);
  assert.match(context.result.expiry, /2098/);
  assert.match(context.result.expiry, /2099/);
  assert.match(context.result.expiry, /账号期限/);
  assert.match(context.result.expiry, /2100/);
  assert.match(context.result.fingerprints, /A aaaaaaaa/);
  assert.match(context.result.fingerprints, /comparison-marker/);
  assert.equal((context.result.email.match(/comparison-marker/g) || []).length, 2);
  assert.match(htmlSource, /<h2>账号差异明细<\/h2>/);
  assert.match(htmlSource, /<th>账号 \/ 文件<\/th>[\s\S]*<th>邮箱对比<\/th>[\s\S]*<th>强身份对比<\/th>/);
});

test('frontend labels an old matched snapshot as merged instead of inventing two sides', () => {
  const primitives = sourceSection('function escapeHtml', 'function finiteNumber');
  const sideRenderers = sourceSection('function rowSideData', 'function renderRows');
  const context = {};
  vm.runInNewContext(primitives + '\n' + sideRenderers + `
    const row = {
      source: 'tokens',
      accountId: 19,
      email: 'legacy-merged@example.test',
      chatgptAccountId: 'legacy-identity',
      fingerprints: { access: '1111111111111111' },
    };
    const sides = rowSideData(row);
    result = {
      legacyMerged: sides.legacyMerged,
      email: renderEmailComparison(row, sides, ''),
      account: renderAccountSummary(row, sides, 'free00019'),
    };
  `, context);
  assert.equal(context.result.legacyMerged, true);
  assert.match(context.result.email, /旧快照/);
  assert.match(context.result.email, /后端尚未提供分侧字段/);
  assert.doesNotMatch(context.result.email, /comparison-marker/);
  assert.match(context.result.account, /Sub2API ID #19/);
});

test('frontend renders scheduler state as enabled, disabled, or unknown with safe availability reasons', () => {
  const primitives = sourceSection('function escapeHtml', 'function finiteNumber');
  const sideRenderers = sourceSection('function rowSideData', 'function renderRows');
  const context = {};
  vm.runInNewContext(primitives + '\n' + sideRenderers + `
    const sides = { remote: { id: 41 } };
    result = {
      enabled: renderRemoteState({
        accountId: 41,
        schedulable: true,
        schedulableKnown: true,
        availability: 'available',
        availabilityReason: 'sub2api_available',
      }, sides),
      disabled: renderRemoteState({
        accountId: 41,
        schedulable: false,
        schedulableKnown: true,
        availability: 'unavailable',
        availabilityReason: 'sub2api_unschedulable',
      }, sides),
      unknown: renderRemoteState({
        accountId: 41,
        schedulable: true,
        schedulableKnown: false,
        availability: 'unknown',
        availabilityReason: 'credential=must-not-be-rendered',
      }, sides),
      invalidAutoPause: renderRemoteState({
        accountId: 41,
        schedulable: true,
        schedulableKnown: true,
        availability: 'unknown',
        availabilityReason: 'sub2api_auto_pause_invalid',
      }, sides),
    };
  `, context);

  assert.match(context.result.enabled, /调度：开启/);
  assert.match(context.result.enabled, />可用</);
  assert.match(context.result.disabled, /调度：关闭/);
  assert.match(context.result.disabled, /不可用：调度已关闭/);
  assert.match(context.result.unknown, /调度：未知/);
  assert.match(context.result.unknown, /可用性未知：原因无法安全识别/);
  assert.doesNotMatch(context.result.unknown, /must-not-be-rendered/);
  assert.match(context.result.invalidAutoPause, /可用性未知：过期自动停调配置无效/);
});
