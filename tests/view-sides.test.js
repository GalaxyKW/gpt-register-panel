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
    observedKind: 'token_changed',
    decisionAction: 'skip',
    decisionReason: 'sub2api_available',
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
  assert.equal(row.observedKind, 'token_changed');
  assert.equal(row.decisionAction, 'skip');
  assert.equal(row.decisionReason, 'sub2api_available');
  assert.equal(JSON.stringify(row).includes('must-not-leak'), false);
  assert.deepEqual(filterRows([row], { search: 'local-workspace' }), [row]);
  assert.deepEqual(filterRows([row], { search: '266' }), [row]);
});

test('view rows fail closed for malformed decision metadata', () => {
  const row = rowFromDiffItem({
    kind: 'token_changed',
    observedKind: 'token_changed',
    decisionAction: 'delete',
    decisionReason: 'credential=must-not-be-forwarded',
    token: {
      source: 'tokens',
      relativePath: 'tokens/local.json',
      fingerprints: {},
    },
    account: null,
    issues: [],
  });
  assert.equal(row.observedKind, 'token_changed');
  assert.equal(row.decisionAction, null);
  assert.equal(row.decisionReason, null);
  assert.equal(JSON.stringify(row).includes('must-not-be-forwarded'), false);
});

test('view rows expose only an opaque process-bound revision for valid remote test targets', () => {
  const account = {
    id: 267,
    name: 'free00007',
    platform: 'openai',
    type: 'oauth',
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    schemaValid: true,
    accountId: 'sensitive-account-267',
    userId: 'sensitive-user-267',
    identityKeys: ['account:sensitive-account-267', 'user:sensitive-user-267'],
    tokenFingerprints: { access: '1234567890abcdef', refresh: null, id: null },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'absent' },
  };
  const row = rowFromDiffItem({
    kind: 'sub2api_only',
    token: null,
    account,
    issues: [],
  });
  assert.match(row.targetRevision, /^account-test-v1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(row.targetRevision.includes(account.accountId), false);
  assert.equal(row.targetRevision.includes(account.userId), false);
  assert.equal(row.targetRevision.includes(account.tokenFingerprints.access), false);

  const replaced = rowFromDiffItem({
    kind: 'sub2api_only',
    token: null,
    account: {
      ...account,
      userId: 'replacement-user-267',
      identityKeys: ['account:sensitive-account-267', 'user:replacement-user-267'],
    },
    issues: [],
  });
  assert.notEqual(replaced.targetRevision, row.targetRevision);
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

test('view rows explicitly reject historical tokens and invalid username phones for Phase3', () => {
  const token = {
    source: 'tokens',
    relativePath: 'tokens/phase3-source.json',
    fileName: 'phase3-source.json',
    email: 'phase3-source@example.test',
    parseStatus: 'ok',
    contentHash: 'a'.repeat(64),
    identityKeys: ['account:phase3-source-account'],
    fingerprints: {},
  };
  const username = {
    index: 0,
    email: token.email,
    phone: '13800138000',
    phoneValid: true,
    hasPassword: true,
    status: 'oauth_done',
  };
  const item = { kind: 'token_only', issues: [], token, account: null };
  const options = {
    usernames: [username],
    usernameContentHash: 'b'.repeat(64),
  };

  const eligible = rowFromDiffItem(item, options);
  assert.equal(eligible.phase3Eligible, true);
  assert.match(eligible.phase3TargetRevision, /^phase3-target-v1\.[A-Za-z0-9_-]{43}$/);

  const historical = rowFromDiffItem({
    ...item,
    kind: 'historical_backup',
    token: { ...token, historical: true },
  }, options);
  assert.equal(historical.historical, true);
  assert.equal(historical.phase3Eligible, false);
  assert.equal(historical.phase3Reason, 'phase3_source_historical');
  assert.equal(historical.phase3TargetRevision, null);

  const invalidPhone = rowFromDiffItem(item, {
    ...options,
    usernames: [{ ...username, phone: '', phoneValid: false }],
  });
  assert.equal(invalidPhone.usernameMatch, 'unique');
  assert.equal(invalidPhone.phone, '');
  assert.equal(invalidPhone.phase3Eligible, false);
  assert.equal(invalidPhone.phase3Reason, 'username_phone_invalid');
  assert.equal(invalidPhone.phase3TargetRevision, null);

  const terminalWithoutCredentials = rowFromDiffItem(item, {
    ...options,
    usernames: [{
      ...username,
      phone: '',
      phoneValid: false,
      hasPassword: false,
      status: 'account_deleted',
    }],
  });
  assert.equal(terminalWithoutCredentials.phase3Eligible, false);
  assert.equal(terminalWithoutCredentials.phase3Reason, 'username_terminal');
  assert.equal(terminalWithoutCredentials.phase3TargetRevision, null);

  const invalidTarget = rowFromDiffItem({
    ...item,
    token: { ...token, relativePath: 'tokens/../phase3-source.json' },
  }, options);
  assert.equal(invalidTarget.usernameMatch, 'unique');
  assert.equal(invalidTarget.phase3Eligible, false);
  assert.equal(invalidTarget.phase3Reason, 'phase3_target_invalid');
  assert.equal(invalidTarget.phase3TargetRevision, null);
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

test('frontend separates observed differences from safe synchronization decisions', () => {
  const primitives = sourceSection('function escapeHtml', 'function finiteNumber');
  const actionContracts = sourceSection('function actionLabel', 'function phase3ReasonLabel');
  const sideRenderers = sourceSection('function rowSideData', 'function renderRows');
  const context = { importPlanContractProblem: () => '' };
  vm.runInNewContext(primitives + '\n' + actionContracts + '\n' + sideRenderers + `
    result = {
      availableChanged: renderDiffDecision({
        diffKind: 'token_changed',
        decisionAction: 'skip',
        decisionReason: 'sub2api_available',
      }, { source: {}, remote: { id: 41 } }),
      unavailableChanged: renderDiffDecision({
        diffKind: 'token_changed',
        decisionAction: 'update',
        decisionReason: 'token_changed',
      }, { source: {}, remote: { id: 42 } }),
      duplicateNeedsPreview: renderDiffDecision({
        diffKind: 'duplicate_identity',
        decisionAction: null,
        decisionReason: null,
      }, { source: {}, remote: null }),
      remoteUnknown: renderDiffDecision({
        diffKind: 'remote_unknown',
        decisionAction: null,
        decisionReason: 'sub2api_read_failed',
      }, { source: {}, remote: null }),
      hostileReason: renderDiffDecision({
        diffKind: 'token_changed',
        decisionAction: 'skip',
        decisionReason: 'credential=must-not-render',
      }, { source: {}, remote: { id: 43 } }),
    };
  `, context);

  assert.match(context.result.availableChanged, /同步：跳过/);
  assert.match(context.result.availableChanged, /Sub2API 当前可用/);
  assert.match(context.result.unavailableChanged, /同步：更新/);
  assert.match(context.result.unavailableChanged, /token 不同/);
  assert.match(context.result.duplicateNeedsPreview, /同步：需先预览/);
  assert.match(context.result.remoteUnknown, /同步：不可决策/);
  assert.match(context.result.remoteUnknown, /Sub2API 读取失败/);
  assert.match(context.result.hostileReason, /操作原因未识别/);
  assert.doesNotMatch(context.result.hostileReason, /must-not-render/);
  assert.match(htmlSource, /<th>差异 \/ 同步决策<\/th>/);
});
