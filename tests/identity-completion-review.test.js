'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
require('./test-isolation');
const { safeAccount } = require('../backend/adapters/sub2apiAdmin');
const { normalizeTokenDocument } = require('../backend/lib/token');
const { accountTestTargetDigest, accountTestTargetRevision } = require('../backend/accountTargetRevision');
const {
  buildImportPlan, buildScopedImportPlan, assertRemoteImportPlan, assertBackupCoversUpdateTargets,
  listIdentityCompletionCandidates, normalizeIdentityCompletionTargets, resolveIdentityCompletionReview,
} = require('../backend/sync');

function fixture(suffix = 'one', id = 160, hash = 'a') {
  const raw = { id, name: 'free' + String(id).padStart(5, '0'), platform: 'openai', type: 'oauth',
    status: 'error', schedulable: false, group_ids: [], credentials: {
      chatgpt_user_id: 'review-user-' + suffix, email: suffix + '@example.test',
      access_token: 'review-old-access-' + suffix, refresh_token: 'review-old-refresh-' + suffix,
    }, credentials_status: { has_access_token: true, has_refresh_token: true, has_id_token: false } };
  const account = safeAccount(raw);
  const data = { chatgpt_account_id: 'review-account-' + suffix, chatgpt_user_id: 'review-user-' + suffix,
    email: suffix + '@example.test', access_token: 'review-new-access-' + suffix,
    refresh_token: 'review-new-refresh-' + suffix, expires_at: '2099-01-01T00:00:00.000Z',
    last_refresh: '2026-01-01T00:00:00.000Z' };
  const token = makeToken(suffix, data, hash);
  const key = 'token:tokens:' + token.relativePath;
  const sources = { tokens: [token], usernames: [] };
  const target = { selectedKey: key, accountId: id,
    targetRevision: accountTestTargetRevision(account), sourceContentHash: token.contentHash };
  return { raw, account, data, token, key, sources, target };
}

function makeToken(suffix, data, hash = 'b') {
  return normalizeTokenDocument({ source: 'tokens', relativePath: 'tokens/review-' + suffix + '.json',
    fileName: 'review-' + suffix + '.json', contentHash: hash.repeat(64), mtimeMs: 1, includeRaw: true, data });
}

function review(f, accounts = [f.account], targets = [f.target], sources = f.sources) {
  return resolveIdentityCompletionReview(sources, accounts, [f.key], targets);
}

function assertUnavailable(f, accounts = [f.account], sources = f.sources) {
  assert.equal(listIdentityCompletionCandidates(sources, accounts, [f.key]).length, 0);
  assert.throws(() => review(f, accounts, [f.target], sources));
}

test('explicit review offers only a user-matched account-ID completion and keeps ordinary import strict', () => {
  const f = fixture();
  assert.equal(buildImportPlan(f.sources, [f.account], [f.key])[0].action, 'conflict');
  const candidates = listIdentityCompletionCandidates(f.sources, [f.account], [f.key]);
  assert.equal(candidates.length, 1);
  assert.deepEqual(candidates[0], { ...f.target, accountName: f.account.name, identityCompletion: 'account_id' });
  const binding = review(f);
  assert.deepEqual(binding.sources, [{ selectedKey: f.key, contentHash: f.token.contentHash }]);
  assert.deepEqual(binding.remoteTargets, [{ accountId: 160, targetRevision: f.target.targetRevision }]);
  assert.deepEqual(binding.sourceBindings, [{ accountId: 160, selectedKey: f.key,
    contentHash: f.token.contentHash, identityKeys: ['user:review-user-one'],
    targetDigest: accountTestTargetDigest(f.account) }]);
  assert.deepEqual(binding.baselines, [{ accountId: 160, targetRevision: f.target.targetRevision,
    targetDigest: accountTestTargetDigest(f.account) }]);
  const planned = buildScopedImportPlan(f.sources, [f.account], [f.key], binding.sourceBindings);
  assert.equal(planned[0].action, 'update');
  assert.equal(planned[0].accountId, 160);
  assert.equal(planned[0].identityCompletion, 'account_id');
  assert.equal(planned[0]._account, f.account);
  assert.equal(f.account.accountId, '', 'the remote backup identity must remain user-only');
  assert.doesNotThrow(() => assertRemoteImportPlan(planned, [f.account], binding.remoteTargets, binding.baselines));
  assert.equal(assertBackupCoversUpdateTargets({ accounts: [f.raw], proxies: [] }, planned).updateTargetCount, 1);
  assert.equal(buildImportPlan(f.sources, [f.account], [f.key])[0].action, 'conflict');
});

test('review normalization strictly binds every selected key once and sorts by original remote ID', () => {
  const first = fixture(), second = fixture('two', 174, 'b');
  const selected = [second.key, first.key];
  const targets = [second.target, first.target];
  assert.deepEqual(normalizeIdentityCompletionTargets(targets, selected), [first.target, second.target]);
  assert.deepEqual(targets, [second.target, first.target], 'normalization does not mutate caller order');
  for (const invalid of [undefined, null, {}, [], [first.target], [first.target, first.target],
    [{ ...first.target, accountId: second.target.accountId }, second.target],
    [{ ...first.target, selectedKey: second.key }, second.target],
    [{ ...first.target, accountId: '160' }, second.target],
    [{ ...first.target, accountId: 0 }, second.target],
    [{ ...first.target, targetRevision: 'invalid' }, second.target],
    [{ ...first.target, sourceContentHash: 'invalid' }, second.target],
    [{ ...first.target, sourceContentHash: 'A'.repeat(64) }, second.target],
    [{ ...first.target, identityKeys: ['user:forged'] }, second.target],
    [{ ...first.target, targetDigest: 'c'.repeat(64) }, second.target],
    [{ ...first.target, identityCompletion: 'account_id' }, second.target],
    [{ accountId: first.target.accountId, targetRevision: first.target.targetRevision,
      selectedKey: first.key }, second.target],
  ]) assert.throws(() => normalizeIdentityCompletionTargets(invalid, selected));
  assert.throws(() => normalizeIdentityCompletionTargets([first.target], []));
  assert.throws(() => normalizeIdentityCompletionTargets([first.target], [first.key, first.key]));
  assert.throws(() => normalizeIdentityCompletionTargets(new Array(1), [first.key]));
  const tooMany = Array.from({ length: 101 }, (_, i) => ({ ...first.target,
    accountId: i + 1, selectedKey: 'token:tokens:tokens/many-' + i + '.json' }));
  assert.throws(() => normalizeIdentityCompletionTargets(tooMany, tooMany.map(item => item.selectedKey)));
});

test('review rejects changed user existing account identity no user and email-only coincidences', () => {
  for (const credentials of [
    { chatgpt_user_id: 'another-review-user' },
    { chatgpt_user_id: 'review-user-one', chatgpt_account_id: 'review-account-one' },
    { chatgpt_user_id: 'review-user-one', chatgpt_account_id: 'another-review-account' },
    { chatgpt_account_id: 'review-account-one' }, {},
  ]) {
    const f = fixture();
    const account = safeAccount({ ...f.raw, credentials: { ...credentials,
      email: f.data.email, access_token: 'review-old-access', refresh_token: 'review-old-refresh' } });
    f.target.targetRevision = accountTestTargetRevision(account);
    assertUnavailable(f, [account]);
  }
});

test('review rejects source tokens missing either strong identity dimension', () => {
  for (const absent of ['chatgpt_account_id', 'chatgpt_user_id', 'both']) {
    const f = fixture();
    const data = { ...f.data };
    if (absent !== 'chatgpt_user_id') delete data.chatgpt_account_id;
    if (absent !== 'chatgpt_account_id') delete data.chatgpt_user_id;
    const sources = { ...f.sources, tokens: [makeToken('one', data, 'a')] };
    assertUnavailable(f, [f.account], sources);
  }
});

test('review refuses every other remote account sharing the candidate account or user', () => {
  for (const identity of [
    { chatgpt_user_id: 'review-user-one', chatgpt_account_id: 'different-account' },
    { chatgpt_user_id: 'different-user', chatgpt_account_id: 'review-account-one' },
    { chatgpt_user_id: 'review-user-one' },
  ]) {
    const f = fixture();
    const other = safeAccount({ ...f.raw, id: 161, name: 'free00161', credentials: {
      ...identity, access_token: 'review-other-access', refresh_token: 'review-other-refresh',
    } });
    assertUnavailable(f, [f.account, other]);
  }
});

test('unselected local identity forks cannot authorize completing the selected source', () => {
  for (const changes of [
    { chatgpt_account_id: 'forked-account' },
    { chatgpt_user_id: 'forked-user' },
  ]) {
    const f = fixture();
    const sibling = makeToken('unselected', { ...f.data, ...changes,
      access_token: 'review-unselected-access', last_refresh: '2025-01-01T00:00:00.000Z' });
    assertUnavailable(f, [f.account], { ...f.sources, tokens: [f.token, sibling] });
  }
});

test('compatible older partial copies never replace the complete selected identity proof', () => {
  const f = fixture();
  const partialData = { ...f.data, chatgpt_account_id: undefined,
    access_token: 'review-partial-access', last_refresh: '2025-01-01T00:00:00.000Z' };
  const partial = makeToken('partial', partialData);
  const sources = { ...f.sources, tokens: [f.token, partial] };
  const candidates = listIdentityCompletionCandidates(sources, [f.account], [f.key]);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].selectedKey, f.key);
  const binding = review(f, [f.account], [f.target], sources);
  const planned = buildScopedImportPlan(sources, [f.account], [f.key], binding.sourceBindings);
  assert.equal(planned[0].accountId, 160);
  assert.equal(planned[0].sourceIdentityKeys.some(key => key.startsWith('account:')), true);
  const partialKey = 'token:tokens:' + partial.relativePath;
  assert.equal(listIdentityCompletionCandidates(sources, [f.account], [partialKey]).length, 0,
    'review must not substitute an unselected winner for an older selected file');
  const latestPartial = makeToken('partial', { ...partialData, last_refresh: '2027-01-01T00:00:00.000Z' });
  assert.equal(listIdentityCompletionCandidates({ ...sources, tokens: [f.token, latestPartial] },
    [f.account], [partialKey]).length, 0, 'a partial winning token cannot authorize completion');
});

test('unrelated unselected local sources are neither reviewed nor authorized', () => {
  const first = fixture(), second = fixture('two', 174, 'b');
  const sources = { tokens: [first.token, second.token], usernames: [] };
  const candidates = listIdentityCompletionCandidates(sources, [first.account, second.account], [first.key]);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].selectedKey, first.key);
  const binding = review(first, [first.account, second.account], [first.target], sources);
  assert.deepEqual(binding.remoteTargets.map(target => target.accountId), [160]);
  assert.throws(() => resolveIdentityCompletionReview(sources, [first.account, second.account],
    [first.key], [second.target]));
});

test('expired disabled terminal historical and superseded sources cannot be reviewed for writes', () => {
  for (const kind of ['expired', 'disabled', 'terminal', 'historical', 'superseded']) {
    const f = fixture();
    const data = { ...f.data };
    if (kind === 'expired') data.expires_at = '2000-01-01T00:00:00.000Z';
    if (kind === 'disabled') data.disabled = true;
    const token = makeToken('one', data, 'a');
    if (kind === 'historical') token.historical = true;
    const sources = { tokens: [token], usernames: kind === 'terminal'
      ? [{ email: f.data.email, status: 'account_deactivated' }] : [] };
    if (kind === 'superseded') sources.tokens.push(makeToken('newest', { ...f.data,
      last_refresh: '2027-01-01T00:00:00.000Z', access_token: 'review-newest-access' }));
    if (kind === 'historical') {
      assert.throws(() => listIdentityCompletionCandidates(sources, [f.account], [f.key]),
        { code: 'IMPORT_SELECTION_MISMATCH' });
      assert.throws(() => review(f, [f.account], [f.target], sources));
    } else assertUnavailable(f, [f.account], sources);
  }
});

test('available unknown or invalid remote state cannot be offered for identity completion', () => {
  for (const state of [
    { status: 'active', schedulable: true }, { status: 'unknown' }, { schemaValid: false },
  ]) {
    const f = fixture();
    const account = { ...f.account, ...state };
    f.target.targetRevision = accountTestTargetRevision(account);
    assertUnavailable(f, [account]);
  }
});

test('review rejects changed source hash target signature and remote state after confirmation', () => {
  const f = fixture(), other = fixture('two', 174, 'b');
  for (const target of [
    { ...f.target, sourceContentHash: 'c'.repeat(64) },
    { ...f.target, targetRevision: other.target.targetRevision },
    { ...f.target, accountId: 174 },
  ]) assert.throws(() => review(f, [f.account], [target]));
  const changedToken = { ...f.token, contentHash: 'c'.repeat(64) };
  assert.throws(() => review(f, [f.account], [f.target], { ...f.sources, tokens: [changedToken] }));
  for (const changes of [{ status: 'active', schedulable: true }, { groupIds: [7] },
    { tokenFingerprints: { access: 'e'.repeat(16) } }]) {
    assert.throws(() => review(f, [{ ...f.account, ...changes }]));
  }
});

test('review rejects crossed source-to-remote mappings even with valid per-target revisions and hashes', () => {
  const first = fixture(), second = fixture('two', 174, 'b');
  const sources = { tokens: [first.token, second.token], usernames: [] };
  const accounts = [first.account, second.account];
  const keys = [first.key, second.key];
  const targets = [first.target, second.target];
  const valid = resolveIdentityCompletionReview(sources, accounts, keys, targets);
  assert.deepEqual(valid.remoteTargets.map(target => target.accountId), [160, 174]);
  const crossed = [
    { ...second.target, selectedKey: first.key, sourceContentHash: first.token.contentHash },
    { ...first.target, selectedKey: second.key, sourceContentHash: second.token.contentHash },
  ];
  assert.throws(() => resolveIdentityCompletionReview(sources, accounts, keys, crossed));
});
