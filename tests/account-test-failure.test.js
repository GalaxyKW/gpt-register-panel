const assert = require('node:assert/strict');
const test = require('node:test');
require('./test-isolation');
const { classifyAccountTestFailure, normalizeAccountTestFailure } = require('../backend/lib/accountTestFailure');

test('account test failure diagnostics classify fixed transport wrappers without preserving details', () => {
  const marker = 'synthetic-private-upstream-marker';
  const result = classifyAccountTestFailure({ type: 'error', error: 'Request failed: Post "https://' + marker + '/": context deadline exceeded' });
  assert.equal(result.failureCategory, 'network');
  assert.equal(result.upstreamStatus, null);
  assert.match(result.message, /网络请求失败/);
  assert.equal(JSON.stringify(result).includes(marker), false);
  assert.equal(classifyAccountTestFailure({ error: 'Help text says Request failed: example' }).failureCategory, 'unknown');
  assert.equal(classifyAccountTestFailure({ error: 'Request failed: first\nsecond' }).failureCategory, 'unknown');
});

test('account test diagnostics only expose allowlisted error codes and HTTP statuses', () => {
  const cases = [
    [400, 'model_not_supported', 'model_unavailable'], [404, 'model_not_found', 'model_unavailable'],
    [429, 'insufficient_quota', 'quota'], [429, 'rate_limit_exceeded', 'rate_limited'],
    [401, 'token_expired', 'authentication'], [403, 'account_deactivated', 'account_status'],
    [502, 'opaque-untrusted-code', 'upstream'],
  ];
  for (const [status, code, category] of cases) {
    const result = classifyAccountTestFailure({ type: 'error', error: 'API returned ' + status + ': ' + JSON.stringify({
      error: { code, message: 'synthetic-private-body-marker', credentials: 'synthetic-private-credential-marker' },
    }) });
    assert.equal(result.failureCategory, category);
    assert.equal(result.upstreamStatus, status);
    assert.equal(JSON.stringify(result).includes('synthetic-private'), false);
    assert.equal(Object.hasOwn(result, 'canDelete'), false);
    assert.equal(Object.hasOwn(result, 'canRefresh'), false);
  }
  assert.equal(classifyAccountTestFailure({ error: 'API returned 200: not successful' }).upstreamStatus, null);
  assert.equal(classifyAccountTestFailure({ error: 'prefix API returned 401: example' }).failureCategory, 'unknown');
  assert.equal(classifyAccountTestFailure({ error: 'API returned 403: account_deactivated in help text' }).failureCategory, 'upstream');
});

test('account test diagnostics support structured codes but ignore arbitrary prose and oversized values', () => {
  assert.equal(classifyAccountTestFailure({ type: 'error', code: 'model_not_found' }).failureCategory, 'model_unavailable');
  assert.equal(classifyAccountTestFailure({ type: 'error', error: { code: 'invalid_token' } }).failureCategory, 'authentication');
  for (const error of ['account_deactivated', 'model_not_found in conversation', 'Bearer synthetic-private-marker', 'Request failed: ' + 'x'.repeat(17000)]) {
    assert.equal(classifyAccountTestFailure({ error }).failureCategory, 'unknown');
  }
});

test('account test diagnostics reject inherited values, getters and unknown metadata', () => {
  let read = false;
  const hostile = Object.defineProperties({}, {
    failureCategory: { get() { read = true; throw new Error('synthetic-private-marker'); } },
    upstreamStatus: { get() { read = true; throw new Error('synthetic-private-marker'); } },
    error: { get() { read = true; throw new Error('synthetic-private-marker'); } },
  });
  assert.equal(normalizeAccountTestFailure(hostile).failureCategory, 'unknown');
  assert.equal(classifyAccountTestFailure(hostile).failureCategory, 'unknown');
  assert.equal(read, false);
  assert.equal(normalizeAccountTestFailure(Object.create({ failureCategory: 'network' })).failureCategory, 'unknown');
  assert.equal(normalizeAccountTestFailure({ failureCategory: '__proto__', upstreamStatus: '502' }).failureCategory, 'unknown');
  assert.equal(normalizeAccountTestFailure({ failureCategory: 'network', upstreamStatus: 999 }).upstreamStatus, null);
  assert.equal(normalizeAccountTestFailure({ failureCategory: 'network', upstreamStatus: 502 }).upstreamStatus, 502);
});
