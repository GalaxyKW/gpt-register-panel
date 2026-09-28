const test = require('node:test');
const assert = require('node:assert/strict');
require('./test-isolation');
const { phase3FailureHint } = require('../backend/lib/phase3FailureHint');
const { classifyPhase3ProcessError } = require('../backend/phase3Worker');

function details(stderr, extra = {}) {
  return { code: 1, terminationConfirmed: true, stderr, ...extra };
}

test('known terminal diagnostics yield fixed hints without echoing child prose', () => {
  const result = phase3FailureHint(details('[主程序] EMAIL_CODE_SUBMIT_NOT_DISPATCHED: synthetic-private-payload'));
  assert.equal(result.code, 'EMAIL_CODE_SUBMIT_NOT_DISPATCHED');
  assert.match(result.message, /未确认表单提交/);
  assert.equal(JSON.stringify(result).includes('synthetic-private-payload'), false);
  assert.equal(phase3FailureHint(details('[Mail] MAIL_CODE_PARSE_FAILED: arbitrary')), null);
  assert.equal(phase3FailureHint(details('prefix [主程序] MAIL_CODE_PARSE_FAILED: arbitrary')), null);
});

test('unknown last diagnostic, success, incomplete termination and stdout cannot supply hints', () => {
  const known = '[主程序] EMAIL_CODE_PAGE_STUCK: fixture';
  for (const value of [details(`${known}\n[主程序] UNKNOWN_FAILURE: fixture`), details(known, { code: 0 }),
    details(known, { code: null }), details(known, { terminationConfirmed: false }),
    details('', { stdout: known }), details('[主程序] ACCOUNT_DEACTIVATED: fixture')]) {
    assert.equal(phase3FailureHint(value), null);
  }
});

test('ordinary failure displays a hint while raw output and policy fields stay absent', () => {
  const error = new Error('phase3 进程失败（退出码 1）');
  error.details = details('[主程序] MAIL_CODE_PARSE_FAILED: fixture-private-body', { stdout: 'fixture-private-stdout' });
  classifyPhase3ProcessError(error);
  assert.match(error.message, /邮件已到达/);
  assert.match(error.message, /MAIL_CODE_PARSE_FAILED/);
  assert.equal(error.code, undefined);
  for (const key of ['accountDisposition', 'retryable', 'retryAllowed', 'doNotRetry', 'requiresReconciliation']) assert.equal(error[key], undefined);
  assert.equal(JSON.stringify(error).includes('fixture-private'), false);
  assert.equal(error.details.stderr, undefined);
  const message = error.message;
  classifyPhase3ProcessError(error);
  assert.equal(error.message, message);
});

test('supervision and reconciliation failures cannot be replaced by a display hint', () => {
  for (const code of ['JOB_INTERRUPTED', 'PHASE3_TIMEOUT', 'PHASE3_OUTPUT_LIMIT', 'PHASE3_TERMINATION_UNCONFIRMED', 'PHASE3_TOKEN_POSTFLIGHT_UNKNOWN']) {
    const error = new Error('primary safety failure');
    error.code = code;
    error.details = details('[主程序] EMAIL_CODE_PAGE_STUCK: fixture');
    classifyPhase3ProcessError(error);
    assert.equal(error.code, code);
    assert.equal(error.message, 'primary safety failure');
    if (code === 'PHASE3_TERMINATION_UNCONFIRMED') assert.equal(error.requiresReconciliation, true);
  }
});

test('diagnostic scanning is bounded and only retains the last known root error', () => {
  const first = '[主程序] MAIL_CODE_TIMEOUT: fixture';
  assert.equal(phase3FailureHint(details(first + '\n' + 'x'.repeat(70 * 1024))), null);
  assert.equal(phase3FailureHint(details(first + '\n[主程序] EMAIL_CODE_REJECTED: fixture')).code, 'EMAIL_CODE_REJECTED');
});
