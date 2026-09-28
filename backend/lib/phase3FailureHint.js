// Child output is untrusted. These hints are display-only: never use them to
// classify an account, authorize retries, clear holds, or accept token output.
const HINTS = Object.freeze({
  EMAIL_CODE_SUBMIT_NOT_DISPATCHED: '邮箱验证码已填入，但未确认表单提交；已停止，未重复提交',
  VERIFICATION_CODE_SUBMIT_NOT_DISPATCHED: '验证码已填入，但未确认表单提交；已停止，未重复提交',
  VERIFICATION_DISPATCH_UNKNOWN: '验证码输入期间出现无法确认用途的请求，提交状态未知；已停止，未补点或重发',
  EMAIL_CODE_PAGE_STUCK: '邮箱验证码处理后页面未跳转；已停止，未重复提交旧验证码',
  EMAIL_CODE_REJECTED: '页面拒绝了邮箱验证码；请检查验证码是否失效',
  MAIL_CODE_PARSE_FAILED: '邮件已到达，但无法安全提取验证码；未自动重发',
  MAIL_STATUS_UNKNOWN: '邮箱查询结果不确定；未自动重发验证码',
  MAIL_BASELINE_UNKNOWN: '发送前的邮箱基线读取失败；已停止发码',
  MAIL_CODE_TIMEOUT: '邮箱查询成功，但等待新的可信验证码超时',
  MAIL_CODE_AMBIGUOUS: '存在多个无法确定先后的验证码；已停止，未猜测使用',
  OAUTH_ACCOUNT_MISMATCH: '登录页面显示的账号与所选账号不一致；已停止',
  ACCOUNT_CREDENTIALS_MISSING: '所选本地账号缺少登录凭据；已停止',
});

function phase3FailureHint(details) {
  if (!details || details.terminationConfirmed !== true
      || !Number.isSafeInteger(details.code) || details.code < 1 || details.code > 255
      || typeof details.stderr !== 'string') return null;
  let lastCode = null;
  // Bound work even if this helper is called outside the supervised runner.
  for (const line of details.stderr.slice(-64 * 1024).split(/\r?\n/)) {
    const match = /^\[主程序\] ([A-Z][A-Z0-9_]{0,95}):/.exec(line);
    if (match) lastCode = match[1];
  }
  if (!lastCode || !Object.hasOwn(HINTS, lastCode)) return null;
  return { code: lastCode, message: HINTS[lastCode] };
}

module.exports = { phase3FailureHint };
