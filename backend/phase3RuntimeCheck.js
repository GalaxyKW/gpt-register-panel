'use strict';

const path = require('node:path');
const { booleanEnvEnabled, validateBooleanEnvironment } = require('./config');
const { _registrationExecution: execution } = require('./phase3Worker');

const REASONS = Object.freeze({
  symlink: 'GPT_REGISTER_NODE_PATH 是符号链接；请配置已核验的真实 Node 普通文件，不要关闭路径保护',
  unsafe_parent: 'GPT_REGISTER_NODE_PATH 的父目录不存在、不可读取或包含符号链接',
  not_regular_file: 'GPT_REGISTER_NODE_PATH 不是普通文件',
  missing: 'GPT_REGISTER_NODE_PATH 指向的文件不存在',
  not_executable: 'GPT_REGISTER_NODE_PATH 指向的文件不可执行',
  unsafe_permissions: 'GPT_REGISTER_NODE_PATH 的所有者或写权限不安全',
  changed: 'GPT_REGISTER_NODE_PATH 在校验期间发生变化',
  unreadable: 'GPT_REGISTER_NODE_PATH 不可读取或无法安全确认',
});

// This is the worker's exact descriptor-based check, not `test -x` or a
// realpath fallback. It never executes Node, opens account files or starts a
// network preflight. Workers repeat the check immediately before each spawn.
function checkPhase3Runtime(environment = process.env) {
  validateBooleanEnvironment(environment);
  if (!booleanEnvEnabled('PANEL_PHASE3_ENABLED', false, environment)) {
    return { enabled: false, checked: false };
  }
  let handle;
  try {
    const filename = path.resolve(environment.GPT_REGISTER_NODE_PATH || process.execPath);
    handle = execution.openPinnedRegularFile(filename, 'GPT_REGISTER_NODE_PATH', { executable: true });
    return { enabled: true, checked: true };
  } catch (cause) {
    const reason = Object.hasOwn(REASONS, cause?.pathReason) ? cause.pathReason : 'unreadable';
    const error = new Error('注册执行器启动检查失败：' + REASONS[reason]);
    error.code = cause?.code === 'PHASE3_PATH_PERMISSIONS_INVALID'
      ? cause.code : 'PHASE3_PATH_INVALID';
    error.pathReason = reason;
    // Intentionally retain no raw cause or configured path: paths themselves
    // may contain pasted credentials and must not reach startup diagnostics.
    throw error;
  } finally {
    execution.closeRegularFileHandle(handle);
  }
}

module.exports = { checkPhase3Runtime };
