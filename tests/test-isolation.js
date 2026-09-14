'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Tests must never inherit deployment credentials or paths. This module is
// preloaded by `npm test` and is also required by each test file before any
// application module, so direct `node --test tests/foo.test.js` runs are safe.
const deploymentVariables = [
  'PANEL_ENV_FILE',
  'SUB2API_BASE_URL',
  'SUB2API_ADMIN_API_KEY',
  'SUB2API_JWT',
  'SUB2API_GROUP_IDS',
  'SUB2API_GROUP_NAME',
  'SUB2API_CONFIRM_MIXED_CHANNEL_RISK',
  'SUB2API_ALLOW_INSECURE_HTTP',
  'SUB2API_TIMEOUT_MS',
  'SUB2API_TEST_TIMEOUT_MS',
  'SUB2API_MAX_RESPONSE_BYTES',
  'GPT_REGISTER_ROOT',
  'GPT_REGISTER_NODE_PATH',
  'GPT_REGISTER_TOKEN_MAX_BYTES',
  'GPT_REGISTER_TOKEN_MAX_FILES',
  'GPT_REGISTER_TOKEN_TOTAL_MAX_BYTES',
  'GPT_REGISTER_USERNAME_MAX_BYTES',
  'GPT_REGISTER_USERNAME_MAX_RECORDS',
  'PANEL_DB_PATH',
  'PANEL_DB_MAX_BYTES',
  'PANEL_DB_LOCK_TIMEOUT_MS',
  'PANEL_LOG_PATH',
  'PANEL_LOG_LEVEL',
  'PANEL_LOG_MAX_BYTES',
  'PANEL_LOG_ROTATIONS',
  'PANEL_LOG_CONSOLE',
  'PANEL_BACKUP_DIR',
  'PANEL_BACKUP_RETENTION_DAYS',
  'PANEL_BACKUP_MAX_FILES',
  'PANEL_BACKUP_MAX_TOTAL_BYTES',
  'PANEL_CONTROL_LOCK_PATH',
  'PANEL_CONTROL_LOCK_TIMEOUT_MS',
  'PANEL_CONTROL_LOCK_POLL_MS',
  'PANEL_TOKEN_QUARANTINE_DIR',
  'PANEL_ADMIN_TOKEN',
  'PANEL_REQUIRE_AUTH',
  'PANEL_WRITE_ENABLED',
  'PANEL_ALLOW_INSECURE_WRITE',
  'PANEL_PHASE3_ENABLED',
  'PANEL_PHASE3_TIMEOUT_MS',
  'PANEL_PHASE3_MAX_OUTPUT_BYTES',
  'PANEL_PHASE3_KILL_GRACE_MS',
  'PANEL_PHASE3_MAX_ACTIVE_JOBS',
  'PANEL_ACCOUNT_TEST_JOB_TIMEOUT_MS',
  'PANEL_AUTH_MAX_FAILURES',
  'PANEL_AUTH_WINDOW_MS',
  'PANEL_AUTH_BLOCK_MS',
  'PANEL_HTTP_REQUEST_TIMEOUT_MS',
  'PANEL_HTTP_HEADERS_TIMEOUT_MS',
  'PANEL_HTTP_KEEP_ALIVE_TIMEOUT_MS',
  'PANEL_HTTP_MAX_HEADERS',
  'PANEL_HTTP_MAX_REQUESTS_PER_SOCKET',
  'PANEL_SHUTDOWN_TIMEOUT_MS',
  'PANEL_MAX_JOBS',
  'PANEL_MAX_AUDIT_EVENTS',
  'PANEL_MAX_SNAPSHOTS',
  'PANEL_HOST',
  'PANEL_PORT',
  'PANEL_ALLOW_INSECURE_REMOTE',
  'PANEL_ALLOW_UNBACKED_WRITES',
];
for (const name of deploymentVariables) delete process.env[name];

const isolationRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-test-process-'));
const registerRoot = path.join(isolationRoot, 'gpt-register');
const runtimeRoot = path.join(isolationRoot, 'runtime');
fs.mkdirSync(path.join(registerRoot, 'tokens'), { recursive: true, mode: 0o700 });
fs.mkdirSync(path.join(registerRoot, 'use_token'), { recursive: true, mode: 0o700 });
fs.mkdirSync(runtimeRoot, { recursive: true, mode: 0o700 });
fs.mkdirSync(path.join(runtimeRoot, 'backups'), { recursive: true, mode: 0o700 });
fs.writeFileSync(path.join(registerRoot, 'username.json'), '[]\n', { mode: 0o600 });

process.env.PANEL_TEST_ISOLATION_ROOT = isolationRoot;
process.env.GPT_REGISTER_ROOT = registerRoot;
process.env.PANEL_DB_PATH = path.join(runtimeRoot, 'panel.sqlite3');
process.env.PANEL_LOG_PATH = path.join(runtimeRoot, 'panel.log');
process.env.PANEL_BACKUP_DIR = path.join(runtimeRoot, 'backups');
process.env.PANEL_CONTROL_LOCK_PATH = path.join(runtimeRoot, 'control-plane.lock');
process.env.PANEL_LOG_CONSOLE = '0';
process.env.PANEL_WRITE_ENABLED = '0';
process.env.PANEL_PHASE3_ENABLED = '0';
process.env.PANEL_REQUIRE_AUTH = '0';
process.env.PANEL_ALLOW_INSECURE_WRITE = '0';

module.exports = { isolationRoot, registerRoot, runtimeRoot };
