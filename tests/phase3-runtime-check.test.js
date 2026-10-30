'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
require('./test-isolation');
const { checkPhase3Runtime } = require('../backend/phase3RuntimeCheck');
const { _registrationExecution: execution } = require('../backend/phase3Worker');
const { startServer } = require('../backend/server');

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-runtime-precheck-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const marker = path.join(directory, 'must-not-execute');
  const executable = path.join(directory, 'node-fixture');
  fs.writeFileSync(executable, '#!/bin/sh\ntouch "' + marker + '"\n', { mode: 0o700 });
  const environment = { PANEL_PHASE3_ENABLED: '1', GPT_REGISTER_NODE_PATH: executable };
  return { directory, marker, executable, environment };
}
function withEnvironment(t, values) {
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
}
function rejectsAs(f, reason, code = 'PHASE3_PATH_INVALID') {
  assert.throws(() => checkPhase3Runtime(f.environment), error => {
    assert.equal(error.code, code); assert.equal(error.pathReason, reason);
    assert.equal(error.cause, undefined);
    assert.equal(error.message.includes(f.directory), false);
    return true;
  });
  assert.equal(fs.existsSync(f.marker), false);
}

test('runtime precheck uses the worker rule and closes its descriptor without executing or writing', t => {
  const f = fixture(t); const before = fs.readFileSync(f.executable);
  const worker = execution.openPinnedRegularFile(f.executable, 'GPT_REGISTER_NODE_PATH', { executable: true });
  execution.closeRegularFileHandle(worker);
  const count = () => process.platform === 'linux' ? fs.readdirSync('/proc/self/fd').length : null;
  const descriptorCount = count();
  for (let i = 0; i < 20; i++) assert.deepEqual(checkPhase3Runtime(f.environment), { enabled: true, checked: true });
  assert.equal(count(), descriptorCount);
  assert.deepEqual(fs.readFileSync(f.executable), before);
  assert.deepEqual(fs.readdirSync(f.directory), ['node-fixture']);
  assert.equal(fs.existsSync(f.marker), false);
  assert.deepEqual(checkPhase3Runtime({ PANEL_PHASE3_ENABLED: '1' }), { enabled: true, checked: true });
});

test('runtime precheck explicitly rejects an executable symlink that test -x would accept', t => {
  const f = fixture(t); const alias = path.join(f.directory, 'node-alias'); fs.symlinkSync(f.executable, alias);
  fs.accessSync(alias, fs.constants.X_OK);
  f.environment.GPT_REGISTER_NODE_PATH = alias;
  rejectsAs(f, 'symlink');
  assert.throws(() => execution.openPinnedRegularFile(alias, 'GPT_REGISTER_NODE_PATH', { executable: true }),
    { code: 'PHASE3_PATH_INVALID', pathReason: 'symlink' });
});

test('runtime precheck rejects parent aliases instead of resolving them', t => {
  const f = fixture(t); const subdir = path.join(f.directory, 'real'); fs.mkdirSync(subdir);
  fs.renameSync(f.executable, path.join(subdir, 'node'));
  const alias = path.join(f.directory, 'alias'); fs.symlinkSync(subdir, alias);
  f.environment.GPT_REGISTER_NODE_PATH = path.join(alias, 'node');
  rejectsAs(f, 'unsafe_parent');
});

for (const [name, reason, mutate] of [
  ['missing executable', 'missing', f => { fs.unlinkSync(f.executable); }],
  ['non-executable file', 'not_executable', f => { fs.chmodSync(f.executable, 0o600); }],
  ['directory instead of executable', 'not_regular_file', f => { f.environment.GPT_REGISTER_NODE_PATH = f.directory; }],
]) test('runtime precheck rejects ' + name, t => { const f = fixture(t); mutate(f); rejectsAs(f, reason); });

test('runtime precheck preserves worker permission restrictions', t => {
  const f = fixture(t); fs.chmodSync(f.executable, 0o722);
  rejectsAs(f, 'unsafe_permissions', 'PHASE3_PATH_PERMISSIONS_INVALID');
});

test('runtime precheck rejects an untrusted executable owner', { skip: process.geteuid?.() !== 0 }, t => {
  const f = fixture(t); fs.chownSync(f.executable, 65534, 65534);
  rejectsAs(f, 'unsafe_permissions', 'PHASE3_PATH_PERMISSIONS_INVALID');
});

test('disabled Phase3 does not inspect the configured executable and does not claim readiness', () => {
  const environment = { PANEL_PHASE3_ENABLED: '0', get GPT_REGISTER_NODE_PATH() { throw new Error('must not read path'); } };
  assert.deepEqual(checkPhase3Runtime(environment), { enabled: false, checked: false });
  assert.deepEqual(checkPhase3Runtime({}), { enabled: false, checked: false });
  assert.throws(() => checkPhase3Runtime({ PANEL_PHASE3_ENABLED: 'true' }), { code: 'ENV_BOOLEAN_INVALID' });
});

test('startup rejects an invalid configured executable before DB/logger creation or listening', async t => {
  const f = fixture(t); const alias = path.join(f.directory, 'node-alias'); fs.symlinkSync(f.executable, alias);
  withEnvironment(t, { PANEL_PHASE3_ENABLED: '1', GPT_REGISTER_NODE_PATH: alias,
    PANEL_REQUIRE_AUTH: '0', PANEL_ADMIN_TOKEN: undefined });
  let dbAccessed = false, loggerAccessed = false, listened = false;
  const previousListen = http.Server.prototype.listen;
  http.Server.prototype.listen = function () { listened = true; throw new Error('must not listen'); };
  t.after(() => { http.Server.prototype.listen = previousListen; });
  await assert.rejects(startServer({ host: '127.0.0.1', port: 0,
    get db() { dbAccessed = true; throw new Error('must not create DB'); },
    get logger() { loggerAccessed = true; throw new Error('must not create logger'); },
  }), { code: 'PHASE3_PATH_INVALID', pathReason: 'symlink' });
  assert.equal(dbAccessed, false); assert.equal(loggerAccessed, false); assert.equal(listened, false);
  assert.equal(fs.existsSync(f.marker), false);
});

test('standalone runtime check reads a private fixture env and never exposes its configured path or secrets', t => {
  const f = fixture(t); const secret = 'SYNTHETIC_ENV_SECRET_NOT_FOR_OUTPUT';
  const alias = path.join(f.directory, 'SYNTHETIC_PATH_SECRET'); fs.symlinkSync(f.executable, alias);
  const envFile = path.join(f.directory, 'fixture.env');
  fs.writeFileSync(envFile, 'PANEL_PHASE3_ENABLED=1\nGPT_REGISTER_NODE_PATH=' + alias + '\nPANEL_ADMIN_TOKEN=' + secret + '\n', { mode: 0o600 });
  const cli = path.resolve(__dirname, '../backend/cli/check-phase3-runtime.js');
  const environment = { PATH: '/usr/bin:/bin', PANEL_ENV_FILE: envFile };
  const run = (env = environment, args = []) => spawnSync(process.execPath, [cli, ...args], {
    env, cwd: f.directory, encoding: 'utf8', timeout: 10000, maxBuffer: 64 * 1024,
  });
  const failed = run();
  assert.equal(failed.status, 1); assert.match(failed.stderr, /符号链接/);
  assert.equal((failed.stdout + failed.stderr).includes(secret), false);
  assert.equal((failed.stdout + failed.stderr).includes('SYNTHETIC_PATH_SECRET'), false);
  assert.equal((failed.stdout + failed.stderr).includes(f.directory), false);
  assert.equal(fs.existsSync(f.marker), false);
  // Like systemd, an explicit process variable takes priority over stale .env.
  const passed = run({ ...environment, GPT_REGISTER_NODE_PATH: f.executable });
  assert.equal(passed.status, 0, passed.stderr);
  assert.deepEqual(JSON.parse(passed.stdout), { phase3Runtime: 'ready', enabled: true, checked: true });
  const disabled = run({ ...environment, PANEL_PHASE3_ENABLED: '0' });
  assert.equal(disabled.status, 0);
  assert.deepEqual(JSON.parse(disabled.stdout), { phase3Runtime: 'disabled', enabled: false, checked: false });
  assert.equal(fs.existsSync(f.marker), false);
  const invalidArgs = run(environment, ['--register']);
  assert.equal(invalidArgs.status, 1); assert.match(invalidArgs.stderr, /不接受命令行参数/);
});

test('importing runtime checker and CLI does not read deployment configuration', t => {
  const f = fixture(t); const cli = path.resolve(__dirname, '../backend/cli/check-phase3-runtime.js');
  const result = spawnSync(process.execPath, ['-e', 'require(' + JSON.stringify(cli) + ')'], {
    env: { PATH: '/usr/bin:/bin', PANEL_ENV_FILE: path.join(f.directory, 'nonexistent-private.env'), PANEL_PHASE3_ENABLED: '1' },
    cwd: f.directory, encoding: 'utf8', timeout: 10000, maxBuffer: 64 * 1024,
  });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
  assert.equal(fs.existsSync(f.marker), false);
});
