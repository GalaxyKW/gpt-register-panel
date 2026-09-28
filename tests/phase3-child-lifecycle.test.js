'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const test = require('node:test');

const { installPhase3ChildLifecycle } = require('../backend/lib/phase3ChildLifecycle');

function runChild(body) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      '-e',
      `(${installPhase3ChildLifecycle.toString()})();\n${body}`,
    ], {
      env: { PATH: process.env.PATH || '' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const output = { stdout: '', stderr: '' };
    let expired = false;
    const timer = setTimeout(() => {
      expired = true;
      child.kill('SIGKILL');
    }, 15000);
    child.stdout.on('data', (chunk) => { output.stdout += chunk; });
    child.stderr.on('data', (chunk) => { output.stderr += chunk; });
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, expired, ...output });
    });
  });
}

function assertExited(result, code) {
  assert.equal(result.expired, false, 'child did not exit within the test deadline');
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.code, code, result.stderr);
}

test('Phase3 child lifecycle observer does not retain an otherwise idle process', async () => {
  const result = await runChild("process.stdout.write('natural exit');");
  assertExited(result, 0);
  assert.equal(result.stdout, 'natural exit');
});

test('Phase3 child lifecycle leaves healthy long-running work and exitCode zero alone', async () => {
  const result = await runChild([
    'setTimeout(() => { process.exitCode = 0; }, 600);',
    "setTimeout(() => { process.stdout.write('completed work'); }, 1450);",
  ].join('\n'));
  assertExited(result, 0);
  assert.equal(result.stdout, 'completed work');
});

test('Phase3 child lifecycle exits a failed leader even when a leaked handle stays live', async () => {
  const result = await runChild([
    'setInterval(() => {}, 1000);',
    'process.exitCode = 23;',
    "process.once('exit', (code) => { require('node:fs').writeSync(1, 'exit hook ' + code); });",
    "setTimeout(() => { process.stdout.write('logging grace'); }, 200);",
  ].join('\n'));
  assertExited(result, 23);
  assert.equal(result.stdout, 'logging graceexit hook 23');
});

test('Phase3 child lifecycle accepts a numeric string failure exit code', async () => {
  const result = await runChild([
    'setInterval(() => {}, 1000);',
    "process.exitCode = '24';",
  ].join('\n'));
  assertExited(result, 24);
});

test('Phase3 child lifecycle cancels its grace when a temporary failure code is cleared', async () => {
  const result = await runChild([
    'process.exitCode = 2;',
    'setTimeout(() => { process.exitCode = 0; }, 300);',
    "setTimeout(() => { process.stdout.write('recovered before terminal grace'); }, 1450);",
  ].join('\n'));
  assertExited(result, 0);
  assert.equal(result.stdout, 'recovered before terminal grace');
});

test('Phase3 child lifecycle does not interpret error-like stdout or stderr as failure', async () => {
  const result = await runChild([
    "process.stdout.write('RUN_FAILED process.exitCode = 1');",
    "process.stderr.write('ECONNREFUSED browser startup failed');",
    "setTimeout(() => { process.stdout.write(' done'); }, 1450);",
  ].join('\n'));
  assertExited(result, 0);
  assert.equal(result.stdout, 'RUN_FAILED process.exitCode = 1 done');
});

test('Phase3 child lifecycle failure grace is not extended by a wall-clock rollback', async () => {
  const result = await runChild([
    'Date.now = () => 0;',
    'setInterval(() => {}, 1000);',
    'process.exitCode = 25;',
  ].join('\n'));
  assertExited(result, 25);
});
