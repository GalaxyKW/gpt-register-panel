'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const { runCommand } = require('../backend/phase3Worker');

test('engine supervisor passes only its validated internal job identity to run logging', async () => {
  const trusted = 'job_' + 'a'.repeat(24), inherited = 'job_' + 'b'.repeat(24);
  for (const jobId of [trusted, undefined, '../untrusted', 'job_' + 'a'.repeat(23) + '\n']) {
    const result = await runCommand(process.execPath, ['-e',
      'process.stdout.write(process.env.GPT_REGISTER_PANEL_JOB_ID || "unbound")'], {
      jobId, env: { GPT_REGISTER_PANEL_JOB_ID: inherited }, timeoutMs: 5000,
    });
    assert.equal(result.code, 0); assert.equal(result.terminationConfirmed, true);
    assert.equal(result.stdout, jobId === trusted ? trusted : 'unbound');
  }
});
