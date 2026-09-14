'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

require('./test-isolation');

const { _testPhase3ProcessScan } = require('../backend/phase3Worker');

const projectRoot = path.resolve(__dirname, '..');

function runIsolatedScanFailure(openFailureExpression, command = '/bin/true', args = []) {
  const source = [
    "'use strict';",
    "const fs = require('node:fs');",
    "const { runCommand } = require('./backend/phase3Worker');",
    '(async () => {',
    '  try {',
    `    await runCommand(${JSON.stringify(command)}, ${JSON.stringify(args)}, {`,
    '      cwd: process.cwd(),',
    "      env: { PATH: process.env.PATH || '' },",
    '      timeoutMs: 5000,',
    '      terminationGraceMs: 100,',
    '      terminationHardDeadlineMs: 100,',
    '      maxOutputBytes: 4096,',
    '      procDirectoryOpener(directoryPath) {',
    `        if (${openFailureExpression}) {`,
    "          const error = new Error('injected proc directory failure');",
    "          error.code = 'EIO';",
    '          throw error;',
    '        }',
    '        return fs.opendirSync(directoryPath);',
    '      },',
    '    });',
    "    process.stdout.write(JSON.stringify({ unexpectedSuccess: true }));",
    '  } catch (error) {',
    '    process.stdout.write(JSON.stringify({',
    '      code: error.code,',
    '      terminationConfirmed: error.details?.terminationConfirmed,',
    '      processScanComplete: error.details?.processScanComplete,',
    '      forcedClose: error.details?.forcedClose,',
    '    }));',
    '  }',
    '})().catch((error) => {',
    '  process.stderr.write(String(error?.stack || error));',
    '  process.exitCode = 1;',
    '});',
  ].join('\n');
  const result = spawnSync(process.execPath, ['-e', source], {
    cwd: projectRoot,
    env: {
      PATH: process.env.PATH || '',
      PANEL_LOG_CONSOLE: '0',
    },
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.signal, null, result.stderr);
  assert.notEqual(result.stdout, '', JSON.stringify(result));
  return JSON.parse(result.stdout);
}

test('Phase3 refuses to confirm termination when the global proc scan fails', () => {
  if (process.platform !== 'linux') return;
  const outcome = runIsolatedScanFailure("directoryPath === '/proc'");
  assert.deepEqual(outcome, {
    code: 'PHASE3_TERMINATION_UNCONFIRMED',
    terminationConfirmed: false,
    processScanComplete: false,
    forcedClose: true,
  });
});

test('Phase3 task enumeration stops at its bound and reports an incomplete scan', () => {
  if (process.platform !== 'linux') return;
  let reads = 0;
  let closed = false;
  const taskId = String(process.pid);
  const result = _testPhase3ProcessScan.linuxChildPids(process.pid, {
    directoryEntryLimit: 2,
    openDirectory(directoryPath) {
      assert.equal(directoryPath, '/proc/' + String(process.pid) + '/task');
      return {
        readSync() {
          reads += 1;
          return reads <= 3 ? { name: taskId } : null;
        },
        closeSync() { closed = true; },
      };
    },
  });
  assert.equal(result.complete, false);
  assert.equal(reads, 3);
  assert.equal(closed, true);
  assert.equal(Array.isArray(result.values), true);
});

test('Phase3 retains complete child PIDs before a bounded children-file truncation', () => {
  assert.deepEqual(
    _testPhase3ProcessScan.parseLinuxChildPids('101 202 30', false),
    { values: [101, 202], complete: false },
  );
  assert.deepEqual(
    _testPhase3ProcessScan.parseLinuxChildPids('101 202 303 ', false),
    { values: [101, 202, 303], complete: false },
  );
});

test('Phase3 retains unreadable or cgroup-moved tracked processes until their identity is gone', () => {
  const expected = {
    pid: 4242,
    startId: 'start-a',
    cgroup: '0::/phase3-a',
    state: 'S',
    processGroupId: 4242,
    depth: 1,
  };
  const tracked = new Map([[expected.pid, expected]]);

  const unreadable = _testPhase3ProcessScan.activeTrackedDescendants(
    tracked,
    () => ({ status: 'unknown', identity: null }),
  );
  assert.deepEqual(unreadable, {
    active: [], pidSignalTargets: [], complete: false,
    unresolvedCount: 1, identityDrifted: false,
  });
  assert.equal(tracked.has(expected.pid), true);

  const moved = _testPhase3ProcessScan.activeTrackedDescendants(
    tracked,
    () => ({
      status: 'ok',
      identity: { ...expected, cgroup: '0::/phase3-b', processGroupId: 9000 },
    }),
  );
  assert.deepEqual(moved, {
    active: [], pidSignalTargets: [{ ...expected, processGroupId: 9000 }], complete: false,
    unresolvedCount: 1, identityDrifted: true,
  });
  assert.equal(tracked.has(expected.pid), true);

  const recycled = _testPhase3ProcessScan.activeTrackedDescendants(
    tracked,
    () => ({
      status: 'ok',
      identity: { ...expected, startId: 'start-b' },
    }),
  );
  assert.deepEqual(recycled, {
    active: [], pidSignalTargets: [], complete: true,
    unresolvedCount: 0, identityDrifted: false,
  });
  assert.equal(tracked.has(expected.pid), false);
});

test('Phase3 signals a cgroup-moved target only by reverified positive PID', () => {
  const expected = {
    pid: 4242,
    startId: 'start-a',
    cgroup: '0::/phase3-a',
    state: 'S',
  };
  const signals = [];
  _testPhase3ProcessScan.signalVerifiedPidTargets(
    [expected],
    'SIGKILL',
    () => ({
      status: 'ok',
      identity: { ...expected, cgroup: '0::/phase3-b' },
    }),
    (pid, signal) => signals.push([pid, signal]),
  );
  assert.deepEqual(signals, [[4242, 'SIGKILL']]);

  _testPhase3ProcessScan.signalVerifiedPidTargets(
    [expected],
    'SIGTERM',
    () => ({ status: 'ok', identity: { ...expected, startId: 'start-b' } }),
    (pid, signal) => signals.push([pid, signal]),
  );
  assert.deepEqual(signals, [[4242, 'SIGKILL']]);
});
