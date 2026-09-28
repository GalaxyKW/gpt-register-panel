'use strict';

// This function is embedded verbatim in the fixed Phase3 launcher. Keep it
// self-contained: it cannot depend on this module's scope or panel secrets.
function installPhase3ChildLifecycle() {
  const { setInterval } = require('node:timers');
  const { performance } = require('node:perf_hooks');
  const exit = process.exit.bind(process);
  let failedAt = null;

  // gpt_register's terminal bootstrap catch sets exitCode after business work
  // has failed. A browser dependency can retain live handles at that point,
  // preventing natural exit indefinitely. Allow a short logging grace, then
  // exit the leader so the panel can perform its verified process-tree cleanup
  // and token/ledger postflight. This does not assert that writes completed.
  const watcher = setInterval(() => {
    const value = process.exitCode;
    const code = typeof value === 'number' || typeof value === 'string'
      ? Number(value)
      : 0;
    if (!Number.isInteger(code) || code < 1 || code > 255) {
      failedAt = null;
      return;
    }
    const now = performance.now();
    if (failedAt === null) failedAt = now;
    if (now - failedAt >= 1000) exit(code);
  }, 100);

  // Healthy commands and failures without leaked handles must exit naturally;
  // this observer must never keep either one alive on its own. In particular,
  // stderr text is not a lifecycle signal and never triggers termination.
  watcher.unref();
}

module.exports = { installPhase3ChildLifecycle };
