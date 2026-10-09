'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { listLogFiles, queryLogs, downloadLog, cleanupLogs } = require('../backend/consoleLogs');

const DEAD_PID = 2147483647;
const timestamp = '2020-01-01T00:00:00.000Z';
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-console-logs-'));
  const panel = path.join(root, 'panel'), register = path.join(root, 'register');
  fs.mkdirSync(panel, { mode: 0o700 }); fs.mkdirSync(register, { mode: 0o700 });
  fs.mkdirSync(path.join(register, 'logs'), { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, panel, register, options: { panelLogPath: path.join(panel, 'panel.log'), rootDirectory: register },
    write(source, name, data, old = false) {
      const filename = path.join(source === 'panel' ? panel : path.join(register, 'logs'), name);
      fs.writeFileSync(filename, data, { mode: 0o600 });
      if (old) fs.utimesSync(filename, new Date(timestamp), new Date(timestamp));
      return filename;
    } };
}
function registerName(pid = DEAD_PID, suffix = '000000000') { return `run-20200101T${suffix}Z-${pid}.log`; }
function record(message, level = 'INFO') { return `[${timestamp}] [${level}] ${message}\n`; }
function jsonRecord(fields = {}) { return JSON.stringify({ time: timestamp, level: 'info', message: 'safe fixture', ...fields }) + '\n'; }
function patch(t, target, key, replacement) {
  const original = target[key]; target[key] = replacement(original); t.after(() => { target[key] = original; });
}
function assertSafe(value) { assert.equal(JSON.stringify(value).includes('fixture-private-'), false, 'synthetic credential must not escape'); }

test('queries and downloads redact complete nested JSONL records', t => {
  const f = fixture(t);
  f.write('panel', 'panel.log', jsonRecord({ jobId: 'job-parent', password: 'fixture-private-password', credentials: { nested: 'fixture-private-nested' }, message: 'Bearer fixture-private-bearer' }));
  const result = queryLogs({}, f.options); assert.equal(result.entries.length, 1); assertSafe(result);
  assert.equal(result.entries[0].jobId, 'job-parent');
  assertSafe(downloadLog(result.files[0].id, f.options));
  for (const key of ['_root', '_rootStat', '_stat', '_path']) assert.equal(Object.hasOwn(result.files[0], key), false);
});
test('register multiline credentials are redacted as a single logical record', t => {
  const f = fixture(t);
  f.write('register', registerName(), record('credentials = {\n"token": "fixture-private-token",\n"password": "fixture-private-password"\n}\nfinished'));
  const result = queryLogs({}, f.options); assert.equal(result.entries.length, 1); assertSafe(result);
  assertSafe(downloadLog(result.files[0].id, f.options));
});
test('a tail entirely inside an oversized credential never exposes its suffix', t => {
  const f = fixture(t);
  f.write('register', registerName(), record('password=' + 'fixture-private-fragment'.repeat(110000)));
  const result = queryLogs({}, f.options); assert.equal(result.entries.length, 0); assertSafe(result);
  const downloaded = downloadLog(result.files[0].id, f.options); assertSafe(downloaded); assert.match(downloaded.content, /省略/);
});
test('tail drops unframed multiline fragments before the next complete record', t => {
  const f = fixture(t);
  f.write('register', registerName(), record('credentials={\n' + 'fixture-private-fragment\n'.repeat(100000) + '}') + record('safe ending'));
  const result = queryLogs({}, f.options); assertSafe(result); assert.equal(result.entries.length, 1); assert.equal(result.entries[0].message, 'safe ending');
});
test('invalid JSONL and incomplete trailing records cannot become raw output', t => {
  const f = fixture(t);
  f.write('panel', 'panel.log', 'fixture-private-unframed\n' + jsonRecord() + '{"password":"fixture-private-incomplete');
  f.write('register', registerName(), record('safe first') + record('password=\nfixture-private-multiline') + 'fixture-private-incomplete');
  const result = queryLogs({}, f.options); assertSafe(result);
  assert.equal(result.entries.filter(entry => entry.source === 'register').length, 1);
  assert.equal(result.entries.some(entry => entry.event === 'log.record_omitted'), true);
  for (const file of result.files) assertSafe(downloadLog(file.id, f.options));
});
test('oversized JSON records are omitted without prefix-only redaction', t => {
  const f = fixture(t); f.write('panel', 'panel.log', jsonRecord({ message: 'fixture-private-'.repeat(5000) }));
  const result = queryLogs({}, f.options); assertSafe(result); assert.equal(result.entries[0].event, 'log.record_omitted');
});
test('job filters accept internal child IDs but never user supplied expansion', t => {
  const f = fixture(t);
  f.write('panel', 'panel.log', ['parent', 'child', 'other'].map(jobId => jsonRecord({ jobId })).join(''));
  assert.equal(queryLogs({ jobId: 'parent', jobIds: ['other'] }, f.options).entries.length, 1);
  const result = queryLogs({ jobId: 'parent' }, { ...f.options, jobIds: ['child'] });
  assert.deepEqual(result.entries.map(entry => entry.jobId).sort(), ['child', 'parent']);
});
test('queries validate bounds and expose deterministic pagination', t => {
  const f = fixture(t); f.write('panel', 'panel.log', jsonRecord({ message: 'first' }) + jsonRecord({ message: 'second', level: 'error' }));
  const first = queryLogs({ limit: 1 }, f.options); assert.equal(first.nextCursor, '1');
  assert.equal(queryLogs({ limit: 1, cursor: first.nextCursor }, f.options).nextCursor, null);
  assert.equal(queryLogs({ level: 'error', q: 'second' }, f.options).entries.length, 1);
  for (const input of [{ limit: 501 }, { limit: 0 }, { limit: 1.5 }, { cursor: '-1' }, { cursor: '10001' }, { source: 'tokens' }, { level: 'fatal' }, { fileId: '../panel.log' }]) assert.throws(() => queryLogs(input, f.options), error => error.code.startsWith('CONSOLE_LOG_'));
});
test('only private regular allowlisted files are listed', t => {
  const f = fixture(t); const safe = f.write('panel', 'panel.log', jsonRecord());
  f.write('panel', 'panel.log.1', jsonRecord()); f.write('panel', 'username.json', 'fixture-private-username');
  fs.symlinkSync(safe, path.join(f.panel, 'panel.log.2'));
  const hard = f.write('panel', 'panel.log.3', jsonRecord()); fs.linkSync(hard, path.join(f.panel, 'unrelated-hardlink'));
  const publicLog = f.write('panel', 'panel.log.4', jsonRecord()); fs.chmodSync(publicLog, 0o644);
  f.write('register', registerName(), record('safe')); f.write('register', 'run-arbitrary.log', 'fixture-private-arbitrary');
  assert.deepEqual(listLogFiles(f.options).map(file => file.name).sort(), ['panel.log', 'panel.log.1', registerName()].sort());
  assert.throws(() => listLogFiles({ ...f.options, panelLogPath: path.join(f.panel, 'username.json') }), { code: 'CONSOLE_LOG_ROOT_INVALID' });
});
test('symlink and writable log directories are rejected', t => {
  const f = fixture(t); fs.renameSync(f.panel, f.panel + '-old'); fs.symlinkSync(f.panel + '-old', f.panel);
  assert.throws(() => listLogFiles(f.options), { code: 'CONSOLE_LOG_UNSAFE' });
  fs.unlinkSync(f.panel); fs.renameSync(f.panel + '-old', f.panel); fs.chmodSync(f.panel, 0o777);
  assert.throws(() => listLogFiles(f.options), { code: 'CONSOLE_LOG_UNSAFE' });
});
test('download validates opaque IDs and refuses oversized files', t => {
  const f = fixture(t); const filename = f.write('panel', 'panel.log', jsonRecord()); fs.truncateSync(filename, 32 * 1024 * 1024 + 1);
  assert.throws(() => downloadLog('../username.json', f.options), { code: 'CONSOLE_LOG_ID_INVALID' });
  assert.throws(() => downloadLog('0'.repeat(32), f.options), { code: 'CONSOLE_LOG_NOT_FOUND' });
  assert.throws(() => downloadLog(listLogFiles(f.options)[0].id, f.options), { code: 'CONSOLE_LOG_TOO_LARGE' });
});
test('cleanup only removes explicitly confirmed old closed allowlisted logs', t => {
  const f = fixture(t); const current = f.write('panel', 'panel.log', jsonRecord(), true);
  const old = f.write('panel', 'panel.log.1', jsonRecord(), true); const oldBytes = fs.statSync(old).size;
  const recent = f.write('panel', 'panel.log.2', jsonRecord()); const unrelated = f.write('panel', 'username.json', 'fixture-private-username', true);
  const retired = f.write('register', registerName(), record('closed'), true); const retiredBytes = fs.statSync(retired).size;
  for (const input of [{ olderThanDays: 7 }, { olderThanDays: 0, confirm: true }, { olderThanDays: 3651, confirm: true }]) assert.throws(() => cleanupLogs(input, f.options), { code: 'CONSOLE_LOG_CLEANUP_INVALID' });
  const result = cleanupLogs({ olderThanDays: 7, confirm: true }, f.options);
  assert.equal(result.removed, 2); assert.equal(result.freedBytes, oldBytes + retiredBytes); assert.equal(result.recoverable, false);
  for (const filename of [current, recent, unrelated]) assert.equal(fs.existsSync(filename), true);
  for (const filename of [old, retired]) assert.equal(fs.existsSync(filename), false);
});
test('external CLI PID protects its log even when panel has no running job', t => {
  const f = fixture(t); const filename = f.write('register', registerName(process.pid), record('running externally'), true);
  const result = cleanupLogs({ olderThanDays: 7, confirm: true }, { ...f.options, registerActive: false });
  assert.equal(result.removed, 0); assert.equal(fs.existsSync(filename), true);
});
test('live or ambiguous registration project locks protect every register log', t => {
  const f = fixture(t); const filename = f.write('register', registerName(), record('old'), true); const lock = path.join(f.register, '.registration.lock');
  for (const content of [JSON.stringify({ pid: process.pid, start: '' }), 'not-json', JSON.stringify({ pid: DEAD_PID })]) {
    fs.writeFileSync(lock, content, { mode: 0o600 });
    assert.equal(cleanupLogs({ olderThanDays: 7, confirm: true }, f.options).removed, 0);
  }
  fs.unlinkSync(lock); fs.mkdirSync(path.join(f.register, '.registration.lock-recovery'), { mode: 0o700 });
  assert.equal(cleanupLogs({ olderThanDays: 7, confirm: true }, f.options).removed, 0); assert.equal(fs.existsSync(filename), true);
});
test('stale registration lock does not prevent confirmed cleanup; panel activity does', t => {
  const f = fixture(t); f.write('register', registerName(), record('old'), true);
  fs.writeFileSync(path.join(f.register, '.registration.lock'), JSON.stringify({ pid: DEAD_PID, start: '' }), { mode: 0o600 });
  assert.equal(cleanupLogs({ olderThanDays: 7, confirm: true }, { ...f.options, registerActive: true }).removed, 0);
  assert.equal(cleanupLogs({ olderThanDays: 7, confirm: true }, f.options).removed, 1);
});
test('read refuses a file inode substituted after enumeration', t => {
  const f = fixture(t); const filename = f.write('panel', 'panel.log', jsonRecord()); let raced = false;
  patch(t, fs, 'openSync', original => function (target, ...args) {
    if (!raced && typeof target === 'string' && target.startsWith('/proc/self/fd/') && target.endsWith('/panel.log')) {
      raced = true; fs.renameSync(filename, filename + '.saved'); fs.writeFileSync(filename, jsonRecord({ password: 'fixture-private-swapped' }), { mode: 0o600 });
    }
    return original.call(this, target, ...args);
  });
  assert.throws(() => queryLogs({}, f.options), { code: 'CONSOLE_LOG_CHANGED' }); assert.equal(raced, true);
});
test('read refuses a log directory replaced after enumeration', t => {
  const f = fixture(t); f.write('panel', 'panel.log', jsonRecord()); let raced = false;
  patch(t, fs, 'openSync', original => function (target, ...args) {
    if (!raced && typeof target === 'string' && target.startsWith('/proc/self/fd/') && target.endsWith('/panel.log')) {
      raced = true; fs.renameSync(f.panel, f.panel + '-original'); fs.mkdirSync(f.panel, { mode: 0o700 });
      fs.writeFileSync(path.join(f.panel, 'panel.log'), jsonRecord({ password: 'fixture-private-swapped' }), { mode: 0o600 });
    }
    return original.call(this, target, ...args);
  });
  assert.throws(() => queryLogs({}, f.options), { code: 'CONSOLE_LOG_CHANGED' }); assert.equal(raced, true);
});
test('cleanup restores a changed inode claimed during a rename race', t => {
  const f = fixture(t); const filename = f.write('panel', 'panel.log.1', jsonRecord(), true); let raced = false;
  patch(t, fs, 'renameSync', original => function (from, to) {
    if (!raced && String(from).endsWith('/panel.log.1') && String(to).includes('.panel-log-cleanup-')) {
      raced = true; original.call(this, filename, filename + '.saved'); fs.writeFileSync(filename, jsonRecord({ message: 'new inode' }), { mode: 0o600 });
    }
    return original.call(this, from, to);
  });
  assert.throws(() => cleanupLogs({ olderThanDays: 7, confirm: true }, f.options), { code: 'CONSOLE_LOG_CHANGED' });
  assert.equal(raced, true); assert.match(fs.readFileSync(filename, 'utf8'), /new inode/);
  assert.equal(fs.readdirSync(f.panel).some(name => name.endsWith('.claim')), false);
});
test('registration starting during a cleanup claim restores the protected log', t => {
  const f = fixture(t); const filename = f.write('register', registerName(), record('old'), true); let raced = false;
  patch(t, fs, 'renameSync', original => function (from, to) {
    const result = original.call(this, from, to);
    if (!raced && String(to).includes('.panel-log-cleanup-')) {
      raced = true; fs.writeFileSync(path.join(f.register, '.registration.lock'), JSON.stringify({ pid: process.pid, start: '' }), { mode: 0o600 });
    }
    return result;
  });
  assert.throws(() => cleanupLogs({ olderThanDays: 7, confirm: true }, f.options), { code: 'CONSOLE_LOG_CHANGED' });
  assert.equal(raced, true); assert.equal(fs.existsSync(filename), true);
});
test('post-delete fsync failure reports unknown durability and forbids automatic retry', t => {
  const f = fixture(t); const filename = f.write('panel', 'panel.log.1', jsonRecord(), true); let deleted = false;
  patch(t, fs, 'unlinkSync', original => function (target) { const result = original.call(this, target); if (String(target).includes('.panel-log-cleanup-')) deleted = true; return result; });
  patch(t, fs, 'fsyncSync', original => function (fd) { if (deleted) throw Object.assign(new Error('fixture sync failure'), { code: 'EIO' }); return original.call(this, fd); });
  assert.throws(() => cleanupLogs({ olderThanDays: 7, confirm: true }, f.options), error => error.writeOutcomeUnknown === true && error.requiresReconciliation === true && error.doNotRetry === true && error.details.removed === 1);
  assert.equal(fs.existsSync(filename), false);
});
test('later cleanup failure preserves the earlier deletion receipt', t => {
  const f = fixture(t); f.write('panel', 'panel.log.1', jsonRecord(), true); f.write('register', registerName(), record('old'), true); let deletions = 0;
  patch(t, fs, 'unlinkSync', original => function (target) {
    const result = original.call(this, target);
    if (String(target).includes('.panel-log-cleanup-') && ++deletions === 1) {
      // Both directories remain pinned-safe for the just-finished deletion,
      // but the next root reopen must notice its original identity is gone.
      const firstIsPanel = fs.existsSync(path.join(f.register, 'logs', registerName()));
      const next = firstIsPanel ? path.join(f.register, 'logs') : f.panel;
      fs.renameSync(next, next + '-original'); fs.mkdirSync(next, { mode: 0o700 });
    }
    return result;
  });
  assert.throws(() => cleanupLogs({ olderThanDays: 7, confirm: true }, f.options), error => error.requiresReconciliation === true && error.doNotRetry === true && error.details.removed === 1 && error.details.freedBytes > 0);
});
test('cleanup retains a claim if restoration would overwrite a new original file', t => {
  const f = fixture(t); const filename = f.write('panel', 'panel.log.1', jsonRecord(), true); let raced = false;
  patch(t, fs, 'renameSync', original => function (from, to) {
    const result = original.call(this, from, to);
    if (!raced && String(to).includes('.panel-log-cleanup-')) {
      raced = true; fs.appendFileSync(to, jsonRecord({ message: 'changed claimed file' }));
      fs.writeFileSync(filename, jsonRecord({ message: 'must not be overwritten' }), { mode: 0o600 });
    }
    return result;
  });
  assert.throws(() => cleanupLogs({ olderThanDays: 7, confirm: true }, f.options), error => error.requiresReconciliation === true && error.details.retainedClaim === true && error.details.removed === 0);
  assert.match(fs.readFileSync(filename, 'utf8'), /must not be overwritten/);
  assert.equal(fs.readdirSync(f.panel).filter(name => name.endsWith('.claim')).length, 1);
});
