'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { redactText, redactValue } = require('./logger');
const { assertDirectoryTree, syncDirectory } = require('./lib/safeFs');
const { openRootDirectory, closeDirectoryHandle } = require('./adapters/gptRegisterFs');

const MAX_FILES = 2000, MAX_SCAN = 10000, READ_BYTES = 2 * 1024 * 1024;
const DOWNLOAD_BYTES = 32 * 1024 * 1024, MAX_RECORD_BYTES = 64 * 1024;
const REGISTER_HEADER = /^\[(\d{4}-\d{2}-\d{2}T[^\]\r\n]{1,40})\]\s*\[([A-Z]{1,12})\]\s?(.*)$/;
const READ_FLAGS = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
function logError(code, message, fields) { return Object.assign(new Error(message), { code, ...fields }); }
function roots(options = {}) {
  const panel = path.resolve(options.panelLogPath || process.env.PANEL_LOG_PATH
    || path.join(path.dirname(process.env.PANEL_DB_PATH || '/tmp/gpt-register-panel/panel.sqlite3'), 'panel.log'));
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:log|jsonl)$/.test(path.basename(panel))) throw logError('CONSOLE_LOG_ROOT_INVALID', '面板日志文件名必须使用 log/jsonl 后缀');
  const registerRoot = path.resolve(options.rootDirectory || process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register');
  return [{ source: 'panel', directory: path.dirname(panel), base: path.basename(panel) },
    { source: 'register', directory: path.join(registerRoot, 'logs'), registerRoot }];
}
function allowedName(root, name) {
  return root.source === 'panel'
    ? name === root.base || (name.startsWith(root.base + '.') && /^\d{1,3}$/.test(name.slice(root.base.length + 1)))
    : /^run-\d{8}T\d{9}Z-[1-9]\d{0,11}\.log$/.test(name);
}
function privateFile(stat) {
  return stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1
    && (typeof process.getuid !== 'function' || stat.uid === process.getuid()) && (stat.mode & 0o077) === 0;
}
function privateDirectory(stat) {
  return stat.isDirectory() && !stat.isSymbolicLink()
    && (typeof process.getuid !== 'function' || stat.uid === process.getuid()) && (stat.mode & 0o022) === 0;
}
function sameIdentity(left, right) { return left?.dev === right?.dev && left?.ino === right?.ino; }
function stableFile(left, right) { return privateFile(right) && sameIdentity(left, right) && left.size === right.size && left.mtimeMs === right.mtimeMs; }
function openLogRoot(root, expected) {
  try { fs.lstatSync(root.directory); } catch (error) { if (error.code === 'ENOENT' && !expected) return null; throw logError('CONSOLE_LOG_CHANGED', '日志目录已变化，请刷新'); }
  let handle;
  try {
    handle = openRootDirectory(root.directory, '日志目录');
    if (!privateDirectory(handle.stat) || (expected && !sameIdentity(handle.stat, expected))) throw new Error();
    return handle;
  } catch { closeDirectoryHandle(handle); throw logError('CONSOLE_LOG_UNSAFE', '日志目录不安全或已被替换'); }
}
function assertRootCurrent(root, handle) {
  try {
    assertDirectoryTree(root.directory, '日志目录');
    const current = fs.lstatSync(root.directory);
    if (!privateDirectory(current) || !sameIdentity(current, handle.stat)) throw new Error();
  } catch { throw logError('CONSOLE_LOG_CHANGED', '日志目录已变化，请刷新'); }
}
function processAlive(pid, expectedStart = '') {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 0x7fffffff) return true;
  try { process.kill(pid, 0); } catch (error) { return error.code !== 'ESRCH'; }
  if (!expectedStart) return true;
  try {
    const text = fs.readFileSync('/proc/' + pid + '/stat', 'utf8');
    const fields = text.slice(text.lastIndexOf(')') + 2).trim().split(/\s+/);
    return !fields[19] || fields[19] === expectedStart;
  } catch { return true; }
}
function externalRegistrationActive(root) {
  let handle, fd;
  try {
    handle = openRootDirectory(root.registerRoot, 'GPT_REGISTER_ROOT');
    try { fs.lstatSync(path.join(handle.traversalPath, '.registration.lock-recovery')); return true; } catch (error) { if (error.code !== 'ENOENT') return true; }
    try { fd = fs.openSync(path.join(handle.traversalPath, '.registration.lock'), READ_FLAGS); } catch (error) { return error.code !== 'ENOENT'; }
    const stat = fs.fstatSync(fd);
    if (!privateFile(stat) || stat.size > 16384) return true;
    const bytes = Buffer.alloc(stat.size); let offset = 0;
    while (offset < bytes.length) { const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset); if (!count) return true; offset += count; }
    if (!stableFile(stat, fs.fstatSync(fd)) || !stableFile(stat, fs.lstatSync(path.join(handle.traversalPath, '.registration.lock')))) return true;
    const owner = JSON.parse(bytes.toString('utf8'));
    if (!Number.isSafeInteger(owner?.pid) || typeof owner.start !== 'string' || !/^\d*$/.test(owner.start)) return true;
    return processAlive(owner.pid, owner.start);
  } catch { return true; }
  finally { if (fd !== undefined) fs.closeSync(fd); closeDirectoryHandle(handle); }
}
function activeLog(root, name, options = {}, registerBusy) {
  if (root.source === 'panel') return name === root.base;
  if (options.registerActive === true || (registerBusy === undefined ? externalRegistrationActive(root) : registerBusy)) return true;
  return processAlive(Number(name.match(/-(\d+)\.log$/)?.[1]));
}
function listLogFiles(options = {}) {
  const files = [];
  for (const root of roots(options)) {
    const handle = openLogRoot(root); if (!handle) continue;
    let directory;
    try {
      directory = fs.opendirSync(handle.traversalPath);
      const registerBusy = root.source === 'register' && externalRegistrationActive(root);
      let entry, seen = 0;
      while ((entry = directory.readSync())) {
        if (++seen > MAX_SCAN) throw logError('CONSOLE_LOG_LIMIT', '日志目录条目过多，请先归档');
        if (!allowedName(root, entry.name)) continue;
        let stat; try { stat = fs.lstatSync(path.join(handle.traversalPath, entry.name)); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
        if (!privateFile(stat)) continue;
        if (files.length >= MAX_FILES) throw logError('CONSOLE_LOG_LIMIT', '日志文件过多，请先归档');
        const id = crypto.createHash('sha256').update(root.source + '\0' + entry.name).digest('hex').slice(0, 32);
        files.push({ id, source: root.source, name: entry.name, bytes: stat.size, modifiedAt: stat.mtime.toISOString(),
          active: activeLog(root, entry.name, options, registerBusy), _root: root, _rootStat: handle.stat, _stat: stat });
      }
      assertRootCurrent(root, handle);
    } finally { directory?.closeSync(); closeDirectoryHandle(handle); }
  }
  return files.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt) || a.id.localeCompare(b.id));
}
function publicFile({ _root, _rootStat, _stat, ...file }) { return file; }
function readLog(file, maximum = READ_BYTES, entire = false) {
  const root = openLogRoot(file._root, file._rootStat); let descriptor;
  try {
    const filename = path.join(root.traversalPath, file.name);
    descriptor = fs.openSync(filename, READ_FLAGS); const stat = fs.fstatSync(descriptor);
    if (!privateFile(stat) || !sameIdentity(stat, file._stat)) throw logError('CONSOLE_LOG_CHANGED', '日志文件已变化，请刷新');
    if (entire && stat.size > maximum) throw logError('CONSOLE_LOG_TOO_LARGE', '日志超过下载大小上限，请按轮转文件下载');
    const length = Math.min(stat.size, maximum), buffer = Buffer.alloc(length); let read = 0;
    while (read < length) { const n = fs.readSync(descriptor, buffer, read, length - read, stat.size - length + read); if (!n) break; read += n; }
    assertRootCurrent(file._root, root);
    const current = fs.lstatSync(filename), opened = fs.fstatSync(descriptor);
    if (!privateFile(current) || !privateFile(opened) || !sameIdentity(stat, current) || !sameIdentity(stat, opened) || opened.size < stat.size
      || (opened.size === stat.size && opened.mtimeMs !== stat.mtimeMs) || read !== length) throw logError('CONSOLE_LOG_CHANGED', '读取期间日志发生替换或截断，请刷新');
    let text = buffer.toString('utf8'); const truncatedStart = stat.size > length;
    if (truncatedStart) {
      // A secret whose label was outside the tail cannot be safely redacted.
      const newline = text.indexOf('\n'); text = newline < 0 ? '' : text.slice(newline + 1);
    }
    const incompleteEnd = text !== '' && !text.endsWith('\n');
    if (incompleteEnd) text = text.slice(0, text.lastIndexOf('\n') + 1);
    return { text, truncatedStart, incompleteEnd };
  } catch (error) { if (/^CONSOLE_LOG_/.test(error?.code || '')) throw error; throw logError('CONSOLE_LOG_CHANGED', '日志文件不可读取或已变化，请刷新'); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); closeDirectoryHandle(root); }
}
function safeRecords(read, file) {
  const records = []; let group = null;
  const flush = () => { if (group) records.push(group); group = null; };
  for (const line of read.text.split('\n')) {
    if (!line && !group) continue;
    if (file.source === 'panel') {
      if (!line.trim()) continue;
      // JSONL corruption must not become an unlabelled-secret output channel.
      if (Buffer.byteLength(line) > MAX_RECORD_BYTES) { records.push({ omitted: true }); continue; }
      let value; try { value = JSON.parse(line); } catch { records.push({ omitted: true }); continue; }
      records.push(value && typeof value === 'object' && !Array.isArray(value) ? { json: value } : { omitted: true });
      continue;
    }
    const match = REGISTER_HEADER.exec(line);
    if (match && Number.isFinite(Date.parse(match[1]))) { flush(); group = { time: match[1], level: match[2], message: match[3], bytes: Buffer.byteLength(line) }; }
    else if (group) { group.bytes += Buffer.byteLength(line) + 1; if (group.bytes <= MAX_RECORD_BYTES) group.message += '\n' + line; }
    // Unframed prefixes may be a multiline credential cut away from its label.
  }
  if (!read.incompleteEnd) flush();
  return records;
}
function lineEntry(record, file, index) {
  if (record.omitted || record.bytes > MAX_RECORD_BYTES) return { time: file.modifiedAt, level: 'warn', source: file.source, fileId: file.id, jobId: null, event: 'log.record_omitted', message: '[不完整、过大或无效日志记录已省略]', index };
  if (record.json) {
    const safe = redactValue(record.json), level = String(safe.level || 'info').toLowerCase(), timestamp = safe.time || safe.timestamp || safe.ts;
    return { time: typeof timestamp === 'string' && Number.isFinite(Date.parse(timestamp)) ? timestamp : file.modifiedAt,
      level: ['debug', 'info', 'warn', 'error'].includes(level) ? level : 'info', source: file.source, fileId: file.id,
      jobId: typeof safe.jobId === 'string' ? safe.jobId : null, event: typeof safe.event === 'string' ? safe.event : 'log',
      message: redactText(JSON.stringify(safe)), index };
  }
  return { time: record.time, level: ['ERROR', 'WARN', 'DEBUG'].includes(record.level) ? record.level.toLowerCase() : 'info',
    source: file.source, fileId: file.id, jobId: null, event: 'register.output', message: redactText(record.message).trimEnd(), index };
}
function queryLogs(query = {}, options = {}) {
  const files = listLogFiles(options), limit = query.limit === undefined ? 100 : Number(query.limit);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw logError('CONSOLE_LOG_LIMIT_INVALID', '日志页大小必须为 1–500 的整数');
  const offset = query.cursor ? Number(query.cursor) : 0;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000) throw logError('CONSOLE_LOG_CURSOR_INVALID', '日志分页位置无效');
  const source = String(query.source || '');
  if (source && !['panel', 'register'].includes(source)) throw logError('CONSOLE_LOG_SOURCE_INVALID', '日志来源无效');
  if (query.level && !['debug', 'info', 'warn', 'error'].includes(query.level)) throw logError('CONSOLE_LOG_LEVEL_INVALID', '日志级别无效');
  if (query.fileId && !/^[a-f0-9]{32}$/.test(query.fileId)) throw logError('CONSOLE_LOG_ID_INVALID', '日志文件编号无效');
  const q = String(query.q || '').slice(0, 200).toLowerCase(), entries = [];
  const jobIds = new Set([String(query.jobId || ''), ...(Array.isArray(options.jobIds) ? options.jobIds.filter(id => typeof id === 'string').slice(0, 4000) : [])]);
  const selected = files.filter(f => (!source || f.source === source) && (!query.fileId || f.id === query.fileId)).slice(0, 8);
  for (const file of selected) {
    const records = safeRecords(readLog(file), file);
    for (let i = records.length - 1; i >= 0; i -= 1) {
      const entry = lineEntry(records[i], file, i);
      if ((!query.level || entry.level === query.level) && (!query.jobId || jobIds.has(entry.jobId)) && (!q || entry.message.toLowerCase().includes(q))) entries.push(entry);
      if (entries.length >= 20000) break;
    }
    if (entries.length >= 20000) break;
  }
  entries.sort((a, b) => String(b.time).localeCompare(String(a.time)) || b.index - a.index);
  return { entries: entries.slice(offset, offset + limit).map(({ index, ...entry }) => entry),
    nextCursor: offset + limit < entries.length && offset + limit <= 10000 ? String(offset + limit) : null,
    files: files.map(publicFile), totalBytes: files.reduce((n, f) => n + f.bytes, 0), boundedSearch: true };
}
function downloadLog(fileId, options = {}) {
  if (typeof fileId !== 'string' || !/^[a-f0-9]{32}$/.test(fileId)) throw logError('CONSOLE_LOG_ID_INVALID', '日志文件编号无效');
  const file = listLogFiles(options).find(f => f.id === fileId);
  if (!file) throw logError('CONSOLE_LOG_NOT_FOUND', '日志文件不存在');
  const records = safeRecords(readLog(file, DOWNLOAD_BYTES, true), file);
  return { name: file.name, content: records.map((record, index) => {
    const entry = lineEntry(record, file, index);
    return file.source === 'panel' ? entry.message : '[' + entry.time + '] [' + entry.level.toUpperCase() + '] ' + entry.message;
  }).join('\n') + (records.length ? '\n' : '') };
}
function restoreClaim(root, original, claim, expected) {
  const current = fs.lstatSync(claim); if (!stableFile(expected, current)) return false;
  try { fs.linkSync(claim, original); } catch { return false; }
  if (!sameIdentity(current, fs.lstatSync(original))) return false;
  fs.unlinkSync(claim); syncDirectory(root.traversalPath); return true;
}
function cleanupLogs({ olderThanDays, confirm } = {}, options = {}) {
  if (confirm !== true || !Number.isInteger(olderThanDays) || olderThanDays < 1 || olderThanDays > 3650) throw logError('CONSOLE_LOG_CLEANUP_INVALID', '请确认清理范围，保留天数必须为 1–3650');
  const before = Date.now() - olderThanDays * 86400000, files = listLogFiles(options), removed = [];
  let freedBytes = 0, protectedCount = 0;
  for (const file of files) {
    if (file.active || file._stat.mtimeMs >= before) { protectedCount += 1; continue; }
    let root, claim, deleted = false;
    try {
      root = openLogRoot(file._root, file._rootStat);
      assertRootCurrent(file._root, root); const original = path.join(root.traversalPath, file.name);
      let stat; try { stat = fs.lstatSync(original); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      if (!stableFile(file._stat, stat) || activeLog(file._root, file.name, options)) { protectedCount += 1; continue; }
      claim = path.join(root.traversalPath, '.panel-log-cleanup-' + crypto.randomBytes(16).toString('hex') + '.claim');
      fs.renameSync(original, claim); const claimedStat = fs.lstatSync(claim);
      // A claim can race rotation: validate the claimed inode before deletion.
      if (!stableFile(file._stat, claimedStat) || activeLog(file._root, file.name, options)) {
        const restored = restoreClaim(root, original, claim, claimedStat); if (restored) claim = null;
        throw logError('CONSOLE_LOG_CHANGED', restored ? '清理期间日志变化，已恢复文件，请刷新' : '清理期间日志变化，已保留隔离文件，请人工核对', { recoverable: true, requiresReconciliation: !restored });
      }
      assertRootCurrent(file._root, root); syncDirectory(root.traversalPath);
      if (!stableFile(claimedStat, fs.lstatSync(claim))) throw logError('CONSOLE_LOG_CHANGED', '隔离日志在删除前变化，已保留供核对', { recoverable: true, requiresReconciliation: true });
      fs.unlinkSync(claim); deleted = true; claim = null;
      removed.push(file.id); freedBytes += stat.size; syncDirectory(root.traversalPath);
    } catch (error) {
      if (removed.length || claim) Object.assign(error, { writeOutcomeUnknown: deleted, requiresReconciliation: true, doNotRetry: true,
        details: { removed: removed.length, freedBytes, retainedClaim: Boolean(claim), recoverable: Boolean(claim) } });
      throw error;
    } finally { closeDirectoryHandle(root); }
  }
  return { removed: removed.length, freedBytes, protected: protectedCount, recoverable: false };
}
module.exports = { listLogFiles, queryLogs, downloadLog, cleanupLogs };
