'use strict';

// Historical registration failures did not freeze an execution-root binding.
// Only an administrator-created, private, expiring evidence file can bridge
// that gap. It is explicitly reconstructed evidence, never a startup proof.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { assertDirectoryTree, syncDirectory } = require('./lib/safeFs');

const DEFAULT_EVIDENCE_DIRECTORY = '/etc/gpt-register-panel/registration-reconciliation';
const HEX = /^[a-f0-9]{64}$/;
const JOB = /^job_[a-f0-9]{24}$/;
const MAX_BYTES = 32 * 1024 * 1024;
const EXCLUDED = new Set(['requiresReconciliation', 'writeOutcomeUnknown', 'writeOutcomeWasUnknown',
  'futureOperationsUnblocked', 'retryAllowed', 'doNotRetry', 'reconciliationHold', 'reconciliationResolved',
  'reconciliationResolution', 'reconciliationAcknowledgedAt', 'reconciliationAcknowledgedBy',
  'reconciliationReviewedContextDigest', 'reconciliationBlockScope', 'reconciliationBlockScopeWas']);
const failure = () => Object.assign(new Error('注册任务需要服务器端人工证据：请先核验原运行目录、进程、短信订单及费用、本地产物；证据缺失、过期或状态变化时不会解除阻挡'), { code: 'JOB_RECONCILIATION_CONTEXT_UNAVAILABLE' });
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value);
function ensure(condition) { if (!condition) throw failure(); }
function taskFingerprint(job) {
  const result = Object.fromEntries(Object.entries(job.result || {}).filter(([key]) => !EXCLUDED.has(key)));
  return hash(canonical({ id: job.id, type: job.type, status: job.status, payload: job.payload, result }));
}
function chainIds(job) {
  ensure(job && ['registration', 'console_register'].includes(job.type));
  const parent = job.type === 'registration' ? job.payload?.parentJobId : job.id;
  const child = job.type === 'registration' ? job.id : job.result?.childJobIds?.[0];
  ensure(JOB.test(parent || '') && JOB.test(child || '') && parent !== child);
  if (job.type === 'console_register') ensure(job.result.childJobIds.length === 1);
  return [parent, child];
}
function validateChain(jobs) {
  ensure(Array.isArray(jobs) && jobs.length === 2);
  const [parent, child] = jobs;
  ensure(parent.type === 'console_register' && child.type === 'registration');
  ensure(chainIds(parent).join() === [parent.id, child.id].join() && child.payload?.parentJobId === parent.id);
  for (const [job, claim] of [[parent, 'console_pipeline'], [child, 'registration']]) {
    ensure(['failed', 'interrupted'].includes(job.status)
      && job.result?.code === 'REGISTRATION_TERMINATION_UNCONFIRMED'
      && job.reconciliationScope === 'claims' && job.claimKeys?.length === 1 && job.claimKeys[0] === claim
      && HEX.test(job.reconciliationClaimDigest || '')
      && (job.reconciliationHold === true || (job.result.reconciliationResolved === true
        && job.result.reconciliationResolution === 'state_manually_reconciled'
        && job.result.retryAllowed === false && job.result.doNotRetry === true
        && job.result.reconciliationAcknowledgedBy === 'panel-admin'
        && HEX.test(job.result.reconciliationReviewedContextDigest || '')
        && job.result.writeOutcomeUnknown === false && job.result.requiresReconciliation === false)));
  }
  const summaryFields = ['registered', 'imported', 'refreshed', 'deleted', 'skipped', 'failed',
    'tokensGenerated', 'tokensUpdated', 'tested', 'verified', 'testFailed'];
  ensure(parent.result.summary && summaryFields.every(key => parent.result.summary[key] === 0)
    && Object.keys(parent.result.summary).every(key => summaryFields.includes(key))
    && Array.isArray(parent.result.items) && parent.result.items.length === 0);
  return jobs;
}
function readFile(file, max = MAX_BYTES, privateFile = false) {
  let fd;
  try {
    const before = fs.lstatSync(file);
    ensure(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.size <= max);
    if (privateFile) ensure((before.mode & 0o777) === 0o600 && [0, process.getuid?.()].includes(before.uid));
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const opened = fs.fstatSync(fd);
    ensure(opened.dev === before.dev && opened.ino === before.ino);
    const buffer = Buffer.alloc(before.size + 1); let size = 0;
    while (size < buffer.length) {
      const count = fs.readSync(fd, buffer, size, buffer.length - size, null);
      if (!count) break; size += count;
    }
    const bytes = buffer.subarray(0, size);
    const after = fs.fstatSync(fd); const latest = fs.lstatSync(file);
    ensure(bytes.length === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs
      && after.ctimeMs === before.ctimeMs && latest.ino === before.ino && latest.dev === before.dev);
    return bytes;
  } catch { throw failure(); } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function rootBinding(root) {
  const absolute = assertDirectoryTree(path.resolve(root), '注册对账目录');
  const stat = fs.lstatSync(absolute);
  return { path: absolute, device: String(stat.dev), inode: String(stat.ino) };
}
function localSnapshot(root) {
  const binding = rootBinding(root);
  const entries = []; const observed = []; let totalBytes = 0;
  function scan(relative, directory = false, depth = 0) {
    ensure(depth < 32);
    const file = path.join(binding.path, relative);
    let stat;
    try { stat = fs.lstatSync(file); } catch (error) {
      if (error.code === 'ENOENT') { entries.push([relative, 'absent']); observed.push({ file, absent: true }); return; }
      throw failure();
    }
    ensure(!stat.isSymbolicLink());
    if (directory) {
      ensure(stat.isDirectory());
      const names = fs.readdirSync(file).sort(); ensure(names.length <= 10000);
      observed.push({ file, stat, names });
      entries.push([relative, 'directory']);
      for (const name of names) {
        ensure(!name.includes('/') && entries.length < 10000);
        const child = path.join(relative, name); const childStat = fs.lstatSync(path.join(binding.path, child));
        ensure(!childStat.isSymbolicLink());
        scan(child, childStat.isDirectory(), depth + 1);
      }
    } else {
      totalBytes += stat.size; ensure(totalBytes <= 128 * 1024 * 1024);
      entries.push([relative, hash(readFile(file))]);
      observed.push({ file, stat });
    }
  }
  for (const name of ['accounts.json', 'username.json', 'sms-activations.json', 'shibai.json', 'config.json', 'config.panel.json',
    'config.server.json', 'src/config.js', 'index.js', 'src/browserService.js', 'src/stateStore.js']) scan(name);
  // Include every engine replay / panel quarantine boundary. A new pending
  // token manifest is a possible future write even before token files change.
  for (const name of ['tokens', 'use_token', 'shibai', 'state-transactions', 'token-transactions',
    '.token-transactions', '.state-transactions', '.panel-quarantine']) scan(name, true);
  for (const item of observed) {
    if (item.absent) {
      let absent = false; try { fs.lstatSync(item.file); } catch (error) { if (error.code === 'ENOENT') absent = true; else throw failure(); }
      ensure(absent); continue;
    }
    const current = fs.lstatSync(item.file);
    ensure(!current.isSymbolicLink() && current.dev === item.stat.dev && current.ino === item.stat.ino
      && current.size === item.stat.size && current.mtimeMs === item.stat.mtimeMs && current.ctimeMs === item.stat.ctimeMs);
    if (item.names) ensure(canonical(fs.readdirSync(item.file).sort()) === canonical(item.names));
  }
  ensure(canonical(rootBinding(root)) === canonical(binding));
  return { root: binding, digest: hash(canonical(entries)), entries: entries.length };
}
function assertNoRegistrationProcess(root, originalProcess = null, processRoot = '/proc') {
  ensure(process.platform === 'linux');
  const names = fs.readdirSync(processRoot); ensure(names.length <= 65536);
  for (const name of names) {
    if (!/^\d+$/.test(name) || Number(name) === process.pid) continue;
    try {
      const stat = fs.readFileSync(path.join(processRoot, name, 'stat'), 'utf8');
      const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      const state = fields[0];
      if (['Z', 'X'].includes(state)) continue;
      if (originalProcess) ensure(Number(name) !== originalProcess.pid && Number(fields[2]) !== originalProcess.pgid);
      const command = fs.readFileSync(path.join(processRoot, name, 'cmdline')); ensure(command.length <= 1024 * 1024);
      const args = command.toString().split('\0');
      ensure(!args.some(arg => /(?:^|\/)gpt-register-panel-phase3-[A-Za-z0-9_-]+(?:\/|\s|$)/.test(arg)
        || (originalProcess && arg.includes(originalProcess.profile))));
      // Read no process environment and never expose command-line arguments.
      const engine = args.some(arg => /(?:^|\s)--(?:panel-register|panel-resume|phase3|phase2|register)(?:\s|$)/.test(arg));
      const node = /(?:^|\/)node(?:js)?(?:\s|$)/.test(args[0] || '');
      if (!engine && !node) continue;
      ensure(!(engine && args.some(arg => arg.includes(path.join(root, 'index.js')))));
      let cwd;
      try { cwd = fs.realpathSync(path.join(processRoot, name, 'cwd')); } catch (error) {
        if (error.code !== 'ENOENT' || fs.existsSync(path.join(processRoot, name, 'stat'))) throw failure(); continue;
      }
      ensure(!(cwd === root || (engine && args.some(arg => arg === path.join(root, 'index.js')))));
    } catch (error) { if (['ENOENT', 'ESRCH'].includes(error.code)) continue; throw failure(); }
  }
}
function secureEvidenceDirectory(directory) {
  let absolute;
  try { absolute = assertDirectoryTree(directory, '注册人工证据目录'); } catch { throw failure(); }
  let current = absolute;
  while (current !== path.dirname(current)) {
    const stat = fs.lstatSync(current);
    ensure([0, process.getuid?.()].includes(stat.uid) && ((stat.mode & 0o022) === 0 || (stat.mode & 0o1000) !== 0));
    current = path.dirname(current);
  }
  ensure((fs.lstatSync(absolute).mode & 0o777) === 0o700);
  return absolute;
}
function buildRegistrationEvidence({ jobs, rootDirectory, verification, now = Date.now(), processRoot = '/proc' }) {
  validateChain(jobs);
  ensure(verification && verification.originalRoot === 'manually_verified'
    && verification.processTree === 'verified_stopped' && verification.localRecords === 'reviewed_preserved'
    && verification.remoteImport === 'not_reached'
    && ['cancelled', 'completed', 'expired'].includes(verification.smsStatus)
    && ['unknown', 'verified'].includes(verification.smsSettlement)
    && HEX.test(verification.providerEvidenceDigest || '') && HEX.test(verification.originalRunEvidenceDigest || '')
    && HEX.test(verification.orderIdDigest || '')
    && Number.isSafeInteger(verification.originalProcess?.pid) && verification.originalProcess.pid > 1
    && Number.isSafeInteger(verification.originalProcess?.pgid) && verification.originalProcess.pgid > 1
    && /^gpt-register-panel-phase3-[A-Za-z0-9_-]{6,80}$/.test(verification.originalProcess?.profile || ''));
  const snapshot = localSnapshot(rootDirectory); assertNoRegistrationProcess(snapshot.root.path, verification.originalProcess, processRoot);
  return { version: 1, mode: 'manual_reconstructed', evidenceId: crypto.randomBytes(16).toString('hex'),
    checkedAt: new Date(now).toISOString(), expiresAt: new Date(now + 24 * 60 * 60 * 1000).toISOString(),
    jobs: jobs.map(job => ({ id: job.id, type: job.type, fingerprint: taskFingerprint(job), claimDigest: job.reconciliationClaimDigest })),
    root: snapshot.root, localStateDigest: snapshot.digest, localEntryCount: snapshot.entries,
    verification: { originalRoot: verification.originalRoot, processTree: verification.processTree,
      localRecords: verification.localRecords, remoteImport: verification.remoteImport, smsStatus: verification.smsStatus,
      smsSettlement: verification.smsSettlement, providerEvidenceDigest: verification.providerEvidenceDigest,
      originalRunEvidenceDigest: verification.originalRunEvidenceDigest, orderIdDigest: verification.orderIdDigest,
      originalProcess: { pid: verification.originalProcess.pid, pgid: verification.originalProcess.pgid, profile: verification.originalProcess.profile } } };
}
function writeRegistrationEvidence(evidence, directory = DEFAULT_EVIDENCE_DIRECTORY) {
  const dir = secureEvidenceDirectory(directory);
  ensure(evidence?.version === 1 && JOB.test(evidence.jobs?.[0]?.id || ''));
  const file = path.join(dir, evidence.jobs[0].id + '.json'); let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, JSON.stringify(evidence, null, 2) + '\n'); fs.fsyncSync(fd);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  syncDirectory(dir); return file;
}
function registrationReviewContext(job, jobs, { rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register', evidenceDirectory = DEFAULT_EVIDENCE_DIRECTORY, now = Date.now(), processRoot = '/proc' } = {}) {
  validateChain(jobs); const ids = chainIds(job);
  ensure(ids.join() === jobs.map(item => item.id).join());
  const dir = secureEvidenceDirectory(evidenceDirectory);
  const raw = readFile(path.join(dir, ids[0] + '.json'), 64 * 1024, true);
  let evidence; try { evidence = JSON.parse(raw); } catch { throw failure(); }
  const checked = Date.parse(evidence.checkedAt); const expiry = Date.parse(evidence.expiresAt);
  ensure(evidence.version === 1 && evidence.mode === 'manual_reconstructed'
    && /^[a-f0-9]{32}$/.test(evidence.evidenceId || '') && checked <= now && now < expiry
    && expiry - checked <= 24 * 60 * 60 * 1000 && expiry > checked);
  const expected = buildRegistrationEvidence({ jobs, rootDirectory, verification: evidence.verification, now, processRoot });
  ensure(canonical(evidence.jobs) === canonical(expected.jobs) && canonical(evidence.root) === canonical(expected.root)
    && evidence.localStateDigest === expected.localStateDigest && evidence.localEntryCount === expected.localEntryCount);
  return { total: 1, complete: true, targets: [{ kind: 'registration_manual_review', parentJobId: ids[0], childJobId: ids[1],
    evidenceMode: evidence.mode, evidenceId: evidence.evidenceId, evidenceDigest: hash(raw),
    checkedAt: evidence.checkedAt, expiresAt: evidence.expiresAt, rootFingerprint: hash(canonical(evidence.root)),
    localStateDigest: evidence.localStateDigest, processScan: 'stopped', originalRoot: evidence.verification.originalRoot,
    localRecords: evidence.verification.localRecords, remoteImport: evidence.verification.remoteImport,
    smsOrder: 'terminal', smsStatus: evidence.verification.smsStatus, smsSettlement: evidence.verification.smsSettlement }] };
}

async function withRegistrationProjectLock(rootDirectory, callback, { processRoot = '/proc' } = {}) {
  const binding = rootBinding(rootDirectory);
  let rootFd; let lockFd; let published = false;
  const owner = JSON.stringify({ pid: process.pid,
    start: fs.readFileSync('/proc/self/stat', 'utf8').split(') ').at(-1).split(' ')[19],
    nonce: crypto.randomUUID() });
  let lock;
  try {
    rootFd = fs.openSync(binding.path, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(rootFd);
    ensure(String(stat.dev) === binding.device && String(stat.ino) === binding.inode);
    ensure(canonical(rootBinding(rootDirectory)) === canonical(binding));
    const pinned = '/proc/self/fd/' + rootFd;
    ensure(!fs.existsSync(path.join(pinned, '.registration.lock-recovery')));
    lock = path.join(pinned, '.registration.lock');
    try { lockFd = fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600); }
    catch { throw failure(); }
    published = true; fs.writeFileSync(lockFd, owner); fs.fsyncSync(lockFd); fs.closeSync(lockFd); lockFd = undefined;
    fs.fsyncSync(rootFd);
    assertNoRegistrationProcess(binding.path, null, processRoot);
    return await callback();
  } finally {
    if (lockFd !== undefined) fs.closeSync(lockFd);
    try {
      if (published) {
        try { ensure(readFile(lock, 4096).toString() === owner); fs.unlinkSync(lock); fs.fsyncSync(rootFd); }
        catch { throw Object.assign(new Error('注册对账锁释放未确认，请只读检查原确认回执，不要自动重试'), { code: 'CONTROL_PLANE_LOCK_RELEASE_FAILED' }); }
      }
    } finally { if (rootFd !== undefined) fs.closeSync(rootFd); }
  }
}

module.exports = { DEFAULT_EVIDENCE_DIRECTORY, chainIds, validateChain, taskFingerprint,
  localSnapshot, assertNoRegistrationProcess, buildRegistrationEvidence, writeRegistrationEvidence,
  registrationReviewContext, withRegistrationProjectLock };
