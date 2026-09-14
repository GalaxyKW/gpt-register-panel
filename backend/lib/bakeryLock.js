const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PROTOCOL = 'lamport-bakery';
const PROTOCOL_VERSION = 2;
const RELEASE_ATTEMPTS = 3;
const poisonedNamespaces = new Map();

// `lockName` is an immutable namespace marker and is never removed. Each
// acquisition publishes choosing/ticket records at paths containing a fresh
// 128-bit token. Lamport ordering provides mutual exclusion without ever
// unlinking a pathname that a later owner could reuse (the shared-path ABA).

function sameInode(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function lockError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function stableRecord(filePath, options) {
  let pathStat;
  let descriptor;
  try {
    try {
      pathStat = fs.lstatSync(filePath);
    } catch (error) {
      if (error?.code === 'ENOENT') return { state: 'missing' };
      throw error;
    }
    if (pathStat.isSymbolicLink() || !pathStat.isFile()
        || pathStat.size <= 0 || pathStat.size > 4096) {
      throw lockError(options.invalidCode, options.invalidMessage);
    }

    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || !sameInode(before, pathStat)) {
      throw lockError(options.changedCode, options.changedMessage);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    let latest;
    try {
      latest = fs.lstatSync(filePath);
    } catch (error) {
      if (error?.code === 'ENOENT') return { state: 'missing' };
      throw error;
    }
    if (latest.isSymbolicLink() || !latest.isFile()
        || !sameInode(before, after) || !sameInode(after, latest)
        || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs || bytes.length !== after.size) {
      throw lockError(options.changedCode, options.changedMessage);
    }
    let record;
    try {
      record = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw lockError(options.invalidCode, options.invalidMessage);
    }
    return { state: 'present', record, stat: after };
  } catch (error) {
    if (error?.code === 'ENOENT') return { state: 'missing' };
    if (error?.code === 'ELOOP') {
      throw lockError(options.invalidCode, options.invalidMessage);
    }
    throw error;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function unlinkUniquePath(filePath, expectedStat, options) {
  let observed;
  try {
    observed = stableRecord(filePath, options);
  } catch {
    return false;
  }
  if (observed.state === 'missing' || !sameInode(observed.stat, expectedStat)) return false;
  try {
    // This pathname contains a freshly generated 128-bit acquisition token and
    // is never reused by another contender. Unlike a shared lock pathname, a
    // delayed unlink therefore cannot remove a successor's lease.
    fs.unlinkSync(filePath);
    return true;
  } catch {
    return false;
  }
}

function publishImmutableRecord(context, finalName, record) {
  const finalPath = path.join(context.accessDirectory, finalName);
  const candidateName = context.lockName + '.publish-v2-'
    + process.pid + '-' + crypto.randomBytes(16).toString('hex');
  const candidatePath = path.join(context.accessDirectory, candidateName);
  let descriptor;
  let candidateStat;
  try {
    descriptor = fs.openSync(
      candidatePath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    const bytes = Buffer.from(JSON.stringify(record), 'utf8');
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    candidateStat = fs.fstatSync(descriptor);
    const candidatePathStat = fs.lstatSync(candidatePath);
    if (!candidateStat.isFile() || !sameInode(candidateStat, candidatePathStat)
        || candidateStat.size !== bytes.length) {
      throw lockError(context.changedCode, context.changedMessage);
    }
    try {
      fs.linkSync(candidatePath, finalPath);
    } catch (error) {
      if (error?.code === 'EEXIST') return { published: false, finalPath };
      throw error;
    }
    try { fs.fsyncSync(context.directoryDescriptor); } catch {}
    return { published: true, finalPath, stat: candidateStat };
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (candidateStat) unlinkUniquePath(candidatePath, candidateStat, context);
  }
}

function validNamespaceRecord(record, context) {
  return Boolean(record
    && record.kind === context.kind
    && record.protocol === PROTOCOL
    && record.version === PROTOCOL_VERSION
    && record.role === 'namespace');
}

function ensureNamespace(context) {
  const markerPath = path.join(context.accessDirectory, context.lockName);
  let marker = stableRecord(markerPath, context);
  if (marker.state === 'missing') {
    const result = publishImmutableRecord(context, context.lockName, {
      kind: context.kind,
      protocol: PROTOCOL,
      version: PROTOCOL_VERSION,
      role: 'namespace',
    });
    marker = stableRecord(markerPath, context);
    if (result.published && marker.state === 'missing') {
      throw lockError(context.changedCode, context.changedMessage);
    }
  }
  if (marker.state !== 'present' || !validNamespaceRecord(marker.record, context)) {
    throw lockError(context.invalidCode, context.invalidMessage);
  }
  return { markerPath, stat: marker.stat };
}

function validOwnerRecord(record) {
  return Number.isSafeInteger(record?.pid)
    && record.pid > 0
    && (record.processStartId === null || typeof record.processStartId === 'string')
    && (record.processBootId === null
      || (typeof record.processBootId === 'string'
        && /^[a-f0-9-]{36}$/i.test(record.processBootId)))
    && typeof record.createdAt === 'string'
    && Number.isFinite(Date.parse(record.createdAt));
}

function validateLeaseRecord(record, expected, context) {
  const valid = record
    && record.kind === context.kind
    && record.protocol === PROTOCOL
    && record.version === PROTOCOL_VERSION
    && record.role === 'lease'
    && record.phase === expected.phase
    && record.token === expected.token
    && validOwnerRecord(record)
    && (record.phase !== 'ticket'
      || (Number.isSafeInteger(record.ticket) && record.ticket > 0));
  if (!valid) throw lockError(context.invalidCode, context.invalidMessage);
}

function leaseFileName(context, token, phase) {
  return context.lockName + '.lease-v2-' + token + '.' + phase;
}

function scanLeaseEntries(context) {
  const names = fs.readdirSync(context.accessDirectory);
  const prefix = context.lockName + '.lease-v2-';
  const groups = new Map();
  for (const name of names) {
    if (!name.startsWith(prefix)) continue;
    const match = /^([a-f0-9]{32})\.(choosing|ticket)$/i.exec(name.slice(prefix.length));
    if (!match) throw lockError(context.invalidCode, context.invalidMessage);
    const token = match[1].toLowerCase();
    const phase = match[2];
    const entryPath = path.join(context.accessDirectory, name);
    const observed = stableRecord(entryPath, context);
    if (observed.state === 'missing') continue;
    validateLeaseRecord(observed.record, { token, phase }, context);
    let group = groups.get(token);
    if (!group) {
      group = { token, choosing: null, ticket: null };
      groups.set(token, group);
    }
    if (group[phase]) throw lockError(context.invalidCode, context.invalidMessage);
    group[phase] = { ...observed, path: entryPath };
  }

  for (const group of groups.values()) {
    const records = [group.choosing?.record, group.ticket?.record].filter(Boolean);
    if (records.length === 2
        && (records[0].pid !== records[1].pid
          || records[0].processStartId !== records[1].processStartId
          || records[0].processBootId !== records[1].processBootId)) {
      throw lockError(context.invalidCode, context.invalidMessage);
    }
    const record = records[0];
    group.alive = context.isOwnerAlive(
      record.pid,
      record.processStartId,
      record.processBootId,
    );
    if (!group.alive) {
      // Dead contenders cannot resume. Their token paths are globally unique
      // and never reused, so cleanup cannot delete a successor lease even if
      // delayed after observation (the ABA that affected the old shared path).
      removeUniqueLeaseEntry(group.choosing, context);
      removeUniqueLeaseEntry(group.ticket, context);
    }
  }
  return groups;
}

function publishLeaseRecord(context, token, phase, ticket = null) {
  const record = {
    kind: context.kind,
    protocol: PROTOCOL,
    version: PROTOCOL_VERSION,
    role: 'lease',
    phase,
    pid: context.owner.pid,
    processStartId: context.owner.processStartId,
    processBootId: context.owner.processBootId ?? null,
    token,
    createdAt: new Date().toISOString(),
    ...(phase === 'ticket' ? { ticket } : {}),
  };
  const result = publishImmutableRecord(context, leaseFileName(context, token, phase), record);
  if (!result.published) throw lockError(context.changedCode, context.changedMessage);
  const observed = stableRecord(result.finalPath, context);
  if (observed.state !== 'present' || !sameInode(observed.stat, result.stat)) {
    throw lockError(context.changedCode, context.changedMessage);
  }
  validateLeaseRecord(observed.record, { token, phase }, context);
  return { path: result.finalPath, stat: result.stat, record };
}

function removeUniqueLeaseEntry(entry, context) {
  if (!entry?.path || !entry?.stat) return true;
  const removed = unlinkUniquePath(entry.path, entry.stat, context);
  if (removed) {
    try { fs.fsyncSync(context.directoryDescriptor); } catch {}
    return true;
  }
  try {
    return stableRecord(entry.path, context).state === 'missing';
  } catch {
    return false;
  }
}

function hasPriority(leftTicket, leftToken, rightTicket, rightToken) {
  return leftTicket < rightTicket
    || (leftTicket === rightTicket && leftToken < rightToken);
}

async function sleep(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function retryChanged(context, startedAt, callback) {
  while (true) {
    try {
      return callback();
    } catch (error) {
      if (error?.code !== context.changedCode) throw error;
      if (Date.now() - startedAt >= context.timeoutMs) throw error;
      await sleep(context.pollMs);
    }
  }
}

function normalizeContext(options) {
  if (!Number.isInteger(options?.directoryDescriptor) || options.directoryDescriptor < 0) {
    throw new TypeError('directoryDescriptor is required');
  }
  if (!options.accessDirectory || !options.lockName || !options.kind
      || typeof options.isOwnerAlive !== 'function') {
    throw new TypeError('incomplete bakery lock options');
  }
  const directory = fs.fstatSync(options.directoryDescriptor);
  const namespaceKey = [directory.dev, directory.ino, options.kind, options.lockName].join(':');
  return {
    ...options,
    namespaceKey,
    invalidCode: options.invalidCode || 'LOCK_PATH_INVALID',
    changedCode: options.changedCode || 'LOCK_CHANGED',
    timeoutCode: options.timeoutCode || 'LOCK_TIMEOUT',
    releaseCode: options.releaseCode || 'LOCK_RELEASE_FAILED',
    invalidMessage: options.invalidMessage || '锁命名空间无效',
    changedMessage: options.changedMessage || '锁文件在操作期间发生变化',
    timeoutMessage: options.timeoutMessage || '等待全局锁超时',
    releaseMessage: options.releaseMessage || '锁租约释放失败，当前进程拒绝继续使用该锁命名空间',
    timeoutMs: Math.max(1, Number(options.timeoutMs) || 30000),
    pollMs: Math.max(1, Number(options.pollMs) || 25),
  };
}

function namespacePoison(context, token) {
  let tokens = poisonedNamespaces.get(context.namespaceKey);
  if (!tokens) {
    tokens = new Set();
    poisonedNamespaces.set(context.namespaceKey, tokens);
  }
  tokens.add(token);
}

function clearNamespacePoison(context, token) {
  const tokens = poisonedNamespaces.get(context.namespaceKey);
  if (!tokens) return;
  tokens.delete(token);
  if (tokens.size === 0) poisonedNamespaces.delete(context.namespaceKey);
}

function assertNamespaceHealthy(context) {
  if (!poisonedNamespaces.has(context.namespaceKey)) return;
  throw lockError(context.releaseCode, context.releaseMessage);
}

function removeLeaseEntries(entries, context, token) {
  const presentEntries = entries.filter(Boolean);
  if (presentEntries.length === 0) return;
  for (let attempt = 0; attempt < RELEASE_ATTEMPTS; attempt += 1) {
    let removed = true;
    for (const entry of presentEntries) {
      if (!removeUniqueLeaseEntry(entry, context)) removed = false;
    }
    if (removed) {
      clearNamespacePoison(context, token);
      return;
    }
  }
  namespacePoison(context, token);
  throw lockError(context.releaseCode, context.releaseMessage);
}

async function acquireBakeryLease(options) {
  const context = normalizeContext(options);
  assertNamespaceHealthy(context);
  const token = crypto.randomBytes(16).toString('hex');
  const startedAt = Date.now();
  let choosing = null;
  let ticketEntry = null;
  try {
    await retryChanged(context, startedAt, () => ensureNamespace(context));
    choosing = publishLeaseRecord(context, token, 'choosing');
    const initialEntries = await retryChanged(context, startedAt, () => scanLeaseEntries(context));
    const ownChoosing = initialEntries.get(token)?.choosing;
    if (!ownChoosing || !sameInode(ownChoosing.stat, choosing.stat)) {
      throw lockError(context.changedCode, context.changedMessage);
    }
    let maximumTicket = 0;
    for (const group of initialEntries.values()) {
      if (group.alive && group.ticket) {
        maximumTicket = Math.max(maximumTicket, group.ticket.record.ticket);
      }
    }
    if (!Number.isSafeInteger(maximumTicket) || maximumTicket >= Number.MAX_SAFE_INTEGER) {
      throw lockError(context.invalidCode, context.invalidMessage);
    }
    const ticket = maximumTicket + 1;
    ticketEntry = publishLeaseRecord(context, token, 'ticket', ticket);
    if (!removeUniqueLeaseEntry(choosing, context)) {
      throw lockError(context.changedCode, context.changedMessage);
    }
    choosing = null;

    while (true) {
      const entries = await retryChanged(context, startedAt, () => scanLeaseEntries(context));
      const ownTicket = entries.get(token)?.ticket;
      if (!ownTicket || !sameInode(ownTicket.stat, ticketEntry.stat)
          || ownTicket.record.ticket !== ticket) {
        throw lockError(context.changedCode, context.changedMessage);
      }
      let blocked = false;
      for (const [otherToken, group] of entries.entries()) {
        if (otherToken === token || !group.alive) continue;
        if (group.choosing) {
          blocked = true;
          break;
        }
        if (group.ticket && hasPriority(
          group.ticket.record.ticket,
          otherToken,
          ticket,
          token,
        )) {
          blocked = true;
          break;
        }
      }
      if (!blocked) {
        return {
          token,
          ticket,
          ticketPath: ticketEntry.path,
          ticketStat: ticketEntry.stat,
          namespacePath: path.join(context.accessDirectory, context.lockName),
          context,
        };
      }
      if (Date.now() - startedAt >= context.timeoutMs) {
        throw lockError(context.timeoutCode, context.timeoutMessage);
      }
      await sleep(context.pollMs);
    }
  } catch (error) {
    try {
      removeLeaseEntries([ticketEntry, choosing], context, token);
    } catch (releaseError) {
      releaseError.cause = error;
      throw releaseError;
    }
    throw error;
  }
}

function releaseBakeryLease(lease) {
  if (!lease?.context || !lease?.ticketPath || !lease?.ticketStat) return;
  removeLeaseEntries(
    [{ path: lease.ticketPath, stat: lease.ticketStat }],
    lease.context,
    lease.token,
  );
}

module.exports = {
  PROTOCOL,
  PROTOCOL_VERSION,
  acquireBakeryLease,
  releaseBakeryLease,
};
