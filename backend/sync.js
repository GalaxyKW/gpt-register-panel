const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { readGptRegisterSources, toSafeSources } = require('./adapters/gptRegisterFs');
const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const { buildDiff, toSafeDiff, isExpired } = require('./diff');
const {
  buildRows,
  filterRows,
  statusOptions,
  diffOptions,
  availabilityOptions,
} = require('./view');
const { getAccountAvailability } = require('./accountAvailability');
const { redactText } = require('./logger');

let syncQueue = Promise.resolve();

function safeErrorMessage(error) {
  return redactText(String(error?.message || error || 'unknown error')).slice(0, 1000);
}

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Logging must never change the outcome of a sync operation.
  }
}

function withSyncLock(callback) {
  const run = syncQueue.then(callback);
  syncQueue = run.catch(() => {});
  return run;
}

function configuredForSub2Api() {
  return Boolean(
    process.env.SUB2API_BASE_URL
      && (process.env.SUB2API_ADMIN_API_KEY || process.env.SUB2API_JWT),
  );
}

function safeVersionInput(snapshot) {
  return {
    tokens: snapshot.sources.tokens.map((token) => ({
      source: token.source,
      relativePath: token.relativePath,
      mtimeMs: token.mtimeMs,
      parseStatus: token.parseStatus,
      identityKeys: token.identityKeys,
      fingerprints: token.fingerprints,
    })),
    accounts: snapshot.accounts.map((account) => ({
      id: account.id,
      name: account.name,
      status: account.status,
      schedulable: account.schedulable,
      tempUnschedulableUntil: account.tempUnschedulableUntil,
      identityKeys: account.identityKeys,
      tokenFingerprints: account.tokenFingerprints,
    })),
  };
}

function snapshotVersion(snapshot) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(safeVersionInput(snapshot)))
    .digest('hex');
}

function normalizeAccountUsage(account) {
  if (!account?.usage || typeof account.usage !== 'object') return null;
  if (account.usage.historical || account.usage.current) return account.usage;
  return {
    historical: account.usage,
    current: null,
    currentWindowStart: null,
    currentWindowEnd: null,
  };
}

function safeAccountForSnapshot(account) {
  return {
    id: account.id,
    name: account.name,
    platform: account.platform,
    type: account.type,
    status: account.status,
    schedulable: account.schedulable,
    tempUnschedulableUntil: account.tempUnschedulableUntil,
    tempUnschedulableReason: account.tempUnschedulableReason || null,
    errorMessage: account.errorMessage || null,
    email: account.email,
    accountId: account.accountId,
    userId: account.userId,
    expiresAt: account.expiresAt,
    tokenFingerprints: account.tokenFingerprints,
    groupIds: account.groupIds,
    usage: account.usage || null,
    usageError: account.usageError || null,
  };
}

async function readSub2ApiAccounts(client) {
  const accounts = await client.listAccounts({
    platform: 'openai',
    type: 'oauth',
    pageSize: 200,
  });
  let statsError = null;
  const ids = accounts.map((account) => account.id).filter((id) => Number.isFinite(id) && id > 0);
  if (ids.length > 0) {
    try {
      const tableStats = await client.getBatchTableUsageStats(ids);
      for (const account of accounts) {
        account.usage = tableStats.stats[String(account.id)] || normalizeAccountUsage(account);
        if (tableStats.errors?.[String(account.id)]) account.usageError = tableStats.errors[String(account.id)];
      }
    } catch (error) {
      statsError = safeErrorMessage(error);
      for (const account of accounts) account.usage = normalizeAccountUsage(account);
    }
  }
  return { accounts, statsError };
}

async function buildSnapshot(query = new URLSearchParams(), options = {}) {
  const startedAt = Date.now();
  const logger = options.logger;
  const logContext = {
    requestId: options.requestId || null,
    jobId: options.jobId || null,
    actor: options.actor || null,
  };
  const shouldReadSub2Api = options.readSub2Api !== false
    && (query.get('withSub2api') === '1' || configuredForSub2Api());
  writeLog(logger, 'info', 'snapshot.started', {
    ...logContext,
    withSub2api: shouldReadSub2Api,
    includeRaw: options.includeRaw === true,
  });
  try {
    const sources = readGptRegisterSources({
      includeRaw: options.includeRaw === true,
      rootDirectory: options.rootDirectory,
    });
    let accounts = [];
    let apiError = null;
    let statsError = null;

    if (shouldReadSub2Api) {
      try {
        const client = options.client || new Sub2ApiAdminClient({ logger, logContext });
        const loaded = await readSub2ApiAccounts(client);
        accounts = loaded.accounts;
        statsError = loaded.statsError;
      } catch (error) {
        apiError = safeErrorMessage(error);
        writeLog(logger, 'warn', 'snapshot.sub2api_failed', { ...logContext, error: apiError });
      }
    }

    const internal = {
      generatedAt: sources.generatedAt,
      sources,
      accounts,
    };
    const diff = buildDiff(sources.tokens, accounts);
    const allRows = buildRows(diff);
    const rows = filterRows(allRows, {
      search: query.get('search'),
      status: query.get('status'),
      source: query.get('source'),
      diffKind: query.get('diff'),
      availability: query.get('availability'),
    });
    const version = snapshotVersion(internal);
    const result = {
      readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
      generatedAt: sources.generatedAt,
      version,
      sources: toSafeSources(sources),
      sub2api: {
        accountCount: accounts.length,
        apiError,
        statsError,
        statsAvailable: accounts.some((account) => account.usage?.historical || account.usage?.current),
        accounts: accounts.map(safeAccountForSnapshot),
      },
      diff: toSafeDiff(diff),
      rows,
      filters: {
        statuses: statusOptions(allRows),
        sources: ['tokens', 'use_token', 'sub2api'],
        diffKinds: diffOptions(allRows),
        availabilities: availabilityOptions(allRows),
      },
      _internal: options.includeInternal === true ? internal : undefined,
    };
    writeLog(logger, 'info', 'snapshot.completed', {
      ...logContext,
      version,
      durationMs: Date.now() - startedAt,
      tokenCount: sources.summary.tokenCount,
      validTokenCount: sources.summary.validTokenCount,
      accountCount: accounts.length,
      rowCount: rows.length,
      diffCounts: diff.counts,
      apiError,
      statsError,
    });
    return result;
  } catch (error) {
    writeLog(logger, 'error', 'snapshot.failed', {
      ...logContext,
      durationMs: Date.now() - startedAt,
      error: safeErrorMessage(error),
    });
    throw error;
  }
}

function primaryIdentity(record) {
  return record?.identityKeys?.[0] || 'file:' + String(record?.source || '') + ':' + String(record?.relativePath || record?.fileName || '');
}

function candidateKey(record) {
  return 'token:' + String(record.source) + ':' + String(record.relativePath || record.fileName);
}

function collectCandidates(sources) {
  const groups = new Map();
  for (const record of sources.tokens || []) {
    if (record.parseStatus !== 'ok' || !record.raw) continue;
    const key = primaryIdentity(record);
    const list = groups.get(key) || [];
    list.push(record);
    groups.set(key, list);
  }
  return [...groups.entries()].map(([identityKey, records]) => {
    records.sort((left, right) => {
      if (right.mtimeMs !== left.mtimeMs) return right.mtimeMs - left.mtimeMs;
      return String(left.relativePath).localeCompare(String(right.relativePath), 'en', { numeric: true });
    });
    const selected = records[0];
    const fingerprints = records.map((record) => record.fingerprints?.access).filter(Boolean);
    return {
      key: candidateKey(selected),
      identityKey,
      record: selected,
      duplicates: records.length > 1,
      conflictingVersions: new Set(fingerprints).size > 1,
      records,
    };
  }).sort((left, right) => String(left.record.relativePath).localeCompare(String(right.record.relativePath), 'en', { numeric: true }));
}

function accountMatches(candidate, accounts) {
  const matches = new Map();
  for (const key of candidate.record.identityKeys || []) {
    for (const account of accounts) {
      if ((account.identityKeys || []).includes(key)) matches.set(String(account.id), account);
    }
  }
  return [...matches.values()];
}

function nextFreeNumber(accounts) {
  let maximum = 0;
  for (const account of accounts) {
    const match = /^free(\d+)$/i.exec(String(account.name || '').trim());
    if (match) maximum = Math.max(maximum, Number(match[1]));
  }
  return maximum + 1;
}

function freeName(number) {
  return 'free' + String(number).padStart(5, '0');
}

function selectedCandidate(candidate, selectedKeys, account = null) {
  if (!Array.isArray(selectedKeys) || selectedKeys.length === 0) return true;
  const keys = new Set(selectedKeys.map((key) => String(key)));
  if (keys.has(candidate.key) || keys.has(candidate.identityKey)) return true;
  if (account && keys.has('account:' + String(account.id))) return true;
  return candidate.records.some((record) => keys.has(candidateKey(record)));
}

function dateMilliseconds(value) {
  const timestamp = Date.parse(String(value || ''));
  return Number.isFinite(timestamp) ? timestamp : Number.NEGATIVE_INFINITY;
}

// A single Sub2API account can have both a freshly refreshed token in
// `tokens` and an older copy in `use_token`. Importing both in sequence makes
// the older copy win. Pick one deterministic winner before writing anything.
function compareCandidateFreshness(left, right, nowMs) {
  const leftRecord = left.record;
  const rightRecord = right.record;
  const leftExpired = isExpired(leftRecord, nowMs);
  const rightExpired = isExpired(rightRecord, nowMs);
  if (leftExpired !== rightExpired) return leftExpired ? 1 : -1;

  for (const field of ['expiresAt', 'lastRefresh']) {
    const leftValue = dateMilliseconds(leftRecord[field]);
    const rightValue = dateMilliseconds(rightRecord[field]);
    if (leftValue !== rightValue) return leftValue > rightValue ? -1 : 1;
  }

  const leftMtime = Number(leftRecord.mtimeMs) || 0;
  const rightMtime = Number(rightRecord.mtimeMs) || 0;
  if (leftMtime !== rightMtime) return leftMtime > rightMtime ? -1 : 1;

  // Prefer the primary tokens directory only when freshness is otherwise
  // identical. A newer use_token file is still allowed to win.
  const leftSourcePriority = leftRecord.source === 'tokens' ? 1 : 0;
  const rightSourcePriority = rightRecord.source === 'tokens' ? 1 : 0;
  if (leftSourcePriority !== rightSourcePriority) {
    return leftSourcePriority > rightSourcePriority ? -1 : 1;
  }
  return String(leftRecord.relativePath || '').localeCompare(
    String(rightRecord.relativePath || ''),
    'en',
    { numeric: true, sensitivity: 'base' },
  );
}

function buildImportPlan(sources, accounts, selectedKeys = []) {
  const candidates = collectCandidates(sources);
  const nowMs = Date.now();
  const entries = candidates.map((candidate) => {
    const matches = accountMatches(candidate, accounts);
    return {
      candidate,
      matches,
      account: matches.length === 1 ? matches[0] : null,
    };
  });
  const preferredByAccount = new Map();
  for (const entry of entries) {
    if (!entry.account || !selectedCandidate(entry.candidate, selectedKeys, entry.account)) continue;
    const accountId = entry.account.id;
    if (accountId === undefined || accountId === null) continue;
    const key = String(accountId);
    const current = preferredByAccount.get(key);
    if (!current || compareCandidateFreshness(entry.candidate, current.candidate, nowMs) < 0) {
      preferredByAccount.set(key, entry);
    }
  }
  const plan = [];
  let nextNumber = nextFreeNumber(accounts);
  for (const entry of entries) {
    const { candidate, matches, account } = entry;
    if (!selectedCandidate(candidate, selectedKeys, account)) continue;
    const accessFingerprint = candidate.record.fingerprints?.access || null;
    const refreshFingerprint = candidate.record.fingerprints?.refresh || null;
    let action = 'create';
    let reason = 'token_only';
    let assignedName = null;
    const preferred = account && account.id !== undefined && account.id !== null
      ? preferredByAccount.get(String(account.id))
      : null;
    const superseded = Boolean(preferred && preferred.candidate !== candidate);
    if (matches.length > 1) {
      action = 'conflict';
      reason = 'multiple_sub2api_accounts';
    } else if (account) {
      assignedName = account.name;
      const availability = getAccountAvailability(account, nowMs);
      if (superseded) {
        action = 'skip';
        reason = 'superseded_by_newer_source';
      } else if (accessFingerprint && accessFingerprint === account.tokenFingerprints?.access
          && (!refreshFingerprint || refreshFingerprint === account.tokenFingerprints?.refresh)) {
        action = 'skip';
        reason = 'already_in_sync';
      } else if (availability.key === 'available') {
        action = 'skip';
        reason = 'sub2api_available';
      } else if (isExpired(candidate.record, nowMs)) {
        action = 'skip';
        reason = 'source_token_expired';
      } else {
        action = 'update';
        reason = 'token_changed';
      }
    } else {
      assignedName = freeName(nextNumber++);
    }
    if (candidate.conflictingVersions) {
      action = 'conflict';
      reason = 'duplicate_token_versions';
      if (!account && matches.length <= 1) {
        nextNumber -= 1;
        assignedName = null;
      }
    }
    const item = {
      key: candidate.key,
      identityKey: candidate.identityKey,
      action,
      reason,
      accountId: account?.id || null,
      accountName: assignedName,
      email: candidate.record.email || '',
      source: candidate.record.source,
      relativePath: candidate.record.relativePath,
      fileName: candidate.record.fileName,
      expiresAt: candidate.record.expiresAt || null,
      fingerprints: candidate.record.fingerprints || {},
      duplicateSource: candidate.duplicates,
      conflictingVersions: candidate.conflictingVersions,
      availability: account ? getAccountAvailability(account, nowMs).key : 'not_present',
      availabilityReason: account ? getAccountAvailability(account, nowMs).reason : 'not_in_sub2api',
      sourceExpired: isExpired(candidate.record, nowMs),
      supersededBy: superseded ? preferred.candidate.record.relativePath : null,
      _raw: candidate.record.raw,
      _account: account,
    };
    plan.push(item);
  }
  return plan;
}

function safeImportItem(item) {
  return {
    key: item.key,
    identityKey: item.identityKey,
    action: item.action,
    reason: item.reason,
    accountId: item.accountId,
    accountName: item.accountName,
    email: item.email,
    source: item.source,
    relativePath: item.relativePath,
    fileName: item.fileName,
    expiresAt: item.expiresAt,
    fingerprints: item.fingerprints,
    duplicateSource: item.duplicateSource,
    conflictingVersions: item.conflictingVersions,
    availability: item.availability,
    availabilityReason: item.availabilityReason,
    sourceExpired: item.sourceExpired,
    supersededBy: item.supersededBy || null,
  };
}

function importPlanSummary(plan) {
  const counts = {};
  for (const item of plan) counts[item.action] = (counts[item.action] || 0) + 1;
  return { counts, items: plan.map(safeImportItem) };
}

function configuredGroupIds() {
  return String(process.env.SUB2API_GROUP_IDS || '')
    .split(',')
    .map((value) => Number(value.trim()))
    .filter((value) => Number.isFinite(value) && value > 0);
}

async function resolveGroupIds(client) {
  const configured = configuredGroupIds();
  if (configured.length > 0) return configured;
  const wanted = String(process.env.SUB2API_GROUP_NAME || 'share').trim().toLowerCase();
  if (!wanted) return [];
  try {
    const groups = await client.listGroups();
    return groups
      .filter((group) => {
        const name = String(group?.name || group?.slug || group?.code || '').trim().toLowerCase();
        return name === wanted || name.includes(wanted);
      })
      .map((group) => Number(group.id))
      .filter((id) => Number.isFinite(id) && id > 0);
  } catch {
    return [];
  }
}

function backupDirectory() {
  return path.resolve(process.env.PANEL_BACKUP_DIR || path.join(__dirname, '..', 'runtime', 'backups'));
}

function writeBackup(payload) {
  const directory = backupDirectory();
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const filePath = path.join(directory, 'sub2api-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json');
  fs.writeFileSync(filePath, JSON.stringify(payload), { mode: 0o600 });
  try { fs.chmodSync(filePath, 0o600); } catch {}
  const retentionDays = Number(process.env.PANEL_BACKUP_RETENTION_DAYS || 30);
  if (Number.isFinite(retentionDays) && retentionDays > 0) {
    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    for (const name of fs.readdirSync(directory)) {
      if (!name.startsWith('sub2api-') || !name.endsWith('.json')) continue;
      const oldPath = path.join(directory, name);
      try {
        if (fs.statSync(oldPath).mtimeMs < cutoff) fs.unlinkSync(oldPath);
      } catch {}
    }
  }
  return filePath;
}

async function executeImport({ snapshotVersion: expectedVersion, selectedKeys = [], actor = 'local', db, jobId = null, logger = null }) {
  const startedAt = Date.now();
  writeLog(logger, 'info', 'import.started', {
    jobId,
    actor,
    expectedVersion: expectedVersion || null,
    selectedCount: Array.isArray(selectedKeys) ? selectedKeys.length : 0,
  });
  try {
    if (process.env.PANEL_WRITE_ENABLED !== '1') {
      const error = new Error('写操作未启用，请设置 PANEL_WRITE_ENABLED=1 后重启面板');
      error.code = 'WRITE_DISABLED';
      throw error;
    }
    if (!configuredForSub2Api()) throw new Error('Sub2API 管理 API 未配置');
    const result = await withSyncLock(async () => {
      const client = new Sub2ApiAdminClient({ logger, logContext: { jobId, actor } });
      const current = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
        includeRaw: true,
        includeInternal: true,
        client,
        logger,
        jobId,
        actor,
      });
      if (expectedVersion && expectedVersion !== current.version) {
        const error = new Error('来源在确认前已变化，请重新检查差异');
        error.code = 'SNAPSHOT_STALE';
        throw error;
      }
      const fullPlan = buildImportPlan(current._internal.sources, current._internal.accounts, selectedKeys);
      const fullSummary = importPlanSummary(fullPlan);
      writeLog(logger, 'info', 'import.plan_built', {
        jobId,
        actor,
        snapshotVersion: current.version,
        counts: fullSummary.counts,
        selectedCount: Array.isArray(selectedKeys) ? selectedKeys.length : 0,
      });
      for (const item of fullPlan.filter((candidate) => candidate.action === 'skip')) {
        writeLog(logger, 'info', 'import.account_skipped', {
          jobId,
          actor,
          action: item.action,
          reason: item.reason,
          accountId: item.accountId,
          accountName: item.accountName,
          email: item.email,
          source: item.source,
          relativePath: item.relativePath,
          availability: item.availability,
          beforeFingerprint: item._account?.tokenFingerprints?.access || null,
          afterFingerprint: item.fingerprints?.access || null,
        });
      }
      const plan = fullPlan.filter((item) => item.action !== 'skip');
      const conflicts = plan.filter((item) => item.action === 'conflict' || item.conflictingVersions);
      if (conflicts.length > 0) {
        for (const item of conflicts) {
          writeLog(logger, 'error', 'import.account_blocked', {
            jobId,
            actor,
            action: item.action,
            reason: item.reason,
            accountId: item.accountId,
            accountName: item.accountName,
            email: item.email,
            source: item.source,
            relativePath: item.relativePath,
          });
        }
        throw new Error('存在身份或版本冲突，已停止导入');
      }
      if (plan.length === 0) return { ...importPlanSummary([]), imported: [], skipped: true };

      let backupPath = null;
      writeLog(logger, 'info', 'import.backup_started', { jobId, actor });
      try {
        backupPath = writeBackup(await client.exportAccounts());
        writeLog(logger, 'info', 'import.backup_succeeded', { jobId, actor, backupPath });
      } catch (error) {
        const message = safeErrorMessage(error);
        writeLog(logger, process.env.PANEL_ALLOW_UNBACKED_WRITES === '1' ? 'warn' : 'error', 'import.backup_failed', {
          jobId,
          actor,
          error: message,
          continuedWithoutBackup: process.env.PANEL_ALLOW_UNBACKED_WRITES === '1',
        });
        if (process.env.PANEL_ALLOW_UNBACKED_WRITES !== '1') {
          throw new Error('导入前备份失败，已停止写入：' + message);
        }
      }

      const groups = await resolveGroupIds(client);
      writeLog(logger, 'info', 'import.accounts_started', {
        jobId,
        actor,
        count: plan.length,
        groupCount: groups.length,
      });
      const imported = [];
      for (const item of plan) {
        const itemStartedAt = Date.now();
        const baseFields = {
          jobId,
          actor,
          action: item.action,
          accountId: item.accountId,
          accountName: item.accountName,
          email: item.email,
          source: item.source,
          relativePath: item.relativePath,
          beforeFingerprint: item._account?.tokenFingerprints?.access || null,
          afterFingerprint: item.fingerprints?.access || null,
        };
        writeLog(logger, 'info', 'import.account_started', baseFields);
        const payload = {
          content: JSON.stringify(item._raw),
          name: item.accountName || undefined,
          group_ids: groups,
          update_existing: true,
          skip_default_group_bind: false,
          confirm_mixed_channel_risk: process.env.SUB2API_CONFIRM_MIXED_CHANNEL_RISK === '1',
        };
        try {
          const result = await client.importCodexSession(payload);
          imported.push({ ...safeImportItem(item), result: result || null });
          await db?.audit({
            jobId,
            actor,
            action: item.action === 'create' ? 'account_import' : 'token_update',
            targetKey: item.identityKey,
            beforeFingerprint: item._account?.tokenFingerprints?.access || null,
            afterFingerprint: item.fingerprints?.access || null,
            result: 'ok',
            details: { accountId: item.accountId, accountName: item.accountName, backupPath },
          });
          await db?.saveLink({
            identityKey: item.identityKey,
            tokenPath: item.relativePath,
            sub2apiId: result?.account_id || item.accountId,
            accountName: item.accountName,
          });
          writeLog(logger, 'info', 'import.account_succeeded', {
            ...baseFields,
            durationMs: Date.now() - itemStartedAt,
            sub2apiAccountId: result?.account_id || item.accountId || null,
          });
        } catch (error) {
          const message = safeErrorMessage(error);
          imported.push({ ...safeImportItem(item), result: null, error: message });
          await db?.audit({
            jobId,
            actor,
            action: item.action === 'create' ? 'account_import' : 'token_update',
            targetKey: item.identityKey,
            beforeFingerprint: item._account?.tokenFingerprints?.access || null,
            afterFingerprint: item.fingerprints?.access || null,
            result: 'failed',
            details: { error: message },
          });
          writeLog(logger, 'error', 'import.account_failed', {
            ...baseFields,
            durationMs: Date.now() - itemStartedAt,
            error: message,
          });
        }
      }
      const failed = imported.filter((item) => item.error).length;
      writeLog(logger, failed > 0 ? 'warn' : 'info', 'import.accounts_completed', {
        jobId,
        actor,
        count: plan.length,
        succeeded: imported.length - failed,
        failed,
      });
      return {
        ...importPlanSummary(plan),
        imported,
        backupPath,
        failed,
      };
    });
    writeLog(logger, result.failed > 0 ? 'warn' : 'info', 'import.completed', {
      jobId,
      actor,
      durationMs: Date.now() - startedAt,
      importedCount: result.imported?.length || 0,
      failed: result.failed || 0,
      skipped: Boolean(result.skipped),
      backupPath: result.backupPath || null,
    });
    return result;
  } catch (error) {
    writeLog(logger, 'error', 'import.failed', {
      jobId,
      actor,
      durationMs: Date.now() - startedAt,
      error: safeErrorMessage(error),
      code: error?.code || null,
    });
    throw error;
  }
}

module.exports = {
  buildSnapshot,
  buildImportPlan,
  collectCandidates,
  executeImport,
  importPlanSummary,
  configuredForSub2Api,
  snapshotVersion,
  safeErrorMessage,
};
