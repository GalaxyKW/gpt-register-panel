const crypto = require('node:crypto');
const { normalizeIdentityValue } = require('./lib/token');

const LIFECYCLE_STATES = new Set(['observed', 'imported', 'delete_pending', 'deleted', 'review_required']);
const TERMINAL_LIFECYCLE_STATES = new Set(['delete_pending', 'deleted', 'review_required']);
const DEFAULT_CONSOLE_SETTINGS = Object.freeze({
  enabled: false,
  intervalMinutes: 30,
  refreshInvalid: true,
  deleteBanned: true,
  importNew: true,
  logsRetentionDays: 14,
  testModel: 'gpt-5.6-luna',
});

function lifecycleError(code = 'ACCOUNT_LIFECYCLE_INVALID') {
  const error = new Error('账号维护履历无效或已发生变化，已保留安全阻挡');
  error.code = code;
  return error;
}

function managementEndpointKey(baseUrl) {
  let url;
  try { url = new URL(baseUrl); } catch { throw lifecycleError(); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
      || url.search || url.hash) throw lifecycleError();
  return 'endpoint-v1.' + crypto.createHash('sha256')
    .update(url.toString().replace(/\/$/, '')).digest('hex');
}

function validEndpointKey(value) {
  return typeof value === 'string' && /^endpoint-v1\.[a-f0-9]{64}$/.test(value);
}

function normalizeLifecycleIdentityKey(value) {
  if (typeof value !== 'string' || value !== value.trim() || value.length > 520) return null;
  const match = /^(account:|user:)([A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511})$/.exec(value);
  if (!match) return null;
  const normalized = normalizeIdentityValue(match[1], match[2]);
  // Strong IDs are not a channel for accidentally persisting credentials.
  if (!normalized || /(?:authorization|bearer|password|credential|(?:access|refresh|id)[_-]?token|api[_-]?key)/i.test(normalized)
      || /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(normalized)) return null;
  return match[1] + normalized;
}

function lifecycleIdentityKeys(account) {
  if (!account || account.schemaValid === false || account.identityConflict === true) return [];
  const values = Array.isArray(account.identityKeys)
    ? account.identityKeys.filter((key) => typeof key === 'string' && /^(account|user):/.test(key))
    : [];
  if (account.accountId) values.push('account:' + account.accountId);
  if (account.userId) values.push('user:' + account.userId);
  const normalized = values.map(normalizeLifecycleIdentityKey);
  if (normalized.some((key) => !key)) return [];
  const unique = [...new Set(normalized)].sort();
  if (unique.filter((key) => key.startsWith('account:')).length > 1
      || unique.filter((key) => key.startsWith('user:')).length > 1) return [];
  return unique;
}

function normalizeLifecycleRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)
      || !validEndpointKey(record.endpointKey)
      || !LIFECYCLE_STATES.has(record.state)
      || !Number.isSafeInteger(record.sub2apiId) || record.sub2apiId <= 0
      || typeof record.accountName !== 'string' || record.accountName.length > 256
      || /[\p{Cc}\p{Default_Ignorable_Code_Point}]/u.test(record.accountName)
      || !Array.isArray(record.identityKeys) || record.identityKeys.length < 1 || record.identityKeys.length > 2
      || typeof record.reasonCode !== 'string' || !/^[a-z0-9_]{1,64}$/.test(record.reasonCode)) {
    throw lifecycleError();
  }
  const keys = lifecycleIdentityKeys({ identityKeys: record.identityKeys });
  if (keys.length !== record.identityKeys.length) throw lifecycleError();
  return { endpointKey: record.endpointKey, identityKeys: keys, sub2apiId: record.sub2apiId,
    accountName: record.accountName, state: record.state, reasonCode: record.reasonCode };
}

function normalizeConsoleSettings(settings) {
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)
      || Object.keys(settings).length !== Object.keys(DEFAULT_CONSOLE_SETTINGS).length
      || Object.keys(settings).some((key) => !Object.hasOwn(DEFAULT_CONSOLE_SETTINGS, key))) {
    throw lifecycleError('CONSOLE_SETTINGS_INVALID');
  }
  for (const field of ['enabled', 'refreshInvalid', 'deleteBanned', 'importNew']) {
    if (typeof settings[field] !== 'boolean') throw lifecycleError('CONSOLE_SETTINGS_INVALID');
  }
  if (!Number.isSafeInteger(settings.intervalMinutes) || settings.intervalMinutes < 5 || settings.intervalMinutes > 1440
      || !Number.isSafeInteger(settings.logsRetentionDays) || settings.logsRetentionDays < 1 || settings.logsRetentionDays > 365) {
    throw lifecycleError('CONSOLE_SETTINGS_INVALID');
  }
  const { safeModelId } = require('./adapters/sub2apiAdmin');
  if (typeof settings.testModel !== 'string' || settings.testModel.length > 100
      || !safeModelId(settings.testModel)) {
    throw lifecycleError('CONSOLE_SETTINGS_INVALID');
  }
  return Object.fromEntries(Object.keys(DEFAULT_CONSOLE_SETTINGS).map((key) => [key, settings[key]]));
}

function accountInMaintenanceScope(account) {
  return account?.platform === 'openai' && account?.type === 'oauth'
    && account?.planType === 'free' && account?.schemaValid !== false;
}

async function recordObservedAccounts(db, { endpointKey, accounts }) {
  if (!validEndpointKey(endpointKey) || !Array.isArray(accounts) || accounts.length > 10000) throw lifecycleError();
  const records = accounts.filter(accountInMaintenanceScope).map((account) => ({
    endpointKey, identityKeys: lifecycleIdentityKeys(account), sub2apiId: account.id,
    accountName: account.name || '', state: 'observed', reasonCode: 'remote_observed',
  })).filter((record) => record.identityKeys.length > 0);
  if (records.length) await db.upsertAccountLifecycles(records);
  return { observed: records.length };
}

function creationEligibility(lifecycles, { endpointKey, identityKeys }) {
  if (!validEndpointKey(endpointKey) || !Array.isArray(lifecycles) || !Array.isArray(identityKeys)) throw lifecycleError();
  const keys = lifecycleIdentityKeys({ identityKeys });
  if (!keys.length) return { allowed: false, reasonCode: 'strong_identity_missing' };
  const matches = lifecycles.filter((row) => (row.endpointKey === endpointKey || row.endpointKey === 'legacy_unbound')
    && keys.includes(row.identityKey));
  if (!matches.length) return { allowed: true, reasonCode: 'never_imported' };
  const terminal = matches.find((row) => TERMINAL_LIFECYCLE_STATES.has(row.state));
  return { allowed: false, reasonCode: terminal ? 'lifecycle_' + terminal.state
    : matches.some((row) => row.endpointKey === 'legacy_unbound') ? 'legacy_import_history' : 'previously_imported' };
}

async function canCreateAccount(db, target) {
  return creationEligibility(await db.listAccountLifecycles(target.endpointKey), target);
}

module.exports = { DEFAULT_CONSOLE_SETTINGS, LIFECYCLE_STATES, TERMINAL_LIFECYCLE_STATES,
  lifecycleError, managementEndpointKey, validEndpointKey, normalizeLifecycleIdentityKey,
  lifecycleIdentityKeys, normalizeLifecycleRecord, normalizeConsoleSettings,
  accountInMaintenanceScope, recordObservedAccounts, creationEligibility, canCreateAccount };
