function parseTime(value) {
  if (value === undefined || value === null || value === '') return null;
  const timestamp = Date.parse(String(value));
  return Number.isFinite(timestamp) ? timestamp : null;
}

function firstPresent(account, keys) {
  for (const key of keys) {
    const value = account?.[key];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return undefined;
}

function timeState(account, valueKeys, statusKeys = []) {
  const rawStatus = firstPresent(account, statusKeys);
  const normalizedStatus = String(rawStatus || '').trim().toLowerCase();
  const rawValue = firstPresent(account, valueKeys);
  const timestamp = parseTime(rawValue);
  if (normalizedStatus === 'invalid') return { status: 'invalid', timestamp: null };
  if (normalizedStatus === 'missing' && rawValue === undefined) return { status: 'missing', timestamp: null };
  if (normalizedStatus === 'valid' && timestamp === null) return { status: 'invalid', timestamp: null };
  if (rawValue === undefined) return { status: 'missing', timestamp: null };
  return timestamp === null
    ? { status: 'invalid', timestamp: null }
    : { status: 'valid', timestamp };
}

function unknown(reason) {
  return { key: 'unknown', reason };
}

function getAccountAvailability(account, nowMs = Date.now()) {
  if (!account) return { key: 'not_present', reason: 'not_in_sub2api' };
  if (account.schemaValid === false) return unknown('sub2api_schema_invalid');

  const status = String(account.status || '').trim().toLowerCase();
  const statusKnown = account.statusKnown === undefined
    ? ['active', 'disabled', 'error'].includes(status)
    : account.statusKnown === true;
  const schedulableKnown = account.schedulableKnown === undefined
    ? typeof account.schedulable === 'boolean'
    : account.schedulableKnown === true && typeof account.schedulable === 'boolean';
  if (!statusKnown) return unknown(status ? 'sub2api_status_unknown' : 'sub2api_status_missing');
  if (!schedulableKnown) return unknown('sub2api_schedulable_missing');
  if (status !== 'active') {
    return { key: 'unavailable', reason: 'sub2api_status_' + status };
  }
  if (account.schedulable === false) {
    return { key: 'unavailable', reason: 'sub2api_unschedulable' };
  }

  if (account.autoPauseOnExpired !== undefined
      && typeof account.autoPauseOnExpired !== 'boolean') {
    return unknown('sub2api_auto_pause_invalid');
  }

  if (account.autoPauseOnExpired !== false) {
    const accountExpiry = timeState(
      account,
      ['expiresAt', 'expires_at', 'expired'],
      ['expiryStatus', 'expiresAtStatus'],
    );
    if (accountExpiry.status === 'invalid') return unknown('sub2api_expiry_invalid');
    if (accountExpiry.timestamp !== null && accountExpiry.timestamp <= nowMs) {
      return { key: 'unavailable', reason: 'sub2api_expired' };
    }

    // credentialExpiresAt is access-token metadata, not the account lifetime.
    // OAuth refresh can renew it, so it must not make an otherwise schedulable
    // account unavailable. Only the top-level account expiry participates in
    // auto-pause semantics.
  }

  const tempUntil = timeState(
    account,
    ['tempUnschedulableUntil', 'temp_unschedulable_until'],
    ['tempUnschedulableUntilStatus'],
  );
  if (tempUntil.status === 'invalid') return unknown('sub2api_temp_unschedulable_invalid');
  if (tempUntil.timestamp !== null && tempUntil.timestamp > nowMs) {
    return { key: 'unavailable', reason: 'sub2api_temp_unschedulable' };
  }

  const rateLimitUntil = timeState(
    account,
    ['rateLimitResetAt', 'rate_limit_reset_at'],
    ['rateLimitResetStatus'],
  );
  if (rateLimitUntil.status === 'invalid') return unknown('sub2api_rate_limit_invalid');
  if (rateLimitUntil.timestamp !== null && rateLimitUntil.timestamp > nowMs) {
    return { key: 'unavailable', reason: 'sub2api_rate_limited' };
  }

  const overloadUntil = timeState(
    account,
    ['overloadUntil', 'overload_until'],
    ['overloadUntilStatus'],
  );
  if (overloadUntil.status === 'invalid') return unknown('sub2api_overload_invalid');
  if (overloadUntil.timestamp !== null && overloadUntil.timestamp > nowMs) {
    return { key: 'unavailable', reason: 'sub2api_overloaded' };
  }

  return { key: 'available', reason: 'sub2api_available' };
}

function isSub2ApiUnavailable(account, nowMs = Date.now()) {
  return getAccountAvailability(account, nowMs).key === 'unavailable';
}

module.exports = {
  getAccountAvailability,
  isSub2ApiUnavailable,
};
