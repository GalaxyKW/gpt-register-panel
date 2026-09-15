const { parseDateValue } = require('./lib/token');

function parseTime(value) {
  if (value === undefined || value === null || value === '') return null;
  const normalized = parseDateValue(value);
  const timestamp = normalized ? Date.parse(normalized) : NaN;
  return Number.isFinite(timestamp) ? timestamp : null;
}

function presentOwnValues(account, keys) {
  const values = [];
  for (const key of keys) {
    if (!account || !Object.prototype.hasOwnProperty.call(account, key)) continue;
    const value = account[key];
    if (value !== undefined && value !== null && value !== '') values.push(value);
  }
  return values;
}

function ownValue(account, key) {
  return account && Object.prototype.hasOwnProperty.call(account, key)
    ? account[key]
    : undefined;
}

function timeState(account, valueKeys, statusKeys = []) {
  const rawStatuses = presentOwnValues(account, statusKeys);
  const normalizedStatuses = rawStatuses.map((value) => (
    typeof value === 'string' ? value.trim().toLowerCase() : ''
  ));
  if (normalizedStatuses.some((value) => !['valid', 'missing', 'invalid'].includes(value))
      || new Set(normalizedStatuses).size > 1) {
    return { status: 'invalid', timestamp: null };
  }
  const declaredStatus = normalizedStatuses[0] || '';
  const rawValues = presentOwnValues(account, valueKeys);
  const timestamps = rawValues.map(parseTime);
  if (timestamps.some((value) => value === null)
      || new Set(timestamps).size > 1) {
    return { status: 'invalid', timestamp: null };
  }
  const timestamp = timestamps[0] ?? null;
  if (declaredStatus === 'invalid') return { status: 'invalid', timestamp: null };
  if (declaredStatus === 'missing') {
    return timestamp === null
      ? { status: 'missing', timestamp: null }
      : { status: 'invalid', timestamp: null };
  }
  if (declaredStatus === 'valid') {
    return timestamp === null
      ? { status: 'invalid', timestamp: null }
      : { status: 'valid', timestamp };
  }
  return timestamp === null
    ? { status: 'missing', timestamp: null }
    : { status: 'valid', timestamp };
}

function unknown(reason) {
  return { key: 'unknown', reason };
}

function getAccountAvailability(account, nowMs = Date.now()) {
  if (!account) return { key: 'not_present', reason: 'not_in_sub2api' };
  if (ownValue(account, 'schemaValid') === false) return unknown('sub2api_schema_invalid');
  if (typeof nowMs !== 'number' || !Number.isFinite(nowMs)) {
    return unknown('panel_clock_invalid');
  }

  const status = String(ownValue(account, 'status') || '').trim().toLowerCase();
  const recognizedStatus = ['active', 'inactive', 'disabled', 'error'].includes(status);
  const rawStatusKnown = ownValue(account, 'statusKnown');
  const rawSchedulable = ownValue(account, 'schedulable');
  const rawSchedulableKnown = ownValue(account, 'schedulableKnown');
  const statusKnown = rawStatusKnown === undefined
    ? recognizedStatus
    : rawStatusKnown === true && recognizedStatus;
  const schedulableKnown = rawSchedulableKnown === undefined
    ? typeof rawSchedulable === 'boolean'
    : rawSchedulableKnown === true && typeof rawSchedulable === 'boolean';
  if (!statusKnown) return unknown(status ? 'sub2api_status_unknown' : 'sub2api_status_missing');
  // A known non-active status is already sufficient evidence that the account
  // is unavailable. Older Sub2API responses can omit `schedulable` for error,
  // inactive, or disabled rows; requiring that unrelated field first would
  // strand exactly the accounts whose OAuth credentials are eligible for
  // repair. Active rows remain fail-closed unless scheduler state is known.
  if (status !== 'active') {
    return { key: 'unavailable', reason: 'sub2api_status_' + status };
  }
  if (!schedulableKnown) return unknown('sub2api_schedulable_missing');
  if (rawSchedulable === false) {
    return { key: 'unavailable', reason: 'sub2api_unschedulable' };
  }

  const autoPauseOnExpired = ownValue(account, 'autoPauseOnExpired');
  if (autoPauseOnExpired !== undefined
      && typeof autoPauseOnExpired !== 'boolean') {
    return unknown('sub2api_auto_pause_invalid');
  }

  if (autoPauseOnExpired !== false) {
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
