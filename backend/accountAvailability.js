function parseTime(value) {
  if (value === undefined || value === null || value === '') return null;
  const timestamp = Date.parse(String(value));
  return Number.isFinite(timestamp) ? timestamp : null;
}

function getAccountAvailability(account, nowMs = Date.now()) {
  if (!account) return { key: 'not_present', reason: 'not_in_sub2api' };

  const status = String(account.status || '').trim().toLowerCase();
  if (status && status !== 'active') {
    return { key: 'unavailable', reason: 'sub2api_status_' + status };
  }
  if (account.schedulable === false) {
    return { key: 'unavailable', reason: 'sub2api_unschedulable' };
  }

  const tempUntil = parseTime(account.tempUnschedulableUntil);
  if (tempUntil !== null && tempUntil > nowMs) {
    return { key: 'unavailable', reason: 'sub2api_temp_unschedulable' };
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
