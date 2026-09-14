const assert = require('node:assert/strict');
const test = require('node:test');

require('./test-isolation');

const { normalizeTokenDocument, parseDateValue } = require('../backend/lib/token');

test('token dates accept explicit RFC3339 instants and existing numeric epochs', () => {
  assert.equal(parseDateValue('2024-02-29T23:59:59Z'), '2024-02-29T23:59:59.000Z');
  assert.equal(parseDateValue('2026-01-02T03:04:05.678Z'), '2026-01-02T03:04:05.678Z');
  assert.equal(parseDateValue('2026-01-02T03:04:05.123456789+08:30'), '2026-01-01T18:34:05.123Z');
  assert.equal(parseDateValue(1_767_323_045), '2026-01-02T03:04:05.000Z');
  assert.equal(parseDateValue('1767323045000'), '2026-01-02T03:04:05.000Z');
});

test('token dates reject rolled, ambiguous, incomplete, or non-RFC3339 strings', () => {
  for (const value of [
    '2026-02-29T00:00:00Z',
    '2026-02-30T00:00:00Z',
    '2026-04-31T00:00:00Z',
    '2026-01-01T24:00:00Z',
    '2026-01-01T00:00:60Z',
    '2026-01-01T00:00:00+24:00',
    '2026-01-01T00:00:00+00:60',
    '2026-01-01T00:00:00-00:00',
    '01/02/03',
    '2026-01-02',
    '2026-01-02T03:04:05',
    '2026-01-02 03:04:05Z',
    '2026-01-02t03:04:05z',
    ' 2026-01-02T03:04:05Z ',
  ]) {
    assert.equal(parseDateValue(value), null, value);
  }
});

test('rolled and ambiguous expiry metadata fail closed instead of affecting token ordering', () => {
  for (const expired of ['2026-02-30T00:00:00Z', '01/02/03']) {
    const record = normalizeTokenDocument({
      source: 'tokens',
      relativePath: 'tokens/date.json',
      fileName: 'date.json',
      mtimeMs: 1,
      data: {
        access_token: 'opaque-access',
        account_id: 'strict-date-account',
        expired,
      },
    });
    assert.equal(record.parseStatus, 'ok', expired);
    assert.equal(record.expiryStatus, 'invalid', expired);
    assert.equal(record.expiresAt, null, expired);
  }
});
