const assert = require('node:assert/strict');
const test = require('node:test');

require('./test-isolation');

const { compareNaturalStrings } = require('../backend/lib/stableOrder');

test('stable natural order handles digit runs without locale tables', () => {
  const values = ['token10', 'token002', 'Token2', 'token1', 'token02'];
  assert.deepEqual(values.sort(compareNaturalStrings), [
    'token1',
    'Token2',
    'token002',
    'token02',
    'token10',
  ]);
});

test('stable natural order is strict for case and malformed surrogate ties', () => {
  assert.equal(compareNaturalStrings('tokens/A2.json', 'tokens/a02.json') < 0, true);
  assert.equal(compareNaturalStrings('tokens/a02.json', 'tokens/A2.json') > 0, true);
  assert.equal(compareNaturalStrings('tokens/malformed-\ud800.json', 'tokens/malformed-\ud801.json') < 0, true);
  assert.equal(compareNaturalStrings('same', 'same'), 0);
});

test('stable natural order does not call the runtime locale comparator', () => {
  const original = String.prototype.localeCompare;
  String.prototype.localeCompare = function localeComparisonForbidden() {
    throw new Error('localeCompare must not define persisted ordering');
  };
  try {
    assert.deepEqual(['文件10', '文件2', '文件1'].sort(compareNaturalStrings), [
      '文件1',
      '文件2',
      '文件10',
    ]);
  } finally {
    String.prototype.localeCompare = original;
  }
});
