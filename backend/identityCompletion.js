'use strict';

const { strongIdentitiesFullyMatch } = require('./diff');
const { normalizeIdentityValue } = require('./lib/token');

const CANONICAL_STRONG_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/;

function canonicalIdentityParts(keys) {
  try {
    if (!Array.isArray(keys) || keys.length < 1 || keys.length > 3) return null;
    const seen = new Set();
    const parts = { account: null, user: null, strong: [] };
    for (let index = 0; index < keys.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(keys, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      const key = descriptor.value;
      if (typeof key !== 'string' || key !== key.trim() || key.length > 520) return null;
      const separator = key.indexOf(':');
      const kind = key.slice(0, separator);
      const value = key.slice(separator + 1);
      if (separator <= 0 || !['account', 'user', 'email'].includes(kind)
          || seen.has(kind) || !value
          || normalizeIdentityValue(kind + ':', value) !== value) return null;
      seen.add(kind);
      // Email may be present in a normalized token row, but never contributes
      // evidence for completion, matching or authorization.
      if (kind === 'email') continue;
      if (!CANONICAL_STRONG_VALUE.test(value)) return null;
      parts[kind] = value;
      parts.strong.push(key);
    }
    return parts;
  } catch {
    return null;
  }
}

function canCompleteParts(expected, actual) {
  return Boolean(expected && actual
    && expected.account === null && expected.user !== null
    && actual.account !== null && actual.user === expected.user);
}

// Directional and narrow: a known user may acquire its previously absent
// account dimension. Existing account IDs and users can never be replaced,
// and the opposite account-only -> account+user direction is not allowed.
function canCompleteAccountIdentity(expectedKeys, actualKeys) {
  return canCompleteParts(canonicalIdentityParts(expectedKeys), canonicalIdentityParts(actualKeys));
}

function remotePhase3OutputIdentityMatches(expectedKeys, actualKeys) {
  const expected = canonicalIdentityParts(expectedKeys);
  const actual = canonicalIdentityParts(actualKeys);
  return Boolean(expected && actual && (
    strongIdentitiesFullyMatch(expected.strong, actual.strong)
      || canCompleteParts(expected, actual)
  ));
}

module.exports = { canCompleteAccountIdentity, remotePhase3OutputIdentityMatches };
