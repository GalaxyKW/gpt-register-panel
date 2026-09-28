'use strict';

const {
  REVISION_PATTERN,
  matchesAccountTestTargetRevision,
  accountTestTargetDigest,
} = require('./accountTargetRevision');
const { getAccountAvailability } = require('./accountAvailability');
const { strongIdentitiesFullyMatch } = require('./diff');
const { normalizeIdentityValue } = require('./lib/token');

const STRONG_IDENTITY = /^(account|user):[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/;

function remoteTargetError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function plainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function ownData(value, key) {
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}

function validateRemoteTarget(value) {
  if (value === undefined || value === null) return null;
  if (!plainObject(value) || Object.keys(value).some((key) => !['accountId', 'targetRevision'].includes(key))) {
    throw remoteTargetError('PHASE3_REMOTE_TARGET_INVALID', '远端 Phase3 目标格式无效');
  }
  const accountId = ownData(value, 'accountId');
  const targetRevision = ownData(value, 'targetRevision');
  if (!Number.isSafeInteger(accountId) || accountId <= 0
      || typeof targetRevision !== 'string' || targetRevision.trim() !== targetRevision
      || !REVISION_PATTERN.test(targetRevision)) {
    throw remoteTargetError('PHASE3_REMOTE_TARGET_INVALID', '远端 Phase3 目标 ID 或版本无效');
  }
  return { accountId, targetRevision };
}

function validateBoundRemoteTarget(value) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !['accountId', 'targetRevision', 'identityKeys', 'targetDigest', 'endpointDigest'].includes(key))) {
    throw remoteTargetError('PHASE3_REMOTE_BINDING_INVALID', '远端 Phase3 身份绑定无效');
  }
  const target = validateRemoteTarget({
    accountId: ownData(value, 'accountId'), targetRevision: ownData(value, 'targetRevision'),
  });
  const keys = ownData(value, 'identityKeys');
  const targetDigest = ownData(value, 'targetDigest');
  const endpointDigest = ownData(value, 'endpointDigest');
  if (typeof targetDigest !== 'string' || targetDigest.length !== 64 || !/^[a-f0-9]{64}$/.test(targetDigest)) {
    throw remoteTargetError('PHASE3_REMOTE_BINDING_INVALID', '远端 Phase3 版本基线缺失或无效');
  }
  if (typeof endpointDigest !== 'string' || endpointDigest.length !== 64 || !/^[a-f0-9]{64}$/.test(endpointDigest)) {
    throw remoteTargetError('PHASE3_REMOTE_BINDING_INVALID', '远端 Phase3 实例绑定缺失或无效');
  }
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > 2
      || Array.from(keys).some((key) => typeof key !== 'string' || !STRONG_IDENTITY.test(key)
        || normalizeIdentityValue(key.slice(0, key.indexOf(':') + 1), key.slice(key.indexOf(':') + 1))
          !== key.slice(key.indexOf(':') + 1))
      || new Set(keys.map((key) => key.slice(0, key.indexOf(':')))).size !== keys.length) {
    throw remoteTargetError('PHASE3_REMOTE_BINDING_INVALID', '远端 Phase3 强身份缺失或无效');
  }
  return Object.freeze({ ...target, identityKeys: Object.freeze([...keys].sort()), targetDigest, endpointDigest });
}

function remotePhase3EndpointDigest(client) {
  try {
    // Reuse the import endpoint identity, including meaningful base-path
    // distinctions. Load lazily: sync imports Phase3 helpers through view.
    const { fingerprint } = require('./sync').resolveImportTargetBinding(client);
    const encoded = typeof fingerprint === 'string' && fingerprint.startsWith('sha256.')
      ? fingerprint.slice('sha256.'.length) : '';
    if (encoded.length !== 43 || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw new Error();
    const digest = Buffer.from(encoded, 'base64url');
    if (digest.length !== 32 || digest.toString('base64url') !== encoded) throw new Error();
    // Hex avoids both hostname disclosure and accidental token-pattern
    // redaction inside otherwise opaque base64url metadata.
    return digest.toString('hex');
  } catch {
    throw remoteTargetError('PHASE3_REMOTE_ENDPOINT_INVALID', '无法确认 Sub2API 管理实例，未启动本地 Phase3');
  }
}

function remoteIdentityKeys(account) {
  const keys = new Set();
  const add = (kind, raw) => {
    if (raw === undefined || raw === null || raw === '') return;
    const value = normalizeIdentityValue(kind + ':', raw);
    keys.add(kind + ':' + value);
  };
  for (const key of Array.isArray(account?.identityKeys) ? account.identityKeys : []) {
    if (typeof key !== 'string') continue;
    const separator = key.indexOf(':');
    const kind = key.slice(0, separator).toLowerCase();
    if (kind === 'account' || kind === 'user') add(kind, key.slice(separator + 1));
  }
  add('account', account?.accountId);
  add('user', account?.userId);
  return [...keys].sort();
}

function assertRemotePhase3TargetCurrent(value, account) {
  const target = validateBoundRemoteTarget(value);
  if (!account || account.id !== target.accountId) {
    throw remoteTargetError('PHASE3_REMOTE_NOT_FOUND', '所选远端账号不存在或 ID 不一致，未启动 Phase3');
  }
  if (!matchesAccountTestTargetRevision(target.targetRevision, account)
      || accountTestTargetDigest(account) !== target.targetDigest
      || !strongIdentitiesFullyMatch(target.identityKeys, remoteIdentityKeys(account))) {
    throw remoteTargetError('PHASE3_REMOTE_TARGET_CHANGED', '远端账号身份、凭据或状态已变化，请重新选择');
  }
  if (getAccountAvailability(account).key !== 'unavailable') {
    throw remoteTargetError('PHASE3_REMOTE_NOT_UNAVAILABLE', '远端账号并非明确不可用，跳过本地 Phase3');
  }
  return target;
}

function bindRemotePhase3Targets(resolvedRequests, accounts, client) {
  if (!Array.isArray(resolvedRequests) || !Array.isArray(accounts)) {
    throw remoteTargetError('PHASE3_REMOTE_TARGET_INVALID', '远端 Phase3 目标清单无效');
  }
  const endpointDigest = remotePhase3EndpointDigest(client);
  const seen = new Set();
  const bindings = [];
  for (const request of resolvedRequests) {
    const target = validateRemoteTarget(request?.remoteTarget);
    if (!target) { bindings.push(null); continue; }
    if (request.sourceMode !== 'username') {
      throw remoteTargetError('PHASE3_REMOTE_SOURCE_INVALID', '远端账号必须绑定明确选择的本地登录记录');
    }
    if (seen.has(target.accountId)) {
      throw remoteTargetError('PHASE3_REMOTE_DUPLICATE', '同一个远端账号不能重复提交本地 Phase3');
    }
    seen.add(target.accountId);
    const matches = accounts.filter((account) => account?.id === target.accountId);
    if (matches.length !== 1) {
      throw remoteTargetError('PHASE3_REMOTE_NOT_FOUND', '所选远端账号不存在或 ID 不唯一');
    }
    const binding = validateBoundRemoteTarget({ ...target, identityKeys: remoteIdentityKeys(matches[0]),
      targetDigest: accountTestTargetDigest(matches[0]), endpointDigest });
    bindings.push(assertRemotePhase3TargetCurrent(binding, matches[0]));
  }
  // Do not partially enrich a batch that fails later validation. Preserve the
  // existing non-enumerable local execution binding on each resolved request.
  resolvedRequests.forEach((request, index) => {
    if (bindings[index]) request.remoteTarget = bindings[index];
  });
  return resolvedRequests;
}

module.exports = {
  validateRemoteTarget,
  validateBoundRemoteTarget,
  bindRemotePhase3Targets,
  assertRemotePhase3TargetCurrent,
  remotePhase3EndpointDigest,
};
