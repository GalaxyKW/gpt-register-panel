const crypto = require('node:crypto');

const TOKEN_IMPORT_CONTEXT_SCHEMA = 'token-import-reconciliation-v1';
const TOKEN_IMPORT_CONTEXT_COVERAGE = 'conservative_all_planned_targets';
const MAX_TOKEN_IMPORT_CONTEXT_TARGETS = 100;
const MAX_TOKEN_IMPORT_CREATE_GROUP_IDS = 1000;
const MAX_RECONCILIATION_CONTEXT_BYTES = 1024 * 1024;
const PLAN_INTENT_PATTERN = /^sync-plan-v1\.[A-Za-z0-9_-]{43}$/;
const EXECUTION_TARGET_SCHEMA = 'sub2api-admin-target-v1';
const EXECUTION_TARGET_FINGERPRINT = /^sha256\.[A-Za-z0-9_-]{43}$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cs}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
const REDACTION_SENTINEL = /\[(?:redacted(?:-key-\d+| encoded text)?|uninspectable|unsupported|binary redacted|circular|accessor omitted|truncated|redaction(?: [a-z]+)* reached|oversized(?: [a-z]+)* omitted|oversized)\]/i;
const STRONG_IDENTITY_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,511}$/;
const DISPLAY_COMPACT_JWT = /(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?=$|[^A-Za-z0-9_-])/;
const DISPLAY_AUTH_CREDENTIAL = /(?:^|[^A-Za-z0-9])(?:bearer|basic)[ \t]+\S/i;
const DISPLAY_CREDENTIAL_ASSIGNMENT = /(?:^|[^A-Za-z0-9])["']?(?:(?:access|refresh|id)[._ -]?tokens?|api[._ -]?keys?|(?:client[._ -]?)?secrets?(?:[._ -]?keys?)?|tokens?|passwords?|passwds?|credentials?)["']?[ \t]*(?:=>|->|:=|[:=：＝→])/i;
const DISPLAY_SAFE_SHA256_METADATA = /^(?:[A-Za-z0-9_.-]+\/)*(?:(?:access|refresh|id)[._-]?tokens?|api[._-]?keys?|credentials?)[._-]?sha256=[a-f0-9]{64}(?:\.json)?$/i;
const UNAVAILABLE_REASONS = new Set([
  'sub2api_status_inactive',
  'sub2api_status_disabled',
  'sub2api_status_error',
  'sub2api_unschedulable',
  'sub2api_expired',
  'sub2api_temp_unschedulable',
  'sub2api_rate_limited',
  'sub2api_overloaded',
]);

function contextError(message, code = 'JOB_RECONCILIATION_CONTEXT_INVALID') {
  const error = new Error(message);
  error.code = code;
  return error;
}

function ownData(value, key) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  let descriptor;
  try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { return undefined; }
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function exactObjectKeys(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  let prototype;
  let keys;
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Object.keys(value);
  } catch {
    return false;
  }
  return (prototype === Object.prototype || prototype === null)
    && keys.length === allowed.size
    && keys.every((key) => allowed.has(key));
}

function looksLikeCredentialText(value) {
  return DISPLAY_COMPACT_JWT.test(value)
    || DISPLAY_AUTH_CREDENTIAL.test(value)
    || DISPLAY_CREDENTIAL_ASSIGNMENT.test(value)
    || value.split(/[^A-Za-z0-9_+./=-]+/).some((chunk) => (
      chunk.length >= 96
        && !DISPLAY_SAFE_SHA256_METADATA.test(chunk)
        && /[A-Za-z]/.test(chunk)
        && /\d/.test(chunk)
    ));
}

function canonicalText(value, maximumCharacters) {
  if (typeof value !== 'string' || !value || value !== value.trim()
      || value.length > maximumCharacters || value.normalize('NFC') !== value
      || UNSAFE_TEXT.test(value) || REDACTION_SENTINEL.test(value)
      || looksLikeCredentialText(value)) return null;
  return value;
}

function canonicalEmail(value) {
  if (value === null) return null;
  const email = canonicalText(value, 320);
  return email && email === email.toLowerCase() && /^[^\s@]+@[^\s@]+$/.test(email)
    ? email
    : null;
}

function canonicalSourcePath(value) {
  const sourcePath = canonicalText(value, 512);
  if (!sourcePath || sourcePath.includes('\\') || sourcePath.startsWith('/')) return null;
  const segments = sourcePath.split('/');
  if (segments.length < 2 || !['tokens', 'use_token'].includes(segments[0])
      || segments.some((segment) => !segment || segment === '.' || segment === '..')
      || !segments.at(-1).toLowerCase().endsWith('.json')) return null;
  const fileStem = segments.at(-1).slice(0, -'.json'.length);
  if (segments.some(looksLikeCredentialText) || looksLikeCredentialText(fileStem)) return null;
  return Buffer.byteLength(sourcePath, 'utf8') <= 2048 ? sourcePath : null;
}

function sourcePathFromPlanItem(item) {
  const source = ownData(item, 'source');
  const relativePath = ownData(item, 'relativePath');
  if (!['tokens', 'use_token'].includes(source) || typeof relativePath !== 'string') return null;
  const firstSegment = relativePath.split('/', 1)[0];
  const sourcePath = ['tokens', 'use_token'].includes(firstSegment)
    ? firstSegment === source ? relativePath : null
    : source + '/' + relativePath;
  return canonicalSourcePath(sourcePath);
}

function canonicalStrongIdentities(value, email) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 3) return null;
  const strong = [];
  const dimensions = new Set();
  let identityEmail = null;
  for (const rawKey of value) {
    if (typeof rawKey !== 'string' || rawKey !== rawKey.trim()
        || rawKey.length > 520 || UNSAFE_TEXT.test(rawKey)
        || REDACTION_SENTINEL.test(rawKey)) return null;
    const separator = rawKey.indexOf(':');
    if (separator <= 0) return null;
    const dimension = rawKey.slice(0, separator);
    const identity = rawKey.slice(separator + 1);
    if (!['account', 'user', 'email'].includes(dimension) || dimensions.has(dimension)) {
      return null;
    }
    dimensions.add(dimension);
    if (dimension === 'email') {
      identityEmail = canonicalEmail(identity);
      if (!identityEmail || rawKey !== 'email:' + identityEmail) return null;
    } else {
      const safeIdentity = canonicalText(identity, 512);
      if (!safeIdentity || !STRONG_IDENTITY_VALUE.test(safeIdentity)
          || rawKey !== dimension + ':' + safeIdentity) return null;
      strong.push(rawKey);
    }
  }
  // Email remains a separately displayed hint, not a strong account selector.
  // The builder accepts the source record's optional email identity so it can
  // prove that it agrees with `email`, then deliberately omits it from the
  // canonical strong-key set. Re-parsing the stored canonical form therefore
  // must also accept the absence of an email key.
  if (strong.length === 0 || (identityEmail !== null && identityEmail !== email)) return null;
  return strong.sort();
}

function strongIdentitiesCompatible(leftKeys, rightKeys) {
  const left = Object.create(null);
  const right = Object.create(null);
  for (const key of leftKeys) {
    const separator = key.indexOf(':');
    left[key.slice(0, separator)] = key.slice(separator + 1);
  }
  for (const key of rightKeys) {
    const separator = key.indexOf(':');
    right[key.slice(0, separator)] = key.slice(separator + 1);
  }
  let strongMatch = false;
  for (const dimension of ['account', 'user']) {
    if (left[dimension] !== undefined && right[dimension] !== undefined) {
      if (left[dimension] !== right[dimension]) return false;
      strongMatch = true;
    }
  }
  return strongMatch;
}

function normalizeCreateGroupBinding(value, hasCreates) {
  if (!exactObjectKeys(value, new Set(['mode', 'groupIds']))) return null;
  const mode = ownData(value, 'mode');
  const rawIds = ownData(value, 'groupIds');
  if (!Array.isArray(rawIds) || rawIds.length > MAX_TOKEN_IMPORT_CREATE_GROUP_IDS
      || rawIds.some((id) => !Number.isSafeInteger(id) || id <= 0)
      || rawIds.some((id, index) => index > 0 && rawIds[index - 1] >= id)) return null;
  if (hasCreates) {
    if (!['explicit', 'sub2api_default'].includes(mode) || rawIds.length === 0) return null;
  } else if (mode !== 'not_applicable' || rawIds.length !== 0) {
    return null;
  }
  return { mode, groupIds: [...rawIds] };
}

function normalizeExecutionTarget(value) {
  if (!exactObjectKeys(value, new Set(['schema', 'fingerprint']))) return null;
  const schema = ownData(value, 'schema');
  const fingerprint = ownData(value, 'fingerprint');
  return schema === EXECUTION_TARGET_SCHEMA
    && typeof fingerprint === 'string'
    && EXECUTION_TARGET_FINGERPRINT.test(fingerprint)
    ? { schema, fingerprint }
    : null;
}

function targetMaterial(target, bindings) {
  return {
    sourcePath: target.sourcePath,
    sourceContentHash: target.sourceContentHash,
    action: target.action,
    remoteAccountId: target.remoteAccountId,
    accountName: target.accountName,
    email: target.email,
    accessFingerprint: target.accessFingerprint,
    strongIdentityKeys: target.strongIdentityKeys,
    availability: target.availability,
    availabilityReason: target.availabilityReason,
    executionTarget: bindings.executionTarget,
    createGroupBinding: target.action === 'create' ? bindings.createGroupBinding : null,
  };
}

function targetDigest(target, bindings) {
  return crypto.createHash('sha256')
    .update('gpt-register-panel/token-import-reconciliation-target/v1\0')
    .update(JSON.stringify(targetMaterial(target, bindings)))
    .digest('hex');
}

function normalizeTokenImportTarget(value, bindings) {
  const allowed = new Set([
    'targetDigest', 'sourcePath', 'sourceContentHash', 'action', 'remoteAccountId',
    'accountName', 'email', 'accessFingerprint', 'strongIdentityKeys',
    'availability', 'availabilityReason',
  ]);
  if (!exactObjectKeys(value, allowed)) return null;
  const sourcePath = canonicalSourcePath(ownData(value, 'sourcePath'));
  const sourceContentHash = ownData(value, 'sourceContentHash');
  const action = ownData(value, 'action');
  const remoteAccountId = ownData(value, 'remoteAccountId');
  const rawAccountName = ownData(value, 'accountName');
  const accountName = rawAccountName === null || rawAccountName === undefined
    || rawAccountName === ''
    ? null
    : canonicalText(rawAccountName, 128);
  const rawEmail = ownData(value, 'email');
  const email = canonicalEmail(rawEmail);
  const accessFingerprint = ownData(value, 'accessFingerprint');
  const availability = ownData(value, 'availability');
  const availabilityReason = ownData(value, 'availabilityReason');
  const strongIdentityKeys = canonicalStrongIdentities(
    ownData(value, 'strongIdentityKeys'),
    email,
  );
  const createValid = action === 'create'
    && remoteAccountId === null
    && /^free\d{5}$/.test(accountName || '')
    && accountName !== 'free00000'
    && availability === 'not_present'
    && availabilityReason === 'not_in_sub2api';
  const updateValid = action === 'update'
    && typeof remoteAccountId === 'number'
    && Number.isSafeInteger(remoteAccountId) && remoteAccountId > 0
    && availability === 'unavailable'
    && UNAVAILABLE_REASONS.has(availabilityReason);
  if (!sourcePath || typeof sourceContentHash !== 'string'
      || !/^[a-f0-9]{64}$/.test(sourceContentHash)
      || (rawAccountName !== null && rawAccountName !== undefined
        && rawAccountName !== '' && accountName === null)
      || (rawEmail !== null && email === null)
      || typeof accessFingerprint !== 'string'
      || !/^[a-f0-9]{16}$/.test(accessFingerprint)
      || !strongIdentityKeys || (!createValid && !updateValid)) return null;
  const normalized = {
    targetDigest: '',
    sourcePath,
    sourceContentHash,
    action,
    remoteAccountId,
    accountName,
    email,
    accessFingerprint,
    strongIdentityKeys,
    availability,
    availabilityReason,
  };
  const digest = targetDigest(normalized, bindings);
  return ownData(value, 'targetDigest') === digest
    ? { ...normalized, targetDigest: digest }
    : null;
}

function contextMaterial(context) {
  return {
    schema: context.schema,
    snapshotVersion: context.snapshotVersion,
    planIntentVersion: context.planIntentVersion,
    coverage: context.coverage,
    executionTarget: context.executionTarget,
    createGroupBinding: context.createGroupBinding,
    targets: context.targets,
  };
}

function manifestDigest(context) {
  return crypto.createHash('sha256')
    .update('gpt-register-panel/token-import-reconciliation-context/v1\0')
    .update(JSON.stringify(contextMaterial(context)))
    .digest('hex');
}

function normalizeTokenImportReconciliationContext(value) {
  const allowed = new Set([
    'schema', 'snapshotVersion', 'planIntentVersion', 'coverage', 'executionTarget',
    'createGroupBinding', 'targets', 'manifestDigest',
  ]);
  if (!exactObjectKeys(value, allowed)) return null;
  const schema = ownData(value, 'schema');
  const snapshotVersion = ownData(value, 'snapshotVersion');
  const planIntentVersion = ownData(value, 'planIntentVersion');
  const coverage = ownData(value, 'coverage');
  const rawTargets = ownData(value, 'targets');
  if (schema !== TOKEN_IMPORT_CONTEXT_SCHEMA
      || typeof snapshotVersion !== 'string' || !/^[a-f0-9]{64}$/.test(snapshotVersion)
      || typeof planIntentVersion !== 'string' || !PLAN_INTENT_PATTERN.test(planIntentVersion)
      || coverage !== TOKEN_IMPORT_CONTEXT_COVERAGE
      || !Array.isArray(rawTargets) || rawTargets.length === 0
      || rawTargets.length > MAX_TOKEN_IMPORT_CONTEXT_TARGETS) return null;
  const hasCreates = rawTargets.some((target) => ownData(target, 'action') === 'create');
  const executionTarget = normalizeExecutionTarget(ownData(value, 'executionTarget'));
  const createGroupBinding = normalizeCreateGroupBinding(
    ownData(value, 'createGroupBinding'),
    hasCreates,
  );
  if (!executionTarget || !createGroupBinding) return null;
  const bindings = { executionTarget, createGroupBinding };
  const targets = rawTargets.map((target) => (
    normalizeTokenImportTarget(target, bindings)
  ));
  if (targets.some((target) => !target)) return null;
  const paths = new Set();
  const identities = [];
  const remoteIds = new Set();
  const createNames = new Set();
  const digests = new Set();
  for (const target of targets) {
    if (paths.has(target.sourcePath) || digests.has(target.targetDigest)
        || identities.some((keys) => (
          strongIdentitiesCompatible(target.strongIdentityKeys, keys)
        ))) return null;
    paths.add(target.sourcePath);
    digests.add(target.targetDigest);
    identities.push(target.strongIdentityKeys);
    if (target.action === 'update') {
      if (remoteIds.has(target.remoteAccountId)) return null;
      remoteIds.add(target.remoteAccountId);
    } else {
      if (createNames.has(target.accountName)) return null;
      createNames.add(target.accountName);
    }
  }
  const normalized = {
    schema,
    snapshotVersion,
    planIntentVersion,
    coverage,
    executionTarget,
    createGroupBinding,
    targets,
    manifestDigest: '',
  };
  const digest = manifestDigest(normalized);
  return ownData(value, 'manifestDigest') === digest
    ? { ...normalized, manifestDigest: digest }
    : null;
}

function buildTokenImportReconciliationContext(plan, options = {}) {
  if (!Array.isArray(plan) || plan.length === 0) {
    throw contextError('导入对账目标为空，拒绝开始写任务');
  }
  if (plan.length > MAX_TOKEN_IMPORT_CONTEXT_TARGETS) {
    throw contextError(
      '导入目标超过单次安全对账上限，拒绝开始写任务',
      'IMPORT_RECONCILIATION_TARGET_LIMIT',
    );
  }
  const hasCreates = plan.some((item) => ownData(item, 'action') === 'create');
  const createGroupBinding = normalizeCreateGroupBinding(
    ownData(options, 'groupBinding'),
    hasCreates,
  );
  if (!createGroupBinding) {
    throw contextError('导入目标缺少安全的 Sub2API 创建分组上下文，拒绝开始写任务');
  }
  const executionTarget = normalizeExecutionTarget(
    ownData(ownData(options, 'executionBinding'), 'target'),
  );
  if (!executionTarget) {
    throw contextError('导入目标缺少安全的 Sub2API 执行目标指纹，拒绝开始写任务');
  }
  const bindings = { executionTarget, createGroupBinding };
  const targets = plan.map((item) => {
    const itemEmail = ownData(item, 'email');
    const email = itemEmail === '' || itemEmail === null || itemEmail === undefined
      ? null
      : canonicalEmail(itemEmail);
    if (itemEmail !== '' && itemEmail !== null && itemEmail !== undefined && !email) {
      throw contextError('导入目标邮箱无法形成安全对账上下文，拒绝开始写任务');
    }
    const itemAccountName = ownData(item, 'accountName');
    const accountName = itemAccountName === '' || itemAccountName === null
      || itemAccountName === undefined
      ? null
      : canonicalText(itemAccountName, 128);
    if (itemAccountName !== '' && itemAccountName !== null
        && itemAccountName !== undefined && !accountName) {
      throw contextError('导入目标名称无法形成安全对账上下文，拒绝开始写任务');
    }
    const strongIdentityKeys = canonicalStrongIdentities(
      ownData(item, 'sourceIdentityKeys'),
      email,
    );
    const rawTarget = {
      targetDigest: '',
      sourcePath: sourcePathFromPlanItem(item),
      sourceContentHash: ownData(ownData(item, '_record'), 'contentHash'),
      action: ownData(item, 'action'),
      remoteAccountId: ownData(item, 'accountId'),
      accountName,
      email,
      accessFingerprint: ownData(ownData(item, 'fingerprints'), 'access'),
      strongIdentityKeys,
      availability: ownData(item, 'availability'),
      availabilityReason: ownData(item, 'availabilityReason'),
    };
    rawTarget.targetDigest = targetDigest(rawTarget, bindings);
    const normalized = normalizeTokenImportTarget(rawTarget, bindings);
    if (!normalized) throw contextError('导入目标无法形成安全对账上下文，拒绝开始写任务');
    return normalized;
  });
  const rawContext = {
    schema: TOKEN_IMPORT_CONTEXT_SCHEMA,
    snapshotVersion: ownData(options, 'snapshotVersion'),
    planIntentVersion: ownData(options, 'planIntentVersion'),
    coverage: TOKEN_IMPORT_CONTEXT_COVERAGE,
    executionTarget,
    createGroupBinding,
    targets,
    manifestDigest: '',
  };
  rawContext.manifestDigest = manifestDigest(rawContext);
  const normalized = normalizeTokenImportReconciliationContext(rawContext);
  if (!normalized) throw contextError('导入对账上下文不满足完整性约束，拒绝开始写任务');
  return normalized;
}

function normalizeReconciliationContext(type, value) {
  if (type !== 'token_import') return null;
  return normalizeTokenImportReconciliationContext(value);
}

function serializeReconciliationContext(type, value) {
  const normalized = normalizeReconciliationContext(type, value);
  if (!normalized) throw contextError('任务对账上下文无效，拒绝开始写任务');
  const serialized = JSON.stringify(normalized);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_RECONCILIATION_CONTEXT_BYTES) {
    throw contextError('任务对账上下文超过安全上限，拒绝开始写任务');
  }
  return serialized;
}

function parseReconciliationContext(type, serialized) {
  if (typeof serialized !== 'string'
      || Buffer.byteLength(serialized, 'utf8') > MAX_RECONCILIATION_CONTEXT_BYTES) return null;
  let parsed;
  try { parsed = JSON.parse(serialized); } catch { return null; }
  const normalized = normalizeReconciliationContext(type, parsed);
  return normalized && JSON.stringify(normalized) === serialized ? normalized : null;
}

module.exports = {
  MAX_RECONCILIATION_CONTEXT_BYTES,
  MAX_TOKEN_IMPORT_CREATE_GROUP_IDS,
  MAX_TOKEN_IMPORT_CONTEXT_TARGETS,
  TOKEN_IMPORT_CONTEXT_COVERAGE,
  TOKEN_IMPORT_CONTEXT_SCHEMA,
  buildTokenImportReconciliationContext,
  normalizeReconciliationContext,
  parseReconciliationContext,
  serializeReconciliationContext,
};
