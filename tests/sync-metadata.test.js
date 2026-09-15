const test = require('node:test');
const assert = require('node:assert/strict');

require('./test-isolation');

const {
  buildOAuthUpdatePayload,
  buildCodexSessionDocument,
  executeImportPlanItem,
  resolveImportCreatePolicy,
} = require('../backend/sync');
const { tokenFingerprint } = require('../backend/lib/token');

function importItem(raw = {}) {
  return {
    _raw: {
      access_token: 'test-only-access-value',
      refresh_token: 'test-only-refresh-value',
      account_id: 'metadata-account',
      user_id: 'metadata-user',
      ...raw,
    },
    _record: {
      accountId: 'metadata-account',
      userId: 'metadata-user',
      email: 'metadata@example.test',
    },
    sourceIdentityKeys: ['account:metadata-account', 'user:metadata-user'],
    email: 'metadata@example.test',
    expiresAt: '2099-02-03T04:05:06.000Z',
  };
}

test('OAuth update accepts normalized camel metadata aliases', () => {
  const payload = buildOAuthUpdatePayload(importItem({
    last_refresh: '',
    lastRefresh: '2099-01-02T03:04:05.000Z',
    token_type: null,
    tokenType: 'Bearer',
  }));

  assert.equal(payload.credentials.last_refresh, '2099-01-02T03:04:05.000Z');
  assert.equal(payload.credentials.token_type, 'Bearer');

  assert.throws(
    () => buildOAuthUpdatePayload(importItem({
      token_type: 'Bearer',
      tokenType: 'Basic',
    })),
    (error) => error.code === 'SOURCE_CREDENTIAL_SCHEMA_INVALID',
  );
});

test('Codex create retains explicit plan and organization metadata', () => {
  const document = buildCodexSessionDocument(importItem({
    plan_type: 'free',
    organizationId: 'organization-explicit',
  }));

  assert.equal(document.plan_type, 'free');
  assert.equal(document.organization_id, 'organization-explicit');
  assert.equal(document.expires_at, '2099-02-03T04:05:06.000Z');
});

test('access-only update verifies that the existing refresh token was preserved', async () => {
  const identityKeys = ['account:metadata-account', 'user:metadata-user'];
  const oldAccess = tokenFingerprint('test-only-old-access');
  const oldRefresh = tokenFingerprint('test-only-old-refresh');
  const newAccess = tokenFingerprint('test-only-new-access');
  const before = {
    id: 71,
    name: 'free00071',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    identityKeys,
    tokenFingerprints: { access: oldAccess, refresh: oldRefresh },
    credentialPresence: { access: 'present', refresh: 'present', id: 'absent' },
  };
  const afterWithoutRefresh = {
    ...before,
    status: 'active',
    schedulable: true,
    tokenFingerprints: { access: newAccess, refresh: null },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'absent' },
  };
  const item = {
    ...importItem({
      access_token: 'test-only-new-access',
      refresh_token: '',
    }),
    action: 'update',
    accountId: 71,
    accountName: 'free00071',
    fingerprints: { access: newAccess, refresh: null, id: null },
    _record: {
      accountId: 'metadata-account',
      userId: 'metadata-user',
      identityKeys,
      fingerprints: { access: newAccess, refresh: null, id: null },
      raw: {
        access_token: 'test-only-new-access',
        account_id: 'metadata-account',
        user_id: 'metadata-user',
      },
    },
    _raw: {
      access_token: 'test-only-new-access',
      account_id: 'metadata-account',
      user_id: 'metadata-user',
    },
    _account: before,
  };
  let reads = 0;
  let writes = 0;

  await assert.rejects(
    executeImportPlanItem({
      item,
      logger: { checkpoint() { return true; } },
      client: {
        async getAccount() {
          reads += 1;
          return reads === 1 ? before : afterWithoutRefresh;
        },
        async applyOAuthCredentials() {
          writes += 1;
        },
      },
    }),
    (error) => error.code === 'SUB2API_IMPORT_VERIFY_REFRESH_PRESERVATION_MISMATCH'
      && error.requiresReconciliation === true,
  );
  assert.equal(writes, 1);

  const afterPreserved = {
    ...afterWithoutRefresh,
    tokenFingerprints: { access: newAccess, refresh: oldRefresh },
    credentialPresence: { access: 'present', refresh: 'present', id: 'absent' },
  };
  reads = 0;
  const verified = await executeImportPlanItem({
    item,
    logger: { checkpoint() { return true; } },
    client: {
      async getAccount() {
        reads += 1;
        return reads === 1 ? before : afterPreserved;
      },
      async applyOAuthCredentials() {},
    },
  });
  assert.equal(verified.skipped, false);
  assert.equal(verified.verification.accountId, 71);

  const afterWithConflictingPresence = {
    ...afterPreserved,
    credentialPresence: { access: 'present', refresh: 'conflict', id: 'absent' },
  };
  reads = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      logger: { checkpoint() { return true; } },
      client: {
        async getAccount() {
          reads += 1;
          return reads === 1 ? before : afterWithConflictingPresence;
        },
        async applyOAuthCredentials() {},
      },
    }),
    (error) => error.code === 'SUB2API_TARGET_SCHEMA_INVALID'
      && error.requiresReconciliation === true,
  );

  const { credentialPresence: ignored, ...afterWithoutPresence } = afterPreserved;
  reads = 0;
  let missingPresenceWrites = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      logger: { checkpoint() { return true; } },
      client: {
        async getAccount() {
          reads += 1;
          return reads === 1 ? before : afterWithoutPresence;
        },
        async applyOAuthCredentials() { missingPresenceWrites += 1; },
      },
    }),
    (error) => error.code === 'SUB2API_TARGET_SCHEMA_INVALID'
      && error.requiresReconciliation === true,
  );
  assert.equal(missingPresenceWrites, 1);
});

test('update verifies that a supplied id token is present after the write', async () => {
  const identityKeys = ['account:metadata-account', 'user:metadata-user'];
  const oldAccess = tokenFingerprint('test-only-old-access');
  const newAccess = tokenFingerprint('test-only-new-access');
  const newId = tokenFingerprint('test-only-new-id');
  const before = {
    id: 72,
    name: 'free00072',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    identityKeys,
    tokenFingerprints: { access: oldAccess, refresh: null, id: null },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'absent' },
  };
  const afterWithoutId = {
    ...before,
    status: 'active',
    schedulable: true,
    tokenFingerprints: { access: newAccess, refresh: null, id: null },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'absent' },
  };
  const item = {
    ...importItem({
      access_token: 'test-only-new-access',
      refresh_token: '',
      id_token: 'test-only-new-id',
    }),
    action: 'update',
    accountId: 72,
    accountName: 'free00072',
    fingerprints: { access: newAccess, refresh: null, id: newId },
    _record: {
      accountId: 'metadata-account',
      userId: 'metadata-user',
      identityKeys,
      fingerprints: { access: newAccess, refresh: null, id: newId },
    },
    _account: before,
  };
  let reads = 0;

  await assert.rejects(
    executeImportPlanItem({
      item,
      logger: { checkpoint() { return true; } },
      client: {
        async getAccount() {
          reads += 1;
          return reads === 1 ? before : afterWithoutId;
        },
        async applyOAuthCredentials() {},
      },
    }),
    (error) => error.code === 'SUB2API_IMPORT_VERIFY_ID_TOKEN_MISMATCH'
      && error.requiresReconciliation === true,
  );

  const targetWithChangedId = {
    ...before,
    tokenFingerprints: { ...before.tokenFingerprints, id: newId },
    credentialPresence: { ...before.credentialPresence, id: 'present' },
  };
  let writes = 0;
  await assert.rejects(
    executeImportPlanItem({
      item,
      logger: { checkpoint() { return true; } },
      client: {
        async getAccount() { return targetWithChangedId; },
        async applyOAuthCredentials() { writes += 1; },
      },
    }),
    (error) => error.code === 'SUB2API_TARGET_CHANGED'
      && error.requiresReconciliation !== true,
  );
  assert.equal(writes, 0);
});

test('create postflight requires complete credential presence metadata', async () => {
  const raw = {
    access_token: 'test-only-create-access',
    refresh_token: 'test-only-create-refresh',
    id_token: 'test-only-create-id',
    account_id: 'metadata-account',
    user_id: 'metadata-user',
  };
  const fingerprints = {
    access: tokenFingerprint(raw.access_token),
    refresh: tokenFingerprint(raw.refresh_token),
    id: tokenFingerprint(raw.id_token),
  };
  const item = {
    ...importItem(raw),
    action: 'create',
    accountName: 'free00074',
    fingerprints,
    _record: {
      accountId: 'metadata-account',
      userId: 'metadata-user',
      fingerprints,
    },
    _raw: raw,
  };
  const createdWithoutPresence = {
    id: 74,
    name: item.accountName,
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'active',
    statusKnown: true,
    schedulable: true,
    schedulableKnown: true,
    identityKeys: item.sourceIdentityKeys,
    tokenFingerprints: fingerprints,
    groupIds: [4],
  };
  let writes = 0;

  await assert.rejects(
    executeImportPlanItem({
      item,
      groups: [4],
      createPolicy: resolveImportCreatePolicy([item], {
        SUB2API_CONFIRM_MIXED_CHANNEL_RISK: '1',
      }),
      logger: { checkpoint() { return true; } },
      client: {
        async listAccounts() { return []; },
        async importCodexSession() {
          writes += 1;
          return {
            total: 1,
            created: 1,
            updated: 0,
            skipped: 0,
            failed: 0,
            items: [{ index: 1, action: 'created', account_id: 74 }],
          };
        },
        async getAccount() { return createdWithoutPresence; },
      },
    }),
    (error) => error.code === 'SUB2API_TARGET_SCHEMA_INVALID'
      && error.requiresReconciliation === true,
  );
  assert.equal(writes, 1);
});

test('conflicting source metadata stops before the remote update', async () => {
  const identityKeys = ['account:metadata-account', 'user:metadata-user'];
  const oldAccess = tokenFingerprint('test-only-old-access');
  const newAccess = tokenFingerprint('test-only-new-access');
  const before = {
    id: 73,
    name: 'free00073',
    platform: 'openai',
    type: 'oauth',
    schemaValid: true,
    status: 'error',
    statusKnown: true,
    schedulable: false,
    schedulableKnown: true,
    identityKeys,
    tokenFingerprints: { access: oldAccess, refresh: null, id: null },
    credentialPresence: { access: 'present', refresh: 'absent', id: 'absent' },
  };
  const conflicts = [
    { last_refresh: '2099-01-01T00:00:00.000Z', lastRefresh: '2099-01-02T00:00:00.000Z' },
    { plan_type: 'free', chatgpt_plan_type: 'pro' },
    { organization_id: 'organization-a', organizationId: 'organization-b' },
  ];

  for (const conflict of conflicts) {
    const raw = {
      access_token: 'test-only-new-access',
      account_id: 'metadata-account',
      user_id: 'metadata-user',
      ...conflict,
    };
    const item = {
      ...importItem(raw),
      action: 'update',
      accountId: 73,
      accountName: 'free00073',
      fingerprints: { access: newAccess, refresh: null, id: null },
      _record: {
        accountId: 'metadata-account',
        userId: 'metadata-user',
        identityKeys,
        fingerprints: { access: newAccess, refresh: null, id: null },
      },
      _raw: raw,
      _account: before,
    };
    let writes = 0;
    await assert.rejects(
      executeImportPlanItem({
        item,
        logger: { checkpoint() { return true; } },
        client: {
          async getAccount() { return before; },
          async applyOAuthCredentials() { writes += 1; },
        },
      }),
      (error) => error.code === 'SOURCE_CREDENTIAL_SCHEMA_INVALID'
        && error.requiresReconciliation !== true,
    );
    assert.equal(writes, 0);
  }
});
