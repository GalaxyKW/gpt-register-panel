const assert = require('node:assert/strict');
const test = require('node:test');

require('./test-isolation');

const {
  MAX_TOKEN_IMPORT_CONTEXT_TARGETS,
  TOKEN_IMPORT_CONTEXT_COVERAGE,
  TOKEN_IMPORT_CONTEXT_SCHEMA,
  buildTokenImportReconciliationContext,
  normalizeReconciliationContext,
  parseReconciliationContext,
  serializeReconciliationContext,
} = require('../backend/reconciliationContext');

const SNAPSHOT_VERSION = 'a'.repeat(64);
const PLAN_INTENT_VERSION = `sync-plan-v1.${'B'.repeat(43)}`;
const EXECUTION_BINDING = {
  target: {
    schema: 'sub2api-admin-target-v1',
    fingerprint: `sha256.${'T'.repeat(43)}`,
  },
};

function importPlanItem(index, options = {}) {
  const sequence = String(index).padStart(5, '0');
  const email = Object.hasOwn(options, 'email')
    ? options.email
    : `account-${sequence}@example.test`;
  const sourceIdentityKeys = Object.hasOwn(options, 'sourceIdentityKeys')
    ? options.sourceIdentityKeys
    : [
      `account:account-${sequence}`,
      `user:user-${sequence}`,
      ...(email === null ? [] : [`email:${email}`]),
    ];
  const item = {
    source: 'tokens',
    relativePath: `account-${sequence}.json`,
    action: 'create',
    accountId: null,
    accountName: `free${sequence}`,
    email,
    sourceIdentityKeys,
    fingerprints: { access: index.toString(16).padStart(16, '0') },
    availability: 'not_present',
    availabilityReason: 'not_in_sub2api',
    _record: { contentHash: index.toString(16).padStart(64, '0') },
  };
  return {
    ...item,
    ...options,
    fingerprints: { ...item.fingerprints, ...options.fingerprints },
    _record: { ...item._record, ...options._record },
  };
}

function buildContext(plan, options = {}) {
  const hasCreates = plan.some((item) => item.action === 'create');
  return buildTokenImportReconciliationContext(plan, {
    snapshotVersion: SNAPSHOT_VERSION,
    planIntentVersion: PLAN_INTENT_VERSION,
    groupBinding: hasCreates
      ? { mode: 'explicit', groupIds: [7] }
      : { mode: 'not_applicable', groupIds: [] },
    executionBinding: EXECUTION_BINDING,
    ...options,
  });
}

function collectObjectKeys(value, destination = new Set()) {
  if (!value || typeof value !== 'object') return destination;
  if (Array.isArray(value)) {
    for (const item of value) collectObjectKeys(item, destination);
    return destination;
  }
  for (const [key, child] of Object.entries(value)) {
    destination.add(key);
    collectObjectKeys(child, destination);
  }
  return destination;
}

test('token import reconciliation context round-trips email and structured sk- strings', () => {
  const email = 'sk-live-user@example.test';
  const sourcePath = 'tokens/sk-live-structured-name.json';
  const context = buildContext([
    importPlanItem(7, {
      relativePath: 'sk-live-structured-name.json',
      email,
      sourceIdentityKeys: [
        'account:sk-account-structured',
        'user:sk-user-structured',
        `email:${email}`,
      ],
    }),
  ]);

  assert.equal(context.schema, TOKEN_IMPORT_CONTEXT_SCHEMA);
  assert.equal(context.coverage, TOKEN_IMPORT_CONTEXT_COVERAGE);
  assert.deepEqual(context.createGroupBinding, { mode: 'explicit', groupIds: [7] });
  assert.deepEqual(context.executionTarget, EXECUTION_BINDING.target);
  assert.equal(context.targets[0].sourcePath, sourcePath);
  assert.equal(context.targets[0].email, email);
  assert.deepEqual(context.targets[0].strongIdentityKeys, [
    'account:sk-account-structured',
    'user:sk-user-structured',
  ]);

  const serialized = serializeReconciliationContext('token_import', context);
  assert.match(serialized, /tokens\/sk-live-structured-name\.json/);
  assert.match(serialized, /sk-live-user@example\.test/);
  assert.deepEqual(parseReconciliationContext('token_import', serialized), context);
});

test('token import reconciliation context never persists raw credential fields or values', () => {
  const secretValues = [
    'test-only-raw-access-value',
    'test-only-raw-refresh-value',
    'test-only-raw-id-value',
    'test-only-password-value',
    'test-only-bearer-value',
  ];
  const item = importPlanItem(8, {
    access_token: secretValues[0],
    refresh_token: secretValues[1],
    _raw: {
      access_token: secretValues[0],
      refresh_token: secretValues[1],
      id_token: secretValues[2],
      password: secretValues[3],
      authorization: `Bearer ${secretValues[4]}`,
      credential: { secret: secretValues[0] },
    },
  });

  const context = buildContext([item]);
  const serialized = serializeReconciliationContext('token_import', context);
  const persistedKeys = collectObjectKeys(context);
  for (const forbiddenKey of [
    '_raw',
    'access_token',
    'refresh_token',
    'id_token',
    'password',
    'authorization',
    'credential',
  ]) {
    assert.equal(persistedKeys.has(forbiddenKey), false, forbiddenKey);
  }
  for (const secret of secretValues) assert.equal(serialized.includes(secret), false);
});

test('token import reconciliation context rejects credential-shaped display metadata', () => {
  const compactJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LW9ubHkifQ.signature12345';
  const genericCompactJwt = 'abcdefgh.ijklmnop.qrstuvwx';
  const safeMetadata = buildContext([
    importPlanItem(35, { relativePath: 'token_count=3.json' }),
    importPlanItem(36, {
      relativePath: `access_token_sha256=${'a'.repeat(64)}.json`,
    }),
  ]);
  assert.equal(safeMetadata.targets.length, 2);
  for (const item of [
    importPlanItem(25, { relativePath: compactJwt + '.json' }),
    importPlanItem(26, { relativePath: genericCompactJwt + '.json' }),
    importPlanItem(27, { relativePath: 'Bearer test-only-canary.json' }),
    importPlanItem(28, { relativePath: 'Basic test-only-canary.json' }),
    importPlanItem(29, { relativePath: 'access_token=test-only-canary.json' }),
    importPlanItem(30, { relativePath: 'password=test-only-canary.json' }),
    importPlanItem(31, { relativePath: 'api_key=test-only-canary.json' }),
    importPlanItem(32, { relativePath: 'credential=test-only-canary.json' }),
    importPlanItem(33, { sourceIdentityKeys: [`account:${compactJwt}`] }),
    importPlanItem(34, {
      sourceIdentityKeys: [`account:${'opaque9'.repeat(16)}`],
    }),
  ]) {
    assert.throws(
      () => buildContext([item]),
      (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_INVALID',
    );
  }
});

test('token import reconciliation context rejects tampering and unknown fields', () => {
  const context = buildContext([importPlanItem(9)]);

  const tamperedTarget = structuredClone(context);
  tamperedTarget.targets[0].accountName = 'free99999';
  assert.equal(normalizeReconciliationContext('token_import', tamperedTarget), null);

  const tamperedManifest = { ...context, manifestDigest: '0'.repeat(64) };
  assert.equal(normalizeReconciliationContext('token_import', tamperedManifest), null);

  const unknownContextField = { ...context, access_token: 'test-only-injected-value' };
  assert.equal(normalizeReconciliationContext('token_import', unknownContextField), null);

  const unknownTargetField = structuredClone(context);
  unknownTargetField.targets[0].credential = 'test-only-injected-value';
  assert.equal(normalizeReconciliationContext('token_import', unknownTargetField), null);

  const tamperedGroup = structuredClone(context);
  tamperedGroup.createGroupBinding.groupIds[0] = 8;
  assert.equal(normalizeReconciliationContext('token_import', tamperedGroup), null);

  const tamperedExecutionTarget = structuredClone(context);
  tamperedExecutionTarget.executionTarget.fingerprint = `sha256.${'U'.repeat(43)}`;
  assert.equal(normalizeReconciliationContext('token_import', tamperedExecutionTarget), null);
});

test('token import reconciliation context rejects duplicate targets', () => {
  const first = importPlanItem(10);
  const duplicate = {
    ...importPlanItem(11),
    relativePath: first.relativePath,
  };

  assert.throws(
    () => buildContext([first, duplicate]),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_INVALID',
  );
});

test('token import reconciliation context distinguishes users within a shared account', () => {
  const sharedAccount = buildContext([
    importPlanItem(19, {
      sourceIdentityKeys: ['account:workspace-a', 'user:user-1'],
    }),
    importPlanItem(20, {
      sourceIdentityKeys: ['account:workspace-a', 'user:user-2'],
    }),
  ]);
  assert.equal(sharedAccount.targets.length, 2);

  const sharedUser = buildContext([
    importPlanItem(21, {
      sourceIdentityKeys: ['account:workspace-a', 'user:shared-user'],
    }),
    importPlanItem(22, {
      sourceIdentityKeys: ['account:workspace-b', 'user:shared-user'],
    }),
  ]);
  assert.equal(sharedUser.targets.length, 2);

  assert.throws(
    () => buildContext([
      importPlanItem(23, {
        sourceIdentityKeys: ['account:workspace-a', 'user:user-1'],
      }),
      importPlanItem(24, {
        sourceIdentityKeys: ['account:workspace-a'],
      }),
    ]),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_INVALID',
  );
});

test('token import reconciliation context canonicalizes a missing update name without digest drift', () => {
  const context = buildContext([
    importPlanItem(12, {
      action: 'update',
      accountId: 412,
      accountName: '',
      availability: 'unavailable',
      availabilityReason: 'sub2api_status_error',
    }),
  ]);
  assert.equal(context.targets[0].accountName, null);
  assert.deepEqual(context.createGroupBinding, { mode: 'not_applicable', groupIds: [] });
  assert.deepEqual(
    parseReconciliationContext(
      'token_import',
      serializeReconciliationContext('token_import', context),
    ),
    context,
  );
});

test('token import reconciliation context rejects rather than erases an invalid nonempty email', () => {
  assert.throws(
    () => buildContext([importPlanItem(13, {
      email: 'NOT AN EMAIL',
      sourceIdentityKeys: ['account:account-00013', 'user:user-00013'],
    })]),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_INVALID',
  );
});

test('token import reconciliation context rejects the reserved zero free-account name', () => {
  assert.throws(
    () => buildContext([importPlanItem(18, { accountName: 'free00000' })]),
    (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_INVALID',
  );
});

test('token import reconciliation context accepts 100 targets and rejects 101', () => {
  const maximumPlan = Array.from(
    { length: MAX_TOKEN_IMPORT_CONTEXT_TARGETS },
    (_, index) => importPlanItem(index + 1),
  );
  const context = buildContext(maximumPlan);

  assert.equal(context.targets.length, 100);
  assert.deepEqual(
    parseReconciliationContext(
      'token_import',
      serializeReconciliationContext('token_import', context),
    ),
    context,
  );

  assert.throws(
    () => buildContext([...maximumPlan, importPlanItem(101)]),
    (error) => error.code === 'IMPORT_RECONCILIATION_TARGET_LIMIT',
  );
});

test('token import reconciliation context binds create groups and execution target into digests', () => {
  const plan = [importPlanItem(14)];
  const first = buildContext(plan);
  const otherGroup = buildContext(plan, {
    groupBinding: { mode: 'explicit', groupIds: [8] },
  });
  const defaultGroup = buildContext(plan, {
    groupBinding: { mode: 'sub2api_default', groupIds: [7] },
  });
  const otherTarget = buildContext(plan, {
    executionBinding: {
      target: {
        schema: 'sub2api-admin-target-v1',
        fingerprint: `sha256.${'U'.repeat(43)}`,
      },
    },
  });

  for (const changed of [otherGroup, defaultGroup, otherTarget]) {
    assert.notEqual(changed.targets[0].targetDigest, first.targets[0].targetDigest);
    assert.notEqual(changed.manifestDigest, first.manifestDigest);
  }
});

test('token import reconciliation context enforces canonical bounded group bindings', () => {
  const plan = [importPlanItem(15)];
  const maximumIds = Array.from({ length: 1000 }, (_, index) => index + 1);
  const maximum = buildContext(plan, {
    groupBinding: { mode: 'explicit', groupIds: maximumIds },
  });
  assert.equal(maximum.createGroupBinding.groupIds.length, 1000);
  assert.ok(Buffer.byteLength(serializeReconciliationContext('token_import', maximum), 'utf8')
    < 1024 * 1024);

  for (const groupBinding of [
    { mode: 'explicit', groupIds: [] },
    { mode: 'explicit', groupIds: [2, 1] },
    { mode: 'explicit', groupIds: [1, 1] },
    { mode: 'explicit', groupIds: ['1'] },
    { mode: 'sub2api_default', groupIds: [0] },
    { mode: 'not_applicable', groupIds: [1] },
    { mode: 'explicit', groupIds: [...maximumIds, 1001] },
  ]) {
    assert.throws(
      () => buildContext(plan, { groupBinding }),
      (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_INVALID',
    );
  }
});

test('token import reconciliation context rejects surrogate ambiguity and noncanonical JSON', () => {
  for (const item of [
    importPlanItem(16, { relativePath: `ambiguous-\ud800.json` }),
    importPlanItem(16, {
      email: `ambiguous-\ud800@example.test`,
      sourceIdentityKeys: ['account:account-00016', 'user:user-00016'],
    }),
    importPlanItem(16, {
      sourceIdentityKeys: [`account:ambiguous-\ud800`, 'user:user-00016'],
    }),
  ]) {
    assert.throws(
      () => buildContext([item]),
      (error) => error.code === 'JOB_RECONCILIATION_CONTEXT_INVALID',
    );
  }

  const context = buildContext([importPlanItem(17)]);
  const serialized = serializeReconciliationContext('token_import', context);
  assert.equal(parseReconciliationContext('token_import', ` ${serialized}`), null);
});
