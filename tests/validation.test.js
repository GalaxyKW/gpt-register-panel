const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

require('./test-isolation');

const {
  normalizedSelectedKeys,
  requestBodyObjectError,
  normalizePhase3Requests,
  authorizationError,
  requestActor,
  validateListenConfiguration,
} = require('../backend/server');
const { safeImportResult, buildSnapshot } = require('../backend/sync');
const { normalizeTokenDocument, tokenCredentialField } = require('../backend/lib/token');
const {
  normalizePhase3CanonicalKeys,
  normalizePhase3Phone,
  normalizePhase3RelativePath,
  normalizePhase3SelectedKey,
  phase3SelectedKeyForToken,
} = require('../backend/lib/phase3Identity');
const { canonicalPhase3Target } = require('../backend/phase3TargetRevision');
const { buildDiff } = require('../backend/diff');
const { PanelDb } = require('../backend/db');
const { findUsernameEntry, persistAccountDisposition } = require('../backend/phase3Worker');
const { withControlPlaneLock } = require('../backend/taskCoordinator');

function waitForChildMessage(child, expectedType, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('timed out waiting for child message: ' + expectedType));
    }, timeoutMs);
    const onMessage = (message) => {
      if (message?.type !== expectedType) return;
      cleanup();
      resolve(message);
    };
    const onExit = (code, signal) => {
      cleanup();
      reject(new Error('child exited before ' + expectedType + ': ' + String(code) + '/' + String(signal)));
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.off('message', onMessage);
      child.off('exit', onExit);
    };
    child.on('message', onMessage);
    child.on('exit', onExit);
  });
}

function waitForChildExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('timed out waiting for child exit'));
    }, timeoutMs);
    const onExit = (code, signal) => {
      cleanup();
      resolve({ code, signal });
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.off('exit', onExit);
    };
    child.on('exit', onExit);
  });
}

test('preview selection accepts an empty array but rejects blank or oversized input', () => {
  assert.deepEqual(normalizedSelectedKeys([], { allowEmpty: true }), []);
  assert.equal(normalizedSelectedKeys(['   '], { allowEmpty: true }), null);
  assert.equal(normalizedSelectedKeys([], { allowEmpty: false }), null);
  assert.equal(normalizedSelectedKeys(Array.from({ length: 501 }, (_, index) => String(index)), { allowEmpty: true }), null);
  assert.equal(normalizedSelectedKeys([' account:1 ', 'account:1'], { allowEmpty: false }), null);
  assert.equal(normalizedSelectedKeys(['account:1', 'account:1'], { allowEmpty: false }), null);
  assert.deepEqual(normalizedSelectedKeys(['account:1'], { allowEmpty: false }), ['account:1']);
});

test('JSON API body validation rejects scalar values', () => {
  assert.equal(requestBodyObjectError({}), null);
  assert.equal(requestBodyObjectError(null)?.code, 'INVALID_REQUEST_BODY');
  assert.equal(requestBodyObjectError('body')?.code, 'INVALID_REQUEST_BODY');
  assert.equal(requestBodyObjectError([])?.code, 'INVALID_REQUEST_BODY');
});

test('Phase3 phone normalization accepts legacy punctuation but rejects lossy input', () => {
  assert.equal(normalizePhase3Phone(' +86 (138) 0013-8000. '), '8613800138000');
  assert.equal(normalizePhase3Phone('1'), '1');
  assert.equal(normalizePhase3Phone(''), '');
  for (const value of [
    '138abc0000',
    '138\t0000',
    '138\u00850000',
    '138\u00a00000',
    '138\u200b0000',
    '138\u202e0000',
    ' +().- ',
    '1'.repeat(81),
    1380000,
    null,
    {},
  ]) {
    assert.equal(normalizePhase3Phone(value), null, String(value));
  }
  assert.equal(normalizePhase3Phone(1380000, { allowNumber: true }), '1380000');
});

test('Phase3 token selection keys are exact bounded source-relative JSON paths', () => {
  const valid = [
    'token:tokens:tokens/account.json',
    'token:use_token:use_token/nested/account.JSON',
    'token:tokens:tokens/账号 01.json',
  ];
  for (const key of valid) assert.equal(normalizePhase3SelectedKey(key), key);
  assert.equal(normalizePhase3RelativePath('tokens/account.JSON', 'tokens'), 'tokens/account.JSON');
  assert.equal(phase3SelectedKeyForToken({
    source: 'tokens',
    relativePath: 'tokens/account.json',
  }), 'token:tokens:tokens/account.json');
  for (const key of [
    '',
    ' token:tokens:tokens/account.json',
    'token:tokens:tokens/account.json ',
    'token:tokens:use_token/account.json',
    'token:other:other/account.json',
    'token:tokens:/tokens/account.json',
    'token:tokens:tokens//account.json',
    'token:tokens:tokens/./account.json',
    'token:tokens:tokens/../account.json',
    'token:tokens:tokens\\account.json',
    'token:tokens:tokens/account.txt',
    'token:tokens:tokens/account\u0000.json',
    'token:tokens:tokens/account\u200b.json',
    'token:tokens:tokens/account\u202e.json',
    'token:tokens:tokens/' + 'a'.repeat(490) + '.json',
  ]) {
    assert.equal(normalizePhase3SelectedKey(key), null, key);
  }
});

test('Phase3 canonical key groups reject partial, duplicate, and noncanonical entries', () => {
  const required = ['email:one@example.test', 'phone:1380000'];
  assert.deepEqual(normalizePhase3CanonicalKeys([...required].reverse(), {
    requiredKeys: required,
  }), required);
  for (const value of [
    ['email:one@example.test'],
    ['email:one@example.test', 'phone:1380000', 'phone:1390000'],
    ['email:one@example.test', 'email:two@example.test'],
    ['email:ONE@example.test', 'phone:1380000'],
    ['email:one@example.test', 'phone:+1380000'],
    ['email:one@example.test', 'credential:opaque-value'],
    ['email:one@example.test', 'phone:138\u200b0000'],
  ]) {
    assert.equal(normalizePhase3CanonicalKeys(value, { requiredKeys: required }), null);
  }
});

test('Phase 3 accepts batches and removes duplicate email/phone targets', () => {
  const phase3TargetRevision = 'phase3-target-v1.' + 'A'.repeat(43);
  const batch = normalizePhase3Requests({
    accounts: [
      { email: ' One@example.test ', phone: '138-0000', selectedKey: 'token:tokens:tokens/one.json', phase3TargetRevision },
      { email: 'one@example.test', selectedKey: 'token:tokens:tokens/one-copy.json', phase3TargetRevision },
      { phone: '1380000', selectedKey: 'token:use_token:use_token/one.json', phase3TargetRevision },
      { email: 'two@example.test', selectedKey: 'token:tokens:tokens/two.json', phase3TargetRevision },
    ],
    selectedKeys: [
      'token:tokens:tokens/one.json',
      'token:tokens:tokens/one-copy.json',
      'token:use_token:use_token/one.json',
      'token:tokens:tokens/two.json',
    ],
  });
  assert.equal(batch.requests.length, 2);
  assert.deepEqual(batch.requests.map((item) => item.email), ['one@example.test', 'two@example.test']);
  assert.deepEqual(batch.duplicateIndexes, [1, 2]);
  assert.throws(
    () => normalizePhase3Requests({ accounts: [], selectedKeys: [] }),
    (error) => error.code === 'PHASE3_BATCH_INVALID',
  );
});

test('Phase 3 requires an exact one-to-one selected-key set', () => {
  const accounts = [{
    email: 'one@example.test',
    selectedKey: 'token:tokens:tokens/one.json',
    phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
  }];
  for (const body of [
    { accounts },
    { accounts, selectedKeys: [] },
    { accounts, selectedKeys: ['token:tokens:tokens/other.json'] },
    {
      accounts: [
        accounts[0],
        {
          email: 'two@example.test',
          selectedKey: 'token:tokens:tokens/two.json',
          phase3TargetRevision: 'phase3-target-v1.' + 'A'.repeat(43),
        },
      ],
      selectedKeys: [
        'token:tokens:tokens/two.json',
        'token:tokens:tokens/one.json',
      ],
    },
    { accounts: [...accounts, { ...accounts[0] }], selectedKeys: [
      'token:tokens:tokens/one.json',
      'token:tokens:tokens/one.json',
    ] },
  ]) {
    assert.throws(
      () => normalizePhase3Requests(body),
      (error) => error.code === 'PHASE3_SELECTION_INVALID',
    );
  }
});

test('Phase 3 rejects invalid explicit identity fields instead of dropping one side', () => {
  const selectedKey = 'token:tokens:tokens/one.json';
  const phase3TargetRevision = 'phase3-target-v1.' + 'A'.repeat(43);
  const invalidAccounts = [
    { email: 'not-an-email', phone: '1380000' },
    { email: 'one@example.test', phone: '138abc0000' },
    { email: 'one@example.test', phone: '138\u00a00000' },
    { email: 'one@example.test', phone: 1380000 },
    { email: ['one@example.test'], phone: '1380000' },
    { email: 'one@example.test', phone: null },
  ];
  for (const account of invalidAccounts) {
    assert.throws(
      () => normalizePhase3Requests({
        accounts: [{ ...account, selectedKey, phase3TargetRevision }],
        selectedKeys: [selectedKey],
      }),
      (error) => error.code === 'PHASE3_ACCOUNT_INVALID',
    );
  }
});

test('Phase3 target revisions reject malformed phone and token paths', () => {
  const base = {
    token: {
      source: 'tokens',
      relativePath: 'tokens/account.json',
      contentHash: 'a'.repeat(64),
      parseStatus: 'ok',
      historical: false,
      email: 'one@example.test',
      identityKeys: [],
    },
    username: {
      index: 0,
      email: 'one@example.test',
      phone: '+86 138-0000',
      status: 'oauth_done',
      hasPassword: true,
    },
    usernameContentHash: 'b'.repeat(64),
  };
  assert.ok(canonicalPhase3Target(base));
  assert.equal(canonicalPhase3Target({
    ...base,
    username: { ...base.username, phone: '138abc0000' },
  }), null);
  assert.equal(canonicalPhase3Target({
    ...base,
    token: { ...base.token, relativePath: 'tokens/../account.json' },
  }), null);
  assert.equal(canonicalPhase3Target({
    ...base,
    token: { ...base.token, relativePath: 'use_token/account.json' },
  }), null);
});

test('Phase 3 refuses missing or malformed snapshot target revisions', () => {
  const selectedKey = 'token:tokens:tokens/one.json';
  for (const phase3TargetRevision of [undefined, '', 'phase3-target-v1.short', 'account-test-v1.' + 'A'.repeat(43)]) {
    assert.throws(
      () => normalizePhase3Requests({
        accounts: [{ email: 'one@example.test', selectedKey, phase3TargetRevision }],
        selectedKeys: [selectedKey],
      }),
      (error) => error.code === 'PHASE3_TARGET_REVISION_INVALID',
    );
  }
});

test('token documents without usable credentials or identity are invalid', () => {
  const noAccess = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/no-access.json',
    fileName: 'no-access.json',
    mtimeMs: 1,
    data: { refresh_token: 'refresh-only', email: 'one@example.test' },
  });
  assert.equal(noAccess.parseStatus, 'invalid');
  assert.match(noAccess.parseError, /access_token/);

  const noIdentity = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/no-identity.json',
    fileName: 'no-identity.json',
    mtimeMs: 1,
    data: { access_token: 'opaque-access' },
  });
  assert.equal(noIdentity.parseStatus, 'invalid');
  assert.match(noIdentity.parseError, /身份/);
});

test('token documents reject nested, oversized, and non-Codex credential fields', () => {
  const cases = [
    {
      relativePath: 'tokens/nested-access.json',
      sensitive: 'nested-access-value',
      data: {
        access_token: { credential: 'nested-access-value' },
        email: 'one@example.test',
      },
    },
    {
      relativePath: 'tokens/nested-identity.json',
      sensitive: 'nested-account-value',
      data: {
        access_token: 'opaque-access',
        account_id: { credential: 'nested-account-value' },
      },
    },
    {
      relativePath: 'tokens/nested-refresh.json',
      sensitive: 'nested-refresh-value',
      data: {
        access_token: 'opaque-access',
        refresh_token: { credential: 'nested-refresh-value' },
        email: 'one@example.test',
      },
    },
    {
      relativePath: 'tokens/nested-type.json',
      sensitive: 'nested-type-value',
      data: {
        access_token: 'opaque-access',
        email: 'one@example.test',
        type: { credential: 'nested-type-value' },
      },
    },
    {
      relativePath: 'tokens/unsupported-type.json',
      data: {
        access_token: 'opaque-access',
        email: 'one@example.test',
        type: 'another-provider',
      },
    },
    {
      relativePath: 'tokens/oversized-email.json',
      data: {
        access_token: 'opaque-access',
        email: 'x'.repeat(321),
      },
    },
  ];
  for (const item of cases) {
    const token = normalizeTokenDocument({
      source: 'tokens',
      relativePath: item.relativePath,
      fileName: path.basename(item.relativePath),
      mtimeMs: 1,
      data: item.data,
    });
    assert.equal(token.parseStatus, 'invalid', item.relativePath);
    if (item.sensitive) {
      assert.equal(JSON.stringify(token).includes(item.sensitive), false, item.relativePath);
    }
  }
});

test('token identities reject C0 and DEL while credentials reject line controls', () => {
  const jwtWithControlledIdentity = [
    'header',
    Buffer.from(JSON.stringify({ sub: 'claim-lure\nsubject' })).toString('base64url'),
    'signature',
  ].join('.');
  const cases = [
    {
      label: 'access CRLF',
      data: { access_token: 'access-lure\r\nInjected: value', email: 'safe@example.test' },
    },
    {
      label: 'refresh NUL',
      data: { access_token: 'opaque-access', refresh_token: 'refresh-lure\0tail', email: 'safe@example.test' },
    },
    {
      label: 'identity DEL',
      data: { access_token: 'opaque-access', account_id: 'account-lure\u007fhidden' },
    },
    {
      label: 'identity tab',
      data: { access_token: 'opaque-access', email: 'safe\t@example.test' },
    },
    {
      label: 'email bidi override',
      data: { access_token: 'opaque-access', email: 'safe\u202e@example.test' },
    },
    {
      label: 'JWT email zero-width separator',
      data: {
        access_token: [
          'header',
          Buffer.from(JSON.stringify({ email: 'safe\u200b@example.test' })).toString('base64url'),
          'signature',
        ].join('.'),
      },
    },
    {
      label: 'JWT claim control',
      data: { access_token: jwtWithControlledIdentity },
    },
  ];
  for (const item of cases) {
    const token = normalizeTokenDocument({
      source: 'tokens',
      relativePath: 'tokens/control.json',
      fileName: 'control.json',
      mtimeMs: 1,
      data: item.data,
    });
    assert.equal(token.parseStatus, 'invalid', item.label);
    assert.equal(token.parseError, 'token 字段类型或长度无效', item.label);
    for (const lure of ['access-lure', 'refresh-lure', 'account-lure', 'claim-lure']) {
      assert.equal(String(token.parseError).includes(lure), false, item.label);
    }
  }

  assert.deepEqual(
    tokenCredentialField({ access_token: 'header\r\nvalue' }, 'access'),
    { value: '', invalid: true },
  );
  assert.deepEqual(
    tokenCredentialField({ access_token: 'opaque-access' }, 'access'),
    { value: 'opaque-access', invalid: false },
  );
});

test('invalid expiry fields are surfaced separately and never treated as expired', () => {
  const token = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/invalid-expiry.json',
    fileName: 'invalid-expiry.json',
    mtimeMs: 1,
    data: {
      access_token: 'opaque-access',
      email: 'invalid-expiry@example.test',
      account_id: 'invalid-expiry-account',
      user_id: 'invalid-expiry-user',
      expired: 'not-a-date',
    },
  });
  assert.equal(token.parseStatus, 'ok');
  assert.equal(token.expiryStatus, 'invalid');
  const diff = buildDiff([token], []);
  assert.equal(diff.counts.expiry_invalid, 1);
  assert.equal(diff.items[0].issues[0], 'expiry_invalid');
});

test('token identity, expiry, refresh, and disabled aliases fail closed', () => {
  const jwt = (payload) => [
    'header',
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    'signature',
  ].join('.');
  const access = jwt({
    sub: 'issuer-subject',
    exp: Math.floor(Date.parse('2020-01-01T00:00:00.000Z') / 1000),
    'https://api.openai.com/auth': {
      chatgpt_account_id: 'jwt-account',
      chatgpt_user_id: 'jwt-user',
    },
  });

  const distinctIssuerSubject = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/distinct-issuer-subject.json',
    fileName: 'distinct-issuer-subject.json',
    mtimeMs: 1,
    data: { access_token: access },
  });
  assert.equal(distinctIssuerSubject.parseStatus, 'ok');
  assert.equal(distinctIssuerSubject.userId, 'jwt-user');

  const identityConflict = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/identity-conflict.json',
    fileName: 'identity-conflict.json',
    mtimeMs: 1,
    data: {
      access_token: access,
      account_id: 'different-account',
    },
  });
  assert.equal(identityConflict.parseStatus, 'invalid');
  assert.match(identityConflict.parseError, /强身份/);

  const idTokenConflict = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/id-token-conflict.json',
    fileName: 'id-token-conflict.json',
    mtimeMs: 1,
    data: {
      access_token: access,
      id_token: jwt({ sub: 'different-user' }),
    },
  });
  assert.equal(idTokenConflict.parseStatus, 'invalid');

  const earliestExpiry = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/earliest-expiry.json',
    fileName: 'earliest-expiry.json',
    mtimeMs: 1,
    data: {
      access_token: access,
      expired: '2099-01-01T00:00:00.000Z',
    },
  });
  assert.equal(earliestExpiry.parseStatus, 'ok');
  assert.equal(earliestExpiry.expiryStatus, 'valid');
  assert.equal(earliestExpiry.expiresAt, '2020-01-01T00:00:00.000Z');

  const invalidAlias = normalizeTokenDocument({
    source: 'tokens',
    relativePath: 'tokens/invalid-expiry-alias.json',
    fileName: 'invalid-expiry-alias.json',
    mtimeMs: 1,
    data: {
      access_token: jwt({ sub: 'expiry-alias-user' }),
      expired: '2099-01-01T00:00:00.000Z',
      expiresAt: 'invalid-date',
    },
  });
  assert.equal(invalidAlias.parseStatus, 'ok');
  assert.equal(invalidAlias.expiryStatus, 'invalid');

  for (const data of [
    {
      access_token: jwt({ sub: 'disabled-user' }),
      disabled: 'false',
    },
    {
      access_token: jwt({ sub: 'refresh-user' }),
      last_refresh: '2099-01-01T00:00:00.000Z',
      lastRefresh: '2098-01-01T00:00:00.000Z',
    },
  ]) {
    const token = normalizeTokenDocument({
      source: 'tokens',
      relativePath: 'tokens/invalid-alias.json',
      fileName: 'invalid-alias.json',
      mtimeMs: 1,
      data,
    });
    assert.equal(token.parseStatus, 'invalid');
  }
});

test('two PanelDb instances cannot claim the same target', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-claim-')), 'panel.sqlite3');
  const firstDb = new PanelDb(file);
  const secondDb = new PanelDb(file);
  const outcomes = await Promise.all([
    firstDb.createJob('token_import', {}, 'first', { claimKeys: ['token_import'] })
      .then((job) => ({ ok: true, job }))
      .catch((error) => ({ ok: false, error })),
    secondDb.createJob('token_import', {}, 'second', { claimKeys: ['token_import'] })
      .then((job) => ({ ok: true, job }))
      .catch((error) => ({ ok: false, error })),
  ]);
  assert.equal(outcomes.filter((item) => item.ok).length, 1);
  const rejected = outcomes.find((item) => !item.ok);
  assert.equal(rejected.error.code, 'JOB_ALREADY_CLAIMED');
  assert.equal((await firstDb.listJobs(10)).filter((job) => job.status === 'queued').length, 1);
});

test('PanelDb persist reloads the latest file instead of overwriting another instance', async () => {
  const file = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-fresh-persist-')),
    'panel.sqlite3',
  );
  const firstDb = new PanelDb(file);
  const secondDb = new PanelDb(file);
  await Promise.all([firstDb.ready, secondDb.ready]);
  const job = await secondDb.createJob('phase3', {}, 'second', {
    claimKeys: ['phase3:fresh-persist'],
  });

  await firstDb.persist();

  assert.equal((await secondDb.getJob(job.id)).status, 'queued');
  await assert.rejects(
    firstDb.createJob('phase3', {}, 'first', { claimKeys: ['phase3:fresh-persist'] }),
    (error) => error.code === 'JOB_ALREADY_CLAIMED'
      && error.existingJobId === job.id,
  );
  await secondDb.updateJob(job.id, { status: 'failed', error: 'test cleanup' });
});

test('PanelDb enforces job status transitions and preserves the first terminal result', async () => {
  const file = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-job-state-')),
    'panel.sqlite3',
  );
  const db = new PanelDb(file);
  const claimKey = 'phase3:strict-state-machine';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });

  await assert.rejects(
    db.updateJob(job.id, { status: 'unknown-status' }),
    (error) => error.code === 'JOB_STATUS_INVALID',
  );
  await assert.rejects(
    db.updateJob('job_does_not_exist', { status: 'running' }),
    (error) => error.code === 'JOB_NOT_FOUND',
  );
  await assert.rejects(
    db.updateJob(job.id, { status: 'queued' }),
    (error) => error.code === 'JOB_STATUS_CONFLICT'
      && error.currentStatus === 'queued',
  );

  const running = await db.updateJob(job.id, {
    status: 'running',
    startedAt: '2026-09-14T00:00:00.000Z',
  });
  assert.equal(running.applied, true);
  assert.equal(running.previousStatus, 'queued');
  assert.equal(running.currentStatus, 'running');
  const runningReplay = await db.updateJob(job.id, { status: 'running' });
  assert.equal(runningReplay.applied, true);
  assert.equal(runningReplay.previousStatus, 'running');

  const terminal = await db.updateJob(job.id, {
    status: 'failed',
    result: { first: true },
    error: 'first terminal error',
    finishedAt: '2026-09-14T00:01:00.000Z',
  });
  assert.equal(terminal.applied, true);
  assert.equal(terminal.previousStatus, 'running');
  assert.equal(terminal.currentStatus, 'failed');
  const replay = await db.updateJob(job.id, {
    status: 'failed',
    result: { replacement: true },
    error: 'replacement terminal error',
    finishedAt: '2026-09-14T00:02:00.000Z',
  });
  assert.equal(replay.applied, false);
  assert.equal(replay.idempotent, true);
  const persisted = await db.getJob(job.id);
  assert.deepEqual(persisted.result, { first: true });
  assert.equal(persisted.error, 'first terminal error');
  assert.equal(persisted.finishedAt, '2026-09-14T00:01:00.000Z');

  await assert.rejects(
    db.updateJob(job.id, { status: 'queued' }),
    (error) => error.code === 'JOB_STATUS_CONFLICT'
      && error.currentStatus === 'failed',
  );
  assert.equal((await db.getJob(job.id)).status, 'failed');
  const replacement = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  assert.equal(replacement.status, 'queued');
  await db.updateJob(replacement.id, { status: 'failed', error: 'test cleanup' });
});

test('PanelDb keeps the durable queued job and claim when a terminal export exceeds the DB limit', async () => {
  const previousMaximum = process.env.PANEL_DB_MAX_BYTES;
  process.env.PANEL_DB_MAX_BYTES = String(1024 * 1024);
  try {
    const file = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-export-limit-')),
      'panel.sqlite3',
    );
    const db = new PanelDb(file);
    const claimKey = 'phase3:oversized-terminal';
    const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
    const durableBefore = fs.readFileSync(file);

    await assert.rejects(
      db.updateJob(job.id, {
        status: 'succeeded',
        result: { output: 'x'.repeat(1536 * 1024) },
        finishedAt: '2026-09-14T00:01:00.000Z',
      }),
      (error) => error.code === 'PANEL_DB_TOO_LARGE'
        && error.actualBytes > error.maximumBytes,
    );

    assert.deepEqual(fs.readFileSync(file), durableBefore);
    const persisted = await db.getJob(job.id);
    assert.equal(persisted.status, 'queued');
    assert.equal(persisted.result, null);
    await assert.rejects(
      db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
      (error) => error.code === 'JOB_ALREADY_CLAIMED'
        && error.existingJobId === job.id,
    );

    const recovered = await db.updateJob(job.id, { status: 'failed', error: 'test cleanup' });
    assert.equal(recovered.applied, true);
    const replacement = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
    assert.equal(replacement.status, 'queued');
    await db.updateJob(replacement.id, { status: 'failed', error: 'test cleanup' });
  } finally {
    if (previousMaximum === undefined) delete process.env.PANEL_DB_MAX_BYTES;
    else process.env.PANEL_DB_MAX_BYTES = previousMaximum;
  }
});

test('PanelDb rejects oversized job and audit fields before changing SQL rows', async () => {
  const file = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-field-limit-')),
    'panel.sqlite3',
  );
  const db = new PanelDb(file);

  await assert.rejects(
    db.createJob('phase3', { output: 'p'.repeat(1024 * 1024) }, 'tester'),
    (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE'
      && error.field === 'sync_jobs.payload_json',
  );
  assert.equal((await db.listJobs(10)).length, 0);

  const claimKey = 'phase3:oversized-fields';
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await assert.rejects(
    db.updateJob(job.id, {
      status: 'succeeded',
      result: { output: 'r'.repeat(2 * 1024 * 1024) },
    }),
    (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE'
      && error.field === 'sync_jobs.result_json',
  );
  await assert.rejects(
    db.updateJob(job.id, {
      status: 'failed',
      error: 'e'.repeat(64 * 1024 + 1),
    }),
    (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE'
      && error.field === 'sync_jobs.error',
  );
  assert.equal((await db.getJob(job.id)).status, 'queued');
  await assert.rejects(
    db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] }),
    (error) => error.code === 'JOB_ALREADY_CLAIMED',
  );

  const oversizedAuditText = '界'.repeat(5462);
  const auditTextFields = new Map([
    ['jobId', 'audit_events.job_id'],
    ['actor', 'audit_events.actor'],
    ['action', 'audit_events.action'],
    ['targetKey', 'audit_events.target_key'],
    ['beforeFingerprint', 'audit_events.before_fingerprint'],
    ['afterFingerprint', 'audit_events.after_fingerprint'],
    ['result', 'audit_events.result'],
  ]);
  for (const [property, field] of auditTextFields) {
    await assert.rejects(
      db.audit({
        actor: 'tester',
        action: 'capacity_test',
        result: 'rejected',
        [property]: oversizedAuditText,
      }),
      (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE'
        && error.field === field
        && error.actualBytes > error.maximumBytes,
    );
  }
  await assert.rejects(
    db.audit({
      actor: 'tester',
      action: 'capacity_test',
      result: 'rejected',
      details: { output: 'd'.repeat(512 * 1024) },
    }),
    (error) => error.code === 'PANEL_DB_FIELD_TOO_LARGE'
      && error.field === 'audit_events.details_json',
  );
  assert.equal((await db.listAudit(10)).length, 0);
  await db.updateJob(job.id, { status: 'failed', error: 'test cleanup' });
});

test('PanelDb rejects oversized or multiply linked database files before loading them', async () => {
  const previousMaximum = process.env.PANEL_DB_MAX_BYTES;
  process.env.PANEL_DB_MAX_BYTES = String(1024 * 1024);
  try {
    const oversizedDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-limit-'));
    const oversizedPath = path.join(oversizedDirectory, 'oversized.sqlite3');
    fs.writeFileSync(oversizedPath, 'x', { mode: 0o600 });
    fs.truncateSync(oversizedPath, 1024 * 1024 + 1);
    const oversizedDb = new PanelDb(oversizedPath);
    await assert.rejects(
      oversizedDb.ready,
      (error) => error.code === 'PANEL_DB_TOO_LARGE',
    );

    const linkedDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-link-'));
    const linkedPath = path.join(linkedDirectory, 'linked.sqlite3');
    fs.writeFileSync(linkedPath, 'not-a-database', { mode: 0o600 });
    fs.linkSync(linkedPath, linkedPath + '.alias');
    const linkedDb = new PanelDb(linkedPath);
    await assert.rejects(linkedDb.ready, /0600 非硬链接/);
  } finally {
    if (previousMaximum === undefined) delete process.env.PANEL_DB_MAX_BYTES;
    else process.env.PANEL_DB_MAX_BYTES = previousMaximum;
  }
});

test('a second process preserves jobs owned by a live panel process', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-live-owner-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const job = await db.createJob('phase3', { email: 'owner@example.test' }, 'tester', {
    claimKeys: ['phase3:email:owner@example.test'],
  });
  const dbModule = require.resolve('../backend/db');
  const source = [
    "const { PanelDb } = require(process.argv[1]);",
    'const db = new PanelDb(process.argv[2]);',
    "db.getJob(process.argv[3]).then((job) => process.send({ type: 'status', status: job.status }, () => process.disconnect())).catch((error) => { process.send({ type: 'failed', message: error.message }, () => process.disconnect()); process.exitCode = 1; });",
  ].join('\n');
  const child = spawn(process.execPath, ['-e', source, dbModule, file, job.id], {
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  const message = await waitForChildMessage(child, 'status');
  assert.equal(message.status, 'queued');
  assert.equal((await waitForChildExit(child)).code, 0);
  await db.updateJob(job.id, { status: 'failed', error: 'test cleanup' });
});

test('PanelDb interrupts only jobs whose owner process is no longer alive', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-dead-owner-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const job = await db.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:dead-owner'] });
  await db.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET owner_pid = ? WHERE id = ?');
    statement.run([2147483647, job.id]);
    statement.free();
  });
  const restarted = new PanelDb(file);
  assert.equal((await restarted.getJob(job.id)).status, 'interrupted');
  const replacement = await restarted.createJob('phase3', {}, 'tester', { claimKeys: ['phase3:dead-owner'] });
  assert.equal(replacement.status, 'queued');
  await restarted.updateJob(replacement.id, { status: 'failed', error: 'test cleanup' });
});

test('PanelDb reclaims a dead owner claim without requiring another restart', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-live-reclaim-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const claimKey = 'phase3:dead-owner-live-reclaim';
  const abandoned = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  await db.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET owner_pid = ? WHERE id = ?');
    statement.run([2147483647, abandoned.id]);
    statement.free();
  });

  const replacement = await db.createJob('phase3', {}, 'tester', { claimKeys: [claimKey] });
  assert.equal((await db.getJob(abandoned.id)).status, 'interrupted');
  assert.equal(replacement.status, 'queued');
  await db.updateJob(replacement.id, { status: 'failed', error: 'test cleanup' });
});

test('control-plane callbacks are mutually exclusive across processes', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-control-lock-'));
  const coordinatorModule = require.resolve('../backend/taskCoordinator');
  const childSource = [
    "const { withControlPlaneLock } = require(process.env.TEST_COORDINATOR_MODULE);",
    'withControlPlaneLock(async () => {',
    "  if (process.send) process.send({ type: 'entered' });",
    "  await new Promise((resolve) => process.on('message', (message) => { if (message === 'release') resolve(); }));",
    '}).then(() => {',
    "  if (process.send) process.send({ type: 'done' }, () => process.disconnect());",
    '}).catch((error) => {',
    "  if (process.send) process.send({ type: 'failed', message: error.message }, () => process.disconnect());",
    '  process.exitCode = 1;',
    '});',
  ].join('\n');
  const childOptions = {
    env: {
      ...process.env,
      TEST_COORDINATOR_MODULE: coordinatorModule,
      PANEL_CONTROL_LOCK_PATH: path.join(root, 'control.lock'),
      PANEL_CONTROL_LOCK_TIMEOUT_MS: '5000',
      PANEL_CONTROL_LOCK_POLL_MS: '10',
    },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  };
  const first = spawn(process.execPath, ['-e', childSource], childOptions);
  let second = null;
  try {
    await waitForChildMessage(first, 'entered');
    second = spawn(process.execPath, ['-e', childSource], childOptions);
    let secondEntered = false;
    const secondEnteredPromise = waitForChildMessage(second, 'entered').then((message) => {
      secondEntered = true;
      return message;
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(secondEntered, false);
    const firstDone = waitForChildMessage(first, 'done');
    first.send('release');
    await firstDone;
    assert.equal((await waitForChildExit(first)).code, 0);
    await secondEnteredPromise;
    const secondDone = waitForChildMessage(second, 'done');
    second.send('release');
    await secondDone;
    assert.equal((await waitForChildExit(second)).code, 0);
  } finally {
    if (first.exitCode === null && first.signalCode === null) first.kill('SIGKILL');
    if (second && second.exitCode === null && second.signalCode === null) second.kill('SIGKILL');
  }
});

test('bakery leases never unlink the shared namespace and stay exclusive under contention', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-bakery-stress-'));
  const lockPath = path.join(root, 'control.lock');
  const guardPath = path.join(root, 'critical.guard');
  const coordinatorModule = require.resolve('../backend/taskCoordinator');
  const childSource = [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const originalUnlink = fs.unlinkSync;',
    'fs.unlinkSync = (filePath) => {',
    '  if (path.basename(String(filePath)) === path.basename(process.env.PANEL_CONTROL_LOCK_PATH)) {',
    "    const error = new Error('attempted to unlink shared namespace'); error.code = 'SHARED_UNLINK'; throw error;",
    '  }',
    '  return originalUnlink.call(fs, filePath);',
    '};',
    "const { withControlPlaneLock } = require(process.env.TEST_COORDINATOR_MODULE);",
    'const rounds = Number(process.env.TEST_ROUNDS);',
    "const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));",
    '(async () => {',
    "  await new Promise((resolve) => process.once('message', (message) => { if (message === 'start') resolve(); }));",
    '  for (let index = 0; index < rounds; index += 1) {',
    '    await withControlPlaneLock(async () => {',
    '      let descriptor;',
    '      try {',
    "        descriptor = fs.openSync(process.env.TEST_GUARD_PATH, 'wx', 0o600);",
    '      } catch (error) {',
    "        if (error.code === 'EEXIST') { const overlap = new Error('critical section overlap'); overlap.code = 'OVERLAP'; throw overlap; }",
    '        throw error;',
    '      }',
    '      try { await wait(3); } finally {',
    '        try { fs.closeSync(descriptor); } catch {}',
    '        try { fs.unlinkSync(process.env.TEST_GUARD_PATH); } catch {}',
    '      }',
    '    });',
    '  }',
    "  process.send({ type: 'result', ok: true }, () => process.disconnect());",
    '})().catch((error) => {',
    "  process.send({ type: 'result', ok: false, code: error.code, message: error.message }, () => process.disconnect());",
    '  process.exitCode = 1;',
    '});',
  ].join('\n');
  const spawnContender = (rounds) => spawn(process.execPath, ['-e', childSource], {
    env: {
      ...process.env,
      TEST_COORDINATOR_MODULE: coordinatorModule,
      TEST_GUARD_PATH: guardPath,
      TEST_ROUNDS: String(rounds),
      PANEL_CONTROL_LOCK_PATH: lockPath,
      PANEL_CONTROL_LOCK_TIMEOUT_MS: '30000',
      PANEL_CONTROL_LOCK_POLL_MS: '10',
    },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });

  const initializer = spawnContender(1);
  initializer.send('start');
  assert.equal((await waitForChildMessage(initializer, 'result', 10000)).ok, true);
  assert.equal((await waitForChildExit(initializer, 10000)).code, 0);
  const namespaceBefore = fs.statSync(lockPath);

  // A valid dead entry may be reclaimed because its unique token path can
  // never become another contender's lease; the shared namespace is retained.
  const deadToken = 'd'.repeat(32);
  const deadTicketPath = lockPath + '.lease-v2-' + deadToken + '.ticket';
  fs.writeFileSync(deadTicketPath, JSON.stringify({
    kind: 'gpt-register-panel-control-lock',
    protocol: 'lamport-bakery',
    version: 2,
    role: 'lease',
    phase: 'ticket',
    pid: process.pid,
    processStartId: null,
    processBootId: '00000000-0000-0000-0000-000000000000',
    token: deadToken,
    ticket: 1,
    createdAt: new Date().toISOString(),
  }), { mode: 0o600 });

  const children = Array.from({ length: 8 }, () => spawnContender(15));
  const readyDelay = new Promise((resolve) => setTimeout(resolve, 30));
  await readyDelay;
  for (const child of children) child.send('start');
  const outcomes = await Promise.all(children.map((child) => waitForChildMessage(child, 'result', 30000)));
  assert.equal(outcomes.every((outcome) => outcome.ok), true, JSON.stringify(outcomes));
  const exits = await Promise.all(children.map((child) => waitForChildExit(child, 10000)));
  assert.deepEqual(exits.map((exit) => exit.code), Array(children.length).fill(0));

  const namespaceAfter = fs.statSync(lockPath);
  assert.equal(namespaceAfter.dev, namespaceBefore.dev);
  assert.equal(namespaceAfter.ino, namespaceBefore.ino);
  assert.equal(fs.existsSync(deadTicketPath), false);
  assert.equal(fs.existsSync(guardPath), false);
  assert.deepEqual(
    fs.readdirSync(root).filter((name) => name.includes('.lease-v2-') && !name.includes(deadToken)),
    [],
  );
});

test('malformed per-contender leases fail closed without deleting the namespace or entry', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-bakery-invalid-'));
  const controlLockPath = path.join(root, 'control.lock');
  const previousLockPath = process.env.PANEL_CONTROL_LOCK_PATH;
  process.env.PANEL_CONTROL_LOCK_PATH = controlLockPath;
  try {
    await withControlPlaneLock(async () => {});
    const namespaceBefore = fs.statSync(controlLockPath);
    const malformedPath = controlLockPath + '.lease-v2-' + 'e'.repeat(32) + '.ticket';
    fs.writeFileSync(malformedPath, 'unrelated-user-file', { mode: 0o600 });
    await assert.rejects(
      withControlPlaneLock(async () => {}),
      (error) => error.code === 'CONTROL_PLANE_LOCK_PATH_INVALID',
    );
    assert.equal(fs.readFileSync(malformedPath, 'utf8'), 'unrelated-user-file');
    const namespaceAfter = fs.statSync(controlLockPath);
    assert.equal(namespaceAfter.dev, namespaceBefore.dev);
    assert.equal(namespaceAfter.ino, namespaceBefore.ino);
  } finally {
    if (previousLockPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousLockPath;
  }
});

test('lock namespaces reject group/world-writable parent directories before publishing files', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-lock-permissions-'));
  const unsafeControlDirectory = path.join(root, 'unsafe-control');
  const unsafeDbDirectory = path.join(root, 'unsafe-db');
  fs.mkdirSync(unsafeControlDirectory, { mode: 0o777 });
  fs.mkdirSync(unsafeDbDirectory, { mode: 0o777 });
  fs.chmodSync(unsafeControlDirectory, 0o777);
  fs.chmodSync(unsafeDbDirectory, 0o777);

  const previousLockPath = process.env.PANEL_CONTROL_LOCK_PATH;
  process.env.PANEL_CONTROL_LOCK_PATH = path.join(unsafeControlDirectory, 'control.lock');
  try {
    await assert.rejects(
      withControlPlaneLock(async () => {}),
      (error) => error.code === 'CONTROL_PLANE_LOCK_PATH_INVALID',
    );
    assert.deepEqual(fs.readdirSync(unsafeControlDirectory), []);
  } finally {
    if (previousLockPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousLockPath;
  }

  const dbPath = path.join(unsafeDbDirectory, 'panel.sqlite3');
  const db = new PanelDb(dbPath);
  await assert.rejects(db.ready, (error) => error.code === 'DB_LOCK_PATH_INVALID');
  assert.deepEqual(fs.readdirSync(unsafeDbDirectory), []);
});

test('database bakery lease preserves concurrent writes and counts all active jobs', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-bakery-'));
  const dbPath = path.join(root, 'panel.sqlite3');
  const dbModule = require.resolve('../backend/db');
  const childSource = [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const originalUnlink = fs.unlinkSync;',
    'fs.unlinkSync = (filePath) => {',
    "  if (path.basename(String(filePath)) === path.basename(process.env.TEST_DB_PATH) + '.lock') {",
    "    const error = new Error('attempted to unlink shared DB namespace'); error.code = 'SHARED_UNLINK'; throw error;",
    '  }',
    '  return originalUnlink.call(fs, filePath);',
    '};',
    "const { PanelDb } = require(process.env.TEST_DB_MODULE);",
    'const db = new PanelDb(process.env.TEST_DB_PATH);',
    'const count = Number(process.env.TEST_WRITE_COUNT);',
    '(async () => {',
    "  await new Promise((resolve) => process.once('message', (message) => { if (message === 'start') resolve(); }));",
    '  for (let index = 0; index < count; index += 1) {',
    "    await db.audit({ actor: 'stress', action: 'bakery_write', result: 'ok', details: { index } });",
    '  }',
    "  process.send({ type: 'result', ok: true }, () => process.disconnect());",
    '})().catch((error) => {',
    "  process.send({ type: 'result', ok: false, code: error.code, message: error.message }, () => process.disconnect());",
    '  process.exitCode = 1;',
    '});',
  ].join('\n');
  const children = Array.from({ length: 6 }, () => spawn(process.execPath, ['-e', childSource], {
    env: {
      ...process.env,
      TEST_DB_MODULE: dbModule,
      TEST_DB_PATH: dbPath,
      TEST_WRITE_COUNT: '8',
      PANEL_DB_LOCK_TIMEOUT_MS: '30000',
    },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  }));
  await new Promise((resolve) => setTimeout(resolve, 30));
  for (const child of children) child.send('start');
  const outcomes = await Promise.all(children.map((child) => waitForChildMessage(child, 'result', 30000)));
  assert.deepEqual(outcomes.map((outcome) => outcome.ok), Array(children.length).fill(true));
  const exits = await Promise.all(children.map((child) => waitForChildExit(child, 10000)));
  assert.deepEqual(exits.map((exit) => exit.code), Array(children.length).fill(0));

  const db = new PanelDb(dbPath);
  assert.equal((await db.listAudit(100)).length, 48);
  const first = await db.createJob('phase3', {}, 'tester');
  const second = await db.createJob('phase3', {}, 'tester');
  const third = await db.createJob('token_import', {}, 'tester');
  await db.updateJob(first.id, { status: 'succeeded', result: {} });
  assert.equal(await db.countActiveJobs(), 2);
  assert.equal(await db.countActiveJobs('phase3'), 1);
  assert.equal(await db.countActiveJobs('token_import'), 1);
  await db.updateJob(second.id, { status: 'failed', error: 'test cleanup' });
  await db.updateJob(third.id, { status: 'failed', error: 'test cleanup' });

  const namespacePath = dbPath + '.lock';
  const namespaceBefore = fs.statSync(namespacePath);
  const malformedPath = namespacePath + '.lease-v2-' + 'f'.repeat(32) + '.ticket';
  fs.writeFileSync(malformedPath, 'not-a-panel-lease', { mode: 0o600 });
  await assert.rejects(
    db.audit({ actor: 'tester', action: 'must_fail_closed', result: 'ok' }),
    (error) => error.code === 'DB_LOCK_PATH_INVALID',
  );
  assert.equal(fs.readFileSync(malformedPath, 'utf8'), 'not-a-panel-lease');
  const namespaceAfter = fs.statSync(namespacePath);
  assert.equal(namespaceAfter.dev, namespaceBefore.dev);
  assert.equal(namespaceAfter.ino, namespaceBefore.ino);
});

test('job payloads, results, errors, and historical rows are redacted at the DB boundary', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-redaction-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const marker = 'sensitive-value-for-boundary-test';
  const job = await db.createJob('account_test', {
    prompt: 'Authorization: Bearer ' + marker,
    credentials: { access_token: marker },
    tokenCount: 7,
    fingerprint: '0123456789abcdef',
  });
  await db.updateJob(job.id, {
    status: 'succeeded',
    result: { message: 'password=' + marker, tokenCount: 9, fingerprint: 'fedcba9876543210' },
    error: 'Bearer ' + marker,
  });
  await db.audit({
    jobId: job.id,
    action: 'redaction_test',
    details: { credential: marker, tokenCount: 11, fingerprint: 'aaaaaaaaaaaaaaaa' },
  });
  await db.write((database) => {
    const statement = database.prepare('UPDATE sync_jobs SET payload_json = ?, result_json = ?, error = ? WHERE id = ?');
    statement.run([
      JSON.stringify({ prompt: 'api_key=' + marker, tokenCount: 13 }),
      JSON.stringify({ message: 'refresh_token=' + marker, fingerprint: 'bbbbbbbbbbbbbbbb' }),
      'Authorization: Bearer ' + marker,
      job.id,
    ]);
    statement.free();
  });
  const loaded = await db.getJob(job.id);
  const audit = await db.listAudit(10);
  assert.equal(JSON.stringify({ loaded, audit }).includes(marker), false);
  assert.equal(loaded.payload.tokenCount, 13);
  assert.equal(loaded.result.fingerprint, 'bbbbbbbbbbbbbbbb');
  assert.equal(audit[0].details.tokenCount, 11);
  assert.equal(audit[0].details.fingerprint, 'aaaaaaaaaaaaaaaa');
});

test('audit scalar fields are redacted both before storage and when reading legacy rows', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-audit-scalar-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const marker = 'audit-scalar-secret-marker';
  const unsafeValues = {
    jobId: 'Bearer ' + marker,
    actor: 'password=' + marker,
    action: 'api_key=' + marker,
    targetKey: 'credential=' + marker,
    beforeFingerprint: 'refresh_token=' + marker,
    afterFingerprint: 'Authorization: Bearer ' + marker,
    result: 'client_secret=' + marker,
  };

  await db.audit(unsafeValues);
  const stored = await db.read((database) => database.exec(`SELECT
    job_id, actor, action, target_key, before_fingerprint, after_fingerprint, result
    FROM audit_events`));
  assert.equal(JSON.stringify(stored).includes(marker), false);

  await db.write((database) => {
    const statement = database.prepare(`UPDATE audit_events SET
      job_id = ?, actor = ?, action = ?, target_key = ?,
      before_fingerprint = ?, after_fingerprint = ?, result = ?`);
    statement.run(Object.values(unsafeValues));
    statement.free();
  });
  assert.equal(JSON.stringify(await db.listAudit(10)).includes(marker), false);
});

test('audit history bounds limits and omits oversized stored fields before decoding', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-audit-bounds-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const marker = 'audit-query-must-not-materialize-secret';
  const oversizedText = marker + '-'.repeat((16 * 1024) + 1);
  const oversizedDetails = JSON.stringify({ credential: marker, filler: 'x'.repeat(17 * 1024) });
  await db.write((database) => {
    database.run('BEGIN IMMEDIATE');
    const statement = database.prepare(`INSERT INTO audit_events
      (job_id, actor, action, target_key, before_fingerprint, after_fingerprint,
        result, details_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    try {
      for (let index = 0; index < 105; index += 1) {
        statement.run([
          null,
          'tester',
          'bounded_history',
          null,
          null,
          null,
          'ok',
          '{}',
          new Date(Date.now() + index).toISOString(),
        ]);
      }
      statement.run([
        'job-' + oversizedText,
        oversizedText,
        oversizedText,
        oversizedText,
        oversizedText,
        oversizedText,
        oversizedText,
        oversizedDetails,
        oversizedText,
      ]);
      database.run('COMMIT');
    } catch (error) {
      try { database.run('ROLLBACK'); } catch {}
      throw error;
    } finally {
      statement.free();
    }
  });

  const originalJsonParse = JSON.parse;
  let oversizedDetailsParsed = false;
  JSON.parse = function monitoredJsonParse(value, ...args) {
    if (typeof value === 'string' && Buffer.byteLength(value, 'utf8') > 16 * 1024) {
      oversizedDetailsParsed = true;
    }
    return originalJsonParse.call(this, value, ...args);
  };
  let events;
  try {
    events = await db.listAudit('999.75');
  } finally {
    JSON.parse = originalJsonParse;
  }
  assert.equal(events.length, 100);
  assert.equal(oversizedDetailsParsed, false);
  assert.equal(JSON.stringify(events).includes(marker), false);
  assert.deepEqual(events[0].scalarFieldsOmitted, [
    'jobId',
    'actor',
    'action',
    'targetKey',
    'beforeFingerprint',
    'afterFingerprint',
    'result',
    'createdAt',
  ]);
  assert.equal(events[0].jobId, null);
  assert.equal(events[0].actor, '[oversized]');
  assert.equal(events[0].detailsOmitted, true);
  assert.equal(events[0].detailsBytes, Buffer.byteLength(oversizedDetails, 'utf8'));
  assert.equal(events[0].detailsInvalid, false);
  assert.deepEqual(events[0].details, {});
  assert.equal((await db.listAudit(2.9)).length, 2);
  assert.equal((await db.listAudit(0)).length, 1);
  assert.equal((await db.listAudit('invalid')).length, 100);
});

test('active account-test admission lookup reads only requested claims and minimal job fields', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-account-admission-')), 'panel.sqlite3');
  const db = new PanelDb(file);
  const marker = 'active-account-query-must-not-return-history';
  const requested = await db.createJob('account_test', {
    accountIds: [41],
    prompt: marker,
  }, 'tester', { claimKeys: ['account_test:41'] });
  await db.createJob('account_test', {
    accountIds: [99],
    prompt: marker,
  }, 'tester', { claimKeys: ['account_test:99'] });
  const historical = await db.createJob('account_test', {
    accountIds: [42],
    prompt: marker,
  }, 'tester', { claimKeys: ['account_test:42'] });
  await db.updateJob(historical.id, {
    status: 'failed',
    result: { code: 'ACCOUNT_TEST_FAILED' },
    error: 'historical failure',
  });
  await db.write((database) => {
    const statement = database.prepare(`UPDATE sync_jobs
      SET payload_json = ?, result_json = ?, error = ? WHERE id IN (?, ?)`);
    statement.run([
      JSON.stringify({ marker, filler: 'p'.repeat(64 * 1024) }),
      JSON.stringify({ marker, filler: 'r'.repeat(64 * 1024) }),
      marker + '-'.repeat((64 * 1024) - Buffer.byteLength(marker, 'utf8')),
      requested.id,
      historical.id,
    ]);
    statement.free();
  });

  const jobs = await db.listActiveAccountTestJobsForAccounts([41, 42]);
  assert.deepEqual(jobs, [{
    id: requested.id,
    type: 'account_test',
    status: 'queued',
    payload: { accountIds: [41] },
  }]);
  assert.equal(JSON.stringify(jobs).includes(marker), false);
  assert.deepEqual(
    await db.listActiveAccountTestJobsForAccounts(['41']),
    jobs,
  );
  await assert.rejects(
    db.listActiveAccountTestJobsForAccounts([0]),
    (error) => error.code === 'ACCOUNT_TEST_ACTIVE_QUERY_INVALID',
  );
  await assert.rejects(
    db.listActiveAccountTestJobsForAccounts([Symbol('41')]),
    (error) => error.code === 'ACCOUNT_TEST_ACTIVE_QUERY_INVALID',
  );
  await assert.rejects(
    db.listActiveAccountTestJobsForAccounts(['041']),
    (error) => error.code === 'ACCOUNT_TEST_ACTIVE_QUERY_INVALID',
  );

  await db.write((database) => {
    const statement = database.prepare('UPDATE job_claims SET job_type = ? WHERE claim_key = ?');
    statement.run(['token_import', 'account_test:41']);
    statement.free();
  });
  await assert.rejects(
    db.listActiveAccountTestJobsForAccounts([41]),
    (error) => error.code === 'JOB_CLAIM_INTEGRITY_INVALID',
  );
});

test('malformed DB and control lock files fail closed and are never deleted as stale markers', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-invalid-lock-'));
  const dbPath = path.join(root, 'panel.sqlite3');
  const dbLockPath = dbPath + '.lock';
  const controlLockPath = path.join(root, 'control.lock');
  const unrelated = 'unrelated-user-file';
  fs.writeFileSync(dbLockPath, unrelated);
  fs.writeFileSync(controlLockPath, unrelated);
  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(dbLockPath, old, old);
  fs.utimesSync(controlLockPath, old, old);

  const db = new PanelDb(dbPath);
  await assert.rejects(db.ready, (error) => error.code === 'DB_LOCK_PATH_INVALID');
  assert.equal(fs.readFileSync(dbLockPath, 'utf8'), unrelated);

  const previousLockPath = process.env.PANEL_CONTROL_LOCK_PATH;
  process.env.PANEL_CONTROL_LOCK_PATH = controlLockPath;
  try {
    await assert.rejects(
      withControlPlaneLock(async () => {}),
      (error) => error.code === 'CONTROL_PLANE_LOCK_PATH_INVALID',
    );
    assert.equal(fs.readFileSync(controlLockPath, 'utf8'), unrelated);
  } finally {
    if (previousLockPath === undefined) delete process.env.PANEL_CONTROL_LOCK_PATH;
    else process.env.PANEL_CONTROL_LOCK_PATH = previousLockPath;
  }
});

test('PanelDb pins its real parent directory and rejects a replacement directory', async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-db-parent-'));
  const displaced = parent + '-displaced';
  const db = new PanelDb(path.join(parent, 'panel.sqlite3'));
  await db.createJob('preview', {}, 'tester');
  fs.renameSync(parent, displaced);
  fs.mkdirSync(parent);
  await assert.rejects(db.listJobs(10), /父目录已被替换/);
});

test('Phase3 disposition refuses to overwrite a concurrently changed username record', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-username-race-'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'race@example.test', password: 'secret', status: 'oauth_done' },
  ]));
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    const entry = findUsernameEntry({ email: 'race@example.test' });
    fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
      { email: 'race@example.test', password: 'secret', status: 'manual_change' },
    ]));
    assert.throws(
      () => persistAccountDisposition(entry, 'ACCOUNT_DEACTIVATED'),
      /记录在 Phase3 期间发生变化/,
    );
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('authentication ignores forged actors, rate-limits failures, and protects remote startup', () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    maxFailures: process.env.PANEL_AUTH_MAX_FAILURES,
    allowRemote: process.env.PANEL_ALLOW_INSECURE_REMOTE,
  };
  const request = {
    headers: { authorization: 'Bearer wrong', 'x-panel-actor': 'forged-admin' },
    socket: { remoteAddress: '198.51.100.77' },
  };
  process.env.PANEL_ADMIN_TOKEN = 'test-admin-token-123456';
  process.env.PANEL_REQUIRE_AUTH = '1';
  process.env.PANEL_AUTH_MAX_FAILURES = '1';
  delete process.env.PANEL_ALLOW_INSECURE_REMOTE;
  try {
    assert.equal(requestActor(request), 'anonymous');
    assert.equal(authorizationError(request).status, 401);
    assert.equal(authorizationError(request).status, 429);
    delete process.env.PANEL_ADMIN_TOKEN;
    process.env.PANEL_REQUIRE_AUTH = '0';
    assert.throws(
      () => validateListenConfiguration('0.0.0.0'),
      (error) => error.code === 'PANEL_REMOTE_AUTH_REQUIRED',
    );
    assert.throws(
      () => validateListenConfiguration('127.example.invalid'),
      (error) => error.code === 'PANEL_REMOTE_AUTH_REQUIRED',
    );
    assert.doesNotThrow(() => validateListenConfiguration('127.0.0.1'));
    assert.doesNotThrow(() => validateListenConfiguration('::1'));

    process.env.PANEL_ADMIN_TOKEN = 'test-admin-token-123456';
    assert.throws(
      () => validateListenConfiguration('0.0.0.0'),
      (error) => error.code === 'PANEL_REMOTE_HTTP_CONFIRMATION_REQUIRED',
    );
    process.env.PANEL_ALLOW_INSECURE_REMOTE = '1';
    assert.doesNotThrow(() => validateListenConfiguration('0.0.0.0'));

    delete process.env.PANEL_ADMIN_TOKEN;
    assert.throws(
      () => validateListenConfiguration('0.0.0.0'),
      (error) => error.code === 'PANEL_REMOTE_AUTH_REQUIRED',
    );
  } finally {
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.maxFailures === undefined) delete process.env.PANEL_AUTH_MAX_FAILURES;
    else process.env.PANEL_AUTH_MAX_FAILURES = previous.maxFailures;
    if (previous.allowRemote === undefined) delete process.env.PANEL_ALLOW_INSECURE_REMOTE;
    else process.env.PANEL_ALLOW_INSECURE_REMOTE = previous.allowRemote;
  }
});

test('snapshot version changes when token or username contents change', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-version-'));
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'version@example.test', status: 'oauth_done' },
  ]));
  const tokenPath = path.join(root, 'tokens', 'token.json');
  fs.writeFileSync(tokenPath, JSON.stringify({ access_token: 'opaque-token-a', email: 'version@example.test' }));
  const first = await buildSnapshot(new URLSearchParams(), {
    rootDirectory: root,
    readSub2Api: false,
    includeInternal: true,
  });
  const tokenStat = fs.statSync(tokenPath);
  fs.writeFileSync(tokenPath, JSON.stringify({ access_token: 'opaque-token-b', email: 'version@example.test' }));
  fs.utimesSync(tokenPath, tokenStat.atime, tokenStat.mtime);
  const second = await buildSnapshot(new URLSearchParams(), {
    rootDirectory: root,
    readSub2Api: false,
    includeInternal: true,
  });
  assert.notEqual(first.version, second.version);
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'version@example.test', status: 'account_deleted' },
  ]));
  const third = await buildSnapshot(new URLSearchParams(), {
    rootDirectory: root,
    readSub2Api: false,
    includeInternal: true,
  });
  assert.notEqual(second.version, third.version);
});

test('import job result keeps only non-sensitive remote fields', () => {
  const opaqueMessage = 'opaque-import-message-d4912e';
  const safe = safeImportResult({
    success: true,
    account_id: 12,
    created: 1,
    access_token: 'secret-access-token',
    credentials: { refresh_token: 'secret-refresh-token' },
    message: opaqueMessage,
  });
  assert.deepEqual(safe, {
    success: true,
    schemaValid: false,
    accountId: 12,
    total: null,
    created: 1,
    updated: null,
    skipped: null,
    failed: null,
    errorCount: 0,
    warningCount: 0,
    message: 'Sub2API 已返回导入状态（详情已隐藏）',
  });
  assert.equal(JSON.stringify(safe).includes('secret-'), false);
  assert.equal(JSON.stringify(safe).includes(opaqueMessage), false);

  const nested = safeImportResult({
    total: 1,
    created: 0,
    updated: 1,
    skipped: 0,
    failed: 0,
    items: [{ index: 0, action: 'updated', account_id: 266 }],
  });
  assert.equal(nested.accountId, 266);
  assert.equal(nested.schemaValid, true);
  assert.equal(Object.hasOwn(nested, 'items'), false);

  const malformedCounters = safeImportResult({
    total: '1',
    created: false,
    updated: 0,
    skipped: 0,
  });
  assert.equal(malformedCounters.schemaValid, false);
  assert.equal(malformedCounters.total, null);
  assert.equal(malformedCounters.created, null);
  assert.equal(malformedCounters.failed, null);
});
