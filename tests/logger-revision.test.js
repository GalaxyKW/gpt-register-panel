'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
require('./test-isolation');

const { PanelLogger, redactText, redactValue } = require('../backend/logger');
const { createAccountTargetRevisionIssuer } = require('../backend/accountTargetRevision');
const {
  createPhase3TargetRevisionIssuer, createLocalPhase3TargetRevisionIssuer,
} = require('../backend/phase3TargetRevision');

// All material is synthetic. Assertions deliberately compare booleans rather
// than printing even synthetic signatures/credential-shaped strings on a
// failed test. Fixed issuer inputs reproduce real base64url pattern collisions.
function revisions() {
  const secret = Buffer.alloc(32, 13);
  const account = createAccountTargetRevisionIssuer(secret).issue({
    id: 943, platform: 'openai', type: 'oauth', status: 'error', schedulable: false,
    identityKeys: ['account:fixture-workspace'], tokenFingerprints: { access: 'a'.repeat(64) },
  });
  const username = {
    index: 0, email: 'revision-fixture@example.test', phone: '', status: 'oauth_done',
    hasPassword: true, phoneValid: true,
  };
  const token = {
    source: 'tokens', relativePath: 'tokens/fixture.json', contentHash: 'a'.repeat(64),
    historical: false, parseStatus: 'ok', email: username.email,
    identityKeys: ['account:fixture-account'],
  };
  const phase3 = createPhase3TargetRevisionIssuer(secret).issue({
    token, username: { ...username, index: 1357 }, usernameContentHash: 'b'.repeat(64),
  });
  const local = createLocalPhase3TargetRevisionIssuer(secret).issue({
    username: { ...username, index: 417 }, usernameContentHash: 'b'.repeat(64),
  });
  const plan = 'sync-plan-v1.' + crypto.createHash('sha256')
    .update('fixture-plan-0').digest('base64url');
  return { account, phase3, local, plan };
}

test('logger preserves issuer-generated revision collisions only in their exact metadata fields', () => {
  const values = revisions();
  const pairs = [
    ['targetRevision', values.account], ['remoteTargetRevision', values.account],
    ['phase3TargetRevision', values.phase3], ['phase3TargetRevision', values.local],
    ['planIntentVersion', values.plan],
  ];
  for (const [field, value] of pairs) {
    assert.ok(typeof value === 'string', 'fixture issuer must produce a revision');
    assert.ok(redactText(value) !== value, 'fixture must exercise a free-text credential-pattern collision');
    assert.ok(redactValue({ [field]: value })[field] === value, 'exact signed metadata must survive');
    assert.ok(redactValue(value, field) === value, 'explicit structured metadata must survive');
    const nested = redactValue({ payload: { targets: [{ [field]: value }] } });
    assert.ok(nested.payload.targets[0][field] === value, 'nested durable metadata must survive');
    const json = JSON.parse(redactText(JSON.stringify({ [field]: value })));
    assert.ok(json[field] === value, 'valid JSON metadata must retain its revision');
  }
});

test('logger revision metadata does not bypass secret fields or containers', () => {
  const { account } = revisions();
  for (const field of ['token', 'access_token', 'refreshToken', 'id_token',
    'password', 'credential', 'authorization', 'apiKey', 'JWT']) {
    const direct = redactValue({ [field]: account });
    assert.ok(direct[field] === '[redacted]', 'sensitive field remains fully redacted');
    const nested = redactValue({ [field]: { targetRevision: account } });
    assert.ok(nested[field] === '[redacted]', 'sensitive parent remains fully redacted');
  }
  for (const field of ['revision', 'message', 'tokenRevision', 'accessTokenRevision',
    'target_revision', 'TargetRevision', 'remote_target_revision', 'phase3targetrevision',
    'plan_intent_version', 'targetRevision ']) {
    const safe = redactValue({ [field]: account });
    assert.ok(safe[field] !== account, 'unapproved field names must not gain the metadata exception');
  }
  const array = redactValue({ targetRevision: [account] });
  assert.ok(array.targetRevision[0] !== account, 'array contents do not inherit scalar metadata authority');
});

test('logger refuses mismatched revision domains, lengths, padding bits and hidden suffixes', () => {
  const { account, phase3, local, plan } = revisions();
  const wrongDomains = [
    ['targetRevision', phase3], ['targetRevision', local], ['targetRevision', plan],
    ['remoteTargetRevision', local], ['phase3TargetRevision', account], ['planIntentVersion', account],
  ];
  for (const [field, value] of wrongDomains) {
    assert.ok(redactValue({ [field]: value })[field] !== value, 'revision domain must match the field');
  }
  const prefixLength = 'account-test-v1.'.length;
  const nonCanonicalFinal = account.slice(0, -1) + 'B';
  const altered = [
    account + '\n', account + '\r', account + '\u2028', account + '\u200b',
    account + '=', account + 'A', account.slice(0, -1), ' ' + account, account + ' ',
    'prefix ' + account, account + ' suffix', nonCanonicalFinal,
    'account-test-v2.' + account.slice(prefixLength),
    'ACCOUNT-TEST-V1.' + account.slice(prefixLength),
  ];
  for (const value of altered) {
    assert.ok(redactValue({ targetRevision: value }).targetRevision !== value,
      'malformed revision must use normal credential redaction');
  }
});

test('logger redacts appended, wrapped and encoded credentials in apparent revision fields', () => {
  const { account } = revisions();
  const marker = 'synthetic-embedded-credential-value';
  const badValues = [
    account + ' Bearer ' + marker,
    account + ' password=' + marker,
    account + '\nAuthorization: Bearer ' + marker,
    'account-test-v1.Bearer ' + marker,
    JSON.stringify({ targetRevision: account, access_token: marker }),
    account + ' credential%3D' + marker,
  ];
  for (const value of badValues) {
    for (const field of ['targetRevision', 'remoteTargetRevision', 'phase3TargetRevision', 'planIntentVersion']) {
      const output = JSON.stringify(redactValue({ [field]: value }));
      assert.ok(!output.includes(marker), 'malformed revision must not leak its embedded credential');
    }
  }
  const bounded = redactValue({ targetRevision: account + 'x'.repeat(2 * 1024 * 1024) });
  assert.ok(bounded.targetRevision === '[oversized text omitted]', 'existing size limits remain enforced');
});

test('logger durable JSON lines and rereads preserve revisions but redact adjacent credentials', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-log-revision-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const { account, local, plan } = revisions();
  const marker = 'synthetic-adjacent-credential-value';
  assert.ok(logger.checkpoint('test.revision_metadata', {
    phase3TargetRevision: local, planIntentVersion: plan,
    remoteTarget: { accountId: 943, targetRevision: account },
    password: marker, access_token: marker,
  }), 'audit checkpoint must complete');
  const text = fs.readFileSync(filePath, 'utf8');
  assert.ok(!text.includes(marker), 'adjacent credentials must not be written');
  const stored = text.trim().split('\n').map((line) => JSON.parse(line))
    .find((entry) => entry.event === 'test.revision_metadata');
  assert.ok(Boolean(stored), 'checkpoint JSON line must be present');
  const reread = redactValue(stored);
  assert.ok(stored.phase3TargetRevision === local && reread.phase3TargetRevision === local,
    'local revision must survive durable writes and rereads');
  assert.ok(stored.planIntentVersion === plan && reread.planIntentVersion === plan,
    'plan intent must survive durable writes and rereads');
  assert.ok(stored.remoteTarget.targetRevision === account && reread.remoteTarget.targetRevision === account,
    'remote target revision must survive durable writes and rereads');
});
