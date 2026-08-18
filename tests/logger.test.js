const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { PanelLogger, redactText } = require('../backend/logger');

test('structured logger redacts token-like fields and process output', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false, level: 'debug' });
  logger.info('test.sensitive', {
    access_token: 'access-secret-value',
    refreshToken: 'refresh-secret-value',
    id_token: 'id-secret-value',
    token: 'opaque-secret-value',
    authorization: 'Bearer bearer-secret-value',
    jwt: 'eyJheader.secret.payload',
    apiKey: 'sk-secret-api-key-value',
    nested: { password: 'password-secret-value' },
    message: '{"access_token":"quoted-secret-value"}',
  });
  const text = fs.readFileSync(filePath, 'utf8');
  for (const secret of [
    'access-secret-value',
    'refresh-secret-value',
    'id-secret-value',
    'opaque-secret-value',
    'bearer-secret-value',
    'secret-api-key-value',
    'password-secret-value',
    'quoted-secret-value',
  ]) assert.equal(text.includes(secret), false, secret + ' leaked');
  assert.match(text, /\[redacted\]/);
  assert.equal(redactText('Authorization: Bearer abc.def.ghi').includes('abc.def.ghi'), false);
});

test('structured logger rotates files, supports tail, and uses restrictive permissions', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'nested', 'panel.log');
  const logger = new PanelLogger({ filePath, console: false, maxBytes: 1024, rotations: 2 });
  for (let index = 0; index < 30; index += 1) {
    logger.info('test.rotation', { index, padding: 'x'.repeat(180) });
  }
  assert.equal(fs.statSync(directory + '/nested').mode & 0o077, 0);
  assert.equal(fs.statSync(filePath).mode & 0o077, 0);
  assert.equal(fs.existsSync(filePath + '.1'), true);
  const entries = logger.tail(3);
  assert.equal(entries.length, 3);
  assert.equal(entries[2].event, 'test.rotation');
});

test('logger write failures do not throw into business code', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const blockingPath = path.join(directory, 'not-a-directory');
  fs.writeFileSync(blockingPath, 'x');
  const logger = new PanelLogger({ filePath: path.join(blockingPath, 'panel.log'), console: false });
  assert.doesNotThrow(() => logger.info('test.write_failure', { value: 'ok' }));
});

test('logger handles circular and bigint fields without throwing', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-log-'));
  const filePath = path.join(directory, 'panel.log');
  const logger = new PanelLogger({ filePath, console: false });
  const fields = { count: 12n };
  fields.self = fields;
  assert.doesNotThrow(() => logger.info('test.circular', fields));
  const entry = logger.tail(1)[0];
  assert.equal(entry.count, '12');
  assert.equal(entry.self, '[circular]');
});
