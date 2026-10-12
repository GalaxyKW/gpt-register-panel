'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { readRegistrationSettings } = require('../backend/registrationSettings');

test('Phase3 configuration readiness is independent from SMS and the new-registration country catalog', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-readiness-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const config = { mailAdminToken: 'fixture-only-mail-secret', mailBaseUrl: 'https://mail.example.test', mailDomain: 'example.test' };
  fs.writeFileSync(path.join(root, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  const view = readRegistrationSettings({ rootDirectory: root });
  assert.equal(view.ready, false); assert.equal(view.phase3Ready, true);
  assert.deepEqual(view.phase3Issues, []); assert.equal(view.countries.length, 0);
  assert.equal(JSON.stringify(view).includes('fixture-only-mail-secret'), false);
  for (const field of ['mailBaseUrl', 'mailDomain', 'mailAdminToken']) {
    const incomplete = { ...config }; delete incomplete[field];
    fs.writeFileSync(path.join(root, 'config.json'), JSON.stringify(incomplete), { mode: 0o600 });
    const invalid = readRegistrationSettings({ rootDirectory: root });
    assert.equal(invalid.phase3Ready, false, field); assert.ok(invalid.phase3Issues.length > 0);
  }
});
