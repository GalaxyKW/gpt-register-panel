'use strict';
require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { BROWSER_SMOKE_SOURCE_FILES, copyBrowserSmokeSources, assertLoopbackOnlyNetwork } = require('./manual/phase3-browser-smoke.cjs');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-smoke-fixture-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'); const output = path.join(root, 'output');
  fs.mkdirSync(path.join(source, 'src'), { recursive: true });
  fs.mkdirSync(path.join(output, 'src'), { recursive: true });
  return { source, output };
}

test('manual browser fixture copies the precise source closure without production config or data', t => {
  const { source, output } = fixture(t);
  for (const file of BROWSER_SMOKE_SOURCE_FILES) fs.writeFileSync(path.join(source, 'src', file), 'module.exports = {};\n');
  fs.writeFileSync(path.join(source, 'src/config.js'), 'must not copy production config');
  for (const file of ['config.json', 'username.json', 'accounts.json']) fs.writeFileSync(path.join(source, file), 'must not copy');
  copyBrowserSmokeSources(source, output);
  assert.deepEqual(fs.readdirSync(path.join(output, 'src')).sort(), [...BROWSER_SMOKE_SOURCE_FILES].sort());
  assert.deepEqual(fs.readdirSync(output), ['src']);
  for (const file of BROWSER_SMOKE_SOURCE_FILES) assert.equal(fs.statSync(path.join(output, 'src', file)).mode & 0o777, 0o600);
});

const engineRoot = path.resolve(__dirname, '../../../gpt_register');
test('real BrowserService relative imports are all included or replaced with fixture config',
  { skip: !fs.existsSync(path.join(engineRoot, 'src/browserService.js')) }, () => {
    const names = new Set(BROWSER_SMOKE_SOURCE_FILES);
    for (const file of names) {
      const source = fs.readFileSync(path.join(engineRoot, 'src', file), 'utf8');
      for (const match of source.matchAll(/require\(['"](\.[^'"]+)['"]\)/g)) {
        const dependency = path.posix.normalize(path.posix.join(path.posix.dirname(file), match[1]));
        assert.ok(dependency === 'config' || names.has(dependency.endsWith('.js') ? dependency : dependency + '.js'),
          'unisolated or missing browser dependency: ' + file + ' -> ' + dependency);
      }
    }
  });

test('manual browser source copying rejects symlinked dependencies', t => {
  const { source, output } = fixture(t);
  fs.writeFileSync(path.join(source, 'real-source.js'), 'module.exports = {};');
  fs.symlinkSync('../real-source.js', path.join(source, 'src', BROWSER_SMOKE_SOURCE_FILES[0]));
  assert.throws(() => copyBrowserSmokeSources(source, output), /regular source file/);
  assert.deepEqual(fs.readdirSync(path.join(output, 'src')), []);
});

function isolatedNetwork(overrides = {}) {
  return { platform: 'linux', namespace: () => 'net:[123]', initialNamespace: () => 'net:[456]',
    interfaces: () => ({ lo: [{ address: '127.0.0.1', internal: true }, { address: '::1', internal: true }] }), ...overrides };
}

test('manual browser check requires a separate namespace with loopback only', () => {
  assert.doesNotThrow(() => assertLoopbackOnlyNetwork(isolatedNetwork()));
  for (const overrides of [
    { platform: 'darwin' },
    { namespace: () => 'net:[456]' },
    { namespace: () => 'unknown' },
    { initialNamespace: () => { throw new Error('unavailable'); } },
    { interfaces: () => ({}) },
    { interfaces: () => ({ lo: [] }) },
    { interfaces: () => ({ lo: [{ address: '127.0.0.1', internal: false }] }) },
    { interfaces: () => ({ lo: [{ address: '192.0.2.1', internal: true }] }) },
    { interfaces: () => ({ lo: [{ address: '127.0.0.1', internal: true }], eth0: [{ address: '192.0.2.1', internal: false }] }) },
  ]) assert.throws(() => assertLoopbackOnlyNetwork(isolatedNetwork(overrides)), { code: 'SMOKE_NETWORK_ISOLATION_REQUIRED' });
});
