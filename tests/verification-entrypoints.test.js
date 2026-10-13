require('./test-isolation');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { collectJavaScript, checkSyntax } = require('../scripts/check-syntax');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-syntax-fixture-'));
  for (const directory of ['backend', 'frontend', 'scripts', 'tests']) fs.mkdirSync(path.join(root, directory));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('syntax verification covers frontend and manual browser scripts without scanning runtime or secrets', t => {
  const root = fixture(t);
  fs.mkdirSync(path.join(root, 'tests/manual'));
  for (const filename of ['backend/server.js', 'frontend/app.js', 'scripts/check.cjs', 'tests/manual/browser.mjs']) {
    fs.writeFileSync(path.join(root, filename), 'const example = 1;\n');
  }
  fs.mkdirSync(path.join(root, 'runtime'));
  fs.writeFileSync(path.join(root, 'runtime/ignored.js'), 'not valid javascript!');
  fs.writeFileSync(path.join(root, '.env'), 'not configuration to load');
  assert.equal(collectJavaScript(root).length, 4);
  assert.equal(checkSyntax(root), 4);
});

test('syntax verification rejects invalid code and returns only the failing path', t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, 'frontend/broken.js'), 'const = invalid;');
  assert.throws(() => checkSyntax(root), error => error.message === 'SYNTAX_CHECK_FAILED'
    && error.relativePath === 'frontend/broken.js' && !JSON.stringify(error).includes('invalid;'));
});

test('syntax verification clears Node preload options before executing checks', t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, 'scripts/safe.js'), 'void 0;');
  const original = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = '--require=must-not-be-loaded';
  try {
    assert.equal(checkSyntax(root, (_binary, args, options) => {
      assert.equal(args[0], '--check');
      assert.equal(options.env.NODE_OPTIONS, undefined);
      assert.equal(options.env.NODE_PATH, undefined);
      return { status: 0 };
    }), 1);
  } finally {
    if (original === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = original;
  }
});

test('syntax verification fails closed on symlinks and missing source directories', t => {
  const root = fixture(t);
  fs.symlinkSync('/does-not-exist', path.join(root, 'frontend/redirect.js'));
  assert.throws(() => collectJavaScript(root), /SYNTAX_SCAN_SYMLINK/);
  fs.unlinkSync(path.join(root, 'frontend/redirect.js'));
  fs.rmdirSync(path.join(root, 'backend'));
  assert.throws(() => collectJavaScript(root), { code: 'ENOENT' });
});

test('complete verification entrypoint includes syntax, automated tests, browser interactions, audit and patch checks', () => {
  const scripts = require('../package.json').scripts;
  assert.equal(scripts['test:syntax'], 'node scripts/check-syntax.js');
  assert.equal(scripts['test:browser'], 'node tests/browser-console.cjs');
  assert.equal(scripts.verify, 'npm run test:syntax && npm test && npm run test:browser && npm audit --omit=dev --audit-level=high && git diff --check');
});
