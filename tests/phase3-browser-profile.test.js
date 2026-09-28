'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const { isolationRoot } = require('./test-isolation');
const {
  PROFILE_ENV,
  assertPhase3ProfileParent,
  createPhase3BrowserProfile,
  removePhase3BrowserProfile,
  configurePhase3BrowserProfile,
} = require('../backend/lib/phase3BrowserProfile');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(isolationRoot, 'browser-profile-'));
  const previous = { TMPDIR: process.env.TMPDIR, [PROFILE_ENV]: process.env[PROFILE_ENV] };
  process.env.TMPDIR = root;
  delete process.env[PROFILE_ENV];
  t.after(() => {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  return root;
}

function fakeMain(root, config) {
  fs.mkdirSync(path.join(root, 'src'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(root, 'src', 'config.js'), '// synthetic config marker\n', { mode: 0o600 });
  const requests = [];
  return {
    requests,
    require(request) {
      requests.push(request);
      assert.equal(request, path.join(root, 'src', 'config.js'));
      return config;
    },
  };
}

test('Phase3 creates unique private browser profiles outside descriptor paths', (t) => {
  const root = fixture(t);
  const first = createPhase3BrowserProfile();
  const second = createPhase3BrowserProfile();
  assert.notEqual(first.path, second.path);
  for (const profile of [first, second]) {
    const stat = fs.lstatSync(profile.path);
    assert.equal(path.dirname(profile.path), root);
    assert.match(path.basename(profile.path), /^gpt-register-panel-phase3-[A-Za-z0-9]+$/);
    assert.equal(stat.isDirectory(), true);
    assert.equal(stat.isSymbolicLink(), false);
    assert.equal(stat.mode & 0o777, 0o700);
    assert.equal(profile.dev, stat.dev);
    assert.equal(profile.ino, stat.ino);
    assert.equal(profile.uid, stat.uid);
    assert.equal(Object.isFrozen(profile), true);
  }
});

test('Phase3 removes its unchanged profile and nested synthetic browser files', (t) => {
  fixture(t);
  const profile = createPhase3BrowserProfile();
  fs.mkdirSync(path.join(profile.path, 'Default'), { mode: 0o700 });
  fs.writeFileSync(path.join(profile.path, 'Default', 'fixture.txt'), 'synthetic browser data');
  removePhase3BrowserProfile(profile);
  assert.equal(fs.existsSync(profile.path), false);
});

test('Phase3 profile cleanup rejects a substituted symlink without deleting its target', (t) => {
  const root = fixture(t);
  const profile = createPhase3BrowserProfile();
  const held = profile.path + '-held';
  const unrelated = path.join(root, 'unrelated');
  fs.renameSync(profile.path, held);
  fs.mkdirSync(unrelated, { mode: 0o700 });
  fs.writeFileSync(path.join(unrelated, 'keep.txt'), 'preserve unrelated directory');
  fs.symlinkSync(unrelated, profile.path);
  assert.throws(() => removePhase3BrowserProfile(profile), { code: 'PHASE3_BROWSER_PROFILE_CHANGED' });
  assert.equal(fs.lstatSync(profile.path).isSymbolicLink(), true);
  assert.equal(fs.readFileSync(path.join(unrelated, 'keep.txt'), 'utf8'), 'preserve unrelated directory');
  assert.equal(fs.existsSync(held), true);
});

test('Phase3 profile cleanup preserves a replacement directory with a different inode', (t) => {
  fixture(t);
  const profile = createPhase3BrowserProfile();
  const held = profile.path + '-held';
  fs.renameSync(profile.path, held);
  fs.mkdirSync(profile.path, { mode: 0o700 });
  fs.writeFileSync(path.join(profile.path, 'keep.txt'), 'replacement must survive');
  assert.notEqual(fs.lstatSync(profile.path).ino, profile.ino);
  assert.throws(() => removePhase3BrowserProfile(profile), { code: 'PHASE3_BROWSER_PROFILE_CHANGED' });
  assert.equal(fs.readFileSync(path.join(profile.path, 'keep.txt'), 'utf8'), 'replacement must survive');
  assert.equal(fs.existsSync(held), true);
});

test('Phase3 profile cleanup refuses a profile whose private permissions changed', (t) => {
  fixture(t);
  const profile = createPhase3BrowserProfile();
  fs.chmodSync(profile.path, 0o755);
  assert.throws(() => removePhase3BrowserProfile(profile), { code: 'PHASE3_BROWSER_PROFILE_CHANGED' });
  assert.equal(fs.existsSync(profile.path), true);
});

test('Phase3 child profile setup only replaces browserUserDataDir and consumes its environment marker', (t) => {
  const root = fixture(t);
  const profile = createPhase3BrowserProfile();
  const config = {
    browserUserDataDir: '/proc/self/fd/5/browser-profile',
    tokenOutputDir: '/proc/self/fd/5/tokens',
    tokenOutputDirs: ['/proc/self/fd/5/tokens', '/proc/self/fd/5/use_token'],
    browserIncognito: true,
    chromePath: '/synthetic/chrome',
    unrelatedOption: { preserve: true },
  };
  const original = structuredClone(config);
  const main = fakeMain(root, config);
  process.env[PROFILE_ENV] = profile.path;
  configurePhase3BrowserProfile(main, root, assertPhase3ProfileParent);
  assert.deepEqual(config, { ...original, browserUserDataDir: profile.path });
  assert.deepEqual(main.requests, [path.join(root, 'src', 'config.js')]);
  assert.equal(process.env[PROFILE_ENV], undefined);
});

test('Phase3 child profile and parent guards remain self-contained when embedded in a launcher', (t) => {
  const root = fixture(t);
  const profile = createPhase3BrowserProfile();
  const config = { browserUserDataDir: 'old', tokenOutputDir: '/proc/self/fd/5/tokens' };
  const main = fakeMain(root, config);
  process.env[PROFILE_ENV] = profile.path;
  vm.runInNewContext(
    `(${configurePhase3BrowserProfile.toString()})(main, root, (${assertPhase3ProfileParent.toString()}));`,
    { require, process, main, root },
  );
  assert.equal(config.browserUserDataDir, profile.path);
  assert.equal(config.tokenOutputDir, '/proc/self/fd/5/tokens');
});

test('Phase3 child profile setup rejects missing, proc, relative, and unknown profile locations', (t) => {
  const root = fixture(t);
  const main = fakeMain(root, {});
  for (const value of [undefined, '/proc/self/fd/5/browser-profile',
    'gpt-register-panel-phase3-relative', path.join(root, 'ordinary-directory')]) {
    if (value === undefined) delete process.env[PROFILE_ENV];
    else process.env[PROFILE_ENV] = value;
    assert.throws(() => configurePhase3BrowserProfile(main, root, assertPhase3ProfileParent),
      /invalid private Phase3 browser profile/);
    assert.equal(process.env[PROFILE_ENV], undefined);
  }
  process.env[PROFILE_ENV] = path.join(root, 'gpt-register-panel-phase3-missing');
  assert.throws(() => configurePhase3BrowserProfile(main, root, assertPhase3ProfileParent), { code: 'ENOENT' });
  assert.deepEqual(main.requests, []);
});

test('Phase3 refuses a non-sticky publicly writable profile ancestor during creation and configuration', (t) => {
  const root = fixture(t);
  const unsafe = path.join(root, 'public-writable');
  fs.mkdirSync(unsafe, { mode: 0o700 });
  fs.chmodSync(unsafe, 0o777);
  process.env.TMPDIR = unsafe;
  assert.throws(() => createPhase3BrowserProfile(), { code: 'PHASE3_BROWSER_PROFILE_PARENT_UNSAFE' });
  assert.deepEqual(fs.readdirSync(unsafe), []);
  const childPath = path.join(unsafe, 'gpt-register-panel-phase3-synthetic');
  fs.mkdirSync(childPath, { mode: 0o700 });
  process.env[PROFILE_ENV] = childPath;
  const main = fakeMain(root, {});
  assert.throws(() => configurePhase3BrowserProfile(main, root, assertPhase3ProfileParent),
    { code: 'PHASE3_BROWSER_PROFILE_PARENT_UNSAFE' });
  assert.deepEqual(main.requests, []);
});

test('Phase3 refuses symlinked profile parents during creation and child configuration', (t) => {
  const root = fixture(t);
  const real = path.join(root, 'real-parent');
  const alias = path.join(root, 'parent-alias');
  fs.mkdirSync(real, { mode: 0o700 });
  fs.symlinkSync(real, alias);
  process.env.TMPDIR = alias;
  assert.throws(() => createPhase3BrowserProfile(), { code: 'PHASE3_BROWSER_PROFILE_PARENT_UNSAFE' });
  const childName = 'gpt-register-panel-phase3-synthetic';
  fs.mkdirSync(path.join(real, childName), { mode: 0o700 });
  process.env[PROFILE_ENV] = path.join(alias, childName);
  const main = fakeMain(root, {});
  assert.throws(() => configurePhase3BrowserProfile(main, root, assertPhase3ProfileParent),
    { code: 'PHASE3_BROWSER_PROFILE_PARENT_UNSAFE' });
  assert.deepEqual(main.requests, []);
});

test('Phase3 profile cleanup preserves its contents after an ancestor becomes unsafe', (t) => {
  const root = fixture(t);
  const profile = createPhase3BrowserProfile();
  fs.writeFileSync(path.join(profile.path, 'keep.txt'), 'retain on unsafe ancestor');
  fs.chmodSync(root, 0o777);
  assert.throws(() => removePhase3BrowserProfile(profile), { code: 'PHASE3_BROWSER_PROFILE_PARENT_UNSAFE' });
  assert.equal(fs.readFileSync(path.join(profile.path, 'keep.txt'), 'utf8'), 'retain on unsafe ancestor');
});

test('Phase3 permits an owned sticky temporary parent while keeping each profile private', (t) => {
  const root = fixture(t);
  fs.chmodSync(root, 0o1777);
  const profile = createPhase3BrowserProfile();
  assert.equal(fs.lstatSync(profile.path).mode & 0o777, 0o700);
  removePhase3BrowserProfile(profile);
  assert.equal(fs.existsSync(profile.path), false);
});
