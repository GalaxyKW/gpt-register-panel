'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PROFILE_ENV = 'GPT_REGISTER_PANEL_BROWSER_PROFILE';

// No untrusted ancestor may rename a private profile out from under Chrome or
// replace the cleanup target. Root/current-owner sticky temp roots are allowed.
function assertPhase3ProfileParent(directory) {
  const fs = require('node:fs');
  const path = require('node:path');
  const absolute = path.resolve(directory);
  const root = path.parse(absolute).root;
  const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  let current = root;
  for (const part of ['', ...absolute.slice(root.length).split(path.sep).filter(Boolean)]) {
    if (part) current = path.join(current, part);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()
        || (uid !== null && stat.uid !== 0 && stat.uid !== uid)
        || ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0)) {
      const error = new Error('Phase3 临时浏览器目录的父路径不安全');
      error.code = 'PHASE3_BROWSER_PROFILE_PARENT_UNSAFE';
      throw error;
    }
  }
}

function createPhase3BrowserProfile() {
  const parent = path.resolve(os.tmpdir());
  assertPhase3ProfileParent(parent);
  const directory = fs.mkdtempSync(path.join(parent, 'gpt-register-panel-phase3-'));
  fs.chmodSync(directory, 0o700);
  const stat = fs.lstatSync(directory);
  return Object.freeze({ path: directory, dev: stat.dev, ino: stat.ino, uid: stat.uid });
}

// This is only called after the complete supervised process tree has stopped.
// Never remove a replacement directory or follow a substituted symlink.
function removePhase3BrowserProfile(profile) {
  if (!profile) return;
  assertPhase3ProfileParent(path.dirname(profile.path));
  const stat = fs.lstatSync(profile.path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== profile.dev
      || stat.ino !== profile.ino || stat.uid !== profile.uid || (stat.mode & 0o077) !== 0) {
    const error = new Error('Phase3 临时浏览器目录身份已变化，保留目录供核对');
    error.code = 'PHASE3_BROWSER_PROFILE_CHANGED';
    throw error;
  }
  fs.rmSync(profile.path, { recursive: true, force: false });
}

// Kept self-contained so the fixed, descriptor-backed launcher can embed it.
// Only the browser profile changes: code, configuration, credentials and token
// paths continue to resolve through the verified inherited source-root FD.
function configurePhase3BrowserProfile(main, root, assertParent) {
  const fs = require('node:fs');
  const path = require('node:path');
  const profile = process.env.GPT_REGISTER_PANEL_BROWSER_PROFILE;
  delete process.env.GPT_REGISTER_PANEL_BROWSER_PROFILE;
  if (!profile || !path.isAbsolute(profile) || /^\/proc\//.test(profile)
      || !/^gpt-register-panel-phase3-[A-Za-z0-9]+$/.test(path.basename(profile))) {
    throw new Error('invalid private Phase3 browser profile');
  }
  assertParent(path.dirname(profile));
  const stat = fs.lstatSync(profile);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
      || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid())) {
    throw new Error('unsafe private Phase3 browser profile');
  }
  const configPath = root + '/src/config.js';
  if (fs.existsSync(configPath)) {
    const config = main.require(configPath);
    config.browserUserDataDir = profile;
    if (config.browserUserDataDir !== profile) throw new Error('Phase3 browser profile override failed');
  }
}

module.exports = { PROFILE_ENV, assertPhase3ProfileParent, createPhase3BrowserProfile,
  removePhase3BrowserProfile, configurePhase3BrowserProfile };
