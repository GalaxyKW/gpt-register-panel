const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const UNIT_PATH = path.resolve(__dirname, '..', 'deploy', 'gpt-register-panel.service');
const README_PATH = path.resolve(__dirname, '..', 'README.md');

function parseUnit(source) {
  const sections = new Map();
  let current = null;
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const section = line.match(/^\[([^\]]+)]$/);
    if (section) {
      current = section[1];
      if (!sections.has(current)) sections.set(current, new Map());
      continue;
    }
    const separator = line.indexOf('=');
    assert.ok(current && separator > 0, `invalid unit line: ${line}`);
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    const directives = sections.get(current);
    const directiveValues = directives.get(key) || [];
    directiveValues.push(value);
    directives.set(key, directiveValues);
  }
  return sections;
}

function values(unit, section, directive) {
  return unit.get(section)?.get(directive) || [];
}

function one(unit, section, directive) {
  const found = values(unit, section, directive);
  assert.equal(found.length, 1, `${section}.${directive} must occur exactly once`);
  return found[0];
}

function recursivePreflightCode(source) {
  const line = source.split(/\r?\n/).find((item) => (
    item.startsWith('ExecStartPre=/usr/bin/node -e ') && item.includes('MAX_ENTRIES=')
  ));
  assert.ok(line, 'recursive preflight command must exist');
  const match = line.match(/^ExecStartPre=\/usr\/bin\/node -e "([^"]+)" \/run\//);
  assert.ok(match, 'recursive preflight command must use one literal Node program');
  return match[1];
}

function runRecursivePreflight(program, roots) {
  return spawnSync('/usr/bin/node', ['-e', program, ...roots], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024,
    timeout: 10_000,
  });
}

test('systemd unit executes only pinned sources and refuses a missing or read-only data mount', () => {
  const source = fs.readFileSync(UNIT_PATH, 'utf8');
  const unit = parseUnit(source);

  assert.equal(one(unit, 'Unit', 'RequiresMountsFor'), '/mnt/nvme');
  assert.equal(one(unit, 'Unit', 'BindsTo'), 'mnt-nvme.mount');
  assert.equal(one(unit, 'Unit', 'AssertPathIsMountPoint'), '/mnt/nvme');
  assert.equal(one(unit, 'Unit', 'AssertPathIsReadWrite'), '/mnt/nvme');
  assert.equal(
    one(unit, 'Service', 'ExecStart'),
    '/usr/bin/node /run/gpt-register-panel/code/backend/server.js',
  );
  assert.equal(one(unit, 'Service', 'WorkingDirectory'), '/run/gpt-register-panel/code');
  assert.equal(one(unit, 'Service', 'RuntimeDirectory'), 'gpt-register-panel');
  assert.equal(one(unit, 'Service', 'RuntimeDirectoryMode'), '0700');
  assert.deepEqual(new Set(values(unit, 'Service', 'BindReadOnlyPaths')), new Set([
    '/mnt/nvme/item/gpt-register-panel:/run/gpt-register-panel/code',
  ]));
  assert.deepEqual(new Set(values(unit, 'Service', 'BindPaths')), new Set([
    '/mnt/nvme/item/gpt-register-panel/runtime:/run/gpt-register-panel/runtime',
    '/mnt/nvme/gpt_register:/run/gpt-register-panel/gpt_register',
  ]));
  assert.equal(values(unit, 'Service', 'EnvironmentFile').length, 0);
  const environment = values(unit, 'Service', 'Environment');
  for (const expected of [
    'NODE_OPTIONS=',
    'NODE_PATH=',
    'PANEL_ENV_FILE=/etc/gpt-register-panel/panel.env',
    'GPT_REGISTER_ROOT=/run/gpt-register-panel/gpt_register',
    'GPT_REGISTER_NODE_PATH=/usr/bin/node',
    'PANEL_DB_PATH=/run/gpt-register-panel/runtime/panel.sqlite3',
    'PANEL_BACKUP_DIR=/run/gpt-register-panel/runtime/backups',
    'PANEL_LOG_PATH=/run/gpt-register-panel/runtime/panel.log',
    'PANEL_CONTROL_LOCK_PATH=/run/gpt-register-panel/runtime/panel.sqlite3.control.lock',
    'PANEL_TOKEN_QUARANTINE_DIR=/run/gpt-register-panel/gpt_register/.panel-quarantine/expired-tokens',
  ]) {
    const name = expected.slice(0, expected.indexOf('=') + 1);
    assert.deepEqual(
      environment.filter((item) => item.startsWith(name)),
      [expected],
      `environment must pin exactly one safe value: ${name}`,
    );
  }
  assert.equal(/(?:^|\s)(?:\/bin\/)?(?:ba|z|da)?sh(?:\s|$)/m.test(source), false);

  const preflight = values(unit, 'Service', 'ExecStartPre');
  assert.ok(preflight.includes('/usr/bin/test -r /etc/gpt-register-panel/panel.env'));
  assert.ok(preflight.includes('/usr/bin/test -x /usr/bin/node'));
  const ownershipChecks = preflight.filter((command) => command.startsWith('/usr/bin/node -e '));
  assert.equal(ownershipChecks.length, 3);
  for (const command of ownershipChecks) {
    assert.match(command, /lstatSync/);
    assert.match(command, /isSymbolicLink/);
    assert.match(command, /s\.uid!==0/);
    assert.match(command, /s\.mode&0o22/);
    assert.equal(command.includes(' /mnt/nvme/'), false);
  }
  assert.ok(ownershipChecks.some((command) => command.includes(
    ' /run/gpt-register-panel/code/backend/server.js',
  )));
  assert.ok(ownershipChecks.some((command) => command.includes(
    ' /run/gpt-register-panel/runtime ',
  )));
  assert.ok(ownershipChecks.some((command) => command.includes(
    ' /run/gpt-register-panel /run/gpt-register-panel/code ',
  )));
  assert.ok(ownershipChecks.some((command) => command.includes(
    ' /run/gpt-register-panel/gpt_register/config.json ',
  )));
  assert.ok(ownershipChecks.some((command) => command.endsWith(
    ' /run/gpt-register-panel/gpt_register/config.server.json',
  )));
  const privateFileCheck = ownershipChecks.find((command) => command.includes('privateFiles=new Set'));
  assert.ok(privateFileCheck);
  assert.match(privateFileCheck, /\/etc\/gpt-register-panel\/panel\.env/);
  assert.match(privateFileCheck, /gpt_register\/config\.json/);
  assert.match(privateFileCheck, /gpt_register\/config\.server\.json/);
  assert.match(privateFileCheck, /s\.mode&0o400/);
  assert.match(privateFileCheck, /s\.mode&0o7177/);
  assert.match(privateFileCheck, /s\.nlink!==1/);

  const recursiveCheck = ownershipChecks.find((command) => command.includes('MAX_ENTRIES='));
  assert.ok(recursiveCheck);
  assert.match(recursiveCheck, /MAX_ENTRIES=50000/);
  assert.match(recursiveCheck, /MAX_DEPTH=64/);
  assert.match(recursiveCheck, /opendirSync/);
  assert.match(recursiveCheck, /directory\.readSync/);
  assert.match(recursiveCheck, /fs\.lstatSync/);
  assert.match(recursiveCheck, /fs\.readlinkSync/);
  assert.match(recursiveCheck, /fs\.realpathSync/);
  assert.match(recursiveCheck, /path\.relative/);
  assert.match(recursiveCheck, /path\.isAbsolute\(raw\)/);
  assert.match(recursiveCheck, /internalTargets\.push/);
  assert.match(recursiveCheck, /validated\.has/);
  assert.match(recursiveCheck, /s\.isDirectory\(\).*s\.isFile\(\)/);
  assert.match(recursiveCheck, /s\.dev!==rs\.dev/);
  assert.match(recursiveCheck, /node_modules\/sleep\/build\/node_gyp_bins\/python3/);
  assert.match(recursiveCheck, /raw==='\/usr\/bin\/python3'/);
  for (const root of [
    '/run/gpt-register-panel/code/backend',
    '/run/gpt-register-panel/code/frontend',
    '/run/gpt-register-panel/code/node_modules',
    '/run/gpt-register-panel/gpt_register/src',
    '/run/gpt-register-panel/gpt_register/node_modules',
  ]) {
    assert.ok(recursiveCheck.endsWith(root) || recursiveCheck.includes(` ${root} `));
  }
});

test('systemd unit limits privilege and writable scope without blocking Phase3 networking', () => {
  const unit = parseUnit(fs.readFileSync(UNIT_PATH, 'utf8'));

  assert.equal(one(unit, 'Service', 'User'), 'root');
  assert.equal(one(unit, 'Service', 'NoNewPrivileges'), 'true');
  assert.equal(one(unit, 'Service', 'PrivateTmp'), 'true');
  assert.equal(one(unit, 'Service', 'PrivateDevices'), 'true');
  assert.equal(one(unit, 'Service', 'ProtectSystem'), 'strict');
  assert.equal(one(unit, 'Service', 'RestrictNamespaces'), 'true');
  assert.equal(one(unit, 'Service', 'CapabilityBoundingSet'), '');
  assert.equal(one(unit, 'Service', 'AmbientCapabilities'), '');
  assert.equal(fs.readFileSync(UNIT_PATH, 'utf8').includes('CAP_SYS_PTRACE'), false);
  assert.equal(one(unit, 'Service', 'LimitCORE'), '0');
  assert.ok(Number(one(unit, 'Service', 'TasksMax')) >= 128);
  assert.deepEqual(
    new Set(one(unit, 'Service', 'RestrictAddressFamilies').split(/\s+/)),
    new Set(['AF_UNIX', 'AF_INET', 'AF_INET6', 'AF_NETLINK']),
  );

  assert.deepEqual(new Set(values(unit, 'Service', 'ReadWritePaths')), new Set([
    '/run/gpt-register-panel/runtime',
    '/run/gpt-register-panel/gpt_register',
  ]));
  assert.equal(values(unit, 'Service', 'ReadWritePaths').some((item) => [
    '/', '/mnt', '/mnt/nvme', '/mnt/nvme/item/gpt-register-panel', '/mnt/nvme/gpt_register',
  ].includes(item)), false);

  const protectedPhase3Paths = values(unit, 'Service', 'ReadOnlyPaths');
  assert.ok(protectedPhase3Paths.includes('/run/gpt-register-panel/code'));
  assert.ok(protectedPhase3Paths.includes('/run/gpt-register-panel/gpt_register/index.js'));
  assert.ok(protectedPhase3Paths.includes('/run/gpt-register-panel/gpt_register/src'));
  assert.ok(protectedPhase3Paths.includes('/run/gpt-register-panel/gpt_register/node_modules'));
  assert.ok(protectedPhase3Paths.includes('/run/gpt-register-panel/gpt_register/config.json'));
  assert.ok(protectedPhase3Paths.includes('/run/gpt-register-panel/gpt_register/config.server.json'));
  assert.ok(protectedPhase3Paths.includes('/etc/gpt-register-panel/panel.env'));
  assert.ok(values(unit, 'Service', 'InaccessiblePaths')
    .includes('-/mnt/nvme/item/gpt-register-panel/.env'));
  assert.ok(values(unit, 'Service', 'InaccessiblePaths')
    .includes('-/mnt/nvme/gpt_register/.git'));
  assert.ok(values(unit, 'Service', 'InaccessiblePaths')
    .includes('-/run/gpt-register-panel/code/.git'));
  assert.ok(values(unit, 'Service', 'InaccessiblePaths')
    .includes('-/run/gpt-register-panel/gpt_register/.git'));
});

test('recursive service preflight accepts only bounded trusted code trees', (context) => {
  if (typeof process.getuid === 'function' && process.getuid() !== 0) {
    context.skip('the production unit and its ownership preflight run as root');
    return;
  }

  const source = fs.readFileSync(UNIT_PATH, 'utf8');
  const program = recursivePreflightCode(source);
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-unit-preflight-'));
  context.after(() => fs.rmSync(fixture, { recursive: true, force: true }));

  const packageDirectory = path.join(fixture, 'package');
  const binDirectory = path.join(packageDirectory, '.bin');
  fs.mkdirSync(binDirectory, { recursive: true });
  fs.writeFileSync(path.join(packageDirectory, 'target.js'), 'module.exports = true;\n', { mode: 0o644 });
  fs.symlinkSync('../target.js', path.join(binDirectory, 'target'));

  const safe = runRecursivePreflight(program, [fixture]);
  assert.equal(safe.status, 0, safe.stderr);

  fs.chmodSync(path.join(packageDirectory, 'target.js'), 0o664);
  const writable = runRecursivePreflight(program, [fixture]);
  assert.notEqual(writable.status, 0);
  assert.match(writable.stderr, /unsafe service code (?:entry|link)/);
  fs.chmodSync(path.join(packageDirectory, 'target.js'), 0o644);

  const externalLink = path.join(packageDirectory, 'external');
  fs.symlinkSync('/usr/bin/node', externalLink);
  const external = runRecursivePreflight(program, [fixture]);
  assert.notEqual(external.status, 0);
  assert.match(external.stderr, /unsafe service code link/);
  fs.unlinkSync(externalLink);

  let deep = path.join(fixture, 'deep');
  fs.mkdirSync(deep);
  for (let index = 0; index < 65; index += 1) {
    deep = path.join(deep, 'd');
    fs.mkdirSync(deep);
  }
  const excessiveDepth = runRecursivePreflight(program, [fixture]);
  assert.notEqual(excessiveDepth.status, 0);
  assert.match(excessiveDepth.stderr, /service code depth limit exceeded/);
});

test('systemd stop policy gives the app a graceful drain window then cleans the cgroup', () => {
  const unit = parseUnit(fs.readFileSync(UNIT_PATH, 'utf8'));

  assert.equal(one(unit, 'Service', 'KillSignal'), 'SIGTERM');
  assert.equal(one(unit, 'Service', 'KillMode'), 'mixed');
  assert.equal(one(unit, 'Service', 'SendSIGKILL'), 'yes');
  assert.ok(Number.parseInt(one(unit, 'Service', 'TimeoutStopSec'), 10) >= 45);
  assert.equal(one(unit, 'Service', 'Restart'), 'on-failure');
});

test('systemd deployment instructions never overwrite an existing secret file', () => {
  const readme = fs.readFileSync(README_PATH, 'utf8');
  const lines = readme.split(/\r?\n/);
  assert.equal(lines.includes(
    '    sudo install -o root -g root -m 0600 .env.example /etc/gpt-register-panel/panel.env',
  ), false);
  assert.equal(lines.includes(
    '    sudo install -o root -g root -m 0600 .env /etc/gpt-register-panel/panel.env',
  ), false);
  assert.ok((readme.match(/sudo test -L \/etc\/gpt-register-panel\/panel\.env/g) || []).length >= 2);
  assert.match(readme, /重复安装或升级不得用 `\.env\.example`、`cp -f` 或 `install` 覆盖/);
  assert.equal(readme.includes('sudo test -d /mnt/nvme/tmp'), false);
});
