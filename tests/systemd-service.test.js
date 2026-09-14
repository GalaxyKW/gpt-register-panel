const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const UNIT_PATH = path.resolve(__dirname, '..', 'deploy', 'gpt-register-panel.service');

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

test('systemd unit pins its executable and refuses a missing or read-only data mount', () => {
  const source = fs.readFileSync(UNIT_PATH, 'utf8');
  const unit = parseUnit(source);

  assert.equal(one(unit, 'Unit', 'RequiresMountsFor'), '/mnt/nvme');
  assert.equal(one(unit, 'Unit', 'BindsTo'), 'mnt-nvme.mount');
  assert.equal(one(unit, 'Unit', 'AssertPathIsMountPoint'), '/mnt/nvme');
  assert.equal(one(unit, 'Unit', 'AssertPathIsReadWrite'), '/mnt/nvme');
  assert.equal(
    one(unit, 'Service', 'ExecStart'),
    '/usr/bin/node /mnt/nvme/item/gpt-register-panel/backend/server.js',
  );
  assert.equal(values(unit, 'Service', 'EnvironmentFile').length, 0);
  assert.ok(values(unit, 'Service', 'Environment')
    .includes('PANEL_ENV_FILE=/etc/gpt-register-panel/panel.env'));
  assert.equal(/(?:^|\s)(?:\/bin\/)?(?:ba|z|da)?sh(?:\s|$)/m.test(source), false);

  const preflight = values(unit, 'Service', 'ExecStartPre');
  assert.ok(preflight.includes('/usr/bin/test -r /etc/gpt-register-panel/panel.env'));
  assert.ok(preflight.includes('/usr/bin/test -x /usr/bin/node'));
  assert.ok(preflight.includes('/usr/bin/test -d /mnt/nvme/item/gpt-register-panel/runtime'));
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
    '/mnt/nvme/item/gpt-register-panel/runtime',
    '/mnt/nvme/gpt_register',
    '/mnt/nvme/tmp',
  ]));
  assert.equal(values(unit, 'Service', 'ReadWritePaths').some((item) => [
    '/', '/mnt', '/mnt/nvme', '/mnt/nvme/item/gpt-register-panel',
  ].includes(item)), false);

  const protectedPhase3Paths = values(unit, 'Service', 'ReadOnlyPaths');
  assert.ok(protectedPhase3Paths.includes('/mnt/nvme/gpt_register/index.js'));
  assert.ok(protectedPhase3Paths.includes('/mnt/nvme/gpt_register/src'));
  assert.ok(protectedPhase3Paths.includes('/mnt/nvme/gpt_register/node_modules'));
  assert.ok(protectedPhase3Paths.includes('/etc/gpt-register-panel/panel.env'));
  assert.ok(values(unit, 'Service', 'InaccessiblePaths')
    .includes('-/mnt/nvme/item/gpt-register-panel/.env'));
  assert.ok(values(unit, 'Service', 'InaccessiblePaths')
    .includes('-/mnt/nvme/gpt_register/.git'));
});

test('systemd stop policy gives the app a graceful drain window then cleans the cgroup', () => {
  const unit = parseUnit(fs.readFileSync(UNIT_PATH, 'utf8'));

  assert.equal(one(unit, 'Service', 'KillSignal'), 'SIGTERM');
  assert.equal(one(unit, 'Service', 'KillMode'), 'mixed');
  assert.equal(one(unit, 'Service', 'SendSIGKILL'), 'yes');
  assert.ok(Number.parseInt(one(unit, 'Service', 'TimeoutStopSec'), 10) >= 45);
  assert.equal(one(unit, 'Service', 'Restart'), 'on-failure');
});
