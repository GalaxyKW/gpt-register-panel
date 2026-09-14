const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { EventEmitter } = require('node:events');
const test = require('node:test');

require('./test-isolation');

const {
  authFailureBucketCount,
  authorizationError,
  createServer,
  openVerifiedStaticFile,
  phase3ClaimKeys,
  readJsonBody,
  resetAuthFailureBuckets,
  safeStaticPath,
  startServer,
} = require('../backend/server');
const configuredPanelToken = process.env.PANEL_ADMIN_TOKEN || '';

test('static routing exposes only the three declared frontend assets', () => {
  assert.equal(path.basename(safeStaticPath('/')), 'index.html');
  assert.equal(path.basename(safeStaticPath('/app.js')), 'app.js');
  assert.equal(path.basename(safeStaticPath('/styles.css')), 'styles.css');
  assert.equal(safeStaticPath('/debug.json'), null);
  assert.equal(safeStaticPath('/nested/asset.js'), null);
});

test('HTTP server applies bounded slow-request and connection limits', () => {
  const logger = {
    requestId: () => 'bounded-http-test',
    info() {},
    warn() {},
    error() {},
  };
  const server = createServer({ db: { dbPath: '/tmp/unused-panel-test.sqlite3' }, logger });
  assert.equal(server.requestTimeout, 30_000);
  assert.equal(server.headersTimeout, 15_000);
  assert.equal(server.keepAliveTimeout, 5_000);
  assert.equal(server.maxHeadersCount, 100);
  assert.equal(server.maxRequestsPerSocket, 100);
});

test('HTTP limits treat blank values as defaults and clamp explicit bounds', () => {
  const names = [
    'PANEL_HTTP_REQUEST_TIMEOUT_MS',
    'PANEL_HTTP_HEADERS_TIMEOUT_MS',
    'PANEL_HTTP_KEEP_ALIVE_TIMEOUT_MS',
    'PANEL_HTTP_MAX_HEADERS',
    'PANEL_HTTP_MAX_REQUESTS_PER_SOCKET',
  ];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  const logger = {
    requestId: () => 'bounded-http-config-test',
    info() {},
    warn() {},
    error() {},
  };
  try {
    process.env.PANEL_HTTP_REQUEST_TIMEOUT_MS = '   ';
    process.env.PANEL_HTTP_HEADERS_TIMEOUT_MS = '999999';
    process.env.PANEL_HTTP_KEEP_ALIVE_TIMEOUT_MS = '-1';
    process.env.PANEL_HTTP_MAX_HEADERS = 'not-a-number';
    process.env.PANEL_HTTP_MAX_REQUESTS_PER_SOCKET = '0';
    const server = createServer({ db: { dbPath: '/tmp/unused-panel-config-test.sqlite3' }, logger });
    assert.equal(server.requestTimeout, 30_000);
    assert.equal(server.headersTimeout, 30_000);
    assert.equal(server.keepAliveTimeout, 1_000);
    assert.equal(server.maxHeadersCount, 100);
    assert.equal(server.maxRequestsPerSocket, 1);
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  }
});

test('JSON request bodies account for bytes incrementally and reject aborted streams', async () => {
  const requestStream = new EventEmitter();
  requestStream.setEncoding = () => {};
  requestStream.resume = () => {};
  const originalByteLength = Buffer.byteLength;
  const measuredLengths = [];
  Buffer.byteLength = function measuredByteLength(value, ...args) {
    measuredLengths.push(String(value).length);
    return originalByteLength.call(Buffer, value, ...args);
  };
  try {
    const parsedPromise = readJsonBody(requestStream, 64);
    requestStream.emit('data', '{"part":');
    requestStream.emit('data', '"value"}');
    requestStream.emit('end');
    assert.deepEqual(await parsedPromise, { part: 'value' });
    assert.deepEqual(measuredLengths, [8, 8]);
  } finally {
    Buffer.byteLength = originalByteLength;
  }

  const abortedStream = new EventEmitter();
  abortedStream.setEncoding = () => {};
  abortedStream.resume = () => {};
  const abortedPromise = readJsonBody(abortedStream, 64);
  abortedStream.emit('data', '{"partial":');
  abortedStream.emit('aborted');
  await assert.rejects(abortedPromise, (error) => error.code === 'REQUEST_ABORTED');
});

test('server startup waits for database initialization before listening', async () => {
  const sentinel = new Error('database initialization failed');
  const db = { dbPath: '/tmp/unused-panel-ready-test.sqlite3' };
  Object.defineProperty(db, 'ready', {
    get() { return Promise.reject(sentinel); },
  });
  const logger = {
    requestId: () => 'db-ready-test',
    info() {},
    warn() {},
    error() {},
    tail() { return []; },
  };
  await assert.rejects(
    startServer({ host: '127.0.0.1', port: 0, db, logger }),
    (error) => error === sentinel,
  );
});

test('write endpoints fail closed when the audit log becomes unavailable', async () => {
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
  };
  process.env.PANEL_WRITE_ENABLED = '1';
  process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
  let server;
  try {
    const logger = {
      requestId: () => 'audit-log-unavailable-test',
      info() {},
      warn() {},
      error() {},
      probe() { return false; },
      health() { return { healthy: false, failedWrites: 1 }; },
    };
    server = createServer({
      db: { dbPath: '/tmp/unused-panel-audit-log-test.sqlite3' },
      logger,
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const baseUrl = 'http://127.0.0.1:' + server.address().port;
    const response = await postJson(baseUrl, '/api/phase3', {
      accounts: [{ email: 'must-not-queue@example.test' }],
    });
    assert.equal(response.status, 503);
    assert.equal(JSON.parse(response.body).error, 'audit_log_unavailable');
    const health = await request(baseUrl, '/api/health');
    assert.equal(JSON.parse(health.body).auditLog.healthy, false);
  } finally {
    await closeHttpServer(server);
    if (previous.writeEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previous.writeEnabled;
    if (previous.allowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
    else process.env.PANEL_ALLOW_INSECURE_WRITE = previous.allowInsecureWrite;
  }
});

function request(baseUrl, pathname) {
  return new Promise((resolve, reject) => {
    const requestObject = http.get(baseUrl + pathname, configuredPanelToken
      ? { headers: { 'x-panel-token': configuredPanelToken } }
      : {}, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body,
      }));
    });
    requestObject.on('error', reject);
  });
}

function postJson(baseUrl, pathname, body) {
  return new Promise((resolve, reject) => {
    const requestObject = http.request(baseUrl + pathname, {
      method: 'POST',
      headers: {
        ...(configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {}),
        'content-type': 'application/json',
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body: responseBody }));
    });
    requestObject.on('error', reject);
    requestObject.end(JSON.stringify(body));
  });
}

function postBody(baseUrl, pathname, body, contentType) {
  return new Promise((resolve, reject) => {
    const requestObject = http.request(baseUrl + pathname, {
      method: 'POST',
      headers: {
        ...(configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {}),
        ...(contentType ? { 'content-type': contentType } : {}),
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { responseBody += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body: responseBody }));
    });
    requestObject.on('error', reject);
    requestObject.end(body);
  });
}

async function closeHttpServer(server) {
  if (!server || !server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function waitForTerminalJob(baseUrl, jobId) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const response = await request(baseUrl, '/api/jobs/' + encodeURIComponent(jobId));
    assert.equal(response.status, 200);
    const job = JSON.parse(response.body);
    if (['succeeded', 'partial', 'failed', 'interrupted'].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('timed out waiting for test job ' + jobId);
}

test('importing the server does not load deployment environment files', () => {
  const script = [
    "const configPath = require.resolve('./backend/config');",
    'let called = false;',
    'require.cache[configPath] = {',
    '  id: configPath,',
    '  filename: configPath,',
    '  loaded: true,',
    '  exports: { loadEnv() { called = true; } },',
    '};',
    "require('./backend/server');",
    "process.stdout.write(called ? 'called' : 'not-called');",
  ].join('\n');
  const child = spawnSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'not-called');
});

test('test isolation removes inherited Sub2API credentials before snapshot code loads', () => {
  const isolationModule = path.resolve(__dirname, 'test-isolation.js');
  const script = [
    'let fetchCalls = 0;',
    "global.fetch = async () => { fetchCalls += 1; throw new Error('unexpected network'); };",
    "const { buildSnapshot, configuredForSub2Api } = require('./backend/sync');",
    '(async () => {',
    '  const snapshot = await buildSnapshot(new URLSearchParams());',
    '  process.stdout.write(JSON.stringify({',
    '    configured: configuredForSub2Api(),',
    '    fetchCalls,',
    '    accountCount: snapshot.sub2api.accountCount,',
    '  }));',
    '})().catch(() => { process.exitCode = 1; });',
  ].join('\n');
  const child = spawnSync(process.execPath, ['--require', isolationModule, '-e', script], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    env: {
      ...process.env,
      SUB2API_BASE_URL: 'http://127.0.0.1:9',
      SUB2API_ADMIN_API_KEY: 'inherited-test-api-key',
      SUB2API_JWT: 'inherited-test-jwt',
    },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), {
    configured: false,
    fetchCalls: 0,
    accountCount: 0,
  });
});

test('executable entrypoints redact fatal stderr instead of printing raw stacks', () => {
  const serverSource = fs.readFileSync(path.resolve(__dirname, '..', 'backend', 'server.js'), 'utf8');
  const snapshotSource = fs.readFileSync(
    path.resolve(__dirname, '..', 'backend', 'cli', 'snapshot.js'),
    'utf8',
  );
  for (const entrypoint of [serverSource, snapshotSource]) {
    assert.doesNotMatch(entrypoint, /process\.stderr\.write\(error\.stack/);
    assert.match(entrypoint, /process\.stderr\.write\(safeErrorText\(error\)/);
  }
  assert.match(snapshotSource, /async function main\(\) \{\s*loadEnv\(\);/);
});

test('verified static opener rejects final and intermediate symlinks', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-static-'));
  const root = path.join(directory, 'frontend');
  const outside = path.join(directory, 'outside');
  fs.mkdirSync(root);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(root, 'regular.txt'), 'regular');
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside');
  fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(root, 'file-link'));
  fs.symlinkSync(outside, path.join(root, 'directory-link'), 'dir');

  const opened = openVerifiedStaticFile(path.join(root, 'regular.txt'), root);
  try {
    assert.equal(fs.readFileSync(opened.descriptor, 'utf8'), 'regular');
  } finally {
    fs.closeSync(opened.descriptor);
  }
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'file-link'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'directory-link', 'secret.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  assert.throws(
    () => openVerifiedStaticFile(path.join(outside, 'secret.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  fs.chmodSync(path.join(root, 'regular.txt'), 0o666);
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'regular.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  fs.chmodSync(path.join(root, 'regular.txt'), 0o644);
  fs.chmodSync(root, 0o777);
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'regular.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );
  fs.chmodSync(root, 0o755);
  fs.writeFileSync(path.join(root, 'linked.txt'), 'linked');
  fs.linkSync(path.join(root, 'linked.txt'), path.join(root, 'linked-copy.txt'));
  assert.throws(
    () => openVerifiedStaticFile(path.join(root, 'linked.txt'), root),
    (error) => error.code === 'STATIC_PATH_INVALID',
  );

  const raceRoot = path.join(directory, 'race-frontend');
  const savedRoot = path.join(directory, 'race-frontend-original');
  fs.mkdirSync(raceRoot);
  const raceFile = path.join(raceRoot, 'app.js');
  fs.writeFileSync(raceFile, 'trusted');
  fs.writeFileSync(path.join(outside, 'app.js'), 'outside');
  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = function guardedOpen(target, ...args) {
    if (!swapped && target === raceFile) {
      swapped = true;
      fs.renameSync(raceRoot, savedRoot);
      fs.symlinkSync(outside, raceRoot, 'dir');
    }
    return originalOpenSync.call(fs, target, ...args);
  };
  try {
    assert.throws(
      () => openVerifiedStaticFile(raceFile, raceRoot),
      (error) => error.code === 'STATIC_PATH_INVALID',
    );
  } finally {
    fs.openSync = originalOpenSync;
    if (swapped) {
      fs.unlinkSync(raceRoot);
      fs.renameSync(savedRoot, raceRoot);
    }
  }
});

test('authentication failure buckets remain strictly bounded for unique sources', () => {
  const previous = {
    token: process.env.PANEL_ADMIN_TOKEN,
    requireAuth: process.env.PANEL_REQUIRE_AUTH,
    maxFailures: process.env.PANEL_AUTH_MAX_FAILURES,
  };
  process.env.PANEL_ADMIN_TOKEN = 'bounded-test-admin-token';
  process.env.PANEL_REQUIRE_AUTH = '1';
  process.env.PANEL_AUTH_MAX_FAILURES = '10';
  resetAuthFailureBuckets();
  try {
    for (let index = 0; index < 10_025; index += 1) {
      const result = authorizationError({
        headers: { authorization: 'Bearer incorrect' },
        socket: { remoteAddress: 'unique-test-source-' + index },
      });
      assert.equal(result.status, 401);
    }
    assert.equal(authFailureBucketCount(), 10_000);

    resetAuthFailureBuckets();
    process.env.PANEL_AUTH_MAX_FAILURES = '1';
    const sharedSource = { remoteAddress: '198.51.100.20' };
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer incorrect' },
      socket: sharedSource,
    }).status, 401);
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer incorrect' },
      socket: sharedSource,
    }).status, 429);
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer bounded-test-admin-token' },
      socket: sharedSource,
    }), null);
    assert.equal(authorizationError({
      headers: { authorization: 'Bearer incorrect' },
      socket: sharedSource,
    }).status, 401);
  } finally {
    resetAuthFailureBuckets();
    if (previous.token === undefined) delete process.env.PANEL_ADMIN_TOKEN;
    else process.env.PANEL_ADMIN_TOKEN = previous.token;
    if (previous.requireAuth === undefined) delete process.env.PANEL_REQUIRE_AUTH;
    else process.env.PANEL_REQUIRE_AUTH = previous.requireAuth;
    if (previous.maxFailures === undefined) delete process.env.PANEL_AUTH_MAX_FAILURES;
    else process.env.PANEL_AUTH_MAX_FAILURES = previous.maxFailures;
  }
});

test('Phase3 claim keys include every canonical email and phone identity', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-phase3-identity-'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([{
    email: 'canonical@example.test',
    phone: '15550000002',
    password: 'fake-password',
  }]));
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  try {
    const expected = [
      'phase3:email:canonical@example.test',
      'phase3:phone:15550000002',
    ];
    assert.deepEqual(phase3ClaimKeys({ email: 'canonical@example.test' }), expected);
    assert.deepEqual(phase3ClaimKeys({ phone: '15550000002' }), expected);
  } finally {
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});

test('serves a read-only health endpoint and safe source snapshot', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-server-'));
  const previous = {
    writeEnabled: process.env.PANEL_WRITE_ENABLED,
    allowInsecureWrite: process.env.PANEL_ALLOW_INSECURE_WRITE,
    phase3Enabled: process.env.PANEL_PHASE3_ENABLED,
    registerRoot: process.env.GPT_REGISTER_ROOT,
  };
  let server = null;
  process.env.PANEL_WRITE_ENABLED = '0';
  process.env.GPT_REGISTER_ROOT = root;
  try {
    fs.mkdirSync(path.join(root, 'tokens'));
    fs.mkdirSync(path.join(root, 'use_token'));
    fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
      {
        email: 'server@example.test',
        phone: '15550000001',
        password: 'hidden-password',
        status: 'oauth_done',
      },
      {
        email: 'second@example.test',
        password: 'second-hidden-password',
        status: 'oauth_done',
      },
    ]));
    fs.writeFileSync(path.join(root, 'tokens', 'token.json'), JSON.stringify({
      access_token: 'not-a-jwt',
      refresh_token: 'refresh-hidden',
      email: 'server@example.test',
      expired: '2099-01-01T00:00:00.000Z',
    }));
    fs.writeFileSync(path.join(root, 'tokens', 'expired.json'), JSON.stringify({
      access_token: 'expired-access',
      refresh_token: 'expired-refresh-hidden',
      email: 'expired@example.test',
      expired: '2020-01-01T00:00:00.000Z',
    }));
    server = createServer({
      dbPath: path.join(root, 'panel.sqlite3'),
      logger: {
        info() {},
        warn() {},
        error() {},
        requestId(value) { return value || 'test-request'; },
        tail() { return []; },
      },
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });
    const address = server.address();
    const baseUrl = 'http://127.0.0.1:' + address.port;
    const health = await request(baseUrl, '/api/health');
    assert.equal(health.status, 200);
    assert.match(health.body, /"readOnly":true/);
    assert.match(health.headers['content-security-policy'], /base-uri 'none'/);
    assert.match(health.headers['content-security-policy'], /object-src 'none'/);
    assert.match(health.headers['content-security-policy'], /form-action 'none'/);
    assert.equal(health.headers['referrer-policy'], 'no-referrer');
    assert.equal(health.headers['x-frame-options'], 'DENY');

    const healthWrite = await postJson(baseUrl, '/api/health', {});
    assert.equal(healthWrite.status, 405);

    const page = await request(baseUrl, '/');
    assert.equal(page.status, 200);
    assert.match(page.body, /账号管理/);
    assert.match(page.headers['content-security-policy'], /base-uri 'none'/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    const app = await request(baseUrl, '/app.js');
    assert.equal(app.status, 200);
    assert.match(app.body, /resumeActiveJob/);

    const staticWrite = await new Promise((resolve, reject) => {
      const req = http.request(baseUrl + '/', { method: 'POST' }, (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      });
      req.on('error', reject);
      req.end('ignored');
    });
    assert.equal(staticWrite, 405);

    const snapshot = await request(baseUrl, '/api/snapshot');
    assert.equal(snapshot.status, 200);
    assert.match(snapshot.body, /server@example.test/);
    assert.equal(snapshot.body.includes('hidden-password'), false);
    assert.equal(snapshot.body.includes('refresh-hidden'), false);

    const incompletePreview = await postJson(baseUrl, '/api/sync/preview', {
      selectedKeys: [],
    });
    assert.equal(incompletePreview.status, 502);
    assert.equal(JSON.parse(incompletePreview.body).error, 'SUB2API_READ_FAILED');

    const writeAttempt = await new Promise((resolve, reject) => {
      const req = http.request(baseUrl + '/api/snapshot', {
        method: 'POST',
        headers: configuredPanelToken ? { 'x-panel-token': configuredPanelToken } : {},
      }, (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(writeAttempt, 405);

    process.env.PANEL_WRITE_ENABLED = '1';
    process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
    process.env.PANEL_PHASE3_ENABLED = '0';
    const crossSiteStylePost = await postBody(
      baseUrl,
      '/api/phase3',
      JSON.stringify({ accounts: [{ email: 'server@example.test' }] }),
      'text/plain',
    );
    assert.equal(crossSiteStylePost.status, 415);
    assert.equal(JSON.parse(crossSiteStylePost.body).error, 'json_content_type_required');

    const batchPhase3 = await postJson(baseUrl, '/api/phase3', {
      accounts: [
        { email: 'server@example.test' },
        { phone: '15550000001' },
        { email: 'second@example.test' },
      ],
      selectedKeys: ['account:one', 'account:two'],
    });
    assert.equal(batchPhase3.status, 202);
    const batchBody = JSON.parse(batchPhase3.body);
    assert.equal(batchBody.batch, true);
    assert.equal(batchBody.jobIds.length, 2);
    assert.equal(batchBody.rejected.length, 1);
    assert.equal(batchBody.rejected[0].error, 'duplicate_in_request');
    const phase3Jobs = await Promise.all(
      batchBody.jobIds.map((jobId) => waitForTerminalJob(baseUrl, jobId)),
    );
    assert.equal(phase3Jobs.every((job) => job.status === 'failed'), true);
    assert.equal(phase3Jobs.every((job) => job.result?.code === 'PHASE3_DISABLED'), true);

    const expiredListing = await request(baseUrl, '/api/tokens/expired');
    assert.equal(expiredListing.status, 200);
    const expiredBody = JSON.parse(expiredListing.body);
    assert.equal(expiredBody.count, 1);
    assert.equal(expiredListing.body.includes('expired-refresh-hidden'), false);
    const expiredDelete = await postJson(baseUrl, '/api/tokens/expired/delete', {
      version: expiredBody.version,
      confirmation: 'DELETE_EXPIRED_TOKENS',
    });
    assert.equal(expiredDelete.status, 200);
    assert.equal(JSON.parse(expiredDelete.body).count, 1);
    assert.equal(fs.existsSync(path.join(root, 'tokens', 'expired.json')), false);
  } finally {
    try {
      await closeHttpServer(server);
    } finally {
      const names = {
        writeEnabled: 'PANEL_WRITE_ENABLED',
        allowInsecureWrite: 'PANEL_ALLOW_INSECURE_WRITE',
        phase3Enabled: 'PANEL_PHASE3_ENABLED',
        registerRoot: 'GPT_REGISTER_ROOT',
      };
      for (const [key, environmentName] of Object.entries(names)) {
        if (previous[key] === undefined) delete process.env[environmentName];
        else process.env[environmentName] = previous[key];
      }
    }
  }
});
