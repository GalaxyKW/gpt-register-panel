const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createServer } = require('../backend/server');
const configuredPanelToken = process.env.PANEL_ADMIN_TOKEN || '';

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

test('serves a read-only health endpoint and safe source snapshot', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-register-panel-server-'));
  const previousWriteEnabled = process.env.PANEL_WRITE_ENABLED;
  process.env.PANEL_WRITE_ENABLED = '0';
  fs.mkdirSync(path.join(root, 'tokens'));
  fs.mkdirSync(path.join(root, 'use_token'));
  fs.writeFileSync(path.join(root, 'username.json'), JSON.stringify([
    { email: 'server@example.test', password: 'hidden-password', status: 'oauth_done' },
  ]));
  fs.writeFileSync(path.join(root, 'tokens', 'token.json'), JSON.stringify({
    access_token: 'not-a-jwt',
    refresh_token: 'refresh-hidden',
    email: 'server@example.test',
    expired: '2099-01-01T00:00:00.000Z',
  }));
  const previousRoot = process.env.GPT_REGISTER_ROOT;
  process.env.GPT_REGISTER_ROOT = root;
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const baseUrl = 'http://127.0.0.1:' + address.port;
  try {
    const health = await request(baseUrl, '/api/health');
    assert.equal(health.status, 200);
    assert.match(health.body, /"readOnly":true/);

    const snapshot = await request(baseUrl, '/api/snapshot');
    assert.equal(snapshot.status, 200);
    assert.match(snapshot.body, /server@example.test/);
    assert.equal(snapshot.body.includes('hidden-password'), false);
    assert.equal(snapshot.body.includes('refresh-hidden'), false);

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

    const previousAllowInsecureWrite = process.env.PANEL_ALLOW_INSECURE_WRITE;
    const previousPhase3Enabled = process.env.PANEL_PHASE3_ENABLED;
    process.env.PANEL_WRITE_ENABLED = '1';
    process.env.PANEL_ALLOW_INSECURE_WRITE = '1';
    process.env.PANEL_PHASE3_ENABLED = '0';
    try {
      const batchPhase3 = await postJson(baseUrl, '/api/phase3', {
        email: 'server@example.test',
        selectedKeys: ['account:one', 'account:two'],
      });
      assert.equal(batchPhase3.status, 400);
      assert.match(batchPhase3.body, /phase3_single_account_required/);
    } finally {
      if (previousAllowInsecureWrite === undefined) delete process.env.PANEL_ALLOW_INSECURE_WRITE;
      else process.env.PANEL_ALLOW_INSECURE_WRITE = previousAllowInsecureWrite;
      if (previousPhase3Enabled === undefined) delete process.env.PANEL_PHASE3_ENABLED;
      else process.env.PANEL_PHASE3_ENABLED = previousPhase3Enabled;
      process.env.PANEL_WRITE_ENABLED = '0';
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
    if (previousWriteEnabled === undefined) delete process.env.PANEL_WRITE_ENABLED;
    else process.env.PANEL_WRITE_ENABLED = previousWriteEnabled;
    if (previousRoot === undefined) delete process.env.GPT_REGISTER_ROOT;
    else process.env.GPT_REGISTER_ROOT = previousRoot;
  }
});
