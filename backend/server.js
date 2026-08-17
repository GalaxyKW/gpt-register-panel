const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { URL } = require('node:url');

require('./config').loadEnv();
const { buildSnapshot, buildImportPlan, importPlanSummary, executeImport, configuredForSub2Api, safeErrorMessage } = require('./sync');
const { PanelDb } = require('./db');
const { runPhase3Job } = require('./phase3Worker');

const FRONTEND_ROOT = path.resolve(__dirname, '..', 'frontend');
const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

function jsonResponse(response, statusCode, body) {
  const payload = JSON.stringify(body);
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'",
  });
  response.end(payload);
}

function configuredPanelToken() {
  return String(process.env.PANEL_ADMIN_TOKEN || '');
}

function headerToken(request) {
  const authorization = String(request.headers.authorization || '');
  if (authorization.toLowerCase().startsWith('bearer ')) return authorization.slice(7).trim();
  return String(request.headers['x-panel-token'] || '');
}

function authorizationError(request, write = false) {
  const configuredToken = configuredPanelToken();
  const shouldProtectRead = process.env.PANEL_REQUIRE_AUTH === '1' || configuredToken;
  if (shouldProtectRead && (!configuredToken || headerToken(request) !== configuredToken)) {
    return { status: 401, error: 'panel_auth_required', message: '需要有效的面板管理员令牌' };
  }
  if (write) {
    if (process.env.PANEL_WRITE_ENABLED !== '1') {
      return { status: 403, error: 'write_disabled', message: '写操作未启用，请设置 PANEL_WRITE_ENABLED=1' };
    }
    if (!configuredToken && process.env.PANEL_ALLOW_INSECURE_WRITE !== '1') {
      return { status: 503, error: 'write_auth_required', message: '写操作必须配置 PANEL_ADMIN_TOKEN' };
    }
  }
  return null;
}

function requestActor(request) {
  const value = String(request.headers['x-panel-actor'] || 'local').trim();
  return value.replace(/[^A-Za-z0-9_.:@-]/g, '').slice(0, 80) || 'local';
}

function readJsonBody(request, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > limit) {
        reject(new Error('request body too large'));
        request.destroy();
      }
    });
    request.on('end', () => {
      if (!body.trim()) return resolve({});
      try { resolve(JSON.parse(body)); } catch { reject(new Error('invalid JSON body')); }
    });
    request.on('error', reject);
  });
}

function pathParam(pathname, prefix) {
  if (!pathname.startsWith(prefix)) return null;
  const value = pathname.slice(prefix.length);
  return value && !value.includes('/') ? decodeURIComponent(value) : null;
}

function safeStaticPath(urlPath) {
  const decoded = decodeURIComponent(urlPath === '/' ? '/index.html' : urlPath);
  const absolute = path.resolve(FRONTEND_ROOT, '.' + decoded);
  if (absolute !== FRONTEND_ROOT && !absolute.startsWith(FRONTEND_ROOT + path.sep)) return null;
  return absolute;
}

function serveStatic(request, response) {
  const filePath = safeStaticPath(new URL(request.url, 'http://localhost').pathname);
  if (!filePath || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    jsonResponse(response, 404, { error: 'not_found' });
    return;
  }
  const extension = path.extname(filePath).toLowerCase();
  response.writeHead(200, {
    'content-type': CONTENT_TYPES[extension] || 'application/octet-stream',
    'cache-control': 'no-cache',
    'x-content-type-options': 'nosniff',
  });
  fs.createReadStream(filePath).pipe(response);
}

function createServer(options = {}) {
  const db = options.db || new PanelDb(options.dbPath);
  return http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url || '/', 'http://localhost');
    const isReadOnlyGet = request.method === 'GET';
    const requiresWrite = request.method === 'POST'
      && ['/api/sync/import', '/api/phase3'].includes(requestUrl.pathname);
    const authError = requestUrl.pathname.startsWith('/api/')
      ? authorizationError(request, requiresWrite)
      : null;
    if (authError) {
      jsonResponse(response, authError.status, authError);
      return;
    }
    if (!isReadOnlyGet && request.method !== 'POST') {
      response.setHeader('allow', 'GET');
      jsonResponse(response, 405, { error: 'read_only_endpoint' });
      return;
    }

    if (requestUrl.pathname === '/api/health') {
      jsonResponse(response, 200, {
        ok: true,
        readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
        sub2apiConfigured: configuredForSub2Api(),
        authConfigured: Boolean(configuredPanelToken()),
        time: new Date().toISOString(),
      });
      return;
    }

    if (requestUrl.pathname === '/api/snapshot') {
      if (request.method !== 'GET') {
        response.setHeader('allow', 'GET');
        jsonResponse(response, 405, { error: 'read_only_endpoint' });
        return;
      }
      try {
        jsonResponse(response, 200, await buildSnapshot(requestUrl.searchParams));
      } catch (error) {
        jsonResponse(response, 500, {
          error: 'snapshot_failed',
          message: safeErrorMessage(error),
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/sync/preview') {
      try {
        const body = await readJsonBody(request);
        const snapshot = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
          includeRaw: true,
          includeInternal: true,
        });
        const plan = buildImportPlan(snapshot._internal.sources, snapshot._internal.accounts, body.selectedKeys);
        const snapshotId = await db.saveSnapshot(snapshot);
        jsonResponse(response, 200, {
          readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
          snapshotId,
          version: snapshot.version,
          generatedAt: snapshot.generatedAt,
          ...importPlanSummary(plan),
        });
      } catch (error) {
        jsonResponse(response, 400, { error: 'preview_failed', message: safeErrorMessage(error) });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/sync/import') {
      try {
        const body = await readJsonBody(request);
        const actor = requestActor(request);
        const job = await db.createJob('token_import', {
          snapshotVersion: body.snapshotVersion || null,
          selectedKeys: Array.isArray(body.selectedKeys) ? body.selectedKeys : [],
        }, actor);
        await db.updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });
        executeImport({
          snapshotVersion: body.snapshotVersion,
          selectedKeys: body.selectedKeys,
          actor,
          db,
          jobId: job.id,
        }).then(async (result) => {
          await db.updateJob(job.id, {
            status: result.failed > 0 ? 'partial' : 'succeeded',
            result,
            finishedAt: new Date().toISOString(),
          });
        }).catch(async (error) => {
          await db.audit({ jobId: job.id, actor, action: 'token_import', result: 'failed', details: { error: safeErrorMessage(error) } });
          await db.updateJob(job.id, {
            status: 'failed',
            error: safeErrorMessage(error),
            finishedAt: new Date().toISOString(),
          });
        });
        jsonResponse(response, 202, { jobId: job.id, status: 'running' });
      } catch (error) {
        jsonResponse(response, 400, { error: 'import_failed', message: safeErrorMessage(error) });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/phase3') {
      try {
        const body = await readJsonBody(request);
        if (!body.email && !body.phone) throw new Error('email 或 phone 必须提供一个');
        const actor = requestActor(request);
        const job = await db.createJob('phase3', { email: body.email || null, phone: body.phone || null }, actor);
        await db.updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });
        runPhase3Job({ email: body.email, phone: body.phone, actor, db, jobId: job.id })
          .then((result) => db.updateJob(job.id, { status: 'succeeded', result, finishedAt: new Date().toISOString() }))
          .catch((error) => Promise.all([
            db.audit({ jobId: job.id, actor, action: 'phase3', result: 'failed', details: { error: safeErrorMessage(error) } }),
            db.updateJob(job.id, { status: 'failed', error: safeErrorMessage(error), finishedAt: new Date().toISOString() }),
          ]));
        jsonResponse(response, 202, { jobId: job.id, status: 'running' });
      } catch (error) {
        jsonResponse(response, 400, { error: 'phase3_failed', message: safeErrorMessage(error) });
      }
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/jobs') {
      jsonResponse(response, 200, { jobs: await db.listJobs(requestUrl.searchParams.get('limit')) });
      return;
    }

    const jobId = pathParam(requestUrl.pathname, '/api/jobs/');
    if (request.method === 'GET' && jobId) {
      const job = await db.getJob(jobId);
      if (!job) jsonResponse(response, 404, { error: 'job_not_found' });
      else jsonResponse(response, 200, job);
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/api/audit') {
      jsonResponse(response, 200, { events: await db.listAudit(requestUrl.searchParams.get('limit')) });
      return;
    }

    serveStatic(request, response);
  });
}

function startServer(options = {}) {
  const host = options.host || process.env.PANEL_HOST || '127.0.0.1';
  const port = Number(options.port || process.env.PANEL_PORT || 4170);
  const server = createServer(options);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const address = server.address();
      process.stdout.write('gpt-register-panel listening on http://' + host + ':' + address.port + '\n');
      resolve(server);
    });
  });
}

if (require.main === module) {
  startServer().catch((error) => {
    process.stderr.write(error.stack + '\n');
    process.exitCode = 1;
  });
}

module.exports = {
  buildSnapshot,
  createServer,
  startServer,
};
