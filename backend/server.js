const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { URL } = require('node:url');

require('./config').loadEnv();
const { buildSnapshot, buildImportPlan, importPlanSummary, executeImport, configuredForSub2Api, safeErrorMessage } = require('./sync');
const { PanelDb } = require('./db');
const { runPhase3Job, getActivePhase3Job } = require('./phase3Worker');
const { createLogger } = require('./logger');

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

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Request handling must continue if the log destination is unavailable.
  }
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
  const logger = options.logger || createLogger({ dbPath: options.dbPath || db.dbPath });
  const server = http.createServer(async (request, response) => {
    const requestId = logger.requestId(request.headers['x-request-id']);
    const actor = requestActor(request);
    const startedAt = Date.now();
    let requestPath = '/';
    let completed = false;
    response.setHeader('x-request-id', requestId);
    response.once('finish', () => {
      completed = true;
      writeLog(logger, 'info', 'http.request_completed', {
        requestId,
        actor,
        method: request.method,
        path: requestPath,
        statusCode: response.statusCode,
        durationMs: Date.now() - startedAt,
      });
    });
    response.once('close', () => {
      if (!completed) {
        writeLog(logger, 'warn', 'http.request_closed', {
          requestId,
          actor,
          method: request.method,
          path: requestPath,
          statusCode: response.statusCode,
          durationMs: Date.now() - startedAt,
        });
      }
    });
    try { requestPath = new URL(request.url || '/', 'http://localhost').pathname; } catch {}
    writeLog(logger, 'info', 'http.request_started', {
      requestId,
      actor,
      method: request.method,
      path: requestPath,
    });
    try {
      const requestUrl = new URL(request.url || '/', 'http://localhost');
      requestPath = requestUrl.pathname;
      const isReadOnlyGet = request.method === 'GET';
      const requiresWrite = request.method === 'POST'
        && ['/api/sync/import', '/api/phase3'].includes(requestUrl.pathname);
      const authError = requestUrl.pathname.startsWith('/api/')
        ? authorizationError(request, requiresWrite)
        : null;
      if (authError) {
        writeLog(logger, 'warn', 'http.auth_failed', {
          requestId,
          actor,
          method: request.method,
          path: requestUrl.pathname,
          statusCode: authError.status,
          error: authError.error,
        });
        jsonResponse(response, authError.status, authError);
        return;
      }
      if (!isReadOnlyGet && request.method !== 'POST') {
        writeLog(logger, 'warn', 'http.method_not_allowed', {
          requestId,
          actor,
          method: request.method,
          path: requestUrl.pathname,
        });
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
        writeLog(logger, 'warn', 'http.method_not_allowed', {
          requestId,
          actor,
          method: request.method,
          path: requestUrl.pathname,
        });
        response.setHeader('allow', 'GET');
        jsonResponse(response, 405, { error: 'read_only_endpoint' });
        return;
      }
      try {
        jsonResponse(response, 200, await buildSnapshot(requestUrl.searchParams, { logger, requestId, actor }));
      } catch (error) {
        writeLog(logger, 'error', 'http.snapshot_failed', {
          requestId,
          actor,
          error: safeErrorMessage(error),
        });
        jsonResponse(response, 500, {
          error: 'snapshot_failed',
          message: safeErrorMessage(error),
        });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/sync/preview') {
      const previewStartedAt = Date.now();
      writeLog(logger, 'info', 'preview.started', { requestId, actor });
      try {
        const body = await readJsonBody(request);
        const snapshot = await buildSnapshot(new URLSearchParams('withSub2api=1'), {
          includeRaw: true,
          includeInternal: true,
          logger,
          requestId,
          actor,
        });
        const plan = buildImportPlan(snapshot._internal.sources, snapshot._internal.accounts, body.selectedKeys);
        const snapshotId = await db.saveSnapshot(snapshot);
        writeLog(logger, 'info', 'preview.completed', {
          requestId,
          actor,
          snapshotId,
          version: snapshot.version,
          durationMs: Date.now() - previewStartedAt,
          counts: importPlanSummary(plan).counts,
        });
        jsonResponse(response, 200, {
          readOnly: process.env.PANEL_WRITE_ENABLED !== '1',
          snapshotId,
          version: snapshot.version,
          generatedAt: snapshot.generatedAt,
          ...importPlanSummary(plan),
        });
      } catch (error) {
        writeLog(logger, 'error', 'preview.failed', {
          requestId,
          actor,
          durationMs: Date.now() - previewStartedAt,
          error: safeErrorMessage(error),
        });
        jsonResponse(response, 400, { error: 'preview_failed', message: safeErrorMessage(error) });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/sync/import') {
      const importRequestStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        const job = await db.createJob('token_import', {
          snapshotVersion: body.snapshotVersion || null,
          selectedKeys: Array.isArray(body.selectedKeys) ? body.selectedKeys : [],
        }, actor);
        await db.updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });
        writeLog(logger, 'info', 'import.job_queued', {
          requestId,
          jobId: job.id,
          actor,
          expectedVersion: body.snapshotVersion || null,
          selectedCount: Array.isArray(body.selectedKeys) ? body.selectedKeys.length : 0,
          durationMs: Date.now() - importRequestStartedAt,
        });
        executeImport({
          snapshotVersion: body.snapshotVersion,
          selectedKeys: body.selectedKeys,
          actor,
          db,
          jobId: job.id,
          logger,
        }).then(async (result) => {
          const status = result.failed > 0 ? 'partial' : 'succeeded';
          await db.updateJob(job.id, {
            status,
            result,
            finishedAt: new Date().toISOString(),
          });
          writeLog(logger, status === 'partial' ? 'warn' : 'info', 'import.job_completed', {
            requestId,
            jobId: job.id,
            actor,
            status,
            importedCount: result.imported?.length || 0,
            failed: result.failed || 0,
          });
        }).catch(async (error) => {
          const message = safeErrorMessage(error);
          try {
            await db.audit({ jobId: job.id, actor, action: 'token_import', result: 'failed', details: { error: message } });
          } catch (auditError) {
            writeLog(logger, 'error', 'import.audit_failed', {
              requestId,
              jobId: job.id,
              actor,
              error: safeErrorMessage(auditError),
            });
          }
          try {
            await db.updateJob(job.id, {
              status: 'failed',
              error: message,
              finishedAt: new Date().toISOString(),
            });
          } catch (jobError) {
            writeLog(logger, 'error', 'import.job_update_failed', {
              requestId,
              jobId: job.id,
              actor,
              error: safeErrorMessage(jobError),
            });
          }
          writeLog(logger, 'error', 'import.job_failed', {
            requestId,
            jobId: job.id,
            actor,
            error: message,
          });
        });
        jsonResponse(response, 202, { jobId: job.id, status: 'running' });
      } catch (error) {
        writeLog(logger, 'error', 'import.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - importRequestStartedAt,
          error: safeErrorMessage(error),
        });
        jsonResponse(response, 400, { error: 'import_failed', message: safeErrorMessage(error) });
      }
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/phase3') {
      const phase3RequestStartedAt = Date.now();
      try {
        const body = await readJsonBody(request);
        if (body.selectedKeys !== undefined
            && (!Array.isArray(body.selectedKeys) || body.selectedKeys.length !== 1)) {
          writeLog(logger, 'warn', 'phase3.batch_rejected', {
            requestId,
            actor,
            selectedCount: Array.isArray(body.selectedKeys) ? body.selectedKeys.length : null,
          });
          jsonResponse(response, 400, {
            error: 'phase3_single_account_required',
            message: 'Phase 3 只支持单账号提交，不能批量选择',
          });
          return;
        }
        if (!body.email && !body.phone) throw new Error('email 或 phone 必须提供一个');
        const existingPhase3Job = getActivePhase3Job({ email: body.email, phone: body.phone });
        if (existingPhase3Job) {
          writeLog(logger, 'warn', 'phase3.duplicate_rejected', {
            requestId,
            actor,
            email: body.email || null,
            phone: body.phone || null,
            existingJobId: existingPhase3Job.jobId || null,
          });
          jsonResponse(response, 409, {
            error: 'phase3_already_running',
            message: '该账号已有 Phase 3 任务排队或运行中',
            jobId: existingPhase3Job.jobId || null,
          });
          return;
        }
        const job = await db.createJob('phase3', { email: body.email || null, phone: body.phone || null }, actor);
        writeLog(logger, 'info', 'phase3.job_queued', {
          requestId,
          jobId: job.id,
          actor,
          email: body.email || null,
          phone: body.phone || null,
          durationMs: Date.now() - phase3RequestStartedAt,
        });
        runPhase3Job({ email: body.email, phone: body.phone, actor, db, jobId: job.id, logger })
          .then(async (result) => {
            await db.updateJob(job.id, { status: 'succeeded', result, finishedAt: new Date().toISOString() });
            writeLog(logger, 'info', 'phase3.job_completed', {
              requestId,
              jobId: job.id,
              actor,
              email: result.email,
              tokenFile: result.tokenFile,
              fingerprint: result.fingerprint,
            });
          })
          .catch(async (error) => {
            const message = safeErrorMessage(error);
            try {
              await db.audit({ jobId: job.id, actor, action: 'phase3', result: 'failed', details: { error: message } });
            } catch (auditError) {
              writeLog(logger, 'error', 'phase3.audit_failed', {
                requestId,
                jobId: job.id,
                actor,
                error: safeErrorMessage(auditError),
              });
            }
            try {
              await db.updateJob(job.id, { status: 'failed', error: message, finishedAt: new Date().toISOString() });
            } catch (jobError) {
              writeLog(logger, 'error', 'phase3.job_update_failed', {
                requestId,
                jobId: job.id,
                actor,
                error: safeErrorMessage(jobError),
              });
            }
            writeLog(logger, 'error', 'phase3.job_failed', {
              requestId,
              jobId: job.id,
              actor,
              error: message,
            });
          });
        jsonResponse(response, 202, { jobId: job.id, status: 'running' });
      } catch (error) {
        writeLog(logger, 'error', 'phase3.request_failed', {
          requestId,
          actor,
          durationMs: Date.now() - phase3RequestStartedAt,
          error: safeErrorMessage(error),
        });
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

    if (request.method === 'GET' && requestUrl.pathname === '/api/logs') {
      const requestedLevel = requestUrl.searchParams.get('level');
      const requestedEvent = requestUrl.searchParams.get('event');
      let logs = logger.tail(requestUrl.searchParams.get('limit'));
      if (requestedLevel) logs = logs.filter((entry) => entry.level === requestedLevel);
      if (requestedEvent) logs = logs.filter((entry) => entry.event === requestedEvent);
      jsonResponse(response, 200, {
        count: logs.length,
        logs,
      });
      return;
    }

    serveStatic(request, response);
    } catch (error) {
      writeLog(logger, 'error', 'http.request_failed', {
        requestId,
        actor,
        method: request.method,
        path: requestPath,
        statusCode: 500,
        error: safeErrorMessage(error),
      });
      if (!response.headersSent) {
        jsonResponse(response, 500, { error: 'internal_error', message: safeErrorMessage(error) });
      } else if (!response.writableEnded) {
        response.end();
      }
    }
  });
  server.panelLogger = logger;
  return server;
}

function startServer(options = {}) {
  const host = options.host || process.env.PANEL_HOST || '127.0.0.1';
  const port = Number(options.port || process.env.PANEL_PORT || 4170);
  const server = createServer(options);
  return new Promise((resolve, reject) => {
    server.once('error', (error) => {
      writeLog(server.panelLogger, 'error', 'server.start_failed', {
        host,
        port,
        error: safeErrorMessage(error),
      });
      reject(error);
    });
    server.listen(port, host, () => {
      const address = server.address();
      writeLog(server.panelLogger, 'info', 'server.started', {
        host,
        port: address.port,
        pid: process.pid,
      });
      process.stdout.write('gpt-register-panel listening on http://' + host + ':' + address.port + '\n');
      resolve(server);
    });
    server.once('close', () => {
      writeLog(server.panelLogger, 'info', 'server.stopped', { host, port });
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
