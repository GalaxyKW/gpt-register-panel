const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { URL } = require('node:url');

const { readGptRegisterSources, toSafeSources } = require('./adapters/gptRegisterFs');
const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const { buildDiff, toSafeDiff } = require('./diff');
const { buildRows, filterRows, statusOptions, diffOptions } = require('./view');

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
  });
  response.end(payload);
}

function configuredForSub2Api() {
  return Boolean(
    process.env.SUB2API_BASE_URL
      && (process.env.SUB2API_ADMIN_API_KEY || process.env.SUB2API_JWT),
  );
}

async function buildSnapshot(query) {
  const sources = readGptRegisterSources();
  let accounts = [];
  let apiError = null;
  const shouldReadSub2Api = query.get('withSub2api') === '1' || configuredForSub2Api();

  if (shouldReadSub2Api) {
    try {
      const client = new Sub2ApiAdminClient();
      accounts = await client.listAccounts({
        platform: 'openai',
        type: 'oauth',
        pageSize: 200,
      });
    } catch (error) {
      apiError = error.message;
    }
  }

  const diff = buildDiff(sources.tokens, accounts);
  const allRows = buildRows(diff);
  const rows = filterRows(allRows, {
    search: query.get('search'),
    status: query.get('status'),
    source: query.get('source'),
    diffKind: query.get('diff'),
  });
  return {
    readOnly: true,
    generatedAt: sources.generatedAt,
    sources: toSafeSources(sources),
    sub2api: {
      accountCount: accounts.length,
      apiError,
    },
    diff: toSafeDiff(diff),
    rows,
    filters: {
      statuses: statusOptions(allRows),
      sources: ['tokens', 'use_token', 'sub2api'],
      diffKinds: diffOptions(allRows),
    },
  };
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
  return http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url || '/', 'http://localhost');
    if (request.method !== 'GET') {
      response.setHeader('allow', 'GET');
      jsonResponse(response, 405, { error: 'read_only_endpoint' });
      return;
    }

    if (requestUrl.pathname === '/api/health') {
      jsonResponse(response, 200, {
        ok: true,
        readOnly: true,
        sub2apiConfigured: configuredForSub2Api(),
        time: new Date().toISOString(),
      });
      return;
    }

    if (requestUrl.pathname === '/api/snapshot') {
      try {
        jsonResponse(response, 200, await buildSnapshot(requestUrl.searchParams));
      } catch (error) {
        jsonResponse(response, 500, {
          error: 'snapshot_failed',
          message: error.message,
        });
      }
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

