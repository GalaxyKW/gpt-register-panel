const assert = require('node:assert/strict');
const test = require('node:test');

require('./test-isolation');

const {
  Sub2ApiAdminClient,
  parseSseEvents,
} = require('../backend/adapters/sub2apiAdmin');

function clientWithLogs(logs = []) {
  const logger = {};
  for (const level of ['info', 'warn', 'error']) {
    logger[level] = (event, fields) => logs.push({ level, event, fields });
  }
  return new Sub2ApiAdminClient({
    baseUrl: 'http://127.0.0.1:8080',
    apiKey: 'adapter-test-key',
    logger,
    testTimeoutMs: 10_000,
  });
}

function streamFromText(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  let sent = false;
  return {
    getReader() {
      return {
        async read() {
          if (sent || bytes.length === 0) return { done: true, value: undefined };
          sent = true;
          return { done: false, value: bytes };
        },
        async cancel() {},
        releaseLock() {},
      };
    },
    async cancel() {},
  };
}

function response(body, options = {}) {
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    statusText: options.statusText || 'OK',
    headers: options.headers === null
      ? undefined
      : { 'Content-Type': options.contentType || 'text/event-stream; charset=utf-8' },
    body: Object.prototype.hasOwnProperty.call(options, 'stream')
      ? options.stream
      : streamFromText(body),
    async text() { return body; },
  };
}

async function withFetch(fetchImplementation, callback) {
  const originalFetch = global.fetch;
  global.fetch = fetchImplementation;
  try {
    return await callback();
  } finally {
    global.fetch = originalFetch;
  }
}

function assertUnknown(error, reason) {
  assert.equal(error.code, 'SUB2API_TEST_RESPONSE_INVALID');
  assert.equal(error.requiresReconciliation, true);
  assert.equal(error.reconciliationScope, 'test');
  assert.equal(error.testOutcomeUnknown, true);
  assert.equal(error.reconciliationReason, reason);
  assert.equal(error.testSuccessKnown, undefined);
  return true;
}

test('Sub2API account test accepts only a final unique success terminal', async () => {
  const client = clientWithLogs();
  const valid = [
    ': initial keepalive',
    '',
    'event: progress',
    'data: {"type":"status","text":"running"}',
    '',
    'data: {"type":"test_complete",',
    'data: "success":true,"model":"gpt-5.6-luna"}',
    '',
    ': terminal keepalive',
    '',
    'data: [DONE]',
    '',
  ].join('\r\n');
  const result = await withFetch(
    async () => response(valid),
    () => client.testAccount(7, { modelId: 'gpt-5.6-luna' }),
  );
  assert.equal(result.success, true);
  assert.equal(result.model, 'gpt-5.6-luna');

  assert.deepEqual(
    parseSseEvents(valid).map((event) => event.type),
    ['status', 'test_complete'],
  );
});

test('Sub2API error terminals are definite failures without returning remote text', async () => {
  const opaqueDetail = 'opaque-upstream-detail-7319';
  const logs = [];
  const client = clientWithLogs(logs);
  for (const terminal of [
    '{"type":"error"}',
    JSON.stringify({ type: 'error', error: opaqueDetail }),
    JSON.stringify({ type: 'test_complete', success: false, message: opaqueDetail }),
  ]) {
    const result = await withFetch(
      async () => response(`data: ${terminal}\n\n`),
      () => client.testAccount(8),
    );
    assert.equal(result.success, false);
    assert.equal(result.message, 'Sub2API 返回失败测试结果');
    assert.equal(JSON.stringify(result).includes(opaqueDetail), false);
  }
  assert.equal(JSON.stringify(logs).includes(opaqueDetail), false);

  const unrequestedModel = await withFetch(
    async () => response(`data: ${JSON.stringify({
      type: 'test_complete',
      success: true,
      model: opaqueDetail,
    })}\n\n`),
    () => client.testAccount(8),
  );
  assert.equal(unrequestedModel.success, true);
  assert.equal(unrequestedModel.model, null);
  assert.equal(JSON.stringify(unrequestedModel).includes(opaqueDetail), false);
  assert.equal(JSON.stringify(logs).includes(opaqueDetail), false);
});

test('Sub2API contradictory, malformed, and incomplete SSE outcomes remain unknown', async () => {
  const logs = [];
  const client = clientWithLogs(logs);
  const cases = [
    {
      reason: 'empty_response',
      body: '',
    },
    {
      reason: 'malformed_json',
      body: 'data: {bad-json}\n\ndata: {"type":"test_complete","success":true}\n\n',
    },
    {
      reason: 'invalid_event_shape',
      body: 'data: ["not-an-event"]\n\ndata: {"type":"test_complete","success":true}\n\n',
    },
    {
      reason: 'duplicate_terminal',
      body: 'data: {"type":"error"}\n\ndata: {"type":"test_complete","success":true}\n\n',
    },
    {
      reason: 'duplicate_terminal',
      body: 'data: {"type":"test_complete","success":true}\n\ndata: {"type":"error"}\n\n',
    },
    {
      reason: 'duplicate_terminal',
      body: 'data: {"type":"test_complete","success":true}\n\ndata: {"type":"test_complete","success":true}\n\n',
    },
    {
      reason: 'event_after_terminal',
      body: 'data: {"type":"test_complete","success":true}\n\ndata: {"type":"status"}\n\n',
    },
    {
      reason: 'malformed_json',
      body: 'data: {"type":"test_complete","success":true}\n\ndata: {bad-json}\n\n',
    },
    {
      reason: 'event_after_done',
      body: 'data: {"type":"test_complete","success":true}\n\ndata: [DONE]\n\ndata: {"type":"status"}\n\n',
    },
    {
      reason: 'done_before_terminal',
      body: 'data: [DONE]\n\ndata: {"type":"test_complete","success":true}\n\n',
    },
    {
      reason: 'invalid_terminal',
      body: 'data: {"type":"test_complete"}\n\n',
    },
    {
      reason: 'conflicting_terminal',
      body: 'data: {"type":"test_complete","success":true,"message":"contradiction"}\n\n',
    },
    {
      reason: 'missing_terminal',
      body: 'data: {"type":"status","text":"running"}\n\n',
    },
  ];

  for (const scenario of cases) {
    await withFetch(
      async () => response(scenario.body),
      () => assert.rejects(
        client.testAccount(9),
        (error) => assertUnknown(error, scenario.reason),
      ),
    );
  }
  const failures = logs.filter((entry) => entry.event === 'sub2api.account_test_failed');
  assert.equal(failures.length, cases.length);
  assert.equal(failures.every((entry) => entry.fields.testOutcomeUnknown === true), true);
});

test('Sub2API account tests reject a tampered request origin before logging or fetch', async () => {
  const logs = [];
  const client = clientWithLogs(logs);
  let fetchCalls = 0;
  await withFetch(
    async () => {
      fetchCalls += 1;
      throw new Error('fetch must not run');
    },
    async () => {
      for (const baseUrl of [
        'http://evil.example',
        'http://user@127.0.0.1:8080',
      ]) {
        client.baseUrl = baseUrl;
        await assert.rejects(
          client.testAccount(9),
          (error) => error.code === 'SUB2API_REQUEST_TARGET_INVALID',
        );
      }
    },
  );
  assert.equal(fetchCalls, 0);
  assert.deepEqual(logs, []);
});

test('Sub2API account test rejects non-SSE, failed HTTP, and invalid UTF-8 as unknown', async () => {
  const client = clientWithLogs();
  const successEvent = 'data: {"type":"test_complete","success":true}\n\n';

  await withFetch(
    async () => response(successEvent, { contentType: 'application/json' }),
    () => assert.rejects(
      client.testAccount(10),
      (error) => assertUnknown(error, 'invalid_content_type'),
    ),
  );
  await withFetch(
    async () => response(successEvent, { headers: null }),
    () => assert.rejects(
      client.testAccount(10),
      (error) => assertUnknown(error, 'invalid_content_type'),
    ),
  );
  await withFetch(
    async () => response(successEvent, {
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
    }),
    () => assert.rejects(
      client.testAccount(10),
      (error) => {
        assert.equal(error.code, 'SUB2API_TEST_REQUEST_REJECTED');
        assert.equal(error.testOutcomeUnknown, true);
        assert.equal(error.reconciliationReason, 'response_rejected');
        return true;
      },
    ),
  );

  const prefix = Buffer.from('data: {"type":"status","text":"', 'utf8');
  const suffix = Buffer.from('"}\n\ndata: {"type":"test_complete","success":true}\n\n', 'utf8');
  const invalidBytes = Buffer.concat([prefix, Buffer.from([0xc3, 0x28]), suffix]);
  let read = false;
  const invalidUtf8Stream = {
    getReader() {
      return {
        async read() {
          if (read) return { done: true, value: undefined };
          read = true;
          return { done: false, value: invalidBytes };
        },
        releaseLock() {},
      };
    },
  };
  await withFetch(
    async () => response('', { stream: invalidUtf8Stream }),
    () => assert.rejects(
      client.testAccount(10),
      (error) => assertUnknown(error, 'invalid_utf8'),
    ),
  );
});

test('Sub2API responses fail closed instead of using an unbounded text fallback', async () => {
  const client = clientWithLogs();
  let textCalls = 0;
  const textOnlyResponse = (contentType) => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Headers({ 'content-type': contentType }),
    body: null,
    async text() {
      textCalls += 1;
      return 'data: {"type":"test_complete","success":true}\n\n';
    },
  });

  await withFetch(
    async () => textOnlyResponse('text/event-stream'),
    () => assert.rejects(
      client.testAccount(11),
      (error) => assertUnknown(error, 'response_stream_unavailable'),
    ),
  );
  await withFetch(
    async () => textOnlyResponse('application/json'),
    () => assert.rejects(
      client.request('GET', '/api/v1/admin/accounts/11'),
      (error) => error.code === 'SUB2API_RESPONSE_STREAM_UNAVAILABLE',
    ),
  );
  assert.equal(textCalls, 0);

  const chunks = [
    Buffer.from('{"code":0,"data":'),
    Buffer.from('{"accepted":true}}'),
  ];
  const result = await withFetch(
    async () => ({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      body: {
        async *[Symbol.asyncIterator]() {
          yield* chunks;
        },
      },
    }),
    () => client.request('GET', '/api/v1/admin/accounts/11'),
  );
  assert.deepEqual(result, { accepted: true });

  let readerCalls = 0;
  let cancelCalls = 0;
  await withFetch(
    async () => ({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      body: {
        getReader() {
          readerCalls += 1;
          throw new Error('body must not be read');
        },
        async cancel() { cancelCalls += 1; },
      },
    }),
    () => assert.rejects(
      client.request('GET', '/api/v1/admin/accounts/11'),
      (error) => error.code === 'SUB2API_RESPONSE_CONTENT_TYPE_INVALID',
    ),
  );
  assert.equal(readerCalls, 0);
  assert.equal(cancelCalls, 1);
});

test('Sub2API account tests validate HTTP and SSE metadata before consuming a body', async () => {
  const logs = [];
  const client = clientWithLogs(logs);
  for (const scenario of [
    {
      ok: false,
      status: 502,
      contentType: 'text/event-stream',
      code: 'SUB2API_TEST_REQUEST_REJECTED',
      reason: 'response_rejected',
    },
    {
      ok: true,
      status: 200,
      contentType: 'application/json',
      code: 'SUB2API_TEST_RESPONSE_INVALID',
      reason: 'invalid_content_type',
    },
  ]) {
    let readerCalls = 0;
    let cancelCalls = 0;
    const unreadBody = {
      getReader() {
        readerCalls += 1;
        throw new Error('body must not be read');
      },
      async cancel() { cancelCalls += 1; },
    };
    await withFetch(
      async () => response('ignored', {
        ok: scenario.ok,
        status: scenario.status,
        contentType: scenario.contentType,
        stream: unreadBody,
      }),
      () => assert.rejects(
        client.testAccount(12),
        (error) => error.code === scenario.code
          && error.requiresReconciliation === true
          && error.reconciliationScope === 'test'
          && error.testOutcomeUnknown === true
          && error.reconciliationReason === scenario.reason,
      ),
    );
    assert.equal(readerCalls, 0);
    assert.equal(cancelCalls, 1);
  }
  assert.equal(
    logs.filter((entry) => entry.event === 'sub2api.account_test_rejected').length,
    1,
  );
});

test('Sub2API account-test timeout covers a stalled response body reader', async () => {
  const client = new Sub2ApiAdminClient({
    baseUrl: 'http://127.0.0.1:8080',
    apiKey: 'adapter-test-key',
    testTimeoutMs: 10,
  });
  let cancelCalls = 0;
  const stalledBody = {
    getReader() {
      return {
        read() { return new Promise(() => {}); },
        async cancel() { cancelCalls += 1; },
        releaseLock() {},
      };
    },
  };
  const startedAt = Date.now();
  await withFetch(
    async () => response('', { stream: stalledBody }),
    () => assert.rejects(
      client.testAccount(13),
      (error) => error.code === 'SUB2API_TEST_TIMEOUT'
        && error.testOutcomeUnknown === true
        && error.reconciliationReason === 'timeout',
    ),
  );
  assert.ok(Date.now() - startedAt < 1000);
  assert.equal(cancelCalls, 1);
});
