const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.resolve(__dirname, '..', 'frontend', 'app.js'), 'utf8');
const start = source.indexOf('let memoryPanelToken');
const end = source.indexOf('const MUTATION_PENDING_PREFIX', start);
assert.ok(start >= 0 && end > start, 'authentication contract must be present');
const authContract = source.slice(start, end);
const SYNTHETIC_TOKEN = 'synthetic-panel-token-0123456789';
const OLD_SYNTHETIC_TOKEN = 'synthetic-old-token-0123456789';
const PENDING_KEY = 'panelMutationPending:v2:store';
const PENDING_MARKER = '{"version":2,"entries":["synthetic-unresolved-intent"]}';
const invalidExamples = [
  ['Chinese', 'synthetic-token-管理员'],
  ['emoji', 'synthetic-token-🔒'],
  ['zero-width', 'synthetic-token-\u200b1234'],
  ['Latin1', 'synthetic-token-é1234'],
  ['carriage-return', 'synthetic-token-\r1234'],
  ['line-feed', 'synthetic-token-\n1234'],
  ['tab', 'synthetic-token-\t1234'],
  ['NUL', 'synthetic-token-\0abcd'],
  ['DEL', 'synthetic-token-\x7fabcd'],
  ['leading-space', ' ' + SYNTHETIC_TOKEN],
  ['trailing-space', SYNTHETIC_TOKEN + ' '],
  ['internal-space', 'synthetic token abcdefgh'],
  ['too-short', 'a'.repeat(15)],
  ['too-long', 'a'.repeat(4097)],
  ['empty', ''],
];

function eventTarget(extra = {}) {
  const listeners = new Map();
  return {
    ...extra,
    addEventListener(type, callback, options = {}) {
      if (!listeners.has(type)) listeners.set(type, new Map());
      listeners.get(type).set(callback, options);
    },
    removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
    dispatch(type, details = {}) {
      const event = {
        type,
        target: this,
        defaultPrevented: false,
        preventDefault() { this.defaultPrevented = true; },
        ...details,
      };
      for (const [callback, options] of [...(listeners.get(type) || [])]) {
        if (options.once) listeners.get(type).delete(callback);
        callback(event);
      }
      return event;
    },
  };
}

function harness(options = {}) {
  const values = new Map(options.values || []);
  const calls = [];
  const storageCalls = [];
  const input = eventTarget({
    value: '',
    validationMessage: '',
    focus() {},
    setCustomValidity(message) { this.validationMessage = message; },
    reportValidity() { return !this.validationMessage; },
    setAttribute() {},
    removeAttribute() {},
  });
  const form = eventTarget();
  input.form = form;
  let shown = 0;
  const dialog = eventTarget({
    returnValue: '',
    open: false,
    querySelector(selector) { return selector === 'form' ? form : null; },
    showModal() {
      shown += 1;
      this.open = true;
      options.onShow?.({ input, dialog, form });
    },
    close(value = '') {
      this.returnValue = value;
      this.open = false;
      this.dispatch('close');
    },
  });
  const errorLabel = { textContent: '', hidden: true };
  const state = {
    jobInventoryVerified: false,
    job: { id: 'synthetic-held-job', status: 'unknown' },
    reconciliationHolds: { total: 1, returned: 1, truncated: false },
  };
  const context = vm.createContext({
    Headers,
    Response,
    AbortController,
    URL,
    Uint8Array,
    ArrayBuffer,
    DOMException,
    state,
    elements: {
      adminTokenDialog: dialog,
      adminTokenInput: input,
      adminTokenOrigin: {},
      adminTokenForm: form,
      adminTokenError: errorLabel,
    },
    sessionStorage: {
      getItem(key) {
        storageCalls.push(['get', key]);
        if (options.failGet) throw new DOMException('storage blocked', 'SecurityError');
        return values.get(key) ?? null;
      },
      setItem(key, value) {
        storageCalls.push(['set', key]);
        if (options.failSet) throw new DOMException('storage unavailable', 'QuotaExceededError');
        if (!options.silentSet) values.set(key, value);
      },
      removeItem(key) {
        storageCalls.push(['remove', key]);
        if (options.failRemove) throw new DOMException('storage blocked', 'SecurityError');
        if (!options.silentRemove) values.delete(key);
      },
    },
    fetch: async (url, requestOptions) => {
      calls.push({ url, options: requestOptions });
      return options.fetch
        ? options.fetch(url, requestOptions, calls.length)
        : new Response('{}', { status: 200 });
    },
    window: {
      setTimeout,
      clearTimeout,
      location: { origin: 'http://panel.test' },
    },
  });
  vm.runInContext(authContract, context);
  const evaluate = (code) => vm.runInContext(code, context);
  const submit = (value, action = 'confirm') => {
    input.value = value;
    const event = form.dispatch('submit', { submitter: { value: action } });
    if (!event.defaultPrevented) dialog.close(action);
    return event;
  };
  return { values, calls, storageCalls, input, form, dialog, errorLabel, context, state,
    evaluate, submit, shown: () => shown };
}

function tick() { return new Promise((resolve) => setImmediate(resolve)); }

test('administrator token validation matches bounded printable ASCII without normalization', () => {
  const h = harness();
  for (const [label, value] of invalidExamples) {
    h.context.candidate = value;
    assert.equal(h.evaluate('isValidPanelToken(candidate)'), false, label);
  }
  for (const value of ['!'.repeat(16), '~'.repeat(4096), SYNTHETIC_TOKEN]) {
    h.context.candidate = value;
    assert.equal(h.evaluate('isValidPanelToken(candidate)'), true);
    h.evaluate('savePanelToken(candidate)');
    assert.equal(h.evaluate('readPanelToken()'), value);
    assert.equal(h.evaluate('apiHeaders().get("x-panel-token")'), value);
  }
  for (const value of [null, undefined, 1234567890123456, {}, ['abcdefghijklmnop']]) {
    h.context.candidate = value;
    assert.equal(h.evaluate('isValidPanelToken(candidate)'), false, 'non-string');
  }
});

test('invalid administrator token input throws a generic error before storage or Headers', () => {
  for (const [label, value] of invalidExamples) {
    const h = harness({ values: [[PENDING_KEY, PENDING_MARKER]] });
    h.context.candidate = value;
    assert.throws(() => h.evaluate('savePanelToken(candidate)'), (error) => {
      assert.equal(error.code, 'PANEL_ADMIN_TOKEN_INVALID', label);
      if (value) assert.equal(error.message.includes(value), false, label);
      return true;
    });
    assert.equal(h.values.has('panelToken'), false, label);
    assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER, label);
    assert.equal(h.calls.length, 0, label);
  }
});

for (const [label, value] of invalidExamples.filter(([, value]) => value)) {
  test('invalid cached administrator token is discarded without touching pending work: ' + label, () => {
    const h = harness({ values: [['panelToken', value], [PENDING_KEY, PENDING_MARKER]] });
    const stateBefore = JSON.stringify(h.state);
    assert.equal(h.evaluate('readPanelToken()'), '');
    assert.equal(h.evaluate('apiHeaders().get("x-panel-token")'), null);
    assert.equal(h.values.has('panelToken'), false);
    assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER);
    assert.equal(JSON.stringify(h.state), stateBefore);
    assert.ok(h.storageCalls.every(([, key]) => key === 'panelToken'));
  });
}

test('unavailable sessionStorage preserves validated memory-only authentication', () => {
  const h = harness({ failGet: true, failSet: true, failRemove: true });
  h.context.candidate = SYNTHETIC_TOKEN;
  h.evaluate('savePanelToken(candidate)');
  assert.equal(h.evaluate('readPanelToken()'), SYNTHETIC_TOKEN);
  assert.equal(h.evaluate('apiHeaders().get("x-panel-token")'), SYNTHETIC_TOKEN);
  h.evaluate('clearPanelToken()');
  assert.equal(h.evaluate('readPanelToken()'), '');
});

test('failed removal cannot let an invalid stored token replace a newly validated memory token', () => {
  const h = harness({ failRemove: true, failSet: true,
    values: [['panelToken', 'synthetic-invalid-中文'], [PENDING_KEY, PENDING_MARKER]] });
  assert.equal(h.evaluate('readPanelToken()'), '');
  h.context.candidate = SYNTHETIC_TOKEN;
  h.evaluate('savePanelToken(candidate)');
  for (let count = 0; count < 3; count += 1) {
    assert.equal(h.evaluate('readPanelToken()'), SYNTHETIC_TOKEN);
    assert.equal(h.evaluate('apiHeaders().get("x-panel-token")'), SYNTHETIC_TOKEN);
  }
  h.evaluate('clearPanelToken()');
  assert.equal(h.evaluate('readPanelToken()'), '');
  assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER);
});

test('failed storage writes cannot revive a previously rejected valid-shaped token', () => {
  const h = harness({ failSet: true, values: [['panelToken', OLD_SYNTHETIC_TOKEN]] });
  assert.equal(h.evaluate('readPanelToken()'), OLD_SYNTHETIC_TOKEN);
  h.context.candidate = SYNTHETIC_TOKEN;
  h.evaluate('savePanelToken(candidate)');
  assert.equal(h.evaluate('readPanelToken()'), SYNTHETIC_TOKEN);
  assert.equal(h.evaluate('apiHeaders().get("x-panel-token")'), SYNTHETIC_TOKEN);
});

test('silent storage failures cannot revive stale tokens after validation or logout', () => {
  const h = harness({ silentSet: true, silentRemove: true,
    values: [['panelToken', OLD_SYNTHETIC_TOKEN], [PENDING_KEY, PENDING_MARKER]] });
  h.context.candidate = SYNTHETIC_TOKEN;
  h.evaluate('savePanelToken(candidate)');
  assert.equal(h.evaluate('readPanelToken()'), SYNTHETIC_TOKEN);
  h.evaluate('clearPanelToken()');
  assert.equal(h.evaluate('readPanelToken()'), '');
  assert.equal(h.evaluate('apiHeaders().get("x-panel-token")'), null);
  assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER);
});

test('authentication dialog rejects invalid submit without closing and clears validation on input', async () => {
  const h = harness();
  const request = h.evaluate('requestAdminToken()');
  let resolved = false;
  request.then(() => { resolved = true; });
  for (const [label, value] of invalidExamples.filter(([, value]) => value)) {
    const event = h.submit(value);
    assert.equal(event.defaultPrevented, true, label);
    assert.equal(h.dialog.open, true, label);
    assert.ok(h.errorLabel.textContent || h.input.validationMessage, label);
    assert.equal((h.errorLabel.textContent + h.input.validationMessage).includes(value), false, label);
    h.input.dispatch('input');
    assert.equal(h.input.validationMessage, '', label);
    assert.equal(h.errorLabel.hidden || !h.errorLabel.textContent, true, label);
  }
  await tick();
  assert.equal(resolved, false);
  h.submit(SYNTHETIC_TOKEN);
  assert.equal(await request, SYNTHETIC_TOKEN);
  assert.equal(h.input.value, '');
});

test('authentication dialog shares one request and cancellation never returns typed credentials', async () => {
  const h = harness({ values: [[PENDING_KEY, PENDING_MARKER]] });
  const first = h.evaluate('requestAdminToken()');
  const second = h.evaluate('requestAdminToken()');
  assert.equal(first, second);
  assert.equal(h.shown(), 1);
  h.submit('synthetic-invalid-中文', 'cancel');
  assert.equal(await first, '');
  assert.equal(await second, '');
  assert.equal(h.input.value, '');
  assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER);
  const next = h.evaluate('requestAdminToken()');
  assert.notEqual(next, first);
  h.dialog.close('cancel');
  assert.equal(await next, '');
});

test('native input validation uses a safe message and leaves no handlers after dialog cancellation', async () => {
  const h = harness();
  const pending = h.evaluate('requestAdminToken()');
  h.input.value = 'synthetic-invalid-中文';
  h.input.dispatch('invalid');
  assert.ok(h.errorLabel.textContent);
  assert.equal(h.errorLabel.textContent.includes(h.input.value), false);
  h.dialog.close('cancel');
  assert.equal(await pending, '');
  assert.equal(h.input.validationMessage, '');
  assert.equal(h.errorLabel.textContent, '');
  h.input.dispatch('invalid');
  assert.equal(h.input.validationMessage, '');
  assert.equal(h.errorLabel.textContent, '');
  assert.equal(h.form.dispatch('submit', { submitter: { value: 'confirm' } }).defaultPrevented, false);
});

test('unavailable dialog cancels authentication without storing any credential', async () => {
  const h = harness({ values: [[PENDING_KEY, PENDING_MARKER]] });
  h.dialog.showModal = () => { throw new Error('dialog unavailable'); };
  assert.equal(await h.evaluate('requestAdminToken()'), '');
  assert.equal(h.input.value, '');
  assert.equal(h.values.has('panelToken'), false);
  assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER);
  assert.equal(h.input.validationMessage, '');
});

test('programmatic dialog close cannot bypass token validation', async () => {
  const h = harness();
  const pending = h.evaluate('requestAdminToken()');
  let resolved = false;
  pending.then(() => { resolved = true; });
  h.input.value = 'synthetic-invalid-中文';
  h.dialog.close('confirm');
  await tick();
  assert.equal(resolved, false);
  assert.equal(h.dialog.open, true);
  assert.equal(h.input.value, '');
  assert.equal(h.values.has('panelToken'), false);
  assert.equal(h.calls.length, 0);
  h.dialog.close('cancel');
  assert.equal(await pending, '');
});

test('invalid cached token recovers through 401 without mutating an existing idempotency key or hold', async () => {
  const h = harness({
    values: [['panelToken', 'synthetic-invalid-中文'], [PENDING_KEY, PENDING_MARKER]],
    fetch: async (_url, _options, attempt) => new Response('{}', { status: attempt === 1 ? 401 : 202 }),
  });
  const stateBefore = JSON.stringify(h.state);
  const pending = h.evaluate(`apiFetch('/api/account-tests', {
    method: 'POST', body: '{}',
    headers: { 'Idempotency-Key': 'idem_v1_synthetic_auth_retry_123456789' }
  })`);
  await tick();
  assert.equal(h.shown(), 1);
  h.submit(SYNTHETIC_TOKEN);
  assert.equal((await pending).status, 202);
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls[0].options.headers.get('x-panel-token'), null);
  assert.equal(h.calls[1].options.headers.get('x-panel-token'), SYNTHETIC_TOKEN);
  for (const call of h.calls) {
    assert.equal(call.options.headers.get('idempotency-key'), 'idem_v1_synthetic_auth_retry_123456789');
    assert.equal(call.options.body, '{}');
    assert.equal(call.options.redirect, 'error');
  }
  assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER);
  assert.equal(JSON.stringify(h.state), stateBefore);
});

test('authentication cancellation leaves pending work and recovery locks intact', async () => {
  const h = harness({
    values: [['panelToken', 'synthetic-invalid-中文'], [PENDING_KEY, PENDING_MARKER]],
    fetch: async () => new Response('{}', { status: 401 }),
  });
  const stateBefore = JSON.stringify(h.state);
  const pending = h.evaluate('apiFetch("/api/jobs?limit=200")');
  await tick();
  h.dialog.close('cancel');
  assert.equal((await pending).status, 401);
  assert.equal(h.calls.length, 1);
  assert.equal(h.values.get(PENDING_KEY), PENDING_MARKER);
  assert.equal(JSON.stringify(h.state), stateBefore);
});

test('simultaneous unauthorized requests share one authentication dialog', async () => {
  const h = harness({ fetch: async (_url, options) => new Response('{}', {
    status: options.headers.get('x-panel-token') === SYNTHETIC_TOKEN ? 200 : 401,
  }) });
  const first = h.evaluate('apiFetch("/api/health")');
  const second = h.evaluate('apiFetch("/api/jobs?limit=200")');
  await tick();
  assert.equal(h.shown(), 1);
  h.submit(SYNTHETIC_TOKEN);
  assert.equal((await first).status, 200);
  assert.equal((await second).status, 200);
  assert.equal(h.calls.length, 4);
  assert.equal(h.shown(), 1);
});

test('a delayed old unauthorized response retries the newly validated token without clearing it', async () => {
  let releaseOldResponse;
  const oldResponse = new Promise((resolve) => { releaseOldResponse = resolve; });
  const h = harness({
    values: [['panelToken', OLD_SYNTHETIC_TOKEN]],
    fetch: async (_url, options, attempt) => {
      if (attempt === 1) return oldResponse;
      return new Response('{}', {
        status: options.headers.get('x-panel-token') === SYNTHETIC_TOKEN ? 200 : 401,
      });
    },
  });
  const first = h.evaluate('apiFetch("/api/health")');
  const second = h.evaluate('apiFetch("/api/jobs?limit=200")');
  await tick();
  h.submit(SYNTHETIC_TOKEN);
  assert.equal((await second).status, 200);
  releaseOldResponse(new Response('{}', { status: 401 }));
  assert.equal((await first).status, 200);
  assert.equal(h.shown(), 1);
  assert.equal(h.evaluate('readPanelToken()'), SYNTHETIC_TOKEN);
  assert.equal(h.calls.length, 4);
  assert.equal(h.calls[3].options.headers.get('x-panel-token'), SYNTHETIC_TOKEN);
});
