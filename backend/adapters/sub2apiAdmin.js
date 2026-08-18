const {
  buildIdentityKeys,
  normalizeEmail,
  tokenFingerprint,
  parseDateValue,
  asString,
} = require('../lib/token');
const { redactText } = require('../logger');

function asList(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return [];
  for (const key of ['items', 'records', 'list', 'accounts']) {
    if (Array.isArray(value[key])) return value[key];
  }
  return [];
}

function unwrapData(value) {
  if (value && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, 'data')) {
    return value.data;
  }
  return value;
}

function accountCredentials(account) {
  return account?.credentials && typeof account.credentials === 'object'
    ? account.credentials
    : {};
}

function storedFingerprint(value) {
  const text = asString(value).toLowerCase();
  return /^[a-f0-9]{16,64}$/.test(text) ? text.slice(0, 16) : null;
}

function safeAccount(account) {
  const credentials = accountCredentials(account);
  const extra = account?.extra && typeof account.extra === 'object' ? account.extra : {};
  const email = normalizeEmail(credentials.email || account.email);
  const accountId = asString(
    credentials.chatgpt_account_id
      || credentials.account_id
      || account.chatgpt_account_id,
  );
  const userId = asString(
    credentials.chatgpt_user_id
      || credentials.user_id
      || account.chatgpt_user_id,
  );
  const accessToken = asString(credentials.access_token || credentials.accessToken);
  const refreshToken = asString(credentials.refresh_token || credentials.refreshToken);
  const idToken = asString(credentials.id_token || credentials.idToken);
  const storedAccessFingerprint = storedFingerprint(
    extra.access_token_sha256 || credentials.access_token_sha256,
  );
  const expiresAt = parseDateValue(
    credentials.expired
      || credentials.expires_at
      || credentials.expiresAt
      || account.expires_at,
  );
  const tempUnschedulableUntil = parseDateValue(
    account.temp_unschedulable_until || account.tempUnschedulableUntil,
  );
  const groupIds = Array.isArray(account.group_ids)
    ? account.group_ids.map((value) => Number(value)).filter(Number.isFinite)
    : [];
  const name = asString(account.name);
  return {
    id: Number(account.id),
    name,
    platform: asString(account.platform),
    type: asString(account.type),
    status: asString(account.status),
    schedulable: account.schedulable !== false,
    tempUnschedulableUntil,
    tempUnschedulableReason: asString(
      account.temp_unschedulable_reason || account.tempUnschedulableReason,
    ),
    errorMessage: asString(account.error_message || account.errorMessage),
    email,
    accountId,
    userId,
    identityKeys: buildIdentityKeys({ accountId, userId, email }),
    expiresAt,
    tokenFingerprints: {
      access: storedAccessFingerprint || tokenFingerprint(accessToken),
      refresh: tokenFingerprint(refreshToken),
      id: tokenFingerprint(idToken),
    },
    groupIds,
    usage: account.usage && typeof account.usage === 'object'
      ? {
          requests: Number(account.usage.requests || account.usage.total_requests || 0),
          inputTokens: Number(account.usage.input_tokens || account.usage.total_input_tokens || 0),
          outputTokens: Number(account.usage.output_tokens || account.usage.total_output_tokens || 0),
          totalTokens: Number(account.usage.total_tokens || 0),
          cost: Number(account.usage.cost || account.usage.actual_cost || 0),
        }
      : null,
  };
}

function numberOrZero(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function normalizeUsageStats(stats) {
  if (!stats || typeof stats !== 'object') return null;
  return {
    requests: numberOrZero(stats.requests || stats.total_requests),
    totalTokens: numberOrZero(
      stats.tokens || stats.total_tokens || stats.input_tokens + stats.output_tokens,
    ),
    inputTokens: numberOrZero(stats.input_tokens),
    outputTokens: numberOrZero(stats.output_tokens),
    cost: numberOrZero(stats.cost || stats.actual_cost),
    standardCost: numberOrZero(stats.standard_cost),
    userCost: numberOrZero(stats.user_cost),
  };
}

function normalizeTableUsageStats(value) {
  if (!value || typeof value !== 'object') return null;
  const historical = normalizeUsageStats(value.historical || value.history);
  const current = normalizeUsageStats(value.current || value.today);
  return {
    historical,
    current,
    currentWindowStart: parseDateValue(value.current_window_start),
    currentWindowEnd: parseDateValue(value.current_window_end),
  };
}

function writeLog(logger, level, event, fields = {}) {
  try {
    if (logger && typeof logger[level] === 'function') logger[level](event, fields);
  } catch {
    // Network logging must never change the adapter result.
  }
}

class Sub2ApiAdminClient {
  constructor(options = {}) {
    this.baseUrl = String(
      options.baseUrl || process.env.SUB2API_BASE_URL || '',
    ).replace(/\/$/, '');
    this.apiKey = String(
      options.apiKey || process.env.SUB2API_ADMIN_API_KEY || '',
    );
    this.jwt = String(
      options.jwt || process.env.SUB2API_JWT || '',
    );
    this.timeoutMs = Number(options.timeoutMs || process.env.SUB2API_TIMEOUT_MS || 15000);
    this.logger = options.logger || null;
    this.logContext = options.logContext && typeof options.logContext === 'object'
      ? options.logContext
      : {};
    if (!this.baseUrl) {
      throw new Error('SUB2API_BASE_URL is required');
    }
    if (!this.apiKey && !this.jwt) {
      throw new Error('SUB2API_ADMIN_API_KEY or SUB2API_JWT is required');
    }
  }

  async request(method, pathname, body) {
    const startedAt = Date.now();
    writeLog(this.logger, 'info', 'sub2api.request_started', { ...this.logContext, method, path: pathname });
    const headers = { Accept: 'application/json' };
    if (this.apiKey) headers['x-api-key'] = this.apiKey;
    else headers.Authorization = 'Bearer ' + this.jwt;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const options = {
      method,
      headers,
      signal: controller.signal,
    };
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(this.baseUrl + pathname, options);
    } catch (error) {
      writeLog(this.logger, 'error', 'sub2api.request_failed', {
        ...this.logContext,
        method,
        path: pathname,
        durationMs: Date.now() - startedAt,
        error: redactText(String(error?.message || error)).slice(0, 1000),
      });
      if (error && error.name === 'AbortError') {
        throw new Error('Sub2API request timed out: ' + method + ' ' + pathname);
      }
      throw new Error('Sub2API request failed: ' + method + ' ' + pathname + ': ' + error.message);
    } finally {
      clearTimeout(timer);
    }
    const text = await response.text();
    let payload;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = { message: 'invalid JSON response' };
    }
    if (!response.ok || (payload && payload.code !== undefined && payload.code !== 0 && payload.code !== '0')) {
      const detail = payload?.message || payload?.code || response.statusText || 'request failed';
      writeLog(this.logger, 'warn', 'sub2api.request_rejected', {
        ...this.logContext,
        method,
        path: pathname,
        statusCode: response.status,
        durationMs: Date.now() - startedAt,
        error: redactText(String(detail)).slice(0, 1000),
      });
      throw new Error('Sub2API ' + method + ' ' + pathname + ' failed: ' + detail);
    }
    writeLog(this.logger, 'info', 'sub2api.request_completed', {
      ...this.logContext,
      method,
      path: pathname,
      statusCode: response.status,
      durationMs: Date.now() - startedAt,
    });
    return unwrapData(payload);
  }

  async listAccounts(options = {}) {
    const pageSize = Number(options.pageSize || 200);
    const rows = [];
    let page = 1;
    while (page <= 100) {
      const query = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
        sort_by: String(options.sortBy || 'name'),
        sort_order: String(options.sortOrder || 'asc'),
        lite: '1',
      });
      if (options.platform) query.set('platform', options.platform);
      if (options.type) query.set('type', options.type);
      if (options.status) query.set('status', options.status);
      if (options.search) query.set('search', options.search);
      const value = await this.request('GET', '/api/v1/admin/accounts?' + query.toString());
      const pageRows = asList(value);
      rows.push(...pageRows.map(safeAccount));
      const total = Number(value?.total || value?.pagination?.total || 0);
      if (pageRows.length === 0 || pageRows.length < pageSize || (total > 0 && rows.length >= total)) break;
      page += 1;
    }
    return rows;
  }

  async listGroups() {
    const value = await this.request('GET', '/api/v1/admin/groups/all');
    return asList(value);
  }

  async getAccountStats(id, days = 30) {
    const value = await this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(id)) + '/stats?days=' + encodeURIComponent(String(days)),
    );
    return value;
  }

  async getAccountTodayStats(id) {
    return this.request(
      'GET',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(id)) + '/today-stats',
    );
  }

  async getBatchTodayStats(ids) {
    return this.request('POST', '/api/v1/admin/accounts/today-stats/batch', {
      account_ids: ids.map((id) => Number(id)).filter(Number.isFinite),
    });
  }

  async getBatchTableUsageStats(ids) {
    const value = await this.request('POST', '/api/v1/admin/accounts/table-usage-stats/batch', {
      account_ids: ids.map((id) => Number(id)).filter(Number.isFinite),
    });
    const stats = value?.stats && typeof value.stats === 'object' ? value.stats : value;
    const normalized = {};
    for (const [id, item] of Object.entries(stats || {})) {
      normalized[String(id)] = normalizeTableUsageStats(item);
    }
    return {
      stats: normalized,
      errors: value?.errors && typeof value.errors === 'object' ? value.errors : {},
    };
  }

  async exportAccounts(ids = []) {
    const query = ids.length > 0 ? '?ids=' + encodeURIComponent(ids.join(',')) : '';
    return this.request('GET', '/api/v1/admin/accounts/data' + query);
  }

  async importCodexSession(payload) {
    return this.request('POST', '/api/v1/admin/accounts/import/codex-session', payload);
  }

  async applyOAuthCredentials(id, payload) {
    return this.request(
      'POST',
      '/api/v1/admin/accounts/' + encodeURIComponent(String(id)) + '/apply-oauth-credentials',
      payload,
    );
  }
}

module.exports = {
  Sub2ApiAdminClient,
  normalizeUsageStats,
  normalizeTableUsageStats,
  safeAccount,
};
