'use strict';

const crypto = require('node:crypto');
const { redactText } = require('../logger');

// Short-lived review proofs, never a persisted proxy configuration. Including
// connection secrets in an HMAC detects node edits without disclosing them.
const revisionSecret = crypto.randomBytes(32);
const PROTOCOLS = new Set(['http', 'https', 'socks5', 'socks5h']);
const unsafeText = /[\p{Cc}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
function proxySchemaError() {
  return Object.assign(new Error('Sub2API 代理节点响应结构无效，未允许选择'), { code: 'SUB2API_PROXY_SCHEMA_INVALID' });
}
function positiveId(value) { return Number.isSafeInteger(value) && value > 0; }
function textField(value, max, required = false) {
  if (value === undefined || value === null) {
    if (required) throw proxySchemaError();
    return '';
  }
  if (typeof value !== 'string' || value.length > max || (required && !value.trim()) || unsafeText.test(value)) throw proxySchemaError();
  return value;
}
function dateField(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length > 80 || !/^\d{4}-\d\d-\d\dT/.test(value)
      || !Number.isFinite(Date.parse(value))) throw proxySchemaError();
  return new Date(value).toISOString();
}
function safeProxy(value, endpoint) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !positiveId(value.id)
      || !PROTOCOLS.has(value.protocol) || !['active', 'inactive', 'expired'].includes(value.status)
      || !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65535) throw proxySchemaError();
  const rawName = textField(value.name, 200, true);
  const host = textField(value.host, 1024, true);
  const username = textField(value.username, 4096);
  const password = textField(value.password, 4096);
  const expiresAt = dateField(value.expires_at);
  const updatedAt = dateField(value.updated_at);
  const createdAt = dateField(value.created_at);
  const fallbackMode = value.fallback_mode === undefined ? 'none' : value.fallback_mode;
  const backupProxyId = value.backup_proxy_id ?? null;
  if (!['none', 'proxy', 'direct'].includes(fallbackMode)
      || (backupProxyId !== null && !positiveId(backupProxyId))) throw proxySchemaError();
  let name = rawName;
  for (const secret of [username, password]) if (secret.length > 0) name = name.split(secret).join('[redacted]');
  name = redactText(name).slice(0, 200);
  const material = [String(endpoint).replace(/\/$/, ''), value.id, rawName, value.protocol,
    host, value.port, username, password, value.status, expiresAt, fallbackMode, backupProxyId, updatedAt, createdAt];
  return { id: value.id, name, protocol: value.protocol, status: value.status, expiresAt, fallbackMode, backupProxyId,
    revision: 'proxy-v1.' + crypto.createHmac('sha256', revisionSecret).update(JSON.stringify(material)).digest('base64url') };
}

function rawAccountProxyState(account) {
  const present = Object.hasOwn(account, 'proxy_id');
  const valid = !present || account.proxy_id === null || positiveId(account.proxy_id);
  return { proxyId: present && valid ? account.proxy_id : null, proxyIdKnown: present && valid, proxyIdValid: valid };
}

// Distinguish a confirmed lack of account-level binding from an older response
// that omitted the field. It does not prove a direct transport path, since the
// service may have other network configuration. Legacy fixtures remain unknown.
function accountProxyState(account) {
  const id = account?.proxyId;
  const known = account?.proxyIdKnown;
  const valid = account?.proxyIdValid;
  if ((known !== undefined && typeof known !== 'boolean') || (valid !== undefined && typeof valid !== 'boolean')
      || valid === false || (id !== undefined && id !== null && !positiveId(id))) return null;
  if (known === true) return id === null || positiveId(id) ? { known: true, id } : null;
  if (known === false && id !== undefined && id !== null) return null;
  if (known === undefined && (id === null || positiveId(id))) return { known: true, id };
  return { known: false, id: null };
}

module.exports = { safeProxy, proxySchemaError, rawAccountProxyState, accountProxyState };
