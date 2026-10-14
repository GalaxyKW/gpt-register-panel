'use strict';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const NODE_REVISION = /^proxy-v1\.[A-Za-z0-9_-]{43}$/;
function failure(code, message) { return Object.assign(new Error(message), { code }); }
function normalizeStoredImportProxy(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== 3
      || Object.keys(value).some(key => !['proxyId', 'endpointDigest', 'lastRequestId'].includes(key))
      || (value.proxyId !== null && (!Number.isSafeInteger(value.proxyId) || value.proxyId < 1))
      || (value.proxyId === null ? value.endpointDigest !== null : typeof value.endpointDigest !== 'string' || !/^[a-f0-9]{64}$/.test(value.endpointDigest))
      || (value.lastRequestId !== null && (typeof value.lastRequestId !== 'string' || !UUID.test(value.lastRequestId)))) {
    throw failure('CONSOLE_IMPORT_PROXY_SETTINGS_INVALID', '默认导入代理设置无效，未继续导入');
  }
  return { proxyId: value.proxyId, endpointDigest: value.endpointDigest, lastRequestId: value.lastRequestId };
}
const DEFAULT_IMPORT_PROXY = Object.freeze({ proxyId: null, endpointDigest: null, lastRequestId: null });
function endpointDigest(client) {
  return require('./remotePhase3').remotePhase3EndpointDigest(client);
}
function proxyEligibility(proxy, nowMs = Date.now()) {
  if (!proxy || !Number.isSafeInteger(proxy.id) || proxy.id < 1
      || !['http', 'https', 'socks5', 'socks5h'].includes(proxy.protocol)
      || typeof proxy.revision !== 'string' || !NODE_REVISION.test(proxy.revision)) {
    return { eligible: false, reason: '节点资料无法完整核验' };
  }
  if (proxy.status === 'expired') return { eligible: false, reason: '节点已过期，不会切换为直连或备用节点' };
  if (proxy.status !== 'active') return { eligible: false, reason: '节点未启用，不能用于新增导入' };
  if (proxy.expiresAt !== null && proxy.expiresAt !== undefined) {
    const expiry = typeof proxy.expiresAt === 'string' ? Date.parse(proxy.expiresAt) : NaN;
    if (!Number.isFinite(expiry)) return { eligible: false, reason: '节点过期时间无效' };
    if (expiry <= nowMs) return { eligible: false, reason: '节点已过期，不会切换为直连或备用节点' };
  }
  return { eligible: true, reason: '仅校验节点配置有效；不代表实际模型出口已连通' };
}
async function readImportProxySettings(db) {
  // Existing direct library callers without a persistence adapter retain the
  // original unconfigured behavior. Every HTTP path supplies the real DB.
  return typeof db?.getImportProxySettings === 'function' ? db.getImportProxySettings()
    : { revision: 0, settings: { ...DEFAULT_IMPORT_PROXY } };
}
async function resolveImportProxyBinding(db, client, plan, { signal } = {}) {
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消，未读取或应用默认代理');
  if (!plan.some(item => item.action === 'create')) return undefined;
  const saved = await readImportProxySettings(db);
  if (saved.settings.proxyId === null) return undefined;
  if (saved.settings.endpointDigest !== endpointDigest(client)) {
    throw failure('CONSOLE_IMPORT_PROXY_ENDPOINT_CHANGED', 'Sub2API 管理实例已变化，请重新保存默认导入代理');
  }
  if (typeof client.getProxy !== 'function') throw failure('CONSOLE_IMPORT_PROXY_UNAVAILABLE', '无法读取默认导入代理，未继续导入');
  let proxy;
  try { proxy = await client.getProxy(saved.settings.proxyId, { signal }); }
  catch (error) {
    if (signal?.aborted || error?.code === 'JOB_INTERRUPTED') throw failure('JOB_INTERRUPTED', '任务已取消，未应用默认代理');
    throw failure('CONSOLE_IMPORT_PROXY_UNAVAILABLE', '默认导入代理读取失败，未切换直连；请检查节点');
  }
  if (signal?.aborted) throw failure('JOB_INTERRUPTED', '任务已取消，未应用默认代理');
  const eligible = proxyEligibility(proxy);
  if (!eligible.eligible || proxy.id !== saved.settings.proxyId) {
    throw failure('CONSOLE_IMPORT_PROXY_UNAVAILABLE', eligible.reason || '默认导入代理身份不一致');
  }
  return { mode: 'selected', proxyId: proxy.id, endpointDigest: saved.settings.endpointDigest,
    settingsRevision: saved.revision, nodeRevision: proxy.revision };
}
function normalizeImportProxyBinding(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 5
      || Object.keys(value).some(key => !['mode', 'proxyId', 'endpointDigest', 'settingsRevision', 'nodeRevision'].includes(key))
      || value.mode !== 'selected' || !Number.isSafeInteger(value.proxyId) || value.proxyId < 1
      || typeof value.endpointDigest !== 'string' || !/^[a-f0-9]{64}$/.test(value.endpointDigest)
      || !Number.isSafeInteger(value.settingsRevision) || value.settingsRevision < 0
      || typeof value.nodeRevision !== 'string' || !NODE_REVISION.test(value.nodeRevision)) {
    throw failure('CONSOLE_IMPORT_PROXY_BINDING_INVALID', '导入代理绑定不完整，请重新预览');
  }
  return { mode: 'selected', proxyId: value.proxyId, endpointDigest: value.endpointDigest,
    settingsRevision: value.settingsRevision, nodeRevision: value.nodeRevision };
}
async function assertImportProxyCurrent(db, client, expected, options) {
  const actual = await resolveImportProxyBinding(db, client, [{ action: 'create' }], options);
  if (JSON.stringify(actual) !== JSON.stringify(normalizeImportProxyBinding(expected))) {
    throw failure('CONSOLE_IMPORT_PROXY_CHANGED', '默认导入代理或节点配置已变化，请重新预览；未切换直连');
  }
  return actual;
}
module.exports = { UUID, DEFAULT_IMPORT_PROXY, normalizeStoredImportProxy, normalizeImportProxyBinding,
  endpointDigest, proxyEligibility, readImportProxySettings, resolveImportProxyBinding, assertImportProxyCurrent };
