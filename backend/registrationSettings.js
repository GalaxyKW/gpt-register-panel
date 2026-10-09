'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { openRootDirectory, closeDirectoryHandle } = require('./adapters/gptRegisterFs');
const { syncDirectory } = require('./lib/safeFs');

const FILE = 'config.panel.json';
const REVISION_KEY = crypto.randomBytes(32);
const SPEC = Object.freeze({
  heroSmsApiKey: ['短信 API Key', 'secret'], heroSmsService: ['短信服务代码', 'identifier'],
  phoneCountryCode: ['默认国家', 'country'], maxBatchRegistrationFailures: ['每批失败上限', 'integer', 1, 10],
  mailProvider: ['邮箱接口', 'enum', ['cloud-mail', 'cloudflare-worker', 'legacy']],
  mailBaseUrl: ['邮箱 API 地址', 'url'], mailAdminEmail: ['邮箱管理员邮箱', 'email'],
  mailAdminPassword: ['邮箱管理员密码', 'secret'], mailAdminToken: ['邮箱 API Token', 'secret'],
  mailSitePassword: ['邮箱站点密码', 'secret'], mailDomain: ['邮箱域名', 'domain'], mailDomains: ['邮箱域名池', 'domains'],
  proxyHost: ['代理主机', 'host'], proxyPort: ['代理端口', 'integer', 1, 65535],
  proxyProtocol: ['代理协议', 'enum', ['http', 'https', 'socks5', 'socks5h', 'socks4', 'socks4a']],
  proxyUsername: ['代理用户名', 'secret'], proxyPassword: ['代理密码', 'secret'],
});
function settingsError(code, message) { return Object.assign(new Error(message), { code, statusCode: code.includes('CHANGED') ? 409 : 400 }); }
function readObject(directory, file) {
  let fd;
  try {
    fd = fs.openSync(path.join(directory, file), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 1024 * 1024) throw new Error();
    const bytes = fs.readFileSync(fd);
    const value = JSON.parse(bytes.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return { value, hash: crypto.createHash('sha256').update(bytes).digest('hex') };
  } catch (error) {
    if (error.code === 'ENOENT') return { value: {}, hash: null };
    throw settingsError('REGISTRATION_SETTINGS_UNSAFE', '注册配置不可读取、格式错误或路径不安全');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function readConfiguration(rootHandle) {
  const files = ['config.json', process.platform === 'darwin' ? 'config.local.json' : 'config.server.json', FILE];
  const records = files.map(file => readObject(rootHandle.traversalPath, file));
  return { raw: Object.assign({}, ...records.map(item => item.value)), overlay: records[2].value,
    revision: crypto.createHmac('sha256', REVISION_KEY).update(JSON.stringify(records.map(item => item.hash))).digest('hex') };
}
function validateValue(key, value) {
  const spec = SPEC[key];
  if (!spec) throw settingsError('REGISTRATION_SETTINGS_FIELD_INVALID', '存在不允许修改的注册配置字段');
  const type = spec[1];
  if (type === 'integer') {
    if (!Number.isSafeInteger(value) || value < spec[2] || value > spec[3]) throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', spec[0] + '超出范围');
    return value;
  }
  if (type === 'domains') {
    if (!Array.isArray(value) || value.length < 1 || value.length > 30) throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', '邮箱域名池须为 1–30 个域名');
    return [...new Set(value.map(item => validateValue('mailDomain', item)))];
  }
  if (typeof value !== 'string' || value.length > (type === 'secret' ? 4096 : 1024) || /[\x00-\x1f\x7f]/.test(value)) throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', spec[0] + '格式无效');
  if (type === 'secret') { if (!value || value !== value.trim()) throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', '密钥留空表示保留，不能提交空值'); return value; }
  value = value.trim();
  const patterns = { identifier: /^[A-Za-z0-9_-]{1,30}$/, country: /^[A-Z]{2}$/, host: /^(?:[A-Za-z0-9._-]+|\[[A-Fa-f0-9:]+\])$/, domain: /^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[A-Za-z]{2,63}$/, email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ };
  if (patterns[type] && !patterns[type].test(value)) throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', spec[0] + '格式无效');
  if (type === 'enum' && !spec[2].includes(value.replace(/:$/, ''))) throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', spec[0] + '选项无效');
  if (type === 'url') {
    let url; try { url = new URL(value); } catch { throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', '邮箱 API 地址无效'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw settingsError('REGISTRATION_SETTINGS_VALUE_INVALID', '邮箱 API 必须使用无内嵌凭据的 HTTPS 地址');
  }
  return type === 'enum' ? value.replace(/:$/, '') : value;
}
function safeView(configuration, rootDirectory) {
  const { raw, revision } = configuration;
  let countries = [];
  try {
    const catalog = require(path.join(rootDirectory, 'src/phoneCountryCatalog.js'));
    countries = catalog.normalizePhoneCountries(raw.phoneCountries?.length ? raw.phoneCountries : catalog.DEFAULT_PHONE_COUNTRIES)
      .map(item => ({ code: item.isoCode, name: item.name, dialCode: item.dialCode, heroSmsCountry: item.heroSmsCountry }));
  } catch { /* A missing catalog disables registration below. */ }
  const defaults = { heroSmsService: 'dr', phoneCountryCode: 'GB', maxBatchRegistrationFailures: 3, mailProvider: 'cloud-mail', proxyProtocol: 'http' };
  const publicValue = (key, spec) => {
    const value = raw[key] ?? defaults[key] ?? (spec[1] === 'domains' ? [] : '');
    if (spec[1] === 'url') {
      try { const url = new URL(value); return url.username || url.password || url.search || url.hash ? '' : url.toString(); } catch { return ''; }
    }
    if (spec[1] === 'enum' && typeof value === 'string') return value.replace(/:$/, '');
    try { return validateValue(key, value); } catch { return spec[1] === 'domains' ? [] : ''; }
  };
  const fields = Object.entries(SPEC).map(([key, spec]) => ({ key, label: spec[0], type: spec[1], secret: spec[1] === 'secret',
    ...(spec[1] === 'secret' ? { configured: typeof raw[key] === 'string' && raw[key].length > 0 }
      : { value: publicValue(key, spec), ...(spec[1] === 'enum' ? { options: spec[2] } : {}), ...(spec[1] === 'integer' ? { min: spec[2], max: spec[3] } : {}) }) }));
  const issues = [];
  if (!raw.heroSmsApiKey) issues.push('缺少短信 API Key');
  if (!raw.mailBaseUrl || !(raw.mailDomain || raw.mailDomains?.length)) issues.push('缺少邮箱地址或域名');
  if (!raw.mailAdminToken && !raw.mailAdminPassword) issues.push('缺少邮箱鉴权配置');
  if (!countries.length) issues.push('无法读取注册国家清单');
  return { revision, fields, countries, ready: issues.length === 0, issues, storage: FILE,
    lastRequestId: /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(configuration.overlay.panelSettingsWriteId || '') ? configuration.overlay.panelSettingsWriteId : null };
}
function readRegistrationSettings({ rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register' } = {}) {
  const handle = openRootDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
  try { return safeView(readConfiguration(handle), rootDirectory); } finally { closeDirectoryHandle(handle); }
}
function updateRegistrationSettings({ rootDirectory = process.env.GPT_REGISTER_ROOT || '/mnt/nvme/gpt_register', revision, changes, requestId } = {}) {
  if (requestId !== undefined && !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(requestId || '')) throw settingsError('REGISTRATION_SETTINGS_REQUEST_INVALID', '保存请求编号无效');
  if (!/^[a-f0-9]{64}$/.test(revision || '') || !changes || typeof changes !== 'object' || Array.isArray(changes) || !Object.keys(changes).length || Object.keys(changes).length > Object.keys(SPEC).length) throw settingsError('REGISTRATION_SETTINGS_INVALID', '配置修改内容或版本无效');
  const normalized = Object.fromEntries(Object.entries(changes).map(([key, value]) => [key, validateValue(key, value)]));
  const handle = openRootDirectory(rootDirectory, 'GPT_REGISTER_ROOT');
  let temporary, renamed = false;
  try {
    const before = readConfiguration(handle);
    if (requestId && before.overlay.panelSettingsWriteId === requestId) throw settingsError('REGISTRATION_SETTINGS_REQUEST_REPLAY', '该保存请求已处理，请刷新核对回执，不可再次提交');
    if (before.revision !== revision) throw settingsError('REGISTRATION_SETTINGS_CHANGED', '配置已变化，请刷新后重新保存');
    const next = { ...before.overlay, ...normalized, panelSettingsWriteId: requestId || null };
    // Updating the primary domain must not be silently shadowed by the old pool.
    if (normalized.mailDomain && !normalized.mailDomains) next.mailDomains = [normalized.mailDomain];
    temporary = path.join(handle.traversalPath, '.panel-config-' + crypto.randomBytes(12).toString('hex'));
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(next, null, 2) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    if (readConfiguration(handle).revision !== revision) throw settingsError('REGISTRATION_SETTINGS_CHANGED', '保存期间配置发生变化，未覆盖');
    fs.renameSync(temporary, path.join(handle.traversalPath, FILE)); temporary = null; renamed = true;
    syncDirectory(handle.traversalPath);
    return safeView(readConfiguration(handle), rootDirectory);
  } catch (error) {
    if (renamed) throw Object.assign(settingsError('REGISTRATION_SETTINGS_WRITE_UNKNOWN', '配置可能已保存，请刷新核对保存回执，勿重复提交'), { writeOutcomeUnknown: true, requestId: requestId || null });
    throw error;
  } finally {
    if (temporary) try { fs.unlinkSync(temporary); } catch {}
    closeDirectoryHandle(handle);
  }
}
module.exports = { readRegistrationSettings, updateRegistrationSettings, validateRegistrationSetting: validateValue };
