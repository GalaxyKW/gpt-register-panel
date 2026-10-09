'use strict';

async function runNetworkPreflight({ rootDirectory, signal, logger, jobId, actor, runner } = {}) {
  const { runEngineCommand } = require('./registrationWorker');
  const output = await runEngineCommand({ rootDirectory, signal, logger, jobId, actor, runner,
    arguments: ['--panel-network-preflight'], timeoutMs: 150000 });
  if (output.commandError?.code === 'JOB_INTERRUPTED') throw Object.assign(new Error('网络预检已取消'), { code: 'JOB_INTERRUPTED' });
  const event = output.events.find(item => item.type === 'preflight_completed');
  const result = event?.result;
  if (!result || !Array.isArray(result.channels) || result.channels.length !== 3
      || ['sms', 'mail', 'oauth'].some(id => result.channels.filter(item => item.id === id).length !== 1)
      || result.channels.some(item => typeof item.ok !== 'boolean' || !/^[A-Z_]{1,50}$/.test(item.code || ''))) {
    throw Object.assign(new Error('网络预检没有返回完整可信结果'), { code: 'NETWORK_PREFLIGHT_INVALID' });
  }
  return { ok: !output.commandError && result.channels.every(item => item.ok), checkedAt: result.checkedAt,
    channels: result.channels.map(item => ({ id: item.id, ok: item.ok, code: item.code,
      message: typeof item.message === 'string' && item.message.length < 200 ? item.message : '通道检测已结束',
      durationMs: Number.isFinite(item.durationMs) ? item.durationMs : null,
      ...(Array.isArray(item.checks) ? { checks: item.checks.filter(check => ['node_oauth', 'browser'].includes(check?.id)).slice(0, 2).map(check => ({
        id: check.id, ok: check.ok === true, code: /^[A-Z_]{1,50}$/.test(check.code || '') ? check.code : 'PREFLIGHT_FAILED',
        message: typeof check.message === 'string' && check.message.length < 200 ? check.message : '子通道检测已结束',
        durationMs: Number.isFinite(check.durationMs) ? check.durationMs : null,
        ...(Number.isInteger(check.httpStatus) && check.httpStatus >= 100 && check.httpStatus <= 599 ? { httpStatus: check.httpStatus } : {}),
      })) } : {}) })) };
}
module.exports = { runNetworkPreflight };
