'use strict';

const { loadEnv } = require('../config');
const { safeErrorText } = require('../logger');
const { checkPhase3Runtime } = require('../phase3RuntimeCheck');

function main(args = process.argv.slice(2)) {
  if (args.length !== 0) {
    throw Object.assign(new Error('执行器启动检查不接受命令行参数'), { code: 'CLI_ARGUMENT_INVALID' });
  }
  loadEnv();
  const result = checkPhase3Runtime();
  process.stdout.write(JSON.stringify({ phase3Runtime: result.checked ? 'ready' : 'disabled', ...result }) + '\n');
  return result;
}

module.exports = { main };
if (require.main === module) {
  try { main(); } catch (error) {
    process.stderr.write(safeErrorText(error) + '\n');
    process.exitCode = 1;
  }
}
