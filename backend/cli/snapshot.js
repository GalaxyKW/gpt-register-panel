const { loadEnv } = require('../config');
const { buildSnapshot } = require('../sync');
const { safeErrorText } = require('../logger');

const ALLOWED_FLAGS = new Set(['--with-sub2api', '--summary']);

function parseFlags(values = process.argv.slice(2)) {
  const flags = new Set();
  for (const value of values) {
    if (typeof value !== 'string' || !ALLOWED_FLAGS.has(value) || flags.has(value)) {
      const error = new Error('快照命令只接受不重复的 --with-sub2api 和 --summary 参数');
      error.code = 'CLI_ARGUMENT_INVALID';
      throw error;
    }
    flags.add(value);
  }
  return flags;
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

async function main() {
  const flags = parseFlags();
  loadEnv();
  const withSub2Api = flags.has('--with-sub2api');
  const output = await buildSnapshot(new URLSearchParams(withSub2Api ? 'withSub2api=1' : ''), {
    readSub2Api: withSub2Api,
    // A command-line snapshot is commonly used as an operational truth
    // source. Missing directories or a malformed username.json must fail the
    // command instead of looking like an empty local account set.
    requireCompleteSources: true,
  });
  if (withSub2Api && output?.sub2api?.readStatus !== 'ok') {
    const error = new Error('未能读取 Sub2API，不能输出远端对比快照');
    error.code = 'SUB2API_SNAPSHOT_UNAVAILABLE';
    throw error;
  }

  if (flags.has('--summary')) {
    process.stdout.write(JSON.stringify({
      generatedAt: output.generatedAt,
      sourceSummary: output.sources.summary,
      sub2api: {
        readStatus: output.sub2api.readStatus,
        accountCount: output.sub2api.accountCount,
        apiError: output.sub2api.apiError,
      },
      comparisonStatus: output.diff?.comparisonStatus || null,
      diffCounts: output.diff?.counts || null,
    }, null, 2) + '\n');
    return;
  }
  printJson(output);
}

main().catch((error) => {
  process.stderr.write(safeErrorText(error) + '\n');
  process.exitCode = 1;
});
