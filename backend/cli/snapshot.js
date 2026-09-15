const { loadEnv } = require('../config');
const { buildSnapshot } = require('../sync');
const { safeErrorText } = require('../logger');

function hasFlag(name) {
  return process.argv.includes(name);
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

async function main() {
  loadEnv();
  const output = await buildSnapshot(new URLSearchParams(hasFlag('--with-sub2api') ? 'withSub2api=1' : ''), {
    readSub2Api: hasFlag('--with-sub2api'),
    // A command-line snapshot is commonly used as an operational truth
    // source. Missing directories or a malformed username.json must fail the
    // command instead of looking like an empty local account set.
    requireCompleteSources: true,
  });

  if (hasFlag('--summary')) {
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
