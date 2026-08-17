require('../config').loadEnv();
const { buildSnapshot } = require('../sync');

function hasFlag(name) {
  return process.argv.includes(name);
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

async function main() {
  const output = await buildSnapshot(new URLSearchParams(hasFlag('--with-sub2api') ? 'withSub2api=1' : ''), {
    readSub2Api: hasFlag('--with-sub2api'),
  });

  if (hasFlag('--summary')) {
    process.stdout.write(JSON.stringify({
      generatedAt: output.generatedAt,
      sourceSummary: output.sources.summary,
      sub2api: {
        accountCount: output.sub2api.accountCount,
        apiError: output.sub2api.apiError,
      },
      diffCounts: output.diff?.counts || null,
    }, null, 2) + '\n');
    return;
  }
  printJson(output);
}

main().catch((error) => {
  process.stderr.write(error.stack + '\n');
  process.exitCode = 1;
});
