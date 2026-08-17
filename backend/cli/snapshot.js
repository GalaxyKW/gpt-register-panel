const { readGptRegisterSources, toSafeSources } = require('../adapters/gptRegisterFs');
const { Sub2ApiAdminClient } = require('../adapters/sub2apiAdmin');
const { buildDiff, toSafeDiff } = require('../diff');

function hasFlag(name) {
  return process.argv.includes(name);
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

async function main() {
  const sources = readGptRegisterSources();
  let accounts = [];
  let diff = null;
  let apiError = null;

  if (hasFlag('--with-sub2api')) {
    try {
      const client = new Sub2ApiAdminClient();
      accounts = await client.listAccounts({
        platform: 'openai',
        type: 'oauth',
        pageSize: 200,
      });
      diff = buildDiff(sources.tokens, accounts);
    } catch (error) {
      apiError = error.message;
    }
  }

  const output = {
    generatedAt: sources.generatedAt,
    sources: toSafeSources(sources),
    sub2api: {
      accountCount: accounts.length,
      accounts,
      apiError,
    },
    diff: diff ? toSafeDiff(diff) : null,
  };

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

