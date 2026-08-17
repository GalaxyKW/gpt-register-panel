const { readGptRegisterSources } = require('./adapters/gptRegisterFs');
const { Sub2ApiAdminClient } = require('./adapters/sub2apiAdmin');
const { buildDiff } = require('./diff');

module.exports = {
  readGptRegisterSources,
  Sub2ApiAdminClient,
  buildDiff,
};

