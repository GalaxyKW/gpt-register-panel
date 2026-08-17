const fs = require('node:fs');
const path = require('node:path');
const {
  normalizeTokenDocument,
  toSafeTokenSummary,
  asString,
  normalizeEmail,
} = require('../lib/token');

function readJsonArray(filePath) {
  if (!fs.existsSync(filePath)) return [];
  try {
    const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (Array.isArray(value)) return value;
    if (value && typeof value === 'object') return [value];
    return [];
  } catch {
    return [];
  }
}

function sortFileNames(left, right) {
  return left.localeCompare(right, 'en', {
    numeric: true,
    sensitivity: 'base',
  });
}

function readTokenDirectory(directory, source, rootDirectory, includeRaw = false) {
  const records = [];
  if (!fs.existsSync(directory)) return records;
  let names = [];
  try {
    names = fs.readdirSync(directory)
      .filter((name) => name.toLowerCase().endsWith('.json'))
      .sort(sortFileNames);
  } catch {
    return records;
  }

  for (const fileName of names) {
    const absolutePath = path.join(directory, fileName);
    let stat;
    try {
      stat = fs.statSync(absolutePath);
    } catch (error) {
      records.push(normalizeTokenDocument({
        source,
        relativePath: path.relative(rootDirectory, absolutePath),
        fileName,
        mtimeMs: 0,
        parseError: error,
        includeRaw,
      }));
      continue;
    }

    let data;
    let parseError = null;
    try {
      data = JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
    } catch (error) {
      parseError = error;
    }

    records.push(normalizeTokenDocument({
      source,
      relativePath: path.relative(rootDirectory, absolutePath),
      fileName,
      mtimeMs: stat.mtimeMs,
      data,
      parseError,
      includeRaw,
    }));
  }
  return records;
}

function safeUsernameRecords(records) {
  return records.map((item, index) => ({
    index,
    email: normalizeEmail(item?.email),
    phone: asString(item?.phone),
    name: asString(item?.name),
    createdAt: item?.createdAt || null,
    status: asString(item?.status),
    hasPassword: Boolean(asString(item?.password)),
  }));
}

function readGptRegisterSources(options = {}) {
  const rootDirectory = path.resolve(
    options.rootDirectory
      || process.env.GPT_REGISTER_ROOT
      || '/mnt/nvme/gpt_register',
  );
  const tokensDirectory = path.resolve(
    options.tokensDirectory || path.join(rootDirectory, 'tokens'),
  );
  const useTokenDirectory = path.resolve(
    options.useTokenDirectory || path.join(rootDirectory, 'use_token'),
  );
  const usernameFile = path.resolve(
    options.usernameFile || path.join(rootDirectory, 'username.json'),
  );
  const tokenRecords = [
    ...readTokenDirectory(tokensDirectory, 'tokens', rootDirectory, options.includeRaw === true),
    ...readTokenDirectory(useTokenDirectory, 'use_token', rootDirectory, options.includeRaw === true),
  ];
  return {
    generatedAt: new Date().toISOString(),
    rootDirectory,
    tokensDirectory,
    useTokenDirectory,
    usernameFile,
    tokens: tokenRecords,
    usernames: safeUsernameRecords(readJsonArray(usernameFile)),
    summary: {
      tokenCount: tokenRecords.length,
      validTokenCount: tokenRecords.filter((item) => item.parseStatus === 'ok').length,
      invalidTokenCount: tokenRecords.filter((item) => item.parseStatus !== 'ok').length,
      usernameCount: readJsonArray(usernameFile).length,
    },
  };
}

function toSafeSources(sources) {
  return {
    generatedAt: sources.generatedAt,
    rootDirectory: sources.rootDirectory,
    tokensDirectory: sources.tokensDirectory,
    useTokenDirectory: sources.useTokenDirectory,
    usernameFile: sources.usernameFile,
    tokens: sources.tokens.map(toSafeTokenSummary),
    usernames: sources.usernames,
    summary: sources.summary,
  };
}

module.exports = {
  readJsonArray,
  readTokenDirectory,
  readGptRegisterSources,
  toSafeSources,
};

