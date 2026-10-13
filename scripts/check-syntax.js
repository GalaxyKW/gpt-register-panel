'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SOURCE_DIRECTORIES = ['backend', 'frontend', 'scripts', 'tests'];
function collectJavaScript(root) {
  const files = [];
  let entries = 0;
  function walk(directory, depth) {
    if (depth > 32) throw new Error('SYNTAX_SCAN_DEPTH_LIMIT');
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('SYNTAX_SCAN_UNSAFE_DIRECTORY');
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (++entries > 20000) throw new Error('SYNTAX_SCAN_ENTRY_LIMIT');
      const filename = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('SYNTAX_SCAN_SYMLINK');
      if (entry.isDirectory()) walk(filename, depth + 1);
      else if (entry.isFile() && /\.(?:js|cjs|mjs)$/.test(entry.name)) files.push(filename);
    }
  }
  for (const directory of SOURCE_DIRECTORIES) walk(path.join(root, directory), 0);
  if (!files.length) throw new Error('SYNTAX_SCAN_EMPTY');
  return files.sort();
}

function checkSyntax(root, run = spawnSync) {
  const files = collectJavaScript(root);
  // Checking source syntax must never execute deployment preload modules.
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  delete env.NODE_PATH;
  delete env.NODE_TEST_CONTEXT;
  for (const filename of files) {
    const result = run(process.execPath, ['--check', filename], {
      cwd: root, env, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
    });
    if (result.error || result.status !== 0) {
      // Do not echo source excerpts, arbitrary preloads or environment values.
      const error = new Error('SYNTAX_CHECK_FAILED');
      error.relativePath = path.relative(root, filename);
      throw error;
    }
  }
  return files.length;
}

module.exports = { collectJavaScript, checkSyntax };
if (require.main === module) {
  try {
    if (process.argv.length !== 2) throw new Error('SYNTAX_CHECK_ARGUMENTS_UNSUPPORTED');
    const count = checkSyntax(path.resolve(__dirname, '..'));
    console.log(JSON.stringify({ syntax: 'passed', files: count }));
  } catch (error) {
    console.error(JSON.stringify({ syntax: 'failed', code: /^SYNTAX_[A-Z_]+$/.test(error.message || '')
      ? error.message : 'SYNTAX_SCAN_FAILED', ...(error.relativePath ? { file: error.relativePath } : {}) }));
    process.exitCode = 1;
  }
}
