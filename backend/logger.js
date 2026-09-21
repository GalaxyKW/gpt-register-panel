const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { ensureDirectoryTree } = require('./lib/safeFs');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MAX_LOG_BYTES = 128 * 1024 * 1024;
const MAX_LOG_ROTATIONS = 100;
const MAX_LOG_TOTAL_BYTES = 512 * 1024 * 1024;
const LOG_TAIL_BLOCK_BYTES = 64 * 1024;
const LOG_TAIL_MAX_BYTES = 4 * 1024 * 1024;
const LOG_REDACTION_LIMITS = Object.freeze({
  depth: 20,
  nodes: 4096,
  entries: 512,
  valueChars: 128 * 1024,
  totalChars: 256 * 1024,
});
const STORED_REDACTION_LIMITS = Object.freeze({
  depth: 64,
  nodes: 200_000,
  entries: 100_000,
  valueChars: 2 * 1024 * 1024,
  totalChars: 4 * 1024 * 1024,
});
const MAX_LOG_ENTRY_BYTES = 256 * 1024;
const MAX_LOG_NAMESPACE_FILES = 1000;
// Count every directory entry, not only files in the rotation namespace. A
// directory full of unrelated names must not make startup materialize an
// unbounded readdir result before the namespace limit can be enforced.
const MAX_LOG_DIRECTORY_ENTRIES = 20_000;
const SECRET_KEY = /(^|_)(access_tokens?|refresh_tokens?|id_tokens?|passwords?|passwds?|pwds?|passphrases?|prompts?|secrets?|secret_keys?|private_keys?|signing_keys?|encryption_keys?|secret_access_keys?|access_keys?|access_key_ids?|service_account_keys?|key_materials?|mfa_secrets?|totp_secrets?|recovery_codes?|api_?keys?|auth|authentication|authorizations?|authorization_codes?|oauth_codes?|verification_codes?|code_verifiers?|cookies?|tokens?|credentials?|nonces?|client_secrets?|jwts?|sessions?|(?:用户|登录)?密码|口令|(?:管理员|访问|刷新|身份|认证|授权|bearer|jwt)?令牌|(?:api|客户端|签名|加密|私有|服务账号|访问)?密钥|私钥|(?:oauth|身份|登录|认证|授权)?凭据|认证信息|授权信息|验证码|授权码)(?:_(?:values?|payloads?|data|raw|headers?|bod(?:y|ies)|texts?|json|lists?|maps?|objects?|arrays?|blobs?|responses?|previews?|plaintexts?|jars?))*(?:值|内容|原文|头|正文|数据|列表|映射|对象|数组|载荷|响应|预览|明文)*$/i;
const NON_SECRET_METADATA_WORDS = new Set([
  'count', 'counts', 'fingerprint', 'fingerprints', 'status', 'statuses',
  'state', 'states', 'expiry', 'expiries', 'expiration', 'expirations',
  'expires', 'expires_at', 'mtime', 'mtime_ms', 'size', 'length',
]);
const SECRET_TEXT = [
  /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----|$)/gi,
  /Bearer\s+(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\s,;]+)/gi,
  /Basic\s+(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\s,;]+)/gi,
  /admin-[A-Za-z0-9._~-]{16,}/gi,
  /sk-[A-Za-z0-9_-]{16,}/gi,
  /eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*){2,4}/g,
  /\brt(?:[._-][A-Za-z0-9_-]+){1,5}\b/gi,
];

function asLevel(value) {
  const level = String(value || 'info').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(LEVELS, level) ? level : 'info';
}

function normalizeSecretKey(key) {
  return String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9\u4e00-\u9fff]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase()
    // The generic acronym splitter turns OAuth into `o_auth`. Restore this
    // credential-domain acronym before matching normalized field names.
    .replace(/(^|_)o_auth(?=_|[\u4e00-\u9fff]|$)/g, '$1oauth');
}

function isSecretKey(normalizedKey) {
  let candidate = String(normalizedKey || '');
  // Indexed/versioned credential containers and derived credential material
  // are still sensitive. Keep explicit fingerprints as non-secret metadata;
  // callers intentionally use those for identity diagnostics.
  for (let count = 0; count < 8 && candidate; count += 1) {
    if (SECRET_KEY.test(candidate)) return true;
    const stripped = candidate
      .replace(/_(?:hash(?:es)?|digests?|checksums?|ids?|identifiers?|base64|b64|encoded|ciphertexts?)$/i, '')
      .replace(/(?:_v?\d{1,6}|\d{1,6})$/i, '')
      .replace(/_+$/, '');
    if (stripped === candidate) break;
    candidate = stripped;
  }
  return /(^|_)(?:client|saml|signed)_assertions?$/.test(candidate);
}

function jsonRedaction(value) {
  const trimmed = String(value || '').trim();
  if (!trimmed || !['{', '['].includes(trimmed[0])) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== 'object') return null;
    return JSON.stringify(redactValue(parsed));
  } catch {
    return null;
  }
}

function secretMayContainSpaces(normalizedKey) {
  return /(^|_)(?:passwords?|passwds?|pwds?|passphrases?|recovery_codes?|credentials?|secrets?|private_keys?)(?:_(?:values?|payloads?|data|raw|headers?|bod(?:y|ies)|texts?|json|lists?|maps?|objects?|arrays?|blobs?|responses?|previews?|plaintexts?|jars?))*$/.test(
    normalizedKey,
  ) || /(?:密码|口令|凭据|私钥)(?:值|内容|原文|正文|数据|载荷|响应|预览|明文)*$/.test(normalizedKey);
}

function assignedValueSpan(text, start, options = {}) {
  if (start >= text.length) return { end: start, replacement: '[redacted]' };
  const quote = text[start] === '"' || text[start] === "'" ? text[start] : null;
  if (quote) {
    let escaped = false;
    for (let index = start + 1; index < text.length; index += 1) {
      const character = text[index];
      if (!escaped && character === quote) {
        return { end: index + 1, replacement: quote + '[redacted]' + quote };
      }
      if (!escaped && character === '\\') escaped = true;
      else escaped = false;
    }
    return {
      end: text.length,
      replacement: quote + '[redacted]',
    };
  }

  const opening = text[start];
  const closing = opening === '{' ? '}' : opening === '[' ? ']' : null;
  if (closing) {
    const stack = [closing];
    let stringQuote = null;
    let escaped = false;
    for (let index = start + 1; index < text.length; index += 1) {
      const character = text[index];
      if (stringQuote) {
        if (!escaped && character === stringQuote) stringQuote = null;
        if (!escaped && character === '\\') escaped = true;
        else escaped = false;
        continue;
      }
      if (character === '"' || character === "'") {
        stringQuote = character;
        continue;
      }
      if (character === '{') stack.push('}');
      else if (character === '[') stack.push(']');
      else if (character === stack[stack.length - 1]) {
        stack.pop();
        if (stack.length === 0) return { end: index + 1, replacement: '[redacted]' };
      }
    }
    return {
      end: text.length,
      replacement: '[redacted]',
    };
  }

  // Passwords and passphrases commonly contain whitespace. For those labels,
  // fail closed and hide the complete diagnostic segment up to punctuation.
  const delimiters = options.allowSpaces ? /[,;，；＆}&\r\n]/ : /[\s,;，；＆}&]/;
  const delimiterOffset = text.slice(start).search(delimiters);
  const end = delimiterOffset < 0 ? text.length : start + delimiterOffset;
  return { end, replacement: '[redacted]' };
}

function redactMultiwordAssignments(value) {
  const text = String(value || '');
  // Natural-language diagnostics often spell names as "access token" or
  // "API key". Match a bounded label (at most four words), then use the same
  // normalized allowlist as structured fields rather than accepting arbitrary
  // prose before a colon.
  const pattern = /(^|[^A-Za-z0-9_])(["']?)([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_.\[\]\-\u4e00-\u9fff]*(?:[ \t]+[A-Za-z_\u4e00-\u9fff][A-Za-z0-9_.\[\]\-\u4e00-\u9fff]*){1,3})(["']?[ \t]*(?:=>|->|:=|[:=：＝→])[ \t]*)/gi;
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (!isSecretKey(normalizeSecretKey(match[3]))) continue;
    if (match.index < cursor) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3] + match[4];
    const normalizedKey = normalizeSecretKey(match[3]);
    const span = assignedValueSpan(text, pattern.lastIndex, {
      allowSpaces: secretMayContainSpaces(normalizedKey),
    });
    output += span.replacement;
    cursor = span.end;
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function redactAssignments(value) {
  const text = String(value || '');
  const pattern = /(^|[^A-Za-z0-9_])(["']?)([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_.\[\]\-\u4e00-\u9fff]{0,255})(["']?[ \t]*(?:=>|->|:=|[:=：＝→])[ \t]*)/gi;
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (!isSecretKey(normalizeSecretKey(match[3]))) continue;
    if (match.index < cursor) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3] + match[4];
    const normalizedKey = normalizeSecretKey(match[3]);
    const span = assignedValueSpan(text, pattern.lastIndex, {
      allowSpaces: secretMayContainSpaces(normalizedKey),
    });
    output += span.replacement;
    cursor = span.end;
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function redactEncodedAssignments(value) {
  const text = String(value || '');
  const pattern = /(^|[^A-Za-z0-9_%])([A-Za-z_\u4e00-\u9fff%][A-Za-z0-9_.\[\]\-\u4e00-\u9fff%]{0,255})([ \t]*=[ \t]*)/gi;
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (!match[2].includes('%')) continue;
    let decoded;
    try { decoded = decodeURIComponent(match[2]); } catch { continue; }
    const normalizedKey = normalizeSecretKey(decoded);
    if (!isSecretKey(normalizedKey) || match.index < cursor) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3];
    const span = assignedValueSpan(text, pattern.lastIndex, {
      allowSpaces: secretMayContainSpaces(normalizedKey),
    });
    output += span.replacement;
    cursor = span.end;
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function redactPercentEncodedAssignments(value) {
  const text = String(value || '');
  // Error messages often contain a redirect URL nested inside another query
  // string. In that form both the key separator and the value delimiter are
  // percent encoded, so the ordinary assignment pass cannot see them.
  const pattern = /(^|%(?:2[36]|3f)|[^A-Za-z0-9_%])((?:[A-Za-z0-9_.\[\]\-\u4e00-\u9fff]|%[0-9a-f]{2}){1,256}?)(%3[da]|%ef%bc%9[ad])/gi;
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    let decoded;
    try { decoded = decodeURIComponent(match[2]); } catch { continue; }
    const normalizedKey = normalizeSecretKey(decoded);
    if (!isSecretKey(normalizedKey) || match.index < cursor) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3];
    const tail = text.slice(pattern.lastIndex);
    const delimiter = secretMayContainSpaces(normalizedKey)
      ? /(?:%(?:26|3b|23|0a|0d|2c)|[&,;#\r\n])/i
      : /(?:%(?:26|3b|23|0a|0d|2c|20|09)|[\s&,;#])/i;
    const delimiterOffset = tail.search(delimiter);
    const end = delimiterOffset < 0 ? text.length : pattern.lastIndex + delimiterOffset;
    output += '[redacted]';
    cursor = end;
    pattern.lastIndex = Math.max(end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function startsWithNonSecretMetadata(text, start) {
  const match = /^[A-Za-z_][A-Za-z0-9_-]{0,63}/.exec(text.slice(start));
  return Boolean(match && NON_SECRET_METADATA_WORDS.has(normalizeSecretKey(match[0])));
}

function redactSpaceSeparatedPattern(value, pattern) {
  const text = String(value || '');
  let output = '';
  let cursor = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (match.index < cursor) continue;
    if (match[3].length > 128 || !isSecretKey(normalizeSecretKey(match[3]))) continue;
    let valueStart = pattern.lastIndex;
    const connector = /^(?:(?:(?:is|was|are|were)\b|是|为)[ \t]+|(?:=>|->|:=|[:=：＝→])[ \t]*)/i
      .exec(text.slice(valueStart));
    if (connector) valueStart += connector[0].length;
    if (valueStart >= text.length || startsWithNonSecretMetadata(text, valueStart)) continue;
    if (text.startsWith('[redacted]', valueStart)) continue;
    output += text.slice(cursor, match.index) + match[1] + match[2] + match[3] + match[4];
    output += text.slice(pattern.lastIndex, valueStart);
    const span = assignedValueSpan(text, valueStart, {
      allowSpaces: secretMayContainSpaces(normalizeSecretKey(match[3])),
    });
    output += span.replacement;
    cursor = span.end;
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }
  return output + text.slice(cursor);
}

function redactSpaceSeparatedSecrets(value) {
  // These labels deliberately enumerate credential concepts. The optional
  // container word covers phrases such as "credential map {...}" without
  // turning ordinary "token count/status/fingerprint" diagnostics into
  // secrets. Labels and single-key forms are both length bounded.
  const naturalPattern = /(^|[^A-Za-z0-9_])(["']?)((?:(?:access|refresh|id)[ \t]+tokens?|api[ \t]+keys?|private[ \t]+keys?|signing[ \t]+keys?|encryption[ \t]+keys?|secret[ \t]+access[ \t]+keys?|access[ \t]+key[ \t]+ids?|access[ \t]+key[ \t]+secrets?|access[ \t]+key[ \t]+materials?|access[ \t]+keys?|service[ \t]+account[ \t]+keys?|key[ \t]+materials?|mfa[ \t]+secrets?|totp[ \t]+secrets?|recovery[ \t]+codes?|authorization(?:[ \t]+codes?)?|oauth[ \t]+codes?|verification[ \t]+codes?|code[ \t]+verifiers?|client[ \t]+secrets?|secret[ \t]+keys?|passwords?|passwds?|passphrases?|secrets?|cookies?|tokens?|credentials?|nonces?|jwts?|authentication|auth|sessions?)(?:[ \t]+(?:values?|payloads?|data|raw|headers?|bodies|texts?|json|lists?|maps?|objects?|arrays?))?)(["']?[ \t]+)/gi;
  const singleKeyPattern = /(^|[^A-Za-z0-9_])(["']?)([A-Za-z_\u4e00-\u9fff][A-Za-z0-9_.\[\]\-\u4e00-\u9fff]{0,127})(["']?[ \t]+)/gi;
  return redactSpaceSeparatedPattern(
    redactSpaceSeparatedPattern(value, naturalPattern),
    singleKeyPattern,
  );
}

function redactUrlUserinfo(value) {
  return String(value || '').replace(
    /((?:[A-Za-z][A-Za-z0-9+.-]{0,30}:)?\/\/)([^/?#\s@]+)@/g,
    '$1[redacted]@',
  );
}

function redactTextCore(value) {
  let text = String(value === undefined || value === null ? '' : value);
  const structured = jsonRedaction(text);
  if (structured !== null) return structured;

  // Authorization and cookie header values may contain spaces or multiple
  // semicolon-delimited credentials. Treat the entire header value as secret.
  text = redactUrlUserinfo(text);
  text = text.replace(/\b((?:proxy[_-]?)?authorization|(?:set[_-]?)?cookie)\s*[:：]\s*[^\r\n]*/gi, '$1: [redacted]');
  for (const pattern of SECRET_TEXT) text = text.replace(pattern, '[redacted]');
  // Assignment forms must run first: otherwise the whitespace-only matcher
  // could consume the container word in `credential payload: {...}` as if it
  // were the secret value and leave the actual payload behind.
  return redactSpaceSeparatedSecrets(redactPercentEncodedAssignments(
    redactEncodedAssignments(redactAssignments(redactMultiwordAssignments(text))),
  ));
}

function decodePercentLayers(value) {
  let text = String(value);
  for (let count = 0; count < 3; count += 1) {
    const decoded = text.replace(/(?:%[0-9a-f]{2})+/gi, (segment) => {
      try { return decodeURIComponent(segment); } catch { return segment; }
    });
    if (decoded === text) break;
    text = decoded;
  }
  return text;
}

function decodeBackslashLayers(value) {
  let text = String(value);
  for (let count = 0; count < 3; count += 1) {
    const decoded = text
      .replace(/\\u([0-9a-f]{4})/gi, (_match, code) => String.fromCharCode(parseInt(code, 16)))
      .replace(/\\x([0-9a-f]{2})/gi, (_match, code) => String.fromCharCode(parseInt(code, 16)))
      .replace(/\\(["'\\/:=])/g, '$1');
    if (decoded === text) break;
    text = decoded;
  }
  return text;
}

function decodeHtmlCredentialEntities(value) {
  const named = {
    amp: '&', apos: "'", colon: ':', equals: '=', lowbar: '_', percnt: '%', quot: '"',
  };
  return String(value)
    .replace(/&#(?:x([0-9a-f]{1,6})|([0-9]{1,7}));/gi, (match, hex, decimal) => {
      const code = parseInt(hex || decimal, hex ? 16 : 10);
      try {
        return Number.isInteger(code) && code >= 0 && code <= 0x10ffff
          ? String.fromCodePoint(code)
          : match;
      } catch {
        return match;
      }
    })
    .replace(/&(amp|apos|colon|equals|lowbar|percnt|quot);/gi,
      (_match, name) => named[String(name).toLowerCase()]);
}

function encodedFormContainsSecret(original) {
  const initial = String(original);
  const seen = new Set([initial]);
  let frontier = [initial];
  const decoders = [decodePercentLayers, decodeBackslashLayers, decodeHtmlCredentialEntities];
  // Encodings are sometimes nested across different schemes (for example a
  // percent-encoded HTML entity which expands to an escaped JSON key). Check
  // a bounded composition graph instead of testing each decoder in isolation.
  for (let depth = 0; depth < 3 && frontier.length > 0; depth += 1) {
    const next = [];
    for (const candidate of frontier) {
      for (const decoder of decoders) {
        let decoded;
        try { decoded = decoder(candidate); } catch { continue; }
        if (decoded === candidate || seen.has(decoded)) continue;
        if (redactTextCore(decoded) !== decoded) return true;
        seen.add(decoded);
        if (seen.size < 32) next.push(decoded);
      }
    }
    frontier = next;
  }
  return false;
}

function redactResidualEncodedSecrets(value) {
  let text = String(value);
  // Preserve already-supported query-string diagnostics field by field. If a
  // remaining encoded token only becomes recognizable after one or more
  // decoding layers, omit that token instead of returning its raw secret.
  text = text.replace(/\S+/g, (segment) => (
    /(?:%[0-9a-f]{2}|\\(?:u[0-9a-f]{4}|x[0-9a-f]{2}|["'\\/:=])|&#(?:x[0-9a-f]{1,6}|[0-9]{1,7});|&(amp|apos|colon|equals|lowbar|percnt|quot);)/i.test(segment)
      && encodedFormContainsSecret(segment)
      ? '[redacted encoded text]'
      : segment
  ));
  if (encodedFormContainsSecret(text)) {
    return '[redacted encoded text]';
  }
  return text;
}

function redactText(value) {
  return redactResidualEncodedSecrets(redactTextCore(value));
}

function readTailText(descriptor, fileSize, lineLimit, maximumBytes = LOG_TAIL_MAX_BYTES) {
  let position = Math.max(0, Math.floor(Number(fileSize) || 0));
  let totalRead = 0;
  let completeLines = 0;
  let currentLineHasContent = false;
  let startsAtLineBoundary = position === 0;
  const chunks = [];

  const readLimit = Math.max(0, Math.min(
    LOG_TAIL_MAX_BYTES,
    Math.floor(Number(maximumBytes) || 0),
  ));
  while (position > 0 && totalRead < readLimit) {
    const length = Math.min(
      LOG_TAIL_BLOCK_BYTES,
      position,
      readLimit - totalRead,
    );
    const start = position - length;
    const buffer = Buffer.alloc(length);
    const bytesRead = fs.readSync(descriptor, buffer, 0, length, start);
    if (bytesRead !== length) throw new Error('日志文件在读取期间发生变化');
    totalRead += bytesRead;
    position = start;

    let sliceStart = 0;
    for (let index = bytesRead - 1; index >= 0; index -= 1) {
      const byte = buffer[index];
      if (byte === 0x0a) {
        if (!currentLineHasContent) continue;
        completeLines += 1;
        currentLineHasContent = false;
        if (completeLines >= lineLimit) {
          sliceStart = index + 1;
          startsAtLineBoundary = true;
          break;
        }
      } else if (byte !== 0x0d) {
        currentLineHasContent = true;
      }
    }
    chunks.unshift(buffer.subarray(sliceStart));
    if (startsAtLineBoundary) break;
  }

  if (position === 0) startsAtLineBoundary = true;
  let bytes = Buffer.concat(chunks);
  if (!startsAtLineBoundary) {
    const firstNewline = bytes.indexOf(0x0a);
    bytes = firstNewline < 0 ? Buffer.alloc(0) : bytes.subarray(firstNewline + 1);
  }
  return { text: bytes.toString('utf8'), bytesRead: totalRead };
}

function redactionContext(candidate, limits) {
  if (candidate && candidate.seen instanceof WeakSet) return candidate;
  return {
    seen: candidate instanceof WeakSet ? candidate : new WeakSet(),
    nodes: 0,
    textChars: 0,
    limits,
  };
}

function safeRedactedKey(key, index) {
  const text = String(key);
  if (text.length > 256 || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(text)) {
    return '[redacted-key-' + index + ']';
  }
  const redacted = redactText(text);
  return redacted === text ? text : '[redacted-key-' + index + ']';
}

function redactValueAt(value, key, context, depth) {
  const normalizedKey = normalizeSecretKey(key);
  if (isSecretKey(normalizedKey)) return '[redacted]';
  context.nodes += 1;
  if (context.nodes > context.limits.nodes) return '[redaction limit reached]';
  if (typeof value === 'string') {
    if (value.length > context.limits.valueChars) return '[oversized text omitted]';
    if (context.textChars + value.length > context.limits.totalChars) {
      return '[redaction text budget reached]';
    }
    context.textChars += value.length;
    return redactText(value);
  }
  if (typeof value === 'bigint') return String(value);
  // Functions are not JSON data. In particular, copying an enumerable
  // `toJSON` function into the sanitized object would let JSON.stringify call
  // attacker-controlled code after redaction and replace the whole safe value
  // with fresh, unredacted credentials.
  if (typeof value === 'function' || typeof value === 'symbol') return '[unsupported]';
  if (value && (Buffer.isBuffer(value) || ArrayBuffer.isView(value)
      || value instanceof ArrayBuffer)) return '[binary redacted]';
  if (Array.isArray(value)) {
    if (context.seen.has(value)) return '[circular]';
    if (depth >= context.limits.depth) return '[redaction depth reached]';
    context.seen.add(value);
    let descriptors;
    try { descriptors = Object.getOwnPropertyDescriptors(value); } catch {
      return '[uninspectable]';
    }
    const indexes = Object.keys(descriptors)
      .filter((childKey) => /^(?:0|[1-9][0-9]*)$/.test(childKey))
      .sort((left, right) => Number(left) - Number(right));
    const selected = indexes.slice(0, context.limits.entries);
    const output = [];
    for (const childKey of selected) {
      const descriptor = descriptors[childKey];
      output.push(Object.prototype.hasOwnProperty.call(descriptor, 'value')
        ? redactValueAt(descriptor.value, '', context, depth + 1)
        : '[accessor omitted]');
    }
    if (indexes.length > selected.length || value.length > selected.length) output.push('[truncated]');
    return output;
  }
  if (value && typeof value === 'object') {
    if (context.seen.has(value)) return '[circular]';
    if (depth >= context.limits.depth) return '[redaction depth reached]';
    context.seen.add(value);
    let descriptors;
    try { descriptors = Object.getOwnPropertyDescriptors(value); } catch {
      return '[uninspectable]';
    }
    const descriptorEntries = Object.entries(descriptors);
    const entries = descriptorEntries.slice(0, context.limits.entries);
    const output = {};
    let keyIndex = 0;
    for (const [childKey, descriptor] of entries) {
      keyIndex += 1;
      const outputKey = safeRedactedKey(childKey, keyIndex);
      // Treat the serialization hook itself as unsafe even when it is not a
      // function. Define properties explicitly so a `__proto__` input key
      // remains inert data instead of changing the sanitized object's
      // prototype and installing an inherited serialization hook.
      const safeChildValue = childKey === 'toJSON' || outputKey !== childKey
        ? '[redacted]'
        : Object.prototype.hasOwnProperty.call(descriptor, 'value')
          ? redactValueAt(descriptor.value, childKey, context, depth + 1)
          : '[accessor omitted]';
      Object.defineProperty(output, outputKey, {
        value: safeChildValue,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    if (descriptorEntries.length > entries.length) {
      Object.defineProperty(output, '[truncated]', {
        value: true,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return output;
  }
  return value;
}

function redactValue(value, key = '', candidateContext) {
  try {
    return redactValueAt(
      value,
      key,
      redactionContext(candidateContext, STORED_REDACTION_LIMITS),
      0,
    );
  } catch {
    return '[uninspectable]';
  }
}

function redactLogValue(value, key = '') {
  try {
    return redactValueAt(value, key, redactionContext(null, LOG_REDACTION_LIMITS), 0);
  } catch {
    return '[uninspectable]';
  }
}

function redactLogText(value) {
  if (!['string', 'number', 'boolean', 'bigint'].includes(typeof value)) return '';
  const text = String(value);
  return text.length <= LOG_REDACTION_LIMITS.valueChars
    ? redactText(text)
    : '[oversized text omitted]';
}

function serializeLogEntry(entry, maximumBytes = MAX_LOG_ENTRY_BYTES) {
  const safeMaximumBytes = Math.max(1024, Math.min(MAX_LOG_ENTRY_BYTES, maximumBytes));
  let line = JSON.stringify(entry) + '\n';
  if (Buffer.byteLength(line) <= safeMaximumBytes) return { entry, line };
  let compact = {
    timestamp: entry.timestamp,
    level: entry.level,
    event: entry.event,
    pid: entry.pid,
    fields: '[oversized fields omitted]',
  };
  line = JSON.stringify(compact) + '\n';
  if (Buffer.byteLength(line) > safeMaximumBytes) {
    compact = {
      timestamp: entry.timestamp,
      level: entry.level,
      event: '[oversized event omitted]',
      pid: entry.pid,
      fields: '[oversized fields omitted]',
    };
    line = JSON.stringify(compact) + '\n';
  }
  return { entry: compact, line };
}

function ownPrimitive(object, property) {
  if (!object || (typeof object !== 'object' && typeof object !== 'function')) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(object, property);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return undefined;
    const value = descriptor.value;
    return ['string', 'number', 'boolean', 'bigint'].includes(typeof value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function safeEventText(value, fallback = 'event') {
  return ['string', 'number', 'boolean', 'bigint'].includes(typeof value)
    ? redactLogText(value)
    : fallback;
}

function safeErrorText(error, limit = 8192) {
  const safeLimit = Math.max(256, Math.min(64 * 1024, Number(limit) || 8192));
  let stack;
  let code;
  if (error && (typeof error === 'object' || typeof error === 'function')) {
    stack = ownPrimitive(error, 'stack') ?? ownPrimitive(error, 'message') ?? 'unknown error';
    code = ownPrimitive(error, 'code');
  } else {
    stack = ['string', 'number', 'boolean', 'bigint'].includes(typeof error)
      ? error
      : 'unknown error';
    code = '';
  }
  stack = String(stack);
  const candidate = String(code ?? '').trim();
  code = /^[A-Za-z0-9_.-]{1,100}$/.test(candidate) ? candidate : '';
  const combined = (code ? 'code=' + code + '\n' : '') + stack;
  if (combined.length > LOG_REDACTION_LIMITS.valueChars) {
    return ((code ? 'code=' + code + '\n' : '') + '[oversized error omitted]').slice(0, safeLimit);
  }
  return redactText(combined).slice(0, safeLimit);
}

function safeFailureMessage(error, fallback = 'unknown error') {
  let value = ownPrimitive(error, 'message');
  if (value === undefined && ['string', 'number', 'boolean', 'bigint'].includes(typeof error)) {
    value = error;
  }
  const text = redactLogText(value === undefined ? fallback : value).slice(0, 1000);
  return text || fallback;
}

function numberFromEnv(value, fallback, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= minimum ? Math.min(parsed, maximum) : fallback;
}

class PanelLogger {
  constructor(options = {}) {
    const dbPath = String(options.dbPath || process.env.PANEL_DB_PATH || '');
    const defaultDirectory = dbPath
      ? path.dirname(path.resolve(dbPath))
      : path.join('/tmp', 'gpt-register-panel');
    this.filePath = path.resolve(
      options.filePath || process.env.PANEL_LOG_PATH || path.join(defaultDirectory, 'panel.log'),
    );
    this.level = asLevel(options.level || process.env.PANEL_LOG_LEVEL || 'info');
    this.maxBytes = Math.floor(numberFromEnv(
      options.maxBytes || process.env.PANEL_LOG_MAX_BYTES,
      10 * 1024 * 1024,
      1024,
      MAX_LOG_BYTES,
    ));
    const requestedRotations = Math.floor(numberFromEnv(
      options.rotations || process.env.PANEL_LOG_ROTATIONS,
      5,
      1,
      MAX_LOG_ROTATIONS,
    ));
    const retainedRotationLimit = Math.max(1, Math.floor(MAX_LOG_TOTAL_BYTES / this.maxBytes) - 1);
    this.rotations = Math.min(requestedRotations, retainedRotationLimit);
    const consoleValue = options.console === undefined
      ? process.env.PANEL_LOG_CONSOLE ?? '1'
      : options.console;
    this.consoleEnabled = consoleValue !== false
      && String(consoleValue).toLowerCase() !== '0'
      && String(consoleValue).toLowerCase() !== 'false';
    this.failedWrites = 0;
    this.fallbackReports = 0;
    this.consecutiveWriteFailures = 0;
    this.lastWriteFailureAt = null;
    this.lastWriteSucceededAt = null;
    this.fileHealthy = false;
    this.pid = process.pid;
    this.directoryIdentity = null;
    this.ensureDirectory();
  }

  ensureDirectory() {
    let descriptor;
    let pinnedDirectory;
    try {
      const directory = ensureDirectoryTree(path.dirname(this.filePath), '日志目录');
      const directoryStat = fs.lstatSync(directory);
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
      if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()
          || (currentUid !== null && directoryStat.uid !== currentUid)
          || (directoryStat.mode & 0o022) !== 0) {
        throw new Error('日志目录必须由当前用户持有且不可由组或其他用户写入');
      }
      this.directoryIdentity = {
        realPath: fs.realpathSync(directory),
        dev: directoryStat.dev,
        ino: directoryStat.ino,
      };
      pinnedDirectory = this.openPinnedDirectory();
      if (this.validateLogNamespace(pinnedDirectory, currentUid)) {
        this.syncPinnedDirectory(pinnedDirectory);
      }

      // Probe the actual destination during startup. Merely validating the
      // parent directory would let a read-only mount, exhausted filesystem,
      // or an unsafe file replacement silently disable the entire audit log.
      const timestamp = new Date().toISOString();
      const line = JSON.stringify({
        timestamp,
        level: 'info',
        event: 'logger.write_preflight',
        pid: this.pid,
      }) + '\n';
      this.rotateIfNeeded(Buffer.byteLength(line), pinnedDirectory);
      descriptor = this.openValidatedFile(pinnedDirectory);
      fs.fchmodSync(descriptor, 0o600);
      fs.writeFileSync(descriptor, line);
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      // A file fsync does not make a newly-created current log or rotation
      // rename durable. Sync the exact directory FD used for the write before
      // the startup preflight is allowed to report success.
      this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.lastWriteSucceededAt = timestamp;
    } catch (error) {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      this.directoryIdentity = null;
      this.fileHealthy = false;
      this.fallback('error', 'logger.initialize_failed', { error: safeFailureMessage(error) });
      const wrapped = new Error('审计日志初始化失败，拒绝启动');
      wrapped.code = 'PANEL_LOG_INITIALIZATION_FAILED';
      wrapped.cause = error;
      throw wrapped;
    } finally {
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
  }

  filePathIn(pinnedDirectory) {
    return path.join(pinnedDirectory.accessDirectory, path.basename(this.filePath));
  }

  validateExistingLogFile(pinnedDirectory, candidatePath, currentUid, normalizePermissions) {
    this.assertPinnedDirectory(pinnedDirectory);
    const pathStat = fs.lstatSync(candidatePath);
    if (pathStat.isSymbolicLink() || !pathStat.isFile() || pathStat.nlink !== 1
        || (currentUid !== null && pathStat.uid !== currentUid)
        || (pathStat.mode & 0o022) !== 0) {
      throw new Error('日志文件必须是当前用户持有且不可被其他用户修改的单链接普通文件');
    }
    let descriptor;
    try {
      const needsNormalization = normalizePermissions && (pathStat.mode & 0o077) !== 0;
      descriptor = fs.openSync(
        candidatePath,
        (needsNormalization ? fs.constants.O_RDWR : fs.constants.O_RDONLY)
          | (fs.constants.O_NOFOLLOW || 0)
          | (fs.constants.O_NONBLOCK || 0),
      );
      let descriptorStat = fs.fstatSync(descriptor);
      if (!descriptorStat.isFile() || descriptorStat.nlink !== 1
          || descriptorStat.dev !== pathStat.dev || descriptorStat.ino !== pathStat.ino
          || (currentUid !== null && descriptorStat.uid !== currentUid)
          || (descriptorStat.mode & 0o022) !== 0) {
        throw new Error('日志文件在安全校验期间发生变化');
      }
      if (needsNormalization) {
        fs.fchmodSync(descriptor, 0o600);
        fs.fsyncSync(descriptor);
        descriptorStat = fs.fstatSync(descriptor);
      }
      if ((descriptorStat.mode & 0o077) !== 0) {
        throw new Error('日志文件权限必须不宽于 0600');
      }
      return { permissionsChanged: needsNormalization, size: descriptorStat.size };
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
    }
  }

  validateLogNamespace(pinnedDirectory, currentUid) {
    this.assertPinnedDirectory(pinnedDirectory);
    const baseName = path.basename(this.filePath);
    const names = [];
    let entryCount = 0;
    let directory;
    try {
      directory = fs.opendirSync(pinnedDirectory.accessDirectory);
      for (let entry = directory.readSync(); entry !== null; entry = directory.readSync()) {
        entryCount += 1;
        if (entryCount > MAX_LOG_DIRECTORY_ENTRIES) {
          throw new Error('日志目录条目数量超过安全上限');
        }
        const name = entry.name;
        if (name === baseName
            || (name.startsWith(baseName + '.') && /^\d+$/.test(name.slice(baseName.length + 1)))) {
          names.push(name);
          if (names.length > MAX_LOG_NAMESPACE_FILES) {
            throw new Error('日志轮转文件数量超过安全上限');
          }
        }
      }
    } finally {
      if (directory) {
        directory.closeSync();
      }
    }
    this.assertPinnedDirectory(pinnedDirectory);
    let permissionsChanged = false;
    let totalBytes = 0;
    for (const name of names) {
      const validation = this.validateExistingLogFile(
        pinnedDirectory,
        path.join(pinnedDirectory.accessDirectory, name),
        currentUid,
        true,
      );
      if (!Number.isSafeInteger(validation.size) || validation.size < 0
          || validation.size > MAX_LOG_TOTAL_BYTES - totalBytes) {
        throw new Error('日志轮转文件实际总大小超过安全上限');
      }
      totalBytes += validation.size;
      permissionsChanged = validation.permissionsChanged || permissionsChanged;
    }
    return permissionsChanged;
  }

  assertPinnedDirectory(pinnedDirectory) {
    if (!pinnedDirectory || !Number.isInteger(pinnedDirectory.descriptor)) {
      throw new Error('日志目录未固定');
    }
    const stat = fs.fstatSync(pinnedDirectory.descriptor);
    const identity = this.directoryIdentity;
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (!identity || !stat.isDirectory()
        || stat.dev !== identity.dev || stat.ino !== identity.ino
        || (currentUid !== null && stat.uid !== currentUid)
        || (stat.mode & 0o022) !== 0) {
      throw new Error('日志目录 FD 与初始化时的安全目录不一致');
    }
    this.assertDirectorySafe();
  }

  openPinnedDirectory() {
    this.assertDirectorySafe();
    const identity = this.directoryIdentity;
    let descriptor;
    try {
      descriptor = fs.openSync(
        identity.realPath,
        fs.constants.O_RDONLY
          | (fs.constants.O_DIRECTORY || 0)
          | (fs.constants.O_NOFOLLOW || 0),
      );
      const pinnedDirectory = {
        descriptor,
        accessDirectory: identity.realPath,
      };
      this.assertPinnedDirectory(pinnedDirectory);
      if (process.platform === 'linux') {
        const accessDirectory = '/proc/self/fd/' + descriptor;
        if (fs.realpathSync(accessDirectory) !== identity.realPath) {
          throw new Error('日志目录 FD 解析结果不一致');
        }
        pinnedDirectory.accessDirectory = accessDirectory;
      }
      descriptor = undefined;
      return pinnedDirectory;
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
    }
  }

  syncPinnedDirectory(pinnedDirectory) {
    this.assertPinnedDirectory(pinnedDirectory);
    fs.fsyncSync(pinnedDirectory.descriptor);
    // Do not return a durable-checkpoint success if the configured path was
    // replaced while the pinned directory itself was being synchronized.
    this.assertPinnedDirectory(pinnedDirectory);
  }

  openValidatedFile(pinnedDirectory) {
    this.assertPinnedDirectory(pinnedDirectory);
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    const descriptor = fs.openSync(
      this.filePathIn(pinnedDirectory),
      fs.constants.O_APPEND
        | fs.constants.O_CREAT
        | fs.constants.O_WRONLY
        | noFollow
        | (fs.constants.O_NONBLOCK || 0),
      0o600,
    );
    try {
      const stat = fs.fstatSync(descriptor);
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
      if (!stat.isFile() || stat.nlink !== 1
          || (currentUid !== null && stat.uid !== currentUid)
          || (stat.mode & 0o077) !== 0) {
        throw new Error('日志文件必须是当前用户持有且不可被其他用户修改的普通文件');
      }
      return descriptor;
    } catch (error) {
      try { fs.closeSync(descriptor); } catch {}
      throw error;
    }
  }

  probe() {
    let descriptor;
    let pinnedDirectory;
    try {
      const line = JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'debug',
        event: 'logger.write_preflight',
        pid: this.pid,
      }) + '\n';
      pinnedDirectory = this.openPinnedDirectory();
      this.rotateIfNeeded(Buffer.byteLength(line), pinnedDirectory);
      descriptor = this.openValidatedFile(pinnedDirectory);
      fs.fchmodSync(descriptor, 0o600);
      fs.writeFileSync(descriptor, line);
      fs.fsyncSync(descriptor);
      this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.fallbackReports = 0;
      this.consecutiveWriteFailures = 0;
      this.lastWriteSucceededAt = new Date().toISOString();
      return true;
    } catch (error) {
      this.fileHealthy = false;
      this.failedWrites += 1;
      this.consecutiveWriteFailures += 1;
      this.lastWriteFailureAt = new Date().toISOString();
      this.fallback('error', 'logger.probe_failed', { error: safeFailureMessage(error) });
      return false;
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
  }

  checkpoint(event, fields = {}) {
    let descriptor;
    let pinnedDirectory;
    const checkpointEvent = safeEventText(event, 'logger.audit_checkpoint');
    try {
      const timestamp = new Date().toISOString();
      const safeFields = fields && typeof fields === 'object' && !Array.isArray(fields)
        ? redactLogValue(fields)
        : {};
      const serialized = serializeLogEntry({
        ...safeFields,
        timestamp,
        level: 'info',
        event: checkpointEvent,
        pid: this.pid,
      }, this.maxBytes);
      const line = serialized.line;
      pinnedDirectory = this.openPinnedDirectory();
      this.rotateIfNeeded(Buffer.byteLength(line), pinnedDirectory);
      descriptor = this.openValidatedFile(pinnedDirectory);
      fs.fchmodSync(descriptor, 0o600);
      fs.writeFileSync(descriptor, line);
      fs.fsyncSync(descriptor);
      this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.fallbackReports = 0;
      this.consecutiveWriteFailures = 0;
      this.lastWriteSucceededAt = timestamp;
      return true;
    } catch (error) {
      this.fileHealthy = false;
      this.failedWrites += 1;
      this.consecutiveWriteFailures += 1;
      this.lastWriteFailureAt = new Date().toISOString();
      this.fallback('error', 'logger.checkpoint_failed', {
        checkpointEvent,
        error: safeFailureMessage(error),
      });
      return false;
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
  }

  health() {
    return {
      healthy: this.fileHealthy && this.directoryIdentity !== null,
      failedWrites: this.failedWrites,
      consecutiveWriteFailures: this.consecutiveWriteFailures,
      lastWriteFailureAt: this.lastWriteFailureAt,
      lastWriteSucceededAt: this.lastWriteSucceededAt,
    };
  }

  assertDirectorySafe() {
    if (!this.directoryIdentity) throw new Error('日志目录未通过安全校验');
    const directory = path.dirname(this.filePath);
    const stat = fs.lstatSync(directory);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (stat.isSymbolicLink() || !stat.isDirectory()
        || stat.dev !== this.directoryIdentity.dev || stat.ino !== this.directoryIdentity.ino
        || fs.realpathSync(directory) !== this.directoryIdentity.realPath
        || (currentUid !== null && stat.uid !== currentUid)
        || (stat.mode & 0o022) !== 0) {
      throw new Error('日志目录在初始化后发生变化或权限不安全');
    }
  }

  shouldLog(level) {
    return LEVELS[level] >= LEVELS[this.level];
  }

  rotateIfNeeded(nextBytes, pinnedDirectory) {
    this.assertPinnedDirectory(pinnedDirectory);
    const currentPath = this.filePathIn(pinnedDirectory);
    let fileStat;
    try {
      fileStat = fs.lstatSync(currentPath);
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      throw error;
    }
    if (fileStat.isSymbolicLink() || !fileStat.isFile()) {
      throw new Error('日志轮转源必须是普通文件');
    }
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    this.validateExistingLogFile(pinnedDirectory, currentPath, currentUid, false);
    if (fileStat.size + nextBytes <= this.maxBytes) return false;
    let directoryChanged = false;
    try {
      for (let index = this.rotations - 1; index >= 1; index -= 1) {
        const from = currentPath + '.' + index;
        const to = currentPath + '.' + (index + 1);
        let fromStat;
        try { fromStat = fs.lstatSync(from); } catch (error) {
          if (error?.code === 'ENOENT') fromStat = null;
          else throw error;
        }
        if (!fromStat) continue;
        this.validateExistingLogFile(pinnedDirectory, from, currentUid, false);
        let toStat;
        try { toStat = fs.lstatSync(to); } catch (error) {
          if (error?.code === 'ENOENT') toStat = null;
          else throw error;
        }
        if (toStat) this.validateExistingLogFile(pinnedDirectory, to, currentUid, false);
        fs.renameSync(from, to);
        directoryChanged = true;
      }
      const target = currentPath + '.1';
      let targetStat;
      try { targetStat = fs.lstatSync(target); } catch (error) {
        if (error?.code === 'ENOENT') targetStat = null;
        else throw error;
      }
      if (targetStat) this.validateExistingLogFile(pinnedDirectory, target, currentUid, false);
      fs.renameSync(currentPath, target);
      directoryChanged = true;
      // Make the completed namespace transition durable before the caller
      // attempts to recreate the current file. If that later open/write
      // fails, a crash must not resurrect an ambiguous partial rotation.
      this.syncPinnedDirectory(pinnedDirectory);
      return true;
    } catch (error) {
      // If a multi-file rotation stopped part way through, at least persist the
      // resulting directory state before reporting the operation as failed.
      if (directoryChanged) {
        try { this.syncPinnedDirectory(pinnedDirectory); } catch (syncError) {
          error = syncError;
        }
      }
      this.fallback('error', 'logger.rotate_failed', { error: safeFailureMessage(error) });
      const wrapped = new Error('日志轮转失败');
      wrapped.code = 'PANEL_LOG_ROTATION_FAILED';
      wrapped.cause = error;
      throw wrapped;
    }
  }

  fallback(level, event, fields = {}) {
    if (this.fallbackReports > 1 || !this.consoleEnabled) return;
    this.fallbackReports += 1;
    try {
      const serialized = serializeLogEntry({
        ...redactLogValue(fields),
        timestamp: new Date().toISOString(),
        level,
        event: safeEventText(event),
        pid: this.pid,
      });
      process.stderr.write(serialized.line);
    } catch {}
  }

  log(level, event, fields = {}) {
    const normalizedLevel = asLevel(level);
    if (!this.shouldLog(normalizedLevel)) return null;
    let entry;
    let line;
    try {
      entry = {
        ...redactLogValue(fields),
        timestamp: new Date().toISOString(),
        level: normalizedLevel,
        event: safeEventText(event),
        pid: this.pid,
      };
      ({ entry, line } = serializeLogEntry(entry, this.maxBytes));
    } catch (error) {
      this.fallback('error', 'logger.serialize_failed', {
        error: safeFailureMessage(error),
        originalEvent: event,
      });
      return null;
    }
    let pinnedDirectory;
    try {
      pinnedDirectory = this.openPinnedDirectory();
      const bytes = Buffer.byteLength(line);
      const rotated = this.rotateIfNeeded(bytes, pinnedDirectory);
      const currentPath = this.filePathIn(pinnedDirectory);
      let currentExisted = true;
      try { fs.lstatSync(currentPath); } catch (error) {
        if (error?.code === 'ENOENT') currentExisted = false;
        else throw error;
      }
      const descriptor = this.openValidatedFile(pinnedDirectory);
      try {
        fs.fchmodSync(descriptor, 0o600);
        fs.writeFileSync(descriptor, line);
      } finally { fs.closeSync(descriptor); }
      if (rotated || !currentExisted) this.syncPinnedDirectory(pinnedDirectory);
      this.fileHealthy = true;
      this.fallbackReports = 0;
      this.consecutiveWriteFailures = 0;
      this.lastWriteSucceededAt = new Date().toISOString();
    } catch (error) {
      this.fileHealthy = false;
      this.failedWrites += 1;
      this.consecutiveWriteFailures += 1;
      this.lastWriteFailureAt = new Date().toISOString();
      this.fallback('error', 'logger.write_failed', {
        error: safeFailureMessage(error),
        originalEvent: event,
      });
    } finally {
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
    if (this.consoleEnabled) {
      try { process.stdout.write(line); } catch {}
    }
    return entry;
  }

  debug(event, fields) { return this.log('debug', event, fields); }
  info(event, fields) { return this.log('info', event, fields); }
  warn(event, fields) { return this.log('warn', event, fields); }
  error(event, fields) { return this.log('error', event, fields); }

  requestId(value) {
    const candidate = String(value || '').trim();
    return candidate && /^[A-Za-z0-9_.:@-]{1,100}$/.test(candidate)
      ? candidate
      : crypto.randomUUID();
  }

  readTailFile(pinnedDirectory, name, lineLimit, byteLimit) {
    this.assertPinnedDirectory(pinnedDirectory);
    const candidatePath = path.join(pinnedDirectory.accessDirectory, name);
    let initial;
    try {
      initial = fs.lstatSync(candidatePath);
    } catch (error) {
      if (error?.code === 'ENOENT') return { entries: [], bytesRead: 0 };
      throw error;
    }
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (initial.isSymbolicLink() || !initial.isFile() || initial.nlink !== 1
        || (currentUid !== null && initial.uid !== currentUid)
        || (initial.mode & 0o077) !== 0) {
      throw new Error('日志读取目标不安全');
    }
    let descriptor;
    try {
      descriptor = fs.openSync(
        candidatePath,
        fs.constants.O_RDONLY
          | (fs.constants.O_NOFOLLOW || 0)
          | (fs.constants.O_NONBLOCK || 0),
      );
      const opened = fs.fstatSync(descriptor);
      if (!opened.isFile() || opened.nlink !== 1
          || opened.dev !== initial.dev || opened.ino !== initial.ino
          || (currentUid !== null && opened.uid !== currentUid)
          || (opened.mode & 0o077) !== 0) {
        throw new Error('日志读取目标在打开期间发生变化');
      }
      const result = readTailText(descriptor, opened.size, lineLimit, byteLimit);
      const latest = fs.lstatSync(candidatePath);
      if (latest.isSymbolicLink() || !latest.isFile() || latest.nlink !== 1
          || latest.dev !== opened.dev || latest.ino !== opened.ino) {
        throw new Error('日志读取目标在读取期间发生变化');
      }
      this.assertPinnedDirectory(pinnedDirectory);
      const entries = result.text.split(/\r?\n/).filter(Boolean).slice(-lineLimit).map((line) => {
        try { return redactLogValue(JSON.parse(line)); } catch {
          return { level: 'error', event: 'logger.invalid_line', message: redactText(line) };
        }
      });
      return { entries, bytesRead: result.bytesRead };
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
    }
  }

  tail(limit = 200) {
    const safeLimit = Math.max(1, Math.min(2000, Math.floor(Number(limit) || 200)));
    let pinnedDirectory;
    try {
      pinnedDirectory = this.openPinnedDirectory();
      const baseName = path.basename(this.filePath);
      let remainingBytes = LOG_TAIL_MAX_BYTES;
      let entries = [];
      for (let index = 0; index <= this.rotations
          && entries.length < safeLimit && remainingBytes > 0; index += 1) {
        const name = index === 0 ? baseName : baseName + '.' + index;
        const result = this.readTailFile(
          pinnedDirectory,
          name,
          safeLimit - entries.length,
          remainingBytes,
        );
        remainingBytes -= result.bytesRead;
        if (result.entries.length > 0) entries = result.entries.concat(entries);
      }
      this.assertPinnedDirectory(pinnedDirectory);
      return entries.slice(-safeLimit);
    } catch {
      return [];
    } finally {
      if (pinnedDirectory?.descriptor !== undefined) {
        try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      }
    }
  }
}

function createLogger(options = {}) {
  return new PanelLogger(options);
}

function assertAuditLogCheckpoint(logger, event, fields = {}) {
  let succeeded = false;
  try {
    if (logger && typeof logger.checkpoint === 'function') {
      succeeded = logger.checkpoint(event, fields) === true;
    } else if (logger && typeof logger.probe === 'function') {
      // Compatibility for injected loggers while every production
      // PanelLogger writes the contextual, fsynced checkpoint above.
      succeeded = logger.probe() === true;
    }
  } catch {}
  if (succeeded) return true;
  const error = new Error('审计日志不可写，已在文件变更前停止操作');
  error.code = 'AUDIT_LOG_UNAVAILABLE';
  throw error;
}

module.exports = {
  LEVELS,
  PanelLogger,
  assertAuditLogCheckpoint,
  createLogger,
  redactText,
  redactValue,
  safeErrorText,
  safeFailureMessage,
};
