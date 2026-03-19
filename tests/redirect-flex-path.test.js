'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadFunctionsFromServer() {
  const source = fs.readFileSync('server.js', 'utf8');
  const start = source.indexOf('function safeDecode(');
  const end = source.indexOf('function normHost(');
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate expected function region in server.js');
  }

  const snippet = `${source.slice(start, end)}\nthis.__loaded = { parseFlexiblePathRedirectInput, validateBase64Url };`;
  const sandbox = { Buffer, process: { env: {} } };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);

  if (!sandbox.__loaded || typeof sandbox.__loaded.parseFlexiblePathRedirectInput !== 'function' || typeof sandbox.__loaded.validateBase64Url !== 'function') {
    throw new Error('Failed to load parser/validator functions from server.js');
  }

  return sandbox.__loaded;
}

const {
  parseFlexiblePathRedirectInput,
  validateBase64Url
} = loadFunctionsFromServer();

function decodeB64urlLoose(s) {
  try {
    let u = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function safeDecode(s) {
  try {
    return decodeURIComponent(String(s || ''));
  } catch {
    return String(s || '');
  }
}

function isLikelyEmail(s) {
  return /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/i.test(String(s || ''));
}

const helpers = {
  decodeBase64UrlLoose: decodeB64urlLoose,
  decodeFallback: safeDecode,
  isValidEmail: isLikelyEmail
};

const b64urlEmail = Buffer.from('alice@example.com', 'utf8').toString('base64url');
const b64stdEmail = Buffer.from('bob@example.com', 'utf8').toString('base64');
const payload = 'I8d-eh9OogUNRrosFLLESnDTLOGI_bDottmN-72JzwezfDqfiudRshnTmpYjXnOYYXNWVFR1SefJp_KfB8ZDyabpDBM';

test('supports /{payload}/{ignored}/{email}', () => {
  const parsed = parseFlexiblePathRedirectInput(`${payload}/test.com/${b64urlEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_ignored_email');
  assert.equal(parsed.emailSegment, 'segment3');
});

test('supports /{payload}/{email}/{ignored}', () => {
  const parsed = parseFlexiblePathRedirectInput(`${payload}/${b64urlEmail}/cosmetic`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_email_ignored');
  assert.equal(parsed.emailSegment, 'segment2');
});

test('supports /{payload}/{ignored} with no email', () => {
  const parsed = parseFlexiblePathRedirectInput(`${payload}/test.com`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_ignored');
  assert.equal(parsed.normalizedBaseString, payload);
});

test('supports URL-safe and standard base64 email', () => {
  const parsedUrl = parseFlexiblePathRedirectInput(`${payload}/${b64urlEmail}/ignored`, helpers);
  const parsedStd = parseFlexiblePathRedirectInput(`${payload}/${b64stdEmail}/ignored`, helpers);
  assert.equal(parsedUrl.emailSegment, 'segment2');
  assert.equal(parsedStd.emailSegment, 'segment2');
});

test('ambiguous both-email segments are flagged', () => {
  const another = Buffer.from('eve@example.org', 'utf8').toString('base64url');
  const parsed = parseFlexiblePathRedirectInput(`${payload}/${b64urlEmail}/${another}`, helpers);
  assert.equal(parsed.ambiguityDetected, true);
  assert.equal(parsed.normalizedBaseString, null);
});

test('validateBase64Url accepts payload//email/ignored', () => {
  assert.equal(validateBase64Url(`${payload}//${b64urlEmail}/test.com`), true);
});

test('validateBase64Url accepts payload/ignored//email', () => {
  assert.equal(validateBase64Url(`${payload}/test.com//${b64urlEmail}`), true);
});

test('validateBase64Url supports second payload sample with optional-prefix style paths', () => {
  const payload2 = 'LiW9YpsvCplyLIlP2nPTeZ5JsWE5TbC7LSECsbflC7Cc2gtL-7LHqm-FT1JBkL2eY8wUyFUoI1RgldgpR2W7kNVG7h-KADXS_Jk';
  const email2 = 'cmUzNDM2OTZAaG90bWFpbC5jb20=';
  assert.equal(validateBase64Url(`${payload2}/test.com//${email2}`), true);
  assert.equal(validateBase64Url(`${payload2}//${email2}/test.com`), true);
});

test('validateBase64Url accepts ignored full URL with email at end', () => {
  assert.equal(validateBase64Url(`${payload}/https://test.com//${b64urlEmail}`), true);
});

test('validateBase64Url accepts email first then ignored full URL', () => {
  assert.equal(validateBase64Url(`${payload}//${b64urlEmail}/https://test.com`), true);
});

test('validateBase64Url accepts ignored full URL without email', () => {
  assert.equal(validateBase64Url(`${payload}/https://test.com`), true);
});

test('validateBase64Url accepts platform-collapsed ignored URL before email', () => {
  assert.equal(validateBase64Url(`${payload}/url=https:/test.com/${b64urlEmail}`), true);
});

test('validateBase64Url accepts platform-collapsed ignored URL after email', () => {
  assert.equal(validateBase64Url(`${payload}/${b64urlEmail}/url=https:/test.com`), true);
});
