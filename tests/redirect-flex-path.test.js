'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadParserFromServer() {
  const source = fs.readFileSync('server.js', 'utf8');
  const detectStart = source.indexOf('function detectEncodedEmailSegment(');
  const parserStart = source.indexOf('function parseFlexiblePathRedirectInput(');
  const normHostStart = source.indexOf('function normHost(');

  if (detectStart < 0 || parserStart < 0 || normHostStart < 0) {
    throw new Error('Could not locate parser functions in server.js');
  }

  const snippet = source.slice(parserStart, normHostStart) + '\nthis.parseFlexiblePathRedirectInput = parseFlexiblePathRedirectInput;';
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);

  return sandbox.parseFlexiblePathRedirectInput;
}

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

const parseFlexiblePathRedirectInput = loadParserFromServer();
const helpers = {
  decodeBase64UrlLoose: decodeB64urlLoose,
  decodeFallback: safeDecode,
  isValidEmail: isLikelyEmail
};

const b64urlEmail = Buffer.from('alice@example.com', 'utf8').toString('base64url');
const b64stdEmail = Buffer.from('bob@example.com', 'utf8').toString('base64');

test('supports /{payload}/{ignored}/{email}', () => {
  const parsed = parseFlexiblePathRedirectInput(`payload123/test.com/${b64urlEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_ignored_email');
  assert.equal(parsed.emailSegment, 'segment3');
  assert.equal(parsed.payload, 'payload123');
  assert.equal(parsed.ignoredSegment, 'test.com');
  assert.equal(parsed.email, b64urlEmail);
  assert.equal(parsed.normalizedBaseString, `payload123/${b64urlEmail}`);
});

test('supports /{payload}/{email}/{ignored}', () => {
  const parsed = parseFlexiblePathRedirectInput(`payload123/${b64urlEmail}/cosmetic`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_email_ignored');
  assert.equal(parsed.emailSegment, 'segment2');
  assert.equal(parsed.ignoredSegment, 'cosmetic');
  assert.equal(parsed.normalizedBaseString, `payload123/${b64urlEmail}`);
});

test('supports /{payload}/{ignored} with no email', () => {
  const parsed = parseFlexiblePathRedirectInput('payload123/test.com', helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_ignored');
  assert.equal(parsed.email, null);
  assert.equal(parsed.ignoredSegment, 'test.com');
  assert.equal(parsed.normalizedBaseString, 'payload123');
});

test('supports URL-safe and standard base64 email', () => {
  const parsedUrl = parseFlexiblePathRedirectInput(`payload/${b64urlEmail}/ignored`, helpers);
  const parsedStd = parseFlexiblePathRedirectInput(`payload/${b64stdEmail}/ignored`, helpers);
  assert.equal(parsedUrl.emailSegment, 'segment2');
  assert.equal(parsedStd.emailSegment, 'segment2');
});

test('ambiguous both-email segments are flagged', () => {
  const another = Buffer.from('eve@example.org', 'utf8').toString('base64url');
  const parsed = parseFlexiblePathRedirectInput(`payload/${b64urlEmail}/${another}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.ambiguityDetected, true);
  assert.equal(parsed.parseMode, 'ambiguous_email_segments');
  assert.equal(parsed.normalizedBaseString, null);
});

test('unsupported segment counts remain legacy', () => {
  assert.equal(parseFlexiblePathRedirectInput('onlypayload', helpers).matchedNewFormat, false);
  assert.equal(parseFlexiblePathRedirectInput('a/b/c/d', helpers).matchedNewFormat, false);
});
