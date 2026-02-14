// server.js — AES redirector + Cloudflare Turnstile, hardened (v4.9.4 Advance Beta widget + Interstitial improved)
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

// fetch (Node 18+ has global fetch)
let fetchFn = globalThis.fetch;
if (!fetchFn) { try { fetchFn = require("node-fetch"); } catch (_) {} }
const fetch = fetchFn;

// Optional local GeoIP (fallback if no edge headers)
let geoip = null;
try {
  geoip = require("geoip-lite");
  console.log(`[${new Date().toISOString()}] ℹ️ geoip-lite enabled as country fallback`);
} catch {
  console.log(`[${new Date().toISOString()}] ⚠️ geoip-lite not installed; ALLOWED_COUNTRIES depends on edge headers only`);
}

// ================== CONSTANTS ==================
const SANITIZATION_MAX_LENGTH = 2000;
const UA_TRUNCATE_LENGTH = 160;
const PATH_TRUNCATE_LENGTH = 200;
const ACCEPT_TRUNCATE_LENGTH = 80;
const REFERER_TRUNCATE_LENGTH = 160;
const BRUTE_FORCE_MIN_RATIO = 0.4;
const LOG_ENTRY_MAX_LENGTH = 300;
const EMAIL_DISPLAY_MAX_LENGTH = 80;
const URL_DISPLAY_MAX_LENGTH = 120;

const app = express();
function parseTrustProxyValue(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) return null;

  if (raw.toLowerCase() === 'true') return true;
  if (raw.toLowerCase() === 'false') return false;
  if (Number.isFinite(+raw) && +raw >= 0) return +raw;
  return null;
}

// Safety override: prefer explicit/safer proxy trust behavior unless explicitly set.
function resolveSaferTrustProxySetting() {
  const parsedTrustProxy = parseTrustProxyValue(process.env.TRUST_PROXY_HOPS);
  const mode = String(process.env.TRUST_PROXY_MODE || 'safe').trim().toLowerCase();

  if (parsedTrustProxy !== null) return parsedTrustProxy;

  // In safe mode, default to explicit single hop on managed platforms, otherwise no trust.
  if (mode === 'safe') {
    if (process.env.VERCEL || process.env.NETLIFY || process.env.RENDER || process.env.RAILWAY || process.env.HEROKU) {
      return 1;
    }
    return false;
  }

  // Legacy behavior compatibility: trust all proxies when hops are unset.
  return true;
}

const trustProxyEffective = resolveSaferTrustProxySetting();
app.set('trust proxy', trustProxyEffective);
console.log(`[PROXY] Effective trust proxy setting: ${trustProxyEffective}`);

const REQUIRE_CF_HEADERS = (process.env.REQUIRE_CF_HEADERS || "").toLowerCase() === "true";

// ------------ Enhanced Global Security Headers ---------------
app.use((req, res, next) => {
  // Generate a nonce for CSP
  const cspNonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = cspNonce;
  
  // Avoid caching challenge pages/tokens
  res.setHeader("Cache-Control", "no-store");
  
  // Determine if secure connection
  const isSecure = req.secure || (req.headers["x-forwarded-proto"] || "").includes("https");
  if (isSecure) {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }
  
  // Private Access Tokens
  res.setHeader(
    "Permissions-Policy",
    'private-token=(self "https://challenges.cloudflare.com" "https://challenges.fed.cloudflare.com" "https://challenges-staging.cloudflare.com")'
  );
  
  // Enhanced CSP with nonce support
  const isChallengePage = req.path === '/challenge' || req.path === '/challenge-fragment';
  const cspDirectives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${cspNonce}' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com ${isChallengePage ? "'unsafe-inline'" : ""}`,
    "style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com",
    "font-src 'self' data:",
    "frame-src 'self' https://challenges.cloudflare.com",
    "worker-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ];
  
  // Add report-uri in production
  if (process.env.NODE_ENV === 'production' && process.env.CSP_REPORT_URI) {
    cspDirectives.push(`report-uri ${process.env.CSP_REPORT_URI}`);
    cspDirectives.push("report-to csp-endpoint");
  }
  
  res.setHeader("Content-Security-Policy", cspDirectives.join('; '));
  
  // Additional security headers
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("X-Download-Options", "noopen");
  
  // Cross-origin headers
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  
  // Remove powered-by header
  res.removeHeader('X-Powered-By');
  
  next();
});

// ================== HELPER FUNCTIONS ==================
function mask(s){ if (!s) return ""; return s.length<=6 ? "*".repeat(s.length) : s.slice(0,4)+"…"+s.slice(-2); }

function safeZone(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz }).format();
    return tz;
  } catch {
    return 'UTC';
  }
}

const TIMEZONE = safeZone(process.env.TIMEZONE || 'UTC');

function formatLocal(ts, tz = TIMEZONE) {
  const d = ts instanceof Date ? ts : new Date(ts);
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: true
  }).formatToParts(d);
  const p = Object.fromEntries(parts.map(x => [x.type, x.value]));
  return `${p.month}-${p.day}-${p.year} - ${p.hour}:${p.minute}:${p.second} ${p.dayPeriod}`;
}

function zoneLabel(tz = TIMEZONE) {
  const now = new Date();
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'shortOffset'
    }).formatToParts(now);

    const name = parts.find(p => p.type === 'timeZoneName')?.value || '';
    const utc = name.replace(/^GMT/, 'UTC');

    const m = utc.match(/^UTC([+-])(\d{1,2})(?::?(\d{2}))?$/);
    if (m) {
      const sign = m[1];
      const hh = String(m[2]).padStart(2, '0');
      const mm = String(m[3] || '00').padStart(2, '0');
      return `${tz} (UTC${sign}${hh}:${mm})`;
    }
    return `${tz} (${utc || 'UTC'})`;
  } catch {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'short'
    }).formatToParts(now);
    const abbr = parts.find(p => p.type === 'timeZoneName')?.value || tz;
    return `${tz} (${abbr})`;
  }
}

// Enhanced log sanitization function (Critical Fix 5)
function safeLogValue(value, maxLength = 100) {
  return String(value || '')
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')  // Remove all control characters
    .replace(/[ \t]{2,}/g, ' ')            // Collapse multiple spaces/tabs
    .replace(/[\r\n]/g, ' ')               // Replace newlines with spaces
    .trim()
    .substring(0, maxLength);
}

// Enhanced JSON logging with proper length handling
function safeLogJson(payload, maxLength = 500) {
  try {
    const jsonString = JSON.stringify(payload);
    return safeLogValue(jsonString, maxLength);
  } catch (e) {
    return safeLogValue(`[JSON-Error: ${e.message}] ${String(payload)}`, maxLength);
  }
}

// Enhanced sanitizeOneLine with additional protection
function sanitizeOneLine(s) {
  return safeLogValue(s, SANITIZATION_MAX_LENGTH);
}

const sanitizeLogLine = sanitizeOneLine;

// Keep all your existing functions as they are...
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

// ================== REQUEST VALIDATION MIDDLEWARE ==================
function validateBase64Url(input) {
  if (!input || typeof input !== "string") return false;

  const clean = input.split("?")[0];
  const base64UrlRegex = /^[A-Za-z0-9_-]+(?:={0,2})?$/;
  const base64AnyRegex = /^[A-Za-z0-9+/_-]+(?:={0,2})?$/;

  if (clean.length < 10) return false;
  if (/[\x00-\x20\x7F]/.test(clean)) return false;

  // Canonical current format: a single base64url payload.
  if (base64UrlRegex.test(clean)) {
    return true;
  }

  // Legacy format still used by older links:
  // <cipher(base64url)><delimiter><email(base64/base64url)>
  const { mainPart, emailPart, delimUsed } = splitCipherAndEmail(
    clean,
    decodeB64urlLoose,
    isLikelyEmail
  );

  if (!delimUsed) return false;
  if (!base64UrlRegex.test(mainPart)) return false;
  if (!emailPart || emailPart.length < 4) return false;

  // Accept legacy rhs formats that splitCipherAndEmail already recognizes:
  // - base64/base64url encoded email
  // - raw or URL-encoded email (e.g. alice%40example.com)
  if (base64AnyRegex.test(emailPart)) return true;

  const decodedEmail = safeDecode(String(emailPart)).trim();
  if (decodedEmail && isLikelyEmail(decodedEmail)) return true;

  if (isLikelyEmail(String(emailPart).trim())) return true;

  return false;
}

function validateRedirectParams(req) {
  const errors = [];

  if (req.path === "/r" || req.path.startsWith("/r/")) {
    const baseString = safeDecode(String(req.query.d || req.params.data || ""));

    if (!baseString) {
      errors.push("Missing required parameter: d");
    } else if (!validateBase64Url(baseString)) {
      errors.push("Invalid data format: must be valid base64url");

      if (baseString.length > 1000) {
        addLog(`[VALIDATION] Oversized payload ip=${safeLogValue(getClientIp(req))} len=${baseString.length}`);
      }
    }
  }

  const suspiciousParams = ["javascript:", "data:", "vbscript:", "alert("];
  for (const [key, value] of Object.entries(req.query || {})) {
    if (typeof value === "string") {
      for (const suspicious of suspiciousParams) {
        if (value.toLowerCase().includes(suspicious)) {
          errors.push(`Suspicious value in parameter ${key}`);
          break;
        }
      }
    }
  }

  // Catch-all route hardening: reject obvious scanner paths early so they do not
  // enter challenge flow/log spam loops.
  if (req.path !== "/" && req.path !== "/r" && !req.path.startsWith("/e/")) {
    const candidate = safeDecode(String((req.originalUrl || "").slice(1).split("?")[0] || ""));
    if (!candidate || !validateBase64Url(candidate)) {
      errors.push("Invalid catch-all path: expected encoded redirect payload");
    }
  }

  return errors;
}

function validateRedirectRequest(req, res, next) {
  const skipPaths = [
    "/health", "/view-log", "/stream-log", "/geo-debug",
    "/admin/", "/__debug/", "/_debug/", "/challenge",
    "/ts-client-log", "/interstitial-human", "/favicon.ico",
    "/robots.txt", "/turnstile-sitekey", "/__hp.gif",
    "/decrypt-challenge-data", "/challenge-fragment",
    "/about", "/services", "/docs", "/status", "/contact",
    "/sitemap.xml", "/api/v1/status"
  ];

  if (skipPaths.some(path => req.path.startsWith(path))) {
    return next();
  }

  if (hasInterstitialBypass(req)) {
    return next();
  }

  const errors = validateRedirectParams(req);
  if (errors.length > 0) {
    const ip = getClientIp(req);
    const ua = req.get("user-agent") || "";
    const onlyCatchAllValidationError =
      errors.length === 1 && errors[0] === "Invalid catch-all path: expected encoded redirect payload";

    if (onlyCatchAllValidationError) {
      // Expected behavior for noisy scanner paths: log the first hit immediately
      // for visibility, then aggregate subsequent hits per-IP into periodic
      // [AGG:VALIDATION-FAILED] summary lines.
      const shouldLog = aggregatePerIpEvent("VALIDATION-FAILED", {
        ip,
        reason: "invalid_catch_all_path"
      });

      if (shouldLog) {
        addLog(`[VALIDATION-FAILED] ip=${safeLogValue(ip)} path=${req.path} errors=${errors.join(", ")} ua="${safeLogValue(ua.slice(0, 100))}"`);
      }
    } else {
      addLog(`[VALIDATION-FAILED] ip=${safeLogValue(ip)} path=${req.path} errors=${errors.join(", ")} ua="${safeLogValue(ua.slice(0, 100))}"`);
    }

    if (errors.some(e => e.includes("Suspicious"))) {
      addStrike(ip, 2);
    }

    const sendValidationError = () => {
      if (req.path === "/r" && !req.query.d) {
        return res.status(400).send("Missing required parameter: d");
      }
      if (errors.some(e => e.includes("Invalid catch-all path"))) {
        return res.status(404).send("Not Found");
      }
      return res.status(400).send("Invalid request");
    };

    if (req.path === "/r" || req.path.startsWith("/r/")) {
      return validationFailureLimiter(req, res, sendValidationError);
    }

    return sendValidationError();
  }

  next();
}

function hasCloudflareHeaders(req) {
  return Boolean(
    req.headers["cf-connecting-ip"] ||
    req.headers["cf-ray"] ||
    req.headers["cf-visitor"]
  );
}

function decodeB64Any(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64 + "===".slice((b64.length + 3) % 4);
  return Buffer.from(pad, "base64");
}

function b64ToBuf(s, flavor = 'url') {
  try {
    let normalized = s || "";
    if (flavor === 'url') {
      normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
    }
    while (normalized.length % 4) normalized += "=";
    return Buffer.from(normalized, "base64");
  } catch { return null; }
}

function b64urlToBuf(s) {
  return b64ToBuf(s, 'url');
}

function b64stdToBuf(s) {
  return b64ToBuf(s, 'std');
}

function tryBase64UrlToUtf8(s) {
  try {
    const norm = (s || "").replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(norm, "base64").toString("utf8");
  } catch { return null; }
}

function decodeB64urlLoose(s) {
  if (!s) return "";
  try {
    let u = s.replace(/-/g, '+').replace(/_/g, '/');
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {}
  try {
    let u = s;
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {}
  return "";
}

function hashFirstSeg(pathStr) {
  const decoded = safeDecode(String(pathStr || ""));
  const splitOn = ["//", "__", "--", "~~", "/"];
  let first = decoded;
  for (const d of splitOn) {
    const i = decoded.indexOf(d);
    if (i >= 0) { first = decoded.slice(0, i); break; }
  }
  return crypto.createHash("sha256").update(first).digest("base64url").slice(0, 32);
}

function isLikelyEmail(s) {
  return /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/i.test(s);
}

function maskEmail(e) {
  const [user, host=''] = e.split('@');
  const [dom, ...rest] = host.split('.');
  const u = user.length <= 2
    ? user[0] + '*'
    : user[0] + '*'.repeat(Math.max(1, user.length - 2)) + user.slice(-1);
  const d = dom ? (dom[0] + '*'.repeat(Math.max(1, dom.length - 2)) + dom.slice(-1)) : '';
  return `${u}@${[d, ...rest].join('.')}`;
}

function splitCipherAndEmail(baseString, decodeFn, isEmailFn) {
  const s = String(baseString || "");
  let mainPart = s, emailPart = "", delimUsed = "";

  function rhsDecodesToEmail(rhs) {
    if (!rhs) return { ok: false, decoded: "" };

    const cand1 = (decodeFn(rhs) || "").trim();
    if (cand1 && isEmailFn(cand1)) {
      return { ok: true, decoded: cand1, src: "b64" };
    }

    const cand2 = (safeDecode(rhs) || "").trim();
    if (cand2 && isEmailFn(cand2)) {
      return { ok: true, decoded: cand2, src: "raw" };
    }

    return { ok: false, decoded: "" };
  }

  const strongDelims = ["//","__","--","~~"];
  for (const d of strongDelims) {
    let i = s.lastIndexOf(d);
    while (i >= 0) {
      const rhs = s.slice(i + d.length);
      const chk = rhsDecodesToEmail(rhs);
      if (chk.ok) {
        mainPart = s.slice(0, i);
        emailPart = rhs;
        delimUsed = d;
        return { mainPart, emailPart, delimUsed };
      }
      i = s.lastIndexOf(d, i - 1);
    }
  }

  const j = s.lastIndexOf("/");
  if (j > 0) {
    const rhs = s.slice(j + 1);
    const chk = rhsDecodesToEmail(rhs);
    if (chk.ok) {
      mainPart = s.slice(0, j);
      emailPart = rhs;
      delimUsed = "/";
      return { mainPart, emailPart, delimUsed };
    }
  }

  return { mainPart, emailPart, delimUsed };
}

function normHost(h) {
  const raw = String(h || "").trim().toLowerCase().replace(/\.$/, "");
  if (!raw) return "";
  if (raw.startsWith("[") && raw.endsWith("]")) return raw;
  const colonCount = (raw.match(/:/g) || []).length;
  if (colonCount === 1) return raw.split(":")[0];
  return raw;
}

function normalizeSuffixPattern(value) {
  let s = String(value || "").trim().toLowerCase();
  if (!s) return null;

  let includeApex = true;
  let allowSubdomains = false;
  if (s.startsWith("*.")) {
    includeApex = false;
    allowSubdomains = true;
    s = s.slice(2);
  } else if (s.startsWith(".")) {
    includeApex = false;
    allowSubdomains = true;
    s = s.slice(1);
  }

  const suffix = normHost(s);
  if (!suffix) return null;
  return { suffix, includeApex, allowSubdomains };
}

function hostMatchesSuffix(hostname, pattern) {
  const host = normHost(hostname);
  if (!host || !pattern || !pattern.suffix) return false;
  if (host === pattern.suffix) return pattern.includeApex;
  return pattern.allowSubdomains && host.endsWith(`.${pattern.suffix}`);
}

function isHostAllowlisted(hostname) {
  return ALLOWLIST_DOMAINS.some(pattern => hostMatchesSuffix(hostname, pattern));
}

function parseMinHourToMs(v, fallbackMs) {
  const s = String(v ?? "").trim().toLowerCase();
  if (!s) return fallbackMs;
  const m = s.match(/^(\d+)\s*(m|h)?$/);
  if (!m) return fallbackMs;
  const n = parseInt(m[1], 10);
  const unit = m[2] || "m";
  const mult = unit === "h" ? 60 * 60 * 1000 : 60 * 1000;
  return n * mult;
}

function fmtDurMH(ms) {
  const minutes = Math.round(ms / 60000);
  if (minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}

function explainDecryptFailure({ tried = [], lastErr = null, segLen = 0 }) {
  const t = tried.join("|") || "none";
  const msg = (lastErr && String(lastErr.message || lastErr)) || "";

  if (/authenticate|authentic/i.test(msg)) {
    return `likely AES key mismatch (GCM auth failed); tried=${t}`;
  }
  if (/Invalid key length|Invalid key|unsupported/i.test(msg)) {
    return `server key invalid or wrong size; tried=${t}`;
  }
  if (/bad decrypt|mac check/i.test(msg)) {
    return `ciphertext/tag corrupted; tried=${t}`;
  }
  if (segLen < 40) {
    return `input too short to be a valid iv||ct||tag; tried=${t}`;
  }
  return `not a recognized encrypted format (wrong delimiter, bad base64, or truncated payload); tried=${t}`;
}

function gcmDecryptWithKey(key, iv, ct, tag) {
  const dec = crypto.createDecipheriv("aes-256-gcm", key, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]);
}

function gcmDecryptAnyKey(iv, ct, tag) {
  let lastErr = null;
  for (let i = 0; i < AES_KEYS.length; i++) {
    const key = AES_KEYS[i];
    try {
      const out = gcmDecryptWithKey(key, iv, ct, tag);
      return { buf: out, keyIndex: i, err: null };
    } catch (e) {
      lastErr = e;
    }
  }
  return { buf: null, keyIndex: -1, err: lastErr };
}

function tryDecryptAny(segment) {
  if (!segment) return { url: null, tried: [], lastErr: null };

  let s = safeDecode(segment);

  const tried = [];
  let lastErr = null;

  if (s.includes(':')) {
    const parts = s.split(':');
    if (parts.length === 3) {
      for (const toBuf of [b64urlToBuf, b64stdToBuf]) {
        const flavor = toBuf === b64urlToBuf ? "url" : "std";
        tried.push(`colon-${flavor}`);
        const iv = toBuf(parts[0]), ct = toBuf(parts[1]), tag = toBuf(parts[2]);
        if (iv && ct && tag && iv.length >= 12 && tag.length === 16) {
          const r = gcmDecryptAnyKey(iv, ct, tag);
          if (r.buf) return { url: r.buf.toString("utf8"), tried, lastErr: null };
          lastErr = r.err || lastErr;
        }
      }
    }
  }

  for (const toBuf of [b64urlToBuf, b64stdToBuf]) {
    const flavor = toBuf === b64urlToBuf ? "url" : "std";
    tried.push(`single-${flavor}`);
    const buf = toBuf(s);
    if (buf && buf.length > 28) {
      for (const ivLen of [12, 16]) {
        if (buf.length > (ivLen + 16)) {
          const iv = buf.slice(0, ivLen), ct = buf.slice(ivLen, -16), tag = buf.slice(-16);
          const r = gcmDecryptAnyKey(iv, ct, tag);
          if (r.buf) return { url: r.buf.toString("utf8"), tried, lastErr: null };
          lastErr = r.err || lastErr;
        }
      }
    }
  }

  const maybe = tryBase64UrlToUtf8(s) || (b64stdToBuf(s)?.toString('utf8'));
  if (maybe && /^https?:\/\//i.test(maybe)) {
    tried.push("plain-b64-url");
    return { url: maybe, tried, lastErr: null };
  }

  return { url: null, tried, lastErr };
}

function bruteSplitDecryptFull(s){
  const minPrefix = Math.max(40, Math.floor(s.length * BRUTE_FORCE_MIN_RATIO));
  for (let k = s.length; k >= minPrefix; k--) {
    const prefix = s.slice(0, k);
    const got = tryDecryptAny(prefix);
    if (got && got.url && /^https?:\/\//i.test(got.url)) {
      const rest = s.slice(k);
      let emailRaw = rest;
      const j = rest.lastIndexOf('/');
      if (j >= 0) emailRaw = rest.slice(j+1);
      return { url: got.url, emailRaw, kTried: k };
    }
  }
  return null;
}

// ================== LOGGING SYSTEM ==================
const LOG_TO_FILE   = process.env.LOG_TO_FILE === "1";
const LOG_FILE      = process.env.LOG_FILE || path.join(process.cwd(), "visitors.log");
const MAX_LOG_LINES = parseInt(process.env.MAX_LOG_LINES || "2000", 10);
const BACKLOG_ON_CONNECT = parseInt(process.env.BACKLOG_ON_CONNECT || "200", 10);

const LOGS = [];
const LOG_IDS = [];
let LOG_SEQ = 0;
const LOG_LISTENERS = new Set();

const AGG_WINDOW_MS = parseInt(process.env.LOG_AGG_WINDOW_MS || "60000", 10);
const AGG_FLUSH_MS = parseInt(process.env.LOG_AGG_FLUSH_MS || "15000", 10);
const logAggregation = new Map();

function aggregatePerIpEvent(eventKey, details = {}) {
  const ip = safeLogValue(details.ip || "unknown", 80);
  const key = `${eventKey}:${ip}`;
  const now = Date.now();
  const st = logAggregation.get(key);

  if (!st || now > st.windowStart + AGG_WINDOW_MS) {
    logAggregation.set(key, {
      count: 1,
      windowStart: now,
      lastDetails: details
    });
    return true;
  }

  st.count += 1;
  st.lastDetails = details;
  logAggregation.set(key, st);
  return false;
}

function flushAggregatedLogs(now = Date.now()) {
  for (const [key, st] of logAggregation.entries()) {
    if (now < st.windowStart + AGG_WINDOW_MS) continue;
    if (st.count > 1) {
      const [eventKey] = key.split(":");
      const ctry = st.lastDetails.country ? ` country=${safeLogValue(st.lastDetails.country, 8)}` : "";
      const reason = st.lastDetails.reason ? ` reason=${safeLogValue(st.lastDetails.reason, 80)}` : "";
      addLog(`[AGG:${eventKey}] blocked=${st.count} ip=${safeLogValue(st.lastDetails.ip || "unknown", 80)} window=${Math.round(AGG_WINDOW_MS / 1000)}s${ctry}${reason}`);
      addSpacer();
    }
    logAggregation.delete(key);
  }
}

function sseSend(res, text, id) {
  if (id != null) res.write(`id: ${id}\n`);
  String(text).split(/\r?\n/).forEach(line => {
    res.write(`data: ${line}\n`);
  });
  res.write('\n');
}

function broadcastLog(line, id) {
  for (const res of LOG_LISTENERS) {
    try { sseSend(res, line, id); } catch {}
  }
}

function addLog(message) {
  const now = new Date();
  const tsLocal = formatLocal(now);

  const parts = String(message).replace(/\r\n/g, "\n").split("\n");

  for (const raw of parts) {
    const line = sanitizeOneLine(raw);
    const entry = `[${tsLocal}] ${line}`;
    const id = ++LOG_SEQ;

    console.log(entry);

    LOGS.push(entry);
    LOG_IDS.push(id);
    if (LOGS.length > MAX_LOG_LINES) { LOGS.shift(); LOG_IDS.shift(); }

    broadcastLog(entry, id);
    if (LOG_TO_FILE) { try { fs.appendFileSync(LOG_FILE, entry + "\n"); } catch {} }
  }
}

function addSpacer() {
  console.log("");
  const id = ++LOG_SEQ;
  LOGS.push("");
  LOG_IDS.push(id);
  if (LOG_TO_FILE) { try { fs.appendFileSync(LOG_FILE, "\n"); } catch {} }
  broadcastLog("", id);
}

// ================== SECURITY & RATE LIMITING ==================
const RATE_CAPACITY = parseInt(process.env.RATE_CAPACITY || "5", 10);
const RATE_WINDOW_SECONDS = parseInt(process.env.RATE_WINDOW_SECONDS || "600", 10);
const RATE_PER_MS = RATE_CAPACITY / (RATE_WINDOW_SECONDS*1000);
const inMemBuckets = new Map();

function inMemTokenBucket(key, now) {
  let st = inMemBuckets.get(key); if (!st) st = { tokens: RATE_CAPACITY, ts: now };
  if (now > st.ts) { const d=now-st.ts; st.tokens = Math.min(RATE_CAPACITY, st.tokens + d*RATE_PER_MS); st.ts=now; }
  let allowed=false, retryAfterMs=0;
  if (st.tokens>=1){ st.tokens-=1; allowed=true; } else { retryAfterMs = Math.ceil((1-st.tokens)/RATE_PER_MS); }
  inMemBuckets.set(key, st);
  return { allowed, retryAfterMs };
}

// Helper function to sanitize IP for use as Map keys
function sanitizeIpForKey(ip) {
  if (!ip || ip === 'unknown' || ip === '') {
    // Use a stable key to avoid bucket bypass while grouping unknown IPs safely
    return 'invalid_unknown';
  }
  
  // Basic IP format validation - if it looks like a valid IP, use it as-is
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]+$/.test(ip)) {
    return ip;
  }
  
  // For malformed IPs, create a deterministic sanitized key
  return `malformed_${crypto.createHash('sha256').update(String(ip)).digest('base64url').slice(0, 16)}`;
}

async function isRateLimited(ip) {
  const safeIp = sanitizeIpForKey(ip);
  const { allowed, retryAfterMs } = inMemTokenBucket(`rl:${safeIp}`, Date.now());
  return { limited: !allowed, retryAfterMs };
}

const BAN_TTL_SEC       = parseInt(process.env.BAN_TTL_SEC || "3600", 10);
const BAN_AFTER_STRIKES = parseInt(process.env.BAN_AFTER_STRIKES || "4", 10);
const STRIKE_WEIGHT_HP  = parseInt(process.env.STRIKE_WEIGHT_HP || "3", 10);
const inMemBans = new Map();
const inMemStrikes = new Map();

const DENY_CACHE_TTL_SEC = parseInt(process.env.DENY_CACHE_TTL_SEC || "300", 10);
const inMemDenyCache = new Map();

function addDenyCache(ip, reason, ttlSec = DENY_CACHE_TTL_SEC) {
  const safeIp = sanitizeIpForKey(ip);
  inMemDenyCache.set(safeIp, { until: Date.now() + (ttlSec * 1000), reason: safeLogValue(reason, 32) });
}

function getDenyCache(ip) {
  const safeIp = sanitizeIpForKey(ip);
  const st = inMemDenyCache.get(safeIp);
  if (!st) return null;
  if (Date.now() > st.until) {
    inMemDenyCache.delete(safeIp);
    return null;
  }
  return st;
}

const ALERT_WINDOW_MS = parseInt(process.env.ALERT_WINDOW_MS || "600000", 10);
const ALERT_UNIQUE_OFFENDER_THRESHOLD = parseInt(process.env.ALERT_UNIQUE_OFFENDER_THRESHOLD || "25", 10);
const ALERT_COUNTRY_SPIKE_THRESHOLD = parseInt(process.env.ALERT_COUNTRY_SPIKE_THRESHOLD || "20", 10);
const ALERT_ASN_SPIKE_THRESHOLD = parseInt(process.env.ALERT_ASN_SPIKE_THRESHOLD || "20", 10);
const alertState = {
  offenders: new Map(),
  countries: new Map(),
  asns: new Map(),
  challengeBypass: new Map(),
  dedupe: new Map()
};

function incrementWindowCounter(map, key, now = Date.now()) {
  const st = map.get(key);
  if (!st || now - st.windowStart > ALERT_WINDOW_MS) {
    map.set(key, { count: 1, windowStart: now });
    return 1;
  }
  st.count += 1;
  map.set(key, st);
  return st.count;
}

function pruneAlertMap(map, now, windowMs = ALERT_WINDOW_MS) {
  for (const [k, ts] of map.entries()) {
    if (now - ts > windowMs) map.delete(k);
  }
}

function pruneWindowCounterMap(map, now, windowMs = ALERT_WINDOW_MS) {
  for (const [k, st] of map.entries()) {
    if (!st || typeof st.windowStart !== "number" || now - st.windowStart > windowMs) {
      map.delete(k);
    }
  }
}

function pruneAlertState(now = Date.now()) {
  pruneAlertMap(alertState.offenders, now);
  pruneAlertMap(alertState.challengeBypass, now);
  pruneAlertMap(alertState.dedupe, now, ALERT_WINDOW_MS * 2);
  pruneWindowCounterMap(alertState.countries, now);
  pruneWindowCounterMap(alertState.asns, now);
}

function shouldEmitAlert(key, now = Date.now()) {
  const last = alertState.dedupe.get(key);
  if (last && (now - last) < ALERT_WINDOW_MS) return false;
  alertState.dedupe.set(key, now);
  return true;
}

function recordOffenderSignals(req, context = {}) {
  const now = Date.now();
  const ip = sanitizeIpForKey(getClientIp(req));
  const country = context.country || getCountry(req) || "--";
  const asn = context.asn || getASN(req) || "--";

  alertState.offenders.set(ip, now);
  const countryHits = incrementWindowCounter(alertState.countries, country, now);
  const asnHits = incrementWindowCounter(alertState.asns, asn, now);

  pruneAlertState(now);

  if (alertState.offenders.size >= ALERT_UNIQUE_OFFENDER_THRESHOLD && shouldEmitAlert("unique-offenders", now)) {
    addLog(`[ALERT] unique offender spike offenders=${alertState.offenders.size} window=${Math.round(ALERT_WINDOW_MS / 60000)}m`);
    addSpacer();
  }

  if (country !== "--" && countryHits >= ALERT_COUNTRY_SPIKE_THRESHOLD && shouldEmitAlert(`country-${country}`, now)) {
    addLog(`[ALERT] country spike country=${safeLogValue(country, 8)} hits=${countryHits} window=${Math.round(ALERT_WINDOW_MS / 60000)}m`);
    addSpacer();
  }

  if (asn !== "--" && asnHits >= ALERT_ASN_SPIKE_THRESHOLD && shouldEmitAlert(`asn-${asn}`, now)) {
    addLog(`[ALERT] asn spike asn=${safeLogValue(asn, 32)} hits=${asnHits} window=${Math.round(ALERT_WINDOW_MS / 60000)}m`);
    addSpacer();
  }
}

function recordChallengeBypassAttempt(req, reason) {
  const now = Date.now();
  const ip = sanitizeIpForKey(getClientIp(req));
  alertState.challengeBypass.set(ip, now);
  pruneAlertState(now);
  if (shouldEmitAlert(`challenge-bypass-${ip}`, now)) {
    addLog(`[ALERT] challenge bypass attempt ip=${safeLogValue(getClientIp(req), 80)} reason=${safeLogValue(reason, 60)} path=${safeLogValue(req.path, 120)}`);
    addSpacer();
  }
}

function createChallengeRedirect(baseString, req, reason, extras = {}) {
  const ip = getClientIp(req);
  const token = createChallengeToken(baseString, req, reason || "auth_required");
  const hostParam = extras.host ? `&host=${encodeURIComponent(extras.host)}` : "";
  const reasonParam = reason ? `&cr=${encodeURIComponent(sanitizeChallengeReason(reason))}` : "";
  addLog(`[CHALLENGE] tokenized redirect ip=${safeLogValue(ip)} reason=${safeLogValue(reason || "auth_required", 40)} len=${baseString.length}`);
  return `/challenge?ct=${encodeURIComponent(token)}${reasonParam}${hostParam}`;
}

function isBanned(ip) {
  const safeIp = sanitizeIpForKey(ip);
  const until = inMemBans.get(safeIp);
  if (!until) return false;
  if (Date.now() > until) { inMemBans.delete(safeIp); return false; }
  return true;
}

function addStrike(ip, weight=1){
  const safeIp = sanitizeIpForKey(ip);
  const c = (inMemStrikes.get(safeIp) || 0) + weight;
  inMemStrikes.set(safeIp, c);
  if (c >= BAN_AFTER_STRIKES) {
    inMemBans.set(safeIp, Date.now() + BAN_TTL_SEC*1000);
    inMemStrikes.delete(safeIp);
    addLog(`[BAN] ip=${safeLogValue(ip)} for ${BAN_TTL_SEC}s`);
  addSpacer();
  }
}

function makeIpLimiter({ capacity, windowSec, keyPrefix }) {
  const RATE_PER_MS_LOCAL = capacity / (windowSec * 1000);
  const buckets = new Map();
  return function ipLimit(req, res, next) {
    if (isAdmin?.(req) || isAdminSSE?.(req)) return next();
    const ip = getClientIp(req) || "unknown";
    const safeIp = sanitizeIpForKey(ip);
    const key = `${keyPrefix}:${safeIp}`;
    const now = Date.now();
    let st = buckets.get(key);
    if (!st) st = { tokens: capacity, ts: now };
    if (now > st.ts) {
      const d = now - st.ts;
      st.tokens = Math.min(capacity, st.tokens + d * RATE_PER_MS_LOCAL);
      st.ts = now;
    }
    if (st.tokens >= 1) {
      st.tokens -= 1;
      buckets.set(key, st);
      return next();
    }
    const retryAfterMs = Math.ceil((1 - st.tokens) / RATE_PER_MS_LOCAL);
    res.setHeader("Retry-After", Math.ceil(retryAfterMs / 1000));
    addLog(`[RL:${keyPrefix}] 429 ip=${safeLogValue(ip)} path=${safeLogValue(req.path)}`);
  addSpacer();
    return res.status(429).send("Too many requests");
  };
}

// ================== ADMIN AUTH ==================
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

function isAdmin(req) {
  if (!ADMIN_TOKEN) return false;
  const h = req.headers["authorization"];
  if (!h || typeof h !== "string") return false;
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  return m[1] === ADMIN_TOKEN;
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) {
    return res.status(401).type("text/plain").send("Unauthorized");
  }
  return next();
}

const EPHEMERAL_TTL_MS = 5 * 60 * 1000;
const EPHEMERAL_SECRET = process.env.ADMIN_TOKEN || "dev-secret";
const EPHEMERAL_SECRET_EFFECTIVE = (() => {
  const explicit = (process.env.EPHEMERAL_SECRET || "").trim();
  if (explicit) return explicit;

  const adminToken = (process.env.ADMIN_TOKEN || "").trim();
  if (adminToken.length >= 16) return adminToken;

  // Cluster-safe deterministic fallback derived from AES key env material.
  // This avoids cross-instance token mismatches when ADMIN_TOKEN is weak/missing.
  const aesSeed = String(process.env.AES_KEYS || process.env.AES_KEY_HEX || process.env.AES_KEY || "").trim();
  if (aesSeed) {
    const derived = crypto.createHash("sha256").update(`ephemeral:${aesSeed}`).digest("base64url");
    console.warn("⚠️ EPHEMERAL_SECRET not provided and ADMIN_TOKEN is weak/missing; deriving fallback secret from AES key material.");
    return derived;
  }

  // Last-resort per-process random fallback.
  const randomFallback = crypto.randomBytes(32).toString("base64url");
  console.warn("⚠️ EPHEMERAL_SECRET not provided and ADMIN_TOKEN/AES key are weak/missing; using process-random ephemeral secret.");
  return randomFallback;
})();

function mintEphemeralToken() {
  const exp = Date.now() + EPHEMERAL_TTL_MS;
  const msg = `sse:${exp}`;
  const sig = crypto.createHmac('sha256', EPHEMERAL_SECRET_EFFECTIVE).update(msg).digest('base64url');
  return `ts:${exp}:${sig}`;
}

function verifyEphemeralToken(tok) {
  const m = /^ts:(\d+):([A-Za-z0-9_-]+)$/.exec(tok || "");
  if (!m) return false;
  const exp = +m[1], sig = m[2];
  if (Date.now() > exp) return false;
  const msg = `sse:${exp}`;
  const expect = crypto.createHmac('sha256', EPHEMERAL_SECRET_EFFECTIVE).update(msg).digest('base64url');
  return sig === expect;
}

function isAdminSSE(req) {
  const hdr = req.headers.authorization || "";
  if (hdr.startsWith("Bearer ") && hdr.slice(7) === process.env.ADMIN_TOKEN) return true;

  const qTok = req.query.token && String(req.query.token);
  if (!qTok) return false;

  if (qTok === process.env.ADMIN_TOKEN) return true;
  return verifyEphemeralToken(qTok);
}

// ================== AES KEY MANAGEMENT ==================
const DEBUG_SHOW_KEYS_ON_START   = (process.env.DEBUG_SHOW_KEYS_ON_START || "0") === "1";
const DEBUG_ALLOW_PLAINTEXT_KEYS = (process.env.DEBUG_ALLOW_PLAINTEXT_KEYS || "0") === "1";
const EXPECT_AES_SHA256          = (process.env.AES_KEY_SHA256 || "").toLowerCase().replace(/[^0-9a-f]/g, "");

function loadKeysFromEnv() {
  const keys = [];

  const hex = (process.env.AES_KEY_HEX || "").trim();
  if (hex) {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("AES_KEY_HEX must be 64 hex chars");
    keys.push(Buffer.from(hex, "hex"));
  }

  const rawList = (process.env.AES_KEYS || process.env.AES_KEY || "")
    .split(",").map(s => s.trim()).filter(Boolean);
  for (const k of rawList) {
    if (!/^[A-Za-z0-9_-]+$/.test(k)) {
      throw new Error("AES_KEY(S) must be base64url (A–Z a–z 0–9 _ -)");
    }
    const buf = decodeB64Any(k);
    if (buf.length !== 32) throw new Error("Each AES key must decode to 32 bytes");
    keys.push(buf);
  }

  if (!keys.length) throw new Error("No AES key configured. Set AES_KEYS or AES_KEY or AES_KEY_HEX");
  return keys;
}

const AES_KEYS = loadKeysFromEnv();

if (EXPECT_AES_SHA256) {
  const got = crypto.createHash("sha256").update(AES_KEYS[0]).digest("hex");
  if (!got.startsWith(EXPECT_AES_SHA256)) {
    console.error(`[FATAL] AES key fingerprint mismatch. expected=${EXPECT_AES_SHA256.slice(0,10)}… got=${got.slice(0,10)}…`);
    process.exit(1);
  }
}

if (DEBUG_SHOW_KEYS_ON_START) {
  const raw = (process.env.AES_KEYS || process.env.AES_KEY || process.env.AES_KEY_HEX || "").trim();
  console.log("[DEBUG] AES_KEY(S) raw:", raw);
}

const LINK_HMAC_KEY = process.env.LINK_HMAC_KEY
  ? Buffer.from(process.env.LINK_HMAC_KEY, "utf8")
  : AES_KEYS[0];

function timingSafeEqualStr(a, b) {
  const aBuf = Buffer.from(String(a || ""));
  const bBuf = Buffer.from(String(b || ""));
  if (aBuf.length !== bBuf.length) return false;
  try { return crypto.timingSafeEqual(aBuf, bBuf); } catch { return false; }
}

function computeLinkHmac(url, destHost) {
  if (!url || !destHost || !LINK_HMAC_KEY) return null;
  try {
    return crypto.createHmac("sha256", LINK_HMAC_KEY)
      .update(`${destHost}|${url}`)
      .digest("base64url");
  } catch {
    return null;
  }
}

function verifyLinkHmac(url, destHost, provided) {
  const expected = computeLinkHmac(url, destHost);
  if (!expected || !provided) return { ok: false, expected };
  return { ok: timingSafeEqualStr(expected, provided), expected };
}

// ================== CHALLENGE TOKEN FUNCTIONS ==================
function hashIpForToken(ip) {
  try {
    return crypto.createHash("sha256")
      .update(String(ip || ""))
      .digest("base64")
      .slice(0, 16);
  } catch {
    return "";
  }
}

function hashUaForToken(ua) {
  try {
    return crypto.createHash("sha256")
      .update(String(ua || ""))
      .digest("base64")
      .slice(0, 16);
  } catch {
    return "";
  }
}

const CHALLENGE_REASON_MAX_LEN = 80;
function sanitizeChallengeReason(reason) {
  if (!reason) return "";
  return String(reason)
    .replace(/[^\x20-\x7E]+/g, "")
    .slice(0, CHALLENGE_REASON_MAX_LEN);
}

function createChallengeToken(nextEnc, req, reason) {
  const raw = parseInt(process.env.CHALLENGE_TOKEN_TTL_MIN || "10", 10);
  const ttlMin = Number.isFinite(raw) && raw > 0 ? raw : 10; // guard
  const exp = Date.now() + ttlMin * 60 * 1000;
  const cr = sanitizeChallengeReason(reason);

  const ip = getClientIp(req);
  const ua = req && req.get ? (req.get("user-agent") || "") : "";

  const payload = {
    next: nextEnc,
    exp,
    ts: Date.now(),
    ih: hashIpForToken(ip),
    uh: hashUaForToken(ua),
    cr: cr || undefined
  };
  const token = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto
        .createHmac("sha256", EPHEMERAL_SECRET_EFFECTIVE)
    .update(token)
    .digest("base64url");
  return `${token}.${sig}`;
}

function verifyChallengeToken(challengeToken, req) {
  if (!challengeToken || typeof challengeToken !== "string") return null;

  const parts = challengeToken.split(".");
  if (parts.length !== 2) return null;

  const [token, sig] = parts;

  const expectedSig = crypto
        .createHmac("sha256", EPHEMERAL_SECRET_EFFECTIVE)
    .update(token)
    .digest("base64url");
  if (sig !== expectedSig) return null;

  try {
    const payload = JSON.parse(Buffer.from(token, "base64url").toString());
    if (Date.now() > payload.exp) return null;

    if (payload.ih || payload.uh) {
      const ip = getClientIp(req);
      const ua = req && req.get ? (req.get("user-agent") || "") : "";
      const ihNow = hashIpForToken(ip);
      const uhNow = hashUaForToken(ua);
      if ((payload.ih && payload.ih !== ihNow) || (payload.uh && payload.uh !== uhNow)) {
        return null;
      }
    }

    return payload;
  } catch (e) {
    return null;
  }
}

function encryptChallengeData(payload) {
  const json = JSON.stringify(payload);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEYS[0], iv);
  const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, encrypted, tag]).toString('base64url');
}

function decryptChallengeData(encryptedData) {
  try {
    const buf = Buffer.from(encryptedData, 'base64url');
    const iv = buf.slice(0, 12);
    const ciphertext = buf.slice(12, -16);
    const tag = buf.slice(-16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEYS[0], iv);
    decipher.setAuthTag(tag);
    
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

// ================== CLIENT IP & GEO FUNCTIONS ==================

// Proper IP address parser that handles IPv4, IPv6, and ports correctly
function parseIpAddress(ip) {
  if (!ip || typeof ip !== 'string') return ip;
  
  // Remove any surrounding whitespace
  ip = ip.trim();
  
  // Handle IPv6 with port format: [2001:db8::1]:8080
  if (ip.startsWith('[') && ip.includes(']')) {
    const endBracket = ip.indexOf(']');
    return ip.slice(1, endBracket);
  }
  
  // Handle IPv4 with port: 192.168.1.1:8080
  if (ip.includes('.') && ip.includes(':')) {
    const lastColon = ip.lastIndexOf(':');
    // Verify it's actually a port by checking if the part after colon is numeric
    const potentialPort = ip.slice(lastColon + 1);
    if (/^\d+$/.test(potentialPort)) {
      return ip.slice(0, lastColon);
    }
  }
  
  // Plain IPv4, IPv6 without port, or unknown format
  return ip;
}

function getClientIp(req) {
  // Platform-specific headers in order of preference
  if (req.headers['x-vercel-forwarded-for']) {
    const ips = String(req.headers['x-vercel-forwarded-for']).split(',').map(ip => ip.trim());
    const clientIp = ips[0];
    if (clientIp && clientIp !== '') {
      return parseIpAddress(clientIp);
    }
  }
  
  // Netlify
  if (req.headers['x-nf-client-connection-ip']) {
    const ip = String(req.headers['x-nf-client-connection-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }
  
  // Cloudflare
  if (req.headers['cf-connecting-ip']) {
    const ip = String(req.headers['cf-connecting-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }
  
  // Render.com
  if (req.headers['x-render-ip']) {
    const ip = String(req.headers['x-render-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }
  
  // Railway
  if (req.headers['x-railway-ip']) {
    const ip = String(req.headers['x-railway-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }
  
  // Heroku, AWS ELB, Google Cloud, Azure, and most other platforms
  if (req.headers['x-forwarded-for']) {
    const ips = String(req.headers['x-forwarded-for']).split(',').map(ip => ip.trim());
    // Get the first IP that's not a known proxy IP
    for (const ip of ips) {
      if (ip && ip !== '' && !isKnownProxyIp(ip)) {
        return parseIpAddress(ip);
      }
    }
    // Fallback to first IP if all are proxy IPs
    if (ips[0] && ips[0] !== '') {
      return parseIpAddress(ips[0]);
    }
  }
  
  // Standard headers
  const standardHeaders = [
    "x-real-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "forwarded"
  ];
  
  for (const header of standardHeaders) {
    const value = req.headers[header];
    if (value) {
      let ip = String(value).trim();
      
      // Handle Forwarded header (RFC 7239)
      if (header === "forwarded") {
        const forMatch = ip.match(/for=([^,;]+)/i);
        if (forMatch) {
          ip = forMatch[1].replace(/^\[?"?'?|"?'?\]?$/g, '').trim();
        }
      }
      
      if (ip && ip !== '') {
        return parseIpAddress(ip);
      }
    }
  }
  
  // Final fallback to Express
  return parseIpAddress(req.ip || "");
}

function getDirectRemoteIp(req) {
  const remote =
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    req.ip ||
    "";
  return parseIpAddress(String(remote || "").trim());
}

function shouldTrustClientIpHeaders(req) {
  if (process.env.TRUST_CLIENT_IP_HEADERS === "1") return true;

  // If proxy trust is explicitly disabled, do not trust forwarded client-ip headers.
  if (trustProxyEffective === false) return false;

  // Cloudflare deployments can trust cf-connecting-ip only when cf context is present.
  if (req.headers["cf-connecting-ip"] && hasCloudflareHeaders(req)) return true;

  // Common managed platforms where upstream populates/normalizes forwarding headers.
  if (process.env.VERCEL || process.env.NETLIFY || process.env.RENDER || process.env.RAILWAY || process.env.HEROKU) return true;

  return false;
}

function getDenyCacheIp(req) {
  const directIp = getDirectRemoteIp(req);

  // When Express proxy trust is enabled, req.ip is already normalized through
  // trusted proxy hops and is safer than raw socket address for per-client keying.
  if (trustProxyEffective !== false) {
    const trustedReqIp = parseIpAddress(String(req.ip || "").trim());
    if (trustedReqIp) return trustedReqIp;
  }

  if (shouldTrustClientIpHeaders(req)) {
    return getClientIp(req) || directIp || "unknown";
  }
  return directIp || "unknown";
}

// Helper function to identify known proxy IPs
function isKnownProxyIp(ip) {
  const proxyRanges = [
    /^3\.\d+\.\d+\.\d+$/,  // Vercel AWS IPs
    /^54\.\d+\.\d+\.\d+$/, // AWS us-east-1
    /^52\.\d+\.\d+\.\d+$/, // AWS us-east-1
    /^34\.\d+\.\d+\.\d+$/, // Google Cloud
    /^35\.\d+\.\d+\.\d+$/, // Google Cloud
    /^13\.\d+\.\d+\.\d+$/, // AWS
    /^10\.\d+\.\d+\.\d+$/, // Private
    /^192\.168\.\d+\.\d+$/, // Private
    /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/, // Private
    /^127\.\d+\.\d+\.\d+$/, // Localhost
    /^::1$/, // IPv6 localhost
    /^f[cd][0-9a-f]{2}:/i, // IPv6 private (fc00::/7)
  ];
  
  return proxyRanges.some(pattern => pattern.test(ip));
}

function getCountry(req) {
  const h = req.headers;
  
  // Platform-specific country headers
  const countryHeaders = [
    ["x-vercel-ip-country", "vercel"],
    ["cf-ipcountry", "cloudflare"], 
    ["cf-edge-country", "cloudflare"],
    ["x-nf-country", "netlify"],
    ["x-render-country", "render"],
    ["x-railway-country", "railway"],
  ];
  
  for (const [header, platform] of countryHeaders) {
    const value = h[header];
    if (value) {
      return String(value).toUpperCase();
    }
  }
  
  // Netlify geo JSON
  if (h["x-nf-geo"]) { 
    try { 
      const geo = JSON.parse(h["x-nf-geo"]);
      if (geo.country) return String(geo.country).toUpperCase();
    } catch {} 
  }
  
  // Fly.io region (sometimes contains country)
  if (h["fly-region"]) {
    const region = String(h["fly-region"]).toLowerCase();
    // Extract country from region codes like "iad" (US), "lhr" (UK), etc.
    const regionToCountry = {
      'iad': 'US', 'atl': 'US', 'dfw': 'US', 'den': 'US', 'lax': 'US', 'mia': 'US',
      'ord': 'US', 'phx': 'US', 'qro': 'MX', 'scl': 'CL', 'bog': 'CO', 'eze': 'AR',
      'gru': 'BR', 'lhr': 'GB', 'cdg': 'FR', 'ams': 'NL', 'fra': 'DE', 'mad': 'ES',
      'waw': 'PL', 'arn': 'SE', 'nrt': 'JP', 'hkg': 'HK', 'sin': 'SG', 'bom': 'IN',
      'syd': 'AU', 'mel': 'AU'
    };
    if (regionToCountry[region]) {
      return regionToCountry[region];
    }
  }
  
  // Fallback to geoip with real client IP
  if (geoip) {
    const ip = getClientIp(req);
    if (ip && !isKnownProxyIp(ip)) {
      const lookup = geoip.lookup(ip);
      if (lookup && lookup.country) {
        return String(lookup.country).toUpperCase();
      }
    }
  }
  
  return null;
}

function getASN(req) { 
  const asnHeaders = [
    "cf-asn",
    "x-asn", 
    "x-vercel-ip-asn",
    "x-nf-asn",
    "x-render-asn"
  ];
  
  for (const header of asnHeaders) {
    const value = req.headers[header];
    if (value) {
      return String(value).toUpperCase();
    }
  }
  return null;
}

// ================== SECURITY POLICY FUNCTIONS ==================
const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const BLOCKED_ASNS      = (process.env.BLOCKED_ASNS || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const EXPECT_HOSTNAME   = process.env.TURNSTILE_EXPECT_HOSTNAME || ".test.com,test.com,sub.test.com"; // main url
const MAX_TOKEN_AGE_SEC = parseInt(process.env.TURNSTILE_MAX_TOKEN_AGE_SEC || "90", 10);
const ENFORCE_ACTION    = (process.env.TURNSTILE_ENFORCE_ACTION || "1") === "1";
const HEADLESS_BLOCK    = (process.env.HEADLESS_BLOCK || "0") === "1";
const HEADLESS_STRIKE_WEIGHT = parseInt(process.env.HEADLESS_STRIKE_WEIGHT || "3", 10);
const HEADLESS_SOFT_STRIKE   = (process.env.HEADLESS_SOFT_STRIKE || "0") === "1";

const ALLOWLIST_DOMAINS = (process.env.ALLOWLIST_DOMAINS || "test2.com,sub.test2.com") // landing
  .split(",").map(normalizeSuffixPattern).filter(Boolean);

// ================== CONFIGURATION VALIDATION ==================
const normalizeTurnstileEnv = (value) => String(value || "").trim();

function validateConfig() {
  const errors = [];
  const warnings = [];
  const isTurnstileKey = (value) => {
    const trimmed = normalizeTurnstileEnv(value);
    if (!trimmed) return false;
    return /^(?:0x)?[0-9a-zA-Z_-]{20,}$/.test(trimmed);
  };

  // Validate AES keys (extra safety; loadKeysFromEnv already enforces this)
  if (!AES_KEYS || AES_KEYS.length === 0) {
    errors.push("No AES keys configured (set AES_KEYS, AES_KEY, or AES_KEY_HEX)");
  } else {
    AES_KEYS.forEach((key, idx) => {
      if (key.length !== 32) {
        errors.push(`AES key #${idx} must be 32 bytes, got ${key.length} bytes`);
      }
    });
  }

  // Validate allowlist configuration
  if (ALLOWLIST_DOMAINS.length === 0) {
    warnings.push("No allowlist domains configured - all redirects will be blocked unless explicitly allowed");
  }

  // Validate TURNSTILE credentials format
  const turnstileSitekey = normalizeTurnstileEnv(process.env.TURNSTILE_SITEKEY);
  const turnstileSecret = normalizeTurnstileEnv(process.env.TURNSTILE_SECRET);
  if (!isTurnstileKey(turnstileSitekey)) {
    errors.push(`Invalid TURNSTILE_SITEKEY format (got: ${turnstileSitekey ? `${turnstileSitekey.slice(0, 8)}...` : "empty"})`);
  }
  if (!isTurnstileKey(turnstileSecret)) {
    errors.push(`Invalid TURNSTILE_SECRET format (got: ${turnstileSecret ? `${turnstileSecret.slice(0, 8)}...` : "empty"})`);
  }

  // Validate timezone
  const configuredTz = process.env.TIMEZONE || "UTC";
  if (safeZone(configuredTz) !== configuredTz) {
    warnings.push(`Invalid TIMEZONE: ${configuredTz}. Using UTC as fallback.`);
  }

  // Validate rate limit settings
  if (RATE_CAPACITY < 1 || RATE_CAPACITY > 1000) {
    errors.push(`RATE_CAPACITY must be between 1-1000, got ${RATE_CAPACITY}`);
  }
  if (RATE_WINDOW_SECONDS < 1 || RATE_WINDOW_SECONDS > 86400) {
    errors.push(`RATE_WINDOW_SECONDS must be between 1-86400, got ${RATE_WINDOW_SECONDS}`);
  }

  // Validate admin token
  if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16) {
    warnings.push("ADMIN_TOKEN is weak or missing. Admin endpoints may be insecure.");
  }

  // Validate INTERSTITIAL_BYPASS_SECRET
  const bypassSecret = process.env.INTERSTITIAL_BYPASS_SECRET || "";
  if (bypassSecret && bypassSecret.length < 8) {
    warnings.push("INTERSTITIAL_BYPASS_SECRET is too short (min 8 chars)");
  }

  return { errors, warnings };
}

// Run validation
const configValidation = validateConfig();
if (configValidation.errors.length > 0) {
  console.error("❌ Configuration errors:");
  configValidation.errors.forEach(err => console.error(`   ${err}`));
  if (process.env.NODE_ENV === "production") process.exit(1);
}
if (configValidation.warnings.length > 0) {
  console.warn("⚠️ Configuration warnings:");
  configValidation.warnings.forEach(warn => console.warn(`   ${warn}`));
}

// Hardening: fail fast in production if ADMIN_TOKEN is weak/missing.
if (process.env.NODE_ENV === "production" && (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16)) {
  console.error("❌ ADMIN_TOKEN must be set with at least 16 characters in production.");
  process.exit(1);
}

const EXPECT_HOSTNAME_LIST   = (EXPECT_HOSTNAME || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const EXPECT_HOSTNAME_EXACT  = new Set(EXPECT_HOSTNAME_LIST.filter(h => !h.startsWith(".")));
const EXPECT_HOSTNAME_SUFFIX = EXPECT_HOSTNAME_LIST.filter(h => h.startsWith("."));

function countryBlocked(country){
  if (!country) return false;
  if (ALLOWED_COUNTRIES.length && !ALLOWED_COUNTRIES.includes(country)) return true;
  if (BLOCKED_COUNTRIES.includes(country)) return true;
  return false;
}

function asnBlocked(asn){ return !!asn && BLOCKED_ASNS.includes(asn); }

// ================== SCANNER DETECTION ==================
const SCANNER_PATTERNS = {
  // High-signal vendor/user-agent substrings (case-insensitive)
  uaSubstrings: [
    // Microsoft / Outlook / EOP / SafeLinks
    'safelinks', 'protection.outlook.com', 'microsoft eop', 'exchange online',
    'microsoft-office', 'outlook', 'x-owa',

    // Proofpoint
    'proofpoint', 'urldefense.proofpoint.com', 'ppops-', 'tap/',

    // Mimecast
    'mimecast', 'mimecast-control-center', 'protect-us.mimecast.com',
    'protect-eu.mimecast.com', 'protect-au.mimecast.com',

    // Barracuda
    'barracuda', 'bemailhec', 'linkprotect.cudasvc.com',

    // Cisco / IronPort
    'ironport', 'cisco secure email', 'sesa.cisco',

    // Trend Micro
    'trendmicro', 'tmurl', 'tmresponse', 'deep discovery', 'ddan',

    // McAfee / Trellix / FireEye / Cloudmark
    'mcafee', 'clickprotect', 'trellix', 'fireeye', 'cloudmark',

    // Zscaler / Forcepoint / Fortinet
    'zscaler', 'zscloud', 'forcepoint', 'websense', 'fortimail', 'fortinet',

    // Google/Gmail prefetch
    'googleimageproxy', 'gmail proxy', 'google proxy',

    // Apple Mail Privacy
    'apple mail privacy', 'mailprivacy',

    // Generic
    'url defense', 'urlrewrite', 'link protect', 'linkprotect',
    'link-scanner', 'security scan', 'sandbox url'
  ],

  // Strong regex hits for vendor/rewriter signatures
  uaRegexes: [
    // Microsoft SafeLinks / EOP / Outlook apps
    /safelinks\.protection\.outlook\.com|(?:nam|eur|apc)\d+\.safelinks/i,
    /(microsoft[- ]?office|outlook|exchange).*(scan|eop)/i,
    /Microsoft[- ]?Office\/[0-9.]+/i,
    /Outlook-(?:Android|iOS)\/[0-9.]+/i,

    // Proofpoint
    /urldefense\.(proofpoint|com)/i,
    /Proofpoint(?:|-[A-Za-z]+)\/[0-9.]+/i,
    /ppops-[a-z0-9-]+/i,

    // Mimecast
    /mimecast|protect-(?:us|eu|au)\.mimecast\.com/i,

    // Barracuda
    /barracuda|bemailhec|linkprotect\.cudasvc\.com/i,

    // Cisco / IronPort
    /ironport|secure\.email|sesa\.cisco/i,

    // Trend Micro
    /trend[\s-]?micro|tmurl|tmresponse|deep\s*discovery|ddan/i,

    // McAfee / Trellix / FireEye / Cloudmark
    /mcafee|clickprotect|cp\.mcafee\.com/i,
    /trellix|fireeye|cloudmark/i,

    // Zscaler / Forcepoint / Fortinet
    /zscaler|zsgov|zscloud|zscalertwo|zscalerthree/i,
    /forcepoint|websense/i,
    /fortinet|fortimail|fortiguard/i,

    // Headless/automation (keep weight low in your scoring)
    /(headless|puppeteer|playwright|phantomjs|selenium|wdio|cypress|curl|wget|python-requests|aiohttp|okhttp|java\/|go-http)/i,
  ],

  // Header fingerprints (browser hints often missing in scanners)
  headerRules: [
    // Missing typical browser hints
    (h) => !h['accept-language'],
    (h) => !h['sec-ch-ua'],
    (h) => !h['sec-fetch-mode'],
    (h) => !h['upgrade-insecure-requests'],

    // Suspicious combinations
    (h) => (h['sec-fetch-site']||'').toLowerCase() === 'none',
    (h) => (h['sec-fetch-mode']||'').toLowerCase() === 'no-cors',

    // No cookies or referer on a deep/first touch
    (h) => !h['cookie'],
    (h) => !h['referer'],
  ],

  // Methods scanners often use for "peek" fetches
  methods: ['HEAD', 'OPTIONS'],

  // Optional infra hints if you later pipe in reverse DNS / ASN (leave empty if unused)
  rdnsHints: [
    // 'pphosted.com', 'mimecast.com', 'barracudanetworks.com'
  ],
};

const IMPERSONATE_SCANNER = (process.env.IMPERSONATE_SCANNER || "1") === "1";
const IMPERSONATE_SCANNER_STRICT = (process.env.IMPERSONATE_SCANNER_STRICT || "1") === "1";
const IMPERSONATE_MIN_CONFIDENCE = Number(process.env.IMPERSONATE_MIN_CONFIDENCE || "0.85");

const SCANNER_PROFILES = [
  {
    name: "Microsoft_SafeLinks",
    ua: "safelinks.protection.outlook.com",
    match: /(safelinks|outlook|exchange|microsoft)/i,
    responseHeaders: {
      "X-MS-Exchange-Organization-Network-Message-Id": () => crypto.randomBytes(16).toString("hex"),
      "X-MS-Exchange-Organization-AuthAs": "Internal",
      "X-MS-Exchange-Organization-AuthSource": "DB7P191MB0757.EURP191.PROD.OUTLOOK.COM"
    }
  },
  {
    name: "Proofpoint",
    ua: "urldefense.proofpoint.com",
    match: /(proofpoint|urldefense|ppops)/i,
    responseHeaders: {
      "X-Proofpoint-Version": "v3",
      "X-Proofpoint-Scan-Id": () => crypto.randomBytes(8).toString("hex")
    }
  },
  {
    name: "Mimecast",
    ua: "mimecast.com",
    match: /(mimecast)/i,
    responseHeaders: {
      "X-Mimecast-Origin": "cloud",
      "X-Mimecast-Scan-Id": () => `mc${Date.now()}${crypto.randomBytes(4).toString("hex")}`
    }
  },
  {
    name: "Barracuda",
    ua: "barracudanetworks.com",
    match: /(barracuda|cudasvc)/i,
    responseHeaders: {
      "X-Barracuda-Connect": "scanner",
      "X-Barracuda-Scan-Time": () => Date.now().toString()
    }
  }
];

const KNOWN_SCANNER_IPS = new Map();
const KNOWN_SCANNER_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const KNOWN_SCANNER_MAX = 10000;

function cleanupKnownScannerIps(now = Date.now()) {
  if (KNOWN_SCANNER_IPS.size <= KNOWN_SCANNER_MAX) return;
  const entries = [...KNOWN_SCANNER_IPS.entries()].sort((a, b) => (a[1].lastSeen || 0) - (b[1].lastSeen || 0));
  const removeCount = Math.max(1, KNOWN_SCANNER_IPS.size - KNOWN_SCANNER_MAX);
  for (let i = 0; i < removeCount; i++) KNOWN_SCANNER_IPS.delete(entries[i][0]);
  const staleBefore = now - KNOWN_SCANNER_TTL_MS;
  for (const [ip, entry] of KNOWN_SCANNER_IPS.entries()) {
    if ((entry.lastSeen || 0) < staleBefore) KNOWN_SCANNER_IPS.delete(ip);
  }
}

function recordScannerIp(ip, scannerName) {
  if (!ip) return;
  const now = Date.now();
  const existing = KNOWN_SCANNER_IPS.get(ip) || { count: 0, firstSeen: now, lastSeen: now, names: new Set() };
  existing.count += 1;
  existing.lastSeen = now;
  if (scannerName) existing.names.add(scannerName);
  KNOWN_SCANNER_IPS.set(ip, existing);
  cleanupKnownScannerIps(now);
}

function isKnownScannerIp(ip) {
  const entry = KNOWN_SCANNER_IPS.get(ip);
  if (!entry) return false;
  return entry.count > 1 && (Date.now() - entry.lastSeen) <= KNOWN_SCANNER_TTL_MS;
}

function pickScannerProfile(detection, req) {
  const detectionName = String((detection && detection.name) || "");
  const matched = String((detection && detection.matchedString) || "");
  const ua = String((req && req.get && req.get("user-agent")) || "");
  const haystack = `${detectionName} ${matched} ${ua}`;
  const profile = SCANNER_PROFILES.find((candidate) => candidate.match.test(haystack));
  return profile || SCANNER_PROFILES[0];
}

function shouldImpersonateForRequest(req, scannerResult, knownScanner) {
  if (!IMPERSONATE_SCANNER || !scannerResult || !scannerResult.isScanner) return false;

  const method = String(req.method || "GET").toUpperCase();
  const path = String(req.path || "").toLowerCase();
  const confidence = Number((scannerResult.detections && scannerResult.detections[0] && scannerResult.detections[0].confidence) || 0);
  const headers = req.headers || {};

  const scannerMethod = method === "HEAD" || method === "OPTIONS";
  const scannerLikePath = /admin|wp-|\.env|phpmyadmin|config/.test(path);
  const headerAnomaly = !headers["accept-language"] || !headers["sec-ch-ua"] || !headers["sec-fetch-site"] || headers["accept"] === "*/*";

  if (!IMPERSONATE_SCANNER_STRICT) {
    return knownScanner || scannerMethod || scannerLikePath || headerAnomaly || confidence >= 0.7;
  }

  return knownScanner || confidence >= IMPERSONATE_MIN_CONFIDENCE || (scannerMethod && (scannerLikePath || headerAnomaly));
}

function materializeProfileHeaders(profile) {
  const out = {};
  if (!profile || !profile.responseHeaders) return out;
  for (const [headerName, headerValue] of Object.entries(profile.responseHeaders)) {
    try {
      out[headerName] = typeof headerValue === "function" ? headerValue() : headerValue;
    } catch (error) {
      addLog(`[SCANNER] header build failed profile=${safeLogValue(profile.name)} header=${safeLogValue(headerName)} err=${safeLogValue(error.message)}`);
    }
  }
  return out;
}

function applyScannerProfileHeaders(res, profile) {
  if (!IMPERSONATE_SCANNER || !res || !profile || !profile.responseHeaders) return;
  const headers = materializeProfileHeaders(profile);
  for (const [headerName, headerValue] of Object.entries(headers)) {
    if (!res.getHeader(headerName)) {
      res.setHeader(headerName, headerValue);
    }
  }
  if (!res.getHeader("X-Scanner-Profile")) {
    res.setHeader("X-Scanner-Profile", profile.name);
  }
  if (!res.getHeader("X-Scanner-Processed")) {
    res.setHeader("X-Scanner-Processed", new Date().toISOString());
  }
}

async function makeScannerRequest(url, options = {}) {
  const profile = SCANNER_PROFILES[Math.floor(Math.random() * SCANNER_PROFILES.length)];
  const headers = {
    "User-Agent": profile.ua || profile.name,
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    Pragma: "no-cache",
    ...(options.headers || {})
  };

  const profileHeaders = materializeProfileHeaders(profile);
  for (const [key, value] of Object.entries(profileHeaders)) {
    headers[key] = value;
  }

  const fetchOptions = {
    method: options.method || "GET",
    redirect: options.redirect || "follow",
    headers,
    body: options.body
  };

  return fetch(url, fetchOptions);
}

// Optional compatibility response headers for scanner/interstitial responses.
// Keep this defensive and standards-based (no vendor impersonation headers).
const SCANNER_COMPAT_HEADERS_ENABLED = (process.env.SCANNER_COMPAT_HEADERS || "1") === "1";
const SCANNER_COMPAT_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
};

function applyScannerCompatHeaders(res) {
  if (!SCANNER_COMPAT_HEADERS_ENABLED || !res || typeof res.setHeader !== "function") return;
  for (const [headerName, headerValue] of Object.entries(SCANNER_COMPAT_HEADERS)) {
    if (!res.getHeader(headerName)) {
      res.setHeader(headerName, headerValue);
    }
  }
}

// --- Back-compat adapter: make SCANNER_PATTERNS iterable for older code ---
const SCANNER_PATTERNS_LIST = Array.isArray(SCANNER_PATTERNS) ? SCANNER_PATTERNS : [
  // turn each UA regex into an entry
  ...((SCANNER_PATTERNS.uaRegexes || []).map(re => ({
    pattern: re,
    name: 'UA regex',
    confidence: 0.9,
    type: 'generic'
  }))),

  // turn each UA substring into a case-insensitive regex entry
  ...((SCANNER_PATTERNS.uaSubstrings || []).map(sub => ({
    pattern: new RegExp(sub.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
    name: 'UA substring',
    confidence: 0.6,
    type: 'generic'
  }))),
];

const EXTERNAL_SCANNER_CONFIG = process.env.SCANNER_CONFIG_URL || null;
let dynamicScanners = [];

async function loadScannerPatterns() {
  if (EXTERNAL_SCANNER_CONFIG) {
    try {
      const response = await fetch(EXTERNAL_SCANNER_CONFIG);
      dynamicScanners = await response.json();
      addLog(`[SCANNER] Loaded ${dynamicScanners.length} external scanner patterns`);
    } catch (error) {
      addLog(`[SCANNER] Failed to load external patterns: ${error.message}`);
    }
  }
}

function detectScannerEnhanced(req) {
  const ua = (req.get("user-agent") || "").toLowerCase();
  const ip = getClientIp(req);
  
  let detected = [];
  const allPatterns = [...SCANNER_PATTERNS_LIST, ...dynamicScanners];
  
  for (const scanner of allPatterns) {
    if (scanner.pattern.test(ua)) {
      detected.push({
        ...scanner,
        matchedString: ua.match(scanner.pattern)[0],
        ip: ip
      });
    }
  }
  
  return detected.sort((a, b) => b.confidence - a.confidence);
}

const SCANNER_STATS = { total: 0, byReason: Object.create(null), byUA: Object.create(null) };

function computeScannerStatsFromLogs() {
  const byReason = Object.create(null);
  const byUA = Object.create(null);
  let total = 0;

  const logLines = Array.isArray(LOGS) ? LOGS : [];
  for (const line of logLines) {
    if (!line || typeof line !== "string") continue;
    if (!line.includes("[SCANNER] 200 interstitial")) continue;

    total += 1;

    let reason = "unknown";
    const rPos = line.indexOf(" reason=");
    if (rPos >= 0) {
      let tail = line.slice(rPos + 8);
      const nPos = tail.indexOf(" nextLen=");
      if (nPos >= 0) tail = tail.slice(0, nPos);
      reason = tail.trim() || "unknown";
    }
    byReason[reason] = (byReason[reason] || 0) + 1;

    let uaKey = "(empty)";
    const uPos = line.indexOf(" uaKey=");
    if (uPos >= 0) {
      let tail = line.slice(uPos + 7);
      const sp = tail.indexOf(" ");
      if (sp >= 0) tail = tail.slice(0, sp);
      uaKey = tail.trim() || "(empty)";
    }
    byUA[uaKey] = (byUA[uaKey] || 0) + 1;
  }

  SCANNER_STATS.total = total;
  SCANNER_STATS.byReason = byReason;
  SCANNER_STATS.byUA = byUA;
  return SCANNER_STATS;
}

function hashUAForStats(uaRaw) {
  try {
    const ua = (uaRaw || "").toString();
    return crypto.createHash("sha256").update(ua).digest("hex").slice(0, 8);
  } catch {
    return "na";
  }
}

// ================== ENHANCED BEHAVIORAL SCANNER DETECTION ==================
const BEHAVIORAL_CONFIG = {
  historyTtlMs: 10 * 60 * 1000,
  maxHistoryPerIp: 50,
  maxIpsBeforeCleanup: 10000,
  cleanupIntervalMs: 5 * 60 * 1000,
  rapidFireWindowMs: 1000,
  recentWindowMs: 5000,
  minBehaviorScoreToFlag: 0.8
};

const BEHAVIORAL_PATTERNS = {
  suspiciousTiming: () => {
    const now = new Date();
    const second = now.getSeconds();
    const minute = now.getMinutes();

    // Scanners often hit at exact intervals
    return (second === 0 || second === 30) && (minute % 5 === 0);
  },

  headerAnomalies: (req) => {
    const headers = req.headers;
    const anomalies = [];

    // Missing typical browser headers
    if (!headers["accept-language"]) anomalies.push("no_accept_language");
    if (!headers["accept-encoding"]) anomalies.push("no_accept_encoding");
    if (headers["accept"] === "*/*") anomalies.push("wildcard_accept");

    // Suspicious header combinations
    if (headers["sec-fetch-site"] === "none" && !headers["referer"]) {
      anomalies.push("no_referer_with_cross_site");
    }
    if (headers["sec-fetch-mode"] === "no-cors" && req.method === "GET") {
      anomalies.push("no_cors_get");
    }

    return anomalies;
  }
};

const REQUEST_HISTORY = new Map();

function cleanupRequestHistory(now) {
  for (const [key, entries] of REQUEST_HISTORY.entries()) {
    if (!entries.length || now - entries[entries.length - 1].timestamp > BEHAVIORAL_CONFIG.historyTtlMs) {
      REQUEST_HISTORY.delete(key);
    }
  }
}

if (BEHAVIORAL_CONFIG.cleanupIntervalMs > 0) {
  const interval = setInterval(() => cleanupRequestHistory(Date.now()), BEHAVIORAL_CONFIG.cleanupIntervalMs);
  if (typeof interval.unref === "function") interval.unref();
}

function trackRequestForBehavior(req) {
  const ip = getClientIp(req);
  const now = Date.now();

  if (!REQUEST_HISTORY.has(ip)) {
    REQUEST_HISTORY.set(ip, []);
  }

  const history = REQUEST_HISTORY.get(ip);
  history.push({ timestamp: now, path: req.path, method: req.method });

  // Clean old entries
  const cutoff = now - BEHAVIORAL_CONFIG.historyTtlMs;
  const freshHistory = history.filter((entry) => entry.timestamp > cutoff);
  REQUEST_HISTORY.set(ip, freshHistory);

  // Cap the history size
  if (freshHistory.length > BEHAVIORAL_CONFIG.maxHistoryPerIp) {
    REQUEST_HISTORY.set(ip, freshHistory.slice(-BEHAVIORAL_CONFIG.maxHistoryPerIp));
  }

  // Periodically clean up old IPs
  if (REQUEST_HISTORY.size > BEHAVIORAL_CONFIG.maxIpsBeforeCleanup) {
    cleanupRequestHistory(now);
  }

  return freshHistory;
}

function detectBehavioralPatterns(req, history) {
  const patterns = [];
  const now = Date.now();
  const recent = history.filter((entry) => entry.timestamp > now - BEHAVIORAL_CONFIG.recentWindowMs);
  const recentRapid = history.filter(
    (entry) => entry.timestamp > now - BEHAVIORAL_CONFIG.rapidFireWindowMs
  );

  // Check for rapid-fire requests
  if (recentRapid.length >= 3) {
    const timeSpan = recentRapid[recentRapid.length - 1].timestamp - recentRapid[0].timestamp || 1;
    patterns.push({
      type: "rapid_fire",
      weight: 0.6,
      rate: (recentRapid.length / (timeSpan / 1000)).toFixed(1)
    });
  }

  // Check for repetitive path access (crawling)
  if (recent.length >= 5) {
    const uniquePaths = new Set(recent.map((entry) => entry.path));
    if (uniquePaths.size >= 3 && uniquePaths.size / recent.length > 0.8) {
      patterns.push({
        type: "path_crawling",
        weight: 0.4,
        uniquePaths: uniquePaths.size
      });
    }
  }

  // Check timing anomalies
  if (BEHAVIORAL_PATTERNS.suspiciousTiming(req)) {
    patterns.push({ type: "suspicious_timing", weight: 0.2 });
  }

  // Check header anomalies
  const anomalies = BEHAVIORAL_PATTERNS.headerAnomalies(req);
  if (anomalies.length >= 2) {
    patterns.push({ type: "header_anomalies", weight: 0.3, anomalies });
  }

  return patterns;
}

function scoreBehavioralPatterns(patterns) {
  const score = patterns.reduce((total, pattern) => total + (pattern.weight || 0), 0);
  const hardCount = patterns.filter((pattern) => pattern.type === "rapid_fire").length;
  return { score, hardCount };
}

// Enhanced scanner detection wrapper
function detectScannerEnhancedWithBehavior(req) {
  // Existing detection
  const scannerDetections = detectScannerEnhanced(req);

  // Add behavioral analysis
  const history = trackRequestForBehavior(req);
  const behavioralPatterns = detectBehavioralPatterns(req, history);
  const { score: behaviorScore, hardCount } = scoreBehavioralPatterns(behavioralPatterns);

  // Combine results
  const combinedDetection = [...scannerDetections];

  if (
    behavioralPatterns.length >= 2 ||
    (hardCount > 0 && behaviorScore >= BEHAVIORAL_CONFIG.minBehaviorScoreToFlag)
  ) {
    const confidence = Math.min(0.9, 0.2 + behaviorScore);
    combinedDetection.push({
      name: "Behavioral Pattern",
      type: "behavioral",
      confidence,
      patterns: behavioralPatterns,
      matchedString: behavioralPatterns.map((pattern) => pattern.type).join(", ")
    });
  }

  const ordered = combinedDetection.sort((a, b) => (b.confidence || 0.5) - (a.confidence || 0.5));

  // Score the detection
  const totalScore = ordered.reduce((score, detection) => {
    return score + (detection.confidence || 0.5);
  }, 0);

  const hasSignatureMatch = scannerDetections.length > 0;
  const isScanner = hasSignatureMatch || (totalScore >= 1.2 && ordered.length > 0);

  return {
    detections: ordered,
    behavioralPatterns,
    totalScore,
    isScanner,
    requestCount: history.length
  };
}

function buildScannerInterstitialContext(req, fallbackReason = "Known scanner UA") {
  const scannerResult = detectScannerEnhancedWithBehavior(req);
  if (!scannerResult || !scannerResult.isScanner) {
    return { scannerReason: fallbackReason, scannerProfile: null };
  }

  const detections = scannerResult.detections || [];
  const topDetection = detections[0] || { name: fallbackReason, confidence: 0.5 };
  const ip = getClientIp(req);

  recordScannerIp(ip, topDetection.name);
  const knownScanner = isKnownScannerIp(ip);
  const shouldImpersonate = shouldImpersonateForRequest(req, scannerResult, knownScanner);

  return {
    scannerReason: shouldImpersonate ? "Known scanner fingerprint" : (topDetection.name || fallbackReason),
    scannerProfile: shouldImpersonate ? pickScannerProfile(topDetection, req) : null
  };
}

function logScannerHit(req, reason, nextEnc) {
  const ip   = getClientIp(req);
  const ua   = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
  const path = (req.originalUrl || req.path || "").slice(0, PATH_TRUNCATE_LENGTH);
  const ref  = (req.get("referer") || req.get("referrer") || "").slice(0, REFERER_TRUNCATE_LENGTH);
  const acc  = (req.get("accept") || "").slice(0, ACCEPT_TRUNCATE_LENGTH);

  SCANNER_STATS.total++;
  SCANNER_STATS.byReason[reason] = (SCANNER_STATS.byReason[reason] || 0) + 1;
  const uaKey = ua.toLowerCase().split(/[;\s]/)[0] || "(empty)";
  SCANNER_STATS.byUA[uaKey] = (SCANNER_STATS.byUA[uaKey] || 0) + 1;

  const uaHash = hashUAForStats(ua);
  const geo = "-";
  const asn = "-";

  addLog(
    `[SCANNER] 200 interstitial ip=${safeLogValue(ip)} geo=${safeLogValue(geo)} asn=${safeLogValue(
      asn
    )} uaKey=${safeLogValue(uaKey)} uaHash=${safeLogValue(uaHash)} path=${safeLogValue(
      path
    )} ref=${safeLogValue(ref)} accept=${safeLogValue(acc)} reason=${safeLogValue(
      reason
    )} nextLen=${(nextEnc || "").length}`
  );
  addSpacer();
}

// ================== HEADLESS / PREFETCH DETECTION ==================
const UA_HEADLESS_MARKS = [
  "headless","puppeteer","playwright","phantomjs","selenium","wdio","cypress",
  "curl","wget","python-requests","httpclient","okhttp","java","go-http-client",
  "libwww","aiohttp","node-fetch","powershell"
];
const SUSPICIOUS_HEADERS = [
  "x-puppeteer","x-headless-browser","x-headless","x-should-not-exist",
  "x-playwright","x-automation","x-bot"
];

function headlessSuspicion(req){
  const reasons = [];
  const hard = [];
  const soft = [];

  const uaRaw = req.get("user-agent") || "";
  const ua = uaRaw.toLowerCase();

  const isChromiumUA = /\b(Chrome|CriOS|Edg|OPR|Brave)\b/i.test(uaRaw) && !/\bMobile Safari\b/i.test(uaRaw);
  const isSafariUA   = /\bSafari\/\d+/i.test(uaRaw) && !/\b(Chrome|CriOS)\/\d+/i.test(uaRaw);
  const isFirefoxUA  = /\bFirefox\/\d+/i.test(uaRaw);

  const expect = {
    clientHints: isChromiumUA,
    fetchMeta:   isChromiumUA
  };

  for (const m of UA_HEADLESS_MARKS) {
    if (ua.includes(m)) { reasons.push("ua:" + m); hard.push("ua:" + m); break; }
  }
  for (const h of SUSPICIOUS_HEADERS) {
    if (req.headers[h]) { reasons.push("hdr:" + h); hard.push("hdr:" + h); }
  }

  if (!req.get("accept-language")) { reasons.push("missing:accept-language"); soft.push("missing:accept-language"); }

  if (expect.clientHints && !req.get("sec-ch-ua")) {
    reasons.push("missing:sec-ch-ua"); soft.push("missing:sec-ch-ua");
  }
  if (expect.fetchMeta && !req.get("sec-fetch-site")) {
    reasons.push("missing:sec-fetch-site"); soft.push("missing:sec-fetch-site");
  }

  const fetchSite = (req.get("sec-fetch-site") || "").toLowerCase();
  const fetchMode = (req.get("sec-fetch-mode") || "").toLowerCase();
  const fetchDest = (req.get("sec-fetch-dest") || "").toLowerCase();

  if (fetchMode && fetchMode !== "navigate" && fetchMode !== "document") {
    reasons.push("mode:" + fetchMode); soft.push("mode:" + fetchMode);
  }
  if (fetchDest && fetchDest !== "document" && fetchDest !== "empty") {
    reasons.push("dest:" + fetchDest); soft.push("dest:" + fetchDest);
  }

  const accept = req.get("accept") || "";
  if (accept && !/text\/html|application\/xhtml\+xml/i.test(accept)) {
    reasons.push("accept-not-html"); hard.push("accept-not-html");
  }

  return {
    suspicious: reasons.length > 0,
    reasons,
    hardCount: hard.length,
    softCount: soft.length,
    isSafariUA,
    isFirefoxUA,
    isChromiumUA
  };
}

// ================== TURNSTILE FUNCTIONS ==================
const TURNSTILE_SITEKEY = normalizeTurnstileEnv(process.env.TURNSTILE_SITEKEY);
const TURNSTILE_SECRET  = normalizeTurnstileEnv(process.env.TURNSTILE_SECRET);
const TURNSTILE_ORIGIN  = "https://challenges.cloudflare.com";
if (!TURNSTILE_SITEKEY || !TURNSTILE_SECRET) {
  console.error("❌ TURNSTILE_SITEKEY and TURNSTILE_SECRET must be set.");
  process.exit(1);
}

async function verifyTurnstileToken(token, remoteip, expected) {
  if (!TURNSTILE_SECRET || !token) return { ok:false, reason:"missing" };
  try {
    const resp = await fetch(TURNSTILE_ORIGIN + "/turnstile/v0/siteverify", {
      method:"POST",
      headers:{ "Content-Type":"application/x-www-form-urlencoded" },
      body:new URLSearchParams({ secret:TURNSTILE_SECRET, response:token, remoteip:remoteip||"" })
    });
    const data = await resp.json();

    if (!data.success) {
      addLog("[TS] verify failed codes=" + JSON.stringify(data["error-codes"] || []));
      return { ok:false, reason:"not_success", data };
    }

    if (ENFORCE_ACTION && expected?.action && data.action !== expected.action)
      return { ok:false, reason:"bad_action", data };

    if (expected?.linkHash) {
      const raw = String(data.cdata||"");
      const m = /^([A-Za-z0-9_-]{8,})_([0-9]{9,})$/.exec(raw);
      const h = m ? m[1] : null;
      const tsSec = m ? parseInt(m[2],10) : 0;
      const age = Math.abs(Math.floor(Date.now()/1000) - tsSec);
      if (h !== expected.linkHash) {
        addLog(`[TS] cdata mismatch got=${h||'-'} want=${expected.linkHash} age=${age}s`);
        return { ok:false, reason:"bad_cdata_hash", data };
      }
      if (age > (expected.maxAgeSec||MAX_TOKEN_AGE_SEC)) return { ok:false, reason:"token_too_old", data, age };
    }

    if (EXPECT_HOSTNAME_LIST.length && data.hostname) {
      const got = normHost(data.hostname);
      const matched =
        EXPECT_HOSTNAME_EXACT.has(got) ||
        EXPECT_HOSTNAME_SUFFIX.some(s => got.endsWith(s));

      if (!matched) {
        addLog(`[TS-HOST-MISMATCH] got=${got} expectExact=[${[...EXPECT_HOSTNAME_EXACT].join(",")||"-"}] expectSuffix=[${EXPECT_HOSTNAME_SUFFIX.join(",")||"-"}]`);
        addSpacer();
        data.hostname = got;
        return { ok:false, reason:"bad_hostname", data };
      }

      data.hostname = got;
    }

    if (EXPECT_HOSTNAME && !EXPECT_HOSTNAME.includes(",") && !EXPECT_HOSTNAME.trim().startsWith(".") && data.hostname && data.hostname !== EXPECT_HOSTNAME) {
      addLog(`[TS-HOST-MISMATCH-LEGACY] got=${data.hostname} expect=${EXPECT_HOSTNAME}`);
      addSpacer();
      return { ok:false, reason:"bad_hostname", data };
    }

    addLog(`[TS] ok action=${data.action||'-'} hostname=${data.hostname||'-'} cdata=${String(data.cdata||'').slice(0,12)}…`);
    return { ok:true, data };
  } catch (e) {
    addLog("Turnstile verify error: " + e.message);
    return { ok:false, reason:"verify_error" };
  }
}

// ================== RATE LIMITERS ==================
const limitChallengeView = makeIpLimiter({ 
  capacity: parseInt(process.env.CHALLENGE_VIEW_CAPACITY || "5", 10), 
  windowSec: parseInt(process.env.CHALLENGE_VIEW_WINDOW_SEC || "300", 10), 
  keyPrefix: "challenge_view" 
});

const limitChallenge   = makeIpLimiter({ capacity: parseInt(process.env.CHALLENGE_CAPACITY || "12",10), windowSec: parseInt(process.env.CHALLENGE_WINDOW_SEC || "300",10), keyPrefix: "challenge" });
const limitTsClientLog = makeIpLimiter({ capacity: parseInt(process.env.TSLOG_CAPACITY || "30",10),      windowSec: parseInt(process.env.TSLOG_WINDOW_SEC || "300",10),      keyPrefix: "tslog" });
const limitSseUnauth   = makeIpLimiter({ capacity: parseInt(process.env.SSE_UNAUTH_CAPACITY || "10",10), windowSec: parseInt(process.env.SSE_UNAUTH_WINDOW_SEC || "60",10),  keyPrefix: "sse_unauth" });
const validationFailureLimiter = makeIpLimiter({ capacity: 10, windowSec: 300, keyPrefix: "validation_fail" });

// ================== CORE REDIRECT / INTERSTITIAL HELPERS ==================
const INTERSTITIAL_REASON_TEXT = {
  "Pre-scan": "Pre-scan",
  "Email-safe path": "Email-safe path",
  "HEAD-probe": "HEAD probe",
  "GET-probe": "GET probe",
  "OPTIONS-probe": "OPTIONS probe",
  "Known scanner UA": "Known scanner user agent"
};

function mapInterstitialReason(reason) {
  if (!reason) return "Pre-scan";
  const key = String(reason);
  return INTERSTITIAL_REASON_TEXT[key] || key;
}

const INTERSTITIAL_STATE = new Map();
const INTERSTITIAL_TTL_MS = 60 * 60 * 1000; // 1 hour
const INTERSTITIAL_MAX_ENTRIES = 10000;

function pruneInterstitialState(now) {
  if (INTERSTITIAL_STATE.size <= INTERSTITIAL_MAX_ENTRIES) return;
  const it = INTERSTITIAL_STATE.keys();
  const firstKey = it.next().value;
  if (firstKey) {
    INTERSTITIAL_STATE.delete(firstKey);
  }
}

function markInterstitialShown(nextEnc) {
  const key = String(nextEnc || "");
  const now = Date.now();
  let entry = INTERSTITIAL_STATE.get(key);
  const firstHit = !entry;
  if (!entry) {
    entry = { firstSeenAt: now, lastSeenAt: now, humanSeen: false };
  } else {
    entry.lastSeenAt = now;
  }
  INTERSTITIAL_STATE.set(key, entry);
  pruneInterstitialState(now);
  return { firstHit, humanSeen: !!entry.humanSeen };
}

function markInterstitialHuman(nextEnc) {
  const key = String(nextEnc || "");
  const now = Date.now();
  let entry = INTERSTITIAL_STATE.get(key);
  if (!entry) {
    entry = { firstSeenAt: now, lastSeenAt: now, humanSeen: true };
  } else {
    entry.humanSeen = true;
    entry.lastSeenAt = now;
  }
  INTERSTITIAL_STATE.set(key, entry);
  pruneInterstitialState(now);
  return entry;
}

const INTERSTITIAL_BYPASS_SECRET = process.env.INTERSTITIAL_BYPASS_SECRET || "";

function hasInterstitialBypass(req) {
  if (!INTERSTITIAL_BYPASS_SECRET) return false;

  const q = req.query || {};
  if (q.ib && q.ib === INTERSTITIAL_BYPASS_SECRET) return true;

  const hdr = req.get("x-interstitial-bypass");
  if (hdr && hdr === INTERSTITIAL_BYPASS_SECRET) return true;

  return false;
}

function renderScannerSafePage(req, res, nextEnc, reason = "Pre-scan", options = {}) {
  applyScannerCompatHeaders(res);
  if (IMPERSONATE_SCANNER && options.scannerProfile) {
    applyScannerProfileHeaders(res, options.scannerProfile);
  }

  const mappedReason = mapInterstitialReason(reason);
  const emailSafe = options.emailSafe === true || reason === "Email-safe path";
  const allowAuto = options.allowAuto === true ? true : !emailSafe;

  const stateInfo = markInterstitialShown(nextEnc);
  const challengeToken = createChallengeToken(nextEnc, req, mappedReason);
  const nonce = res.locals.cspNonce || crypto.randomBytes(16).toString("base64");

  res.setHeader("Cache-Control", "no-store");
  try {
    res.setHeader(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self';`
    );
  } catch {}

  const cfg = {
    ct: challengeToken,
    next: nextEnc,
    allowAuto,
    firstHit: !!stateInfo.firstHit,
    humanSeen: !!stateInfo.humanSeen,
    emailSafe: !!emailSafe
  };
  const cfgJson = JSON.stringify(cfg);

  const html = `<!doctype html><html><head>
<meta charset="utf-8">
<title>Checking link…</title>
<meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="font:16px system-ui;padding:24px;max-width:720px;margin:auto">
  <h1>Checking this link</h1>
  <p>This link was pre-scanned by security or preview software. If you're the intended recipient, click continue.</p>
  <p><a id="continue-link" href="/challenge?ct=${encodeURIComponent(challengeToken)}" rel="noopener">Continue</a></p>
  <p style="color:#6b7280;font-size:14px">Reason: ${mappedReason}</p>
  <script nonce="${nonce}">
    (function(){
      var cfg = ${cfgJson};
      try {
        if (cfg && cfg.next) {
          var payload = JSON.stringify({ next: cfg.next });
          if (navigator.sendBeacon) {
            var blob = new Blob([payload], { type: "application/json" });
            navigator.sendBeacon("/interstitial-human", blob);
          } else if (window.fetch) {
            fetch("/interstitial-human", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: payload,
              keepalive: true
            }).catch(function(){});
          }
        }
      } catch (e) {}

      if (!cfg.allowAuto) return;
      if (cfg.firstHit || !cfg.humanSeen) return;

      setTimeout(function(){
        try {
          if (document.visibilityState && document.visibilityState !== "visible") return;
          window.location.href = "/challenge?ct=" + encodeURIComponent(cfg.ct);
        } catch (e) {}
      }, 1200);
    })();
  </script>
</body>
</html>`;

  res.type("html").send(html);
}

// --- Early short-circuit for HEAD/OPTIONS scanner-style probes on deep links ---
app.use((req, res, next) => {
  if (hasInterstitialBypass(req)) return next();

  // allow your own health, logs, and challenge endpoints through
  if (
    req.path === "/health" ||
    req.path.startsWith("/view-log") ||
    req.path.startsWith("/challenge") ||
    req.path.startsWith("/ts-client-log") ||
    req.path.startsWith("/interstitial-human")
  ) {
    return next();
  }

  // only care about HEAD/OPTIONS prefetches (scanner probes)
  if (req.method !== "HEAD" && req.method !== "OPTIONS") return next();

  // Handle /e/* specifically (email-safe deep links)
  if (req.path.startsWith("/e/")) {
    const clean = (req.originalUrl || "").slice(3).split("?")[0];
    const scannerCtx = buildScannerInterstitialContext(req, req.method + "-probe");
    if (req.method === "HEAD") {
      logScannerHit(req, scannerCtx.scannerReason || "HEAD-probe", clean);
      if (scannerCtx.scannerProfile) {
        applyScannerCompatHeaders(res);
        applyScannerProfileHeaders(res, scannerCtx.scannerProfile);
      }
      return res.status(200).type("html").end();
    }
    logScannerHit(req, scannerCtx.scannerReason || (req.method + "-probe"), clean);
    return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || (req.method + "-probe"), {
      emailSafe: true,
      scannerProfile: scannerCtx.scannerProfile
    });
  }

  const url = req.originalUrl || "";
  const looksEncoded = /[A-Za-z0-9+/=_-]{40,}/.test(url);
  const longPath = url.length > 80;
  const hasCookies = !!req.headers["cookie"];
  const fetchMode = (req.get("sec-fetch-mode") || "").toLowerCase();
  const looksPrefetch = fetchMode && fetchMode !== "navigate" && fetchMode !== "document";

  const looksDeep = longPath && looksEncoded && (!hasCookies || looksPrefetch);

  if (looksDeep) {
    const clean = url.replace(/^\//, "").split("?")[0];
    const scannerCtx = buildScannerInterstitialContext(req, req.method + "-probe");
    logScannerHit(req, scannerCtx.scannerReason || (req.method + "-probe"), clean);
    return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || (req.method + "-probe"), {
      scannerProfile: scannerCtx.scannerProfile
    });
  }

  return next();
});

// --- OPTIONAL: catch GET probes on /e/... and show the safe interstitial ---
app.use((req, res, next) => {
  if (hasInterstitialBypass(req)) return next();

  // Let your own endpoints through untouched
  if (
    req.path === "/health" ||
    req.path.startsWith("/view-log") ||
    req.path.startsWith("/challenge") ||
    req.path.startsWith("/ts-client-log") ||
    req.path.startsWith("/interstitial-human")
  ) {
    return next();
  }

  if (req.method === "GET" && req.path.startsWith("/e/")) {
    const clean = (req.originalUrl || "").slice(3).split("?")[0];
    const scannerCtx = buildScannerInterstitialContext(req, "GET-probe");
    logScannerHit(req, scannerCtx.scannerReason || "GET-probe", clean);
    return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || "GET-probe", {
      emailSafe: true,
      scannerProfile: scannerCtx.scannerProfile
    });
  }

  return next();
});

const { handleRedirectCore } = require('./modules/redirectCore')({
  getClientIp,
  getDenyCacheIp,
  hasInterstitialBypass,
  getDenyCache,
  aggregatePerIpEvent,
  addLog,
  safeLogValue,
  addSpacer,
  recordOffenderSignals,
  REQUIRE_CF_HEADERS,
  hasCloudflareHeaders,
  isBanned,
  detectScannerEnhancedWithBehavior,
  recordScannerIp,
  pickScannerProfile,
  isKnownScannerIp,
  shouldImpersonateForRequest,
  addDenyCache,
  headlessSuspicion,
  addStrike,
  HEADLESS_STRIKE_WEIGHT,
  HEADLESS_SOFT_STRIKE,
  HEADLESS_BLOCK,
  getCountry,
  getASN,
  countryBlocked,
  asnBlocked,
  hashFirstSeg,
  verifyTurnstileToken,
  MAX_TOKEN_AGE_SEC,
  UA_TRUNCATE_LENGTH,
  recordChallengeBypassAttempt,
  createChallengeRedirect,
  isRateLimited,
  sanitizeChallengeReason,
  hashUaForToken,
  safeLogJson,
  LOG_ENTRY_MAX_LENGTH,
  splitCipherAndEmail,
  decodeB64urlLoose,
  isLikelyEmail,
  tryDecryptAny,
  bruteSplitDecryptFull,
  explainDecryptFailure,
  EMAIL_DISPLAY_MAX_LENGTH,
  verifyLinkHmac,
  safeDecode,
  maskEmail,
  normHost,
  isHostAllowlisted,
  URL_DISPLAY_MAX_LENGTH,
  PATH_TRUNCATE_LENGTH,
  logScannerHit,
  renderScannerSafePage,
});

// ================== MIDDLEWARE SETUP ==================
app.use(cors());
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

// ================== ENHANCED PUBLIC CONTENT SURFACE ==================
const {
  PUBLIC_CONTENT_SURFACE,
  PUBLIC_ENABLE_BACKGROUND,
  PUBLIC_SITE_BASE_URL,
  isPublicContentSurfaceEnabled,
  getActivePersona,
  generateAllPaths,
  initEnhancedPublicContent,
} = require('./modules/publicContent')({
  app,
  crypto,
  addLog,
  resolvePublicBaseUrls,
  rotationSeed,
  hash32,
  express,
  PORT: process.env.PORT || 8080,
});

initEnhancedPublicContent();

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.type === "entity.parse.failed") {
    try { addLog(`[TS-CLIENT] JSON parse error: ${String(err.message||'').slice(0,120)}`); addSpacer(); } catch {}
    req.body = null;
    return next();
  }
  return next(err);
});

app.use((req, res, next) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Permissions-Policy", "interest-cohort=(), browsing-topics=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  if (process.env.ENABLE_HSTS === "1") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }
  next();
});

app.use(validateRedirectRequest);

// Apply rate limiters BEFORE routes
app.use("/challenge",          limitChallenge);
app.use("/ts-client-log",      limitTsClientLog);
app.use("/interstitial-human", limitTsClientLog);
app.use("/stream-log", (req, res, next) => {
  if (isAdminSSE(req)) return next();
  return limitSseUnauth(req, res, next);
});

// ✅ Put the debug route here (before your normal routes)
if (process.env.IP_DEBUG === '1') {
  app.get('/_debug/ip', (req, res) => {
    const clientIp = getClientIp(req); // Use the same function!
    res.json({
      trustProxy: req.app.get('trust proxy'),
      clientIp: clientIp,
      reqIp: req.ip,
      reqIps: req.ips,
      xff: req.headers['x-forwarded-for'] || null,
      xVercelForwarded: req.headers['x-vercel-forwarded-for'] || null,
      xReal: req.headers['x-real-ip'] || null,
      nf: req.headers['x-nf-client-connection-ip'] || null,
      allHeaders: {
        'x-forwarded-for': req.headers['x-forwarded-for'],
        'x-vercel-forwarded-for': req.headers['x-vercel-forwarded-for'],
        'x-real-ip': req.headers['x-real-ip'],
        'x-vercel-ip': req.headers['x-vercel-ip']
      }
    });
  });
}

// ================== ROUTES ==================
app.post("/decrypt-challenge-data",
  express.json({ limit: "1kb" }),
  (req, res) => {
    const { data } = req.body || {};
    if (!data) return res.json({ success: false, error: "No data" });

    const payload = decryptChallengeData(data);
    if (!payload) return res.json({ success: false, error: "Decryption failed" });

    const raw = parseInt(process.env.CHALLENGE_PAYLOAD_TTL_MIN || "5", 10);
    const ttlMin = Number.isFinite(raw) && raw > 0 ? raw : 5; // guard

    // extra sanity: ensure payload.ts is a number
    const issuedAt = typeof payload.ts === "number" ? payload.ts : 0;
    if (Date.now() - issuedAt > ttlMin * 60 * 1000) {
      return res.json({ success: false, error: "Payload expired" });
    }

    return res.json({ success: true, payload });
  }
);

app.get("/health", (_req, res) => res.json({ ok:true, time:new Date().toISOString() }));

app.post(
"/ts-client-log",
  express.text({ type: "*/*", limit: "64kb" }),
  (req, res) => {
    const ip  = getClientIp(req) || "unknown";
    const ua  = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
    const ct  = req.get("content-type") || "-";
    const len = req.get("content-length") || "0";

    let payload = null;

    if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
      payload = req.body;
    } else {
      const raw = typeof req.body === "string" ? req.body : "";

      if (raw && raw.trim()) {
        try { payload = JSON.parse(raw); } catch { }
      }

      if ((!payload || typeof payload !== "object") && raw && raw.includes("=")) {
        try {
          const params = new URLSearchParams(raw);
          const obj = {};
          for (const [k, v] of params.entries()) obj[k] = v;
          payload = obj;
        } catch { }
      }

      if (!payload) req.__rawPreview = raw.slice(0, 200);
    }

    if (!payload || typeof payload !== "object" || !payload.phase) {
      const preview = req.__rawPreview != null
        ? JSON.stringify(req.__rawPreview)
        : (typeof req.body === "object" ? JSON.stringify(req.body).slice(0, 200) : '""');
      addLog(`[TS-CLIENT:empty] ip=${safeLogValue(ip)} ua="${safeLogValue(ua)}" ct=${safeLogValue(ct)} len=${safeLogValue(len)} preview=${safeLogValue(preview)}`);
      return res.status(204).end();
    }

    addLog(`[TS-CLIENT:${safeLogValue(payload.phase)}] ip=${safeLogValue(ip)} ua="${safeLogValue(ua)}" ${safeLogJson(payload)}`);
    addSpacer();
    res.status(204).end();
  }
);

app.post(
"/interstitial-human",
  express.json({ type: "application/json", limit: "4kb" }),
  (req, res) => {
    const body = req.body || {};
    const nextEnc = typeof body.next === "string" ? body.next.slice(0, 4096) : "";
    if (!nextEnc) {
      return res.status(400).json({ ok: false, error: "missing_next" });
    }

    markInterstitialHuman(nextEnc);

    const ip = getClientIp(req) || "unknown";
    const ua = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
    addLog(
      `[INTERSTITIAL-HUMAN] ip=${safeLogValue(ip)} ua="${safeLogValue(ua)}" nextLen=${nextEnc.length}`
    );
    addSpacer();

    res.json({ ok: true });
  }
);

app.get("/stream-log", (req, res) => {
  if (!isAdminSSE(req)) return res.status(403).end("Forbidden: missing admin token (SSE)");

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  try { res.write(": connected\n\n"); } catch {}

  const lastIdHdr = req.get("last-event-id");
  const lastId = lastIdHdr ? parseInt(lastIdHdr, 10) : NaN;
  let startIdx = Math.max(0, LOG_IDS.length - BACKLOG_ON_CONNECT);
  if (Number.isFinite(lastId) && lastId >= 0) {
    const pos = LOG_IDS.lastIndexOf(lastId);
    if (pos >= 0) startIdx = pos + 1;
  } else {
    res.write(`event: reset\ndata: {"ts":${Date.now()}}\n\n`);
  }

  for (let i = startIdx; i < LOGS.length; i++) {
    sseSend(res, LOGS[i], LOG_IDS[i]);
  }

  LOG_LISTENERS.add(res);

  try { res.write(": hb-ready\n\n"); } catch {}

  const hb = setInterval(() => { try { res.write(": ping\n\n"); } catch {} }, 25000);

  let cleaned = false;
  function cleanup() {
    if (cleaned) return;
    cleaned = true;
    try { clearInterval(hb); } catch {}
    LOG_LISTENERS.delete(res);
  }

  req.once("aborted", cleanup);
  req.once("close", cleanup);
  res.once("close", cleanup);
  res.once("error", cleanup);
  res.once("finish", cleanup);

  req.socket?.setTimeout?.(0);
  req.socket?.setKeepAlive?.(true);
});

app.get("/view-log-live", (req, res) => {
  if (!(isAdmin(req) || isAdminSSE(req))) {
    return res.status(401).type("text/plain").send("Unauthorized");
  }

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
  );

  const pageTok = req.query.token && String(req.query.token);
  const tok = pageTok || mintEphemeralToken();
  const streamUrl = `/stream-log?token=${encodeURIComponent(tok)}`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="referrer" content="no-referrer" />
  <meta name="color-scheme" content="dark light" />
  <title>Live Logs</title>
  <style>
    body{margin:0;font:14px/1.4 ui-monospace,Menlo,Consolas,monospace}
    #log{padding:12px;white-space:pre-wrap;word-break:break-word}
    .status{color:#888;padding:8px 12px}
  </style>
</head>
<body>
  <div class="status">Connecting…</div>
  <pre id="log"></pre>
  <script>
    const logEl = document.getElementById('log');
    const statusEl = document.querySelector('.status');
    const es = new EventSource(${JSON.stringify(streamUrl)});

    es.onopen = () => {
      statusEl.textContent = 'Connected';
    };

    es.addEventListener('reset', () => {
      logEl.textContent = '';
      statusEl.textContent = 'Repainting…';
    });

    es.onmessage = (e) => {
      logEl.textContent += e.data + '\\n';
      statusEl.textContent = '';
      window.scrollTo(0, document.body.scrollHeight);
    };

    es.onerror = (e) => {
      statusEl.textContent = 'Disconnected — retrying…';
      console.debug('SSE error', e, 'readyState=', es.readyState);
    };
  </script>
</body>
</html>`);
});

app.get("/view-log", requireAdmin, (req, res) => {
  return res.type("text/plain").send(LOGS.join("\n") || "No logs yet.");
});

app.get("/geo-debug", (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");
  res.json({
    ip: getClientIp(req),
    resolvedCountry: getCountry(req),
    headers: {
      "cf-ipcountry": req.headers["cf-ipcountry"] || null,
      "cf-edge-country": req.headers["cf-edge-country"] || null,
      "x-nf-geo": req.headers["x-nf-geo"] || null,
      "x-vercel-ip-country": req.headers["x-vercel-ip-country"] || null
    }
  });
});

app.get("/favicon.ico", (_req, res) => {
  res.set("Cache-Control","public, max-age=86400");
  return res.status(204).end();
});

// ================== PUBLIC CONTENT HELPERS ==================
function dayStamp(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

function weekStamp(d = new Date()) {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dayNum = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((dt - yearStart) / 86400000) + 1) / 7);
  return `${dt.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

function rotationSeed() {
  const mode = String(process.env.PUBLIC_ROTATION_MODE || "daily").trim().toLowerCase();
  if (mode === "weekly") return weekStamp();
  if (mode === "fixed") return "fixed";
  return dayStamp();
}

function hash32(input) {
  const hex = crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 8);
  return parseInt(hex, 16) >>> 0;
}

function deterministicPick(items, seed, count = 3) {
  if (!Array.isArray(items) || items.length === 0) return [];
  const out = [];
  const n = Math.min(Math.max(1, count), items.length);
  const used = new Set();
  let i = 0;
  while (out.length < n && i < (items.length * 3)) {
    const idx = hash32(`${seed}:${i}`) % items.length;
    if (!used.has(idx)) {
      used.add(idx);
      out.push(items[idx]);
    }
    i += 1;
  }
  return out;
}

function wildcardMatches(hostname, wildcardPattern) {
  const cleanHost = String(hostname || "").toLowerCase().split(":")[0];
  const cleanPattern = String(wildcardPattern || "").toLowerCase().trim();
  if (!cleanHost || !cleanPattern.startsWith("*.") || cleanPattern.length < 3) return false;
  const suffix = cleanPattern.slice(2);
  if (!suffix) return false;
  if (!cleanHost.endsWith(`.${suffix}`)) return false;
  return cleanHost !== suffix;
}

function resolvePublicBaseUrls(req, options = {}) {
  const rawForwardedHost = String(req.get("x-forwarded-host") || "")
    .split(",")
    .map((part) => part.trim())
    .find(Boolean);
  const host = String(
    rawForwardedHost ||
    req.get("x-original-host") ||
    req.get("x-host") ||
    req.get("host") ||
    "localhost"
  ).trim();
  const hostNoPort = host.split(":")[0];
  const proto = req.secure || String(req.get("x-forwarded-proto") || "").includes("https") ? "https" : "http";
  const requestBase = `${proto}://${host}`;
  const requestHostOnly = options && options.requestHostOnly === true;
  const preferConfiguredCanonical = options && options.preferConfiguredCanonical === true;

  const configured = parsePublicBaseUrlEntries();

  if (requestHostOnly) {
    if (preferConfiguredCanonical) {
      const firstConfiguredCanonical = configured
        .map((entry) => {
          try {
            if (!entry || entry === "*" || entry.startsWith("*.")) return null;
            const value = /^https?:\/\//i.test(entry) ? entry : `https://${entry}`;
            const asUrl = new URL(value);
            return `${asUrl.protocol}//${asUrl.host}`;
          } catch {
            return null;
          }
        })
        .find(Boolean);

      if (firstConfiguredCanonical) {
        return [firstConfiguredCanonical];
      }
    }

    return [requestBase];
  }

  if (configured.length === 0) {
    return [requestBase];
  }

  const out = [];
  for (const entry of configured) {
    if (entry === "*") {
      out.push(requestBase);
      continue;
    }

    const asUrl = (() => {
      try {
        const value = /^https?:\/\//i.test(entry) ? entry : `https://${entry}`;
        return new URL(value);
      } catch {
        return null;
      }
    })();

    if (!asUrl) continue;

    const wildcardHost = asUrl.hostname;
    if (wildcardHost.startsWith("*.")) {
      if (wildcardMatches(hostNoPort, wildcardHost)) {
        out.push(`${asUrl.protocol}//${host}`);
      }
      continue;
    }

    out.push(`${asUrl.protocol}//${asUrl.host}`);
  }

  const resolved = [...new Set(out.filter(Boolean))];
  return resolved.length > 0 ? resolved : [requestBase];
}

function parsePublicBaseUrlEntries() {
  return PUBLIC_SITE_BASE_URL
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

app.get("/robots.txt", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.type("text/plain");

  if (process.env.ROBOTS_CONTENT) {
    return res.send(process.env.ROBOTS_CONTENT);
  }

  const p = path.join(process.cwd(), "robots.txt");
  if (fs.existsSync(p)) {
    return res.send(fs.readFileSync(p, "utf8"));
  }

  return res.send("User-agent: *\nDisallow: /\n");
});

app.get("/turnstile-sitekey", (_req, res) => res.json({ sitekey: TURNSTILE_SITEKEY }));

app.get("/__debug/key", requireAdmin, (req, res) => {
  const items = AES_KEYS.map((buf, idx) => {
    const sha = crypto.createHash("sha256").update(buf).digest("hex");
    const b64url = buf.toString("base64url");
    return {
      index: idx,
      len: buf.length,
      sha256: sha,
      b64url: DEBUG_ALLOW_PLAINTEXT_KEYS ? b64url : mask(b64url),
      note: buf.length === 32 ? "OK (32 bytes)" : "Unexpected length"
    };
  });
  res.json({ ok:true, count: items.length, keys: items });
});

app.get("/__debug/decrypt", requireAdmin, (req, res) => {
  const d = String(req.query.d || "");
  const out = tryDecryptAny(d);
  if (out && out.url) return res.status(200).type("text/plain").send(out.url);
  const bf = bruteSplitDecryptFull(d);
  if (bf && bf.url) return res.status(200).type("text/plain").send(bf.url);
  const tried = (out && out.tried) ? out.tried.join("|") : "none";
  return res.status(200).type("text/plain").send("fail; tried=" + tried);
});

app.get("/__hp.gif", (req, res) => {
  const ip = getClientIp(req);
  addLog(`[HP] honeypot hit ip=${safeLogValue(ip)} ua="${safeLogValue((req.get("user-agent")||"").slice(0,UA_TRUNCATE_LENGTH))}"`);
  addStrike(ip, STRIKE_WEIGHT_HP);
  res.set("Cache-Control","no-store");
  return res.status(204).end();
});

// Helper function to validate IP address format
function isValidIpAddress(ip) {
  if (!ip || typeof ip !== 'string') return false;
  
  // IPv4 validation
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipv4Match = ip.match(ipv4Regex);
  if (ipv4Match) {
    return ipv4Match.slice(1).every(octet => {
      const num = parseInt(octet, 10);
      return num >= 0 && num <= 255;
    });
  }
  
  // IPv6 validation (more comprehensive)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip);
}

app.post("/admin/unban", (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(403).send("Forbidden");
    const ip = String(req.query.ip||"").trim();
    if (!ip) return res.status(400).send("ip required");
    
    // Validate IP format
    if (!isValidIpAddress(ip)) {
      return res.status(400).json({error: "Invalid IP address format"});
    }
    
    const safeIp = sanitizeIpForKey(ip);
    if (!inMemBans.has(safeIp)) return res.json({ok:true, message:"not banned"});
    inMemBans.delete(safeIp);
    return res.json({ok:true, message:"unbanned", ip});
  } catch (error) {
    addLog(`[ADMIN-ERROR] unban: ${error.message}`);
    return res.status(500).json({error: "Internal server error"});
  }
});

app.post("/admin/strike-reset", (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(403).send("Forbidden");
    const ip = String(req.query.ip||"").trim();
    if (!ip) return res.status(400).send("ip required");
    
    // Validate IP format
    if (!isValidIpAddress(ip)) {
      return res.status(400).json({error: "Invalid IP address format"});
    }
    
    const safeIp = sanitizeIpForKey(ip);
    inMemStrikes.delete(safeIp);
    return res.json({ok:true, message:"strikes reset", ip});
  } catch (error) {
    addLog(`[ADMIN-ERROR] strike-reset: ${error.message}`);
    return res.status(500).json({error: "Internal server error"});
  }
});

app.get(
  "/admin/scanner-stats",
  (req, res, next) => {
    if (isAdmin(req) || isAdminSSE(req)) return next();
    addLog(`[ADMIN] scanner-stats denied ip=${safeLogValue(getClientIp(req))} ua="${safeLogValue((req.get("user-agent")||"").slice(0,UA_TRUNCATE_LENGTH))}"`);
    return res.status(401).type("text/plain").send("Unauthorized");
  },
  
  (req, res) => {
    const derived = computeScannerStatsFromLogs();
    const use = (derived && derived.total > 0) ? derived : {
      total: SCANNER_STATS.total,
      byReason: SCANNER_STATS.byReason,
      byUA: SCANNER_STATS.byUA
    };

    const topUA = Object.entries(use.byUA || {})
      .sort((a,b) => b[1] - a[1])
      .slice(0, 20)
      .map(([ua, count]) => ({ ua, count }));

    res.json({
      ok: true,
      source: (derived && derived.total > 0) ? "logs" : "counters",
      total: use.total || 0,
      byReason: use.byReason || {},
      topUA,
      now: new Date().toISOString()
    });
  }
);

const adminHits = new Map();
app.use(["/view-log", "/__debug", "/admin"], (req, res, next) => {
  if (isAdmin(req)) return next();
  const ip = getClientIp(req) || "unknown";
  const now = Date.now();
  const winMs = 60_000;
  const rec = adminHits.get(ip) || { count: 0, resetAt: now + winMs };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + winMs; }
  rec.count++;
  adminHits.set(ip, rec);
  if (rec.count > 120) return res.status(429).send("Too Many Requests");
  next();
});

const registerChallengeRoutes = require('./modules/challengeRoutes');
registerChallengeRoutes({
  app,
  limitChallengeView,
  sanitizeChallengeReason,
  verifyChallengeToken,
  addLog,
  recordChallengeBypassAttempt,
  createChallengeRedirect,
  createChallengeToken,
  safeDecode,
  hashFirstSeg,
  safeLogValue,
  TURNSTILE_SITEKEY,
  encryptChallengeData,
});

app.get("/e/:data(*)", (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(3);
  const clean = urlPathFull.split("?")[0];
  const scannerCtx = buildScannerInterstitialContext(req, "Email-safe path");
  addLog(`[INTERSTITIAL] /e path used len=${clean.length}`);
  logScannerHit(req, scannerCtx.scannerReason || "Email-safe path", clean);
  return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || "Email-safe path", {
    emailSafe: true,
    scannerProfile: scannerCtx.scannerProfile
  });
});

app.head("/e/:data(*)", (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(3);
  const clean = urlPathFull.split("?")[0];
  const scannerCtx = buildScannerInterstitialContext(req, "HEAD-probe");
  addLog(`[INTERSTITIAL] HEAD /e path`);
  logScannerHit(req, scannerCtx.scannerReason || "HEAD-probe", clean);
  if (scannerCtx.scannerProfile) {
    applyScannerCompatHeaders(res);
    applyScannerProfileHeaders(res, scannerCtx.scannerProfile);
  }
  res.status(200).type("html").end();
});

app.get("/r", async (req, res) => {
  const baseString = safeDecode(String(req.query.d || ""));
  if (!baseString) return res.status(400).send("Missing data");
  return handleRedirectCore(req, res, baseString);
});

app.get("/:data(*)", async (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(1);
  const cleanPath = urlPathFull.split("?")[0];
  if (!cleanPath) return res.status(400).send("Missing data");
  return handleRedirectCore(req, res, cleanPath);
});

// ================== HEALTH CHECK CONSTANTS ==================
const MIN_INTERVAL_MS  = process.env.NODE_ENV === "production" ? 60 * 1000 : 60 * 1000;
const MIN_HEARTBEAT_MS = process.env.NODE_ENV === "production" ? 5  * 60 * 1000 : 5 * 60 * 1000;

const HEALTH_INTERVAL_MS  = Math.max(
  MIN_INTERVAL_MS,
  parseMinHourToMs(process.env.HEALTH_INTERVAL  ?? "5m",  5 * 60 * 1000)
);

const HEALTH_HEARTBEAT_MS = Math.max(
  MIN_HEARTBEAT_MS,
  parseMinHourToMs(process.env.HEALTH_HEARTBEAT ?? "2h",  2 * 60 * 60 * 1000)
);

// ================== STARTUP & HEALTH CHECKS ==================
function publicContentStartupSummaryLines() {
  const publicSurfaceEnabled = isPublicContentSurfaceEnabled();
  const backgroundTrafficEnabled = PUBLIC_ENABLE_BACKGROUND && PUBLIC_CONTENT_SURFACE;
  const publicForce = String(process.env.PUBLIC_CONTENT_SURFACE_FORCE || '').trim() ? 'set' : 'unset';
  const publicExplicit = String(process.env.PUBLIC_CONTENT_SURFACE || '').trim() ? 'set' : 'unset';
  const lines = [
    `[PUBLIC-CONTENT] Effective enabled=${publicSurfaceEnabled} declared=${PUBLIC_CONTENT_SURFACE} force=${publicForce} explicit=${publicExplicit}`
  ];

  if (!publicSurfaceEnabled) {
    lines.push("[PUBLIC-CONTENT] Disabled by safe default (set PUBLIC_CONTENT_SURFACE=1 or PUBLIC_CONTENT_SURFACE_FORCE=1 to enable)");
    return lines;
  }

  const persona = getActivePersona();
  const allPaths = generateAllPaths(persona, rotationSeed());
  lines.push(`[PUBLIC-CONTENT] Active persona: ${persona.name} (${persona.sitekey})`);
  const currentRotationMode = String(process.env.PUBLIC_ROTATION_MODE || "daily").trim().toLowerCase();
  lines.push(`[PUBLIC-CONTENT] Generated ${allPaths.length} unique paths, rotation=${currentRotationMode}`);
  if (backgroundTrafficEnabled) {
    lines.push(`[PUBLIC-TRAFFIC] Background traffic generator started (persona: ${persona.sitekey})`);
  } else {
    lines.push(`[PUBLIC-TRAFFIC] Background traffic generator disabled (PUBLIC_ENABLE_BACKGROUND=${PUBLIC_ENABLE_BACKGROUND}, PUBLIC_CONTENT_SURFACE=${PUBLIC_CONTENT_SURFACE})`);
  }
  return lines;
}

function startupSummary() {
  const keyPrints = AES_KEYS.map((k, i) => {
    const sha = crypto.createHash("sha256").update(k).digest("hex");
    return `#${i} len=${k.length} sha256=${sha.slice(0,10)}…`;
  }).join(", ");

  return [
    "🛡️ Security profile",
    `[KEY] Loaded ${AES_KEYS.length} AES key(s): ${keyPrints}`,
    `  • Time: zone=${zoneLabel()}`,
    `  • Turnstile: enforceAction=${ENFORCE_ACTION} maxAgeSec=${MAX_TOKEN_AGE_SEC} expectHost=${EXPECT_HOSTNAME || "-"}`,
    `  • Turnstile sitekey=${mask(TURNSTILE_SITEKEY)} secret=${mask(TURNSTILE_SECRET)}`,
    `  • Geo: allow=[${ALLOWED_COUNTRIES.join(",")||"-"}] block=[${BLOCKED_COUNTRIES.join(",")||"-"}] asn=[${BLOCKED_ASNS.join(",")||"-"}]`,
    `  • Headless: block=${HEADLESS_BLOCK} hardWeight=${HEADLESS_STRIKE_WEIGHT} softStrike=${HEADLESS_SOFT_STRIKE}`,
    `  • Scanner impersonation: enabled=${IMPERSONATE_SCANNER} strict=${IMPERSONATE_SCANNER_STRICT} minConfidence=${IMPERSONATE_MIN_CONFIDENCE}`,
    `  • Scanner compatibility headers: enabled=${SCANNER_COMPAT_HEADERS_ENABLED}`,
    `  • Edge checks: requireCfHeaders=${REQUIRE_CF_HEADERS}`,
    `  • RateLimit: capacity=${RATE_CAPACITY}/window=${RATE_WINDOW_SECONDS}s`,
    `  • Bans: ttl=${BAN_TTL_SEC}s threshold=${BAN_AFTER_STRIKES} hpWeight=${STRIKE_WEIGHT_HP}`,
    `  • Allowlist patterns=[${ALLOWLIST_DOMAINS.map(p => p.allowSubdomains ? `*.${p.suffix}` : p.suffix).join(",")||"-"}]`,
    `  • Challenge security: rateLimit=5/5min tokens=10min`,
    `  • Geo fallback active=${Boolean(geoip)}`,
    `  • Health: interval=${fmtDurMH(HEALTH_INTERVAL_MS)} heartbeat=${fmtDurMH(HEALTH_HEARTBEAT_MS)}`,
    ...publicContentStartupSummaryLines()
  ].join("\n");
}

let _health = { ok: null, lastHeartbeat: 0, okStreak: 0, failStreak: 0, inflight: false };

async function checkTurnstileReachable() {
  if (_health.inflight) return;
  _health.inflight = true;

  const now = Date.now();
  try {
    const url = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js`;
    const r = await fetch(url, { method: "HEAD" });
    const ok = r.ok;

    if (ok) { _health.okStreak++; _health.failStreak = 0; }
    else    { _health.failStreak++; _health.okStreak  = 0; }

    if (_health.ok !== ok) {
      addLog(`[HEALTH] turnstile HEAD ${r.status} ${ok ? "ok" : "not-ok"} (change)`);
      _health.ok = ok;
      _health.lastHeartbeat = now;
    } else if (now - _health.lastHeartbeat >= HEALTH_HEARTBEAT_MS) {
      addLog(`[HEALTH] heartbeat status=${ok ? "ok" : "not-ok"} okStreak=${_health.okStreak} failStreak=${_health.failStreak}`);
      _health.lastHeartbeat = now;
    }
  } catch (e) {
    _health.failStreak++; _health.okStreak = 0;
    if (_health.ok !== false) {
      addLog(`[HEALTH] turnstile HEAD error ${String(e)} (change)`);
      _health.ok = false;
      _health.lastHeartbeat = now;
    } else if (now - _health.lastHeartbeat >= HEALTH_HEARTBEAT_MS) {
      addLog(`[HEALTH] heartbeat status=not-ok okStreak=${_health.okStreak} failStreak=${_health.failStreak}`);
      _health.lastHeartbeat = now;
    }
  } finally {
    _health.inflight = false;
  }
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  if (geoip) addLog("ℹ️ geoip-lite enabled as country fallback");
  
  await loadScannerPatterns();

  checkTurnstileReachable();
  setInterval(checkTurnstileReachable, HEALTH_INTERVAL_MS);

  // Memory cleanup interval
  setInterval(() => {
    const now = Date.now();
    // Clean old rate limit buckets (older than 1 hour)
    for (const [key, value] of inMemBuckets.entries()) {
      if (now - value.ts > 3600000) { // 1 hour
        inMemBuckets.delete(key);
      }
    }

    for (const [key, st] of inMemDenyCache.entries()) {
      if (!st || now > st.until) inMemDenyCache.delete(key);
    }

    flushAggregatedLogs(now);
  }, 300000);

  setInterval(() => flushAggregatedLogs(Date.now()), AGG_FLUSH_MS);

  // Server + security summary logs
  addLog(`🚀 Server running on port ${PORT}`);
  addLog(startupSummary());

  // BYPASS status (CORRECT LOCATION)
  if (!INTERSTITIAL_BYPASS_SECRET) {
    addLog("[BYPASS] disabled (no INTERSTITIAL_BYPASS_SECRET set)");
  } else {
    addLog("[BYPASS] enabled for debug use");
  }

  addSpacer();
});
