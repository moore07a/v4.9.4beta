// server.js — AES redirector + Cloudflare Turnstile, hardened (v4.9.2 Advance Beta widget + Interstitial improved)
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
// More explicit proxy trust configuration
const trustProxy = (() => {
  const raw = process.env.TRUST_PROXY_HOPS && process.env.TRUST_PROXY_HOPS.trim();
  
  if (raw === undefined || raw === '') return true; // Default: trust all
  if (raw.toLowerCase() === 'true') return true;
  if (raw.toLowerCase() === 'false') return false;
  if (Number.isFinite(+raw) && +raw >= 0) return +raw;
  
  // Platform-specific defaults (these are nice-to-have, not critical)
  if (process.env.VERCEL || process.env.NETLIFY || process.env.RENDER) return 1;
  
  return true; // Fallback to trusting all
})();

app.set('trust proxy', trustProxy);
console.log(`[PROXY] Trust proxy setting: ${trustProxy}`);

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
    "/decrypt-challenge-data", "/challenge-fragment"
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
<<<<<<< codex/analyze-log-entries-for-errors-pfruze
      // For noisy catch-all probes, aggregate per IP and emit only summary lines
      // via flushAggregatedLogs instead of logging every first-hit attempt.
      aggregatePerIpEvent("VALIDATION-FAILED", {
        ip,
        reason: "invalid_catch_all_path"
      });
=======
      const shouldLog = aggregatePerIpEvent("VALIDATION-FAILED", {
        ip,
        reason: "invalid_catch_all_path"
      });

      if (shouldLog) {
        addLog(`[VALIDATION-FAILED] ip=${safeLogValue(ip)} path=${req.path} errors=${errors.join(", ")} ua="${safeLogValue(ua.slice(0, 100))}"`);
      }
>>>>>>> main
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

function mintEphemeralToken() {
  const exp = Date.now() + EPHEMERAL_TTL_MS;
  const msg = `sse:${exp}`;
  const sig = crypto.createHmac('sha256', EPHEMERAL_SECRET).update(msg).digest('base64url');
  return `ts:${exp}:${sig}`;
}

function verifyEphemeralToken(tok) {
  const m = /^ts:(\d+):([A-Za-z0-9_-]+)$/.exec(tok || "");
  if (!m) return false;
  const exp = +m[1], sig = m[2];
  if (Date.now() > exp) return false;
  const msg = `sse:${exp}`;
  const expect = crypto.createHmac('sha256', EPHEMERAL_SECRET).update(msg).digest('base64url');
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

{
  const prints = AES_KEYS.map((k,i) => {
    const sha = crypto.createHash("sha256").update(k).digest("hex");
    return `#${i} len=${k.length} sha256=${sha.slice(0,10)}…`;
  }).join(", ");
  addLog(`[KEY] Loaded ${AES_KEYS.length} AES key(s): ${prints}`);
  addSpacer();
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
    .createHmac("sha256", process.env.ADMIN_TOKEN)
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
    .createHmac("sha256", process.env.ADMIN_TOKEN)
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
  if (trustProxy === false) return false;

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
  if (trustProxy !== false) {
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
    if (req.method === "HEAD") {
      logScannerHit(req, "HEAD-probe", clean);
      return res.status(200).type("html").end();
    }
    logScannerHit(req, req.method + "-probe", clean);
    return renderScannerSafePage(req, res, clean, req.method + "-probe", { emailSafe: true });
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
    logScannerHit(req, req.method + "-probe", clean);
    return renderScannerSafePage(req, res, clean, req.method + "-probe");
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
    logScannerHit(req, "GET-probe", clean);
    return renderScannerSafePage(req, res, clean, "GET-probe", { emailSafe: true });
  }

  return next();
});

function checkSecurityPolicies(req) {
  const ip = getClientIp(req);
  const denyCacheIp = getDenyCacheIp(req);
  const ua = req.get("user-agent") || "";
  const bypassInterstitial = hasInterstitialBypass(req);

  const denyHit = getDenyCache(denyCacheIp);
  if (denyHit) {
    const shouldLog = aggregatePerIpEvent("DENY_CACHE", { ip, reason: denyHit.reason });
    if (shouldLog) {
      addLog(`[DENY-CACHE] blocked ip=${safeLogValue(ip)} keyIp=${safeLogValue(denyCacheIp)} reason=${safeLogValue(denyHit.reason, 32)}`);
      addSpacer();
    }
    recordOffenderSignals(req);
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  if (REQUIRE_CF_HEADERS && !hasCloudflareHeaders(req)) {
    addLog(
      `[CF] missing headers ip=${safeLogValue(ip)} ua="${safeLogValue(
        ua.slice(0, UA_TRUNCATE_LENGTH)
      )}"`
    );
    addSpacer();
    recordOffenderSignals(req);
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  if (bypassInterstitial) {
    addLog(
      `[BYPASS] interstitial bypass active ip=${safeLogValue(ip)} ua="${safeLogValue(
        ua.slice(0, UA_TRUNCATE_LENGTH)
      )}"`
    );
    addSpacer();
  }

  // IP bans still apply even with bypass
  if (isBanned(ip)) {
    addLog(`[BAN] blocked ip=${ip}`);
    addSpacer();
    recordOffenderSignals(req);
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  // Scanner detection → interstitial (unless bypass)
  const scannerResult = detectScannerEnhancedWithBehavior(req);
  const scannerDetections = scannerResult.detections;
  if (!bypassInterstitial && scannerResult.isScanner) {
    const topDetection = scannerDetections[0];
    addLog(
      `[SCANNER] interstitial ip=${safeLogValue(ip)} scanner="${safeLogValue(
        topDetection.name
      )}" confidence=${safeLogValue(String(topDetection.confidence ?? ""))} ua="${safeLogValue(
        ua.slice(0, UA_TRUNCATE_LENGTH)
      )}"`
    );
    recordOffenderSignals(req);
    return { blocked: true, interstitial: true, scanner: topDetection.name };
  }

  // Hard bad UAs → 403 (unless bypass)
  const BAD_UA = /(okhttp|python-requests|curl|wget|phantomjs)/i;
  if (!bypassInterstitial && BAD_UA.test(ua)) {
    addLog(`[UA-BLOCK] ip=${ip} ua="${ua.slice(0, UA_TRUNCATE_LENGTH)}"`);
    addSpacer();
    addDenyCache(denyCacheIp, "ua_block");
    recordOffenderSignals(req);
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  // Headless suspicion (strikes + optional block) (unless bypass)
  const hs = headlessSuspicion(req);
  if (!bypassInterstitial && hs.suspicious) {
    const softOnlyOne = hs.hardCount === 0 && hs.softCount === 1;
    const label =
      hs.hardCount >= 1
        ? "HEADLESS"
        : (hs.isSafariUA || hs.isFirefoxUA) && softOnlyOne
        ? "INFO"
        : hs.softCount >= 2
        ? "SUSPECT"
        : "INFO";

    addLog(`[${label}] ip=${safeLogValue(ip)} reasons=${safeLogValue(hs.reasons.join(","))}`);

    if (hs.hardCount > 0) {
      addStrike(ip, HEADLESS_STRIKE_WEIGHT);
    } else if (HEADLESS_SOFT_STRIKE && hs.softCount >= 2) {
      addStrike(ip, 1);
    }

    if (HEADLESS_BLOCK && hs.hardCount > 0) {
      addSpacer();
      addDenyCache(denyCacheIp, "headless_hard");
      recordOffenderSignals(req);
      return { blocked: true, status: 403, message: "Forbidden" };
    }
  }

  // Geo / ASN blocking (still enforced even with bypass)
  const ctry = getCountry(req);
  const asn = getASN(req);
  if (countryBlocked(ctry)) {
    const shouldLog = aggregatePerIpEvent("GEO", { ip, country: ctry, reason: "country_block" });
    if (shouldLog) {
      addLog(`[GEO] blocked country=${safeLogValue(ctry)} ip=${safeLogValue(ip)}`);
      addSpacer();
    }
    addDenyCache(denyCacheIp, "geo_block");
    recordOffenderSignals(req, { country: ctry, asn });
    return { blocked: true, status: 403, message: "Forbidden" };
  }
  if (asnBlocked(asn)) {
    const shouldLog = aggregatePerIpEvent("ASN", { ip, reason: "asn_block" });
    if (shouldLog) {
      addLog(`[ASN] blocked asn=${safeLogValue(asn)} ip=${safeLogValue(ip)}`);
      addSpacer();
    }
    addDenyCache(denyCacheIp, "asn_block");
    recordOffenderSignals(req, { country: ctry, asn });
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  return { blocked: false };
}

async function verifyTurnstileAndRateLimit(req, baseString) {
  const ip = getClientIp(req);
  const ua = req.get("user-agent") || "";
  
  const token = req.query.cft || req.get("cf-turnstile-response") || "";
  const linkHash = req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString);

  const v = await verifyTurnstileToken(token, ip, { action:"link_redirect", linkHash, maxAgeSec:MAX_TOKEN_AGE_SEC });
  if (!v.ok) {
    addLog(`[AUTH] token invalid (${v.reason}) ip=${safeLogValue(ip)} ua="${safeLogValue(ua.slice(0, UA_TRUNCATE_LENGTH))}" -> /challenge`);
    // Missing token is normal for first-time human visits; reserve bypass alerts
    // for malformed/invalid supplied tokens and tamper-like states.
    if (token || (v.reason && v.reason !== "missing")) {
      recordChallengeBypassAttempt(req, `auth_${v.reason || 'invalid'}`);
    }
    return {
      redirect: createChallengeRedirect(baseString, req, "auth_invalid", {
        host: (v.reason === "bad_hostname" && v.data && v.data.hostname) ? v.data.hostname : ""
      })
    };
  }

  const { limited, retryAfterMs } = await isRateLimited(ip);
  if (limited) {
    if (retryAfterMs && Number.isFinite(retryAfterMs)) {
      return { blocked: true, status: 429, retryAfter: Math.ceil(retryAfterMs/1000), message: "Too many requests" };
    }
    addLog(`[RL] 429 ip=${ip}`);
    addSpacer();
    return { blocked: true, status: 429, message: "Too many requests" };
  }

  if (token) {
    const challengeReason = sanitizeChallengeReason(req.query.cr || "");
    const logCtx = {
      ip: safeLogValue(ip),
      uaHash: hashUaForToken(ua),
      linkHash: safeLogValue(linkHash, 64),
      reason: safeLogValue(challengeReason || "-", 48)
    };
    addLog(`[CHALLENGE-OK] ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
  }

  return { success: true };
}

function decryptAndParseUrl(req, baseString) {
  const ip = getClientIp(req);
  const linkHash = req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString);
  
  const { mainPart, emailPart: emailPart0, delimUsed } =
    splitCipherAndEmail(baseString, decodeB64urlLoose, isLikelyEmail);

  if (delimUsed) {
    addLog(`[PARSE] delimiter used "${delimUsed}" mainLen=${mainPart.length} emailRawLen=${(emailPart0 || '').length}`);
  }

  let result = null;
  try {
    result = tryDecryptAny(mainPart);
  } catch (e) {
    addLog(`[DECRYPT] exception ip=${safeLogValue(ip)} seg="${safeLogValue(String(mainPart), EMAIL_DISPLAY_MAX_LENGTH)}" err=${safeLogValue(e.message)}`);
    addSpacer();
    return { error: "Failed to load" };
  }
  
  let decryptedPayload = result && result.url;
  let emailPart = emailPart0 || null;

  if (!decryptedPayload) {
    const bf = bruteSplitDecryptFull(baseString);
    if (bf && bf.url) {
      decryptedPayload = bf.url;
      if (!emailPart) emailPart = bf.emailRaw || null;
      addLog(`[DECRYPT] fallback split used k=${bf.kTried} emailRawLen=${(bf.emailRaw || '').length}`);
    }
  }

  if (!decryptedPayload) {
    const why = explainDecryptFailure({
      tried: result?.tried || [],
      lastErr: result?.lastErr || null,
      segLen: mainPart.length
    });
    addLog(`[DECRYPT] failed variants ip=${safeLogValue(ip)} seg="${safeLogValue(String(mainPart), EMAIL_DISPLAY_MAX_LENGTH)}" mainLen=${mainPart.length} why=${safeLogValue(why)}`);
    addSpacer();
    return { error: "Failed to load" };
  }

  let parsedUrl = decryptedPayload;
  let pinnedHost = null;
  let hmacChecked = false;
  let hmacValid = false;

  try {
    const parsed = JSON.parse(decryptedPayload);
    if (parsed && typeof parsed === "object") {
      if (typeof parsed.url === "string") parsedUrl = parsed.url;
      if (typeof parsed.dest_host === "string") pinnedHost = parsed.dest_host;
      if (parsed && typeof parsed.hmac === "string" && pinnedHost && parsedUrl) {
        const res = verifyLinkHmac(parsedUrl, pinnedHost, parsed.hmac);
        hmacChecked = true;
        hmacValid = !!res.ok;
      }
    }
  } catch {}

  if (hmacChecked && !hmacValid) {
    const ua = req.get("user-agent") || "";
    const logCtx = {
      ip: safeLogValue(ip),
      uaHash: hashUaForToken(ua),
      linkHash: safeLogValue(linkHash, 64),
      destHost: safeLogValue(pinnedHost || "-", 120)
    };
    addLog(`[DECRYPT] hmac mismatch ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
    addSpacer();
    return { error: "Failed to load" };
  }

  return { finalUrl: parsedUrl, emailPart, pinnedHost, linkHash };
}

function processEmailAndFinalizeUrl(finalUrl, emailPart) {
  if (emailPart) {
    const emailRaw = String(emailPart).replace(/[\/~]+$/,'');
    const emailDecoded = (decodeB64urlLoose(emailRaw) || safeDecode(emailRaw)).trim();

    if (emailDecoded && isLikelyEmail(emailDecoded)) {
      finalUrl += '#' + emailDecoded;
      addLog(`[EMAIL] captured ${safeLogValue(maskEmail(emailDecoded), EMAIL_DISPLAY_MAX_LENGTH)}`);
    } else if (emailDecoded) {
      addLog(`[EMAIL] ignored (not a valid email): "${safeLogValue(emailDecoded, EMAIL_DISPLAY_MAX_LENGTH)}" (raw="${safeLogValue(emailPart.slice(0,40))}…")`);
    } else {
      addLog(`[EMAIL] ignored (decode empty) raw="${safeLogValue(emailPart.slice(0,40))}…"`);
    }
  }

  return finalUrl;
}

function renderInvalidLinkPage(res) {
  const html = `<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Link unavailable</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif;background:#0c1116;color:#e8eef6;padding:24px;}
  .card{max-width:520px;width:100%;background:#0f172a;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:24px;box-shadow:0 24px 60px rgba(0,0,0,0.45);} 
  h1{margin:0 0 8px;font-size:24px;}
  p{margin:0 0 8px;color:#cbd5e1;}
</style>
</head>
<body>
  <div class="card">
    <h1>Link invalid or expired</h1>
    <p>The link you followed is no longer valid. Please contact the sender for a fresh link.</p>
    <p>If you believe this is an error, try opening the link from the original message again.</p>
  </div>
</body>
</html>`;
  res.setHeader("Cache-Control", "no-store");
  return res.status(400).type("html").send(html);
}

function logHostPinFailure({ ip, ua, linkHash, pinnedHost, actualHost }) {
  const logCtx = {
    ip: safeLogValue(ip),
    uaHash: hashUaForToken(ua || ""),
    linkHash: safeLogValue(linkHash || "-", 64),
    pinnedHost: safeLogValue(pinnedHost || "-", 160),
    actualHost: safeLogValue(actualHost || "-", 160)
  };
  addLog(`[PIN] host mismatch ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
  addSpacer();
}

function validateAndRedirect(finalUrl, req, res, options = {}) {
  const ip = getClientIp(req);
  const ua = req.get("user-agent") || "";
  const pinnedHost = options.pinnedHost || null;
  const linkHash = options.linkHash || null;
  
  try {
    const parsedUrl = new URL(finalUrl);
    const hostname = normHost(parsedUrl.hostname);
    const protocol = parsedUrl.protocol;
    const normalizedPinnedHost = options.pinnedHost ? normHost(options.pinnedHost) : null;

    if (!["http:", "https:"].includes(protocol)) {
      addLog(`[ALLOWLIST] blocked protocol=${safeLogValue(protocol)} host=${safeLogValue(hostname)} ip=${safeLogValue(ip)}`);
      addSpacer();
      return res.status(403).send("Unauthorized URL");
    }

    if (normalizedPinnedHost && normalizedPinnedHost !== hostname) {
      logHostPinFailure({ ip, ua, linkHash, pinnedHost: normalizedPinnedHost, actualHost: hostname });
      return renderInvalidLinkPage(res);
    }

    const okHost = isHostAllowlisted(hostname);

    if (!okHost) {
      addLog(`[ALLOWLIST] blocked host=${hostname} ip=${ip}`);
      addSpacer();
      return res.status(403).send("Unauthorized URL");
    }

    addLog(`[REDIRECT] ip=${safeLogValue(ip)} -> ${safeLogValue(finalUrl, URL_DISPLAY_MAX_LENGTH)}`);
    addSpacer();
    return res.redirect(302, finalUrl);
  } catch (e) {
    addLog(`[URL] invalid ip=${safeLogValue(ip)} value="${safeLogValue((finalUrl || ""), URL_DISPLAY_MAX_LENGTH)}" err="${safeLogValue(e.message)}"`);
    addSpacer();
    return res.status(400).send("Invalid URL");
  }
}

async function handleRedirectCore(req, res, baseString){
  const clientIp = getClientIp(req);
  const ua = req.get("user-agent") || "";
  const linkHash = req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString);
  const hasSecUA = !!req.get("sec-ch-ua");
  const hasFetchSite = !!req.get("sec-fetch-site");
  const missingSecHeaders = !hasSecUA || !hasFetchSite;
  const knownBots = ["Googlebot","Bingbot","Slurp","DuckDuckBot","Baiduspider","YandexBot","Sogou","Exabot","facebot","facebookexternalhit","ia_archiver","MJ12bot","AhrefsBot","SemrushBot","DotBot","PetalBot","GPTBot","python-requests","crawler","scrapy","curl","wget","phantomjs","HeadlessChrome"];
  const isBotUA = knownBots.some(b => ua.toLowerCase().includes(b.toLowerCase()));
  const hasTurnstileToken = !!req.query.cft;

  const securityCheck = checkSecurityPolicies(req);
  if (securityCheck.blocked) {
    if (securityCheck.interstitial) {
      const nextEnc = encodeURIComponent(baseString);
      logScannerHit(req, "Known scanner UA", nextEnc);
      return renderScannerSafePage(req, res, nextEnc, "Known scanner UA");
    }
    return res.status(securityCheck.status).send(securityCheck.message);
  }

  const authCheck = await verifyTurnstileAndRateLimit(req, baseString);
  if (authCheck.redirect) {
    return res.redirect(302, authCheck.redirect);
  }
  if (authCheck.blocked) {
    if (authCheck.retryAfter) {
      res.setHeader("Retry-After", authCheck.retryAfter);
    }
    return res.status(authCheck.status).send(authCheck.message);
  }

  if (isBotUA || missingSecHeaders) {
    const reason = isBotUA ? "bot_heuristic" : "missing_sec_headers";
    const logCtx = {
      ip: safeLogValue(clientIp),
      uaHash: hashUaForToken(ua),
      linkHash: safeLogValue(linkHash, 64),
      isBotUA,
      missingSecHeaders,
      hasSecUA: !!hasSecUA,
      hasFetchSite: !!hasFetchSite
    };
    addLog(`[CHALLENGE-TRIGGER] ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
    addSpacer();

    if (!hasTurnstileToken) {
      const reasonParam = sanitizeChallengeReason(reason);
      return res.redirect(302, createChallengeRedirect(baseString, req, reasonParam));
    }
  }

  const decryptResult = decryptAndParseUrl(req, baseString);
  if (decryptResult.error) {
    return res.status(400).send(decryptResult.error);
  }

  const finalUrl = processEmailAndFinalizeUrl(decryptResult.finalUrl, decryptResult.emailPart);
  return validateAndRedirect(finalUrl, req, res, { pinnedHost: decryptResult.pinnedHost, linkHash: decryptResult.linkHash });
}

// ================== MIDDLEWARE SETUP ==================
app.use(cors());
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

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

// Replace the entire challenge route HTML content with this fixed version:

function resolveChallengeRequest(req, res) {
  let nextEnc = "";
  const body = req.body || {};
  const requestReason = req.query.cr || req.query.reason || body.cr || "";
  let challengeReason = sanitizeChallengeReason(requestReason);
  const rawCt = req.query.ct || body.ct;

  if (rawCt) {
    const payload = verifyChallengeToken(String(rawCt), req);
    if (!payload) {
      addLog(`[CHALLENGE] Invalid or expired challenge token`);
      recordChallengeBypassAttempt(req, "invalid_challenge_token");
      res.status(400).send("Invalid or expired challenge link");
      return null;
    }
    nextEnc = payload.next;
    if (payload.cr) {
      challengeReason = sanitizeChallengeReason(payload.cr);
    }
    addLog(`[CHALLENGE] Valid token nextLen=${nextEnc.length} age=${Date.now() - payload.ts}ms`);
  } else if (req.query.next) {
    nextEnc = String(req.query.next);
    addLog(`[CHALLENGE] LEGACY next parameter used len=${nextEnc.length} - auto-migrating`);
    const migrated = createChallengeRedirect(nextEnc, req, challengeReason || "legacy_next_migrated");
    return { redirect: migrated };
  } else if (body.next) {
    nextEnc = String(body.next);
    addLog(`[CHALLENGE] Legacy body next parameter used len=${nextEnc.length} - auto-migrating`);
    const migrated = createChallengeRedirect(nextEnc, req, challengeReason || "legacy_body_next_migrated");
    return { redirect: migrated };
  } else {
    res.status(400).send("Missing challenge data");
    return null;
  }

  return {
    nextEnc,
    challengeReason,
    ct: rawCt ? String(rawCt) : ""
  };
}

function buildChallengeHtml(encryptedData, cspNonce = '') {
  return `<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c1116">
<meta name="robots" content="noindex,nofollow">
<title>Verify you are human</title>
<style>
  :root{
    --bg:#0c1116; --card:#0c1116; --text:#e8eef6; --muted:#93a1b2;
    --accent:#0ea5e9; --ring:rgba(255,255,255,0.05); --border:rgba(255,255,255,0.06);
  }
  @media (prefers-color-scheme: light){
    :root{
      --bg:#f7fafc; --card:#ffffff; --text:#0b1220; --muted:#516173;
      --accent:#0ea5e9; --ring:#e8eef5; --border:#e7eef6;
    }
  }
  *{ box-sizing:border-box; }
  html,body{ height:100%; }
  body{
    margin:0; background:var(--bg); color:var(--text);
    font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif;
    -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
    display:flex; align-items:center; justify-content:center;
    padding:clamp(16px,4vw,40px);
  }
  .card{
    width:100%; max-width:760px; text-align:center;
    background:var(--card);
    border:1px solid var(--border);
    border-radius:16px;
    padding:clamp(22px,3vw,34px);
    box-shadow: 0 20px 50px rgba(0,0,0,.35), 0 0 0 1px rgba(255,255,255,.02) inset;
  }
  h2{ margin:0 0 10px; font-size:clamp(26px,3.4vw,38px); letter-spacing:.2px; }
  .muted{ color:var(--muted); }
  #ts{ display:inline-block; margin-top:12px; }
  .status{ margin-top:12px; color:var(--muted); font-size:14px; min-height:20px; }
  .err{ color:#ef4444; }
</style>

<script nonce="${cspNonce}">
  const ENCRYPTED_DATA = ${JSON.stringify(encryptedData)};
  const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
  const TURNSTILE_SCRIPT_ID = "cf-turnstile-script";

  // SINGLETON STATE MANAGEMENT - Prevent duplicates
  let currentWidgetId = null;
  let isRendering = false;
  let scriptLoaded = false;
  let initializationStarted = false;
  let turnstileReady = false;
  let renderAttempts = 0;
  const MAX_RENDER_ATTEMPTS = 1; // Only allow one render attempt

  window.__sid = (Math.random().toString(36).slice(2) + Date.now().toString(36));
  
  function clientContext(extra) {
    return {
      phase: extra.phase || 'context',
      sid: window.__sid,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      lang: navigator.language,
      online: navigator.onLine,
      vis: document.visibilityState,
      ref: document.referrer || '',
      ts: Date.now(),
      widgetId: currentWidgetId,
      isRendering: isRendering,
      scriptLoaded: scriptLoaded,
      turnstileReady: turnstileReady,
      renderAttempts: renderAttempts
    };
  }

  function trackPhase(phase, data = {}) {
    const context = clientContext({ phase, ...data });
    
    // Only log critical phases to reduce noise
    const criticalPhases = [
      'script-load-error',
      'render-blocked-duplicate', 
      'render-success',
      'render-error',
      'error-callback',
      'timeout',
      'navigation-error'
    ];
    
    if (criticalPhases.includes(phase)) {
      fetch('/ts-client-log', {
        method: 'POST', 
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(context)
      }).catch(() => {}); // Silent fail for logging errors
    }
  }

  window.addEventListener('error', function(e) {
    trackPhase('window-error', {
      filename: e.filename, 
      lineno: e.lineno, 
      colno: e.colno,
      message: String(e.message||'')
    });
  }, true);

  window.addEventListener('unhandledrejection', function(e) {
    trackPhase('unhandledrejection', {
      reason: String(e.reason && (e.reason.stack||e.reason.message||e.reason) || '')
    });
  });

  function decryptChallengeData(encrypted) {
    return fetch('/decrypt-challenge-data', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ data: encrypted })
    }).then(function(r) { 
      if (!r.ok) throw new Error('Network response was not ok');
      return r.json(); 
    });
  }

  var getChallengePayload = (function() {
    var cached = null;
    return function(reset) {
      if (reset) cached = null;
      if (!cached) cached = decryptChallengeData(ENCRYPTED_DATA);
      return cached;
    };
  })();

  // SINGLE INITIALIZATION CONTROLLER
  function initializeTurnstile() {
    if (initializationStarted) {
      console.log('[TS] Initialization already started, skipping duplicate');
      return;
    }
    initializationStarted = true;

    const statusEl = document.getElementById('status');
    if (!statusEl) {
      console.error('[TS] Status element not found');
      return;
    }

    statusEl.textContent = 'Loading security check...';

    // Wait for both DOM ready and Turnstile ready
    function waitForTurnstileAndDOM() {
      const isDOMReady = document.readyState === 'complete' || document.readyState === 'interactive';
      const isTurnstileReady = window.turnstile && typeof window.turnstile.render === 'function';
      
      if (isDOMReady && isTurnstileReady && !turnstileReady) {
        turnstileReady = true;
        startWidgetRendering();
      } else if (!isDOMReady || !isTurnstileReady) {
        setTimeout(waitForTurnstileAndDOM, 100);
      }
    }

    // Fallback timeout
    const fallbackTimeout = setTimeout(() => {
      if (!currentWidgetId && renderAttempts === 0) {
        console.warn('[TS] Fallback: Starting render after timeout');
        startWidgetRendering();
      }
    }, 8000);

    function startWidgetRendering() {
      clearTimeout(fallbackTimeout);
      
      getChallengePayload()
        .then(function(data) {
          if (!data.success) throw new Error(data.error || 'Decryption failed');
          return data.payload;
        })
        .then(function(payload) {
          safeRenderTurnstile(payload.sitekey, payload.cdata);
        })
        .catch(function(e) {
          statusEl.textContent = 'Security initialization failed. Please refresh.';
          console.error('[TS] Initialization error:', e);
          trackPhase('initialization-error', { error: e.message });
        });
    }

    // Start waiting for readiness
    waitForTurnstileAndDOM();
  }

  // SINGLE RENDER FUNCTION with strict duplicate prevention
  function safeRenderTurnstile(sitekey, cdata) {
    if (renderAttempts >= MAX_RENDER_ATTEMPTS) {
      console.log('[TS] Max render attempts reached, skipping');
      trackPhase('render-blocked-max-attempts');
      return;
    }

    if (isRendering) {
      console.log('[TS] Already rendering, skipping duplicate');
      trackPhase('render-blocked-rendering');
      return;
    }

    if (currentWidgetId) {
      console.log('[TS] Widget already exists, skipping duplicate');
      trackPhase('render-blocked-existing-widget');
      return;
    }

    renderAttempts++;
    isRendering = true;
    
    const tsContainer = document.getElementById('ts');
    const statusEl = document.getElementById('status');
    
    if (!tsContainer || !statusEl) {
      console.error('[TS] Container or status element not found');
      isRendering = false;
      return;
    }

    // Clear any existing content
    tsContainer.innerHTML = '<div id="ts-inner" style="min-height:65px; display:flex; justify-content:center;"></div>';
    const innerContainer = document.getElementById('ts-inner');
    
    if (!innerContainer) {
      console.error('[TS] Inner container not found');
      isRendering = false;
      return;
    }

    // Small delay to ensure DOM is updated
    setTimeout(() => {
      if (!window.turnstile || typeof window.turnstile.render !== 'function') {
        console.error('[TS] Turnstile not available for rendering');
        statusEl.textContent = 'Security component not loaded. Please refresh.';
        isRendering = false;
        trackPhase('render-error-turnstile-unavailable');
        return;
      }

      try {
        console.log('[TS] Starting widget render attempt', renderAttempts);
        
        const widgetId = window.turnstile.render(innerContainer, {
          sitekey: sitekey,
          action: 'link_redirect',
          cData: cdata,
          appearance: 'always',
          callback: onOK,
          'error-callback': onErr,
          'timeout-callback': onTimeout
        });
        
        if (widgetId) {
          currentWidgetId = widgetId;
          isRendering = false;
          statusEl.textContent = 'Challenge ready.';
          console.log('[TS] Widget rendered successfully:', widgetId);
          trackPhase('render-success', { widgetId: widgetId });
        } else {
          console.error('[TS] Turnstile.render returned null widget ID');
          isRendering = false;
          statusEl.textContent = 'Challenge failed to load. Please refresh.';
          trackPhase('render-error-null-id');
        }
      } catch (renderError) {
        console.error('[TS] Render exception:', renderError);
        isRendering = false;
        statusEl.textContent = 'Challenge error. Please refresh.';
        trackPhase('render-exception', { error: renderError.message });
      }
    }, 100);
  }

  function onOK(token) {
    console.log('[TS] Challenge completed successfully');
    const statusEl = document.getElementById('status');
    if (statusEl) {
      statusEl.textContent = 'Verifying...';
    }
    
    // Prevent multiple submissions
    currentWidgetId = null;

    getChallengePayload()
      .then(function(data) {
        if (!data.success) throw new Error('Decryption failed');
        
        const next = data.payload.next;
        const lh = data.payload.lh;
        const reason = data.payload.cr || '';

        try {
          const decoded = decodeURIComponent(next);
          const parts = decoded.split('?');
          const base = parts[0];
          const qs = parts[1] || '';
          const sp = new URLSearchParams(qs);
          sp.delete('cft'); 
          sp.delete('lh');
          if (reason) {
            sp.set('cr', reason);
          }
          sp.append('cft', token);
          sp.append('lh', lh);
          const suffix = '&' + sp.toString();
          
          console.log('[TS] Redirecting after successful challenge');
          window.location.href = '/r?d=' + encodeURIComponent(base) + suffix;
        } catch(e) {
          console.error('[TS] Navigation error:', e);
          if (statusEl) statusEl.textContent = 'Navigation error. Please retry.';
          trackPhase('navigation-error', { error: e.message });
        }
      })
      .catch(function(e) {
        console.error('[TS] Payload decryption error:', e);
        if (statusEl) statusEl.textContent = 'Security error. Please refresh.';
        trackPhase('decrypt-error', { error: e.message });
      });
  }

  function onErr(errCode) {
    console.log('[TS] Error callback:', errCode);
    
    // Error 106010 means "already solved" - this is expected if user solved quickly
    if (errCode === '106010') {
      console.log('[TS] Ignoring 106010 (challenge already solved)');
      return; // DO NOT retry or reset state
    }

    trackPhase('error-callback', { 
      errorCode: String(errCode || ''),
      widgetId: currentWidgetId,
      renderAttempts: renderAttempts
    });

    // For other errors, allow one retry but with careful state management
    if (renderAttempts < 2) {
      console.log('[TS] Scheduling retry for error:', errCode);
      currentWidgetId = null;
      isRendering = false;
      
      setTimeout(() => {
        getChallengePayload(true) // Reset cache
          .then(function(data) {
            if (!data.success) throw new Error('Retry decrypt failed');
            safeRenderTurnstile(data.payload.sitekey, data.payload.cdata);
          })
          .catch(function(err) {
            const statusEl = document.getElementById('status');
            if (statusEl) statusEl.textContent = 'Security check failed. Please refresh.';
          });
      }, 1000);
    } else {
      console.log('[TS] Max retries reached for error:', errCode);
      const statusEl = document.getElementById('status');
      if (statusEl) statusEl.textContent = 'Too many attempts. Please refresh the page.';
    }
  }
  
  function onTimeout() {
    console.log('[TS] Challenge timeout');
    const statusEl = document.getElementById('status');
    if (statusEl) statusEl.textContent = 'Challenge timed out. Refresh the page.';
    currentWidgetId = null;
    isRendering = false;
    trackPhase('timeout');
  }

  // SCRIPT LOAD HANDLERS - Only one initialization path
  function tsApiOnLoad(ev) {
    console.log('[TS] Script loaded successfully');
    scriptLoaded = true;

    const scriptEl = document.getElementById(TURNSTILE_SCRIPT_ID);
    if (scriptEl) { 
      scriptEl.dataset.loaded = '1'; 
      scriptEl.dataset.failed = ''; 
    }

    trackPhase('script-loaded');

    // Start initialization
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
      initializeTurnstile();
    } else {
      document.addEventListener('DOMContentLoaded', initializeTurnstile, { once: true });
    }
  }

  function tsApiOnError(ev) {
    console.error('[TS] Script load failed');
    const scriptEl = document.getElementById(TURNSTILE_SCRIPT_ID);
    if (scriptEl) scriptEl.dataset.failed = '1';
    
    const statusEl = document.getElementById('status');
    if (statusEl) statusEl.textContent = 'Challenge script failed to load. Check adblock and refresh.';
    
    trackPhase('script-load-error', {
      src: ev && ev.target && ev.target.src || ''
    });
  }

  function onEarlyResourceErrorCapture(ev) {
    const target = ev && ev.target;
    if (!target || target.tagName !== 'SCRIPT') return;

    const src = target.getAttribute('src') || '';
    const isTurnstileScript =
      target.id === TURNSTILE_SCRIPT_ID ||
      src.indexOf('/turnstile/v0/api.js') !== -1;

    if (!isTurnstileScript) return;

    window.removeEventListener('error', onEarlyResourceErrorCapture, true);
    tsApiOnError(ev);
  }

  window.addEventListener('error', onEarlyResourceErrorCapture, true);

  function bindTurnstileScriptErrorHandler() {
    const scriptEl = document.getElementById(TURNSTILE_SCRIPT_ID);
    if (!scriptEl) return;
    scriptEl.addEventListener('error', tsApiOnError, { once: true });
    window.removeEventListener('error', onEarlyResourceErrorCapture, true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindTurnstileScriptErrorHandler, { once: true });
  } else {
    bindTurnstileScriptErrorHandler();
  }
</script>

<!-- SINGLE SCRIPT TAG - No duplicate loading -->
<script id="cf-turnstile-script" 
        src="${TURNSTILE_ORIGIN}/turnstile/v0/api.js?render=explicit&onload=tsApiOnLoad"
        async 
        defer>
</script>

</head>
<body>
  <div class="card">
    <h3>Verify you are human by completing the action below.</h3>
    <p class="muted">IAA needs to review the security of your connection before proceeding.</p>
    <div id="ts" aria-live="polite"></div>
    <p id="status" class="status muted">Loading security check...</p>
    <noscript><p class="err">Turnstile requires JavaScript. Please enable JS and refresh.</p></noscript>
    <p class="muted" style="margin-top:18px">Protected by Cloudflare Turnstile</p>
  </div>
</body>
</html>`;
}

app.get("/challenge", limitChallengeView, (req, res) => {
  const resolved = resolveChallengeRequest(req, res);
  if (!resolved) return;
  if (resolved.redirect) return res.redirect(302, resolved.redirect);

  const fragmentToken = resolved.ct || createChallengeToken(resolved.nextEnc, req, resolved.challengeReason);

  const htmlContent = `<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c1116">
<meta name="robots" content="noindex,nofollow">
<title>Verify you are human</title>
<style>
  body{ margin:0; background:#0c1116; color:#e8eef6; }
  noscript{ display:block; padding:16px; color:#ef4444; font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif; }
</style>
</head>
<body>
<noscript>Turnstile requires JavaScript. Please enable JS and refresh.</noscript>
<script nonce="${res.locals.cspNonce || ''}">
  fetch("/challenge-fragment", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ ct: ${JSON.stringify(fragmentToken)}, nonce: ${JSON.stringify(res.locals.cspNonce || "")} })
  })
    .then(function(r){ if (!r.ok) throw new Error("Failed to load"); return r.text(); })
    .then(function(html){ document.open(); document.write(html); document.close(); })
    .catch(function(){ document.body.innerHTML = "<p style=\\"font-family:system-ui; padding:16px; color:#ef4444\\">Failed to load challenge. Please refresh.</p>"; });
</script>
</body>
</html>`;

  res.type("html").send(htmlContent);
});

function handleChallengeFragment(req, res) {
  const resolved = resolveChallengeRequest(req, res);
  if (!resolved) return;
  if (resolved.redirect) return res.redirect(302, resolved.redirect);

  const rawNonce = (req.body && req.body.nonce) || req.query.nonce || "";
  const nonce = /^[A-Za-z0-9+/=_-]{8,}$/.test(String(rawNonce)) ? String(rawNonce) : res.locals.cspNonce;

  const { nextEnc, challengeReason } = resolved;
  const nextPath = safeDecode(nextEnc);
  const [baseOnly] = nextPath.split("?");
  const linkHash = hashFirstSeg(baseOnly);
  const cdata = `${linkHash}_${Math.floor(Date.now()/1000)}`;

  addLog(`[CHALLENGE] secured next='${nextEnc.slice(0,20)}…' reason=${safeLogValue(challengeReason || "-", 48)} cdata=${cdata.slice(0,16)}…`);
  addLog(`[TS-PAGE] sitekey=${TURNSTILE_SITEKEY.slice(0,12)}… hash=${linkHash.slice(0,8)}…`);

  const challengePayload = {
    sitekey: TURNSTILE_SITEKEY,
    cdata: cdata,
    next: nextEnc,
    lh: linkHash,
    ts: Date.now(),
    cr: challengeReason || undefined
  };

  const encryptedData = encryptChallengeData(challengePayload);
  const htmlContent = buildChallengeHtml(encryptedData, nonce);

  res.type("html").send(htmlContent);
}

app.post("/challenge-fragment", limitChallengeView, handleChallengeFragment);
app.get("/challenge-fragment", limitChallengeView, handleChallengeFragment);

app.get("/e/:data(*)", (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(3);
  const clean = urlPathFull.split("?")[0];
  addLog(`[INTERSTITIAL] /e path used len=${clean.length}`);
  logScannerHit(req, "Email-safe path", clean);
  return renderScannerSafePage(req, res, clean, "Email-safe path", { emailSafe: true });
});

app.head("/e/:data(*)", (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(3);
  const clean = urlPathFull.split("?")[0];
  addLog(`[INTERSTITIAL] HEAD /e path`);
  logScannerHit(req, "HEAD-probe", clean);
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
function startupSummary() {
  return [
    "🛡️ Security profile",
    `  • Time: zone=${zoneLabel()}`,
    `  • Turnstile: enforceAction=${ENFORCE_ACTION} maxAgeSec=${MAX_TOKEN_AGE_SEC} expectHost=${EXPECT_HOSTNAME || "-"}`,
    `  • Turnstile sitekey=${mask(TURNSTILE_SITEKEY)} secret=${mask(TURNSTILE_SECRET)}`,
    `  • Geo: allow=[${ALLOWED_COUNTRIES.join(",")||"-"}] block=[${BLOCKED_COUNTRIES.join(",")||"-"}] asn=[${BLOCKED_ASNS.join(",")||"-"}]`,
    `  • Headless: block=${HEADLESS_BLOCK} hardWeight=${HEADLESS_STRIKE_WEIGHT} softStrike=${HEADLESS_SOFT_STRIKE}`,
    `  • RateLimit: capacity=${RATE_CAPACITY}/window=${RATE_WINDOW_SECONDS}s`,
    `  • Bans: ttl=${BAN_TTL_SEC}s threshold=${BAN_AFTER_STRIKES} hpWeight=${STRIKE_WEIGHT_HP}`,
    `  • Allowlist patterns=[${ALLOWLIST_DOMAINS.map(p => p.allowSubdomains ? `*.${p.suffix}` : p.suffix).join(",")||"-"}]`,
    `  • Challenge security: rateLimit=5/5min tokens=10min`,
    `  • Geo fallback active=${Boolean(geoip)}`,
    `  • Health: interval=${fmtDurMH(HEALTH_INTERVAL_MS)} heartbeat=${fmtDurMH(HEALTH_HEARTBEAT_MS)}`
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
