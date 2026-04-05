// WebSafe — Firebase Cloud Functions (index.js)
// Converted from server.js for Firebase deployment
// All /api/* routes are handled here as a single Cloud Function

const functions = require('firebase-functions');
const express   = require('express');
const fetch     = require('node-fetch');
const tls       = require('tls');
const cheerio   = require('cheerio');
const whois     = require('whois');
const cors      = require('cors');

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

// ── Simple in-memory blacklist ────────────────────────────────────────────────
const BLACKLIST = ['example-malicious.com', 'bad-domain.test'];
function isBlacklisted(hostname) {
  const h = hostname.toLowerCase();
  return BLACKLIST.some(b => h.includes(b));
}

// ── Known URL shorteners ──────────────────────────────────────────────────────
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'short.link', 'tiny.cc', 'bl.ink',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'snip.ly', 'clicky.me',
  'bit.do', 't2mio.com', 'link.tl', 'trib.al'
];
function isShortener(hostname) {
  const h = hostname.toLowerCase().replace(/^www\./, '');
  return URL_SHORTENERS.some(s => h === s || h.endsWith('.' + s));
}

// ── Follow redirects ──────────────────────────────────────────────────────────
async function followRedirects(url, maxRedirects = 10, timeout = 10000) {
  let current = url;
  const chain = [url];
  for (let i = 0; i < maxRedirects; i++) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(current, {
        method: 'HEAD', redirect: 'manual', signal: controller.signal,
        headers: { 'User-Agent': 'WebSafe/1.0' }
      });
      clearTimeout(id);
      const loc = res.headers.get('location');
      if ((res.status >= 300 && res.status < 400) && loc) {
        try { current = new URL(loc, current).href; } catch(e) { current = loc; }
        chain.push(current);
      } else { break; }
    } catch(e) { clearTimeout(id); break; }
  }
  return { finalUrl: current, chain };
}

// ── Fetch HTML ────────────────────────────────────────────────────────────────
async function fetchHtml(url, timeout = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: { 'User-Agent': 'WebSafe/1.0', 'Accept-Language': 'en-US,en;q=0.9' },
      signal: controller.signal,
    });
    clearTimeout(id);
    const text = await res.text();
    return { text, finalUrl: res.url, status: res.status, ok: res.ok };
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// ── TLS / SSL Certificate ─────────────────────────────────────────────────────
function getCertificateInfo(hostname, port = 443, timeout = 8000) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      try {
        const cert = sock.getPeerCertificate(true) || {};
        const now  = Date.now();
        let expires = null, valid = false;
        if (cert && cert.valid_to) {
          const exp = new Date(cert.valid_to);
          if (!Number.isNaN(exp.getTime())) {
            expires = Math.floor((exp.getTime() - now) / (1000 * 60 * 60 * 24));
            valid   = exp.getTime() > now;
          }
        }
        resolve({ cert, certExpiresDays: expires, certValid: valid });
      } catch (e) {
        resolve({ cert: null, certExpiresDays: null, certValid: false });
      } finally {
        try { sock.end(); } catch (e) {}
      }
    });
    sock.setTimeout(timeout, () => { try { sock.destroy(); } catch (e) {} resolve({ cert: null, certExpiresDays: null, certValid: false }); });
    sock.on('error', () => resolve({ cert: null, certExpiresDays: null, certValid: false }));
  });
}

// ── Parse HTML meta ───────────────────────────────────────────────────────────
function parseMeta(html, baseUrl) {
  const $ = cheerio.load(html);
  const title = $('title').first().text().trim() || '';
  const desc  = $('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '';
  let icon    = $('link[rel~="icon"]').attr('href') || $('link[rel~="shortcut icon"]').attr('href') || '';
  if (icon) { try { icon = new URL(icon, baseUrl).href; } catch (e) {} }
  return { title, description: desc, favicon: icon };
}

// ── WHOIS lookup (multi-source) ───────────────────────────────────────────────
async function whoisLookup(domain, timeout = 15000) {
  const clean = domain.replace(/^www\./, '');

  // Source 1: whoisjsonapi.com
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://www.whoisjsonapi.com/v1/${encodeURIComponent(clean)}`, { signal: ctrl.signal, headers: { 'Accept': 'application/json' } });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && j.domain && j.domain.created_date) return { source: 'whoisjsonapi', createdDate: j.domain.created_date, expiresDate: j.domain.expiration_date, registrar: j.registrar && j.registrar.name };
    }
  } catch(e) {}

  // Source 2: rdap.org
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://rdap.org/domain/${encodeURIComponent(clean)}`, { signal: ctrl.signal, headers: { 'Accept': 'application/json' } });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && Array.isArray(j.events)) {
        const reg = j.events.find(e => e.eventAction === 'registration');
        if (reg && reg.eventDate) return { source: 'rdap', createdDate: reg.eventDate };
      }
    }
  } catch(e) {}

  // Source 3: raw whois package
  try {
    const raw = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout')), timeout);
      whois.lookup(clean, (err, data) => { clearTimeout(t); err ? reject(err) : resolve(data); });
    });
    const lines = (raw || '').split('\n');
    for (const line of lines) {
      if (/creation date|created|registered on/i.test(line)) {
        const dateStr = line.split(':').slice(1).join(':').trim();
        const d = new Date(dateStr);
        if (!isNaN(d.getTime())) return { source: 'raw-whois', createdDate: dateStr };
      }
    }
  } catch(e) {}

  return null;
}

function parseWhoisAge(result) {
  if (!result || !result.createdDate) return null;
  const d = new Date(result.createdDate);
  if (isNaN(d.getTime())) return null;
  return Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
}

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /api/fetch?url=...
app.get('/fetch', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'missing url' });
  try {
    const result = await fetchHtml(url);
    const html   = result.text || '';
    const meta   = parseMeta(html, url);
    res.json({ ok: true, htmlSnippet: html.slice(0, 200000), title: meta.title, description: meta.description, favicon: meta.favicon, finalUrl: result.finalUrl });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// GET /api/whois?domain=...
app.get('/whois', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'missing domain' });
  try {
    const result       = await whoisLookup(domain, 15000);
    const domainAgeDays = parseWhoisAge(result);
    res.json({ ok: true, result, domainAgeDays, source: result && result.source });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// GET /api/check?url=...
app.get('/check', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'missing url' });
  try {
    const u        = new URL(url);
    const hostname = u.hostname.toLowerCase();
    const httpsOk  = u.protocol === 'https:';
    const blacklisted = isBlacklisted(hostname);
    const shortened   = isShortener(hostname);

    let resolvedUrl      = url;
    let redirectChain    = [url];
    let resolvedHostname = hostname;
    let resolvedHttpsOk  = httpsOk;

    if (shortened) {
      const redirectResult = await followRedirects(url, 10, 8000);
      resolvedUrl     = redirectResult.finalUrl;
      redirectChain   = redirectResult.chain;
      try {
        const ru        = new URL(resolvedUrl);
        resolvedHostname = ru.hostname.toLowerCase();
        resolvedHttpsOk  = ru.protocol === 'https:';
      } catch(e) {}
    }

    const skipWhois = (hostname === 'localhost' || hostname === '127.0.0.1');

    let html = '', finalUrl = url, reachable = false, statusCode = null;
    let certInfo = { cert: null, certExpiresDays: null, certValid: false };

    const fetchPromise = fetchHtml(url, 8000).catch(() => null);
    const tlsPromise   = httpsOk ? getCertificateInfo(hostname, 443, 4000).catch(() => ({ cert: null, certExpiresDays: null, certValid: false })) : Promise.resolve({ cert: null, certExpiresDays: null, certValid: false });
    const whoisPromise = skipWhois ? Promise.resolve(null) : whoisLookup(resolvedHostname || hostname, 8000).catch(() => null);

    const [fetched, tlsResult, whoisInfo] = await Promise.all([fetchPromise, tlsPromise, whoisPromise]);
    if (fetched) { html = fetched.text || ''; finalUrl = fetched.finalUrl || finalUrl; statusCode = fetched.status || null; reachable = !!fetched.ok; }
    certInfo = tlsResult || certInfo;

    // Content analysis
    const contentFlags = [];
    try {
      const $ = cheerio.load(html || '');
      const TRUSTED_DOMAINS = ['facebook.com','google.com','youtube.com','twitter.com','instagram.com','microsoft.com','apple.com','amazon.com','wikipedia.org','linkedin.com','reddit.com','yahoo.com','netflix.com','github.com','stackoverflow.com','paypal.com','x.com','tiktok.com','discord.com','twitch.tv','spotify.com','dropbox.com'];
      const isTrusted = TRUSTED_DOMAINS.some(d => resolvedHostname === d || resolvedHostname.endsWith('.' + d));
      if (!isTrusted) {
        const highRiskKeywords   = ['ssn', 'social security', 'wire transfer', 'western union'];
        const mediumRiskKeywords = ['verify your account', 'confirm your identity', 'suspended', 'unusual activity', 'click here to restore'];
        const bodyText = ($('body').text() || '').toLowerCase();
        const foundHigh   = highRiskKeywords.filter(k => bodyText.includes(k));
        const foundMedium = mediumRiskKeywords.filter(k => bodyText.includes(k));
        if (foundHigh.length)   contentFlags.push({ type: 'keywords', severity: 'high',   detail: foundHigh.slice(0,5) });
        else if (foundMedium.length) contentFlags.push({ type: 'keywords', severity: 'medium', detail: foundMedium.slice(0,5) });

        const forms = $('form').toArray();
        for (const f of forms) {
          const action = $(f).attr('action') || '';
          if (action) {
            try {
              const actUrl = new URL(action, finalUrl);
              if (actUrl.hostname && actUrl.hostname !== resolvedHostname) contentFlags.push({ type: 'form-external-post', severity: 'high', detail: `form posts to ${actUrl.hostname}` });
            } catch (e) {}
          }
        }
        const scripts = $('script').toArray().map(s => $(s).html() || '');
        const joined  = scripts.join('\n').toLowerCase();
        if (/eval\(|unescape\(|atob\(|fromcharcode\(|document\.write\(/.test(joined)) contentFlags.push({ type: 'obfuscation', severity: 'medium', detail: 'suspicious JS obfuscation detected' });
        if (/[A-Za-z0-9+/]{40,}={0,2}/.test(joined)) contentFlags.push({ type: 'base64-large', severity: 'medium', detail: 'long base64-like string found' });
      }
    } catch (e) {}

    let redirectsToHttp = false;
    try { const fu = new URL(finalUrl); redirectsToHttp = fu.protocol === 'http:' && httpsOk; } catch (e) {}

    const domainAgeDays = whoisInfo ? parseWhoisAge(whoisInfo) : null;

    res.json({ ok: true, reachable, statusCode, httpsOk: resolvedHttpsOk, certValid: certInfo.certValid, certExpiresDays: certInfo.certExpiresDays, redirectsToHttp, blacklisted: isBlacklisted(resolvedHostname) || blacklisted, contentFlags, domainAgeDays, shortened, resolvedUrl: shortened ? resolvedUrl : undefined, redirectChain: shortened && redirectChain.length > 1 ? redirectChain : undefined });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// ── Export as Firebase Cloud Function ─────────────────────────────────────────
exports.api = functions.https.onRequest(app);
