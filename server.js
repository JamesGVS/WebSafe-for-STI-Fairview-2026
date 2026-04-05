const express = require('express');
const fetch = require('node-fetch');
const tls = require('tls');
const cheerio = require('cheerio');
const whois = require('whois');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Serve main.html at root URL
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'main.html')));

// simple request logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()}  ${req.method} ${req.originalUrl}`);
  next();
});

// Simple in-memory blacklist - extend as needed
const BLACKLIST = [
  // Test/example domains
  'example-malicious.com', 'bad-domain.test',
  // Known Philippine phishing domains and patterns
  'gcash-promo.com', 'gcash-verify.net', 'gcash-reward.com',
  'bdo-verify.com', 'bdo-online.net', 'bdo-secure.com',
  'bpi-verify.net', 'bpi-online.xyz', 'bpi-secure.net',
  'metrobank-verify.com', 'metrobank-online.net',
  'pnb-verify.net', 'landbank-verify.com',
  // Common phishing patterns
  'paypal-verify.com', 'paypal-secure.net', 'paypal-login.xyz',
  'facebook-login.xyz', 'fb-verify.com', 'facebook-verify.net',
  'google-verify.net', 'google-account-verify.com',
  'apple-id-verify.com', 'apple-support-verify.net',
  'amazon-verify.net', 'amazon-secure.xyz',
  // Known malware/scam domains
  'free-robux-now.com', 'getrobux.xyz', 'roblox-free.net',
  'claim-prize.xyz', 'you-won.net', 'winner-claim.com',
  'crypto-doubler.com', 'bitcoin-generator.xyz',
  'covid-relief-fund.com', 'stimulus-check.xyz',
  // Typosquatting common sites
  'faceb00k.com', 'gooogle.com', 'paypa1.com', 'amaz0n.com',
  'netfl1x.com', 'yout0be.com', 'twltter.com',
];

function isBlacklisted(hostname) {
  const h = hostname.toLowerCase();
  return BLACKLIST.some(b => h.includes(b));
}

// Known URL shorteners - we always follow these to reveal the real destination
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

// Follow redirects manually to get final destination URL
async function followRedirects(url, maxRedirects = 10, timeout = 10000) {
  let current = url;
  const chain = [url];
  for (let i = 0; i < maxRedirects; i++) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(current, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'WebSafe/1.0' }
      });
      clearTimeout(id);
      const loc = res.headers.get('location');
      if ((res.status >= 300 && res.status < 400) && loc) {
        // Resolve relative redirects
        try { current = new URL(loc, current).href; } catch(e) { current = loc; }
        chain.push(current);
      } else {
        break; // no more redirects
      }
    } catch(e) {
      clearTimeout(id);
      break;
    }
  }
  return { finalUrl: current, chain };
}

async function fetchHtml(url, timeout = 15000) {
  console.log(`fetchHtml: fetching ${url}`);
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: { 'User-Agent': 'WebSafe/1.0 (+https://example.local)', 'Accept-Language': 'en-US,en;q=0.9' },
      signal: controller.signal,
    });
    clearTimeout(id);
    const text = await res.text();
    return { text, finalUrl: res.url, status: res.status, ok: res.ok };
  } catch (err) {
    clearTimeout(id);
    console.error(`fetchHtml error for ${url}:`, err && err.message ? err.message : err);
    throw err;
  }
}

function getCertificateInfo(hostname, port = 443, timeout = 8000) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      try {
        const cert = sock.getPeerCertificate(true) || {};
        const now = Date.now();
        let expires = null;
        let valid = false;
        if (cert && cert.valid_to) {
          const exp = new Date(cert.valid_to);
          if (!Number.isNaN(exp.getTime())) {
            expires = Math.floor((exp.getTime() - now) / (1000 * 60 * 60 * 24));
            valid = exp.getTime() > now;
          }
        }
        resolve({ cert, certExpiresDays: expires, certValid: valid });
      } catch (e) {
        resolve({ cert: null, certExpiresDays: null, certValid: false });
      } finally {
        try { sock.end(); } catch (e) {}
      }
    });
    sock.setTimeout(timeout, () => {
      try { sock.destroy(); } catch (e) {}
      resolve({ cert: null, certExpiresDays: null, certValid: false });
    });
    sock.on('error', () => resolve({ cert: null, certExpiresDays: null, certValid: false }));
  });
}

function parseMeta(html, baseUrl) {
  const $ = cheerio.load(html);
  const title = $('title').first().text().trim() || '';
  const desc = $('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '';
  let icon = $('link[rel~="icon"]').attr('href') || $('link[rel~="shortcut icon"]').attr('href') || '';
  if (icon) {
    try { icon = new URL(icon, baseUrl).href; } catch (e) { }
  }
  return { title, description: desc, favicon: icon };
}

app.get('/api/fetch', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'missing url' });
  try {
    const result = await fetchHtml(url);
    const html = result.text || '';
    const meta = parseMeta(html, url);
    console.log(`/api/fetch OK ${url} title=${meta.title || '(no title)'} finalUrl=${result.finalUrl}`);
    // whois can be slow; do not block basic preview - return minimal, and provide whois endpoint
    res.json({ ok: true, htmlSnippet: html.slice(0, 200000), title: meta.title, description: meta.description, favicon: meta.favicon, finalUrl: result.finalUrl });
  } catch (err) {
    console.warn(`/api/fetch ERROR ${url}:`, err && err.message ? err.message : err);
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// ── Multi-source WHOIS lookup ──────────────────────────────────────────────
// Tries 3 free public APIs in order, falls back to raw whois package last
async function whoisLookup(domain, timeout = 15000) {
  const clean = domain.replace(/^www\./, '');

  // Source 1: whoisjsonapi.com — returns clean JSON
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://www.whoisjsonapi.com/v1/${encodeURIComponent(clean)}`, {
      signal: ctrl.signal,
      headers: { 'Accept': 'application/json' }
    });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && j.domain && j.domain.created_date) {
        console.log(`whois [whoisjsonapi] ${clean}: created=${j.domain.created_date}`);
        return { source: 'whoisjsonapi', createdDate: j.domain.created_date, expiresDate: j.domain.expiration_date, registrar: j.registrar && j.registrar.name };
      }
    }
  } catch(e) { console.log(`whois [whoisjsonapi] ${clean} failed: ${e.message}`); }

  // Source 2: rdap.org — ICANN standardized protocol, very reliable
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://rdap.org/domain/${encodeURIComponent(clean)}`, {
      signal: ctrl.signal,
      headers: { 'Accept': 'application/json' }
    });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && Array.isArray(j.events)) {
        const reg = j.events.find(e => e.eventAction === 'registration');
        if (reg && reg.eventDate) {
          console.log(`whois [rdap] ${clean}: created=${reg.eventDate}`);
          const registrar = j.entities && j.entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'));
          return { source: 'rdap', createdDate: reg.eventDate, registrar: registrar && registrar.vcardArray && registrar.vcardArray[1] && registrar.vcardArray[1].find(v => v[0] === 'fn') && registrar.vcardArray[1].find(v => v[0] === 'fn')[3] };
        }
      }
    }
  } catch(e) { console.log(`whois [rdap] ${clean} failed: ${e.message}`); }

  // Source 3: domainsdb.info — good coverage for many TLDs
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://api.domainsdb.info/v1/domains/search?domain=${encodeURIComponent(clean)}&zone=${clean.split('.').pop()}`, {
      signal: ctrl.signal,
      headers: { 'Accept': 'application/json' }
    });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && Array.isArray(j.domains) && j.domains.length > 0) {
        const match = j.domains.find(d => d.domain === clean) || j.domains[0];
        if (match && match.create_date) {
          console.log(`whois [domainsdb] ${clean}: created=${match.create_date}`);
          return { source: 'domainsdb', createdDate: match.create_date };
        }
      }
    }
  } catch(e) { console.log(`whois [domainsdb] ${clean} failed: ${e.message}`); }

  // Source 4: fallback to raw whois package
  try {
    const raw = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('whois timeout')), timeout);
      whois.lookup(clean, (err, data) => {
        clearTimeout(timer);
        if (err) return reject(err);
        resolve(data || '');
      });
    });
    if (raw) {
      const patterns = [
        /Creation Date:\s*(.+)/i,
        /Created:\s*(.+)/i,
        /Domain Registration Date:\s*(.+)/i,
        /Registered on:\s*(.+)/i,
        /created:\s*(.+)/i,
      ];
      for (const p of patterns) {
        const m = raw.match(p);
        if (m) {
          const dateStr = m[1].trim();
          const d = new Date(dateStr);
          if (!isNaN(d.getTime())) {
            console.log(`whois [raw] ${clean}: created=${dateStr}`);
            return { source: 'raw-whois', createdDate: dateStr };
          }
        }
      }
    }
  } catch(e) { console.log(`whois [raw] ${clean} failed: ${e.message}`); }

  console.log(`whois ${clean}: all sources failed`);
  return null;
}

function parseWhoisAge(result) {
  if (!result || !result.createdDate) return null;
  const d = new Date(result.createdDate);
  if (isNaN(d.getTime())) return null;
  return Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
}

app.get('/api/whois', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'missing domain' });
  try {
    console.log(`/api/whois ${domain}`);
    const result = await whoisLookup(domain, 15000);
    const domainAgeDays = parseWhoisAge(result);
    res.json({ ok: true, result, domainAgeDays, source: result && result.source });
  } catch (err) {
    console.warn(`/api/whois ERROR ${domain}:`, err && err.message ? err.message : err);
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// convenience endpoint for server-side safety checks
app.get('/api/check', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'missing url' });
  try {
    const start = Date.now();
    console.log(`/api/check ${url}`);
    const u = new URL(url);
    const hostname = u.hostname.toLowerCase();
    const httpsOk = u.protocol === 'https:';
    const blacklisted = isBlacklisted(hostname);
    const shortened = isShortener(hostname);

    // If it's a shortener, follow the redirect chain first to get the real URL
    let resolvedUrl = url;
    let redirectChain = [url];
    let resolvedHostname = hostname;
    let resolvedHttpsOk = httpsOk;
    if (shortened) {
      console.log(`/api/check shortener detected: ${hostname} — following redirects`);
      const redirectResult = await followRedirects(url, 10, 8000);
      resolvedUrl = redirectResult.finalUrl;
      redirectChain = redirectResult.chain;
      try {
        const ru = new URL(resolvedUrl);
        resolvedHostname = ru.hostname.toLowerCase();
        resolvedHttpsOk = ru.protocol === 'https:';
      } catch(e) {}
      console.log(`/api/check shortener resolved: ${url} → ${resolvedUrl}`);
    }

    // Shorter timeouts
    const fetchTimeout = 8000;
    const tlsTimeout = 4000;
    const whoisTimeout = 8000;

    // Well-known domains to skip WHOIS
    // Only skip localhost — all real domains get WHOIS checked
    const skipWhois = (hostname === 'localhost' || hostname === '127.0.0.1');

    // Parallel fetch and TLS
    let html = '';
    let finalUrl = url;
    let reachable = false;
    let statusCode = null;
    let certInfo = { cert: null, certExpiresDays: null, certValid: false };
    // Run fetch, TLS, and WHOIS all in parallel — WHOIS no longer waits for fetch to finish
    const fetchPromise = fetchHtml(url, fetchTimeout).catch(() => null);
    const tlsPromise   = httpsOk ? getCertificateInfo(hostname, 443, tlsTimeout).catch(() => ({ cert: null, certExpiresDays: null, certValid: false })) : Promise.resolve({ cert: null, certExpiresDays: null, certValid: false });
    const whoisPromise = skipWhois ? Promise.resolve(null) : whoisLookup(resolvedHostname || hostname, whoisTimeout).catch(() => null);

    // Wait for fetch, TLS, and WHOIS all at once
    const [fetched, tlsResult, whoisInfo] = await Promise.all([fetchPromise, tlsPromise, whoisPromise]);
    if (fetched) {
      html = fetched.text || '';
      finalUrl = fetched.finalUrl || finalUrl;
      statusCode = fetched.status || null;
      reachable = !!fetched.ok;
    }
    certInfo = tlsResult || certInfo;

    // Content analysis
    const contentFlags = [];
    try {
      const $ = cheerio.load(html || '');
      // Trusted domains — skip aggressive keyword flagging for these
      const TRUSTED_DOMAINS = [
        'facebook.com', 'google.com', 'youtube.com', 'twitter.com', 'instagram.com',
        'microsoft.com', 'apple.com', 'amazon.com', 'wikipedia.org', 'linkedin.com',
        'reddit.com', 'yahoo.com', 'netflix.com', 'github.com', 'stackoverflow.com',
        'paypal.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'x.com',
        'tiktok.com', 'discord.com', 'twitch.tv', 'spotify.com', 'dropbox.com'
      ];
      const isTrusted = TRUSTED_DOMAINS.some(d => resolvedHostname === d || resolvedHostname.endsWith('.' + d));

      if (!isTrusted) {
        // Only flag keywords on unknown/untrusted domains
        // Use more suspicious keywords — generic "login" alone is not enough
        const highRiskKeywords = ['ssn', 'social security', 'wire transfer', 'western union'];
        const mediumRiskKeywords = ['verify your account', 'confirm your identity', 'suspended', 'unusual activity', 'click here to restore'];
        const bodyText = ($('body').text() || '').toLowerCase();

        const foundHigh = highRiskKeywords.filter(k => bodyText.includes(k));
        const foundMedium = mediumRiskKeywords.filter(k => bodyText.includes(k));

        if (foundHigh.length) {
          contentFlags.push({ type: 'keywords', severity: 'high', detail: foundHigh.slice(0, 5) });
        } else if (foundMedium.length) {
          contentFlags.push({ type: 'keywords', severity: 'medium', detail: foundMedium.slice(0, 5) });
        }
      }
      if (!isTrusted) {
        const forms = $('form').toArray();
        for (const f of forms) {
          const action = $(f).attr('action') || '';
          if (action) {
            try {
              const actUrl = new URL(action, finalUrl);
              if (actUrl.hostname && actUrl.hostname !== resolvedHostname) {
                contentFlags.push({ type: 'form-external-post', severity: 'high', detail: `form posts to ${actUrl.hostname}` });
              }
            } catch (e) {}
          }
        }
      }
      if (!isTrusted) {
        const scripts = $('script').toArray().map(s => $(s).html() || '');
        const joined = scripts.join('\n').toLowerCase();
        if (/eval\(|unescape\(|atob\(|fromcharcode\(|document\.write\(/.test(joined)) {
          contentFlags.push({ type: 'obfuscation', severity: 'medium', detail: 'suspicious JS obfuscation detected' });
        }
        if (/[A-Za-z0-9+/]{40,}={0,2}/.test(joined)) {
          contentFlags.push({ type: 'base64-large', severity: 'medium', detail: 'long base64-like string found' });
        }
      }
    } catch (e) {}

    // Redirects to HTTP
    let redirectsToHttp = false;
    try {
      const fu = new URL(finalUrl);
      redirectsToHttp = fu.protocol === 'http:' && httpsOk;
    } catch (e) {}

    // WHOIS already completed in parallel above
    let domainAgeDays = null;
    const whoisDuration = 0; // runs in parallel now, not sequential
    if (whoisInfo) {
      domainAgeDays = parseWhoisAge(whoisInfo);
      console.log(`whois result for ${resolvedHostname || hostname}: ageDays=${domainAgeDays}`);
    }

    // Duration logging
    const totalDuration = Date.now() - start;
    console.log(`/api/check result ${url} total=${totalDuration}ms fetch+tls=${totalDuration-whoisDuration}ms whois=${whoisDuration}ms reachable=${reachable} https=${httpsOk} certValid=${certInfo.certValid} redirectsToHttp=${redirectsToHttp} blacklisted=${blacklisted} domainAgeDays=${domainAgeDays} contentFlags=${contentFlags.length}`);
    res.json({ ok: true, reachable, statusCode, httpsOk: resolvedHttpsOk, certValid: certInfo.certValid, certExpiresDays: certInfo.certExpiresDays, redirectsToHttp, blacklisted: isBlacklisted(resolvedHostname) || blacklisted, contentFlags, domainAgeDays, totalDuration, whoisDuration, shortened, resolvedUrl: shortened ? resolvedUrl : undefined, redirectChain: shortened && redirectChain.length > 1 ? redirectChain : undefined });
  } catch (err) {
    console.warn(`/api/check ERROR ${url}:`, err && err.message ? err.message : err);
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.listen(PORT, () => {
  const url = `http://localhost:${PORT}/main.html`;
  console.log(`\nWebSafe server running!`);
  console.log(`Open: ${url}\n`);
  const { exec } = require('child_process');
  const cmd =
    process.platform === 'win32'  ? `start "" "${url}"` :
    process.platform === 'darwin' ? `open "${url}"` :
                                    `xdg-open "${url}"`;
  exec(cmd, err => {
    if (err) console.log('(Could not auto-open browser — visit the URL above manually)');
  });
});