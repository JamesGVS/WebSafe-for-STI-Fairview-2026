// server.js — WebSafe v6 HARDENED
// Multi-layer phishing/scam detection engine
// Fixes: false negatives on known bad domains, weak scoring, shallow content checks

const express  = require('express');
const fetch    = require('node-fetch');
const tls      = require('tls');
const cheerio  = require('cheerio');
const whois    = require('whois');
const path     = require('path');
const cors     = require('cors');
const dns      = require('dns').promises;

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'main.html')));
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()}  ${req.method} ${req.originalUrl}`);
  next();
});

// ════════════════════════════════════════════════════════════════════════════
// SECTION 1 — BLACKLISTS & PATTERN DETECTION
// ════════════════════════════════════════════════════════════════════════════

// Hard blacklist: exact hostnames known to be malicious
const HARD_BLACKLIST = new Set([
  // Test/example
  'example-malicious.com','bad-domain.test',
  // PH banking phishing
  'gcash-promo.com','gcash-verify.net','gcash-reward.com','gcash-login.net','gcash-update.com',
  'bdo-verify.com','bdo-online.net','bdo-secure.com','bdo-login.net','bdo-alert.com',
  'bpi-verify.net','bpi-online.xyz','bpi-secure.net','bpi-login.xyz','bpi-alert.net',
  'metrobank-verify.com','metrobank-online.net','metrobank-login.xyz',
  'pnb-verify.net','landbank-verify.com','unionbank-verify.net','rcbc-verify.com',
  'ewallet-gcash.com','paymaya-verify.net','maya-promo.xyz',
  // Global bank phishing
  'paypal-verify.com','paypal-secure.net','paypal-login.xyz','paypal-update.net',
  'paypal-account-verify.com','paypal-resolution.net','paypal-billing.xyz',
  // Social media phishing
  'facebook-login.xyz','fb-verify.com','facebook-verify.net','fb-login.net',
  'facebook-security.xyz','instagram-verify.net','instagram-login.xyz',
  'twitter-verify.net','twitterlogin.xyz','x-verify.net',
  // Tech giant phishing
  'google-verify.net','google-account-verify.com','google-security.xyz',
  'apple-id-verify.com','apple-support-verify.net','apple-id-login.xyz',
  'microsoft-verify.net','microsoft-account-login.xyz','microsoftsupport.xyz',
  'amazon-verify.net','amazon-secure.xyz','amazon-account-verify.com',
  // Scam/prize sites
  'free-robux-now.com','getrobux.xyz','roblox-free.net',
  'claim-prize.xyz','you-won.net','winner-claim.com','prize-claim.xyz',
  'crypto-doubler.com','bitcoin-generator.xyz','eth-doubler.net',
  'covid-relief-fund.com','stimulus-check.xyz',
  // Typosquatting
  'faceb00k.com','gooogle.com','paypa1.com','amaz0n.com',
  'netfl1x.com','yout0be.com','twltter.com','lnstagram.com',
  'gogle.com','goggle.com','micosoft.com','arnazon.com',
]);

// Partial match patterns: if any appear anywhere in the hostname, flag it
const SUSPICIOUS_PATTERNS = [
  // Brand impersonation with action words
  /\b(gcash|bdo|bpi|metrobank|landbank|unionbank|rcbc|pnb|paymaya|maya)\b.*(verify|login|secure|update|promo|reward|alert|confirm|suspend|restore|unlock)/i,
  /\b(paypal|stripe|square)\b.*(verify|login|secure|update|confirm|suspend|restore|billing)/i,
  /\b(google|gmail|youtube)\b.*(verify|login|secure|update|confirm|suspend|alert)/i,
  /\b(facebook|instagram|twitter|tiktok)\b.*(verify|login|secure|update|confirm|suspend)/i,
  /\b(apple|icloud|itunes)\b.*(verify|login|secure|update|confirm|suspend|id-)/i,
  /\b(microsoft|outlook|office365|onedrive)\b.*(verify|login|secure|update|confirm)/i,
  /\b(amazon|aws|prime)\b.*(verify|login|secure|update|confirm|suspend)/i,
  /\b(netflix|spotify|hulu|disney)\b.*(verify|login|secure|update|confirm|billing)/i,
  /\b(bank|banking)\b.*(verify|login|secure|update|confirm|alert)/i,
  // Deceptive TLD combos for trusted brands
  /(paypal|google|facebook|amazon|apple|microsoft|netflix|instagram)\.(xyz|top|club|online|site|space|fun|info|live|store|shop|bid|win|gq|ml|cf|ga|tk)/i,
  // Numeric homoglyph substitution in popular brands
  /(g[o0]{2}gle|f[a@]ceb[o0]{2}k|tw[i1]tter|[i1]nstagram|am[a@]z[o0]n|p[a@]yp[a@]l)/i,
  // Subdomain stuffing trick: real brand as subdomain of malicious domain
  /^(paypal|google|facebook|amazon|apple|microsoft|netflix|instagram|gcash|bdo|bpi)\..+\.(com|net|org|xyz|top)\./i,
  // Common scam subdomains
  /^(secure|login|verify|account|update|billing|support|alert|confirm|restore|unlock|helpdesk)\./i,
  // Lookalike / combosquatting suffixes
  /-(verify|login|secure|update|account|billing|support|alert|confirm|restore|help|official|online|web|portal|service|center|access)(\.|$)/i,
  // Crypto scam patterns
  /(bitcoin|crypto|nft|token|wallet|defi|web3).*(free|giveaway|doubler|generator|claim|earn|airdrop)/i,
  // Prize / lottery scams
  /(prize|promo|reward|winner|claim|lottery|won|congrats).*(claim|click|collect|verify|fill|form)/i,
  // Free giveaway bait
  /^(free|get|claim|win|earn|bonus)[-.]?(robux|vbucks|diamonds|coins|gems|credits)/i,
];

// Trusted brands that should ONLY appear on their own domains
// Used to detect spoofing (e.g. "gcash" in domain but not gcash.com)
const BRAND_LEGITIMATE_DOMAINS = {
  gcash:      ['gcash.com'],
  bdo:        ['bdo.com.ph'],
  bpi:        ['bpi.com.ph','bpiexpressonline.com'],
  metrobank:  ['metrobank.com.ph','mbtc.com.ph'],
  landbank:   ['landbank.com'],
  unionbank:  ['unionbankph.com'],
  rcbc:       ['rcbc.com'],
  paymaya:    ['paymaya.com','maya.ph'],
  paypal:     ['paypal.com'],
  google:     ['google.com','accounts.google.com','googleapis.com'],
  gmail:      ['gmail.com','google.com'],
  facebook:   ['facebook.com','fb.com','fbcdn.net'],
  instagram:  ['instagram.com'],
  twitter:    ['twitter.com','x.com','t.co'],
  tiktok:     ['tiktok.com'],
  apple:      ['apple.com','icloud.com','appleid.apple.com'],
  microsoft:  ['microsoft.com','live.com','outlook.com','office.com'],
  amazon:     ['amazon.com','aws.amazon.com','prime.amazon.com'],
  netflix:    ['netflix.com'],
  spotify:    ['spotify.com'],
};

/**
 * Deep hostname analysis.
 * Returns { hardBlacklisted, patternMatch, brandSpoof, spoofedBrand }
 */
function analyzeHostname(hostname) {
  const h = hostname.toLowerCase().replace(/^www\./, '');

  // 1. Hard blacklist check
  if (HARD_BLACKLIST.has(h)) {
    return { hardBlacklisted: true, patternMatch: false, brandSpoof: false };
  }

  // 2. Check subdomain tree (e.g. www.gcash-verify.net → flag gcash-verify.net)
  const parts = h.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const sub = parts.slice(i).join('.');
    if (HARD_BLACKLIST.has(sub)) return { hardBlacklisted: true, patternMatch: false, brandSpoof: false };
  }

  // 3. Pattern matching
  const patternMatch = SUSPICIOUS_PATTERNS.some(p => p.test(h));

  // 4. Brand spoofing: brand keyword in domain but not on the real domain
  let brandSpoof = false;
  let spoofedBrand = null;
  for (const [brand, legitimateDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
    const brandRegex = new RegExp(`\\b${brand}\\b`, 'i');
    if (brandRegex.test(h)) {
      const isLegit = legitimateDomains.some(d => h === d || h.endsWith('.' + d));
      if (!isLegit) {
        brandSpoof = true;
        spoofedBrand = brand;
        break;
      }
    }
  }

  return { hardBlacklisted: false, patternMatch, brandSpoof, spoofedBrand };
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 2 — URL STRUCTURE ANALYSIS
// ════════════════════════════════════════════════════════════════════════════

/**
 * Deep URL structural analysis for phishing signals.
 */
function analyzeUrlStructure(urlStr) {
  const flags = [];
  let parsed;
  try { parsed = new URL(urlStr); } catch(e) { return flags; }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = urlStr.toLowerCase();

  // Excessive subdomains (phishers use: secure.login.verify.bank.malicious.com)
  const labels = hostname.split('.');
  if (labels.length >= 5) {
    flags.push({ type: 'excessive-subdomains', severity: 'high',
      detail: `Unusually deep subdomain chain (${labels.length} levels) — common phishing trick` });
  }

  // Brand keyword in subdomain but real domain is suspicious
  const tldPlusOne = labels.slice(-2).join('.'); // e.g. "malicious.com"
  const subdomains = labels.slice(0, -2).join('.'); // everything before
  for (const [brand, legitimateDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
    if (new RegExp(`\\b${brand}\\b`, 'i').test(subdomains)) {
      const isLegit = legitimateDomains.some(d => hostname === d || hostname.endsWith('.' + d));
      if (!isLegit) {
        flags.push({ type: 'brand-in-subdomain', severity: 'high',
          detail: `"${brand}" used as subdomain on unrelated domain "${tldPlusOne}" — classic phishing` });
      }
    }
  }

  // IP address instead of domain name
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    flags.push({ type: 'ip-address', severity: 'high',
      detail: 'URL uses a raw IP address instead of a domain name — almost always malicious' });
  }

  // Very long URLs (phishing URLs are often obfuscated with long paths)
  if (urlStr.length > 150) {
    flags.push({ type: 'long-url', severity: 'medium',
      detail: `Unusually long URL (${urlStr.length} characters) — often used to hide the real destination` });
  }

  // @ symbol in URL (classic trick: https://google.com@evil.com)
  if (fullUrl.includes('@')) {
    flags.push({ type: 'at-sign-url', severity: 'high',
      detail: 'URL contains an @ sign — this can be used to disguise the real destination' });
  }

  // Multiple dashes in domain (e.g. secure-login-verify-paypal.xyz)
  const dashCount = (hostname.match(/-/g) || []).length;
  if (dashCount >= 3) {
    flags.push({ type: 'dash-heavy-domain', severity: 'medium',
      detail: `Domain has ${dashCount} dashes — over-hyphenated domains are common in phishing` });
  }

  // Suspicious TLD
  const SUSPICIOUS_TLDS = ['xyz','top','club','online','site','space','fun','live','store',
    'shop','bid','win','gq','ml','cf','ga','tk','pw','cc','su','icu','vip','loan','work',
    'click','link','zip','mov','date','download','review'];
  const tld = labels[labels.length - 1];
  if (SUSPICIOUS_TLDS.includes(tld)) {
    flags.push({ type: 'suspicious-tld', severity: 'medium',
      detail: `".${tld}" domains are frequently abused for phishing and scams` });
  }

  // Encoded characters in hostname (deception)
  if (/%[0-9a-f]{2}/i.test(hostname)) {
    flags.push({ type: 'encoded-hostname', severity: 'high',
      detail: 'Hostname contains percent-encoded characters — often used to disguise malicious URLs' });
  }

  // Data URI or javascript: protocol
  if (/^(data:|javascript:|vbscript:)/i.test(urlStr)) {
    flags.push({ type: 'dangerous-protocol', severity: 'high',
      detail: 'URL uses a dangerous protocol (data:, javascript:, or vbscript:)' });
  }

  return flags;
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 3 — CONTENT ANALYSIS (deep)
// ════════════════════════════════════════════════════════════════════════════

// Trusted domains — less aggressive content scanning
const TRUSTED_DOMAINS = new Set([
  'facebook.com','google.com','youtube.com','twitter.com','instagram.com',
  'microsoft.com','apple.com','amazon.com','wikipedia.org','linkedin.com',
  'reddit.com','yahoo.com','netflix.com','github.com','stackoverflow.com',
  'paypal.com','bankofamerica.com','chase.com','wellsfargo.com','x.com',
  'tiktok.com','discord.com','twitch.tv','spotify.com','dropbox.com',
  'gcash.com','bdo.com.ph','bpi.com.ph','metrobank.com.ph','landbank.com',
  'unionbankph.com','rcbc.com','paymaya.com','maya.ph',
]);

function isTrustedDomain(hostname) {
  const h = hostname.toLowerCase().replace(/^www\./, '');
  return TRUSTED_DOMAINS.has(h) || [...TRUSTED_DOMAINS].some(d => h.endsWith('.' + d));
}

// High-confidence phishing phrases — these in isolation on an unknown site are very suspicious
const HIGH_RISK_PHRASES = [
  'enter your social security','social security number','ssn','wire transfer now',
  'western union','moneygram','send money to verify','bitcoin payment required',
  'your account has been suspended','account will be terminated','verify now to avoid suspension',
  'click here to restore access','update your billing immediately','your card has been declined',
  'unusual activity detected','unauthorized access attempt','one-time password expired',
  'confirm your identity to continue','we have detected suspicious','limited time to respond',
  'your account is at risk','action required immediately','failure to comply will result',
];

// Medium-risk: common in phishing but also in legit sites
const MEDIUM_RISK_PHRASES = [
  'verify your account','confirm your identity','account suspended',
  'click here to verify','validate your information','confirm billing',
  'your password has expired','update payment details','reactivate your account',
  'unusual sign-in activity','verify your email address',
];

// Password field harvesting: multiple password inputs = credential phishing
// Brand impersonation in page title or headings
function deepContentAnalysis(html, hostname, finalUrl) {
  const flags = [];
  if (!html || html.length < 50) return flags;

  const isTrusted = isTrustedDomain(hostname);
  if (isTrusted) return flags; // trusted domains: skip aggressive scanning

  let $;
  try { $ = cheerio.load(html); } catch(e) { return flags; }

  const bodyText = ($('body').text() || '').toLowerCase().replace(/\s+/g, ' ');
  const titleText = ($('title').text() || '').toLowerCase();
  const fullText = bodyText + ' ' + titleText;

  // 1. High-risk keyword scanning
  const foundHigh = HIGH_RISK_PHRASES.filter(k => fullText.includes(k.toLowerCase()));
  if (foundHigh.length >= 2) {
    flags.push({ type: 'keywords-high', severity: 'high', detail: foundHigh.slice(0, 4) });
  } else if (foundHigh.length === 1) {
    flags.push({ type: 'keywords-high', severity: 'medium', detail: foundHigh });
  }

  // 2. Medium-risk keywords
  const foundMedium = MEDIUM_RISK_PHRASES.filter(k => fullText.includes(k.toLowerCase()));
  if (foundMedium.length >= 2) {
    flags.push({ type: 'keywords-medium', severity: 'medium', detail: foundMedium.slice(0, 4) });
  }

  // 3. Brand impersonation in title/heading
  for (const [brand, legitimateDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
    const brandRegex = new RegExp(`\\b${brand}\\b`, 'i');
    const isLegit = legitimateDomains.some(d => hostname === d || hostname.endsWith('.' + d));
    if (!isLegit) {
      const inTitle   = brandRegex.test(titleText);
      const inHeading = $('h1,h2,h3').toArray().some(el => brandRegex.test($(el).text()));
      if (inTitle || inHeading) {
        flags.push({ type: 'brand-impersonation', severity: 'high',
          detail: `Page claims to be "${brand}" but is hosted on "${hostname}" — strong phishing indicator` });
        break; // one is enough
      }
    }
  }

  // 4. Multiple password fields (credential harvesting)
  const pwFields = $('input[type="password"]').length;
  if (pwFields >= 2) {
    flags.push({ type: 'multiple-password-fields', severity: 'high',
      detail: `Page has ${pwFields} password fields — possibly harvesting credentials` });
  }

  // 5. External form action (submitting to a different domain)
  const finalHostname = (() => { try { return new URL(finalUrl).hostname.toLowerCase(); } catch(e) { return hostname; } })();
  $('form').each((_, f) => {
    const action = $(f).attr('action') || '';
    if (!action || action.startsWith('#') || action.startsWith('javascript')) return;
    try {
      const actUrl = new URL(action, finalUrl);
      if (actUrl.hostname && actUrl.hostname !== finalHostname && actUrl.hostname !== hostname) {
        flags.push({ type: 'form-external-post', severity: 'high',
          detail: `Form submits to "${actUrl.hostname}" — credentials go to a different server` });
      }
    } catch(e) {}
  });

  // 6. JavaScript obfuscation
  const scripts = $('script').toArray().map(s => $(s).html() || '').join('\n');
  const scriptLow = scripts.toLowerCase();
  const obfuscationPatterns = [
    { re: /eval\s*\(/, label: 'eval()' },
    { re: /document\.write\s*\(/, label: 'document.write()' },
    { re: /unescape\s*\(/, label: 'unescape()' },
    { re: /String\.fromCharCode\s*\(/i, label: 'fromCharCode()' },
    { re: /atob\s*\(/, label: 'atob()' },
  ];
  const obfuscationFound = obfuscationPatterns.filter(p => p.re.test(scriptLow)).map(p => p.label);
  if (obfuscationFound.length >= 2) {
    flags.push({ type: 'obfuscation', severity: 'medium',
      detail: `Suspicious JS techniques detected: ${obfuscationFound.join(', ')} — common in malicious pages` });
  }

  // 7. Large base64 blobs (hidden payloads)
  const base64Matches = (scripts.match(/[A-Za-z0-9+/]{80,}={0,2}/g) || []);
  if (base64Matches.length >= 2) {
    flags.push({ type: 'base64-payload', severity: 'medium',
      detail: `${base64Matches.length} large encoded data blobs found — may be hiding malicious content` });
  }

  // 8. Invisible/hidden iframes pointing to external domains
  $('iframe').each((_, el) => {
    const src   = $(el).attr('src') || '';
    const style = ($(el).attr('style') || '').toLowerCase();
    const hidden = style.includes('display:none') || style.includes('display: none') ||
                   style.includes('visibility:hidden') || style.includes('width:0') || style.includes('height:0');
    if (hidden && src) {
      flags.push({ type: 'hidden-iframe', severity: 'high',
        detail: `Hidden iframe loading "${src}" — can be used for clickjacking or silent redirects` });
    }
  });

  // 9. Auto-redirect / meta refresh
  $('meta[http-equiv]').each((_, el) => {
    const equiv   = ($(el).attr('http-equiv') || '').toLowerCase();
    const content = $(el).attr('content') || '';
    if (equiv === 'refresh' && /url=/i.test(content)) {
      const dest = content.replace(/.*url=/i, '').trim();
      try {
        const destHost = new URL(dest, finalUrl).hostname.toLowerCase();
        if (destHost !== hostname && destHost !== finalHostname) {
          flags.push({ type: 'meta-redirect', severity: 'high',
            detail: `Page silently redirects to "${destHost}" — common in phishing relay pages` });
        }
      } catch(e) {}
    }
  });

  // 10. Fake security badges (scammers copy trust badges)
  const securityBadgeKeywords = ['mcafee secure','norton secured','ssl secured','verified by visa',
    'security verified','100% safe','your information is safe'];
  const badgesFound = securityBadgeKeywords.filter(b => fullText.includes(b));
  if (badgesFound.length >= 2) {
    flags.push({ type: 'fake-trust-badges', severity: 'medium',
      detail: 'Page uses multiple "security verified" claims — commonly faked on scam sites to build false trust' });
  }

  return flags;
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 4 — NETWORK HELPERS (unchanged from v5, plus DNS check)
// ════════════════════════════════════════════════════════════════════════════

const URL_SHORTENERS = [
  'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd',
  'buff.ly','rebrand.ly','short.link','tiny.cc','bl.ink',
  'cutt.ly','rb.gy','shorturl.at','snip.ly','clicky.me',
  'bit.do','t2mio.com','link.tl','trib.al','shorte.st',
  's.id','v.gd','urlz.fr','x.co','u.to',
];

function isShortener(hostname) {
  const h = hostname.toLowerCase().replace(/^www\./, '');
  return URL_SHORTENERS.some(s => h === s || h.endsWith('.' + s));
}

async function followRedirects(url, maxRedirects = 10, timeout = 10000) {
  let current = url;
  const chain = [url];
  for (let i = 0; i < maxRedirects; i++) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(current, {
        method: 'HEAD', redirect: 'manual', signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebSafe/6.0)' }
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

async function fetchHtml(url, timeout = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
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

function getCertificateInfo(hostname, port = 443, timeout = 8000) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      try {
        const cert = sock.getPeerCertificate(true) || {};
        const now  = Date.now();
        let expires = null, valid = false, selfSigned = false;
        if (cert && cert.valid_to) {
          const exp = new Date(cert.valid_to);
          if (!Number.isNaN(exp.getTime())) {
            expires = Math.floor((exp.getTime() - now) / (1000 * 60 * 60 * 24));
            valid   = exp.getTime() > now;
          }
        }
        // Self-signed: issuer === subject
        if (cert && cert.issuer && cert.subject) {
          selfSigned = JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);
        }
        const issuer = cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || '') : '';
        resolve({ cert, certExpiresDays: expires, certValid: valid, selfSigned, issuer });
      } catch (e) {
        resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' });
      } finally {
        try { sock.end(); } catch (e) {}
      }
    });
    sock.setTimeout(timeout, () => { try { sock.destroy(); } catch(e) {} resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }); });
    sock.on('error', () => resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }));
  });
}

/**
 * DNS reputation check: look for known malicious nameservers / hosting patterns
 */
async function checkDnsReputation(hostname) {
  const flags = [];
  const clean = hostname.replace(/^www\./, '');
  try {
    const addresses = await dns.resolve4(clean).catch(() => []);
    // No-IP / dynamic DNS abuse
    const dynamicDnsProviders = ['no-ip.com','ddns.net','dyndns.org','changeip.com',
      'hopto.org','sytes.net','zapto.org','myftp.org','serveblog.net',
      'freedns.afraid.org','duckdns.org'];
    const cnameRecords = await dns.resolveCname(clean).catch(() => []);
    for (const cname of cnameRecords) {
      if (dynamicDnsProviders.some(d => cname.endsWith(d))) {
        flags.push({ type: 'dynamic-dns', severity: 'medium',
          detail: `Domain uses a free dynamic DNS service (${cname}) — frequently abused in phishing` });
      }
    }
    // Bulletproof / anonymous hosting IP ranges
    // Common scam hosting: raw IP check
    if (addresses.length > 0) {
      const ip = addresses[0];
      // 185.x.x.x range is notoriously used for scam hosting
      if (ip.startsWith('185.')) {
        flags.push({ type: 'suspicious-hosting', severity: 'low',
          detail: `Hosted on IP block (${ip}) commonly associated with bulletproof hosting` });
      }
    }
  } catch(e) {}
  return flags;
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 5 — WHOIS LOOKUP (unchanged multi-source approach from v5)
// ════════════════════════════════════════════════════════════════════════════

async function whoisLookup(domain, timeout = 15000) {
  const clean = domain.replace(/^www\./, '');

  // Source 1: whoisjsonapi.com
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://www.whoisjsonapi.com/v1/${encodeURIComponent(clean)}`, {
      signal: ctrl.signal, headers: { 'Accept': 'application/json' }
    });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && j.domain && j.domain.created_date) {
        return { source: 'whoisjsonapi', createdDate: j.domain.created_date, expiresDate: j.domain.expiration_date, registrar: j.registrar && j.registrar.name };
      }
    }
  } catch(e) {}

  // Source 2: rdap.org
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://rdap.org/domain/${encodeURIComponent(clean)}`, {
      signal: ctrl.signal, headers: { 'Accept': 'application/json' }
    });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && Array.isArray(j.events)) {
        const reg = j.events.find(e => e.eventAction === 'registration');
        if (reg && reg.eventDate) {
          const registrar = j.entities && j.entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'));
          return { source: 'rdap', createdDate: reg.eventDate,
            registrar: registrar && registrar.vcardArray && registrar.vcardArray[1] && registrar.vcardArray[1].find(v => v[0] === 'fn') && registrar.vcardArray[1].find(v => v[0] === 'fn')[3] };
        }
      }
    }
  } catch(e) {}

  // Source 3: domainsdb.info
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    const res  = await fetch(`https://api.domainsdb.info/v1/domains/search?domain=${encodeURIComponent(clean)}&zone=${clean.split('.').pop()}`, {
      signal: ctrl.signal, headers: { 'Accept': 'application/json' }
    });
    clearTimeout(tid);
    if (res.ok) {
      const j = await res.json();
      if (j && Array.isArray(j.domains) && j.domains.length > 0) {
        const match = j.domains.find(d => d.domain === clean) || j.domains[0];
        if (match && match.create_date) {
          return { source: 'domainsdb', createdDate: match.create_date };
        }
      }
    }
  } catch(e) {}

  // Source 4: raw whois
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
      const patterns = [/Creation Date:\s*(.+)/i,/Created:\s*(.+)/i,/Domain Registration Date:\s*(.+)/i,/Registered on:\s*(.+)/i,/created:\s*(.+)/i];
      for (const p of patterns) {
        const m = raw.match(p);
        if (m) {
          const d = new Date(m[1].trim());
          if (!isNaN(d.getTime())) return { source: 'raw-whois', createdDate: m[1].trim() };
        }
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

function parseMeta(html, baseUrl) {
  const $ = cheerio.load(html);
  const title = $('title').first().text().trim() || '';
  const desc  = $('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '';
  let icon    = $('link[rel~="icon"]').attr('href') || $('link[rel~="shortcut icon"]').attr('href') || '';
  if (icon) { try { icon = new URL(icon, baseUrl).href; } catch(e) {} }
  return { title, description: desc, favicon: icon };
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 6 — SCORING ENGINE (weighted, no false-safe clamping)
// ════════════════════════════════════════════════════════════════════════════

/**
 * Calculate a final risk score (0–100, where 100 = safest).
 * Each signal contributes a penalty; score starts at 100 and is deducted.
 * This avoids the v5 bug where a site with multiple red flags still scored 50+.
 */
function calculateRiskScore(signals) {
  let score = 100;

  // Instant disqualifiers (hard blacklist, brand spoofing)
  if (signals.hardBlacklisted)           score -= 80;
  if (signals.brandSpoof)                score -= 60;
  if (signals.patternMatch)              score -= 40;

  // URL structure
  if (signals.urlFlags) {
    for (const f of signals.urlFlags) {
      if (f.severity === 'high')   score -= 25;
      if (f.severity === 'medium') score -= 12;
      if (f.severity === 'low')    score -= 5;
    }
  }

  // Network / certificate
  if (!signals.httpsOk)              score -= 30;
  if (!signals.certValid)            score -= 25;
  if (signals.selfSignedCert)        score -= 20;
  if (signals.redirectsToHttp)       score -= 20;
  if (signals.certExpiresSoon)       score -= 10; // expires in <14 days

  // Domain age
  if (signals.domainAgeDays !== null) {
    if (signals.domainAgeDays < 7)        score -= 40;
    else if (signals.domainAgeDays < 30)  score -= 25;
    else if (signals.domainAgeDays < 90)  score -= 10;
    else if (signals.domainAgeDays < 180) score -= 5;
  } else {
    score -= 8; // unknown age = slight penalty
  }

  // Content analysis
  if (signals.contentFlags) {
    for (const f of signals.contentFlags) {
      if (f.type === 'brand-impersonation')       score -= 35;
      if (f.type === 'keywords-high')             score -= f.severity === 'high' ? 25 : 15;
      if (f.type === 'keywords-medium')           score -= 10;
      if (f.type === 'multiple-password-fields')  score -= 15;
      if (f.type === 'form-external-post')        score -= 20;
      if (f.type === 'hidden-iframe')             score -= 20;
      if (f.type === 'meta-redirect')             score -= 15;
      if (f.type === 'obfuscation')               score -= 10;
      if (f.type === 'base64-payload')            score -= 8;
      if (f.type === 'fake-trust-badges')         score -= 5;
    }
  }

  // DNS signals
  if (signals.dnsFlags) {
    for (const f of signals.dnsFlags) {
      if (f.severity === 'high')   score -= 20;
      if (f.severity === 'medium') score -= 10;
      if (f.severity === 'low')    score -= 5;
    }
  }

  // Site not reachable
  if (signals.reachable === false) score -= 15;

  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Determine verdict level from score + hard signals.
 * No more false "safe" for blacklisted/spoofed domains.
 */
function determineVerdict(score, signals) {
  // Hard overrides
  if (signals.hardBlacklisted || signals.brandSpoof) return 'danger';

  const hasCriticalContentFlag = (signals.contentFlags || []).some(f =>
    ['brand-impersonation','hidden-iframe','meta-redirect'].includes(f.type) && f.severity === 'high'
  );
  const hasCriticalUrlFlag = (signals.urlFlags || []).some(f =>
    ['ip-address','at-sign-url','dangerous-protocol'].includes(f.type)
  );
  if (hasCriticalContentFlag || hasCriticalUrlFlag) return 'danger';

  if (score >= 70) return 'safe';
  if (score >= 40) return 'hazard';
  return 'danger';
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 7 — API ROUTES
// ════════════════════════════════════════════════════════════════════════════

// Well-known domains: skip aggressive checks but still analyze
const SERVER_WELL_KNOWN = [
  'github.com','github.io','facebook.com','fb.com','instagram.com',
  'twitter.com','x.com','tiktok.com','netflix.com','linkedin.com',
  'discord.com','twitch.tv','spotify.com','paypal.com','reddit.com',
  'stackoverflow.com','google.com','youtube.com','microsoft.com',
  'apple.com','amazon.com','wikipedia.org','yahoo.com',
  'gcash.com','bdo.com.ph','bpi.com.ph','metrobank.com.ph',
  'landbank.com','unionbankph.com','rcbc.com','paymaya.com','maya.ph',
];

app.get('/api/fetch', async (req, res) => {
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

app.get('/api/whois', async (req, res) => {
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

// ── Main safety check endpoint ──────────────────────────────────────────────
app.get('/api/check', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'missing url' });

  try {
    const start = Date.now();
    console.log(`\n/api/check ▶ ${url}`);

    // ── Parse and normalise ────────────────────────────────────────────────
    let parsed;
    try { parsed = new URL(url); } catch(e) {
      return res.status(400).json({ ok: false, error: 'Invalid URL' });
    }

    const hostname       = parsed.hostname.toLowerCase();
    const httpsOk        = parsed.protocol === 'https:';
    const shortened      = isShortener(hostname);

    // Follow shortener redirects first
    let resolvedUrl      = url;
    let redirectChain    = [url];
    let resolvedHostname = hostname;
    let resolvedHttpsOk  = httpsOk;

    if (shortened) {
      const rr = await followRedirects(url, 10, 8000);
      resolvedUrl   = rr.finalUrl;
      redirectChain = rr.chain;
      try {
        const ru        = new URL(resolvedUrl);
        resolvedHostname = ru.hostname.toLowerCase();
        resolvedHttpsOk  = ru.protocol === 'https:';
      } catch(e) {}
      console.log(`  shortener resolved: ${url} → ${resolvedUrl}`);
    }

    // ── Hostname analysis ──────────────────────────────────────────────────
    const hostnameAnalysis = analyzeHostname(resolvedHostname);

    // ── URL structure analysis ─────────────────────────────────────────────
    const urlFlags = analyzeUrlStructure(resolvedUrl);

    // ── Parallelise: fetch + TLS + WHOIS + DNS ─────────────────────────────
    const isWellKnown   = SERVER_WELL_KNOWN.some(d => resolvedHostname === d || resolvedHostname.endsWith('.' + d));
    const skipWhois     = (resolvedHostname === 'localhost' || resolvedHostname === '127.0.0.1');
    const fetchTimeout  = 10000;
    const tlsTimeout    = 5000;
    const whoisTimeout  = 12000;

    const [fetched, tlsResult, whoisInfo, dnsFlags] = await Promise.all([
      fetchHtml(resolvedUrl, fetchTimeout).catch(() => null),
      resolvedHttpsOk
        ? getCertificateInfo(resolvedHostname, 443, tlsTimeout).catch(() => ({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }))
        : Promise.resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }),
      skipWhois ? Promise.resolve(null) : whoisLookup(resolvedHostname, whoisTimeout).catch(() => null),
      checkDnsReputation(resolvedHostname).catch(() => []),
    ]);

    const html        = fetched ? (fetched.text || '') : '';
    const finalUrl    = fetched ? (fetched.finalUrl || resolvedUrl) : resolvedUrl;
    const statusCode  = fetched ? fetched.status : null;
    const reachable   = fetched ? !!fetched.ok : isWellKnown;

    const certValid        = tlsResult.certValid;
    const certExpiresDays  = tlsResult.certExpiresDays;
    const selfSignedCert   = tlsResult.selfSigned;
    const certExpiresSoon  = certExpiresDays !== null && certExpiresDays >= 0 && certExpiresDays < 14;

    let redirectsToHttp = false;
    try {
      const fu = new URL(finalUrl);
      redirectsToHttp = fu.protocol === 'http:' && resolvedHttpsOk;
    } catch(e) {}

    const domainAgeDays = parseWhoisAge(whoisInfo);

    // ── Deep content analysis ──────────────────────────────────────────────
    const contentFlags = deepContentAnalysis(html, resolvedHostname, finalUrl);

    // ── Build signals bundle for scoring ──────────────────────────────────
    const signals = {
      hardBlacklisted: hostnameAnalysis.hardBlacklisted,
      brandSpoof:      hostnameAnalysis.brandSpoof,
      spoofedBrand:    hostnameAnalysis.spoofedBrand,
      patternMatch:    hostnameAnalysis.patternMatch,
      urlFlags,
      httpsOk:         resolvedHttpsOk,
      certValid,
      certExpiresDays,
      selfSignedCert,
      certExpiresSoon,
      redirectsToHttp,
      domainAgeDays,
      contentFlags,
      dnsFlags,
      reachable,
    };

    const riskScore = calculateRiskScore(signals);
    const verdict   = determineVerdict(riskScore, signals);

    // ── Consolidate all flags for the client ───────────────────────────────
    const allFlags = [
      ...urlFlags,
      ...contentFlags,
      ...dnsFlags,
    ];

    const totalDuration = Date.now() - start;
    console.log(`  verdict=${verdict} score=${riskScore} blacklisted=${hostnameAnalysis.hardBlacklisted} brandSpoof=${hostnameAnalysis.brandSpoof} patternMatch=${hostnameAnalysis.patternMatch} domainAge=${domainAgeDays} flags=${allFlags.length} total=${totalDuration}ms`);

    res.json({
      ok: true,
      // Core results
      reachable, statusCode, httpsOk: resolvedHttpsOk,
      certValid, certExpiresDays, selfSignedCert, certExpiresSoon,
      redirectsToHttp,
      // Blacklist / pattern results
      blacklisted:  hostnameAnalysis.hardBlacklisted,
      patternMatch: hostnameAnalysis.patternMatch,
      brandSpoof:   hostnameAnalysis.brandSpoof,
      spoofedBrand: hostnameAnalysis.spoofedBrand,
      // Domain age
      domainAgeDays,
      // Flags (URL structure + content + DNS combined)
      contentFlags: allFlags,
      // Score & verdict
      riskScore,
      verdict,
      // Shortener
      shortened,
      resolvedUrl:   shortened ? resolvedUrl    : undefined,
      redirectChain: shortened && redirectChain.length > 1 ? redirectChain : undefined,
      totalDuration,
    });

  } catch (err) {
    console.warn(`/api/check ERROR ${url}:`, err && err.message ? err.message : err);
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// SECTION 8 — SERVER START
// ════════════════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
  const url = `http://localhost:${PORT}/main.html`;
  console.log(`\n╔══════════════════════════════════════════════════╗`);
  console.log(`║   WebSafe v6 HARDENED  —  http://localhost:${PORT}  ║`);
  console.log(`╚══════════════════════════════════════════════════╝\n`);
  const { exec } = require('child_process');
  const cmd =
    process.platform === 'win32'  ? `start "" "${url}"` :
    process.platform === 'darwin' ? `open "${url}"` :
                                    `xdg-open "${url}"`;
  exec(cmd, err => { if (err) console.log('(Could not auto-open browser — visit the URL above)'); });
});
