// server.js — WebSafe v8
// ─────────────────────────────────────────────────────────────────────────────
// API keys are read from environment variables ONLY — never hardcoded.
//
//   GSB_KEY          : Google Safe Browsing v4  (free, unlimited non-commercial)
//   VT_KEY           : VirusTotal Public API    (free, ~500 req/day)
//   URLSCAN_KEY      : urlscan.io               (free, ~5 000 scans/day)
//   CHECKPHISH_KEY   : CheckPhish API           (free, ~250 scans/month)
//   ANTHROPIC_API_KEY: Claude chat assistant
//
// All keys are optional — their checks are gracefully skipped when unset.
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

// Load .env file first — must be before any process.env reads
require('dotenv').config();

const express  = require('express');
const fetch    = require('node-fetch');
const tls      = require('tls');
const cheerio  = require('cheerio');
const whois    = require('whois');
const path     = require('path');
const cors     = require('cors');
const dns      = require('dns').promises;

// ── Key loading (env only — no leakage) ──────────────────────────────────────
const GSB_KEY         = process.env.GSB_KEY          || '';
const VT_KEY          = process.env.VT_KEY           || '';
const URLSCAN_KEY     = process.env.URLSCAN_KEY      || '';
const CHECKPHISH_KEY  = process.env.CHECKPHISH_KEY   || '';
const GEMINI_KEY      = process.env.GEMINI_API_KEY   || '';

const app  = express();
const PORT = process.env.PORT || 3000;

// Trust the first hop proxy (Render, Railway, Fly.io, etc.) so req.ip is
// the real client IP rather than the load-balancer IP — required for rate
// limiting to work correctly in production.
app.set('trust proxy', 1);

// ── In-memory scan result cache (5-minute TTL) ────────────────────────────────
// Prevents redundant external API calls when the same URL is re-scanned
// within a short window. Especially important for VirusTotal (500/day) and
// CheckPhish (250/month) which have tight free-tier limits.
const SCAN_CACHE = new Map();
const SCAN_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of SCAN_CACHE) {
        if (now > entry.expires) SCAN_CACHE.delete(key);
    }
}, 60_000);

// ── CORS ──────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .concat(['http://localhost:3000', 'http://localhost:3001']);

if (process.env.NODE_ENV === 'production' && !(process.env.ALLOWED_ORIGINS || '').trim()) {
    console.warn('[WARN] ALLOWED_ORIGINS is not set — set it to your production domain to restrict CORS.');
}

app.use(cors({
    origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        return cb(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '64kb' }));

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    // Content-Security-Policy — lock down what the browser is allowed to load/run
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        // Inline styles are required by the current UI (heavy inline style= usage)
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        // Scripts: self + inline event handlers used by the UI (onmouseover etc.)
        // 'unsafe-inline' scripts are intentional — no eval() is used
        "script-src 'self' 'unsafe-inline'",
        // Images: self + data URIs (favicons) + external screenshot services
        "img-src 'self' data: https:",
        // Fetch/XHR: only back to same origin (all API calls go to our own server)
        "connect-src 'self'",
        // Frames: completely blocked — users should never be iframed or iframe others
        "frame-src 'none'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ].join('; '));
    next();
});

// ── Static file allowlist — source files are NEVER exposed ───────────────────
const PUBLIC_FILES = {
    '/main.html':              'main.html',
    '/main.css':               'main.css',
    '/check_link.js':          'check_link.js',
    '/tld_list.js':            'tld_list.js',
    '/about_us.html':          'about_us.html',
    '/about_us.css':           'about_us.css',
    '/contact_local.html':     'contact_local.html',
    '/contact_local.css':      'contact_local.css',
    '/jsQR.min.js':            'jsQR.min.js',
    '/html5-qrcode.min.js':    'html5-qrcode.min.js',
};

app.use('/images', express.static(path.join(__dirname, 'images'), {
    dotfiles: 'deny',
    index: false,
}));

Object.entries(PUBLIC_FILES).forEach(([route, file]) => {
    app.get(route, (req, res) => res.sendFile(path.join(__dirname, file)));
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'main.html')));

// Deny everything else outside the allowlist
app.use((req, res, next) => {
    if (req.path.startsWith('/api/') || req.path.startsWith('/images/')) return next();
    const allowed = Object.keys(PUBLIC_FILES).concat(['/', '/images']);
    if (!allowed.includes(req.path)) return res.status(404).send('Not found');
    next();
});

// ── Rate limiters — separate budgets per endpoint cost ────────────────────────
//
//   /api/check  → 5 req/min  (fires 8 external API calls each — most expensive)
//   /api/chat   → 10 req/min (costs real Anthropic tokens per message)
//   everything  → 30 req/min (fetch, whois, status — cheap reads)
//
function makeRateLimiter(maxPerMin, message) {
    const map = new Map();
    setInterval(() => {
        const now = Date.now();
        for (const [ip, e] of map) { if (now > e.reset) map.delete(ip); }
    }, 300_000);
    return (req, res, next) => {
        const ip    = req.ip || req.socket?.remoteAddress || 'unknown';
        const now   = Date.now();
        const entry = map.get(ip) || { count: 0, reset: now + 60_000 };
        if (now > entry.reset) { entry.count = 0; entry.reset = now + 60_000; }
        entry.count++;
        map.set(ip, entry);
        if (entry.count > maxPerMin) {
            return res.status(429).json({ ok: false, error: message || 'Too many requests — please wait a moment.' });
        }
        next();
    };
}

// Most expensive: /api/check fires 8 parallel external API calls
app.use('/api/check', makeRateLimiter(5,  'Scan limit reached (5/min) — please wait before scanning again.'));
// Chat burns real API tokens — tighter cap
app.use('/api/chat',  makeRateLimiter(10, 'Chat limit reached (10/min) — please slow down.'));
// Cheap endpoints: fetch, whois, status
app.use('/api/',      makeRateLimiter(30, 'Too many requests — please wait a moment.'));

// ── Request logger ────────────────────────────────────────────────────────────
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()}  ${req.method} ${req.path}`);
    next();
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1 — URL VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

function isValidHostname(hostname) {
    if (!hostname || hostname.length < 4) return false;
    if (!hostname.includes('.')) return false;

    const parts = hostname.split('.');
    const tld   = parts[parts.length - 1];
    if (!/^[a-zA-Z]{2,}$/.test(tld)) return false;

    for (const part of parts) {
        if (part.length === 0) return false;
        if (!/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/.test(part)) return false;
    }

    const vowels = /[aeiou]/i;
    for (const part of parts) {
        if (part.length >= 5 && !vowels.test(part) && /^[a-zA-Z]+$/.test(part)) return false;
    }

    for (const part of parts) {
        if (/^[a-zA-Z]+$/.test(part) && part.length >= 6) {
            const consonants = (part.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
            if (consonants / part.length > 0.88) return false;
        }
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2 — BLACKLISTS & PATTERN DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

const HARD_BLACKLIST = new Set([
    'example-malicious.com','bad-domain.test',
    // PH banking/ewallet phishing
    'gcash-promo.com','gcash-verify.net','gcash-reward.com','gcash-login.net','gcash-update.com',
    'bdo-verify.com','bdo-online.net','bdo-secure.com','bdo-login.net','bdo-alert.com',
    'bpi-verify.net','bpi-online.xyz','bpi-secure.net','bpi-login.xyz','bpi-alert.net',
    'metrobank-verify.com','metrobank-online.net','metrobank-login.xyz',
    'pnb-verify.net','landbank-verify.com','unionbank-verify.net','rcbc-verify.com',
    'ewallet-gcash.com','paymaya-verify.net','maya-promo.xyz',
    // Paypal
    'paypal-verify.com','paypal-secure.net','paypal-login.xyz','paypal-update.net',
    'paypal-account-verify.com','paypal-resolution.net','paypal-billing.xyz',
    // Social
    'facebook-login.xyz','fb-verify.com','facebook-verify.net','fb-login.net',
    'facebook-security.xyz','instagram-verify.net','instagram-login.xyz',
    'twitter-verify.net','twitterlogin.xyz','x-verify.net',
    // Tech
    'google-verify.net','google-account-verify.com','google-security.xyz',
    'apple-id-verify.com','apple-support-verify.net','apple-id-login.xyz',
    'microsoft-verify.net','microsoft-account-login.xyz','microsoftsupport.xyz',
    'amazon-verify.net','amazon-secure.xyz','amazon-account-verify.com',
    // Scam/prize
    'free-robux-now.com','getrobux.xyz','roblox-free.net',
    'claim-prize.xyz','you-won.net','winner-claim.com','prize-claim.xyz',
    'crypto-doubler.com','bitcoin-generator.xyz','eth-doubler.net',
    'covid-relief-fund.com','stimulus-check.xyz',
    // Typosquatting
    'faceb00k.com','gooogle.com','paypa1.com','amaz0n.com',
    'netfl1x.com','yout0be.com','twltter.com','lnstagram.com',
    'gogle.com','goggle.com','micosoft.com','arnazon.com',
]);

const SUSPICIOUS_PATTERNS = [
    /\b(gcash|bdo|bpi|metrobank|landbank|unionbank|rcbc|pnb|paymaya|maya)\b.*(verify|login|secure|update|promo|reward|alert|confirm|suspend|restore|unlock)/i,
    /\b(paypal|stripe|square)\b.*(verify|login|secure|update|confirm|suspend|restore|billing)/i,
    /\b(google|gmail|youtube)\b.*(verify|login|secure|update|confirm|suspend|alert)/i,
    /\b(facebook|instagram|twitter|tiktok)\b.*(verify|login|secure|update|confirm|suspend)/i,
    /\b(apple|icloud|itunes)\b.*(verify|login|secure|update|confirm|suspend|id-)/i,
    /\b(microsoft|outlook|office365|onedrive)\b.*(verify|login|secure|update|confirm)/i,
    /\b(amazon|aws|prime)\b.*(verify|login|secure|update|confirm|suspend)/i,
    /\b(netflix|spotify|hulu|disney)\b.*(verify|login|secure|update|confirm|billing)/i,
    /\b(bank|banking)\b.*(verify|login|secure|update|confirm|alert)/i,
    /(paypal|google|facebook|amazon|apple|microsoft|netflix|instagram)\.(xyz|top|club|online|site|space|fun|info|live|store|shop|bid|win|gq|ml|cf|ga|tk)/i,
    /(g[o0]{2}gle|f[a@]ceb[o0]{2}k|tw[i1]tter|[i1]nstagram|am[a@]z[o0]n|p[a@]yp[a@]l)/i,
    /^(paypal|google|facebook|amazon|apple|microsoft|netflix|instagram|gcash|bdo|bpi)\..+\.(com|net|org|xyz|top)\./i,
    /^(secure|login|verify|account|update|billing|support|alert|confirm|restore|unlock|helpdesk)\./i,
    /-(verify|login|secure|update|account|billing|support|alert|confirm|restore|help|official|online|web|portal|service|center|access)(\.|$)/i,
    /(bitcoin|crypto|nft|token|wallet|defi|web3).*(free|giveaway|doubler|generator|claim|earn|airdrop)/i,
    /(prize|promo|reward|winner|claim|lottery|won|congrats).*(claim|click|collect|verify|fill|form)/i,
    /^(free|get|claim|win|earn|bonus)[-.]?(robux|vbucks|diamonds|coins|gems|credits)/i,
    /\b(exodus|metamask|ledger|trezor|coinbase|binance|trust.?wallet)\b.*(download|install|support|recover|restore|seed|phrase|connect)/i,
];

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
    exodus:     ['exodus.com','exodus.io'],
    metamask:   ['metamask.io'],
    coinbase:   ['coinbase.com'],
    binance:    ['binance.com','binance.us'],
    ledger:     ['ledger.com'],
    trezor:     ['trezor.io','trezor.com'],
};

const FREE_SITE_BUILDERS = [
    { domain: 'wix.com',       name: 'Wix' },
    { domain: 'wixsite.com',   name: 'Wix' },
    { domain: 'wixstudio.com', name: 'Wix Studio' },
    { domain: 'editorx.com',   name: 'Editor X (Wix)' },
    { domain: 'weebly.com',    name: 'Weebly' },
    { domain: 'wordpress.com', name: 'WordPress.com' },
    { domain: 'blogger.com',   name: 'Blogger' },
    { domain: 'blogspot.com',  name: 'Blogspot' },
    { domain: 'tumblr.com',    name: 'Tumblr' },
    { domain: 'squarespace.com', name: 'Squarespace' },
    { domain: 'webflow.io',    name: 'Webflow' },
    { domain: 'carrd.co',      name: 'Carrd' },
    { domain: 'strikingly.com',name: 'Strikingly' },
    { domain: 'jimdo.com',     name: 'Jimdo' },
    { domain: 'yolasite.com',  name: 'Yola' },
    { domain: 'site123.me',    name: 'Site123' },
    { domain: 'godaddysites.com', name: 'GoDaddy Website Builder' },
    { domain: 'webnode.com',   name: 'Webnode' },
    { domain: 'tilda.cc',      name: 'Tilda' },
    { domain: 'netlify.app',   name: 'Netlify' },
    { domain: 'vercel.app',    name: 'Vercel' },
    { domain: 'github.io',     name: 'GitHub Pages' },
    { domain: 'glitch.me',     name: 'Glitch' },
    { domain: 'replit.dev',    name: 'Replit' },
    { domain: 'myshopify.com', name: 'Shopify (free trial)' },
    { domain: 'pages.dev',     name: 'Cloudflare Pages' },
    { domain: 'web.app',       name: 'Firebase Hosting' },
    { domain: 'firebaseapp.com', name: 'Firebase Hosting' },
];

const CRYPTO_FINANCIAL_BRANDS = [
    'exodus','metamask','coinbase','binance','ledger','trezor','trust wallet','trustwallet',
    'phantom','solflare','keplr','uniswap','pancakeswap','opensea','rarible','crypto.com',
    'blockchain','bitcoin','ethereum','wallet','seed phrase','recovery phrase','private key',
    'defi','web3','nft','gcash','paymaya','maya','bdo','bpi','metrobank',
    'paypal','stripe','bank account','wire transfer',
];

function detectFreeSiteBuilder(hostname) {
    const h = hostname.toLowerCase().replace(/^www\./, '');
    for (const builder of FREE_SITE_BUILDERS) {
        if (h === builder.domain || h.endsWith('.' + builder.domain)) return builder;
    }
    return null;
}

function detectCryptoFinancialContent(html, title) {
    const text = ((html || '') + ' ' + (title || '')).toLowerCase();
    return CRYPTO_FINANCIAL_BRANDS.filter(brand => text.includes(brand.toLowerCase()));
}

function analyzeHostname(hostname) {
    const h = hostname.toLowerCase().replace(/^www\./, '');
    if (isTrustedDomain(h)) return { hardBlacklisted: false, patternMatch: false, brandSpoof: false };
    if (HARD_BLACKLIST.has(h)) return { hardBlacklisted: true, patternMatch: false, brandSpoof: false };

    const parts = h.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
        const sub = parts.slice(i).join('.');
        if (HARD_BLACKLIST.has(sub)) return { hardBlacklisted: true, patternMatch: false, brandSpoof: false };
    }

    const patternMatch = SUSPICIOUS_PATTERNS.some(p => p.test(h));

    let brandSpoof = false, spoofedBrand = null;
    for (const [brand, legitDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
        const re = new RegExp(`\\b${brand}\\b`, 'i');
        if (re.test(h)) {
            const isLegit = legitDomains.some(d => h === d || h.endsWith('.' + d));
            if (!isLegit) { brandSpoof = true; spoofedBrand = brand; break; }
        }
    }
    return { hardBlacklisted: false, patternMatch, brandSpoof, spoofedBrand };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3 — URL STRUCTURE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

function analyzeUrlStructure(urlStr) {
    const flags = [];
    let parsed;
    try { parsed = new URL(urlStr); } catch(e) { return flags; }

    const hostname = parsed.hostname.toLowerCase();
    const labels   = hostname.split('.');

    if (labels.length >= 5) {
        flags.push({ type: 'excessive-subdomains', severity: 'high',
            detail: `Unusually deep subdomain chain (${labels.length} levels) — common phishing trick` });
    }

    const tldPlusOne = labels.slice(-2).join('.');
    const subdomains = labels.slice(0, -2).join('.');
    for (const [brand, legitDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
        if (new RegExp(`\\b${brand}\\b`, 'i').test(subdomains)) {
            const isLegit = legitDomains.some(d => hostname === d || hostname.endsWith('.' + d));
            if (!isLegit) {
                flags.push({ type: 'brand-in-subdomain', severity: 'high',
                    detail: `"${brand}" used as subdomain on unrelated domain "${tldPlusOne}" — classic phishing` });
            }
        }
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        flags.push({ type: 'ip-address', severity: 'high',
            detail: 'URL uses a raw IP address instead of a domain — almost always malicious' });
    }

    if (urlStr.length > 150) {
        flags.push({ type: 'long-url', severity: 'medium',
            detail: `Unusually long URL (${urlStr.length} chars) — often used to hide the real destination` });
    }

    if (urlStr.includes('@')) {
        flags.push({ type: 'at-sign-url', severity: 'high',
            detail: 'URL contains an @ sign — can disguise the real destination' });
    }

    const dashCount = (hostname.match(/-/g) || []).length;
    if (dashCount >= 3) {
        flags.push({ type: 'dash-heavy-domain', severity: 'medium',
            detail: `Domain has ${dashCount} dashes — over-hyphenated domains are common in phishing` });
    }

    const SUSPICIOUS_TLDS = ['xyz','top','club','online','site','space','fun','live','store',
        'shop','bid','win','gq','ml','cf','ga','tk','pw','su','icu','vip','loan','work',
        'click','link','zip','mov','date','download','review'];
    const tld = labels[labels.length - 1];
    if (SUSPICIOUS_TLDS.includes(tld)) {
        flags.push({ type: 'suspicious-tld', severity: 'medium',
            detail: `".${tld}" domains are frequently abused for phishing and scams` });
    }

    if (/%[0-9a-f]{2}/i.test(hostname)) {
        flags.push({ type: 'encoded-hostname', severity: 'high',
            detail: 'Hostname contains percent-encoded characters — often used to disguise malicious URLs' });
    }

    if (/^(data:|javascript:|vbscript:)/i.test(urlStr)) {
        flags.push({ type: 'dangerous-protocol', severity: 'high',
            detail: 'URL uses a dangerous protocol (data:, javascript:, or vbscript:)' });
    }

    function shannonEntropy(str) {
        const freq = {};
        for (const c of str) freq[c] = (freq[c] || 0) + 1;
        const len = str.length;
        let e = 0;
        for (const c in freq) { const p = freq[c]/len; e -= p * Math.log2(p); }
        return e;
    }
    const domainNoTld = labels.slice(0, -1).join('').replace(/-/g, '');
    if (/^[a-zA-Z]+$/.test(domainNoTld) && domainNoTld.length > 10) {
        const ent = shannonEntropy(domainNoTld);
        if (ent > 3.8) {
            flags.push({ type: 'high-entropy-domain', severity: 'medium',
                detail: `Domain entropy is ${ent.toFixed(2)} — statistically random-looking, typical of algorithmically-generated phishing domains` });
        }
    }

    if (/[^\x00-\x7F]/.test(hostname)) {
        flags.push({ type: 'homograph-attack', severity: 'high',
            detail: 'Hostname contains non-ASCII characters — possible IDN homograph attack using lookalike letters' });
    }

    const hostnameNoWww = hostname.replace(/^www\./, '');
    const domainLabel   = hostnameNoWww.split('.')[0];
    if (!/^[0-9]/.test(domainLabel) && /[a-z][0-9][a-z]/i.test(hostnameNoWww.replace(/\./g, ''))) {
        flags.push({ type: 'numeric-substitution', severity: 'high',
            detail: 'Numbers replacing letters in domain — classic brand-spoofing (e.g. g00gle, p4ypal)' });
    }

    return flags;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4 — EXTERNAL THREAT APIs
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Google Safe Browsing v4
 * Free, non-commercial usage, highly accurate.
 * Returns { flagged, threatType, skipped, error? }
 */
async function checkGoogleSafeBrowsing(url, timeout = 8000) {
    if (!GSB_KEY) return { flagged: false, threatType: null, skipped: true };
    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_KEY}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: ctrl.signal,
                body: JSON.stringify({
                    client:     { clientId: 'websafe-v8', clientVersion: '8.0' },
                    threatInfo: {
                        threatTypes:      ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
                        platformTypes:    ['ANY_PLATFORM'],
                        threatEntryTypes: ['URL'],
                        threatEntries:    [{ url }],
                    },
                }),
            }
        );
        clearTimeout(tid);
        if (!res.ok) return { flagged: false, threatType: null, error: `HTTP ${res.status}` };
        const j = await res.json();
        if (j?.matches?.length > 0) {
            return { flagged: true, threatType: j.matches[0].threatType || 'THREAT_DETECTED' };
        }
        return { flagged: false, threatType: null };
    } catch(e) {
        return { flagged: false, threatType: null, error: e.message };
    }
}

/**
 * VirusTotal Public API v3
 * Free tier: ~500 req/day, 4 req/min.
 * Returns { positives, total, permalink, skipped, error? }
 */
async function checkVirusTotal(url, timeout = 15000) {
    if (!VT_KEY) return { positives: null, total: null, skipped: true };
    try {
        // Submit URL for analysis
        const submitCtrl = new AbortController();
        const submitTid  = setTimeout(() => submitCtrl.abort(), timeout);
        const submitRes  = await fetch('https://www.virustotal.com/api/v3/urls', {
            method:  'POST',
            headers: { 'x-apikey': VT_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
            body:    `url=${encodeURIComponent(url)}`,
            signal:  submitCtrl.signal,
        });
        clearTimeout(submitTid);
        if (!submitRes.ok) return { positives: null, total: null, error: `Submit HTTP ${submitRes.status}` };
        const submitJson = await submitRes.json();
        const analysisId = submitJson?.data?.id;
        if (!analysisId) return { positives: null, total: null, error: 'No analysis ID returned' };

        // Poll (3s wait then fetch)
        await new Promise(r => setTimeout(r, 3000));
        const reportCtrl = new AbortController();
        const reportTid  = setTimeout(() => reportCtrl.abort(), timeout);
        const reportRes  = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { 'x-apikey': VT_KEY },
            signal:  reportCtrl.signal,
        });
        clearTimeout(reportTid);
        if (!reportRes.ok) return { positives: null, total: null, error: `Report HTTP ${reportRes.status}` };
        const reportJson = await reportRes.json();
        const stats      = reportJson?.data?.attributes?.stats;
        if (!stats) return { positives: null, total: null };
        const positives = (stats.malicious || 0) + (stats.suspicious || 0);
        const total     = Object.values(stats).reduce((a, b) => a + b, 0);
        return { positives, total };
    } catch(e) {
        return { positives: null, total: null, error: e.message };
    }
}

/**
 * urlscan.io API
 * Free tier: ~5 000 scans/day. Visual + sandbox analysis.
 * Returns { verdict, malicious, score, screenshotURL, reportURL, skipped, error? }
 */
async function checkUrlScan(url, timeout = 20000) {
    if (!URLSCAN_KEY) return { verdict: null, malicious: null, skipped: true };
    try {
        // Submit scan
        const submitCtrl = new AbortController();
        const submitTid  = setTimeout(() => submitCtrl.abort(), 10000);
        const submitRes  = await fetch('https://urlscan.io/api/v1/scan/', {
            method:  'POST',
            headers: { 'API-Key': URLSCAN_KEY, 'Content-Type': 'application/json' },
            body:    JSON.stringify({ url, visibility: 'unlisted' }),
            signal:  submitCtrl.signal,
        });
        clearTimeout(submitTid);
        if (submitRes.status === 429) return { verdict: null, malicious: null, error: 'urlscan rate limit' };
        if (!submitRes.ok) return { verdict: null, malicious: null, error: `urlscan submit HTTP ${submitRes.status}` };
        const submitJson = await submitRes.json();
        const uuid       = submitJson?.uuid;
        const reportURL  = submitJson?.result;
        if (!uuid) return { verdict: null, malicious: null, error: 'No scan UUID returned' };

        // Poll for result (max ~18s)
        const pollStart = Date.now();
        while (Date.now() - pollStart < timeout - 4000) {
            await new Promise(r => setTimeout(r, 5000));
            try {
                const resultCtrl = new AbortController();
                const resultTid  = setTimeout(() => resultCtrl.abort(), 8000);
                const resultRes  = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
                    headers: { 'API-Key': URLSCAN_KEY },
                    signal:  resultCtrl.signal,
                });
                clearTimeout(resultTid);
                if (resultRes.status === 404) continue; // still processing
                if (!resultRes.ok) break;
                const resultJson = await resultRes.json();
                const verdicts   = resultJson?.verdicts?.overall;
                const score      = verdicts?.score ?? null;
                const malicious  = verdicts?.malicious ?? false;
                const verdict    = verdicts?.categories?.join(', ') || (malicious ? 'malicious' : 'clean');
                const screenshotURL = resultJson?.task?.screenshotURL || null;
                return { verdict, malicious, score, screenshotURL, reportURL, uuid };
            } catch(e) { break; }
        }
        return { verdict: null, malicious: null, error: 'urlscan result timed out', reportURL };
    } catch(e) {
        return { verdict: null, malicious: null, error: e.message };
    }
}

/**
 * CheckPhish API (by Bolster)
 * Free tier: ~250 scans/month. Specialises in brand impersonation / phishing.
 * Returns { disposition, brand, status, skipped, error? }
 *   disposition: 'clean' | 'phish' | 'suspect' | 'unknown'
 */
async function checkCheckPhish(url, timeout = 30000) {
    if (!CHECKPHISH_KEY) return { disposition: null, brand: null, skipped: true };
    try {
        // Submit scan
        const submitCtrl = new AbortController();
        const submitTid  = setTimeout(() => submitCtrl.abort(), 10000);
        const submitRes  = await fetch('https://developers.checkphish.ai/api/neo/scan', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ apiKey: CHECKPHISH_KEY, urlInfo: { url }, scanType: 'quick' }),
            signal:  submitCtrl.signal,
        });
        clearTimeout(submitTid);
        if (!submitRes.ok) return { disposition: null, brand: null, error: `CheckPhish submit HTTP ${submitRes.status}` };
        const submitJson = await submitRes.json();
        const jobID      = submitJson?.jobID;
        if (!jobID) return { disposition: null, brand: null, error: 'No jobID returned' };

        // Poll for result (max ~25s)
        const pollStart = Date.now();
        while (Date.now() - pollStart < timeout - 5000) {
            await new Promise(r => setTimeout(r, 4000));
            try {
                const statusCtrl = new AbortController();
                const statusTid  = setTimeout(() => statusCtrl.abort(), 8000);
                const statusRes  = await fetch('https://developers.checkphish.ai/api/neo/scan/status', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ apiKey: CHECKPHISH_KEY, jobID, insights: true }),
                    signal:  statusCtrl.signal,
                });
                clearTimeout(statusTid);
                if (!statusRes.ok) break;
                const statusJson = await statusRes.json();
                if (statusJson?.status === 'DONE') {
                    return {
                        disposition: statusJson.disposition || 'unknown',
                        brand:       statusJson.brand       || null,
                        phishDetails: statusJson.insights?.phishDetails || null,
                    };
                }
            } catch(e) { break; }
        }
        return { disposition: null, brand: null, error: 'CheckPhish result timed out' };
    } catch(e) {
        return { disposition: null, brand: null, error: e.message };
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — TRUSTED DOMAINS & CONTENT ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

const TRUSTED_DOMAINS = new Set([
    'facebook.com','google.com','youtube.com','twitter.com','instagram.com',
    'microsoft.com','apple.com','amazon.com','wikipedia.org','linkedin.com',
    'reddit.com','yahoo.com','netflix.com','github.com','stackoverflow.com',
    'paypal.com','bankofamerica.com','chase.com','wellsfargo.com','x.com',
    'tiktok.com','discord.com','twitch.tv','spotify.com','dropbox.com',
    'gcash.com','bdo.com.ph','bpi.com.ph','metrobank.com.ph','landbank.com',
    'unionbankph.com','rcbc.com','paymaya.com','maya.ph',
    'chatgpt.com','openai.com','claude.ai','anthropic.com','gemini.google.com',
    'bard.google.com','copilot.microsoft.com','bing.com',
    'scholar.google.com','drive.google.com','docs.google.com','maps.google.com',
    'mail.google.com','accounts.google.com','play.google.com','news.google.com',
    'translate.google.com','meet.google.com','classroom.google.com',
    'googleapis.com','gstatic.com','googleusercontent.com',
    'office.com','outlook.com','live.com','hotmail.com','azure.com',
    'microsoftonline.com','sharepoint.com','teams.microsoft.com',
    'zoom.us','slack.com','notion.so','canva.com','figma.com',
    'medium.com','substack.com','twitch.tv','pinterest.com','tumblr.com',
    'shopee.ph','lazada.com.ph','grab.com','rappler.com','inquirer.net',
    'philstar.com','abs-cbn.com','gma.com.ph','pna.gov.ph','gov.ph',
    'exodus.com','exodus.io','metamask.io','coinbase.com','binance.com',
    'ledger.com','trezor.io','trezor.com',
    'archive.org','archive.ph','pastebin.com',
    'protonmail.com','proton.me','tutanota.com','protonvpn.com',
    'duckduckgo.com','startpage.com','brave.com',
    'npmjs.com','pypi.org','packagist.org','crates.io',
    'cloudflare.com','fastly.com','akamai.com',
]);

function isTrustedDomain(hostname) {
    const h = hostname.toLowerCase().replace(/^www\./, '');
    return TRUSTED_DOMAINS.has(h) || [...TRUSTED_DOMAINS].some(d => h.endsWith('.' + d));
}

const HIGH_RISK_PHRASES = [
    'enter your social security','social security number','ssn','wire transfer now',
    'western union','moneygram','send money to verify','bitcoin payment required',
    'your account has been suspended','account will be terminated','verify now to avoid suspension',
    'click here to restore access','update your billing immediately','your card has been declined',
    'unusual activity detected','unauthorized access attempt','one-time password expired',
    'confirm your identity to continue','we have detected suspicious','limited time to respond',
    'your account is at risk','action required immediately','failure to comply will result',
    'enter your seed phrase','enter your recovery phrase','enter your private key',
    'wallet has been compromised','connect your wallet to verify','sync your wallet',
    'validate your wallet','restore your exodus','restore your metamask',
];

const MEDIUM_RISK_PHRASES = [
    'verify your account','confirm your identity','account suspended',
    'click here to verify','validate your information','confirm billing',
    'your password has expired','update payment details','reactivate your account',
    'unusual sign-in activity','verify your email address',
];

function deepContentAnalysis(html, hostname, finalUrl) {
    const flags = [];
    if (!html || html.length < 50) return flags;
    if (isTrustedDomain(hostname)) return flags;

    let $;
    try { $ = cheerio.load(html); } catch(e) { return flags; }

    const bodyText  = ($('body').text() || '').toLowerCase().replace(/\s+/g, ' ');
    const titleText = ($('title').text() || '').toLowerCase();
    const fullText  = bodyText + ' ' + titleText;

    const foundHigh = HIGH_RISK_PHRASES.filter(k => fullText.includes(k.toLowerCase()));
    if (foundHigh.length >= 2)       flags.push({ type: 'keywords-high',   severity: 'high',   detail: foundHigh.slice(0, 4) });
    else if (foundHigh.length === 1) flags.push({ type: 'keywords-high',   severity: 'medium', detail: foundHigh });

    const foundMedium = MEDIUM_RISK_PHRASES.filter(k => fullText.includes(k.toLowerCase()));
    if (foundMedium.length >= 2)     flags.push({ type: 'keywords-medium', severity: 'medium', detail: foundMedium.slice(0, 4) });

    for (const [brand, legitDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
        const re     = new RegExp(`\\b${brand}\\b`, 'i');
        const isLegit = legitDomains.some(d => hostname === d || hostname.endsWith('.' + d));
        if (!isLegit && (re.test(titleText) || $('h1,h2,h3').toArray().some(el => re.test($(el).text())))) {
            flags.push({ type: 'brand-impersonation', severity: 'high',
                detail: `Page claims to be "${brand}" but hosted on "${hostname}" — strong phishing indicator` });
            break;
        }
    }

    const pwFields = $('input[type="password"]').length;
    if (pwFields >= 2) {
        flags.push({ type: 'multiple-password-fields', severity: 'high',
            detail: `Page has ${pwFields} password fields — possibly harvesting credentials` });
    }

    const finalHostname = (() => { try { return new URL(finalUrl).hostname.toLowerCase(); } catch(e) { return hostname; } })();
    $('form').each((_, f) => {
        const action = $(f).attr('action') || '';
        if (!action || /^(#|javascript)/i.test(action)) return;
        try {
            const actUrl = new URL(action, finalUrl);
            if (actUrl.hostname && actUrl.hostname !== finalHostname && actUrl.hostname !== hostname) {
                flags.push({ type: 'form-external-post', severity: 'high',
                    detail: `Form submits to "${actUrl.hostname}" — credentials go to a different server` });
            }
        } catch(e) {}
    });

    const scripts = $('script').toArray().map(s => $(s).html() || '').join('\n');
    const obfuscationFound = [
        { re: /eval\s*\(/, label: 'eval()' },
        { re: /document\.write\s*\(/, label: 'document.write()' },
        { re: /unescape\s*\(/, label: 'unescape()' },
        { re: /String\.fromCharCode\s*\(/i, label: 'fromCharCode()' },
        { re: /atob\s*\(/, label: 'atob()' },
    ].filter(p => p.re.test(scripts)).map(p => p.label);
    if (obfuscationFound.length >= 2) {
        flags.push({ type: 'obfuscation', severity: 'medium',
            detail: `Suspicious JS techniques: ${obfuscationFound.join(', ')} — common in malicious pages` });
    }

    const base64Matches = (scripts.match(/[A-Za-z0-9+/]{80,}={0,2}/g) || []);
    if (base64Matches.length >= 2) {
        flags.push({ type: 'base64-payload', severity: 'medium',
            detail: `${base64Matches.length} large encoded data blobs found — may hide malicious content` });
    }

    $('iframe').each((_, el) => {
        const src   = $(el).attr('src') || '';
        const style = ($(el).attr('style') || '').toLowerCase();
        const hidden = style.includes('display:none') || style.includes('display: none') ||
                       style.includes('visibility:hidden') || style.includes('width:0') || style.includes('height:0');
        if (hidden && src) {
            flags.push({ type: 'hidden-iframe', severity: 'high',
                detail: `Hidden iframe loading "${src}" — used for clickjacking or silent redirects` });
        }
    });

    $('meta[http-equiv]').each((_, el) => {
        const equiv   = ($(el).attr('http-equiv') || '').toLowerCase();
        const content = $(el).attr('content') || '';
        if (equiv === 'refresh' && /url=/i.test(content)) {
            try {
                const destHost = new URL(content.replace(/.*url=/i, '').trim(), finalUrl).hostname.toLowerCase();
                if (destHost !== hostname && destHost !== finalHostname) {
                    flags.push({ type: 'meta-redirect', severity: 'high',
                        detail: `Page silently redirects to "${destHost}" — common in phishing relay pages` });
                }
            } catch(e) {}
        }
    });

    const badgeKeywords = ['mcafee secure','norton secured','ssl secured','verified by visa',
        'security verified','100% safe','your information is safe'];
    if (badgeKeywords.filter(b => fullText.includes(b)).length >= 2) {
        flags.push({ type: 'fake-trust-badges', severity: 'medium',
            detail: 'Page uses multiple fake "security verified" claims — common on scam sites' });
    }

    return flags;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6 — NETWORK HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

const URL_SHORTENERS = [
    'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','buff.ly','rebrand.ly',
    'short.link','tiny.cc','bl.ink','cutt.ly','rb.gy','shorturl.at','snip.ly',
    'clicky.me','bit.do','t2mio.com','link.tl','trib.al','shorte.st',
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
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), timeout);
        try {
            const res = await fetch(current, {
                method: 'HEAD', redirect: 'manual', signal: ctrl.signal,
                headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebSafe/8.0)' }
            });
            clearTimeout(tid);
            const loc = res.headers.get('location');
            if (res.status >= 300 && res.status < 400 && loc) {
                try { current = new URL(loc, current).href; } catch(e) { current = loc; }
                chain.push(current);
            } else break;
        } catch(e) { clearTimeout(tid); break; }
    }
    return { finalUrl: current, chain };
}

/**
 * Probe whether a URL is truly dead/unreachable vs just blocking bots.
 * Returns { dead, reason }
 *   dead   : true  → DNS NXDOMAIN, connection refused, or TLS handshake failure
 *            false → site responded (even with 4xx/5xx) or is DNS-resolvable
 *   reason : human-readable explanation when dead === true
 */
async function checkDeadLink(urlStr, timeout = 8000) {
    let parsed;
    try { parsed = new URL(urlStr); } catch(e) { return { dead: false, reason: null }; }
    const hostname = parsed.hostname;

    // Step 1: DNS — does the domain even exist?
    try {
        const addresses = await dns.resolve4(hostname).catch(() => null)
                       || await dns.resolve6(hostname).catch(() => null);
        if (!addresses || addresses.length === 0) {
            // Double-check with AAAA
            return { dead: true, reason: 'DNS_NXDOMAIN' };
        }
    } catch(e) {
        return { dead: true, reason: 'DNS_NXDOMAIN' };
    }

    // Step 2: Try an HTTP HEAD request — any response means server is alive
    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(urlStr, {
            method: 'HEAD',
            redirect: 'follow',
            signal: ctrl.signal,
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebSafe/8.0)' },
        });
        clearTimeout(tid);
        // Any HTTP response — even 404 / 410 / 503 — means the server is alive
        // 404 = page not found (could be expired/removed), 410 = explicitly gone
        if (res.status === 404 || res.status === 410) {
            return { dead: true, reason: `HTTP_${res.status}`, statusCode: res.status };
        }
        return { dead: false, reason: null, statusCode: res.status };
    } catch(e) {
        const msg = e.message || '';
        if (msg.includes('ECONNREFUSED'))  return { dead: true, reason: 'CONNECTION_REFUSED' };
        if (msg.includes('ETIMEDOUT') || msg.includes('abort')) return { dead: true, reason: 'TIMEOUT' };
        if (msg.includes('certificate') || msg.includes('SSL') || msg.includes('TLS')) {
            return { dead: true, reason: 'TLS_ERROR' };
        }
        // Other network errors — treat as dead
        return { dead: true, reason: 'NETWORK_ERROR' };
    }
}

const DEAD_REASON_LABELS = {
    DNS_NXDOMAIN:      'Domain does not exist — it may have expired or never been registered',
    HTTP_404:          'Page not found (404) — this URL no longer exists on the server',
    HTTP_410:          'Page permanently removed (410) — the site explicitly says this content is gone',
    CONNECTION_REFUSED:'Server is refusing connections — the site is down or no longer hosted',
    TIMEOUT:           'Connection timed out — the server is unreachable',
    TLS_ERROR:         'SSL/TLS handshake failed — the site\'s security certificate is broken or expired',
    NETWORK_ERROR:     'Network error — the site could not be reached',
};

async function fetchHtml(url, timeout = 15000) {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    try {
        const res = await fetch(url, {
            redirect: 'follow',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
            signal: ctrl.signal,
        });
        clearTimeout(tid);
        const text = await res.text();
        return { text, finalUrl: res.url, status: res.status, ok: res.ok };
    } catch(err) { clearTimeout(tid); throw err; }
}

function getCertificateInfo(hostname, port = 443, timeout = 8000) {
    return new Promise(resolve => {
        const sock = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
            try {
                const cert  = sock.getPeerCertificate(true) || {};
                const now   = Date.now();
                let expires = null, valid = false, selfSigned = false;
                if (cert?.valid_to) {
                    const exp = new Date(cert.valid_to);
                    if (!isNaN(exp.getTime())) {
                        expires = Math.floor((exp.getTime() - now) / 86_400_000);
                        valid   = exp.getTime() > now;
                    }
                }
                if (cert?.issuer && cert?.subject) {
                    selfSigned = JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);
                }
                const issuer = cert?.issuer ? (cert.issuer.O || cert.issuer.CN || '') : '';
                resolve({ cert, certExpiresDays: expires, certValid: valid, selfSigned, issuer });
            } catch(e) {
                resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' });
            } finally { try { sock.end(); } catch(e) {} }
        });
        sock.setTimeout(timeout, () => { try { sock.destroy(); } catch(e) {} resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }); });
        sock.on('error', () => resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }));
    });
}

async function checkDnsReputation(hostname) {
    const flags = [];
    const clean = hostname.replace(/^www\./, '');
    const dynamicDns = ['no-ip.com','ddns.net','dyndns.org','changeip.com','hopto.org',
        'sytes.net','zapto.org','myftp.org','serveblog.net','freedns.afraid.org','duckdns.org'];
    try {
        const cnameRecords = await dns.resolveCname(clean).catch(() => []);
        for (const cname of cnameRecords) {
            if (dynamicDns.some(d => cname.endsWith(d))) {
                flags.push({ type: 'dynamic-dns', severity: 'medium',
                    detail: `Domain uses free dynamic DNS (${cname}) — frequently abused in phishing` });
            }
        }
        const addresses = await dns.resolve4(clean).catch(() => []);
        if (addresses.length > 0 && addresses[0].startsWith('185.')) {
            flags.push({ type: 'suspicious-hosting', severity: 'low',
                detail: `Hosted on IP block (${addresses[0]}) commonly associated with bulletproof hosting` });
        }
    } catch(e) { console.debug(`checkDnsReputation failed for ${clean}:`, e.message); }
    return flags;
}

// ── WHOIS ─────────────────────────────────────────────────────────────────────

async function whoisLookup(domain, timeout = 15000) {
    const clean = domain.replace(/^www\./, '');

    // Attempt 1: whoisjsonapi
    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(`https://www.whoisjsonapi.com/v1/${encodeURIComponent(clean)}`, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
        clearTimeout(tid);
        if (res.ok) {
            const j = await res.json();
            if (j?.domain?.created_date) return { source: 'whoisjsonapi', createdDate: j.domain.created_date, expiresDate: j.domain.expiration_date, registrar: j.registrar?.name };
        }
    } catch(e) {}

    // Attempt 2: RDAP
    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(`https://rdap.org/domain/${encodeURIComponent(clean)}`, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
        clearTimeout(tid);
        if (res.ok) {
            const j = await res.json();
            if (Array.isArray(j?.events)) {
                const reg = j.events.find(e => e.eventAction === 'registration');
                if (reg?.eventDate) return { source: 'rdap', createdDate: reg.eventDate };
            }
        }
    } catch(e) {}

    // Attempt 3: domainsdb.info
    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(`https://api.domainsdb.info/v1/domains/search?domain=${encodeURIComponent(clean)}&zone=${clean.split('.').pop()}`, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
        clearTimeout(tid);
        if (res.ok) {
            const j = await res.json();
            if (Array.isArray(j?.domains) && j.domains.length > 0) {
                const match = j.domains.find(d => d.domain === clean) || j.domains[0];
                if (match?.create_date) return { source: 'domainsdb', createdDate: match.create_date };
            }
        }
    } catch(e) {}

    // Attempt 4: raw whois
    try {
        const raw = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('whois timeout')), timeout);
            whois.lookup(clean, (err, data) => { clearTimeout(timer); if (err) return reject(err); resolve(data || ''); });
        });
        if (raw) {
            for (const p of [/Creation Date:\s*(.+)/i,/Created:\s*(.+)/i,/Domain Registration Date:\s*(.+)/i,/Registered on:\s*(.+)/i,/created:\s*(.+)/i]) {
                const m = raw.match(p);
                if (m) { const d = new Date(m[1].trim()); if (!isNaN(d.getTime())) return { source: 'raw-whois', createdDate: m[1].trim() }; }
            }
        }
    } catch(e) {}

    return null;
}

function parseWhoisAge(result) {
    if (!result?.createdDate) return null;
    const d = new Date(result.createdDate);
    if (isNaN(d.getTime())) return null;
    return Math.floor((Date.now() - d.getTime()) / 86_400_000);
}

function parseMeta(html, baseUrl) {
    const $ = cheerio.load(html);
    const title = $('title').first().text().trim() || '';
    const desc  = $('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '';
    let icon    = $('link[rel~="icon"]').attr('href') || $('link[rel~="shortcut icon"]').attr('href') || '';
    if (icon) { try { icon = new URL(icon, baseUrl).href; } catch(e) {} }
    return { title, description: desc, favicon: icon };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7 — SCORING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

function calculateRiskScore(signals) {
    let score = 100;

    // Hard overrides
    if (signals.hardBlacklisted)  score -= 80;
    if (signals.brandSpoof)       score -= 60;
    if (signals.patternMatch)     score -= 40;

    // External API results
    if (signals.googleSafeBrowsing)           score -= 70;
    if (signals.virusTotalPositives > 3)      score -= 40;
    else if (signals.virusTotalPositives > 0) score -= 20;
    if (signals.urlScanMalicious)             score -= 50;
    if (signals.checkPhishPhish)              score -= 60;
    else if (signals.checkPhishSuspect)       score -= 30;

    // Free site builder
    if (signals.freeSiteBuilder) {
        score -= 20;
        if (signals.cryptoFinancialContent) score -= 40;
    }

    // URL structure flags
    if (signals.urlFlags) {
        for (const f of signals.urlFlags) {
            if (f.severity === 'high')   score -= 25;
            if (f.severity === 'medium') score -= 12;
            if (f.severity === 'low')    score -= 5;
        }
    }

    // Network / certificate
    if (!signals.httpsOk)        score -= 30;
    if (!signals.certValid)      score -= 25;
    if (signals.selfSignedCert)  score -= 20;
    if (signals.redirectsToHttp) score -= 20;
    if (signals.certExpiresSoon) score -= 10;

    // Domain age
    if (signals.domainAgeDays !== null) {
        if      (signals.domainAgeDays < 7)    score -= 40;
        else if (signals.domainAgeDays < 30)   score -= 25;
        else if (signals.domainAgeDays < 90)   score -= 10;
        else if (signals.domainAgeDays < 180)  score -= 5;
        else if (signals.domainAgeDays >= 365) score += 5;
        if (signals.domainAgeDays >= 1825)     score += 5; // 5+ years
    } else { score -= 8; }

    // Content analysis
    for (const f of (signals.contentFlags || [])) {
        if (f.type === 'brand-impersonation')      score -= 35;
        if (f.type === 'keywords-high')            score -= f.severity === 'high' ? 25 : 15;
        if (f.type === 'keywords-medium')          score -= 10;
        if (f.type === 'multiple-password-fields') score -= 15;
        if (f.type === 'form-external-post')       score -= 20;
        if (f.type === 'hidden-iframe')            score -= 20;
        if (f.type === 'meta-redirect')            score -= 15;
        if (f.type === 'obfuscation')              score -= 10;
        if (f.type === 'base64-payload')           score -= 8;
        if (f.type === 'fake-trust-badges')        score -= 5;
    }

    // DNS
    for (const f of (signals.dnsFlags || [])) {
        if (f.severity === 'high')   score -= 20;
        if (f.severity === 'medium') score -= 10;
        if (f.severity === 'low')    score -= 5;
    }

    if (signals.reachable === false) score -= 10;

    // Positive signals
    if (signals.httpsOk && signals.certValid && !signals.selfSignedCert) score += 5;
    if (signals.domainAgeDays >= 730 && signals.httpsOk && signals.certValid) score += 5;

    return Math.max(0, Math.min(100, Math.round(score)));
}

function determineVerdict(score, signals) {
    if (signals.isTrusted) return 'safe';

    if (signals.hardBlacklisted || signals.brandSpoof) return 'danger';
    if (signals.googleSafeBrowsing)                    return 'danger';
    if (signals.virusTotalPositives > 3)               return 'danger';
    if (signals.urlScanMalicious)                      return 'danger';
    if (signals.checkPhishPhish)                       return 'danger';
    if (signals.freeSiteBuilder && signals.cryptoFinancialContent) return 'danger';

    const hasCriticalContent = (signals.contentFlags || []).some(f =>
        ['brand-impersonation','hidden-iframe','meta-redirect'].includes(f.type) && f.severity === 'high'
    );
    const hasCriticalUrl = (signals.urlFlags || []).some(f =>
        ['ip-address','at-sign-url','dangerous-protocol'].includes(f.type)
    );
    if (hasCriticalContent || hasCriticalUrl) return 'danger';

    if (signals.checkPhishSuspect) return score >= 70 ? 'hazard' : 'danger';

    if (score >= 70) return 'safe';
    if (score >= 40) return 'hazard';
    return 'danger';
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8 — API ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

const SERVER_WELL_KNOWN = [
    'github.com','github.io','facebook.com','fb.com','instagram.com',
    'twitter.com','x.com','tiktok.com','netflix.com','linkedin.com',
    'discord.com','twitch.tv','spotify.com','paypal.com','reddit.com',
    'stackoverflow.com','google.com','youtube.com','microsoft.com',
    'apple.com','amazon.com','wikipedia.org','yahoo.com',
    'gcash.com','bdo.com.ph','bpi.com.ph','metrobank.com.ph',
    'landbank.com','unionbankph.com','rcbc.com','paymaya.com','maya.ph',
    'exodus.com','exodus.io','metamask.io','coinbase.com','binance.com',
    'ledger.com','trezor.io',
];

// GET /api/fetch — fetch HTML for preview
app.get('/api/fetch', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'missing url' });
    try {
        const result = await fetchHtml(url);
        const html   = result.text || '';
        const meta   = parseMeta(html, url);
        res.json({
            ok: true,
            htmlSnippet:  html.slice(0, 200_000),
            title:        meta.title,
            description:  meta.description,
            favicon:      meta.favicon,
            finalUrl:     result.finalUrl,
        });
    } catch(err) {
        res.status(500).json({ ok: false, error: String(err.message || err) });
    }
});

// GET /api/whois
app.get('/api/whois', async (req, res) => {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ error: 'missing domain' });
    try {
        const result        = await whoisLookup(domain, 15000);
        const domainAgeDays = parseWhoisAge(result);
        res.json({ ok: true, result, domainAgeDays, source: result?.source });
    } catch(err) {
        res.status(500).json({ ok: false, error: String(err.message || err) });
    }
});

// GET /api/status — health + key availability (never exposes key values)
app.get('/api/status', (req, res) => {
    res.json({
        ok: true,
        version: '8.0.0',
        apis: {
            googleSafeBrowsing: !!GSB_KEY,
            virusTotal:         !!VT_KEY,
            urlscan:            !!URLSCAN_KEY,
            checkPhish:         !!CHECKPHISH_KEY,
            chatAssistant:      !!GEMINI_KEY,
            chatProvider:       GEMINI_KEY ? 'gemini' : null,
        },
    });
});

// GET /api/check — main safety check
app.get('/api/check', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'missing url' });

    // Reject absurdly long URLs before touching any external APIs
    if (url.length > 2083) {
        return res.status(400).json({ ok: false, error: 'URL is too long (max 2083 characters)' });
    }

    const start = Date.now();
    console.log(`\n/api/check ▶ ${url}`);

    // Cache hit — return previous result immediately
    const cacheKey = url.toLowerCase();
    const cached = SCAN_CACHE.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
        console.log(`  cache HIT (${Math.round((cached.expires - Date.now()) / 1000)}s remaining)`);
        return res.json({ ...cached.data, fromCache: true });
    }

    let parsed;
    try { parsed = new URL(url); } catch(e) {
        return res.status(400).json({ ok: false, error: 'Invalid URL' });
    }

    const hostname = parsed.hostname.toLowerCase();

    if (!isValidHostname(hostname)) {
        return res.status(400).json({ ok: false, error: 'Invalid URL — hostname appears to be gibberish or malformed' });
    }

    try {
        const httpsOk   = parsed.protocol === 'https:';
        const shortened = isShortener(hostname);

        let resolvedUrl      = url;
        let redirectChain    = [url];
        let resolvedHostname = hostname;
        let resolvedHttpsOk  = httpsOk;

        if (shortened) {
            const rr = await followRedirects(url, 10, 8000);
            resolvedUrl      = rr.finalUrl;
            redirectChain    = rr.chain;
            try {
                const ru         = new URL(resolvedUrl);
                resolvedHostname = ru.hostname.toLowerCase();
                resolvedHttpsOk  = ru.protocol === 'https:';
            } catch(e) {}
            console.log(`  shortener resolved: ${url} → ${resolvedUrl}`);
        }

        const hostnameAnalysis = analyzeHostname(resolvedHostname);
        const urlFlags         = analyzeUrlStructure(resolvedUrl);
        const builderInfo      = detectFreeSiteBuilder(resolvedHostname);
        const isWellKnown      = SERVER_WELL_KNOWN.some(d => resolvedHostname === d || resolvedHostname.endsWith('.' + d));
        const skipWhois        = resolvedHostname === 'localhost' || resolvedHostname === '127.0.0.1';

        // Parallelise all network + API calls
        const [
            fetched, tlsResult, whoisInfo, dnsFlags,
            gsbResult, vtResult, urlScanResult, checkPhishResult,
            deadResult
        ] = await Promise.all([
            fetchHtml(resolvedUrl, 10000).catch(() => null),
            resolvedHttpsOk
                ? getCertificateInfo(resolvedHostname, 443, 5000).catch(() => ({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }))
                : Promise.resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }),
            skipWhois ? Promise.resolve(null) : whoisLookup(resolvedHostname, 12000).catch(() => null),
            checkDnsReputation(resolvedHostname).catch(() => []),
            checkGoogleSafeBrowsing(resolvedUrl, 8000).catch(() => ({ flagged: false, threatType: null })),
            checkVirusTotal(resolvedUrl, 15000).catch(() => ({ positives: null, total: null })),
            checkUrlScan(resolvedUrl, 20000).catch(() => ({ verdict: null, malicious: null })),
            checkCheckPhish(resolvedUrl, 30000).catch(() => ({ disposition: null, brand: null })),
            checkDeadLink(resolvedUrl, 8000).catch(() => ({ dead: false, reason: null })),
        ]);

        const html       = fetched ? (fetched.text || '') : '';
        const finalUrl   = fetched ? (fetched.finalUrl || resolvedUrl) : resolvedUrl;
        const statusCode = fetched ? fetched.status : null;
        const reachable  = fetched ? (fetched.status != null && fetched.status > 0) : isWellKnown;

        // Dead-link enrichment — confirmed dead if our probe says so AND the server
        // also failed to fetch the page (not just bot-blocked).
        const deadLink   = (deadResult?.dead === true) && !fetched;
        const deadReason = deadLink ? (deadResult?.reason || 'NETWORK_ERROR') : null;
        const deadLabel  = deadLink ? (DEAD_REASON_LABELS[deadReason] || 'This URL is unreachable') : null;

        const { certValid, certExpiresDays, selfSigned: selfSignedCert, issuer: certIssuer } = tlsResult;
        const certExpiresSoon = certExpiresDays !== null && certExpiresDays >= 0 && certExpiresDays < 14;

        let redirectsToHttp = false;
        try { const fu = new URL(finalUrl); redirectsToHttp = fu.protocol === 'http:' && resolvedHttpsOk; } catch(e) {}

        const domainAgeDays = parseWhoisAge(whoisInfo);
        const contentFlags  = deepContentAnalysis(html, resolvedHostname, finalUrl);

        // Free site builder enrichment
        let freeSiteBuilder       = !!builderInfo;
        let freeSiteBuilderName   = builderInfo?.name || null;
        let freeSiteBuilderDetail = null;
        let cryptoFinancialContent = false;
        let cryptoBrands           = [];

        if (builderInfo && html) {
            const meta   = parseMeta(html, resolvedUrl);
            cryptoBrands = detectCryptoFinancialContent(html, meta.title);
            if (cryptoBrands.length > 0) {
                cryptoFinancialContent = true;
                freeSiteBuilderDetail  = `Site hosted on ${builderInfo.name} and references "${cryptoBrands.slice(0,3).join('", "')}" — legitimate financial/crypto services NEVER use free website builders. Almost certainly phishing.`;
                contentFlags.unshift({ type: 'crypto-brand-on-free-host', severity: 'high', detail: freeSiteBuilderDetail });
            } else {
                freeSiteBuilderDetail = `Site is hosted on ${builderInfo.name} — a free website builder. Legitimate businesses and financial services do not use these platforms.`;
                contentFlags.push({ type: 'free-site-builder', severity: 'medium', detail: freeSiteBuilderDetail });
            }
        }

        // urlscan enrichment
        const urlScanMalicious  = urlScanResult?.malicious === true;
        const urlScanVerdict    = urlScanResult?.verdict || null;
        const urlScanScore      = urlScanResult?.score   ?? null;
        const urlScanScreenshot = urlScanResult?.screenshotURL || null;
        const urlScanReport     = urlScanResult?.reportURL     || null;

        if (urlScanMalicious) {
            contentFlags.push({ type: 'urlscan-malicious', severity: 'high',
                detail: `urlscan.io flagged this site as malicious (${urlScanVerdict || 'threat detected'})` });
        }

        // CheckPhish enrichment
        const checkPhishDisposition = checkPhishResult?.disposition || null;
        const checkPhishBrand       = checkPhishResult?.brand       || null;
        const checkPhishPhish       = checkPhishDisposition === 'phish';
        const checkPhishSuspect     = checkPhishDisposition === 'suspect';

        if (checkPhishPhish || checkPhishSuspect) {
            contentFlags.push({ type: 'checkphish-flag', severity: checkPhishPhish ? 'high' : 'medium',
                detail: checkPhishBrand
                    ? `CheckPhish identified this page as impersonating "${checkPhishBrand}" (${checkPhishDisposition})`
                    : `CheckPhish flagged this site as ${checkPhishDisposition}` });
        }

        // Build signals
        const signals = {
            isTrusted:              isTrustedDomain(resolvedHostname),
            hardBlacklisted:        hostnameAnalysis.hardBlacklisted,
            brandSpoof:             hostnameAnalysis.brandSpoof,
            spoofedBrand:           hostnameAnalysis.spoofedBrand,
            patternMatch:           hostnameAnalysis.patternMatch,
            urlFlags,
            httpsOk:                resolvedHttpsOk,
            certValid, certExpiresDays, selfSignedCert, certExpiresSoon,
            redirectsToHttp,
            domainAgeDays,
            contentFlags,
            dnsFlags,
            reachable,
            googleSafeBrowsing:     gsbResult.flagged,
            virusTotalPositives:    vtResult.positives,
            urlScanMalicious,
            checkPhishPhish,
            checkPhishSuspect,
            freeSiteBuilder,
            cryptoFinancialContent,
        };

        const riskScore = calculateRiskScore(signals);
        const verdict   = determineVerdict(riskScore, signals);
        const allFlags  = [...urlFlags, ...contentFlags, ...dnsFlags];
        const totalDuration = Date.now() - start;

        console.log(`  verdict=${verdict} score=${riskScore} gsb=${gsbResult.flagged} vt=${vtResult.positives} urlscan=${urlScanMalicious} checkphish=${checkPhishDisposition} freeBuild=${freeSiteBuilder} crypto=${cryptoFinancialContent} flags=${allFlags.length} ${totalDuration}ms`);

        const responseData = {
            ok: true,
            reachable, statusCode, httpsOk: resolvedHttpsOk,
            deadLink, deadReason, deadLabel,
            certValid, certExpiresDays, certIssuer, selfSignedCert, certExpiresSoon,
            redirectsToHttp,
            blacklisted:  hostnameAnalysis.hardBlacklisted,
            patternMatch: hostnameAnalysis.patternMatch,
            brandSpoof:   hostnameAnalysis.brandSpoof,
            spoofedBrand: hostnameAnalysis.spoofedBrand,
            domainAgeDays,
            contentFlags: allFlags,
            riskScore,
            verdict,
            shortened,
            resolvedUrl:   shortened ? resolvedUrl   : undefined,
            redirectChain: shortened && redirectChain.length > 1 ? redirectChain : undefined,
            // Google Safe Browsing
            googleSafeBrowsing: gsbResult.flagged,
            safeBrowsingThreat: gsbResult.threatType,
            // VirusTotal
            virusTotalPositives: vtResult.positives,
            virusTotalTotal:     vtResult.total,
            // urlscan.io
            urlScanMalicious,
            urlScanVerdict,
            urlScanScore,
            urlScanScreenshot,
            urlScanReport,
            // CheckPhish
            checkPhishDisposition,
            checkPhishBrand,
            // Free site builder
            freeSiteBuilder,
            freeSiteBuilderName,
            freeSiteBuilderDetail,
            cryptoFinancialContent,
            cryptoBrands,
            // Meta
            totalDuration,
        };

        // Store in cache before responding
        SCAN_CACHE.set(cacheKey, { data: responseData, expires: Date.now() + SCAN_CACHE_TTL });

        res.json(responseData);

    } catch(err) {
        console.warn(`/api/check ERROR ${url}:`, err?.message || err);
        res.status(500).json({ ok: false, error: String(err.message || err) });
    }
});

// POST /api/chat — Gemini streaming chat assistant proxy (key stays server-side)
app.post('/api/chat', async (req, res) => {
    if (!GEMINI_KEY) {
        return res.status(503).json({ ok: false, error: 'Chat assistant is not configured on this server.' });
    }
    const { messages, system } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ ok: false, error: 'messages array is required.' });
    }

    // Sanitise messages — only allow role + string content
    // Gemini uses "user" / "model" roles (not "assistant")
    const safeMessages = messages
        .filter(m => m && ['user', 'assistant'].includes(m.role) && typeof m.content === 'string')
        .slice(-20)
        .map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] }));

    if (safeMessages.length === 0) {
        return res.status(400).json({ ok: false, error: 'No valid messages provided.' });
    }

    // Token-budget guard: reject if total content exceeds ~40 000 chars (~10k tokens)
    const totalChars = safeMessages.reduce((acc, m) => acc + (m.parts[0]?.text?.length || 0), 0);
    if (totalChars > 40_000) {
        return res.status(400).json({ ok: false, error: 'Conversation is too long — please start a new chat.' });
    }

    // Build Gemini request body
    const geminiBody = {
        system_instruction: typeof system === 'string' && system
            ? { parts: [{ text: system.slice(0, 8192) }] }
            : undefined,
        contents: safeMessages,
        generationConfig: {
            maxOutputTokens: 1024,
            temperature: 0.7,
        },
    };

    // Remove undefined key so JSON.stringify omits it cleanly
    if (!geminiBody.system_instruction) delete geminiBody.system_instruction;

    const GEMINI_URL =
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:streamGenerateContent` +
        `?alt=sse&key=${GEMINI_KEY}`;

    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), 30000);

        const upstream = await fetch(GEMINI_URL, {
            method:  'POST',
            signal:  ctrl.signal,
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(geminiBody),
        });

        clearTimeout(tid);

        if (!upstream.ok) {
            const errText = await upstream.text().catch(() => '');
            console.warn('/api/chat Gemini upstream error:', upstream.status, errText.slice(0, 300));
            return res.status(502).json({ ok: false, error: 'Chat service returned an error. Please try again.' });
        }

        // Stream Gemini SSE → client using our own SSE format
        // Gemini sends: data: {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
        // We re-emit as:  data: {"text":"..."}   (simpler format the frontend reads)
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('X-Accel-Buffering', 'no');

        let buffer = '';

        upstream.body.on('data', chunk => {
            if (res.writableEnded) return;
            buffer += chunk.toString('utf8');
            const lines = buffer.split('\n');
            buffer = lines.pop(); // keep any incomplete line

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed.startsWith('data:')) continue;
                const raw = trimmed.slice(5).trim();
                if (!raw || raw === '[DONE]') continue;
                try {
                    const evt  = JSON.parse(raw);
                    const text = evt?.candidates?.[0]?.content?.parts?.[0]?.text;
                    if (text) {
                        res.write(`data: ${JSON.stringify({ text })}\n\n`);
                    }
                } catch (_) { /* partial JSON — skip */ }
            }
        });

        upstream.body.on('end', () => {
            if (!res.writableEnded) {
                res.write('data: [DONE]\n\n');
                res.end();
            }
        });

        upstream.body.on('error', err => {
            console.warn('/api/chat Gemini stream error:', err.message);
            if (!res.writableEnded) res.end();
        });

    } catch(err) {
        console.warn('/api/chat error:', err.message);
        if (!res.headersSent) res.status(500).json({ ok: false, error: 'Chat request failed.' });
    }
});

// ── Graceful shutdown (SIGTERM sent by Render / Railway / Fly.io) ─────────────────
let server; // assigned below by app.listen

process.on('SIGTERM', () => {
    console.log('[shutdown] SIGTERM received — closing gracefully…');
    if (server) {
        server.close(() => { console.log('[shutdown] Closed. Exiting.'); process.exit(0); });
        setTimeout(() => process.exit(1), 10_000).unref();
    } else {
        process.exit(0);
    }
});

// ── Catch-all for unmatched routes ────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
    console.error('Unhandled error:', err.message);
    res.status(500).json({ ok: false, error: 'Internal server error' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9 — STARTUP
// ═══════════════════════════════════════════════════════════════════════════════

server = app.listen(PORT, () => {
    const url = `http://localhost:${PORT}`;
    console.log('\n╔══════════════════════════════════════════╗');
    const envLabel = process.env.NODE_ENV === 'production' ? 'Production ' : 'Local Dev  ';
    console.log(`║         WebSafe v8 — ${envLabel}          ║`);
    console.log('╠══════════════════════════════════════════╣');
    console.log(`║  Server : ${url.padEnd(31)}║`);
    console.log('║  APIs   :                                ║');
    console.log(`║    GSB          : ${(GSB_KEY         ? '✓ configured' : '✗ unset (GSB_KEY)').padEnd(22)}║`);
    console.log(`║    VirusTotal   : ${(VT_KEY          ? '✓ configured' : '✗ unset (VT_KEY)').padEnd(22)}║`);
    console.log(`║    urlscan.io   : ${(URLSCAN_KEY     ? '✓ configured' : '✗ unset (URLSCAN_KEY)').padEnd(22)}║`);
    console.log(`║    CheckPhish   : ${(CHECKPHISH_KEY  ? '✓ configured' : '✗ unset (CHECKPHISH_KEY)').padEnd(22)}║`);
    console.log(`║    Chat (Gemini) : ${(GEMINI_KEY     ? '✓ configured' : '✗ unset (GEMINI_API_KEY)').padEnd(22)}║`);
    console.log('╚══════════════════════════════════════════╝\n');

    // Auto-open browser on local dev only — never runs in production
    if (process.env.NODE_ENV !== 'production') {
        const { exec } = require('child_process');
        const cmd =
            process.platform === 'win32'  ? `start "" "${url}"` :
            process.platform === 'darwin' ? `open "${url}"` :
                                            `xdg-open "${url}"`;
        exec(cmd, err => { if (err) console.log(`  Open in browser: ${url}/main.html`); });
    }
});
