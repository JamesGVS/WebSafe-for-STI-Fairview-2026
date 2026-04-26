// server.js — WebSafe
// API keys are read from environment variables:
//   GSB_KEY : Google Safe Browsing v4 — https://developers.google.com/safe-browsing/v4/get-started
//   VT_KEY  : VirusTotal Public API   — https://www.virustotal.com/gui/join-us (free: 4 req/min)
// Both are optional; their checks are skipped when the vars are unset.

const GOOGLE_SAFE_BROWSING_KEY = process.env.GSB_KEY || '';
const VIRUSTOTAL_KEY           = process.env.VT_KEY  || '';

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

const ALLOWED_ORIGINS = [
    'https://websafe-v9gz.onrender.com',
    'http://localhost:3000',
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    }
}));
app.use(express.json());
// Serve only specific public files — do NOT expose server.js or other source files
const PUBLIC_FILES = {
    '/main.html':          'main.html',
    '/main.css':           'main.css',
    '/check_link.js':      'check_link.js',
    '/about_us.html':      'about_us.html',
    '/about_us.css':       'about_us.css',
    '/contact_local.html': 'contact_local.html',
    '/contact_local.css':  'contact_local.css',
};
app.use('/images', express.static(path.join(__dirname, 'images')));
Object.entries(PUBLIC_FILES).forEach(([route, file]) => {
    app.get(route, (req, res) => res.sendFile(path.join(__dirname, file)));
});
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'main.html')));

// ── Simple in-memory rate limiter (10 req/min per IP) ────────────────────────
const _rateMap = new Map();
app.use('/api/', (req, res, next) => {
    const ip  = req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    const entry = _rateMap.get(ip) || { count: 0, reset: now + 60000 };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
    entry.count++;
    _rateMap.set(ip, entry);
    if (entry.count > 10) {
        return res.status(429).json({ ok: false, error: 'Too many requests — please wait a moment.' });
    }
    next();
});
// Clean up rate map every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of _rateMap) { if (now > entry.reset) _rateMap.delete(ip); }
}, 300000);

app.use((req, res, next) => {
    console.log(`${new Date().toISOString()}  ${req.method} ${req.originalUrl}`);
    next();
});

// ── URL VALIDATION ───────────────────────────────────────────────────────────

/**
 * Returns false for gibberish input like "snawkd nskan", "asdfjk.qwer", etc.
 */
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

    // Gibberish: label >= 5 chars with no vowels
    const vowels = /[aeiou]/i;
    for (const part of parts) {
        if (part.length >= 5 && !vowels.test(part)) return false;
    }

    // Consonant-cluster gibberish: >88% consonants in a label ≥ 6 chars
    for (const part of parts) {
        if (part.length >= 6) {
            const consonants = (part.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
            if (consonants / part.length > 0.88) return false;
        }
    }

    return true;
}

// ── BLACKLISTS & PATTERN DETECTION ───────────────────────────────────────────

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
    // v7 additions: crypto wallet brand impersonation
    /\b(exodus|metamask|ledger|trezor|coinbase|binance|trust.?wallet)\b.*(download|install|support|recover|restore|seed|phrase|connect)/i,
    /\b(exodus|metamask|ledger|trezor|coinbase|binance|trust.?wallet)\b/i, // any mention on suspicious hosting
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
    // v7: crypto wallets
    exodus:     ['exodus.com','exodus.io'],
    metamask:   ['metamask.io'],
    coinbase:   ['coinbase.com'],
    binance:    ['binance.com','binance.us'],
    ledger:     ['ledger.com'],
    trezor:     ['trezor.io','trezor.com'],
};

// ── FREE SITE BUILDER / DISPOSABLE HOSTING DETECTION ─────────────────────────
// Legitimate businesses never use these platforms for banking, crypto, or finance.
// Presence alone = WARNING. Presence + financial/crypto brand = DANGER.
const FREE_SITE_BUILDERS = [
    // Wix family
    { domain: 'wix.com',       name: 'Wix' },
    { domain: 'wixsite.com',   name: 'Wix' },
    { domain: 'wixstudio.com', name: 'Wix Studio' },
    { domain: 'editorx.com',   name: 'Editor X (Wix)' },
    // Other builders
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
    // Dev/free hosting (high abuse)
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

/**
 * Crypto wallet and financial brands that should NEVER appear on free hosting.
 */
const CRYPTO_FINANCIAL_BRANDS = [
    'exodus', 'metamask', 'coinbase', 'binance', 'ledger', 'trezor',
    'trust wallet', 'trustwallet', 'phantom', 'solflare', 'keplr',
    'uniswap', 'pancakeswap', 'opensea', 'rarible', 'crypto.com',
    'blockchain', 'bitcoin', 'ethereum', 'wallet', 'seed phrase',
    'recovery phrase', 'private key', 'defi', 'web3', 'nft',
    'gcash', 'paymaya', 'maya', 'bdo', 'bpi', 'metrobank',
    'paypal', 'stripe', 'bank account', 'wire transfer',
];

/**
 * Returns the matching free site builder info, or null.
 */
function detectFreeSiteBuilder(hostname) {
    const h = hostname.toLowerCase().replace(/^www\./, '');
    for (const builder of FREE_SITE_BUILDERS) {
        if (h === builder.domain || h.endsWith('.' + builder.domain)) {
            return builder;
        }
    }
    return null;
}

/**
 * Checks if HTML content references crypto/financial brands.
 * Returns matched brand names.
 */
function detectCryptoFinancialContent(html, title) {
    const text = ((html || '') + ' ' + (title || '')).toLowerCase();
    return CRYPTO_FINANCIAL_BRANDS.filter(brand => text.includes(brand.toLowerCase()));
}

function analyzeHostname(hostname) {
    const h = hostname.toLowerCase().replace(/^www\./, '');

    // Trusted domains are never flagged — they are the real sites
    if (isTrustedDomain(h)) return { hardBlacklisted: false, patternMatch: false, brandSpoof: false };

    if (HARD_BLACKLIST.has(h)) return { hardBlacklisted: true, patternMatch: false, brandSpoof: false };

    const parts = h.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
        const sub = parts.slice(i).join('.');
        if (HARD_BLACKLIST.has(sub)) return { hardBlacklisted: true, patternMatch: false, brandSpoof: false };
    }

    const patternMatch = SUSPICIOUS_PATTERNS.some(p => p.test(h));

    let brandSpoof = false, spoofedBrand = null;
    for (const [brand, legitimateDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
        const brandRegex = new RegExp(`\\b${brand}\\b`, 'i');
        if (brandRegex.test(h)) {
            const isLegit = legitimateDomains.some(d => h === d || h.endsWith('.' + d));
            if (!isLegit) { brandSpoof = true; spoofedBrand = brand; break; }
        }
    }

    return { hardBlacklisted: false, patternMatch, brandSpoof, spoofedBrand };
}

// ── URL STRUCTURE ANALYSIS ────────────────────────────────────────────────────

function analyzeUrlStructure(urlStr) {
    const flags = [];
    let parsed;
    try { parsed = new URL(urlStr); } catch(e) { return flags; }

    const hostname = parsed.hostname.toLowerCase();

    const labels = hostname.split('.');
    if (labels.length >= 5) {
        flags.push({ type: 'excessive-subdomains', severity: 'high',
            detail: `Unusually deep subdomain chain (${labels.length} levels) — common phishing trick` });
    }

    const tldPlusOne = labels.slice(-2).join('.');
    const subdomains = labels.slice(0, -2).join('.');
    for (const [brand, legitimateDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
        if (new RegExp(`\\b${brand}\\b`, 'i').test(subdomains)) {
            const isLegit = legitimateDomains.some(d => hostname === d || hostname.endsWith('.' + d));
            if (!isLegit) {
                flags.push({ type: 'brand-in-subdomain', severity: 'high',
                    detail: `"${brand}" used as subdomain on unrelated domain "${tldPlusOne}" — classic phishing` });
            }
        }
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        flags.push({ type: 'ip-address', severity: 'high',
            detail: 'URL uses a raw IP address instead of a domain name — almost always malicious' });
    }

    if (urlStr.length > 150) {
        flags.push({ type: 'long-url', severity: 'medium',
            detail: `Unusually long URL (${urlStr.length} characters) — often used to hide the real destination` });
    }

    if (urlStr.toLowerCase().includes('@')) {
        flags.push({ type: 'at-sign-url', severity: 'high',
            detail: 'URL contains an @ sign — can be used to disguise the real destination' });
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

    // ── PhishTank-style: Shannon entropy of domain ────────────────────────────
    // High-entropy domains (random-generated) are a strong phishing signal
    function shannonEntropy(str) {
        const freq = {};
        for (const c of str) freq[c] = (freq[c] || 0) + 1;
        const len = str.length;
        let e = 0;
        for (const c in freq) { const p = freq[c]/len; e -= p * Math.log2(p); }
        return e;
    }
    const domainNoTld = labels.slice(0, -1).join('').replace(/-/g, '');
    // Only check entropy on purely alphabetic domains — numeric-prefixed brands (1337x, 4chan, 9gag) are legitimate
    const isAlphaOnly = /^[a-zA-Z]+$/.test(domainNoTld);
    if (isAlphaOnly && domainNoTld.length > 10) {
        const ent = shannonEntropy(domainNoTld);
        if (ent > 3.8) {
            flags.push({ type: 'high-entropy-domain', severity: 'medium',
                detail: `Domain name entropy is ${ent.toFixed(2)} — statistically random-looking, typical of algorithmically-generated phishing domains` });
        }
    }

    // ── PhishTank-style: IDN Homograph / non-ASCII hostname ──────────────────
    if (/[^\x00-\x7F]/.test(hostname)) {
        flags.push({ type: 'homograph-attack', severity: 'high',
            detail: 'Hostname contains non-ASCII characters — possible IDN homograph attack using lookalike letters (e.g. Cyrillic "а" instead of Latin "a")' });
    }

    // Numeric letter substitution: only flag when numbers replace letters mid-brand (g00gle, p4ypal)
    // NOT when the domain starts with numbers — those are legitimate brand names (1337x, 4chan, 9gag, 1337x)
    const hostnameNoWww = hostname.replace(/^www\./, '');
    const domainLabel   = hostnameNoWww.split('.')[0];
    const startsWithNum = /^[0-9]/.test(domainLabel);
    if (!startsWithNum && /[a-z][0-9][a-z]/i.test(hostnameNoWww.replace(/\./g, ''))) {
        flags.push({ type: 'numeric-substitution', severity: 'high',
            detail: 'Numbers replacing letters detected in domain — a classic brand-spoofing technique (e.g. g00gle, p4ypal)' });
    }

    return flags;
}

// ── EXTERNAL THREAT APIS ─────────────────────────────────────────────────────

/**
 * Google Safe Browsing v4 — free API, extremely accurate.
 * Returns { flagged: bool, threatType: string|null }
 */
async function checkGoogleSafeBrowsing(url, timeout = 8000) {
    if (!GOOGLE_SAFE_BROWSING_KEY) {
        return { flagged: false, threatType: null, skipped: true };
    }
    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_KEY}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: ctrl.signal,
                body: JSON.stringify({
                    client:    { clientId: 'websafe-v7', clientVersion: '7.0' },
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
        if (j && j.matches && j.matches.length > 0) {
            const match = j.matches[0];
            return { flagged: true, threatType: match.threatType || 'THREAT_DETECTED' };
        }
        return { flagged: false, threatType: null };
    } catch (e) {
        return { flagged: false, threatType: null, error: e.message };
    }
}

/**
 * VirusTotal Public API v3 — free (4 req/min), multi-engine URL scanner.
 * Returns { positives: number, total: number, permalink: string }
 */
async function checkVirusTotal(url, timeout = 12000) {
    if (!VIRUSTOTAL_KEY) {
        return { positives: null, total: null, skipped: true };
    }
    try {
        // Step 1: submit URL for analysis
        const submitCtrl = new AbortController();
        const submitTid  = setTimeout(() => submitCtrl.abort(), timeout);
        const submitRes  = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'x-apikey':     VIRUSTOTAL_KEY,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body:   `url=${encodeURIComponent(url)}`,
            signal: submitCtrl.signal,
        });
        clearTimeout(submitTid);
        if (!submitRes.ok) return { positives: null, total: null, error: `Submit HTTP ${submitRes.status}` };
        const submitJson = await submitRes.json();
        const analysisId = submitJson?.data?.id;
        if (!analysisId) return { positives: null, total: null, error: 'No analysis ID' };

        // Step 2: poll result (wait 3s then fetch)
        await new Promise(r => setTimeout(r, 3000));
        const reportCtrl = new AbortController();
        const reportTid  = setTimeout(() => reportCtrl.abort(), timeout);
        const reportRes  = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { 'x-apikey': VIRUSTOTAL_KEY },
            signal: reportCtrl.signal,
        });
        clearTimeout(reportTid);
        if (!reportRes.ok) return { positives: null, total: null, error: `Report HTTP ${reportRes.status}` };
        const reportJson = await reportRes.json();
        const stats = reportJson?.data?.attributes?.stats;
        if (!stats) return { positives: null, total: null };
        const positives = (stats.malicious || 0) + (stats.suspicious || 0);
        const total     = Object.values(stats).reduce((a, b) => a + b, 0);
        return { positives, total };
    } catch (e) {
        return { positives: null, total: null, error: e.message };
    }
}

// ── TRUSTED DOMAINS & CONTENT ANALYSIS ───────────────────────────────────────

const TRUSTED_DOMAINS = new Set([
    'facebook.com','google.com','youtube.com','twitter.com','instagram.com',
    'microsoft.com','apple.com','amazon.com','wikipedia.org','linkedin.com',
    'reddit.com','yahoo.com','netflix.com','github.com','stackoverflow.com',
    'paypal.com','bankofamerica.com','chase.com','wellsfargo.com','x.com',
    'tiktok.com','discord.com','twitch.tv','spotify.com','dropbox.com',
    'gcash.com','bdo.com.ph','bpi.com.ph','metrobank.com.ph','landbank.com',
    'unionbankph.com','rcbc.com','paymaya.com','maya.ph',
    // AI assistants & tools
    'chatgpt.com','openai.com','claude.ai','anthropic.com','gemini.google.com',
    'bard.google.com','copilot.microsoft.com','bing.com',
    // Google subdomains
    'scholar.google.com','drive.google.com','docs.google.com','maps.google.com',
    'mail.google.com','accounts.google.com','play.google.com','news.google.com',
    'translate.google.com','meet.google.com','classroom.google.com',
    'googleapis.com','gstatic.com','googleusercontent.com',
    // Microsoft / Office
    'office.com','outlook.com','live.com','hotmail.com','azure.com',
    'microsoftonline.com','sharepoint.com','teams.microsoft.com',
    // Popular productivity & social
    'zoom.us','slack.com','notion.so','canva.com','figma.com',
    'medium.com','substack.com','twitch.tv','pinterest.com','tumblr.com',
    // Philippines-specific
    'shopee.ph','lazada.com.ph','grab.com','rappler.com','inquirer.net',
    'philstar.com','abs-cbn.com','gma.com.ph','pna.gov.ph','gov.ph',
    // Crypto (legitimate)
    'exodus.com','exodus.io','metamask.io','coinbase.com','binance.com',
    'ledger.com','trezor.io','trezor.com',
    // Well-known sites with non-.com TLDs that would otherwise be flagged
    '1337x.to','limetorrents.info','thepiratebay.org','nyaa.si',
    'archive.org','archive.ph','web.archive.org',
    'pastebin.com','hastebin.com','privatebin.net',
    'protonmail.com','proton.me','tutanota.com','protonvpn.com',
    'duckduckgo.com','startpage.com','brave.com',
    'npm.js','npmjs.com','pypi.org','packagist.org','crates.io',
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
    // v7 additions
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

    const isTrusted = isTrustedDomain(hostname);
    if (isTrusted) return flags;

    let $;
    try { $ = cheerio.load(html); } catch(e) { return flags; }

    const bodyText  = ($('body').text() || '').toLowerCase().replace(/\s+/g, ' ');
    const titleText = ($('title').text() || '').toLowerCase();
    const fullText  = bodyText + ' ' + titleText;

    // 1. High-risk keywords
    const foundHigh = HIGH_RISK_PHRASES.filter(k => fullText.includes(k.toLowerCase()));
    if (foundHigh.length >= 2)      flags.push({ type: 'keywords-high', severity: 'high', detail: foundHigh.slice(0, 4) });
    else if (foundHigh.length === 1) flags.push({ type: 'keywords-high', severity: 'medium', detail: foundHigh });

    // 2. Medium-risk keywords
    const foundMedium = MEDIUM_RISK_PHRASES.filter(k => fullText.includes(k.toLowerCase()));
    if (foundMedium.length >= 2)    flags.push({ type: 'keywords-medium', severity: 'medium', detail: foundMedium.slice(0, 4) });

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
                break;
            }
        }
    }

    // 4. Multiple password fields
    const pwFields = $('input[type="password"]').length;
    if (pwFields >= 2) {
        flags.push({ type: 'multiple-password-fields', severity: 'high',
            detail: `Page has ${pwFields} password fields — possibly harvesting credentials` });
    }

    // 5. External form action
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
            detail: `Suspicious JS techniques: ${obfuscationFound.join(', ')} — common in malicious pages` });
    }

    // 7. Large base64 blobs
    const base64Matches = (scripts.match(/[A-Za-z0-9+/]{80,}={0,2}/g) || []);
    if (base64Matches.length >= 2) {
        flags.push({ type: 'base64-payload', severity: 'medium',
            detail: `${base64Matches.length} large encoded data blobs found — may be hiding malicious content` });
    }

    // 8. Hidden iframes
    $('iframe').each((_, el) => {
        const src   = $(el).attr('src') || '';
        const style = ($(el).attr('style') || '').toLowerCase();
        const hidden = style.includes('display:none')||style.includes('display: none')||
                       style.includes('visibility:hidden')||style.includes('width:0')||style.includes('height:0');
        if (hidden && src) {
            flags.push({ type: 'hidden-iframe', severity: 'high',
                detail: `Hidden iframe loading "${src}" — can be used for clickjacking or silent redirects` });
        }
    });

    // 9. Meta refresh redirect
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

    // 10. Fake security badges
    const securityBadgeKeywords = ['mcafee secure','norton secured','ssl secured','verified by visa',
        'security verified','100% safe','your information is safe'];
    const badgesFound = securityBadgeKeywords.filter(b => fullText.includes(b));
    if (badgesFound.length >= 2) {
        flags.push({ type: 'fake-trust-badges', severity: 'medium',
            detail: 'Page uses multiple "security verified" claims — commonly faked on scam sites' });
    }

    return flags;
}

// ── NETWORK HELPERS ───────────────────────────────────────────────────────────

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
                headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebSafe/7.0)' }
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
    } catch (err) { clearTimeout(id); throw err; }
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
                if (cert && cert.issuer && cert.subject) {
                    selfSigned = JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);
                }
                const issuer = cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || '') : '';
                resolve({ cert, certExpiresDays: expires, certValid: valid, selfSigned, issuer });
            } catch (e) {
                resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' });
            } finally { try { sock.end(); } catch (e) {} }
        });
        sock.setTimeout(timeout, () => { try { sock.destroy(); } catch(e) {} resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }); });
        sock.on('error', () => resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }));
    });
}

async function checkDnsReputation(hostname) {
    const flags = [];
    const clean = hostname.replace(/^www\./, '');
    try {
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
        const addresses = await dns.resolve4(clean).catch(() => []);
        if (addresses.length > 0) {
            const ip = addresses[0];
            if (ip.startsWith('185.')) {
                flags.push({ type: 'suspicious-hosting', severity: 'low',
                    detail: `Hosted on IP block (${ip}) commonly associated with bulletproof hosting` });
            }
        }
    } catch(e) { console.debug(`checkDnsReputation failed for ${clean}:`, e.message); }
    return flags;
}

// ── WHOIS / DOMAIN AGE ────────────────────────────────────────────────────────

async function whoisLookup(domain, timeout = 15000) {
    const clean = domain.replace(/^www\./, '');

    try {
        const ctrl = new AbortController(); const tid = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(`https://www.whoisjsonapi.com/v1/${encodeURIComponent(clean)}`, { signal: ctrl.signal, headers: { 'Accept': 'application/json' } });
        clearTimeout(tid);
        if (res.ok) {
            const j = await res.json();
            if (j && j.domain && j.domain.created_date) return { source: 'whoisjsonapi', createdDate: j.domain.created_date, expiresDate: j.domain.expiration_date, registrar: j.registrar && j.registrar.name };
        }
    } catch(e) { console.debug(`whois whoisjsonapi failed for ${clean}:`, e.message); }

    try {
        const ctrl = new AbortController(); const tid = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(`https://rdap.org/domain/${encodeURIComponent(clean)}`, { signal: ctrl.signal, headers: { 'Accept': 'application/json' } });
        clearTimeout(tid);
        if (res.ok) {
            const j = await res.json();
            if (j && Array.isArray(j.events)) {
                const reg = j.events.find(e => e.eventAction === 'registration');
                if (reg && reg.eventDate) return { source: 'rdap', createdDate: reg.eventDate };
            }
        }
    } catch(e) { console.debug(`whois rdap failed for ${clean}:`, e.message); }

    try {
        const ctrl = new AbortController(); const tid = setTimeout(() => ctrl.abort(), timeout);
        const res  = await fetch(`https://api.domainsdb.info/v1/domains/search?domain=${encodeURIComponent(clean)}&zone=${clean.split('.').pop()}`, { signal: ctrl.signal, headers: { 'Accept': 'application/json' } });
        clearTimeout(tid);
        if (res.ok) {
            const j = await res.json();
            if (j && Array.isArray(j.domains) && j.domains.length > 0) {
                const match = j.domains.find(d => d.domain === clean) || j.domains[0];
                if (match && match.create_date) return { source: 'domainsdb', createdDate: match.create_date };
            }
        }
    } catch(e) { console.debug(`whois domainsdb failed for ${clean}:`, e.message); }

    try {
        const raw = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('whois timeout')), timeout);
            whois.lookup(clean, (err, data) => { clearTimeout(timer); if (err) return reject(err); resolve(data || ''); });
        });
        if (raw) {
            const patterns = [/Creation Date:\s*(.+)/i,/Created:\s*(.+)/i,/Domain Registration Date:\s*(.+)/i,/Registered on:\s*(.+)/i,/created:\s*(.+)/i];
            for (const p of patterns) {
                const m = raw.match(p);
                if (m) { const d = new Date(m[1].trim()); if (!isNaN(d.getTime())) return { source: 'raw-whois', createdDate: m[1].trim() }; }
            }
        }
    } catch(e) { console.debug(`whois raw-whois failed for ${clean}:`, e.message); }

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

// ── SCORING ENGINE ────────────────────────────────────────────────────────────

function calculateRiskScore(signals) {
    let score = 100;

    // Hard blacklist / brand spoof
    if (signals.hardBlacklisted)  score -= 80;
    if (signals.brandSpoof)       score -= 60;
    if (signals.patternMatch)     score -= 40;

    // External API results (v7)
    if (signals.googleSafeBrowsing) score -= 70; // Google says it's bad = nearly auto-fail
    if (signals.virusTotalPositives > 3)  score -= 40;
    else if (signals.virusTotalPositives > 0) score -= 20;

    // Free site builder (v7)
    if (signals.freeSiteBuilder) {
        score -= 20; // being on free hosting alone = moderate penalty
        if (signals.cryptoFinancialContent) score -= 40; // brand on free hosting = very high penalty
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
    if (!signals.httpsOk)            score -= 30;
    if (!signals.certValid)          score -= 25;
    if (signals.selfSignedCert)      score -= 20;
    if (signals.redirectsToHttp)     score -= 20;
    if (signals.certExpiresSoon)     score -= 10;

    // Domain age — penalise new, reward established
    if (signals.domainAgeDays !== null) {
        if      (signals.domainAgeDays < 7)        score -= 40;
        else if (signals.domainAgeDays < 30)       score -= 25;
        else if (signals.domainAgeDays < 90)       score -= 10;
        else if (signals.domainAgeDays < 180)      score -= 5;
        else if (signals.domainAgeDays >= 365)     score += 5;  // bonus: 1+ year old
        else if (signals.domainAgeDays >= 1825)    score += 10; // bonus: 5+ years
    } else { score -= 8; } // unknown age = slight penalty

    // Content analysis
    if (signals.contentFlags) {
        for (const f of signals.contentFlags) {
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
    }

    // DNS
    if (signals.dnsFlags) {
        for (const f of signals.dnsFlags) {
            if (f.severity === 'high')   score -= 20;
            if (f.severity === 'medium') score -= 10;
            if (f.severity === 'low')    score -= 5;
        }
    }

    // Reachability — not a hard signal, just a soft one
    if (signals.reachable === false) score -= 10;

    // Positive signals that reduce false-positive rate
    if (signals.httpsOk && signals.certValid && !signals.selfSignedCert)  score += 5;
    if (signals.domainAgeDays >= 730 && signals.httpsOk && signals.certValid) score += 5; // 2+ years + valid cert = trust boost

    return Math.max(0, Math.min(100, Math.round(score)));
}

function determineVerdict(score, signals) {
    // Trusted domains — always safe, no overrides apply
    if (signals.isTrusted) return 'safe';

    // Hard overrides — no escape
    if (signals.hardBlacklisted || signals.brandSpoof) return 'danger';
    if (signals.googleSafeBrowsing) return 'danger';
    if (signals.virusTotalPositives > 3) return 'danger';

    // Free site builder + crypto brand = always danger
    if (signals.freeSiteBuilder && signals.cryptoFinancialContent) return 'danger';

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

// ── API ROUTES ────────────────────────────────────────────────────────────────

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
        const result        = await whoisLookup(domain, 15000);
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

        let parsed;
        try { parsed = new URL(url); } catch(e) {
            return res.status(400).json({ ok: false, error: 'Invalid URL' });
        }

        const hostname = parsed.hostname.toLowerCase();

        // ── Server-side gibberish check ────────────────────────────────────
        if (!isValidHostname(hostname)) {
            return res.status(400).json({ ok: false, error: 'Invalid URL — hostname appears to be gibberish or malformed' });
        }

        const httpsOk   = parsed.protocol === 'https:';
        const shortened = isShortener(hostname);

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

        const hostnameAnalysis = analyzeHostname(resolvedHostname);
        const urlFlags         = analyzeUrlStructure(resolvedUrl);

        // ── Free site builder detection (v7) ───────────────────────────────
        const builderInfo = detectFreeSiteBuilder(resolvedHostname);

        const isWellKnown  = SERVER_WELL_KNOWN.some(d => resolvedHostname === d || resolvedHostname.endsWith('.' + d));
        const skipWhois    = (resolvedHostname === 'localhost' || resolvedHostname === '127.0.0.1');

        // ── Parallelise all network calls ──────────────────────────────────
        const [fetched, tlsResult, whoisInfo, dnsFlags, gsbResult, vtResult] = await Promise.all([
            fetchHtml(resolvedUrl, 10000).catch(() => null),
            resolvedHttpsOk
                ? getCertificateInfo(resolvedHostname, 443, 5000).catch(() => ({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }))
                : Promise.resolve({ cert: null, certExpiresDays: null, certValid: false, selfSigned: false, issuer: '' }),
            skipWhois ? Promise.resolve(null) : whoisLookup(resolvedHostname, 12000).catch(() => null),
            checkDnsReputation(resolvedHostname).catch(() => []),
            checkGoogleSafeBrowsing(resolvedUrl, 8000).catch(() => ({ flagged: false, threatType: null })),
            checkVirusTotal(resolvedUrl, 12000).catch(() => ({ positives: null, total: null })),
        ]);

        const html        = fetched ? (fetched.text || '') : '';
        const finalUrl    = fetched ? (fetched.finalUrl || resolvedUrl) : resolvedUrl;
        const statusCode  = fetched ? fetched.status : null;
        // A site is "reachable" if we got ANY HTTP response at all — including
        // 403 Forbidden, 429 Too Many Requests, 503 (Cloudflare bot challenges),
        // and other non-2xx codes. Those mean the server IS online and responded.
        // Only a network error, DNS failure, or timeout truly means unreachable.
        const reachable   = fetched
            ? (fetched.status != null && fetched.status > 0)
            : isWellKnown;

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
        const contentFlags  = deepContentAnalysis(html, resolvedHostname, finalUrl);

        // ── Free site builder analysis (v7) ───────────────────────────────
        let freeSiteBuilder        = !!builderInfo;
        let freeSiteBuilderName    = builderInfo ? builderInfo.name : null;
        let freeSiteBuilderDetail  = null;
        let cryptoFinancialContent = false;
        let cryptoBrands           = [];

        if (builderInfo && html) {
            const meta   = parseMeta(html, resolvedUrl);
            cryptoBrands = detectCryptoFinancialContent(html, meta.title);
            if (cryptoBrands.length > 0) {
                cryptoFinancialContent = true;
                freeSiteBuilderDetail = `This site is hosted on ${builderInfo.name} and references "${cryptoBrands.slice(0,3).join('", "')}" — legitimate financial/crypto services NEVER use free website builders. This is almost certainly a phishing site.`;
                // Inject a high-severity content flag for this
                contentFlags.unshift({
                    type: 'crypto-brand-on-free-host',
                    severity: 'high',
                    detail: freeSiteBuilderDetail,
                });
            } else {
                freeSiteBuilderDetail = `Site is hosted on ${builderInfo.name} — a free website builder. Legitimate businesses and financial services do not use these platforms. Treat with caution.`;
                contentFlags.push({
                    type: 'free-site-builder',
                    severity: 'medium',
                    detail: freeSiteBuilderDetail,
                });
            }
        }

        // ── Build signals for scoring ──────────────────────────────────────
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
            freeSiteBuilder,
            cryptoFinancialContent,
        };

        const riskScore = calculateRiskScore(signals);
        const verdict   = determineVerdict(riskScore, signals);

        const allFlags = [...urlFlags, ...contentFlags, ...dnsFlags];
        const totalDuration = Date.now() - start;

        console.log(`  verdict=${verdict} score=${riskScore} gsb=${gsbResult.flagged} vt=${vtResult.positives} freeBuild=${freeSiteBuilder} crypto=${cryptoFinancialContent} blacklisted=${hostnameAnalysis.hardBlacklisted} brandSpoof=${hostnameAnalysis.brandSpoof} flags=${allFlags.length} total=${totalDuration}ms`);

        res.json({
            ok: true,
            reachable, statusCode, httpsOk: resolvedHttpsOk,
            certValid, certExpiresDays, selfSignedCert, certExpiresSoon,
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
            resolvedUrl:   shortened ? resolvedUrl    : undefined,
            redirectChain: shortened && redirectChain.length > 1 ? redirectChain : undefined,
            // v7 new fields
            googleSafeBrowsing:  gsbResult.flagged,
            safeBrowsingThreat:  gsbResult.threatType,
            virusTotalPositives: vtResult.positives,
            virusTotalTotal:     vtResult.total,
            freeSiteBuilder,
            freeSiteBuilderName,
            freeSiteBuilderDetail,
            cryptoFinancialContent,
            cryptoBrands,
            totalDuration,
        });

    } catch (err) {
        console.warn(`/api/check ERROR ${url}:`, err && err.message ? err.message : err);
        res.status(500).json({ ok: false, error: String(err.message || err) });
    }
});


// ── CHAT PROXY (keeps Anthropic API key server-side) ─────────────────────────

app.post('/api/chat', async (req, res) => {
    const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
    if (!ANTHROPIC_KEY) {
        return res.status(503).json({ ok: false, error: 'Chat assistant is not configured on this server.' });
    }
    const { messages, system } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ ok: false, error: 'messages array is required.' });
    }
    try {
        const ctrl = new AbortController();
        const tid  = setTimeout(() => ctrl.abort(), 20000);
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            signal: ctrl.signal,
            headers: {
                'Content-Type':      'application/json',
                'x-api-key':         ANTHROPIC_KEY,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model:      'claude-sonnet-4-20250514',
                max_tokens: 1000,
                system:     system || '',
                messages,
            }),
        });
        clearTimeout(tid);
        const data = await response.json();
        res.json(data);
    } catch (err) {
        console.warn('/api/chat error:', err.message);
        res.status(500).json({ ok: false, error: 'Chat request failed.' });
    }
});

// ════════════════════════════════════════════════════════════════════════════
// SECTION 8 — START
// ════════════════════════════════════════════════════════════════════════════

// ── STARTUP ───────────────────────────────────────────────────────────────────

// Security response headers — must be registered before app.listen
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

app.listen(PORT, () => {
    const url = `http://localhost:${PORT}/main.html`;
    console.log(`\nWebSafe — http://localhost:${PORT}`);
    console.log(`  GSB key: ${GOOGLE_SAFE_BROWSING_KEY ? '✓ configured' : '✗ not set (export GSB_KEY)'}`);
    console.log(`  VT key:  ${VIRUSTOTAL_KEY           ? '✓ configured' : '✗ not set (export VT_KEY)'}\n`);
    const { exec } = require('child_process');
    const cmd =
        process.platform === 'win32'  ? `start "" "${url}"` :
        process.platform === 'darwin' ? `open "${url}"` :
                                        `xdg-open "${url}"`;
    exec(cmd, err => { if (err) console.log(`Visit: ${url}`); });
});
