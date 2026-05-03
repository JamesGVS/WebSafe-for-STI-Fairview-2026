// check_link.js — WebSafe client-side scan module

// ─── HTML escape helper — ALWAYS use this before putting any server/API-derived
//     string into innerHTML. Prevents XSS from malicious page titles, brand
//     names, details, or any other untrusted text that flows from scanned sites.
function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#39;');
}

// ─── Strict URL validation ────────────────────────────────────────────────────
/**
 * Returns a normalized URL string, or null if the input is not a real URL.
 * Gibberish like "snawkd nskan", "asdfjkl.qwer", single words, etc. → null.
 */
function normalizeURL(raw) {
    if (!raw) return null;
    raw = String(raw).trim();
    if (!raw || raw.length < 4) return null;

    // Reject input containing spaces unless it could be a URL with spaces (unlikely)
    if (/\s/.test(raw)) return null;

    let withProto = raw;
    if (!/^[a-z][a-z0-9+\-.]*:\/\//i.test(raw)) {
        withProto = 'https://' + raw;
    }

    let parsed;
    try { parsed = new URL(withProto); } catch (e) { return null; }

    const host = parsed.hostname;
    if (!host || host.length < 4) return null;
    if (!host.includes('.')) return null;

    const parts = host.split('.');
    const tld = parts[parts.length - 1];

    // TLD must be 2+ letters only (basic format check)
    if (!/^[a-zA-Z]{2,}$/.test(tld)) return null;

    // TLD must exist in the official IANA list (tld_list.js).
    // Falls back to accepting any 2–24 letter TLD if the list isn't loaded yet.
    if (typeof VALID_TLDS !== 'undefined' && !VALID_TLDS.has(tld.toLowerCase())) return null;

    // Each hostname label must be valid
    for (const part of parts) {
        if (part.length === 0) return null;
        if (!/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/.test(part)) return null;
    }

    // Gibberish heuristic: only check purely alphabetic labels >= 5 chars with no vowels
    // Skip labels containing numbers — alphanumeric domains like 1137x are legitimate
    const vowels = /[aeiou]/i;
    for (const part of parts) {
        const isAlphaOnly = /^[a-zA-Z]+$/.test(part);
        if (isAlphaOnly && part.length >= 5 && !vowels.test(part)) return null;
    }

    // Second gibberish check: consonant ratio > 88% on long purely-alphabetic labels only
    for (const part of parts) {
        const isAlphaOnly = /^[a-zA-Z]+$/.test(part);
        if (isAlphaOnly && part.length >= 6) {
            const consonants = (part.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
            if (consonants / part.length > 0.88) return null;
        }
    }

    return parsed.href;
}

/**
 * Renders the same-style "Invalid URL" error card in the status element.
 */
function showInvalidUrlError(statusEl) {
    if (!statusEl) return;
    statusEl.innerHTML = `
        <div style="max-width:580px;margin:16px auto 0;border-radius:14px;background:#121929;border:2px solid rgba(220,38,38,0.6);box-shadow:0 4px 24px rgba(220,38,38,.18);overflow:hidden;font-family:inherit;text-align:left;">
            <div style="display:flex;align-items:center;gap:14px;padding:15px 20px;background:linear-gradient(135deg,#dc2626,#991b1b);border-bottom:3px solid rgba(220,38,38,0.8);">
                <span style="width:32px;height:32px;border-radius:50%;background:rgba(255,255,255,0.15);display:inline-flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;font-weight:900;color:#fff;border:1px solid rgba(255,255,255,0.3);">✕</span>
                <div style="flex:1">
                    <div style="font-size:18px;font-weight:700;color:#fff">Invalid URL</div>
                    <div style="font-size:12px;color:#fecaca;margin-top:4px">The input you entered is not a recognisable web address</div>
                </div>
            </div>
            <div style="padding:14px 20px;background:#121929;">
                <div style="display:flex;flex-direction:column;gap:8px;">
                    <div style="display:flex;align-items:flex-start;gap:10px;border-radius:8px;padding:8px 12px;background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.25);">
                        <span style="width:9px;height:9px;border-radius:50%;background:#f87171;display:inline-block;margin-top:4px;flex-shrink:0"></span>
                        <div>
                            <span style="font-weight:700;color:#f87171;font-size:13px">Invalid URL</span>
                            <span style="color:#64748b;font-size:12px;margin-left:6px">— Enter a valid web address, e.g. <code style="background:rgba(220,38,38,0.15);color:#fca5a5;padding:1px 6px;border-radius:4px;font-size:11px;font-family:'IBM Plex Mono',monospace">https://example.com</code></span>
                        </div>
                    </div>
                    <p style="font-size:12px;color:#64748b;padding:2px 4px;">A valid URL must have a real domain and extension (like .com, .net, .ph). Random text, made-up words, or incomplete addresses won't be accepted.</p>
                </div>
            </div>
        </div>`;
}

// ─── Shared helpers ───────────────────────────────────────────────────────────
function showSpinner() {
    const s = document.getElementById('loading_spinner');
    if (s) s.style.display = 'block';
}
function hideSpinner() {
    const s = document.getElementById('loading_spinner');
    if (s) s.style.display = 'none';
}

// ─── Scan History (persisted to localStorage, max 20 entries) ────────────────
const HISTORY_KEY = 'ws_scan_history';
const HISTORY_MAX = 20;

function _loadHistory() {
    try {
        const raw = localStorage.getItem(HISTORY_KEY);
        return raw ? JSON.parse(raw) : [];
    } catch(e) { return []; }
}
function _saveHistory(arr) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(arr)); } catch(e) {}
}

// Expose scanHistory as a live reference so syncSidebarHistory() in main.html
// continues to work unchanged — it reads window.scanHistory directly.
window.scanHistory = _loadHistory();

function addToHistory(url, level) {
    const hostname = (() => { try { return new URL(url).hostname; } catch(e) { return url; } })();
    const entry = { hostname, url, level, time: new Date().toLocaleTimeString() };
    // Remove any existing entry for the same URL, then prepend
    window.scanHistory = window.scanHistory.filter(h => h.url !== url);
    window.scanHistory.unshift(entry);
    if (window.scanHistory.length > HISTORY_MAX) window.scanHistory.length = HISTORY_MAX;
    _saveHistory(window.scanHistory);
    renderHistory();
}

// Renders to BOTH the main-page list and the sidebar list so they stay in sync.
function renderHistory() {
    const colors = { safe:'#22c55e', hazard:'#fbbf24', danger:'#f87171' };
    const labels = { safe:'Safe', hazard:'Warning', danger:'Danger' };

    function buildRow(h) {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 12px;background:#0f1525;border:1px solid rgba(59,130,246,0.18);border-radius:8px;cursor:pointer;transition:background 0.15s,border-color 0.15s;';
        row.onmouseenter = () => { row.style.background='rgba(59,130,246,0.07)'; row.style.borderColor='rgba(59,130,246,0.35)'; };
        row.onmouseleave = () => { row.style.background='#0f1525'; row.style.borderColor='rgba(59,130,246,0.18)'; };
        row.innerHTML = `
            <span style="width:10px;height:10px;border-radius:50%;background:${colors[h.level]||'#64748b'};flex-shrink:0;display:inline-block;box-shadow:0 0 6px ${colors[h.level]||'#64748b'}88"></span>
            <span style="flex:1;font-size:13px;color:#e2e8f0;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span>
            <span style="font-size:11px;font-weight:700;color:${colors[h.level]||'#64748b'}">${labels[h.level]||'?'}</span>
            <span style="font-size:11px;color:#64748b">${h.time}</span>
        `;
        row.querySelectorAll('span')[1].textContent = h.hostname;
        row.addEventListener('click', () => {
            const inp = document.getElementById('link_input');
            if (inp) inp.value = h.url;
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
        return row;
    }

    const empty = '<p style="color:#64748b;font-size:13px;text-align:center;padding:8px">No scans yet</p>';
    const targets = [
        { id: 'ws_history_list',      maxItems: 20 },
        { id: 'sidebar_history_list', maxItems: 5  },
    ];
    targets.forEach(({ id, maxItems }) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (window.scanHistory.length === 0) { el.innerHTML = empty; return; }
        el.innerHTML = '';
        window.scanHistory.slice(0, maxItems).forEach(h => el.appendChild(buildRow(h)));
    });
}

// Initialise history display on page load
renderHistory();

// ─── Animated loading steps ───────────────────────────────────────────────────
const LOADING_STEPS = [
    'Validating URL format...',
    'Looking up the website...',
    'Checking connection security...',
    'Checking domain age...',
    'Scanning threat databases...',
    'Checking Google Safe Browsing...',
    'Scanning page for phishing signals...',
    'Generating your safety report...',
];
let _loadingInterval = null;
function startLoadingSteps() {
    const el = document.getElementById('link_status');
    if (!el) return;
    let i = 0;
    el.innerHTML = `<p style="color:#60a5fa;margin-top:8px;font-weight:600;font-size:14px;font-family:'IBM Plex Mono',monospace;letter-spacing:0.03em">🔍 ${LOADING_STEPS[0]}</p>`;
    _loadingInterval = setInterval(() => {
        i = (i + 1) % LOADING_STEPS.length;
        if (el) el.innerHTML = `<p style="color:#60a5fa;margin-top:8px;font-weight:600;font-size:14px;font-family:'IBM Plex Mono',monospace;letter-spacing:0.03em">🔍 ${LOADING_STEPS[i]}</p>`;
    }, 1800);
}
function stopLoadingSteps() {
    if (_loadingInterval) { clearInterval(_loadingInterval); _loadingInterval = null; }
}

// ─── Safety Score Calculator (client-side fallback) ───────────────────────────
const CHECK_WEIGHTS = {
    'HTTPS':                25,
    'SSL Certificate':      20,
    'Threat Database':      20,
    'Google Safe Browsing': 20,
    'Domain Age':           15,
    'Reachable':            10,
    'Connection Safety':     5,
    'Page Content':          5,
    'Shortened Link':        0,
};
const DEFAULT_WEIGHT = 5;
function calcSafetyScore(checks, level) {
    let earned = 0, possible = 0;
    checks.forEach(ch => {
        const w = CHECK_WEIGHTS[ch.label] ?? DEFAULT_WEIGHT;
        if (w === 0) return;
        possible += w;
        if (ch.ok === true)  earned += w;
        else if (ch.ok === null) earned += w * 0.5;
    });
    if (possible === 0) return 50;
    const raw = Math.round((earned / possible) * 100);
    if (level === 'danger') return Math.min(raw, 29);
    if (level === 'hazard') return Math.min(Math.max(raw, 30), 64);
    return Math.max(raw, 65);
}

// ─── Flag label map ───────────────────────────────────────────────────────────
function flagTypeLabel(type) {
    const map = {
        'brand-impersonation':       'Fake Brand',
        'keywords-high':             'Dangerous Wording',
        'keywords-medium':           'Suspicious Wording',
        'multiple-password-fields':  'Password Stealing Attempt',
        'form-external-post':        'Data Theft Risk',
        'hidden-iframe':             'Hidden Trap',
        'meta-redirect':             'Sneaky Redirect',
        'obfuscation':               'Hidden Code',
        'base64-payload':            'Hidden Code',
        'base64-large':              'Hidden Code',
        'fake-trust-badges':         'Fake Trust Badges',
        'ip-address':                'No Real Domain Name',
        'at-sign-url':               'Misleading Web Address',
        'dash-heavy-domain':         'Suspicious Site Name',
        'suspicious-tld':            'Risky Website Ending',
        'excessive-subdomains':      'Complex Address — Could Be a Trick',
        'brand-in-subdomain':        'Fake Brand in Address',
        'long-url':                  'Unusually Long Address',
        'encoded-hostname':          'Hidden Characters in Address',
        'dynamic-dns':               'Untrusted Dynamic Address',
        'suspicious-hosting':        'Suspicious Hosting',
        'free-site-builder':         'Free Hosting — Scammer Favourite',
        'crypto-brand-on-free-host': 'Crypto Scam Risk',
        'wix-phishing':              'Possible Scam Page on Free Host',
        'google-safebrowsing':       'Google Safety Alert',
        'virustotal-flag':           'Flagged by Antivirus Tools',
        'urlscan-malicious':         'Sandbox: Malicious Page Detected',
        'checkphish-flag':           'Brand Impersonation Detected',
        'disposable-hosting':        'Temporary Free Hosting',
        'dangerous-protocol':        'Dangerous Link Type',
        'high-entropy-domain':       'Random-Looking Site Name',
        'homograph-attack':          'Lookalike Web Address',
        'numeric-substitution':      'Letter-Number Trick',
    };
    return map[type] || 'Suspicious Signal';
}

// ─── Friendly flag details ────────────────────────────────────────────────────
function friendlyFlagDetail(f) {
    switch(f.type) {
        case 'brand-impersonation':
            return f.detail || 'This page is pretending to be a well-known brand to trick you into trusting it';
        case 'keywords-high':
            { const kws = Array.isArray(f.detail) ? f.detail : [f.detail];
              return `Contains high-risk phrases (${kws.map(k=>`"${k}"`).join(', ')}) — strongly associated with phishing`; }
        case 'keywords-medium':
            { const kws = Array.isArray(f.detail) ? f.detail : [f.detail];
              return `Contains suspicious phrases (${kws.map(k=>`"${k}"`).join(', ')}) — verify the URL is correct`; }
        case 'multiple-password-fields':
            return f.detail || 'This page has multiple password boxes — it may be trying to steal your login details';
        case 'form-external-post':
            return f.detail || 'This page sends what you type to a completely different website — a common trick used by scammers';
        case 'hidden-iframe':
            return f.detail || 'A hidden panel was found on this page — it may be used to track you or trick your clicks';
        case 'meta-redirect':
            return f.detail || 'This page automatically sends you to a different website without warning — a common scam tactic';
        case 'obfuscation':
            return f.detail || 'The code on this page is deliberately scrambled — often done to hide malicious activity';
        case 'base64-payload': case 'base64-large':
            return f.detail || 'Suspicious hidden data was found on this page — it may be concealing something harmful';
        case 'fake-trust-badges':
            return f.detail || 'Multiple fake "security verified" claims — a common scam site tactic';
        case 'ip-address':
            return f.detail || 'This link uses a raw number address instead of a real website name — almost always a red flag';
        case 'at-sign-url':
            return f.detail || 'This link contains an @ symbol which can be used to hide where it actually takes you';
        case 'dash-heavy-domain':
            return f.detail || 'This website name has lots of hyphens — a common trick scammers use to imitate real sites';
        case 'suspicious-tld':
            return f.detail || 'This website uses a web ending (.extension) that is frequently used by scammers';
        case 'excessive-subdomains':
            return f.detail || 'This web address has an unusually complex structure that can make fake sites look real';
        case 'brand-in-subdomain':
            return f.detail || 'A well-known brand name appears early in this address to make it look legitimate — but the real site is different';
        case 'long-url':
            return f.detail || 'This web address is unusually long — long links are often used to hide where they really take you';
        case 'encoded-hostname':
            return f.detail || 'This web address contains hidden characters — a trick used to disguise scam links';
        case 'dynamic-dns':
            return f.detail || 'This site uses a free dynamic address service that is commonly abused by scammers';
        case 'suspicious-hosting':
            return f.detail || 'This site is hosted in a location known for ignoring abuse reports — a red flag';
        case 'free-site-builder':
            return f.detail || 'This site is built on a free website platform — scammers commonly use these to create fake pages quickly';
        case 'crypto-brand-on-free-host':
            return f.detail || 'A crypto or financial brand appears on a free hosting site — this is an extremely common setup for scams';
        case 'wix-phishing':
            return f.detail || 'This appears to be a scam page on Wix pretending to be a crypto or financial service. Real financial companies never use free website builders.';
        case 'google-safebrowsing':
            return f.detail || 'Google has marked this link as dangerous';
        case 'virustotal-flag':
            return f.detail || 'Multiple antivirus tools have flagged this link as malicious';
        case 'disposable-hosting':
            return f.detail || 'This site is hosted on a free, temporary platform commonly used for short-lived scam pages';
        case 'high-entropy-domain':
            return f.detail || 'This website name looks randomly generated by a computer — a common sign of scam infrastructure';
        case 'homograph-attack':
            return f.detail || 'Hostname uses lookalike characters from non-Latin scripts to impersonate a real website';
        case 'numeric-substitution':
            return f.detail || 'Numbers replace letters in the domain to impersonate a real brand (e.g. g00gle, p4ypal)';
        case 'urlscan-malicious':
            return f.detail || 'urlscan.io opened this page in an isolated sandbox and confirmed it is malicious';
        case 'checkphish-flag':
            return f.detail || 'CheckPhish AI detected brand impersonation or phishing content on this page';
        default:
            return f.detail || 'Suspicious signal detected';
    }
}

// ─── Check Link module ────────────────────────────────────────────────────────
(function () {
    const input    = document.getElementById('link_input');
    const btn      = document.getElementById('check_btn');
    const statusEl = document.getElementById('link_status');
    const safetyEl = document.getElementById('safety_status');

    let _lastValue = '';
    function clearResults() {
        if (statusEl) statusEl.innerHTML = '';
        if (safetyEl) { safetyEl.textContent = ''; safetyEl.className = ''; }
        const pa = document.getElementById('preview_area');
        if (pa) pa.style.display = 'none';
        ['preview_actions','preview_checks'].forEach(id => {
            const el = document.getElementById(id); if (el) el.innerHTML = '';
        });
        ['preview_title','preview_domain'].forEach(id => {
            const el = document.getElementById(id); if (el) el.textContent = '';
        });
    }
    let _debounceTimer = null;
    if (input) {
        input.addEventListener('input', () => {
            const cur = input.value.trim();
            if (cur !== _lastValue) {
                _lastValue = cur;
                clearTimeout(_debounceTimer);
                _debounceTimer = setTimeout(clearResults, 120);
            }
        });
    }

    function logSafetyReport(url, level, reason, checks) {
        const icons  = { safe:'✅', hazard:'⚠️', danger:'🚨' };
        const styles = { safe:'color:#16a34a;font-weight:bold;font-size:13px', hazard:'color:#d97706;font-weight:bold;font-size:13px', danger:'color:#dc2626;font-weight:bold;font-size:13px' };
        console.group(`%c${icons[level]||'?'} WebSafe [${level.toUpperCase()}] — ${url}`, styles[level]||'');
        console.log(`%cVerdict:%c ${reason}`, 'font-weight:bold', 'font-weight:normal');
        checks.forEach(ch => {
            const ico = ch.ok===true?'✅':ch.ok===false?'❌':'ℹ️';
            const det = ch.detail?` — ${ch.detail}`:'';
            if(ch.ok===false) console.warn(`${ico} ${ch.label}${det}`);
            else if(ch.ok===null) console.info(`${ico} ${ch.label}${det}`);
            else console.log(`${ico} ${ch.label}${det}`);
        });
        console.groupEnd();
    }

    function renderResultCard(data) {
        if (!statusEl) return;
        statusEl.innerHTML = '';
        let { level, reason, checks, fourBadges, score } = data;

        const theme = {
            safe:   {
                accent:'#22c55e', glow:'rgba(34,197,94,0.3)',
                icon:'<span style="width:32px;height:32px;border-radius:50%;background:#22c55e;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 0 14px rgba(34,197,94,0.6);"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg></span>',
                label:'Link Looks Safe',
                headerBg:'linear-gradient(135deg,#0d2318,#0a1f14)'
            },
            hazard: {
                accent:'#fbbf24', glow:'rgba(251,191,36,0.3)',
                icon:'<span style="width:32px;height:32px;border-radius:50%;background:#fbbf24;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 0 14px rgba(251,191,36,0.6);"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span>',
                label:'Potential Warning',
                headerBg:'linear-gradient(135deg,#1c1505,#1a1204)'
            },
            danger: {
                accent:'#f87171', glow:'rgba(248,113,113,0.3)',
                icon:'<span style="width:32px;height:32px;border-radius:50%;background:#f87171;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 0 14px rgba(248,113,113,0.6);"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></span>',
                label:'Dangerous Link',
                headerBg:'linear-gradient(135deg,#1a0505,#180404)'
            },
        };
        if (!level) level = checks.some(ch=>ch.ok===false)?'hazard':'safe';
        const t = theme[level]||theme.safe;

        const card = document.createElement('div');
        card.style.cssText = `max-width:580px;margin:16px auto 0;border-radius:14px;background:#121929;border:2px solid ${t.accent}55;box-shadow:0 4px 24px ${t.glow},0 0 0 1px ${t.accent}33;overflow:hidden;font-family:inherit;text-align:left;`;

        const header = document.createElement('div');
        header.style.cssText = `display:flex;align-items:center;gap:14px;padding:16px 20px;background:${t.headerBg};border-bottom:2px solid ${t.accent}55;`;
        const resolvedBanner = data.shortened && data.resolvedUrl
            ? `<div style="margin-top:6px;padding:5px 10px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:6px;font-size:11px;color:#93c5fd;font-family:'IBM Plex Mono',monospace;">🔗 Shortened → <span style="color:#e2e8f0;font-weight:700;word-break:break-all">${esc(data.resolvedUrl)}</span></div>`
            : '';
        const scoreColor = level==='safe'?'#22c55e':level==='hazard'?'#fbbf24':'#f87171';
        const scoreCircle = `<div style="flex-shrink:0;width:54px;height:54px;border-radius:50%;border:2px solid ${scoreColor};display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(255,255,255,0.04);box-shadow:0 0 12px ${scoreColor}44;"><span style="font-size:17px;font-weight:900;color:${scoreColor};line-height:1;font-family:'IBM Plex Mono',monospace">${esc(score)}</span><span style="font-size:8px;color:#64748b;letter-spacing:.8px;text-transform:uppercase">SCORE</span></div>`;
        header.innerHTML = `${t.icon}<div style="flex:1;min-width:0"><div style="font-size:18px;font-weight:700;color:#f1f5f9">${t.label}${data.shortened?' <span style="font-size:11px;background:rgba(255,255,255,0.1);color:#94a3b8;padding:2px 8px;border-radius:10px;vertical-align:middle;border:1px solid rgba(255,255,255,0.15)">Shortened</span>':''}</div><div style="font-size:12px;color:#94a3b8;margin-top:4px">${esc(reason)||''}</div>${resolvedBanner}</div>${scoreCircle}`;
        card.appendChild(header);

        const passed  = checks.filter(c=>c.ok===true).length;
        const failed  = checks.filter(c=>c.ok===false).length;
        const unknown = checks.filter(c=>c.ok===null).length;
        const summary = document.createElement('div');
        summary.style.cssText = 'display:flex;gap:16px;padding:10px 20px;background:rgba(255,255,255,0.02);border-bottom:1px solid rgba(59,130,246,0.15);font-size:12px;font-weight:700;';
        summary.innerHTML = `<span style="color:#22c55e">✓ ${passed} Passed</span><span style="color:#f87171">✕ ${failed} Failed</span><span style="color:#64748b">? ${unknown} Unknown</span><span style="margin-left:auto;color:#60a5fa">${checks.length} checks total</span>`;
        card.appendChild(summary);

        if (Array.isArray(fourBadges) && fourBadges.length) {
            const badgeRow = document.createElement('div');
            badgeRow.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 20px;background:rgba(255,255,255,0.01);border-bottom:1px solid rgba(59,130,246,0.12);';
            const lbl = document.createElement('span');
            lbl.style.cssText = 'font-size:10px;font-weight:800;color:#64748b;text-transform:uppercase;letter-spacing:.8px;margin-right:4px;';
            lbl.textContent = 'Key Checks:';
            badgeRow.appendChild(lbl);
            fourBadges.forEach(b => {
                const bOk=b.ok===true, bNull=b.ok===null;
                const bgCol  = bOk ? 'rgba(34,197,94,0.12)'  : bNull ? 'rgba(255,255,255,0.04)' : 'rgba(248,113,113,0.12)';
                const fgCol  = bOk ? '#4ade80' : bNull ? '#64748b' : '#fca5a5';
                const border = bOk ? 'rgba(34,197,94,0.4)'   : bNull ? 'rgba(255,255,255,0.1)'  : 'rgba(248,113,113,0.4)';
                const ico    = bOk ? '✓' : bNull ? '?' : '✕';
                const badge  = document.createElement('div');
                badge.style.cssText = `display:inline-flex;align-items:center;gap:5px;background:${bgCol};color:${fgCol};border:1px solid ${border};border-radius:6px;padding:4px 11px;font-size:12px;font-weight:700;cursor:default;`;
                badge.innerHTML = `<span style="font-weight:900;font-size:11px">${ico}</span><span>${esc(b.label)}</span>`;
                badge.title = b.detail||'';
                badgeRow.appendChild(badge);
            });
            card.appendChild(badgeRow);
        }

        if (Array.isArray(checks) && checks.length) {
            const list = document.createElement('div');
            list.style.cssText = 'padding:12px 20px 16px;display:flex;flex-direction:column;gap:5px;background:transparent;';
            checks.forEach(ch => {
                const row = document.createElement('div');
                row.style.cssText = 'display:flex;align-items:flex-start;gap:10px;border-radius:8px;padding:8px 12px;background:rgba(255,255,255,0.02);border:1px solid rgba(59,130,246,0.1);transition:background 0.2s;';
                row.onmouseenter = () => row.style.background='rgba(59,130,246,0.06)';
                row.onmouseleave = () => row.style.background='rgba(255,255,255,0.02)';
                const dotCol = ch.ok===true ? '#22c55e' : ch.ok===false ? '#f87171' : '#64748b';
                const lblCol = ch.ok===true ? '#4ade80' : ch.ok===false ? '#fca5a5' : '#94a3b8';
                row.innerHTML = `<span style="width:8px;height:8px;border-radius:50%;background:${dotCol};display:inline-block;margin-top:5px;flex-shrink:0;box-shadow:0 0 5px ${dotCol}88"></span><div><span style="font-weight:600;color:${lblCol};font-size:13px">${esc(ch.label)}</span>${ch.detail?`<span style="color:#64748b;font-size:12px;margin-left:6px">— ${esc(ch.detail)}</span>`:''}</div>`;
                list.appendChild(row);
            });
            card.appendChild(list);
        }

        statusEl.appendChild(card);

        // ── Report button for dangerous links ────────────────────────────────
        if (level === 'danger') {
            const reportBtn = document.createElement('div');
            reportBtn.style.cssText = 'max-width:580px;margin:10px auto 0;';
            reportBtn.innerHTML = `
                <a href="#authorities-anchor"
                   id="ws_report_danger_btn"
                   style="display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:13px 20px;background:linear-gradient(135deg,rgba(220,38,38,0.2),rgba(153,27,27,0.2));color:#fca5a5;border-radius:12px;text-decoration:none;font-size:14px;font-weight:700;letter-spacing:0.3px;box-shadow:0 4px 16px rgba(220,38,38,0.25);border:1px solid rgba(220,38,38,0.45);transition:transform 0.15s ease,box-shadow 0.15s ease,background 0.15s ease;box-sizing:border-box;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Report to Authorities
                </a>`;
            const anchor = reportBtn.querySelector('a');
            anchor.addEventListener('mouseenter', () => {
                anchor.style.transform = 'translateY(-2px)';
                anchor.style.boxShadow = '0 8px 24px rgba(220,38,38,0.35)';
                anchor.style.background = 'linear-gradient(135deg,rgba(220,38,38,0.3),rgba(153,27,27,0.3))';
            });
            anchor.addEventListener('mouseleave', () => {
                anchor.style.transform = '';
                anchor.style.boxShadow = '0 4px 16px rgba(220,38,38,0.25)';
                anchor.style.background = 'linear-gradient(135deg,rgba(220,38,38,0.2),rgba(153,27,27,0.2))';
            });
            anchor.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector('#authorities-anchor');
                if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
            statusEl.appendChild(reportBtn);
        }
    }

    async function checkLink() {
        if (!input || !btn) return;
        const raw = input.value || '';
        _lastValue = raw.trim();
        clearResults();

        // ── Empty check ───────────────────────────────────────────────────────
        if (!raw.trim()) {
            if (statusEl) statusEl.innerHTML = `<p style="color:#dc2626;margin-top:8px;font-weight:600">⚠️ Please enter a URL to scan.</p>`;
            return;
        }

        // ── STRICT URL validation — shows Invalid URL card for gibberish ──────
        const normalized = normalizeURL(raw);
        if (!normalized) {
            showInvalidUrlError(statusEl);
            if (input) {
                input.style.border = '2px solid #dc2626';
                input.style.boxShadow = '0 0 0 3px rgba(220,38,38,0.15)';
                setTimeout(() => { input.style.border = ''; input.style.boxShadow = ''; }, 2500);
            }
            return;
        }

        btn.disabled = true;
        showSpinner();
        startLoadingSteps();

        let level  = null;
        let reason = 'Could not complete all checks';
        let checks = [];
        let serverData = null;

        try {
            const apiUrl = '/api/check?url=' + encodeURIComponent(normalized);
            console.log('[WebSafe] Calling:', apiUrl);
            const res = await fetch(apiUrl);
            if (res.ok) { const j = await res.json(); if (j && j.ok) serverData = j; }
            else console.warn('[WebSafe] API non-OK:', res.status);
        } catch(e) { console.warn('[WebSafe] API failed:', e.message); }

        if (serverData) {
            const d = serverData;

            // ── Dead / Expired link detection ─────────────────────────────
            if (d.deadLink) {
                const deadIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;
                checks.unshift({ label: 'Dead / Expired Link', ok: false,
                    detail: d.deadLabel || 'This URL is unreachable — the page may have been taken down or the domain has expired',
                    icon: deadIcon });
            }

            // Shortened link
            if (d.shortened && d.resolvedUrl)
                checks.push({label:'Shortened Link', ok:null, detail:`This is a shortened link — it actually leads to: ${d.resolvedUrl}`});

            // HTTPS
            checks.push({label:'Secure Connection', ok:!!d.httpsOk,
                detail: d.httpsOk
                    ? 'Your connection to this site is private and secure'
                    : 'This site is not secure — don\'t enter passwords or personal info here'});

            // Reachable — any HTTP response means the site exists.
            // 403/429/503 = Cloudflare/bot protection = site IS live, just blocking scrapers.
            const sc = d.statusCode;
            let reachDetail;
            if (d.reachable) {
                if (!sc || sc === 200 || sc === 301 || sc === 302 || sc === 304) {
                    reachDetail = 'We can reach this website — it\'s live';
                } else if (sc === 403) {
                    reachDetail = 'The website is live — it\'s protected by a security filter that blocked our automated check';
                } else if (sc === 429) {
                    reachDetail = 'The website is live — it temporarily blocked our check due to too many requests';
                } else if (sc === 503 || sc === 502) {
                    reachDetail = `Website exists but is temporarily unavailable (HTTP ${sc})`;
                } else {
                    reachDetail = `Website is online and responded (HTTP ${sc})`;
                }
            } else {
                reachDetail = 'We couldn\'t reach this website — it may be offline or the address may be wrong';
            }
            checks.push({label:'Website Exists', ok:d.reachable !== false, detail: reachDetail});

            // SSL Certificate
            const certDetail = d.certValid
                ? (d.selfSignedCert
                    ? 'This site\'s security certificate wasn\'t issued by a trusted source — treat with caution'
                    : d.certExpiresSoon
                        ? `This site\'s security certificate expires very soon (${d.certExpiresDays} days) — this is unusual`
                        : `This site has a valid security certificate (expires in ${d.certExpiresDays ?? '?'} days) — all good`)
                : 'This site is missing a valid security certificate — a major warning sign';
            checks.push({label:'Website Identity', ok: d.certValid && !d.selfSignedCert && !d.certExpiresSoon, detail: certDetail});

            // Threat database
            const isFlagged = d.blacklisted || d.brandSpoof || d.patternMatch;
            checks.push({label:'Known Threats', ok:!isFlagged,
                detail: d.blacklisted
                    ? 'This website is on our list of known dangerous sites — do not visit it'
                    : d.brandSpoof
                        ? `Domain is impersonating "${d.spoofedBrand}" — NOT the real website`
                        : d.patternMatch
                            ? 'This website address matches patterns commonly used by scammers'
                            : 'Not found on any known scam or malware list — good sign'});

            // Connection safety
            checks.push({label:'Stay-Safe Check', ok:!d.redirectsToHttp,
                detail: d.redirectsToHttp
                    ? 'This site starts secure but then switches to an unprotected connection — suspicious'
                    : 'The connection stays secure the whole time — good'});

            // Domain age
            if (d.domainAgeDays != null) {
                const ageOk = d.domainAgeDays >= 30;
                const years  = Math.floor(d.domainAgeDays / 365);
                const months = Math.floor((d.domainAgeDays % 365) / 30);
                const ageText = years > 0
                    ? `${years} year${years>1?'s':''}${months>0?` and ${months} month${months>1?'s':''}`:''}`
                    : `${months>0 ? months+' month'+(months>1?'s':'') : d.domainAgeDays+' days'}`;
                checks.push({label:'How Old Is This Site?', ok:ageOk,
                    detail: ageOk
                        ? `This website has been around for ${ageText} — that\'s a good sign`
                        : `This website was only created ${ageText} ago — brand-new sites are a common trick used by scammers`});
            } else {
                checks.push({label:'How Old Is This Site?', ok:null, detail:'We couldn\'t find out how old this website is'});
            }

            // Google Safe Browsing (v7)
            if (d.googleSafeBrowsing != null) {
                checks.push({label:'Google Safety Check', ok:!d.googleSafeBrowsing,
                    detail: d.googleSafeBrowsing
                        ? `Google has flagged this site as dangerous: ${d.safeBrowsingThreat || 'malware or phishing'}`
                        : 'Google has checked this site and found no threats'});
            }

            // VirusTotal
            if (d.virusTotalPositives != null) {
                const vtOk = d.virusTotalPositives === 0;
                checks.push({label:'Antivirus Scan (VirusTotal)', ok:vtOk,
                    detail: vtOk
                        ? 'None of the antivirus engines flagged this link — looks clean'
                        : `${d.virusTotalPositives} of ${d.virusTotalTotal} antivirus engines flagged this link as dangerous`});
            }

            // urlscan.io
            if (d.urlScanMalicious != null) {
                const urlscanOk = !d.urlScanMalicious;
                const reportLink = d.urlScanReport ? ` (<a href="${d.urlScanReport}" target="_blank" rel="noopener noreferrer" style="color:#60a5fa">full report</a>)` : '';
                checks.push({label:'Visual Sandbox (urlscan.io)', ok:urlscanOk,
                    detail: urlscanOk
                        ? 'urlscan.io loaded the page in an isolated sandbox and found no threats'
                        : `urlscan.io flagged this page as malicious${d.urlScanVerdict ? ` (${d.urlScanVerdict})` : ''}${reportLink}`});
            }

            // CheckPhish
            if (d.checkPhishDisposition != null) {
                const cpOk = d.checkPhishDisposition === 'clean';
                const cpLabel = { clean:'clean', phish:'phishing site', suspect:'suspicious', unknown:'unknown' }[d.checkPhishDisposition] || d.checkPhishDisposition;
                checks.push({label:'Brand Impersonation Check (CheckPhish)', ok:cpOk,
                    detail: cpOk
                        ? 'CheckPhish found no brand impersonation or phishing patterns'
                        : d.checkPhishBrand
                            ? `CheckPhish identified this page as impersonating "${d.checkPhishBrand}" — ${cpLabel}`
                            : `CheckPhish flagged this page as ${cpLabel}`});
            }

            // Free site builder warning
            if (d.freeSiteBuilder) {
                checks.push({label:'Suspicious Hosting', ok:false,
                    detail: d.freeSiteBuilderDetail || 'This site is hosted on a free website builder — scammers often use these to create fake pages'});
            }

            // Content / URL / DNS flags
            if (Array.isArray(d.contentFlags) && d.contentFlags.length) {
                const highFlags   = d.contentFlags.filter(f => f.severity === 'high');
                const mediumFlags = d.contentFlags.filter(f => f.severity === 'medium');
                for (const f of d.contentFlags) {
                    // Skip flags already rendered above
                    if (['urlscan-malicious','checkphish-flag','free-site-builder','crypto-brand-on-free-host'].includes(f.type)) continue;
                    checks.push({ label: flagTypeLabel(f.type), ok: false, detail: friendlyFlagDetail(f) });
                }
                if (highFlags.length) { level = 'danger'; reason = friendlyFlagDetail(highFlags[0]); }
                else if (mediumFlags.length && level !== 'danger') { level = 'hazard'; reason = 'Page has suspicious characteristics — proceed with caution'; }
            } else {
                checks.push({label:'Page Content', ok:true, detail:'Nothing suspicious found on this page — looks normal'});
            }

            if (d.verdict) level = d.verdict;
            if (!level) level = 'safe';

            // Dead link overrides verdict messaging (but don't override 'danger' threat verdict)
            if (d.deadLink) {
                if (level !== 'danger') level = 'hazard';
                reason = `☠️ Dead or expired link — ${d.deadLabel || 'This URL is unreachable'}`;
            }

            // Final reason string
            if (level === 'danger') {
                if (!reason || reason === 'Could not complete all checks') {
                    if (d.googleSafeBrowsing)        reason = '🚨 Google has flagged this link as dangerous — do not visit';
                    else if (d.urlScanMalicious)     reason = '🚨 urlscan.io sandbox detected this page as malicious';
                    else if (d.checkPhishDisposition === 'phish') reason = d.checkPhishBrand
                        ? `🚨 CheckPhish confirmed this is a phishing site impersonating "${d.checkPhishBrand}"`
                        : '🚨 CheckPhish confirmed this is a phishing site';
                    else if (d.blacklisted)          reason = '🚨 This website is on our known-dangerous list — stay away';
                    else if (d.brandSpoof)           reason = `🚨 This site is impersonating "${d.spoofedBrand}" — phishing site`;
                    else if (d.freeSiteBuilder && d.cryptoFinancialContent) reason = '🚨 Scam page pretending to be a real brand, hosted on a free site';
                    else if (d.patternMatch)         reason = '🚨 This web address matches patterns used by known scammers';
                    else if (d.virusTotalPositives > 3) reason = `🚨 ${d.virusTotalPositives} antivirus engines flagged this link`;
                    else                             reason = '🚨 Multiple red flags detected — avoid this site';
                }
            } else if (level === 'hazard') {
                if (!reason || reason === 'Could not complete all checks') {
                    if (d.checkPhishDisposition === 'suspect') reason = '⚠️ CheckPhish flagged this page as suspicious — verify before proceeding';
                    else reason = '⚠️ A few warning signs found — double-check this site before doing anything';
                }
            } else {
                const apiCount = [d.googleSafeBrowsing != null, d.virusTotalPositives != null, d.urlScanMalicious != null, d.checkPhishDisposition != null].filter(Boolean).length;
                reason = apiCount >= 2
                    ? `✅ Checked against ${apiCount} threat intelligence APIs — this link looks safe`
                    : `✅ ${checks.filter(c=>c.ok===true).length} of ${checks.filter(c=>c.ok!==null).length} checks passed — this link looks safe to visit`;
            }

        } else {
            // ── Client-only fallback (no server) ────────────────────────────
            // Key insight: browsers block cross-origin fetches (CORS), so we get
            // network errors even for live sites. r.type === 'opaque' = site IS live
            // but blocked by CORS. Any HTTP response (even 403/429) = site exists.
            let reachable  = false;
            let reachStatus = null;
            let reachBlocked = false; // CORS / bot protection blocked us but site is live

            try {
                const ctrl = new AbortController();
                const tid  = setTimeout(() => ctrl.abort(), 6000);
                const r    = await fetch(normalized, { method: 'HEAD', signal: ctrl.signal, mode: 'no-cors' });
                clearTimeout(tid);
                // no-cors always gives type=opaque — that means server responded = site is live
                if (r.type === 'opaque' || r.ok) {
                    reachable     = true;
                    reachBlocked  = r.type === 'opaque';
                }
            } catch(e) {
                // Network error / DNS failure / timeout — might still be a CORS block
                // Try again with GET and catch opaque responses
                try {
                    const ctrl2 = new AbortController();
                    const tid2  = setTimeout(() => ctrl2.abort(), 6000);
                    const r2    = await fetch(normalized, { method: 'GET', signal: ctrl2.signal, mode: 'no-cors' });
                    clearTimeout(tid2);
                    if (r2.type === 'opaque' || r2.ok) { reachable = true; reachBlocked = r2.type === 'opaque'; }
                } catch(e2) { reachable = false; }
            }

            const WELL_KNOWN = [
                'youtube.com','google.com','facebook.com','twitter.com','x.com','instagram.com',
                'microsoft.com','apple.com','amazon.com','wikipedia.org','linkedin.com','reddit.com',
                'github.com','netflix.com','discord.com','tiktok.com','spotify.com','paypal.com',
                'chatgpt.com','openai.com','claude.ai','anthropic.com',
                'scholar.google.com','drive.google.com','docs.google.com','gmail.com',
                'office.com','outlook.com','bing.com','zoom.us','slack.com',
                'gcash.com','maya.ph','paymaya.com','bdo.com.ph','bpi.com.ph',
                'shopee.ph','lazada.com.ph','grab.com',
                // Well-known protected/bot-blocked sites
                '1337x.to','thepiratebay.org','rarbg.to','nyaa.si','cloudflare.com',
                'fandom.com','archive.org','twitch.tv','stackoverflow.com','imgur.com',
            ];
            let hostname = '';
            try { hostname = new URL(normalized).hostname.toLowerCase(); } catch(e) {}
            const isWellKnown = WELL_KNOWN.some(d => hostname === d || hostname.endsWith('.' + d));

            // DNS existence check via public DNS-over-HTTPS as a last resort
            let dnsExists = null;
            if (!reachable && !isWellKnown) {
                try {
                    const dnsRes = await fetch(
                        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
                        { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(4000) }
                    );
                    if (dnsRes.ok) {
                        const dnsJson = await dnsRes.json();
                        // Status 0 = NOERROR (domain exists), 3 = NXDOMAIN (does not exist)
                        dnsExists = dnsJson.Status === 0 && Array.isArray(dnsJson.Answer) && dnsJson.Answer.length > 0;
                    }
                } catch(e) { dnsExists = null; }
            }

            const confirmed = reachable || isWellKnown || dnsExists === true;
            const httpsOk   = normalized.startsWith('https://');

            let reachDetail;
            if (confirmed) {
                if (isWellKnown && !reachable)      reachDetail = 'This is a well-known website — confirmed as legitimate';
                else if (dnsExists && !reachable)   reachDetail = 'This web address exists — the site may be blocking our automated check';
                else if (reachBlocked)               reachDetail = 'The website is live — it\'s protected by a security filter that blocked our automated check';
                else                                 reachDetail = 'We can reach this website — it\'s live';
            } else {
                reachDetail = dnsExists === false
                    ? 'Domain does not exist (DNS lookup returned NXDOMAIN)'
                    : 'We couldn\'t reach this website — it may be offline or the address may be wrong';
            }

            checks.push({label:'Secure Connection', ok:httpsOk, detail:httpsOk?'Your connection to this site is private and secure':'This site is not secure — don\'t enter passwords or personal info here'});
            checks.push({label:'Website Exists', ok:confirmed, detail:reachDetail});
            checks.push({label:'Website Identity', ok:null, detail:'We couldn\'t check the security certificate without a server connection'});
            checks.push({label:'Known Threats', ok:null, detail:'Scam database check wasn\'t available — try again with a server connection'});
            checks.push({label:'How Old Is This Site?', ok:null, detail:'We couldn\'t check how old this site is without a server connection'});

            if (!confirmed && dnsExists === false) {
                level='danger'; reason='This web address doesn\'t exist — it may be mistyped or the site may have been removed';
            } else if (!confirmed) {
                // Could not confirm, but don't call it danger — mark hazard with unknown reachability
                level='hazard'; reason='We couldn\'t confirm this website is online — it may be down or blocking our check';
            } else if (!httpsOk) {
                level='hazard'; reason='This site is not using a secure connection — avoid entering any personal info';
            } else {
                reason='The connection is secure and the site is live — run a full scan for a deeper check';
            }
        }

        const score = (serverData && typeof serverData.riskScore === 'number')
            ? serverData.riskScore
            : calcSafetyScore(checks, level);

        const fourBadges = [
            checks.find(c=>c.label==='Secure Connection')                ||{label:'Secure Connection',                ok:null,detail:''},
            checks.find(c=>c.label==='Website Identity')      ||{label:'Website Identity',      ok:null,detail:''},
            checks.find(c=>c.label==='Known Threats')      ||{label:'Known Threats',      ok:null,detail:''},
            checks.find(c=>c.label==='Google Safety Check')
                || checks.find(c=>c.label==='Visual Sandbox (urlscan.io)')
                || checks.find(c=>c.label==='Brand Impersonation Check (CheckPhish)')
                || checks.find(c=>c.label==='How Old Is This Site?')
                ||{label:'How Old Is This Site?',ok:null,detail:''},
        ];

        // ── Extra client-side heuristic flags (entropy, homograph, etc.) ──────
        if (typeof window._wsExtraHeuristics === 'function') {
            const extra = window._wsExtraHeuristics(normalized);
            for (const f of extra) {
                if (!checks.some(c => c.label === f.label)) {
                    checks.push(f);
                    if (level !== 'danger') level = 'hazard';
                }
            }
        }

        stopLoadingSteps();
        renderResultCard({level, reason, checks, fourBadges, score,
            shortened: !!(serverData && serverData.shortened),
            resolvedUrl: serverData && serverData.resolvedUrl});
        logSafetyReport(normalized, level, reason, checks);
        addToHistory(normalized, level);

        // Notify chat widget of scan result for context-aware responses
        if (typeof window._wsChatContext === "function" && serverData) {
            window._wsChatContext({
                url:                 normalized,
                verdict:             level,
                riskScore:           serverData.riskScore    ?? null,
                httpsOk:             serverData.httpsOk      ?? false,
                domainAgeDays:       serverData.domainAgeDays ?? null,
                googleSafeBrowsing:  serverData.googleSafeBrowsing  ?? false,
                virusTotalPositives: serverData.virusTotalPositives  ?? null,
                virusTotalTotal:     serverData.virusTotalTotal       ?? null,
                flags:               serverData.contentFlags ?? [],
            });
        }

        // Store for preview button
        window._wsLastUrl       = normalized;
        window._wsLastLevel     = level;
        window._wsLastDeadLink  = !!(serverData && serverData.deadLink);
        window._wsLastDeadLabel = (serverData && serverData.deadLabel) || null;

        btn.disabled = false;
        hideSpinner();
    }

    if (btn)   btn.addEventListener('click', checkLink);
    if (input) {
        input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); checkLink(); } });
        input.addEventListener('paste', e => {
            // Auto-trim whitespace from pasted URLs
            setTimeout(() => { input.value = input.value.trim(); }, 0);
        });
    }
})();




// ─── Preview module ───────────────────────────────────────────────────────────
(function () {
    const previewBtn  = document.getElementById('preview_btn');
    const previewArea = document.getElementById('preview_area');
    const pvDomain    = document.getElementById('preview_domain');
    const pvChecks    = document.getElementById('preview_checks');
    const pvActions   = document.getElementById('preview_actions');

    if (!previewBtn) return;

    // ── Inject all styles once ────────────────────────────────────────────────
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ws-shimmer {
            0%   { background-position: -800px 0 }
            100% { background-position:  800px 0 }
        }
        @keyframes ws-fadeUp {
            from { opacity: 0; transform: translateY(20px) scale(0.985); }
            to   { opacity: 1; transform: translateY(0)    scale(1);    }
        }
        @keyframes ws-spin {
            to { transform: rotate(360deg); }
        }
        @keyframes ws-dot-bounce {
            0%, 80%, 100% { transform: translateY(0);    opacity: .35; }
            40%           { transform: translateY(-7px); opacity: 1;   }
        }
        @keyframes ws-danger-pulse {
            0%   { box-shadow: 0 0 0 0   rgba(239,68,68,0.5); }
            70%  { box-shadow: 0 0 0 10px rgba(239,68,68,0);  }
            100% { box-shadow: 0 0 0 0   rgba(239,68,68,0);   }
        }

        /* ── Skeleton shimmer ── */
        .ws-skel {
            background: linear-gradient(90deg, #172035 25%, #1f2f4a 50%, #172035 75%);
            background-size: 800px 100%;
            animation: ws-shimmer 1.5s infinite linear;
            border-radius: 6px;
        }

        /* ── Main wrapper card ── */
        .ws-preview-wrap {
            width: 100%;
            max-width: 720px;
            margin: 18px auto 0;
            border-radius: 18px;
            overflow: hidden;
            background: #0b1120;
            border: 1px solid rgba(59,130,246,0.2);
            box-shadow:
                0 0 0 1px rgba(59,130,246,0.06),
                0 12px 50px rgba(0,0,0,0.6),
                0 2px 10px rgba(59,130,246,0.1);
            animation: ws-fadeUp 0.45s cubic-bezier(0.22,1,0.36,1) both;
        }

        /* Danger state wrapper */
        .ws-preview-wrap.ws-danger-mode {
            border-color: rgba(239,68,68,0.45);
            box-shadow:
                0 0 0 1px rgba(239,68,68,0.15),
                0 12px 50px rgba(0,0,0,0.6),
                0 0 24px rgba(239,68,68,0.12);
        }

        /* ── Danger banner ── */
        .ws-danger-banner {
            background: linear-gradient(135deg, rgba(220,38,38,0.18), rgba(153,27,27,0.18));
            border-bottom: 1px solid rgba(239,68,68,0.4);
            padding: 10px 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12.5px;
            font-weight: 600;
            color: #fca5a5;
            letter-spacing: 0.01em;
        }
        .ws-danger-banner svg { stroke: #f87171; flex-shrink: 0; }
        .ws-danger-banner strong { color: #ff6b6b; }

        /* ── Browser chrome bar ── */
        .ws-browser-chrome {
            background: #0f1929;
            border-bottom: 1px solid rgba(59,130,246,0.15);
            padding: 10px 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            user-select: none;
        }
        .ws-traffic-lights { display: flex; gap: 6px; flex-shrink: 0; }
        .ws-tl {
            width: 11px; height: 11px;
            border-radius: 50%;
            display: inline-block;
            transition: filter 0.2s;
        }
        .ws-tl:hover { filter: brightness(1.3); }
        .ws-tl-red   { background: #ff5f57; box-shadow: 0 0 6px #ff5f5766; }
        .ws-tl-amber { background: #febc2e; box-shadow: 0 0 6px #febc2e66; }
        .ws-tl-green { background: #28c840; box-shadow: 0 0 6px #28c84066; }

        .ws-url-bar {
            flex: 1;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(59,130,246,0.15);
            border-radius: 8px;
            padding: 5px 12px 5px 10px;
            display: flex;
            align-items: center;
            gap: 7px;
            min-width: 0;
            transition: border-color 0.2s, background 0.2s;
        }
        .ws-url-bar:hover {
            border-color: rgba(59,130,246,0.35);
            background: rgba(59,130,246,0.06);
        }
        .ws-lock-icon { flex-shrink: 0; display: flex; align-items: center; }
        .ws-lock-icon svg { stroke: #22c55e; }
        .ws-lock-icon.ws-no-lock svg { stroke: #f87171; }
        .ws-url-text {
            font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
            font-size: 11.5px;
            color: #94a3b8;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .ws-url-text em { font-style: normal; color: #e2e8f0; font-weight: 600; }

        /* ── Chrome action buttons ── */
        .ws-chrome-actions { display: flex; gap: 4px; flex-shrink: 0; }
        .ws-chrome-btn {
            width: 28px; height: 28px;
            border-radius: 7px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.07);
            display: grid;
            place-items: center;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s, color 0.15s;
            text-decoration: none;
            color: #64748b;
            position: relative;
        }
        .ws-chrome-btn:hover {
            background: rgba(59,130,246,0.15);
            border-color: rgba(59,130,246,0.35);
            color: #60a5fa;
        }
        .ws-chrome-btn svg { stroke: currentColor; }
        /* Active/on state for live frame toggle */
        .ws-chrome-btn.ws-active {
            background: rgba(34,197,94,0.15);
            border-color: rgba(34,197,94,0.4);
            color: #4ade80;
        }
        /* Tooltip */
        .ws-chrome-btn::after {
            content: attr(data-tip);
            position: absolute;
            bottom: calc(100% + 6px);
            left: 50%;
            transform: translateX(-50%);
            background: #1e2d47;
            color: #e2e8f0;
            font-size: 10px;
            font-family: 'Space Grotesk', sans-serif;
            white-space: nowrap;
            padding: 3px 8px;
            border-radius: 5px;
            border: 1px solid rgba(59,130,246,0.2);
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.15s;
            z-index: 10;
        }
        .ws-chrome-btn:hover::after { opacity: 1; }



        /* ── Viewport area ── */
        .ws-viewport {
            position: relative;
            background: #0e1928;
            min-height: 320px;
            overflow: hidden;
        }

        /* Screenshot mode — scrollable */
        .ws-viewport.ws-scroll-mode {
            overflow-y: auto;
            max-height: 520px;
            scroll-behavior: smooth;
        }
        .ws-viewport.ws-scroll-mode::-webkit-scrollbar {
            width: 6px;
        }
        .ws-viewport.ws-scroll-mode::-webkit-scrollbar-track {
            background: #0b1120;
        }
        .ws-viewport.ws-scroll-mode::-webkit-scrollbar-thumb {
            background: rgba(59,130,246,0.3);
            border-radius: 3px;
        }
        .ws-viewport.ws-scroll-mode::-webkit-scrollbar-thumb:hover {
            background: rgba(59,130,246,0.55);
        }

        .ws-screenshot-img {
            width: 100%;
            height: auto;
            display: block;
            transition: opacity 0.3s ease;
        }

        /* Zoom controls overlay on screenshot */
        .ws-zoom-controls {
            position: sticky;
            bottom: 10px;
            right: 10px;
            display: flex;
            justify-content: flex-end;
            padding: 0 10px;
            pointer-events: none;
            z-index: 5;
            margin-top: -40px;
        }
        .ws-zoom-pill {
            display: inline-flex;
            align-items: center;
            gap: 2px;
            background: rgba(11,17,32,0.85);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(59,130,246,0.25);
            border-radius: 20px;
            padding: 4px 6px;
            pointer-events: all;
        }
        .ws-zoom-btn {
            width: 26px; height: 26px;
            border-radius: 50%;
            background: transparent;
            border: none;
            color: #94a3b8;
            display: grid;
            place-items: center;
            cursor: pointer;
            font-size: 14px;
            font-weight: 700;
            transition: background 0.15s, color 0.15s;
        }
        .ws-zoom-btn:hover {
            background: rgba(59,130,246,0.2);
            color: #60a5fa;
        }
        .ws-zoom-label {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 10px;
            color: #64748b;
            min-width: 32px;
            text-align: center;
        }



        /* ── Loading overlay ── */
        .ws-loading-overlay {
            position: absolute;
            inset: 0;
            background: #0b1120;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 18px;
            z-index: 8;
        }
        .ws-spinner {
            width: 38px; height: 38px;
            border: 3px solid rgba(59,130,246,0.12);
            border-top-color: #3b82f6;
            border-radius: 50%;
            animation: ws-spin 0.75s linear infinite;
        }
        .ws-loading-dots { display: flex; gap: 5px; }
        .ws-loading-dots span {
            width: 6px; height: 6px;
            border-radius: 50%;
            background: #3b82f6;
            animation: ws-dot-bounce 1.2s infinite ease-in-out;
        }
        .ws-loading-dots span:nth-child(2) { animation-delay: 0.15s; }
        .ws-loading-dots span:nth-child(3) { animation-delay: 0.30s; }
        .ws-loading-label { font-size: 12.5px; color: #64748b; letter-spacing: 0.02em; }

        /* Skeleton body */
        .ws-skel-body {
            padding: 18px 20px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            background: #0b1120;
        }

        /* ── Fallback (no screenshot) ── */
        .ws-fallback {
            padding: 52px 24px 56px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
            background: #0b1120;
        }
        .ws-fallback-globe {
            width: 68px; height: 68px;
            border-radius: 50%;
            background: rgba(59,130,246,0.08);
            border: 1px solid rgba(59,130,246,0.22);
            display: grid;
            place-items: center;
            margin-bottom: 6px;
        }
        .ws-fallback-globe svg { stroke: #60a5fa; }
        .ws-fallback h4 { font-size: 16px; font-weight: 700; color: #e2e8f0; margin: 0; }
        .ws-fallback p  { font-size: 12.5px; color: #64748b; margin: 0; max-width: 320px; line-height: 1.6; }

        /* ── Screenshot badge ── */
        .ws-screenshot-badge {
            position: absolute;
            top: 10px; right: 10px;
            background: rgba(0,0,0,0.7);
            backdrop-filter: blur(6px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 3px 10px;
            font-size: 10.5px;
            color: #94a3b8;
            letter-spacing: 0.05em;
            pointer-events: none;
            font-family: 'IBM Plex Mono', monospace;
        }

        /* ── Footer bar ── */
        .ws-preview-footer {
            padding: 11px 16px;
            background: #090f1e;
            border-top: 1px solid rgba(59,130,246,0.1);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }
        .ws-footer-left {
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 0;
            flex: 1;
        }
        .ws-footer-favicon {
            width: 16px; height: 16px;
            border-radius: 3px;
            flex-shrink: 0;
            background: rgba(59,130,246,0.1);
        }
        .ws-footer-domain {
            font-size: 12px;
            color: #64748b;
            overflow: hidden;
            white-space: nowrap;
            text-overflow: ellipsis;
        }
        .ws-footer-right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
        .ws-open-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 7px 16px;
            background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.3);
            border-radius: 8px;
            text-decoration: none;
            font-size: 12px;
            font-weight: 600;
            color: #60a5fa;
            letter-spacing: 0.02em;
            transition: background 0.2s, box-shadow 0.2s, transform 0.15s;
            white-space: nowrap;
        }
        .ws-open-btn:hover {
            background: rgba(59,130,246,0.2);
            box-shadow: 0 0 16px rgba(59,130,246,0.22);
            transform: translateY(-1px);
        }
        .ws-open-btn svg { stroke: #60a5fa; }

        /* Mobile */
        @media (max-width: 520px) {
            .ws-preview-wrap { border-radius: 14px; }
            .ws-viewport.ws-scroll-mode { max-height: 380px; }
        }
    `;
    document.head.appendChild(style);

    // ── State ─────────────────────────────────────────────────────────────────
    let _currentUrl   = '';
    let _currentLevel = 'safe';
    let _currentZoom  = 100;

    // ── Helpers ───────────────────────────────────────────────────────────────
    function setPreviewVisible(v) {
        if (previewArea) previewArea.style.display = v ? 'block' : 'none';
    }
    function resetPreviewContent() {
        if (pvDomain)  pvDomain.textContent = '';
        if (pvChecks)  pvChecks.innerHTML   = '';
        if (pvActions) pvActions.innerHTML  = '';
        _currentZoom   = 100;
    }

    function formatDisplayUrl(url) {
        try {
            const u    = new URL(url);
            const rest = u.pathname + u.search + u.hash;
            const path = rest.length > 1
                ? rest.substring(0, 28) + (rest.length > 28 ? '…' : '')
                : '';
            return `${u.protocol}//<em>${u.hostname}</em>${path}`;
        } catch(e) { return url; }
    }

    // ── Screenshot sources ────────────────────────────────────────────────────
    function tryLoadImage(src, ms) {
        return new Promise(resolve => {
            const img = new Image();
            const tid = setTimeout(() => { img.src = ''; resolve(null); }, ms);
            img.onload  = () => { clearTimeout(tid); resolve(img.src); };
            img.onerror = () => { clearTimeout(tid); resolve(null); };
            img.src = src;
        });
    }

    async function getScreenshot(url) {
        const enc = encodeURIComponent(url);
        const sources = [
            `https://image.thum.io/get/width/960/crop/700/noanimate/${url}`,
            `https://pageshot.site/v1/screenshot?url=${enc}&width=960&height=700&format=png&block_ads=true&hide_banners=true`,
            `https://mini.s-shot.ru/1024x768/PNG/1024/Z100/?${url}`,
        ];
        for (const src of sources) {
            const r = await tryLoadImage(src, 13000);
            if (r) return r;
        }
        return null;
    }

    // ── Build browser chrome ──────────────────────────────────────────────────
    function makeBrowserChrome(url) {
        const isHttps = url.startsWith('https://');
        const div = document.createElement('div');
        div.className = 'ws-browser-chrome';
        div.innerHTML = `
            <div class="ws-traffic-lights">
                <span class="ws-tl ws-tl-red"></span>
                <span class="ws-tl ws-tl-amber"></span>
                <span class="ws-tl ws-tl-green"></span>
            </div>
            <div class="ws-url-bar">
                <span class="ws-lock-icon${isHttps ? '' : ' ws-no-lock'}">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        ${isHttps
                            ? `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`
                            : `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1M17 11V9"/>`
                        }
                    </svg>
                </span>
                <span class="ws-url-text">${formatDisplayUrl(url)}</span>
            </div>
            <div class="ws-chrome-actions" id="ws_chrome_actions"></div>
        `;
        return div;
    }

    // ── Loading overlay ───────────────────────────────────────────────────────
    function makeLoadingOverlay(msg) {
        const div = document.createElement('div');
        div.className = 'ws-loading-overlay';
        div.innerHTML = `
            <div class="ws-spinner"></div>
            <div class="ws-loading-dots"><span></span><span></span><span></span></div>
            <p class="ws-loading-label">${msg || 'Capturing screenshot…'}</p>
        `;
        return div;
    }

    // ── Skeleton ──────────────────────────────────────────────────────────────
    function makeSkeletonBody() {
        const body = document.createElement('div');
        body.className = 'ws-skel-body';
        body.innerHTML = `<div class="ws-skel" style="height:180px;width:100%;border-radius:8px;margin-bottom:4px;"></div>`;
        [100, 82, 90, 68, 50].forEach(w => {
            const l = document.createElement('div');
            l.className = 'ws-skel';
            l.style.cssText = `height:12px;width:${w}%;`;
            body.appendChild(l);
        });
        return body;
    }

    // ── Fallback UI ───────────────────────────────────────────────────────────
    function makeFallback(hostname) {
        const div = document.createElement('div');
        div.className = 'ws-fallback';
        div.innerHTML = `
            <div class="ws-fallback-globe">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="2" y1="12" x2="22" y2="12"/>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
            </div>
            <h4>${hostname}</h4>
            <p>Screenshot unavailable — this site may block preview services, or the page requires a login to display content.</p>
        `;
        return div;
    }

    // ── Dead link UI ──────────────────────────────────────────────────────────
    function makeDeadLinkUI(url, deadLabel) {
        let hostname = url;
        try { hostname = new URL(url).hostname; } catch(e) {}

        const div = document.createElement('div');
        div.className = 'ws-dead-link-ui';
        div.style.cssText = `
            display:flex; flex-direction:column; align-items:center; justify-content:center;
            gap:14px; padding:40px 24px; text-align:center;
            background: repeating-linear-gradient(
                -45deg,
                rgba(220,38,38,0.04) 0px, rgba(220,38,38,0.04) 10px,
                transparent 10px, transparent 20px
            );
        `;
        div.innerHTML = `
            <div style="width:56px;height:56px;border-radius:50%;background:rgba(220,38,38,0.12);border:2px solid rgba(220,38,38,0.4);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                </svg>
            </div>
            <div>
                <div style="font-size:15px;font-weight:700;color:#f87171;margin-bottom:6px;">Dead / Unreachable Link</div>
                <div style="font-size:12px;color:#94a3b8;line-height:1.55;max-width:320px;margin:0 auto;">
                    ${deadLabel || 'This URL is unreachable — the page may have been taken down, the domain has expired, or the server is offline.'}
                </div>
            </div>
            <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:#475569;background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.06);padding:6px 12px;border-radius:6px;word-break:break-all;max-width:320px;">${hostname}</div>
            <div style="font-size:11px;color:#64748b;">Preview unavailable — cannot load a page that doesn't exist.</div>
        `;
        return div;
    }
    function makeDangerBanner(level) {
        if (level === 'safe') return null;
        const div = document.createElement('div');
        div.className = 'ws-danger-banner';
        if (level === 'danger') {
            div.innerHTML = `
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <span><strong>⚠ Dangerous Link Detected</strong> — This preview is shown in a sandboxed frame. Do not enter any personal information or click any links on this page.</span>
            `;
        } else {
            div.innerHTML = `
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="stroke:#fbbf24">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <span style="color:#fde68a"><strong>⚠ Proceed With Caution</strong> — This site has suspicious characteristics. Avoid entering personal details.</span>
            `;
        }
        return div;
    }

    // ── Footer bar ────────────────────────────────────────────────────────────
    function makeFooter(url) {
        let hostname = '';
        try { hostname = new URL(url).hostname; } catch(e) { hostname = url; }

        const footer = document.createElement('div');
        footer.className = 'ws-preview-footer';
        footer.innerHTML = `
            <div class="ws-footer-left">
                <img class="ws-footer-favicon"
                     src="https://www.google.com/s2/favicons?sz=16&domain=${encodeURIComponent(hostname)}"
                     onerror="this.style.display='none'"
                     alt="">
                <span class="ws-footer-domain">${hostname}</span>
            </div>
            <div class="ws-footer-right">
                <a href="${url}" target="_blank" rel="noopener noreferrer" class="ws-open-btn" data-ws-newtab="1">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                        <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                    </svg>
                    Open in new tab
                </a>
            </div>
        `;
        return footer;
    }

    // ── Zoom controls for screenshot ──────────────────────────────────────────
    function makeZoomControls(imgEl) {
        const wrap = document.createElement('div');
        wrap.className = 'ws-zoom-controls';
        wrap.innerHTML = `
            <div class="ws-zoom-pill">
                <button class="ws-zoom-btn" id="ws_zoom_out" title="Zoom out">−</button>
                <span class="ws-zoom-label" id="ws_zoom_label">100%</span>
                <button class="ws-zoom-btn" id="ws_zoom_in" title="Zoom in">+</button>
            </div>
        `;
        wrap.querySelector('#ws_zoom_out').addEventListener('click', () => updateZoom(-25, imgEl, wrap));
        wrap.querySelector('#ws_zoom_in').addEventListener('click',  () => updateZoom(+25, imgEl, wrap));
        return wrap;
    }

    function updateZoom(delta, imgEl, controlsWrap) {
        _currentZoom = Math.max(50, Math.min(200, _currentZoom + delta));
        imgEl.style.width = _currentZoom + '%';
        imgEl.style.height = 'auto';
        const lbl = controlsWrap.querySelector('#ws_zoom_label');
        if (lbl) lbl.textContent = _currentZoom + '%';
    }

    // ── Main render ───────────────────────────────────────────────────────────
    async function renderPreview(url, level, opts) {
        // opts = { deadLink, deadLabel } — passed from scan result when URL is dead
        _currentUrl   = url;
        _currentLevel = level || 'safe';
        let hostname = '';
        try { hostname = new URL(url).hostname; } catch(e) {}

        const isDead = opts?.deadLink === true;

        // Hide old content
        setPreviewVisible(true);
        resetPreviewContent();
        if (pvDomain) pvDomain.textContent = hostname;

        if (!pvActions) { hideSpinner(); return; }

        // ── Build wrapper ─────────────────────────────────────────────────────
        const wrapper = document.createElement('div');
        wrapper.className = 'ws-preview-wrap' + (_currentLevel === 'danger' ? ' ws-danger-mode' : '');

        // Danger/hazard banner
        const banner = makeDangerBanner(_currentLevel);
        if (banner) wrapper.appendChild(banner);

        // Browser chrome
        wrapper.appendChild(makeBrowserChrome(url));

        // Viewport
        const viewport = document.createElement('div');
        viewport.className = 'ws-viewport ws-scroll-mode';

        // ── Dead link fast-path — no screenshot attempt ───────────────────────
        if (isDead) {
            viewport.appendChild(makeDeadLinkUI(url, opts?.deadLabel));
            wrapper.appendChild(viewport);
            wrapper.appendChild(makeFooter(url));

            // Remove the "open in new tab" link from the footer for dead links
            const ftLink = wrapper.querySelector('.ws-open-btn');
            if (ftLink) {
                ftLink.style.opacity = '0.4';
                ftLink.style.pointerEvents = 'none';
                ftLink.title = 'Link is unreachable';
            }

            pvActions.appendChild(wrapper);
            return;
        }

        // Skeleton + loading overlay in viewport
        viewport.appendChild(makeSkeletonBody());
        viewport.appendChild(makeLoadingOverlay('Capturing screenshot…'));

        wrapper.appendChild(viewport);
        wrapper.appendChild(makeFooter(url));

        pvActions.appendChild(wrapper);

        // ── Fetch screenshot ──────────────────────────────────────────────────
        showSpinner();
        const shot = await getScreenshot(url);
        hideSpinner();
        viewport.innerHTML = '';

        if (shot) {
            viewport.style.overflowY = 'auto';
            const img = document.createElement('img');
            img.className = 'ws-screenshot-img';
            img.src  = shot;
            img.alt  = `Preview of ${hostname}`;
            viewport.appendChild(img);

            // Badge
            const badge = document.createElement('div');
            badge.className = 'ws-screenshot-badge';
            badge.textContent = 'SCREENSHOT';
            viewport.appendChild(badge);

            // Zoom controls
            viewport.appendChild(makeZoomControls(img));

            // Chrome action buttons (refresh screenshot)
            const actions = wrapper.querySelector('#ws_chrome_actions');
            if (actions) {
                const refreshBtn = document.createElement('button');
                refreshBtn.className = 'ws-chrome-btn';
                refreshBtn.setAttribute('data-tip', 'Refresh screenshot');
                refreshBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`;
                refreshBtn.addEventListener('click', async () => {
                    viewport.innerHTML = '';
                    viewport.appendChild(makeSkeletonBody());
                    viewport.appendChild(makeLoadingOverlay('Refreshing…'));
                    const newShot = await getScreenshot(url + '?_ws=' + Date.now());
                    viewport.innerHTML = '';
                    if (newShot) {
                        const img2 = document.createElement('img');
                        img2.className = 'ws-screenshot-img';
                        img2.src = newShot;
                        viewport.appendChild(img2);
                        const b2 = document.createElement('div');
                        b2.className = 'ws-screenshot-badge';
                        b2.textContent = 'SCREENSHOT';
                        viewport.appendChild(b2);
                        viewport.appendChild(makeZoomControls(img2));
                    } else {
                        viewport.appendChild(makeFallback(hostname));
                    }
                });
                actions.appendChild(refreshBtn);

                // Open in new tab
                const openBtn = document.createElement('a');
                openBtn.className = 'ws-chrome-btn';
                openBtn.href      = url;
                openBtn.target    = '_blank';
                openBtn.rel       = 'noopener noreferrer';
                openBtn.setAttribute('data-tip', 'Open in new tab');
                openBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`;
                actions.appendChild(openBtn);
            }
        } else {
            viewport.appendChild(makeFallback(hostname));
            // Still add open button in chrome
            const actions = wrapper.querySelector('#ws_chrome_actions');
            if (actions) {
                const openBtn = document.createElement('a');
                openBtn.className = 'ws-chrome-btn';
                openBtn.href      = url;
                openBtn.target    = '_blank';
                openBtn.rel       = 'noopener noreferrer';
                openBtn.setAttribute('data-tip', 'Open in new tab');
                openBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`;
                actions.appendChild(openBtn);
            }
        }
    }

    // ── Preview button click ──────────────────────────────────────────────────
    previewBtn.addEventListener('click', async () => {
        const inputEl = document.getElementById('link_input');
        if (!inputEl) return;
        const raw = (inputEl.value || '').trim();
        if (!raw) { alert('Please enter a URL first.'); return; }

        const normalized = normalizeURL(raw);
        if (!normalized) {
            showInvalidUrlError(document.getElementById('link_status'));
            return;
        }

        // Use last known scan level + dead-link status if URL matches
        const level    = (window._wsLastUrl === normalized) ? (window._wsLastLevel || 'safe') : 'safe';
        const deadLink = (window._wsLastUrl === normalized) ? (window._wsLastDeadLink || false) : false;
        const deadLabel= (window._wsLastUrl === normalized) ? (window._wsLastDeadLabel || null) : null;
        await renderPreview(normalized, level, { deadLink, deadLabel });
    });

})();


// ─── Extra Client-Side Phishing Heuristics ────────────────────────────────────
// These run before the server call to catch signals the server may not
// have had time to compute (entropy, homograph, subdomain spoofing).
(function () {
    // Shannon entropy — high value indicates a randomly-generated domain name
    function domainEntropy(str) {
        const freq = {};
        for (const c of str) freq[c] = (freq[c] || 0) + 1;
        const len = str.length;
        let e = 0;
        for (const c in freq) {
            const p = freq[c] / len;
            e -= p * Math.log2(p);
        }
        return e;
    }

    /**
     * Detect homograph / lookalike characters (Punycode spoofing)
     * e.g. "раypal.com" uses Cyrillic 'р' and 'а'
     */
    function hasHomographChars(hostname) {
        // Non-ASCII chars in the hostname hint at IDN homograph attack
        return /[^\x00-\x7F]/.test(hostname);
    }

    /**
     * Detect excessive numeric substitution (p4yp4l, g00gle, amaz0n)
     * Targets numbers sandwiched between letters (letter-number-letter pattern),
     * which is the hallmark of brand spoofing (g00gle, p4ypal, amaz0n).
     * Does NOT flag domains that start with numbers like 1337x, 4chan, 9gag —
     * those are legitimate sites where numbers are part of the brand name.
     */
    function hasNumericSubstitution(hostname) {
        // Only flag letter-DIGIT-letter patterns (brand substitution: g00gle, p4ypal)
        // NOT when the domain label starts with a number — those are legitimate brand names (1337x, 4chan, 9gag)
        const domainLabel = hostname.replace(/^www\./, '').split('.')[0];
        if (/^[0-9]/.test(domainLabel)) return false;
        return /[a-z][0-9][a-z]/i.test(hostname.replace(/\./g, ''));
    }

    // Brand names that should never appear in subdomains of unrelated domains.
    // Kept in sync with BRAND_LEGITIMATE_DOMAINS in server.js.
    const BRANDS = [
        'paypal','google','gmail','youtube','facebook','instagram','twitter','tiktok',
        'apple','icloud','microsoft','outlook','amazon','netflix','spotify',
        'gcash','bdo','bpi','metrobank','landbank','unionbank','rcbc','paymaya','maya',
        'exodus','metamask','coinbase','binance','ledger','trezor',
    ];
    function brandInSubdomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length <= 2) return null;
        const sub = parts.slice(0, -2).join('.');
        for (const b of BRANDS) {
            if (sub.toLowerCase().includes(b)) return b;
        }
        return null;
    }

    /**
     * Detect data: or javascript: URIs
     */
    function hasDangerousProtocol(url) {
        return /^(data:|javascript:|vbscript:)/i.test(url.trim());
    }

    // Expose so check_link module can call it after normalising the URL
    window._wsExtraHeuristics = function(url) {
        const flags = [];
        let hostname = '';
        try { hostname = new URL(url).hostname.toLowerCase(); } catch(e) { return flags; }

        if (hasDangerousProtocol(url)) {
            flags.push({ label: 'Dangerous Link Type', ok: false, detail: 'URL uses a dangerous protocol (data:/javascript:) — never visit' });
        }
        if (hasHomographChars(hostname)) {
            flags.push({ label: 'Lookalike Web Address', ok: false, detail: 'This web address contains look-alike characters from other languages, designed to impersonate a real site' });
        }
        const domainPart = hostname.replace(/^www\./, '');
        const domainLabel = domainPart.split('.')[0];
        const isAlphaOnly = /^[a-zA-Z]+$/.test(domainLabel);
        const entScore = domainEntropy(domainPart.replace(/\./g, ''));
        if (isAlphaOnly && entScore > 3.8 && domainPart.length > 12) {
            flags.push({ label: 'Random-Looking Site Name', ok: false, detail: `This website name looks randomly generated by a computer (score: ${entScore.toFixed(2)}) — a common pattern in scam networks` });
        }
        if (hasNumericSubstitution(hostname)) {
            flags.push({ label: 'Letter-Number Trick', ok: false, detail: 'This address swaps letters for numbers (like g00gle or p4ypal) to imitate a real brand — a classic scammer trick' });
        }
        const brand = brandInSubdomain(hostname);
        if (brand) {
            flags.push({ label: 'Brand Buried in Subdomain', ok: false, detail: `"${brand}" appears deep in the subdomain path — designed to trick you into thinking it's the real site` });
        }
        return flags;
    };
})();
