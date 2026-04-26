// check_link.js — WebSafe client-side scan module

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

// ─── Scan History (session only) ─────────────────────────────────────────────
const scanHistory = [];
function addToHistory(url, level) {
    const hostname = (() => { try { return new URL(url).hostname; } catch(e) { return url; } })();
    scanHistory.unshift({ hostname, url, level, time: new Date().toLocaleTimeString() });
    if (scanHistory.length > 5) scanHistory.pop();
    renderHistory();
}
function renderHistory() {
    const el = document.getElementById('ws_history_list');
    if (!el) return;
    if (scanHistory.length === 0) {
        el.innerHTML = '<p style="color:#64748b;font-size:13px;text-align:center;padding:8px">No scans yet this session</p>';
        return;
    }
    const colors = { safe:'#22c55e', hazard:'#fbbf24', danger:'#f87171' };
    const labels = { safe:'Safe', hazard:'Warning', danger:'Danger' };
    el.innerHTML = '';
    scanHistory.forEach((h, idx) => {
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
        el.appendChild(row);
    });
}

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
            ? `<div style="margin-top:6px;padding:5px 10px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:6px;font-size:11px;color:#93c5fd;font-family:'IBM Plex Mono',monospace;">🔗 Shortened → <span style="color:#e2e8f0;font-weight:700;word-break:break-all">${data.resolvedUrl}</span></div>`
            : '';
        const scoreColor = level==='safe'?'#22c55e':level==='hazard'?'#fbbf24':'#f87171';
        const scoreCircle = `<div style="flex-shrink:0;width:54px;height:54px;border-radius:50%;border:2px solid ${scoreColor};display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(255,255,255,0.04);box-shadow:0 0 12px ${scoreColor}44;"><span style="font-size:17px;font-weight:900;color:${scoreColor};line-height:1;font-family:'IBM Plex Mono',monospace">${score}</span><span style="font-size:8px;color:#64748b;letter-spacing:.8px;text-transform:uppercase">SCORE</span></div>`;
        header.innerHTML = `${t.icon}<div style="flex:1;min-width:0"><div style="font-size:18px;font-weight:700;color:#f1f5f9">${t.label}${data.shortened?' <span style="font-size:11px;background:rgba(255,255,255,0.1);color:#94a3b8;padding:2px 8px;border-radius:10px;vertical-align:middle;border:1px solid rgba(255,255,255,0.15)">Shortened</span>':''}</div><div style="font-size:12px;color:#94a3b8;margin-top:4px">${reason||''}</div>${resolvedBanner}</div>${scoreCircle}`;
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
                badge.innerHTML = `<span style="font-weight:900;font-size:11px">${ico}</span><span>${b.label}</span>`;
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
                row.innerHTML = `<span style="width:8px;height:8px;border-radius:50%;background:${dotCol};display:inline-block;margin-top:5px;flex-shrink:0;box-shadow:0 0 5px ${dotCol}88"></span><div><span style="font-weight:600;color:${lblCol};font-size:13px">${ch.label}</span>${ch.detail?`<span style="color:#64748b;font-size:12px;margin-left:6px">— ${ch.detail}</span>`:''}</div>`;
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

            // VirusTotal (v7)
            if (d.virusTotalPositives != null) {
                const vtOk = d.virusTotalPositives === 0;
                checks.push({label:'Antivirus Scan', ok:vtOk,
                    detail: vtOk
                        ? 'None of the antivirus tools we checked flagged this link — looks clean'
                        : `${d.virusTotalPositives} out of ${d.virusTotalTotal} antivirus tools flagged this link as dangerous`});
            }

            // Free site builder warning (v7)
            if (d.freeSiteBuilder) {
                checks.push({label:'Suspicious Hosting', ok:false,
                    detail: d.freeSiteBuilderDetail || 'This site is hosted on a free website builder — scammers often use these to create fake pages'});
            }

            // Content / URL / DNS flags
            if (Array.isArray(d.contentFlags) && d.contentFlags.length) {
                const highFlags   = d.contentFlags.filter(f => f.severity === 'high');
                const mediumFlags = d.contentFlags.filter(f => f.severity === 'medium');
                for (const f of d.contentFlags) {
                    checks.push({ label: flagTypeLabel(f.type), ok: false, detail: friendlyFlagDetail(f) });
                }
                if (highFlags.length) { level = 'danger'; reason = friendlyFlagDetail(highFlags[0]); }
                else if (mediumFlags.length && level !== 'danger') { level = 'hazard'; reason = 'Page has suspicious characteristics — proceed with caution'; }
            } else {
                checks.push({label:'Page Content', ok:true, detail:'Nothing suspicious found on this page — looks normal'});
            }

            if (d.verdict) level = d.verdict;
            if (!level) level = 'safe';

            // Final reason string
            if (level === 'danger') {
                if (!reason || reason === 'Could not complete all checks') {
                    if (d.googleSafeBrowsing)  reason = '🚨 Google has flagged this link as dangerous — do not visit';
                    else if (d.blacklisted)    reason = '🚨 This website is on our list of known dangerous sites — stay away';
                    else if (d.brandSpoof)     reason = `🚨 This site is impersonating "${d.spoofedBrand}" — phishing site`;
                    else if (d.freeSiteBuilder) reason = '🚨 This looks like a scam page pretending to be a real brand, hosted on a free site';
                    else if (d.patternMatch)   reason = '🚨 This web address matches patterns used by known scammers';
                    else                       reason = '🚨 Multiple red flags found — avoid this site';
                }
            } else if (level === 'hazard') {
                if (!reason || reason === 'Could not complete all checks')
                    reason = '⚠️ A few warning signs found — double-check this site before doing anything';
            } else {
                reason = `✅ ${checks.filter(c=>c.ok===true).length} of ${checks.filter(c=>c.ok!==null).length} checks passed — this link looks safe to visit`;
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
            checks.find(c=>c.label==='Google Safety Check') || checks.find(c=>c.label==='How Old Is This Site?') ||{label:'How Old Is This Site?',ok:null,detail:''},
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
