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
        'brand-impersonation':       'Brand Impersonation',
        'keywords-high':             'High-Risk Phrases',
        'keywords-medium':           'Suspicious Phrases',
        'multiple-password-fields':  'Credential Harvesting',
        'form-external-post':        'Data Theft Risk',
        'hidden-iframe':             'Hidden Frame',
        'meta-redirect':             'Silent Redirect',
        'obfuscation':               'Code Obfuscation',
        'base64-payload':            'Hidden Payload',
        'base64-large':              'Hidden Payload',
        'fake-trust-badges':         'Fake Security Badges',
        'ip-address':                'Raw IP Address',
        'at-sign-url':               'URL Spoofing',
        'dash-heavy-domain':         'Suspicious Domain Name',
        'suspicious-tld':            'Suspicious Domain Extension',
        'excessive-subdomains':      'Subdomain Spoofing',
        'brand-in-subdomain':        'Brand Spoofing',
        'long-url':                  'Obfuscated URL',
        'encoded-hostname':          'Encoded Hostname',
        'dynamic-dns':               'Dynamic DNS Abuse',
        'suspicious-hosting':        'Suspicious Hosting',
        'free-site-builder':         'Free Site Builder (Phishing Risk)',
        'crypto-brand-on-free-host': 'Crypto Brand on Free Hosting',
        'wix-phishing':              'Wix-Hosted Phishing Site',
        'google-safebrowsing':       'Google Safe Browsing Alert',
        'virustotal-flag':           'VirusTotal Malicious Flag',
        'disposable-hosting':        'Disposable/Free Hosting',
        'dangerous-protocol':        'Dangerous Protocol',
        'high-entropy-domain':       'Random-Looking Domain',
        'homograph-attack':          'Homograph/Lookalike Attack',
        'numeric-substitution':      'Numeric Letter Substitution',
    };
    return map[type] || 'Suspicious Signal';
}

// ─── Friendly flag details ────────────────────────────────────────────────────
function friendlyFlagDetail(f) {
    switch(f.type) {
        case 'brand-impersonation':
            return f.detail || 'This page is pretending to be a brand it isn\'t — a classic phishing tactic';
        case 'keywords-high':
            { const kws = Array.isArray(f.detail) ? f.detail : [f.detail];
              return `Contains high-risk phrases (${kws.map(k=>`"${k}"`).join(', ')}) — strongly associated with phishing`; }
        case 'keywords-medium':
            { const kws = Array.isArray(f.detail) ? f.detail : [f.detail];
              return `Contains suspicious phrases (${kws.map(k=>`"${k}"`).join(', ')}) — verify the URL is correct`; }
        case 'multiple-password-fields':
            return f.detail || 'Multiple password fields detected — possible credential harvesting';
        case 'form-external-post':
            return f.detail || 'This page sends your data to a different server — common in phishing attacks';
        case 'hidden-iframe':
            return f.detail || 'Hidden frame detected — may be used for silent tracking or clickjacking';
        case 'meta-redirect':
            return f.detail || 'Page silently redirects to another domain — often used in phishing relay attacks';
        case 'obfuscation':
            return f.detail || 'Scrambled/hidden code detected — often used to conceal malicious behaviour';
        case 'base64-payload': case 'base64-large':
            return f.detail || 'Large encoded data blobs found — may be hiding malicious content';
        case 'fake-trust-badges':
            return f.detail || 'Multiple fake "security verified" claims — a common scam site tactic';
        case 'ip-address':
            return f.detail || 'URL uses a raw IP address instead of a domain — almost always suspicious';
        case 'at-sign-url':
            return f.detail || 'URL contains @ symbol — can be used to disguise the real destination';
        case 'dash-heavy-domain':
            return f.detail || 'Over-hyphenated domain — a common pattern in phishing domains';
        case 'suspicious-tld':
            return f.detail || 'Domain uses a TLD frequently abused for scams';
        case 'excessive-subdomains':
            return f.detail || 'Unusual subdomain depth — often used to make phishing URLs look legitimate';
        case 'brand-in-subdomain':
            return f.detail || 'A trusted brand is used in the subdomain to impersonate the real site';
        case 'long-url':
            return f.detail || 'Unusually long URL — often used to obscure the real destination';
        case 'encoded-hostname':
            return f.detail || 'Percent-encoded characters in the hostname — common phishing obfuscation';
        case 'dynamic-dns':
            return f.detail || 'Uses a free dynamic DNS service — frequently abused in phishing campaigns';
        case 'suspicious-hosting':
            return f.detail || 'Hosted on an IP range associated with bulletproof hosting';
        case 'free-site-builder':
            return f.detail || 'Site is hosted on a free website builder — commonly abused for phishing pages';
        case 'crypto-brand-on-free-host':
            return f.detail || 'A crypto wallet or financial brand is referenced on a free hosting platform — extremely high phishing risk';
        case 'wix-phishing':
            return f.detail || 'This site is hosted on Wix and shows crypto/financial brand content — a known phishing vector. Legitimate services never use free website builders.';
        case 'google-safebrowsing':
            return f.detail || 'Google Safe Browsing has flagged this URL as dangerous';
        case 'virustotal-flag':
            return f.detail || 'Multiple antivirus engines on VirusTotal flagged this URL as malicious';
        case 'disposable-hosting':
            return f.detail || 'Hosted on a known free/disposable platform used for temporary scam sites';
        case 'high-entropy-domain':
            return f.detail || 'Domain name appears algorithmically generated — typical of phishing infrastructure';
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
                checks.push({label:'Shortened Link', ok:null, detail:`Short link resolves to: ${d.resolvedUrl}`});

            // HTTPS
            checks.push({label:'HTTPS', ok:!!d.httpsOk,
                detail: d.httpsOk
                    ? 'Connection is private and encrypted'
                    : 'Site does not use encryption — avoid entering personal info'});

            // Reachable
            checks.push({label:'Reachable', ok:d.reachable!==false,
                detail: d.reachable ? 'Website is online and responding' : 'Could not reach this website'});

            // SSL Certificate
            const certDetail = d.certValid
                ? (d.selfSignedCert
                    ? 'Certificate is self-signed — not issued by a trusted authority'
                    : d.certExpiresSoon
                        ? `Certificate expires in ${d.certExpiresDays} days — suspicious`
                        : `Security certificate valid (expires in ${d.certExpiresDays ?? '?'} days)`)
                : 'Security certificate is missing or expired — red flag';
            checks.push({label:'SSL Certificate', ok: d.certValid && !d.selfSignedCert && !d.certExpiresSoon, detail: certDetail});

            // Threat database
            const isFlagged = d.blacklisted || d.brandSpoof || d.patternMatch;
            checks.push({label:'Threat Database', ok:!isFlagged,
                detail: d.blacklisted
                    ? 'Domain is on known-dangerous list — do NOT proceed'
                    : d.brandSpoof
                        ? `Domain is impersonating "${d.spoofedBrand}" — NOT the real website`
                        : d.patternMatch
                            ? 'Domain matches known phishing patterns'
                            : 'Not found on any known threat list'});

            // Connection safety
            checks.push({label:'Connection Safety', ok:!d.redirectsToHttp,
                detail: d.redirectsToHttp
                    ? 'Site starts secure then drops encryption — warning sign'
                    : 'Connection stays protected throughout'});

            // Domain age
            if (d.domainAgeDays != null) {
                const ageOk = d.domainAgeDays >= 30;
                const years  = Math.floor(d.domainAgeDays / 365);
                const months = Math.floor((d.domainAgeDays % 365) / 30);
                const ageText = years > 0
                    ? `${years} year${years>1?'s':''}${months>0?` and ${months} month${months>1?'s':''}`:''}`
                    : `${months>0 ? months+' month'+(months>1?'s':'') : d.domainAgeDays+' days'}`;
                checks.push({label:'Domain Age', ok:ageOk,
                    detail: ageOk
                        ? `Domain has been around for ${ageText} — legitimate sign`
                        : `Domain was registered only ${ageText} ago — new domains are a major phishing red flag`});
            } else {
                checks.push({label:'Domain Age', ok:null, detail:'Could not determine domain age'});
            }

            // Google Safe Browsing (v7)
            if (d.googleSafeBrowsing != null) {
                checks.push({label:'Google Safe Browsing', ok:!d.googleSafeBrowsing,
                    detail: d.googleSafeBrowsing
                        ? `Google Safe Browsing flagged this as: ${d.safeBrowsingThreat || 'MALWARE/PHISHING'}`
                        : 'Google Safe Browsing: no threats detected'});
            }

            // VirusTotal (v7)
            if (d.virusTotalPositives != null) {
                const vtOk = d.virusTotalPositives === 0;
                checks.push({label:'VirusTotal Scan', ok:vtOk,
                    detail: vtOk
                        ? 'VirusTotal: no engines flagged this URL'
                        : `${d.virusTotalPositives} of ${d.virusTotalTotal} antivirus engines flagged this URL as malicious`});
            }

            // Free site builder warning (v7)
            if (d.freeSiteBuilder) {
                checks.push({label:'Free Site Builder', ok:false,
                    detail: d.freeSiteBuilderDetail || 'Hosted on a free website builder — frequently abused for phishing'});
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
                checks.push({label:'Page Content', ok:true, detail:'No suspicious content detected'});
            }

            if (d.verdict) level = d.verdict;
            if (!level) level = 'safe';

            // Final reason string
            if (level === 'danger') {
                if (!reason || reason === 'Could not complete all checks') {
                    if (d.googleSafeBrowsing)  reason = '🚨 Google Safe Browsing has flagged this URL as dangerous';
                    else if (d.blacklisted)    reason = '🚨 This website is on our known-dangerous list — do NOT visit';
                    else if (d.brandSpoof)     reason = `🚨 This site is impersonating "${d.spoofedBrand}" — phishing site`;
                    else if (d.freeSiteBuilder) reason = '🚨 Phishing brand content detected on a free hosting platform';
                    else if (d.patternMatch)   reason = '🚨 URL matches known phishing patterns';
                    else                       reason = '🚨 Multiple high-risk signals detected — avoid this site';
                }
            } else if (level === 'hazard') {
                if (!reason || reason === 'Could not complete all checks')
                    reason = '⚠️ Warning signs found — double-check before proceeding';
            } else {
                reason = `✅ ${checks.filter(c=>c.ok===true).length} of ${checks.filter(c=>c.ok!==null).length} checks passed — this link looks safe`;
            }

        } else {
            // ── Client-only fallback (no server) ────────────────────────────
            let reachable = false;
            try {
                const ctrl = new AbortController(); const tid = setTimeout(()=>ctrl.abort(), 5000);
                const r = await fetch(normalized, {method:'HEAD', signal:ctrl.signal});
                clearTimeout(tid); reachable = r.ok || r.type === 'opaque';
            } catch(e) {
                try {
                    const ctrl2 = new AbortController(); const tid2 = setTimeout(()=>ctrl2.abort(), 5000);
                    const r2 = await fetch(normalized, {method:'GET', signal:ctrl2.signal});
                    clearTimeout(tid2); reachable = r2.ok || r2.type === 'opaque';
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
            ];
            let hostname = '';
            try { hostname = new URL(normalized).hostname.toLowerCase(); } catch(e) {}
            const isWellKnown = WELL_KNOWN.some(d => hostname === d || hostname.endsWith('.' + d));
            const httpsOk = normalized.startsWith('https://');
            checks.push({label:'HTTPS', ok:httpsOk, detail:httpsOk?'Connection is private and encrypted':'Site does not use encryption — avoid entering personal info'});
            checks.push({label:'Reachable', ok:reachable||isWellKnown, detail:reachable?'Website is online and responding':isWellKnown?'Well-known trusted website — confirmed safe':'Could not reach this website'});
            checks.push({label:'SSL Certificate', ok:null, detail:'Certificate details unavailable in this mode'});
            checks.push({label:'Threat Database', ok:null, detail:'Threat database lookup unavailable in this mode'});
            checks.push({label:'Domain Age', ok:null, detail:'Domain age could not be determined in this mode'});
            if (!reachable && !isWellKnown) { level='danger'; reason='Could not reach this website — it may not exist or is currently offline'; }
            else if (!httpsOk)              { level='hazard'; reason='Site is not using a secure HTTPS connection — data is not encrypted'; }
            else                            { level='safe';   reason='HTTPS is active and site is reachable — deeper checks unavailable'; }
        }

        const score = (serverData && typeof serverData.riskScore === 'number')
            ? serverData.riskScore
            : calcSafetyScore(checks, level);

        const fourBadges = [
            checks.find(c=>c.label==='HTTPS')                ||{label:'HTTPS',                ok:null,detail:''},
            checks.find(c=>c.label==='SSL Certificate')      ||{label:'SSL Certificate',      ok:null,detail:''},
            checks.find(c=>c.label==='Threat Database')      ||{label:'Threat Database',      ok:null,detail:''},
            checks.find(c=>c.label==='Google Safe Browsing') || checks.find(c=>c.label==='Domain Age') ||{label:'Domain Age',ok:null,detail:''},
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

        // ── Show "Open Live Frame" button below result card ──────────────────
        const openBtn = document.getElementById('open_live_frame_btn');
        if (openBtn) {
            openBtn.style.display = 'inline-block';
            openBtn.onclick = () => {
                if (typeof window._wsOpenLiveFrame === 'function')
                    window._wsOpenLiveFrame(normalized, level);
            };
            const toggleRow = document.getElementById('live_frame_toggle_row');
            if (toggleRow) toggleRow.style.display = 'block';
            // Store for live frame module
            window._wsLastUrl   = normalized;
            window._wsLastLevel = level;
        }

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

    // ── Inject styles ─────────────────────────────────────────────────────────
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ws-shimmer {
            0%   { background-position: -700px 0 }
            100% { background-position:  700px 0 }
        }
        @keyframes ws-fadeUp {
            from { opacity: 0; transform: translateY(18px) scale(0.98); }
            to   { opacity: 1; transform: translateY(0)    scale(1);    }
        }
        @keyframes ws-spin {
            to { transform: rotate(360deg); }
        }
        @keyframes ws-dot-bounce {
            0%, 80%, 100% { transform: translateY(0);   opacity: .4; }
            40%            { transform: translateY(-6px); opacity: 1;  }
        }

        .ws-skel {
            background: linear-gradient(90deg,
                #172035 25%, #1e2d47 50%, #172035 75%);
            background-size: 700px 100%;
            animation: ws-shimmer 1.5s infinite linear;
            border-radius: 6px;
        }

        /* ── wrapper card ── */
        .ws-preview-wrap {
            width: 100%;
            max-width: 680px;
            margin: 16px auto 0;
            border-radius: 16px;
            overflow: hidden;
            background: #0d1422;
            border: 1px solid rgba(59,130,246,0.22);
            box-shadow:
                0 0 0 1px rgba(59,130,246,0.06),
                0 8px 40px rgba(0,0,0,0.55),
                0 2px 8px  rgba(59,130,246,0.12);
            animation: ws-fadeUp 0.45s cubic-bezier(0.22,1,0.36,1) both;
        }

        /* ── browser chrome ── */
        .ws-browser-chrome {
            background: #111827;
            border-bottom: 1px solid rgba(59,130,246,0.18);
            padding: 10px 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            user-select: none;
        }
        .ws-traffic-lights {
            display: flex;
            gap: 6px;
            flex-shrink: 0;
        }
        .ws-tl {
            width: 11px; height: 11px;
            border-radius: 50%;
            display: inline-block;
        }
        .ws-tl-red   { background: #ff5f57; box-shadow: 0 0 5px #ff5f5766; }
        .ws-tl-amber { background: #febc2e; box-shadow: 0 0 5px #febc2e66; }
        .ws-tl-green { background: #28c840; box-shadow: 0 0 5px #28c84066; }

        .ws-url-bar {
            flex: 1;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(59,130,246,0.18);
            border-radius: 8px;
            padding: 5px 12px 5px 10px;
            display: flex;
            align-items: center;
            gap: 7px;
            min-width: 0;
            transition: border-color 0.2s;
        }
        .ws-url-bar:hover {
            border-color: rgba(59,130,246,0.38);
        }
        .ws-lock-icon {
            flex-shrink: 0;
            color: #22c55e;
            display: flex;
            align-items: center;
        }
        .ws-lock-icon svg { stroke: #22c55e; }
        .ws-url-text {
            font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
            font-size: 11.5px;
            color: #94a3b8;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .ws-url-text em { font-style: normal; color: #e2e8f0; font-weight: 600; }

        .ws-chrome-actions {
            display: flex;
            gap: 4px;
            flex-shrink: 0;
        }
        .ws-chrome-btn {
            width: 28px; height: 28px;
            border-radius: 7px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.07);
            display: grid;
            place-items: center;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
            text-decoration: none;
            color: #64748b;
        }
        .ws-chrome-btn:hover {
            background: rgba(59,130,246,0.15);
            border-color: rgba(59,130,246,0.35);
            color: #60a5fa;
        }
        .ws-chrome-btn svg { stroke: currentColor; }

        /* ── screenshot viewport ── */
        .ws-viewport {
            position: relative;
            background: #121929;
            min-height: 300px;
            overflow: hidden;
        }
        .ws-viewport img {
            width: 100%;
            height: auto;
            display: block;
        }

        /* ── loading overlay inside viewport ── */
        .ws-loading-overlay {
            position: absolute;
            inset: 0;
            background: #0d1422;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 20px;
            z-index: 5;
        }
        .ws-spinner {
            width: 36px; height: 36px;
            border: 3px solid rgba(59,130,246,0.15);
            border-top-color: #3b82f6;
            border-radius: 50%;
            animation: ws-spin 0.75s linear infinite;
        }
        .ws-loading-dots {
            display: flex;
            gap: 5px;
        }
        .ws-loading-dots span {
            width: 6px; height: 6px;
            border-radius: 50%;
            background: #3b82f6;
            animation: ws-dot-bounce 1.2s infinite ease-in-out;
        }
        .ws-loading-dots span:nth-child(2) { animation-delay: 0.15s; }
        .ws-loading-dots span:nth-child(3) { animation-delay: 0.30s; }
        .ws-loading-label {
            font-size: 12.5px;
            color: #64748b;
            letter-spacing: 0.02em;
        }

        /* skeleton body */
        .ws-skel-body {
            padding: 18px 20px;
            display: flex;
            flex-direction: column;
            gap: 11px;
            background: #0d1422;
        }

        /* ── fallback (no screenshot) ── */
        .ws-fallback {
            padding: 48px 24px 52px;
            text-align: center;
            background: #0d1422;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
        }
        .ws-fallback-globe {
            width: 64px; height: 64px;
            border-radius: 50%;
            background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.25);
            display: grid;
            place-items: center;
            margin-bottom: 4px;
        }
        .ws-fallback-globe svg { stroke: #60a5fa; }
        .ws-fallback h4 {
            font-size: 16px;
            font-weight: 700;
            color: #e2e8f0;
            margin: 0;
        }
        .ws-fallback p {
            font-size: 12.5px;
            color: #64748b;
            margin: 0;
            max-width: 320px;
            line-height: 1.55;
        }

        /* ── footer bar ── */
        .ws-preview-footer {
            padding: 11px 16px;
            background: #0b1120;
            border-top: 1px solid rgba(59,130,246,0.12);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }
        .ws-footer-domain {
            display: flex;
            align-items: center;
            gap: 7px;
            font-size: 12px;
            color: #64748b;
            overflow: hidden;
            white-space: nowrap;
            text-overflow: ellipsis;
        }
        .ws-footer-domain svg { stroke: #64748b; flex-shrink: 0; }
        .ws-open-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 7px 16px;
            background: rgba(59,130,246,0.12);
            border: 1px solid rgba(59,130,246,0.32);
            border-radius: 8px;
            text-decoration: none;
            font-size: 12.5px;
            font-weight: 600;
            color: #60a5fa;
            letter-spacing: 0.02em;
            transition: background 0.2s, box-shadow 0.2s, transform 0.15s;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .ws-open-btn:hover {
            background: rgba(59,130,246,0.22);
            box-shadow: 0 0 14px rgba(59,130,246,0.25);
            transform: translateY(-1px);
        }
        .ws-open-btn svg { stroke: #60a5fa; }

        /* ── screenshot overlay badge ── */
        .ws-screenshot-badge {
            position: absolute;
            top: 10px; right: 10px;
            background: rgba(0,0,0,0.65);
            backdrop-filter: blur(6px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 3px 10px;
            font-size: 10.5px;
            color: #94a3b8;
            letter-spacing: 0.04em;
            pointer-events: none;
        }
    `;
    document.head.appendChild(style);

    // ── Helpers ───────────────────────────────────────────────────────────────
    function setPreviewVisible(v) {
        if (previewArea) previewArea.style.display = v ? 'block' : 'none';
    }
    function resetPreviewContent() {
        if (pvDomain)  pvDomain.textContent = '';
        if (pvChecks)  pvChecks.innerHTML   = '';
        if (pvActions) pvActions.innerHTML  = '';
    }

    function formatDisplayUrl(normalized) {
        // Bold the hostname, dim the rest
        try {
            const u = new URL(normalized);
            const host = u.hostname;
            const rest = u.pathname + u.search + u.hash;
            const proto = u.protocol + '//';
            return `${proto}<em>${host}</em>${rest.length > 1 ? rest.substring(0, 30) + (rest.length > 30 ? '…' : '') : ''}`;
        } catch(e) {
            return normalized;
        }
    }

    function makeBrowserChrome(hostname, normalized) {
        const isHttps = normalized.startsWith('https://');
        const bar = document.createElement('div');
        bar.className = 'ws-browser-chrome';
        bar.innerHTML = `
            <div class="ws-traffic-lights">
                <span class="ws-tl ws-tl-red"></span>
                <span class="ws-tl ws-tl-amber"></span>
                <span class="ws-tl ws-tl-green"></span>
            </div>
            <div class="ws-url-bar">
                ${isHttps ? `
                <span class="ws-lock-icon">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                </span>` : ''}
                <span class="ws-url-text">${formatDisplayUrl(normalized)}</span>
            </div>
            <div class="ws-chrome-actions">
                <a href="${normalized}" target="_blank" rel="noopener noreferrer" class="ws-chrome-btn" title="Open in new tab">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                        <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                    </svg>
                </a>
            </div>
        `;
        return bar;
    }

    function makeLoadingOverlay() {
        const div = document.createElement('div');
        div.className = 'ws-loading-overlay';
        div.innerHTML = `
            <div class="ws-spinner"></div>
            <div>
                <div class="ws-loading-dots">
                    <span></span><span></span><span></span>
                </div>
            </div>
            <p class="ws-loading-label">Capturing screenshot…</p>
        `;
        return div;
    }

    function makeSkeletonBody() {
        const body = document.createElement('div');
        body.className = 'ws-skel-body';
        const sizes = [100, 85, 92, 70, 55];
        body.innerHTML = `<div class="ws-skel" style="height:160px;width:100%;border-radius:8px;margin-bottom:4px;"></div>`;
        sizes.forEach(w => {
            const line = document.createElement('div');
            line.className = 'ws-skel';
            line.style.cssText = `height:12px;width:${w}%;`;
            body.appendChild(line);
        });
        return body;
    }

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
            <p>Live screenshot unavailable — the site may block preview services or require a login to load.</p>
        `;
        return div;
    }

    function makePreviewFooter(hostname, normalized) {
        const footer = document.createElement('div');
        footer.className = 'ws-preview-footer';
        footer.innerHTML = `
            <span class="ws-footer-domain">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="2" y1="12" x2="22" y2="12"/>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
                ${hostname}
            </span>
            <a href="${normalized}" target="_blank" rel="noopener noreferrer" class="ws-open-btn" data-ws-newtab="1">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                    <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                </svg>
                Open in new tab
            </a>
        `;
        return footer;
    }

    // ── Image sources ─────────────────────────────────────────────────────────
    function tryLoadImage(url, ms) {
        return new Promise(resolve => {
            const img = new Image();
            const tid = setTimeout(() => { img.src = ''; resolve(null); }, ms);
            img.onload  = () => { clearTimeout(tid); resolve(img.src); };
            img.onerror = () => { clearTimeout(tid); resolve(null); };
            img.src = url;
        });
    }

    async function getScreenshot(url) {
        const enc = encodeURIComponent(url);
        const sources = [
            `https://image.thum.io/get/width/900/crop/600/noanimate/${url}`,
            `https://shot.screenshotapi.net/screenshot?url=${enc}&width=1280&height=768&output=image&file_type=png&wait_for_event=load`,
            `https://mini.s-shot.ru/1024x768/PNG/1024/Z100/?${url}`,
        ];
        for (const src of sources) {
            const r = await tryLoadImage(src, 10000);
            if (r) return r;
        }
        return null;
    }

    // ── Main click handler ────────────────────────────────────────────────────
    previewBtn.addEventListener('click', async () => {
        const inputEl = document.getElementById('link_input');
        if (!inputEl) return;
        const raw = inputEl.value || '';

        if (!raw.trim()) { alert('Please enter a URL first.'); return; }
        const normalized = normalizeURL(raw);
        if (!normalized) {
            showInvalidUrlError(document.getElementById('link_status'));
            return;
        }

        let hostname = '';
        try { hostname = new URL(normalized).hostname; } catch(e) {}

        // Update legacy elements if present
        setPreviewVisible(true);
        resetPreviewContent();
        if (pvDomain) pvDomain.textContent = hostname;
        showSpinner();

        if (pvActions) {
            // Build wrapper
            const wrapper = document.createElement('div');
            wrapper.className = 'ws-preview-wrap';

            // Browser chrome
            wrapper.appendChild(makeBrowserChrome(hostname, normalized));

            // Viewport with skeleton + loading overlay
            const viewport = document.createElement('div');
            viewport.className = 'ws-viewport';
            viewport.appendChild(makeSkeletonBody());
            viewport.appendChild(makeLoadingOverlay());
            wrapper.appendChild(viewport);

            // Footer
            wrapper.appendChild(makePreviewFooter(hostname, normalized));

            pvActions.appendChild(wrapper);

            // Fetch screenshot
            const shot = await getScreenshot(normalized);
            hideSpinner();

            // Clear viewport
            viewport.innerHTML = '';

            if (shot) {
                const img = document.createElement('img');
                img.src = shot;
                img.alt = `Live preview of ${hostname}`;
                img.style.cssText = 'width:100%;height:auto;display:block;';
                viewport.appendChild(img);

                // Small "LIVE PREVIEW" badge on top-right
                const badge = document.createElement('div');
                badge.className = 'ws-screenshot-badge';
                badge.textContent = 'LIVE PREVIEW';
                viewport.appendChild(badge);
            } else {
                viewport.appendChild(makeFallback(hostname));
            }
        }
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
            flags.push({ label: 'Dangerous Protocol', ok: false, detail: 'URL uses a dangerous protocol (data:/javascript:) — never visit' });
        }
        if (hasHomographChars(hostname)) {
            flags.push({ label: 'Homograph Attack', ok: false, detail: 'Hostname contains non-ASCII characters — possible lookalike spoofing (e.g. Cyrillic letters)' });
        }
        const domainPart = hostname.replace(/^www\./, '');
        const domainLabel = domainPart.split('.')[0];
        const isAlphaOnly = /^[a-zA-Z]+$/.test(domainLabel);
        const entScore = domainEntropy(domainPart.replace(/\./g, ''));
        if (isAlphaOnly && entScore > 3.8 && domainPart.length > 12) {
            flags.push({ label: 'High Domain Entropy', ok: false, detail: `Domain name looks randomly generated (entropy ${entScore.toFixed(2)}) — common in phishing infrastructure` });
        }
        if (hasNumericSubstitution(hostname)) {
            flags.push({ label: 'Numeric Substitution', ok: false, detail: 'Numbers replacing letters detected (e.g. g00gle, p4ypal) — classic URL spoofing technique' });
        }
        const brand = brandInSubdomain(hostname);
        if (brand) {
            flags.push({ label: 'Brand Buried in Subdomain', ok: false, detail: `"${brand}" appears deep in the subdomain path — designed to trick you into thinking it's the real site` });
        }
        return flags;
    };
})();
