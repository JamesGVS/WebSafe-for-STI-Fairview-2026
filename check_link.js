// ── Firebase API base URL (for server-side checks) ─────────────────────────────────
const WEBSAFE_API_BASE = "https://us-central1-websafe-capstone.cloudfunctions.net/api";
// ─────────────────────────────────────────────────────────────────────────────

// check_link.js — WebSafe v4
// • Input change/clear  → result card auto-clears
// • Check Link          → rich card styled to site palette + 4 badges + console report
// • Preview             → website preview only, no safety info

// ─── Shared helpers ───────────────────────────────────────────────────────────
function showSpinner() {
    const s = document.getElementById('loading_spinner');
    if (s) s.style.display = 'block';
}
function hideSpinner() {
    const s = document.getElementById('loading_spinner');
    if (s) s.style.display = 'none';
}
function normalizeURL(raw) {
    if (!raw) return null;
    raw = String(raw).trim();
    if (!raw) return null;
    // If no protocol given, default to https:// (safer assumption)
    if (!/^https?:\/\//i.test(raw) && !/^[a-z]+:\/\//i.test(raw)) {
        raw = 'https://' + raw;
    }
    try { return new URL(raw).href; } catch (e) {
        try { return new URL('https://' + raw).href; } catch (e2) { return null; }
    }
}

// ─── Check Link module ────────────────────────────────────────────────────────
(function () {
    const input    = document.getElementById('link_input');
    const btn      = document.getElementById('check_btn');
    const statusEl = document.getElementById('link_status');
    const safetyEl = document.getElementById('safety_status'); // kept hidden for compat

    // ── Auto-clear on input change ────────────────────────────────────────────
    let _lastValue = '';
    function clearResults() {
        if (statusEl) statusEl.innerHTML = '';
        if (safetyEl) { safetyEl.textContent = ''; safetyEl.className = ''; }
        const pa = document.getElementById('preview_area');
        if (pa) pa.style.display = 'none';
    }
    if (input) {
        input.addEventListener('input', () => {
            const cur = input.value.trim();
            if (cur !== _lastValue) { _lastValue = cur; clearResults(); }
        });
    }

    // ── Console report ────────────────────────────────────────────────────────
    function logSafetyReport(url, level, reason, checks) {
        const icons  = { safe: '✅', hazard: '⚠️', danger: '🚨' };
        const styles = {
            safe:   'color:#16a34a;font-weight:bold;font-size:13px',
            hazard: 'color:#d97706;font-weight:bold;font-size:13px',
            danger: 'color:#dc2626;font-weight:bold;font-size:13px',
        };
        console.group(`%c${icons[level] || '?'} WebSafe [${level.toUpperCase()}] — ${url}`, styles[level] || '');
        console.log(`%cVerdict:%c ${reason}`, 'font-weight:bold', 'font-weight:normal');
        console.log('─── Individual Checks ───────────────────────────');
        checks.forEach(ch => {
            const ico    = ch.ok === true ? '✅' : ch.ok === false ? '❌' : 'ℹ️';
            const detail = ch.detail ? ` — ${ch.detail}` : '';
            if      (ch.ok === false) console.warn(`${ico} ${ch.label}${detail}`);
            else if (ch.ok === null)  console.info(`${ico} ${ch.label}${detail}`);
            else                      console.log (`${ico} ${ch.label}${detail}`);
        });
        const failed  = checks.filter(c => c.ok === false).map(c => c.label);
        const unknown = checks.filter(c => c.ok === null).map(c => c.label);
        console.log('─────────────────────────────────────────────────');
        if (failed.length)  console.warn(`❌ Failed: ${failed.join(', ')}`);
        if (unknown.length) console.info(`ℹ️  Unknown/skipped: ${unknown.join(', ')}`);
        if (!failed.length && !unknown.length) console.log('✅ All checks passed.');
        console.groupEnd();
    }

    // ── Result card — styled to match site palette ────────────────────────────
    // Site colors: navy #1E3A8A, off-white #F8FAFC, black border, white panels
    function renderResultCard(data) {
        if (!statusEl) return;
        statusEl.innerHTML = '';

        const { level, reason, checks, fourBadges } = data;

        // Accent per verdict level
       const theme = {
    safe:   { accent: '#16a34a', icon: '<span style="width:28px;height:28px;border-radius:50%;background:#16a34a;display:inline-block;box-shadow:0 0 10px #16a34a88;flex-shrink:0"></span>', label: 'Link Looks Safe'   },
    hazard: { accent: '#d97706', icon: '<span style="width:28px;height:28px;border-radius:50%;background:#d97706;display:inline-block;box-shadow:0 0 10px #d9770688;flex-shrink:0"></span>', label: 'Potential Warning' },
    danger: { accent: '#dc2626', icon: '<span style="width:28px;height:28px;border-radius:50%;background:#dc2626;display:inline-block;box-shadow:0 0 10px #dc262688;flex-shrink:0"></span>', label: 'Dangerous Link'    },
};
        if (!level) level = checks.some(ch => ch.ok === false) ? 'hazard' : 'safe';
        const t = theme[level] || theme.safe;

        // Outer card — white background, navy border, colored left stripe
        const card = document.createElement('div');
        card.style.cssText = `
            max-width:580px; margin:16px auto 0;
            border-radius:10px;
            background:#ffffff;
            border:2px solid #1E3A8A;
            box-shadow:0 4px 14px rgba(30,58,138,.15);
            overflow:hidden; font-family:inherit; text-align:left;
        `;

        // Header — navy background, white text (matches the site header)
        const header = document.createElement('div');
        header.style.cssText = `
            display:flex; align-items:center; gap:14px;
            padding:15px 20px;
            background:#1E3A8A;
            border-bottom:3px solid ${t.accent};
        `;
        const resolvedBanner = data.shortened && data.resolvedUrl ? `
            <div style="margin-top:6px;padding:5px 10px;background:#0f2460;border-radius:6px;font-size:11px;color:#93c5fd;">
                🔗 Shortened link → <span style="color:#ffffff;font-weight:700;word-break:break-all">${data.resolvedUrl}</span>
            </div>` : '';
        header.innerHTML = `
            ${t.icon}
            <div style="flex:1;min-width:0">
                <div style="font-size:18px;font-weight:700;color:#F8FAFC;letter-spacing:.3px">
                    ${t.label}${data.shortened ? ' <span style="font-size:12px;background:#ffffff22;padding:2px 8px;border-radius:10px;vertical-align:middle">Shortened Link</span>' : ''}
                </div>
                <div style="font-size:12px;color:#93c5fd;margin-top:4px">${reason || ''}</div>
                ${resolvedBanner}
            </div>
        `;
        card.appendChild(header);

        // 4 Key Check badges — light #F8FAFC strip, navy "Key Checks:" label
        if (Array.isArray(fourBadges) && fourBadges.length) {
            const badgeRow = document.createElement('div');
            badgeRow.style.cssText = `
                display:flex; flex-wrap:wrap; gap:8px; align-items:center;
                padding:12px 20px;
                background:#F8FAFC;
                border-bottom:1px solid #1E3A8A44;
            `;
            const lbl = document.createElement('span');
            lbl.style.cssText = `
                font-size:10px; font-weight:800; color:#1E3A8A;
                text-transform:uppercase; letter-spacing:.8px; margin-right:4px;
            `;
            lbl.textContent = 'Key Checks:';
            badgeRow.appendChild(lbl);

            fourBadges.forEach(b => {
                const bOk   = b.ok === true;
                const bNull = b.ok === null;
                // Pass → navy filled; Fail → red filled; Unknown → grey outline
                const bgCol  = bOk ? '#1E3A8A' : bNull ? '#ffffff'  : '#dc2626';
                const fgCol  = bOk ? '#ffffff'  : bNull ? '#6b7280'  : '#ffffff';
                const border = bOk ? '#1E3A8A'  : bNull ? '#9ca3af'  : '#dc2626';
                const ico    = bOk ? '✓'        : bNull ? '?'        : '✕';
                const badge  = document.createElement('div');
                badge.style.cssText = `
                    display:inline-flex; align-items:center; gap:5px;
                    background:${bgCol}; color:${fgCol};
                    border:2px solid ${border}; border-radius:6px;
                    padding:4px 11px; font-size:12px; font-weight:700;
                    cursor:default; letter-spacing:.2px;
                `;
                badge.innerHTML = `<span style="font-weight:900;font-size:11px">${ico}</span><span>${b.label}</span>`;
                badge.title = b.detail || '';
                badgeRow.appendChild(badge);
            });
            card.appendChild(badgeRow);
        }

        // Full checks list — white bg, each row has a colored dot + navy text
        if (Array.isArray(checks) && checks.length) {
            const list = document.createElement('div');
            list.style.cssText = `
                padding:12px 20px 16px;
                display:flex; flex-direction:column; gap:5px;
                background:#ffffff;
            `;
            checks.forEach(ch => {
                const row = document.createElement('div');
                row.style.cssText = `
                    display:flex; align-items:flex-start; gap:10px;
                    border-radius:7px; padding:8px 12px;
                    background:#F8FAFC;
                    border:1px solid #e2e8f0;
                `;
                // Dot color: pass=green, fail=red, unknown=grey
                const dotCol   = ch.ok === true ? '#16a34a' : ch.ok === false ? '#dc2626' : '#9ca3af';
                // Label color: pass=navy, fail=red, unknown=grey
                const lblCol   = ch.ok === true ? '#1E3A8A' : ch.ok === false ? '#dc2626' : '#6b7280';
                const dot      = `<span style="width:9px;height:9px;border-radius:50%;background:${dotCol};display:inline-block;margin-top:4px;flex-shrink:0"></span>`;
                row.innerHTML  = `
                    ${dot}
                    <div>
                        <span style="font-weight:700;color:${lblCol};font-size:13px">${ch.label}</span>
                        ${ch.detail ? `<span style="color:#64748b;font-size:12px;margin-left:6px">— ${ch.detail}</span>` : ''}
                    </div>
                `;
                list.appendChild(row);
            });
            card.appendChild(list);
        }

        statusEl.appendChild(card);
    }

    // ── Main check function ───────────────────────────────────────────────────
    async function checkLink() {
        if (!input || !btn) return;
        const raw        = input.value || '';
        _lastValue       = raw.trim();
        const normalized = normalizeURL(raw);

        clearResults();

        if (!normalized) {
            if (statusEl) statusEl.innerHTML = `<p style="color:#dc2626;margin-top:8px;font-weight:600">⚠️ Please enter a valid URL.</p>`;
            return;
        }

        btn.disabled = true;
        showSpinner();
        if (statusEl) statusEl.innerHTML = `<p style="color:#1E3A8A;margin-top:8px;font-weight:600">Checking link…</p>`;

        let level  = null;
        let reason = 'Could not complete all checks';
        let checks = [];

        // ── Try server /api/check ─────────────────────────────────────────
        let serverData = null;
        try {
            const res = await fetch(WEBSAFE_API_BASE + '/check?url=' + encodeURIComponent(normalized));
            if (res.ok) { const j = await res.json(); if (j && j.ok) serverData = j; }
        } catch (e) { /* server offline */ }

        if (serverData) {
            const d = serverData;
            if (d.shortened && d.resolvedUrl) {
                checks.push({ label: 'Shortened Link', ok: null, detail: `Resolves to: ${d.resolvedUrl}` });
            }
            checks.push({ label: 'HTTPS',          ok: !!d.httpsOk,          detail: d.httpsOk          ? 'Secure connection'                                      : 'No HTTPS — data may not be encrypted' });
            checks.push({ label: 'Reachable',       ok: d.reachable !== false, detail: d.reachable        ? `HTTP ${d.statusCode || '—'}`                             : 'Site could not be reached' });
            checks.push({ label: 'SSL Certificate', ok: !!d.certValid,         detail: d.certValid         ? (d.certExpiresDays != null ? `Expires in ${d.certExpiresDays} days` : 'Valid') : 'Invalid or missing certificate' });
            checks.push({ label: 'Blacklist',       ok: !d.blacklisted,        detail: d.blacklisted       ? 'Domain is on our blacklist'                             : 'Not found on blacklist' });
            checks.push({ label: 'HTTP Redirect',   ok: !d.redirectsToHttp,    detail: d.redirectsToHttp   ? 'HTTPS redirects to HTTP (downgrade)'                    : 'No insecure redirect' });
            if (d.domainAgeDays != null) {
                const ageOk = d.domainAgeDays >= 30;
                checks.push({ label: 'Domain Age', ok: ageOk, detail: ageOk ? `${d.domainAgeDays} days old` : `Only ${d.domainAgeDays} days old — very new domain` });
            } else {
                checks.push({ label: 'Domain Age', ok: null, detail: 'Could not retrieve WHOIS data' });
            }
            if (Array.isArray(d.contentFlags) && d.contentFlags.length) {
                const highFlags = d.contentFlags.filter(f => f.severity === 'high');
                checks.push({ label: 'Content Scan', ok: false, detail: d.contentFlags.map(f => f.detail || f.type).join('; ') });
                if (highFlags.length) { level = 'danger'; reason = highFlags.map(f => f.detail || f.type).join('; '); }
                else if (level !== 'danger') { level = 'hazard'; reason = 'Suspicious content detected'; }
            } else {
                checks.push({ label: 'Content Scan', ok: true, detail: 'No suspicious content found' });
            }
            if (d.blacklisted) {
                level = 'danger'; reason = 'Blacklisted domain';
            } else if (d.reachable === false) {
                level = 'danger'; reason = 'Site is not reachable';
            } else if (level === 'danger') {
                // already set by content flags
            } else {
                const anyBad = !d.httpsOk || d.redirectsToHttp || !d.certValid || (d.domainAgeDays != null && d.domainAgeDays < 30);
                if (anyBad) {
                    level = 'hazard'; reason = 'One or more security concerns detected';
                } else if (level === 'hazard') {
                    // content flags set hazard — keep it
                } else {
                    level = 'safe'; reason = 'All checks passed';
                }
            }
        } else {
            // ── Client-side fallback ──────────────────────────────────────
            let reachable = false;
            try {
                const ctrl = new AbortController(); const tid = setTimeout(() => ctrl.abort(), 5000);
                const r    = await fetch(normalized, { method: 'HEAD', signal: ctrl.signal });
                clearTimeout(tid); reachable = r.ok || r.type === 'opaque';
            } catch (e) {
                try {
                    const ctrl2 = new AbortController(); const tid2 = setTimeout(() => ctrl2.abort(), 5000);
                    const r2    = await fetch(normalized, { method: 'GET',  signal: ctrl2.signal });
                    clearTimeout(tid2); reachable = r2.ok || r2.type === 'opaque';
                } catch (e2) { reachable = false; }
            }
            const WELL_KNOWN = ['youtube.com','www.youtube.com','google.com','www.google.com','facebook.com','twitter.com','instagram.com','microsoft.com','apple.com','amazon.com','wikipedia.org','linkedin.com','reddit.com','yahoo.com'];
            let hostname = '';
            try { hostname = new URL(normalized).hostname.toLowerCase(); } catch (e) {}
            const isWellKnown = WELL_KNOWN.includes(hostname);
            const httpsOk     = normalized.startsWith('https://');
            checks.push({ label: 'HTTPS',          ok: httpsOk,                detail: httpsOk   ? 'Secure connection' : 'No HTTPS' });
            checks.push({ label: 'Reachable',       ok: reachable||isWellKnown, detail: reachable ? 'Site responded'   : isWellKnown ? 'Well-known site (may block bots)' : 'Could not reach site' });
            checks.push({ label: 'SSL Certificate', ok: null, detail: 'Run "npm start" locally for full checks' });
            checks.push({ label: 'Blacklist',       ok: null, detail: 'Run "npm start" locally for full checks' });
            checks.push({ label: 'Domain Age',      ok: null, detail: 'Run "npm start" locally for full checks' });
            if (!reachable && !isWellKnown) { level = 'danger'; reason = 'Site not reachable'; }
            else if (!httpsOk)              { level = 'hazard'; reason = 'No HTTPS'; }
            else                            { level = 'safe';   reason = 'Basic checks passed — run npm start for full analysis'; }
        }

        // 4 core badges for the badge row
        const fourBadges = [
            checks.find(c => c.label === 'HTTPS')          || { label: 'HTTPS',      ok: null, detail: '' },
            checks.find(c => c.label === 'SSL Certificate') || { label: 'SSL',        ok: null, detail: '' },
            checks.find(c => c.label === 'Blacklist')       || { label: 'Blacklist',  ok: null, detail: '' },
            checks.find(c => c.label === 'Domain Age')      || { label: 'Domain Age', ok: null, detail: '' },
        ];

        renderResultCard({ level, reason, checks, fourBadges, shortened: !!(serverData && serverData.shortened), resolvedUrl: serverData && serverData.resolvedUrl });
        logSafetyReport(normalized, level, reason, checks);
        btn.disabled = false;
        hideSpinner();
    }

    if (btn)   btn.addEventListener('click', checkLink);
    if (input) input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); checkLink(); } });
})();


// ─── Preview module ───────────────────────────────────────────────────────────
(function () {
    const previewBtn  = document.getElementById('preview_btn');
    const previewArea = document.getElementById('preview_area');
    const pvDomain    = document.getElementById('preview_domain');
    const pvTitle     = document.getElementById('preview_title');
    const pvDesc      = document.getElementById('preview_description');
    const pvFavicon   = document.getElementById('preview_favicon');
    const pvChecks    = document.getElementById('preview_checks');
    const pvActions   = document.getElementById('preview_actions');

    if (!previewBtn) return;

    // Inject shimmer animation once
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ws-shimmer {
            0%   { background-position: -600px 0; }
            100% { background-position:  600px 0; }
        }
        .ws-skel {
            background: linear-gradient(90deg, #e2e8f0 25%, #f1f5f9 50%, #e2e8f0 75%);
            background-size: 600px 100%;
            animation: ws-shimmer 1.4s infinite linear;
            border-radius: 6px;
        }
    `;
    document.head.appendChild(style);

    function setPreviewVisible(v) { if (previewArea) previewArea.style.display = v ? 'block' : 'none'; }

    function resetPreviewContent() {
        if (pvTitle)   pvTitle.textContent   = '';
        if (pvDomain)  pvDomain.textContent  = '';
        if (pvDesc)    pvDesc.textContent    = '';
        if (pvFavicon) { pvFavicon.src = ''; pvFavicon.style.display = 'none'; }
        if (pvChecks)  pvChecks.innerHTML    = '';
        if (pvActions) pvActions.innerHTML   = '';
    }

    function makeBrowserBar(hostname) {
        const bar = document.createElement('div');
        bar.style.cssText = 'background:#1E3A8A;padding:10px 14px;display:flex;align-items:center;gap:8px;';
        bar.innerHTML = `
            <span style="width:10px;height:10px;border-radius:50%;background:#ffffff44;display:inline-block"></span>
            <span style="width:10px;height:10px;border-radius:50%;background:#ffffff44;display:inline-block"></span>
            <span style="width:10px;height:10px;border-radius:50%;background:#ffffff44;display:inline-block"></span>
            <div style="flex:1;background:#ffffff22;border-radius:20px;padding:5px 14px;margin-left:6px;">
                <span style="color:#93c5fd;font-size:12px;font-weight:600">${hostname}</span>
            </div>
        `;
        return bar;
    }

    function makeWrapper() {
        const w = document.createElement('div');
        w.style.cssText = `
            width:100%;max-width:640px;margin:12px auto 0;
            border:2px solid #1E3A8A;border-radius:10px;
            overflow:hidden;background:#ffffff;
        `;
        return w;
    }

    function renderSkeleton(container, hostname) {
        container.innerHTML = '';
        container.appendChild(makeBrowserBar(hostname));
        const body = document.createElement('div');
        body.style.cssText = 'padding:20px;display:flex;flex-direction:column;gap:12px;min-height:280px;';
        const hero = document.createElement('div');
        hero.className = 'ws-skel'; hero.style.cssText = 'height:120px;width:100%;';
        body.appendChild(hero);
        [[100],[80],[90],[60]].forEach(([w]) => {
            const line = document.createElement('div');
            line.className = 'ws-skel'; line.style.cssText = `height:14px;width:${w}%;`;
            body.appendChild(line);
        });
        const cols = document.createElement('div');
        cols.style.cssText = 'display:flex;gap:12px;margin-top:4px;';
        [45,45].forEach(w => {
            const col = document.createElement('div');
            col.className = 'ws-skel'; col.style.cssText = `height:60px;width:${w}%;`;
            cols.appendChild(col);
        });
        body.appendChild(cols);
        const status = document.createElement('p');
        status.style.cssText = 'text-align:center;color:#94a3b8;font-size:13px;margin-top:8px;';
        status.textContent = '📸 Taking screenshot… this may take up to 15 seconds';
        body.appendChild(status);
        container.appendChild(body);
    }

    function tryLoadImage(url, ms) {
        return new Promise(resolve => {
            const img = new Image();
            const tid = setTimeout(() => { img.src=''; resolve(null); }, ms);
            img.onload  = () => { clearTimeout(tid); resolve(img.src); };
            img.onerror = () => { clearTimeout(tid); resolve(null); };
            img.src = url;
        });
    }

   async function getScreenshot(url) {
    const enc = encodeURIComponent(url);
    const sources = [
        // thum.io — free, no signup, fastest
        `https://image.thum.io/get/width/900/crop/600/noanimate/${url}`,
        // screenshotapi.net — free tier, no signup needed
        `https://shot.screenshotapi.net/screenshot?url=${enc}&width=1280&height=768&output=image&file_type=png&wait_for_event=load`,
        // s-shot.ru — free, no signup
        `https://mini.s-shot.ru/1024x768/PNG/1024/Z100/?${url}`,
    ];
    // Try each with a 10s timeout — skip slow ones fast
    for (const src of sources) {
        const r = await tryLoadImage(src, 10000);
        if (r) return r;
    }
    return null;
}
    previewBtn.addEventListener('click', async () => {
        const inputEl = document.getElementById('link_input');
        if (!inputEl) return;
        const normalized = normalizeURL(inputEl.value || '');
        if (!normalized) { alert('Please enter a valid URL first.'); return; }

        setPreviewVisible(true);
        resetPreviewContent();
        showSpinner();

        let hostname = '';
        try { hostname = new URL(normalized).hostname; } catch(e) {}
        if (pvDomain) pvDomain.textContent = hostname;

        if (pvActions) {
            pvActions.innerHTML = '';
            const wrapper = makeWrapper();
            pvActions.appendChild(wrapper);

            // Show skeleton while loading
            renderSkeleton(wrapper, hostname);

            // Get screenshot
            const shot = await getScreenshot(normalized);
            hideSpinner();

            // Replace skeleton with result
            wrapper.innerHTML = '';
            wrapper.appendChild(makeBrowserBar(hostname));

            if (shot) {
                const img = document.createElement('img');
                img.src = shot;
                img.alt = `Preview of ${hostname}`;
                img.style.cssText = 'width:100%;height:auto;display:block;';
                wrapper.appendChild(img);
            } else {
                const fb = document.createElement('div');
                fb.style.cssText = 'padding:50px 20px;text-align:center;';
                fb.innerHTML = `
                    <span style="font-size:48px">🌐</span>
                    <p style="color:#1E3A8A;font-weight:700;font-size:16px;margin:12px 0 6px">${hostname}</p>
                    <p style="color:#94a3b8;font-size:13px;margin:0">Screenshot unavailable — this site may block preview services</p>
                `;
                wrapper.appendChild(fb);
            }

            // Open in new tab button
            const a = document.createElement('a');
            a.href = normalized; a.target = '_blank'; a.rel = 'noopener noreferrer';
            a.textContent = '🔗 Open in new tab';
            a.style.cssText = `
                display:inline-block;margin:12px 0 4px;padding:9px 20px;
                background:#1E3A8A;color:#F8FAFC;border-radius:8px;
                text-decoration:none;font-size:14px;font-weight:600;border:2px solid #000;
            `;
            pvActions.appendChild(a);
        }
    });
})();