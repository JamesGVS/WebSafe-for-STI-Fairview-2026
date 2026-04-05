// check_link.js — WebSafe v5
// Improvements: safety score, animated loading steps, scan history, better messages

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
    if (!/^https?:\/\//i.test(raw) && !/^[a-z]+:\/\//i.test(raw)) raw = 'https://' + raw;
    try { return new URL(raw).href; } catch (e) {
        try { return new URL('https://' + raw).href; } catch (e2) { return null; }
    }
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
        el.innerHTML = '<p style="color:#94a3b8;font-size:13px;text-align:center;padding:8px">No scans yet this session</p>';
        return;
    }
    const colors = { safe:'#16a34a', hazard:'#d97706', danger:'#dc2626' };
    const labels = { safe:'Safe', hazard:'Warning', danger:'Danger' };
    el.innerHTML = scanHistory.map(h => `
        <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:#F8FAFC;border:1px solid #e2e8f0;border-radius:8px;cursor:pointer;"
             onclick="document.getElementById('link_input').value='${h.url}';window.scrollTo({top:0,behavior:'smooth'})">
            <span style="width:10px;height:10px;border-radius:50%;background:${colors[h.level]||'#9ca3af'};flex-shrink:0;display:inline-block"></span>
            <span style="flex:1;font-size:13px;color:#1E3A8A;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h.hostname}</span>
            <span style="font-size:11px;font-weight:700;color:${colors[h.level]||'#9ca3af'}">${labels[h.level]||'?'}</span>
            <span style="font-size:11px;color:#94a3b8">${h.time}</span>
        </div>
    `).join('');
}

// ─── Animated loading steps ───────────────────────────────────────────────────
const LOADING_STEPS = [
    'Resolving domain...',
    'Checking HTTPS & SSL certificate...',
    'Looking up domain age via WHOIS...',
    'Scanning for blacklisted domains...',
    'Analyzing page content...',
    'Calculating safety score...',
];
let _loadingInterval = null;
function startLoadingSteps() {
    const el = document.getElementById('link_status');
    if (!el) return;
    let i = 0;
    el.innerHTML = `<p style="color:#1E3A8A;margin-top:8px;font-weight:600;font-size:14px">🔍 ${LOADING_STEPS[0]}</p>`;
    _loadingInterval = setInterval(() => {
        i = (i + 1) % LOADING_STEPS.length;
        if (el) el.innerHTML = `<p style="color:#1E3A8A;margin-top:8px;font-weight:600;font-size:14px">🔍 ${LOADING_STEPS[i]}</p>`;
    }, 1800);
}
function stopLoadingSteps() {
    if (_loadingInterval) { clearInterval(_loadingInterval); _loadingInterval = null; }
}

// ─── Safety Score Calculator ──────────────────────────────────────────────────
// Weighted scoring: each check contributes a fixed number of points.
// Unknown (null) checks contribute half their weight as a neutral penalty.
// Final score is clamped to realistic bands per verdict level.
const CHECK_WEIGHTS = {
    'HTTPS':           25,   // Fundamental — no HTTPS is a big red flag
    'SSL Certificate': 20,   // Encryption validity
    'Blacklist':       20,   // Known-bad domain list
    'Domain Age':      15,   // Very new domains are suspicious
    'Reachable':       10,   // Site must respond
    'HTTP Redirect':   5,    // HTTPS → HTTP downgrade
    'Content Scan':    5,    // Suspicious page content
    'Shortened Link':  0,    // Informational only, no score impact
};
const DEFAULT_WEIGHT = 5;   // fallback for any unlisted check label

function calcSafetyScore(checks, level) {
    let earned = 0;
    let possible = 0;

    checks.forEach(ch => {
        const w = CHECK_WEIGHTS[ch.label] ?? DEFAULT_WEIGHT;
        if (w === 0) return; // informational check, skip
        possible += w;
        if (ch.ok === true)  earned += w;
        else if (ch.ok === null) earned += w * 0.5; // uncertain = half credit
        // ch.ok === false → 0 points
    });

    // If no scoreable checks ran, return a neutral score
    if (possible === 0) return 50;

    const raw = Math.round((earned / possible) * 100);

    // Clamp to believable ranges per verdict so the score and badge always agree
    if (level === 'danger') return Math.min(raw, 29);
    if (level === 'hazard') return Math.min(Math.max(raw, 30), 64);
    return Math.max(raw, 65); // safe
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
        // Wipe preview content too so stale buttons/screenshots never survive a URL change
        const pActions = document.getElementById('preview_actions');
        if (pActions) pActions.innerHTML = '';
        const pChecks = document.getElementById('preview_checks');
        if (pChecks) pChecks.innerHTML = '';
        const pTitle = document.getElementById('preview_title');
        if (pTitle) pTitle.textContent = '';
        const pDomain = document.getElementById('preview_domain');
        if (pDomain) pDomain.textContent = '';
    }
    if (input) {
        input.addEventListener('input', () => {
            const cur = input.value.trim();
            if (cur !== _lastValue) { _lastValue = cur; clearResults(); }
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
            safe:   { accent:'#16a34a', icon:'<span style="width:28px;height:28px;border-radius:50%;background:#16a34a;display:inline-block;box-shadow:0 0 10px #16a34a88;flex-shrink:0"></span>', label:'Link Looks Safe' },
            hazard: { accent:'#d97706', icon:'<span style="width:28px;height:28px;border-radius:50%;background:#d97706;display:inline-block;box-shadow:0 0 10px #d9770688;flex-shrink:0"></span>', label:'Potential Warning' },
            danger: { accent:'#dc2626', icon:'<span style="width:28px;height:28px;border-radius:50%;background:#dc2626;display:inline-block;box-shadow:0 0 10px #dc262688;flex-shrink:0"></span>', label:'Dangerous Link' },
        };
        if (!level) level = checks.some(ch=>ch.ok===false)?'hazard':'safe';
        const t = theme[level]||theme.safe;

        const card = document.createElement('div');
        card.style.cssText = 'max-width:580px;margin:16px auto 0;border-radius:10px;background:#ffffff;border:2px solid #1E3A8A;box-shadow:0 4px 14px rgba(30,58,138,.15);overflow:hidden;font-family:inherit;text-align:left;';

        const header = document.createElement('div');
        header.style.cssText = `display:flex;align-items:center;gap:14px;padding:15px 20px;background:#1E3A8A;border-bottom:3px solid ${t.accent};`;
        const resolvedBanner = data.shortened && data.resolvedUrl ? `<div style="margin-top:6px;padding:5px 10px;background:#0f2460;border-radius:6px;font-size:11px;color:#93c5fd;">🔗 Shortened → <span style="color:#fff;font-weight:700;word-break:break-all">${data.resolvedUrl}</span></div>` : '';
        const scoreColor = level==='safe'?'#16a34a':level==='hazard'?'#d97706':'#dc2626';
        const scoreCircle = `<div style="flex-shrink:0;width:52px;height:52px;border-radius:50%;border:3px solid ${scoreColor};display:flex;flex-direction:column;align-items:center;justify-content:center;background:#ffffff11;"><span style="font-size:16px;font-weight:900;color:${scoreColor};line-height:1">${score}</span><span style="font-size:8px;color:#93c5fd;letter-spacing:.5px">SCORE</span></div>`;

        header.innerHTML = `${t.icon}<div style="flex:1;min-width:0"><div style="font-size:18px;font-weight:700;color:#F8FAFC">${t.label}${data.shortened?' <span style="font-size:12px;background:#ffffff22;padding:2px 8px;border-radius:10px;vertical-align:middle">Shortened</span>':''}</div><div style="font-size:12px;color:#93c5fd;margin-top:4px">${reason||''}</div>${resolvedBanner}</div>${scoreCircle}`;
        card.appendChild(header);

        const passed  = checks.filter(c=>c.ok===true).length;
        const failed  = checks.filter(c=>c.ok===false).length;
        const unknown = checks.filter(c=>c.ok===null).length;
        const summary = document.createElement('div');
        summary.style.cssText = 'display:flex;gap:16px;padding:10px 20px;background:#f0f4ff;border-bottom:1px solid #1E3A8A22;font-size:12px;font-weight:700;';
        summary.innerHTML = `<span style="color:#16a34a">✓ ${passed} Passed</span><span style="color:#dc2626">✕ ${failed} Failed</span><span style="color:#9ca3af">? ${unknown} Unknown</span><span style="margin-left:auto;color:#1E3A8A">${checks.length} checks total</span>`;
        card.appendChild(summary);

        if (Array.isArray(fourBadges) && fourBadges.length) {
            const badgeRow = document.createElement('div');
            badgeRow.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 20px;background:#F8FAFC;border-bottom:1px solid #1E3A8A44;';
            const lbl = document.createElement('span');
            lbl.style.cssText = 'font-size:10px;font-weight:800;color:#1E3A8A;text-transform:uppercase;letter-spacing:.8px;margin-right:4px;';
            lbl.textContent = 'Key Checks:';
            badgeRow.appendChild(lbl);
            fourBadges.forEach(b => {
                const bOk=b.ok===true, bNull=b.ok===null;
                const bgCol=bOk?'#1E3A8A':bNull?'#ffffff':'#dc2626';
                const fgCol=bOk?'#ffffff':bNull?'#6b7280':'#ffffff';
                const border=bOk?'#1E3A8A':bNull?'#9ca3af':'#dc2626';
                const ico=bOk?'✓':bNull?'?':'✕';
                const badge=document.createElement('div');
                badge.style.cssText=`display:inline-flex;align-items:center;gap:5px;background:${bgCol};color:${fgCol};border:2px solid ${border};border-radius:6px;padding:4px 11px;font-size:12px;font-weight:700;cursor:default;`;
                badge.innerHTML=`<span style="font-weight:900;font-size:11px">${ico}</span><span>${b.label}</span>`;
                badge.title=b.detail||'';
                badgeRow.appendChild(badge);
            });
            card.appendChild(badgeRow);
        }

        if (Array.isArray(checks) && checks.length) {
            const list = document.createElement('div');
            list.style.cssText = 'padding:12px 20px 16px;display:flex;flex-direction:column;gap:5px;background:#ffffff;';
            checks.forEach(ch => {
                const row=document.createElement('div');
                row.style.cssText='display:flex;align-items:flex-start;gap:10px;border-radius:7px;padding:8px 12px;background:#F8FAFC;border:1px solid #e2e8f0;';
                const dotCol=ch.ok===true?'#16a34a':ch.ok===false?'#dc2626':'#9ca3af';
                const lblCol=ch.ok===true?'#1E3A8A':ch.ok===false?'#dc2626':'#6b7280';
                row.innerHTML=`<span style="width:9px;height:9px;border-radius:50%;background:${dotCol};display:inline-block;margin-top:4px;flex-shrink:0"></span><div><span style="font-weight:700;color:${lblCol};font-size:13px">${ch.label}</span>${ch.detail?`<span style="color:#64748b;font-size:12px;margin-left:6px">— ${ch.detail}</span>`:''}</div>`;
                list.appendChild(row);
            });
            card.appendChild(list);
        }

        statusEl.appendChild(card);
    }

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
        startLoadingSteps();

        let level  = null;
        let reason = 'Could not complete all checks';
        let checks = [];

        let serverData = null;
        try {
            const apiUrl = '/api/check?url=' + encodeURIComponent(normalized);
            console.log('[WebSafe] Calling:', apiUrl);
            const res = await fetch(apiUrl);
            console.log('[WebSafe] API status:', res.status);
            if (res.ok) { const j=await res.json(); if(j&&j.ok) serverData=j; }
            else { console.warn('[WebSafe] API non-OK:', res.status); }
        } catch(e) { console.warn('[WebSafe] API failed:', e.message); }

        if (serverData) {
            const d = serverData;
            if(d.shortened&&d.resolvedUrl) checks.push({label:'Shortened Link',ok:null,detail:`Resolves to: ${d.resolvedUrl}`});
            checks.push({label:'HTTPS',         ok:!!d.httpsOk,        detail:d.httpsOk?'Secure connection':'No HTTPS — data may not be encrypted'});
            checks.push({label:'Reachable',      ok:d.reachable!==false,detail:d.reachable?`HTTP ${d.statusCode||'—'}`:'Site could not be reached'});
            checks.push({label:'SSL Certificate',ok:!!d.certValid,      detail:d.certValid?(d.certExpiresDays!=null?`Expires in ${d.certExpiresDays} days`:'Valid'):'Invalid or missing certificate'});
            checks.push({label:'Blacklist',      ok:!d.blacklisted,     detail:d.blacklisted?'Domain is on our blacklist':'Not found on blacklist'});
            checks.push({label:'HTTP Redirect',  ok:!d.redirectsToHttp, detail:d.redirectsToHttp?'HTTPS redirects to HTTP (downgrade)':'No insecure redirect'});
            if(d.domainAgeDays!=null){
                const ageOk=d.domainAgeDays>=30;
                checks.push({label:'Domain Age',ok:ageOk,detail:ageOk?`${d.domainAgeDays} days old`:`Only ${d.domainAgeDays} days old — very new domain`});
            } else {
                checks.push({label:'Domain Age',ok:null,detail:'Could not retrieve WHOIS data'});
            }
            if(Array.isArray(d.contentFlags)&&d.contentFlags.length){
                const highFlags=d.contentFlags.filter(f=>f.severity==='high');
                checks.push({label:'Content Scan',ok:false,detail:d.contentFlags.map(f=>f.detail||f.type).join('; ')});
                if(highFlags.length){level='danger';reason=highFlags.map(f=>f.detail||f.type).join('; ');}
                else if(level!=='danger'){level='hazard';reason='Suspicious content detected';}
            } else {
                checks.push({label:'Content Scan',ok:true,detail:'No suspicious content found'});
            }
            if(d.blacklisted)           {level='danger';reason='Blacklisted domain';}
            else if(d.reachable===false) {level='danger';reason='Site is not reachable';}
            else if(level==='danger')   {/* already set */}
            else {
                const anyBad=!d.httpsOk||d.redirectsToHttp||!d.certValid||(d.domainAgeDays!=null&&d.domainAgeDays<30);
                if(anyBad)             {level='hazard';reason='One or more security concerns detected';}
                else if(level==='hazard'){/* keep */}
                else                   {level='safe';reason=`All ${checks.filter(c=>c.ok!==null).length} checks passed`;}
            }
        } else {
            let reachable=false;
            try {
                const ctrl=new AbortController();const tid=setTimeout(()=>ctrl.abort(),5000);
                const r=await fetch(normalized,{method:'HEAD',signal:ctrl.signal});
                clearTimeout(tid);reachable=r.ok||r.type==='opaque';
            } catch(e){
                try{
                    const ctrl2=new AbortController();const tid2=setTimeout(()=>ctrl2.abort(),5000);
                    const r2=await fetch(normalized,{method:'GET',signal:ctrl2.signal});
                    clearTimeout(tid2);reachable=r2.ok||r2.type==='opaque';
                } catch(e2){reachable=false;}
            }
            const WELL_KNOWN=['youtube.com','www.youtube.com','google.com','www.google.com','facebook.com','fb.com','twitter.com','x.com','instagram.com','microsoft.com','apple.com','amazon.com','wikipedia.org','linkedin.com','reddit.com','yahoo.com','github.com','www.github.com','github.io','netflix.com','twitch.tv','discord.com','tiktok.com','spotify.com','stackoverflow.com','paypal.com'];
            let hostname='';
            try{hostname=new URL(normalized).hostname.toLowerCase();}catch(e){}
            const isWellKnown=WELL_KNOWN.includes(hostname);
            const httpsOk=normalized.startsWith('https://');
            checks.push({label:'HTTPS',         ok:httpsOk,               detail:httpsOk?'Secure connection':'No HTTPS'});
            checks.push({label:'Reachable',      ok:reachable||isWellKnown,detail:reachable?'Site responded':isWellKnown?'Well-known site':'Could not reach site'});
            checks.push({label:'SSL Certificate',ok:null,detail:'Server check unavailable'});
            checks.push({label:'Blacklist',      ok:null,detail:'Server check unavailable'});
            checks.push({label:'Domain Age',     ok:null,detail:'Server check unavailable'});
            if(!reachable&&!isWellKnown){level='danger';reason='Site not reachable';}
            else if(!httpsOk)           {level='hazard';reason='No HTTPS detected';}
            else                        {level='safe';  reason='Basic checks passed';}
        }

        const score = calcSafetyScore(checks, level);
        const fourBadges = [
            checks.find(c=>c.label==='HTTPS')          ||{label:'HTTPS',      ok:null,detail:''},
            checks.find(c=>c.label==='SSL Certificate') ||{label:'SSL',        ok:null,detail:''},
            checks.find(c=>c.label==='Blacklist')       ||{label:'Blacklist',  ok:null,detail:''},
            checks.find(c=>c.label==='Domain Age')      ||{label:'Domain Age', ok:null,detail:''},
        ];

        stopLoadingSteps();
        renderResultCard({level,reason,checks,fourBadges,score,shortened:!!(serverData&&serverData.shortened),resolvedUrl:serverData&&serverData.resolvedUrl});
        logSafetyReport(normalized,level,reason,checks);
        addToHistory(normalized,level);
        btn.disabled=false;
        hideSpinner();
    }

    if(btn)   btn.addEventListener('click',checkLink);
    if(input) input.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();checkLink();}});
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

    const style=document.createElement('style');
    style.textContent=`@keyframes ws-shimmer{0%{background-position:-600px 0}100%{background-position:600px 0}}.ws-skel{background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);background-size:600px 100%;animation:ws-shimmer 1.4s infinite linear;border-radius:6px;}`;
    document.head.appendChild(style);

    function setPreviewVisible(v){if(previewArea)previewArea.style.display=v?'block':'none';}
    function resetPreviewContent(){
        if(pvTitle)pvTitle.textContent='';if(pvDomain)pvDomain.textContent='';if(pvDesc)pvDesc.textContent='';
        if(pvFavicon){pvFavicon.src='';pvFavicon.style.display='none';}
        if(pvChecks)pvChecks.innerHTML='';if(pvActions)pvActions.innerHTML='';
    }
    function makeBrowserBar(hostname){
        const bar=document.createElement('div');
        bar.style.cssText='background:#1E3A8A;padding:10px 14px;display:flex;align-items:center;gap:8px;';
        bar.innerHTML=`<span style="width:10px;height:10px;border-radius:50%;background:#ffffff44;display:inline-block"></span><span style="width:10px;height:10px;border-radius:50%;background:#ffffff44;display:inline-block"></span><span style="width:10px;height:10px;border-radius:50%;background:#ffffff44;display:inline-block"></span><div style="flex:1;background:#ffffff22;border-radius:20px;padding:5px 14px;margin-left:6px;"><span style="color:#93c5fd;font-size:12px;font-weight:600">${hostname}</span></div>`;
        return bar;
    }
    function makeWrapper(){
        const w=document.createElement('div');
        w.style.cssText='width:100%;max-width:640px;margin:12px auto 0;border:2px solid #1E3A8A;border-radius:10px;overflow:hidden;background:#ffffff;';
        return w;
    }
    function renderSkeleton(container,hostname){
        container.innerHTML='';container.appendChild(makeBrowserBar(hostname));
        const body=document.createElement('div');body.style.cssText='padding:20px;display:flex;flex-direction:column;gap:12px;min-height:280px;';
        const hero=document.createElement('div');hero.className='ws-skel';hero.style.cssText='height:120px;width:100%;';body.appendChild(hero);
        [[100],[80],[90],[60]].forEach(([w])=>{const line=document.createElement('div');line.className='ws-skel';line.style.cssText=`height:14px;width:${w}%;`;body.appendChild(line);});
        const status=document.createElement('p');status.style.cssText='text-align:center;color:#94a3b8;font-size:13px;margin-top:8px;';status.textContent='📸 Taking screenshot… this may take up to 15 seconds';body.appendChild(status);
        container.appendChild(body);
    }
    function tryLoadImage(url,ms){
        return new Promise(resolve=>{
            const img=new Image();const tid=setTimeout(()=>{img.src='';resolve(null);},ms);
            img.onload=()=>{clearTimeout(tid);resolve(img.src);};img.onerror=()=>{clearTimeout(tid);resolve(null);};img.src=url;
        });
    }
    async function getScreenshot(url){
        const enc=encodeURIComponent(url);
        const sources=[`https://image.thum.io/get/width/900/crop/600/noanimate/${url}`,`https://shot.screenshotapi.net/screenshot?url=${enc}&width=1280&height=768&output=image&file_type=png&wait_for_event=load`,`https://mini.s-shot.ru/1024x768/PNG/1024/Z100/?${url}`];
        for(const src of sources){const r=await tryLoadImage(src,10000);if(r)return r;}
        return null;
    }

    previewBtn.addEventListener('click',async()=>{
        const inputEl=document.getElementById('link_input');if(!inputEl)return;
        const normalized=normalizeURL(inputEl.value||'');
        if(!normalized){alert('Please enter a valid URL first.');return;}
        setPreviewVisible(true);resetPreviewContent();showSpinner();
        let hostname='';try{hostname=new URL(normalized).hostname;}catch(e){}
        if(pvDomain)pvDomain.textContent=hostname;
        if(pvActions){
            pvActions.innerHTML='';const wrapper=makeWrapper();pvActions.appendChild(wrapper);
            renderSkeleton(wrapper,hostname);
            const shot=await getScreenshot(normalized);hideSpinner();
            wrapper.innerHTML='';wrapper.appendChild(makeBrowserBar(hostname));
            if(shot){
                const img=document.createElement('img');img.src=shot;img.alt=`Preview of ${hostname}`;img.style.cssText='width:100%;height:auto;display:block;';wrapper.appendChild(img);
            } else {
                const fb=document.createElement('div');fb.style.cssText='padding:50px 20px;text-align:center;';
                fb.innerHTML=`<span style="font-size:48px">🌐</span><p style="color:#1E3A8A;font-weight:700;font-size:16px;margin:12px 0 6px">${hostname}</p><p style="color:#94a3b8;font-size:13px;margin:0">Screenshot unavailable — this site may block preview services</p>`;
                wrapper.appendChild(fb);
            }
            const a=document.createElement('a');a.href=normalized;a.target='_blank';a.rel='noopener noreferrer';a.textContent='🔗 Open in new tab';
            a.style.cssText='display:inline-block;margin:12px 0 4px;padding:9px 20px;background:#1E3A8A;color:#F8FAFC;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;border:2px solid #000;';
            pvActions.appendChild(a);
        }
    });
})();
