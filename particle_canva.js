/* PARTICLE CANVAS */
(function () {
    const canvas = document.getElementById("bg-canvas");
    const ctx = canvas.getContext("2d");
    let W, H, particles = [];
    function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
    resize();
    window.addEventListener("resize", resize);
    const COLORS = ["rgba(29,106,255,","rgba(77,143,255,","rgba(0,212,255,","rgba(10,79,212,","rgba(0,150,220,"];
    function rand(a, b) { return a + Math.random() * (b - a); }
    for (let i = 0; i < 55; i++) {
        particles.push({ x: rand(0, window.innerWidth), y: rand(0, window.innerHeight), r: rand(1, 2.8), dx: rand(-0.2, 0.2), dy: rand(-0.15, 0.15), color: COLORS[Math.floor(Math.random() * COLORS.length)], alpha: rand(0.2, 0.55) });
    }
    function draw() {
        ctx.clearRect(0, 0, W, H);
        particles.forEach(p => {
            ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = p.color + p.alpha + ")"; ctx.fill();
            p.x += p.dx; p.y += p.dy;
            if (p.x < -5) p.x = W + 5; if (p.x > W + 5) p.x = -5;
            if (p.y < -5) p.y = H + 5; if (p.y > H + 5) p.y = -5;
        });
        requestAnimationFrame(draw);
    }
    draw();
})();

/* SCROLL REVEAL */
(function () {
    const obs = new IntersectionObserver((entries) => {
        entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("visible"); obs.unobserve(e.target); } });
    }, { threshold: 0.1 });
    document.querySelectorAll(".reveal, .reveal-left, .reveal-right").forEach(el => obs.observe(el));
})();

/* LOADER */
window.addEventListener("load", () => {
    setTimeout(() => {
        document.getElementById("loader").classList.add("hide");
        document.getElementById("main_content").classList.add("show");
    }, 2000);
});

/* RANDOM GREETING */
const greetings = ["Hello there! Are you ready?","Welcome to WebSafe!","Good to see you again!","Let's get started, Shall we?","Are you ready for another scan?","Let's keep you safe now."];
document.getElementById("dynamic_greeting").textContent = greetings[Math.floor(Math.random() * greetings.length)];

/* THREAT CARD CYCLE */
(function () {
    const cards = document.querySelectorAll(".threat-card");
    let current = 2;
    setInterval(() => {
        cards[current].classList.remove("active");
        current = (current + 1) % cards.length;
        cards[current].classList.add("active");
    }, 3000);
})();

/* SIDEBAR */
const menuToggle   = document.getElementById("menu_toggle");
const sidebarEl    = document.getElementById("sidebar_menu");
const overlayEl    = document.getElementById("sidebar_overlay");
const sidebarClose = document.getElementById("sidebar_close");
function openSidebar()  { sidebarEl.classList.add("active"); overlayEl.classList.add("active"); menuToggle.setAttribute("aria-expanded","true"); menuToggle.style.opacity="0"; menuToggle.style.pointerEvents="none"; syncSidebarHistory(); }
function closeSidebar() { sidebarEl.classList.remove("active"); overlayEl.classList.remove("active"); menuToggle.setAttribute("aria-expanded","false"); menuToggle.style.opacity="1"; menuToggle.style.pointerEvents=""; }
menuToggle.addEventListener("click", openSidebar);
sidebarClose.addEventListener("click", closeSidebar);
overlayEl.addEventListener("click", closeSidebar);
document.querySelectorAll("#sidebar_menu .sidebar-link").forEach(link => {
    link.addEventListener("click", e => {
        const href = link.getAttribute("href");
        if (href && href !== "#") { e.preventDefault(); closeSidebar(); const target = document.querySelector(href); if (target) target.scrollIntoView({ behavior: "smooth", block: "start" }); }
        else { closeSidebar(); }
    });
});
document.getElementById("aboutLink").addEventListener("click", e => { e.preventDefault(); closeSidebar(); window.location.href = "about_us.html"; });
document.getElementById("contactLocalLink").addEventListener("click", e => { e.preventDefault(); closeSidebar(); window.location.href = "contact_local.html"; });

function syncSidebarHistory() {
    const panel = document.getElementById("sidebar_history_list");
    if (!panel) return;
    if (typeof scanHistory === "undefined" || scanHistory.length === 0) { panel.innerHTML = '<p class="sidebar-empty">No scans yet this session</p>'; return; }
    const colors = { safe:"#34d399", hazard:"#fbbf24", danger:"#f87171" };
    const labels = { safe:"Safe", hazard:"Warning", danger:"Danger" };
    panel.innerHTML = "";
    scanHistory.slice(0,5).forEach(h => {
        const row = document.createElement("div"); row.className = "sidebar-scan-row";
        row.innerHTML = `<span class="sidebar-scan-dot" style="background:${colors[h.level]||"#9ca3af"}"></span><span class="sidebar-scan-host"></span><span class="sidebar-scan-badge" style="color:${colors[h.level]||"#9ca3af"}">${labels[h.level]||"?"}</span>`;
        row.querySelector(".sidebar-scan-host").textContent = h.hostname;
        row.addEventListener("click", () => { const inp = document.getElementById("link_input"); if (inp) inp.value = h.url; closeSidebar(); document.getElementById("link_checker").scrollIntoView({ behavior:"smooth" }); checkBtn.click(); });
        panel.appendChild(row);
    });
}
setInterval(syncSidebarHistory, 2000);

/* ELEMENT REFERENCES */
const input       = document.getElementById("link_input");
const checkBtn    = document.getElementById("check_btn");
const previewBtn  = document.getElementById("preview_btn");
const scanBtn     = document.getElementById("scan_qr_btn");
const uploadQrBtn = document.getElementById("upload_qr_btn");
const spinner     = document.getElementById("loading_spinner");
const status      = document.getElementById("safety_status");
const resultBox   = document.getElementById("link_status");
const previewArea    = document.getElementById("preview_area");
const previewTitle   = document.getElementById("preview_title");
const previewDomain  = document.getElementById("preview_domain");
const previewDesc    = document.getElementById("preview_description");
const previewFavicon = document.getElementById("preview_favicon");
const previewActions = document.getElementById("preview_actions");
const previewChecks  = document.getElementById("preview_checks");
const qrModal           = document.getElementById("qr_modal");
const closeQR           = document.getElementById("close_qr");
const startScan         = document.getElementById("start_scan");
const viewfinder        = document.getElementById("qr-viewfinder");
const cameraPlaceholder = document.getElementById("qr-camera-placeholder");
const qrUploadModal    = document.getElementById("qr_upload_modal");
const closeQrUpload    = document.getElementById("close_qr_upload");
const qrDropZone       = document.getElementById("qr_drop_zone");
const qrFileInput      = document.getElementById("qr_file_input");
const qrPreviewWrap    = document.getElementById("qr_preview_wrap");
const qrDropDefault    = document.getElementById("qr_drop_default");
const qrPreviewImg     = document.getElementById("qr_preview_img");
const qrImageName      = document.getElementById("qr_image_name");
const qrUploadScanBtn  = document.getElementById("qr_upload_scan_btn");
const qrUploadClearBtn = document.getElementById("qr_upload_clear_btn");
const qrUploadResult   = document.getElementById("qr_upload_result");
const qrResultIcon     = document.getElementById("qr_result_icon");
const qrResultLabel    = document.getElementById("qr_result_label");
const qrResultUrl      = document.getElementById("qr_result_url");
const qrScanBtnLabel   = document.getElementById("qr_scan_btn_label");
const qrUploadSpinner  = document.getElementById("qr_upload_spinner");
let html5QrCode; let isScanning = false; let uploadedImageData = null;
// check_btn and preview_btn listeners are registered by check_link.js
input.addEventListener("keydown", e => { if (e.key === "Enter") checkBtn.click(); });

/* CAMERA QR MODAL */
scanBtn.onclick = () => { qrModal.classList.remove("hidden"); setTimeout(() => qrModal.classList.add("show"), 10); document.body.style.overflow = "hidden"; };
closeQR.onclick = () => { qrModal.classList.remove("show"); viewfinder.classList.remove("scanning"); setTimeout(() => qrModal.classList.add("hidden"), 300); document.body.style.overflow = ""; if (html5QrCode && isScanning) { html5QrCode.stop().catch(() => {}); isScanning = false; } };
startScan.onclick = async () => {
    if (isScanning) return;
    const ripple = document.createElement("span"); ripple.classList.add("qr-ripple");
    const rect = startScan.getBoundingClientRect(); const size = Math.max(rect.width, rect.height);
    ripple.style.cssText = `width:${size}px;height:${size}px;left:${rect.width/2-size/2}px;top:${rect.height/2-size/2}px`;
    startScan.appendChild(ripple); setTimeout(() => ripple.remove(), 600);
    viewfinder.classList.add("scanning"); html5QrCode = new Html5Qrcode("qr-reader");
    try {
        await html5QrCode.start({ facingMode:"environment" }, { fps:10, qrbox:220 }, (decodedText) => { html5QrCode.stop().catch(() => {}); isScanning = false; viewfinder.classList.remove("scanning"); input.value = decodedText; closeQR.onclick(); checkBtn.click(); });
        isScanning = true;
    } catch { viewfinder.classList.remove("scanning"); alert("Camera error — please allow camera access and try again."); }
};

/* UPLOAD QR MODAL */
uploadQrBtn.onclick = () => { resetUploadModal(); qrUploadModal.classList.remove("hidden"); setTimeout(() => qrUploadModal.classList.add("show"), 10); document.body.style.overflow = "hidden"; };
closeQrUpload.onclick = closeUploadModal;
qrUploadModal.addEventListener("click", e => { if (e.target === qrUploadModal) closeUploadModal(); });
function closeUploadModal() { qrUploadModal.classList.remove("show"); setTimeout(() => qrUploadModal.classList.add("hidden"), 300); document.body.style.overflow = ""; }
function resetUploadModal() { uploadedImageData = null; qrFileInput.value = ""; qrPreviewImg.src = ""; qrImageName.textContent = ""; qrPreviewWrap.classList.remove("visible"); qrDropDefault.style.display = ""; qrUploadScanBtn.disabled = true; qrUploadResult.className = "qr-upload-result"; qrResultIcon.textContent = ""; qrResultLabel.textContent = ""; qrResultUrl.textContent = ""; qrScanBtnLabel.textContent = "Scan & Check Safety"; qrUploadSpinner.classList.remove("active"); }
qrDropZone.addEventListener("click", (e) => { if (e.target.closest("button")) return; qrFileInput.click(); });
qrDropZone.addEventListener("dragover", e => { e.preventDefault(); qrDropZone.classList.add("dragover"); });
qrDropZone.addEventListener("dragleave", () => qrDropZone.classList.remove("dragover"));
qrDropZone.addEventListener("drop", e => { e.preventDefault(); qrDropZone.classList.remove("dragover"); const file = e.dataTransfer.files[0]; if (file && file.type.startsWith("image/")) loadQrFile(file); });
qrFileInput.addEventListener("change", () => { const file = qrFileInput.files[0]; if (file) loadQrFile(file); });
function loadQrFile(file) {
    const reader = new FileReader();
    reader.onload = e => {
        const dataUrl = e.target.result; qrPreviewImg.src = dataUrl; qrImageName.textContent = file.name; qrDropDefault.style.display = "none"; qrPreviewWrap.classList.add("visible"); qrUploadScanBtn.disabled = false; qrUploadResult.className = "qr-upload-result";
        const img = new Image(); img.onload = () => { const canvas = document.createElement("canvas"); canvas.width = img.naturalWidth; canvas.height = img.naturalHeight; const ctx = canvas.getContext("2d"); ctx.drawImage(img, 0, 0); uploadedImageData = ctx.getImageData(0, 0, canvas.width, canvas.height); }; img.src = dataUrl;
    };
    reader.readAsDataURL(file);
}
qrUploadClearBtn.addEventListener("click", resetUploadModal);
qrUploadScanBtn.addEventListener("click", () => {
    if (!uploadedImageData) return;
    qrScanBtnLabel.textContent = "Scanning…"; qrUploadSpinner.classList.add("active"); qrUploadScanBtn.disabled = true; qrUploadResult.className = "qr-upload-result";
    setTimeout(() => {
        const code = jsQR(uploadedImageData.data, uploadedImageData.width, uploadedImageData.height, { inversionAttempts:"dontInvert" });
        qrUploadSpinner.classList.remove("active"); qrScanBtnLabel.textContent = "Scan & Check Safety"; qrUploadScanBtn.disabled = false;
        if (!code) { showUploadResult("error","⚠️","No QR code detected in this image.","Please try a clearer or higher-resolution image.",""); return; }
        const decoded = code.data.trim(); let isUrl = false; try { new URL(decoded); isUrl = true; } catch (_) {}
        if (!isUrl) { showUploadResult("info","ℹ️","QR code decoded (not a URL):",decoded,""); return; }
        // Show a provisional result badge; the full scan runs after the modal closes
        showUploadResult("info","🔍","Link found — scanning…","",decoded);
        input.value = decoded;
        setTimeout(() => { closeUploadModal(); document.getElementById("link_checker").scrollIntoView({ behavior:"smooth" }); checkBtn.click(); }, 1800);
    }, 600);
});
function showUploadResult(type, icon, label, detail, url) { qrResultIcon.textContent = icon; qrResultLabel.innerHTML = `<strong>${label}</strong>${detail?` <br><small style="font-weight:400;opacity:0.8">${detail}</small>`:""}`; qrResultUrl.textContent = url || ""; qrUploadResult.className = `qr-upload-result visible ${type}`; }

/* CHAT WIDGET */
(function () {
    const toggle = document.getElementById("chatToggle"), widget = document.getElementById("chatWidget"), closeBtn = document.getElementById("closeChat"), inputEl = document.getElementById("chatInput"), sendBtn = document.getElementById("chatSendBtn"), messagesEl = document.getElementById("chatMessages"), typingEl = document.getElementById("chatTyping"), quickEl = document.getElementById("chatQuickActions");
    let isOpen = false, conversationHistory = [];
    const SYSTEM_PROMPT = `You are the WebSafe Assistant — a friendly, knowledgeable cybersecurity helper embedded in WebSafe, a Philippine-based URL safety checker tool. Your purpose: Help users understand online threats: phishing, malware, QR code scams, fake websites. Explain how WebSafe works. Guide users on what to do if they encounter a phishing scam, especially in the Philippines. Provide contact info for Philippine cybercrime authorities when relevant: PNP Cybercrime Division: (+632) 724-3660, Globe: 211, Smart: 1511, DICT: onlinecims.ocs@gmail.com. Tone: Friendly, clear, and reassuring. Keep responses concise (2-4 sentences). Do not help with anything unrelated to cybersecurity.`;
    function openChat()  { isOpen = true; widget.classList.add("show"); widget.setAttribute("aria-hidden","false"); toggle.setAttribute("aria-expanded","true"); toggle.classList.add("is-open"); setTimeout(() => inputEl.focus(), 350); }
    function closeChat() { isOpen = false; widget.classList.remove("show"); widget.setAttribute("aria-hidden","true"); toggle.setAttribute("aria-expanded","false"); toggle.classList.remove("is-open"); }
    toggle.addEventListener("click", () => isOpen ? closeChat() : openChat());
    closeBtn.addEventListener("click", closeChat);
    document.querySelectorAll(".quick-action-btn").forEach(btn => { btn.addEventListener("click", () => { const msg = btn.getAttribute("data-msg"); if (msg) sendMessage(msg); }); });
    inputEl.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(inputEl.value.trim()); } });
    sendBtn.addEventListener("click", () => sendMessage(inputEl.value.trim()));
    function sendMessage(text) { if (!text) return; inputEl.value = ""; if (quickEl) quickEl.style.display = "none"; appendMessage("user", text); conversationHistory.push({ role:"user", content:text }); showTyping(); callClaude(); }
    async function callClaude() {
        try {
            const response = await fetch("/api/chat", { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({ system:SYSTEM_PROMPT, messages:conversationHistory }) });
            const data = await response.json();
            hideTyping();
            if (data && data.content && data.content[0]) { const replyText = data.content.filter(b => b.type==="text").map(b => b.text).join("\n"); conversationHistory.push({ role:"assistant", content:replyText }); appendMessage("bot", replyText); }
            else appendMessage("bot", "Sorry, I couldn't get a response. Please try again.");
        } catch { hideTyping(); appendMessage("bot", "Something went wrong connecting to the assistant. Please check your connection and try again."); }
    }
    function appendMessage(role, text) {
        const isBot = role === "bot"; const wrapper = document.createElement("div"); wrapper.className = `chat-msg ${isBot ? "bot-msg" : "user-msg"}`;
        if (isBot) { wrapper.innerHTML = `<div class="msg-avatar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><div class="msg-bubble">${formatMessage(text)}</div>`; }
        else { wrapper.innerHTML = `<div class="msg-bubble">${escapeHtml(text)}</div>`; }
        messagesEl.appendChild(wrapper); scrollToBottom();
    }
    function formatMessage(text) { return escapeHtml(text).replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/\*(.*?)\*/g,'<em>$1</em>').replace(/`(.*?)`/g,'<code style="background:rgba(29,106,255,0.15);padding:1px 5px;border-radius:3px;font-family:\'JetBrains Mono\',monospace;font-size:11px;">$1</code>').replace(/\n\n/g,'</p><p style="margin-top:8px">').replace(/\n/g,'<br>'); }
    function escapeHtml(str) { return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
    function showTyping() { typingEl.style.display = "flex"; typingEl.setAttribute("aria-hidden","false"); scrollToBottom(); }
    function hideTyping() { typingEl.style.display = "none"; typingEl.setAttribute("aria-hidden","true"); }
    function scrollToBottom() { const body = document.getElementById("chatBody"); setTimeout(() => { body.scrollTop = body.scrollHeight; }, 50); }
})();
