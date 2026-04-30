@echo off
:: WebSafe v8 — Windows quick start
:: ─────────────────────────────────────────────────────────
:: Set your API keys below OR use a .env file.
:: NEVER commit this file with real keys filled in.
:: ─────────────────────────────────────────────────────────

:: Optional: set keys here for local dev only
:: set GSB_KEY=your_google_safe_browsing_key
:: set VT_KEY=your_virustotal_key
:: set URLSCAN_KEY=your_urlscan_key
:: set CHECKPHISH_KEY=your_checkphish_key
:: set ANTHROPIC_API_KEY=your_anthropic_key

cd /d "%~dp0"
call npm install
call npm start
pause
