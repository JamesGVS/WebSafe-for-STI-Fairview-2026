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
:: set GEMINI_API_KEY=your_gemini_key

cd /d "%~dp0"

:: Auto-create .env from env.example if .env doesn't exist yet
if not exist ".env" (
    if exist "env.example" (
        copy "env.example" ".env" >nul
        echo [setup] Created .env from env.example
    )
)

call npm install
call npm start
pause
