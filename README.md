# WebSafe v8

A production-ready URL safety checker. Paste any link to get an instant threat assessment backed by four external intelligence APIs.

---

## Threat Intelligence APIs

| API | Purpose | Free Tier |
|---|---|---|
| **Google Safe Browsing v4** | General phishing & malware | Unlimited (non-commercial) |
| **VirusTotal** | Multi-engine antivirus scan | ~500 req/day |
| **urlscan.io** | Visual sandbox analysis | ~5 000 scans/day |
| **CheckPhish** | Brand impersonation detection | ~250 scans/month |

All API keys are **optional** — WebSafe degrades gracefully if any key is missing.

---

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Set environment variables

```bash
cp .env.example .env
# Edit .env and add your API keys
```

### 3. Run

```bash
npm start
```

Open http://localhost:3000

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GSB_KEY` | Optional | Google Safe Browsing v4 key |
| `VT_KEY` | Optional | VirusTotal Public API key |
| `URLSCAN_KEY` | Optional | urlscan.io API key |
| `CHECKPHISH_KEY` | Optional | CheckPhish API key |
| `ANTHROPIC_API_KEY` | Optional | Claude chat assistant key |
| `PORT` | Optional | Server port (default: 3000) |
| `ALLOWED_ORIGINS` | Optional | Comma-separated CORS origins |

**Never hardcode keys.** Never commit `.env` to source control.

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/check?url=` | GET | Full safety check |
| `/api/fetch?url=` | GET | Fetch page HTML for preview |
| `/api/whois?domain=` | GET | WHOIS / domain age lookup |
| `/api/chat` | POST | Claude chat assistant proxy |
| `/api/status` | GET | Server health + API key status |

---

## Security Features

- All API keys are read from environment variables only
- Static file allowlist — `server.js` and other source files are never served
- Rate limiting: 20 requests per IP per minute
- CORS allowlist
- Strict security headers (CSP, X-Frame-Options, etc.)
- Request body size limit (64 KB)
- Chat message sanitisation + hard cap (20 messages)

---

## Production Deployment (Render / Railway / Fly.io)

1. Push your code (`.env` is gitignored — set vars in the platform dashboard)
2. Set `NODE_ENV=production`
3. Set your API keys as environment variables in the platform
4. Set `ALLOWED_ORIGINS` to your production domain
5. `npm start`

---

## Files

| File | Purpose |
|---|---|
| `server.js` | Express server, all API integrations, scoring engine |
| `main.html` | Main UI |
| `main.css` | Main styles |
| `check_link.js` | Client-side scan module |
| `tld_list.js` | IANA TLD list for URL validation |
| `about_us.html/css` | About page |
| `contact_local.html/css` | Contact authorities page |
| `.env.example` | Key template (copy to `.env`) |
| `.gitignore` | Prevents `.env` and `node_modules` from being committed |

---

© 2026 WebSafe — STI College Fairview
