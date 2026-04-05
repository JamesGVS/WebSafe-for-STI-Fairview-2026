# WebSafe (local)

This workspace contains a small static UI (`main.html`, `main.css`, `check_link.js`) and an optional Node.js server (`server.js`) that provides reliable fetching and WHOIS lookups to avoid CORS limitations.

Why the server
- Browsers block cross-origin HTML fetches for many sites (CORS). The client attempts a public proxy (AllOrigins) first, then falls back to the local server when available.
- The server can perform WHOIS domain age lookups and more authoritative blacklist checks.

Quick start (Windows / PowerShell) DEVELOPER ONLY! NOT USERS!

1. Install dependencies:

```powershell
cd "c:\Users\james\OneDrive\Desktop\CODING MATERIAL\HTML CODES\websafe"
npm install
```

2. Run the server:

```powershell
npm start
```

3. Open the site in your browser:

http://localhost:3000/main.html

Notes and limitations
- The server uses `whois-json` which performs network WHOIS lookups; WHOIS availability depends on registrars and network.
- The local server is optional; the client will try public proxy first but it may fail for some sites.
- For production, use a hardened server, rate-limiting, and vetted blacklists.

Files:
- `server.js` -- Express server with `/api/fetch`, `/api/whois`, and `/api/check` endpoints.
- `package.json` -- lists runtime dependencies.

TODO:
- Add a richer blacklist (file or remote API),
- Add rate-limiting and caching to the server,
- Provide a small `dockerfile` to containerize the server.
