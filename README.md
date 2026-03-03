<p align="center">
  <img src="frontend/logo/logo.png" alt="pRoxy" width="120">
</p>

<h1 align="center">pRoxy</h1>

<p align="center">
  A web-based MITM proxy with a real-time dashboard for intercepting, inspecting, and modifying HTTP/HTTPS traffic.
</p>

---

## Features

**Traffic Capture & Inspection**
- Live HTTP/HTTPS traffic streaming via WebSocket
- Request/response detail viewer with headers and body
- Full-text and regex search across captured flows
- HAR export/import for sharing and analysis
- cURL command generation from any captured request

**Request Modification**
- Header injection and removal (request & response phase)
- Body content replacement with regex support
- Mock rules — return custom responses without hitting the server
- Map Local — serve local files instead of remote resources
- Map Remote — rewrite URLs to different endpoints

**Intercept & Replay**
- Breakpoint rules to pause and edit requests/responses in-flight
- HTTP request replay (Repeater) for manual testing

**DNS**
- DNS-over-HTTPS (DoH) resolution
- Domain blocklist (returns 403)
- Custom hostname-to-IP mappings

**Security Header Control**
- Strip HSTS, HPKP, Expect-CT, CSP headers
- Inject CORS bypass headers
- Force SSL upgrade (http to https)

**Certificate Management**
- Auto-generated CA certificate on first run
- Download CA cert in PEM, CRT, and Android system formats
- View certificate fingerprint and validity dates
- Regenerate CA certificate from the dashboard
- Platform-specific installation guides (Linux, macOS, Windows, Firefox, Android, iOS)

**Upstream Proxy**
- HTTP/HTTPS upstream proxy support
- SOCKS5 upstream proxy support

## Quick Start

```bash
# Clone
git clone https://github.com/your-username/pRoxy.git
cd pRoxy

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

The proxy starts on port **8080** and the dashboard on port **8081**.
Open `http://localhost:8081` in your browser.

Configure your browser or device to use `localhost:8080` as the HTTP/HTTPS proxy.
Install the CA certificate from the **Cert** tab to intercept HTTPS traffic.

## Configuration

Proxy settings are configurable from the dashboard **Settings** tab and persisted to `~/.pRoxy/settings.json`.

| Setting | Description |
|---------|-------------|
| Upstream Proxy | HTTP, HTTPS, or SOCKS5 proxy to chain through |
| Strip HSTS | Remove Strict-Transport-Security headers |
| Strip CSP | Remove Content-Security-Policy headers |
| CORS Bypass | Inject permissive CORS headers |
| Force SSL | Upgrade HTTP requests to HTTPS |
| Custom User-Agent | Override User-Agent header on all requests |

DNS settings are persisted to `~/.pRoxy/dns.json`.

## Tech Stack

- **Proxy Engine:** [mitmproxy](https://mitmproxy.org/) — MITM proxy core
- **Backend API:** [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/)
- **Frontend:** Vanilla JavaScript + [Tailwind CSS](https://tailwindcss.com/)
- **Real-time:** WebSocket for live traffic streaming

## Project Structure

```
pRoxy/
├── main.py                 # Entry point
├── requirements.txt        # Python dependencies
├── api/
│   ├── server.py           # FastAPI app + router registration
│   └── routes/
│       ├── cert.py         # CA cert download + info + regenerate
│       ├── dns.py          # DNS settings
│       ├── flows.py        # Traffic flows (list, search, export)
│       ├── intercept.py    # Request/response interception
│       ├── replay.py       # HTTP request replay
│       ├── settings.py     # Proxy settings
│       └── ws.py           # WebSocket real-time updates
├── proxy/
│   ├── addon.py            # mitmproxy addon (traffic hooks + rules)
│   ├── ca.py               # CA certificate management
│   └── engine.py           # Proxy server startup
├── state/
│   ├── models.py           # Pydantic data models
│   └── shared.py           # Thread-safe state singleton
└── frontend/
    ├── index.html           # Main HTML shell
    ├── app.js               # Tab router + WebSocket client
    ├── components/          # Reusable UI components
    └── tabs/                # Feature tabs (traffic, rules, dns, etc.)
```

## License

[MIT](LICENSE)
