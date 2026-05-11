# BrandMonitor

A self-hosted brand monitoring & threat intelligence tool for Kali Linux.
Open `http://localhost:8000` — the dashboard is served directly by the backend (no CORS issues).

## Tools Integrated

| Tool | Purpose | Status |
|---|---|---|
| snscrape | Twitter/X mention scraping (replaces twint on Python 3.13) | Python module |
| RSS-Bridge | News & forum feeds | Python module |
| GitLeaks | GitHub secret scanning | Binary → `~/.local/bin` |
| TruffleHog | Deep credential scanning | Binary → `~/.local/bin` |
| dnstwist | Lookalike domain detection | Python module |
| Amass | Subdomain enumeration | Binary → `~/.local/bin` (crt.sh fallback) |
| SpiderFoot | Full OSINT automation | Docker (HIBP+Shodan fallback) |
| Scrapy | Custom spiders (optional) | Python module |

## Quick Start

```bash
# 1. Setup (first time only)
bash setup.sh

# 2. Start
bash start.sh

# 3. Open browser
http://localhost:8000
```

## Manual Start

```bash
source venv/bin/activate
uvicorn brand_monitor:app --host 0.0.0.0 --port 8000 --reload
```

## Fix Missing Tools

If `/health` shows tools as missing:
```bash
source venv/bin/activate
bash fix_missing.sh
```

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/health` | GET | Tool availability |
| `/scan/start` | POST | Start a new scan |
| `/scan/{id}` | GET | Poll scan state |
| `/scan/{id}/stream` | GET | SSE live log stream |
| `/scan/{id}/findings` | GET | Findings (filterable by severity) |
| `/scans` | GET | List all scans |

## Example Scan via curl

```bash
curl -X POST http://localhost:8000/scan/start \
  -H "Content-Type: application/json" \
  -d '{"brand": "psgtech", "domain": "psgtech.ac.in"}'
```

## Optional API Keys (.env)

| Key | Source | What it unlocks |
|---|---|---|
| `GITHUB_TOKEN` | github.com/settings/tokens | 5000 req/hr (vs 60) |
| `HIBP_API_KEY` | haveibeenpwned.com/API/Key | Domain breach lookup |
| `HUNTER_API_KEY` | hunter.io/api-keys | Email discovery (25 free/mo) |

## Project Structure

```
brandmonitor/
├── brand_monitor.py    ← FastAPI backend + embedded dashboard
├── requirements.txt    ← Python dependencies
├── setup.sh            ← First-time installer
├── start.sh            ← Daily launcher
├── fix_missing.sh      ← Fix missing Python modules
├── .env.example        ← Config template
├── .env                ← Your config (created by setup.sh)
└── results/            ← Scan JSON output files
```
