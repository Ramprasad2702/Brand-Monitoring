# BrandMonitor v3.0 — Quick Start

## Run now (everything already installed)

```bash
cd ~/Downloads/brandmonitor
bash start.sh
```

Open Firefox → **http://localhost:8000**

---

## What's new in v3.0 — 4 new modules

### 🔍 GitHub Code Search
Searches ALL public GitHub for leaked credentials — not just your org repos.
Finds secrets in forks, personal repos of ex-employees, and third-party integrations.

**Requires:** Add `GITHUB_TOKEN=your_token` to `.env`
Get a free token at: github.com/settings/tokens (no special scopes needed)

### 📱 Social Media Guard
Checks 8 platforms (Twitter, Instagram, LinkedIn, YouTube, Telegram, Facebook, GitHub, Medium)
for unclaimed handles and impersonation accounts.

No API keys needed — uses public profile URLs and Google News RSS.

### 🌑 Dark Web Monitor
Scans paste sites (Pastebin, rentry, hastebin), GitHub Gists, IntelligenceX,
HackerNews, and HaveIBeenPwned for credential dumps and breach data.

**Optional keys for deeper coverage:**
- `HIBP_API_KEY=` — HaveIBeenPwned domain breach lookup (£3.50/mo)
- `INTELX_API_KEY=` — IntelligenceX dark web search (free tier available)
- `GITHUB_TOKEN=` — GitHub Gist search (free, just needs account)

### 📸 Visual Clone Detector
Screenshots lookalike domains found by dnstwist and compares visual similarity
to your real site using perceptual hashing. Catches pixel-perfect clones.

**Install for best results:**
```bash
source venv/bin/activate
pip install playwright imagehash Pillow
playwright install chromium
```
**Without Playwright:** Falls back to HTML text similarity (still works, less accurate).

---

## Complete tool inventory

| Module | What it finds |
|---|---|
| Social Monitoring | Brand mentions, breach announcements, fake account reports |
| News Intelligence | Press coverage, security incidents, vulnerability disclosures |
| Secret Detection | API keys, passwords, tokens in GitHub org repos |
| Deep Credential Scan | Verified live credentials (only confirmed active ones reported) |
| Domain Impersonation | Typosquat, homoglyph, lookalike domains (smart-scored) |
| Infrastructure Mapping | Subdomains, wildcard certs, sensitive services exposed |
| Threat Intelligence | CVEs, DNS misconfig, WHOIS, paste site refs (all free) |
| Custom Scraping | GitHub Gists, StackOverflow configs, dork hints |
| **GitHub Code Search** | **Any public file containing your domain + credentials** |
| **Social Media Guard** | **Unclaimed handles + impersonation accounts** |
| **Dark Web Monitor** | **Paste dumps, breach DBs, dark web mentions** |
| **Visual Clone Detector** | **Pixel-perfect site clones among lookalike domains** |

---

## Scan your college

| Field | Value |
|---|---|
| Brand name | `drmcet` |
| Domain | `drmcet.ac.in` |

Click **▶ SCAN** — all 12 modules run in 5 parallel phases.

---

## Severity guide

| | Severity | Action |
|---|---|---|
| 🔴 | CRITICAL | Fix within hours — active threat |
| 🟡 | WARNING | Review within 24h |
| 🔵 | INFO | Background intelligence |
| 🟢 | OK | Check passed, no action needed |
