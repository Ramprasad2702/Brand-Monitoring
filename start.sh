#!/usr/bin/env bash
# start.sh — BrandMonitor one-command launcher
cd "$(dirname "$0")"

GREEN="\e[32m"; CYAN="\e[36m"; YELLOW="\e[33m"; BOLD="\e[1m"; RESET="\e[0m"

# Create venv if missing
if [[ ! -d "venv" ]]; then
  echo -e "${YELLOW}First run — setting up...${RESET}"
  python3 -m venv venv
  source venv/bin/activate
  pip install fastapi "uvicorn[standard]" httpx feedparser \
      aiofiles python-dotenv pydantic dnstwist --quiet
else
  source venv/bin/activate
fi

export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"

# Verify core packages
python3 -c "import fastapi, uvicorn, httpx, feedparser" 2>/dev/null || {
  echo -e "${YELLOW}Reinstalling core packages...${RESET}"
  pip install fastapi "uvicorn[standard]" httpx feedparser \
      aiofiles python-dotenv pydantic --quiet
}

echo ""
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}   BrandMonitor v2.0 — Starting                 ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo -e "  Open in Firefox : ${GREEN}http://localhost:8000${RESET}"
echo -e "  Health check    : ${CYAN}http://localhost:8000/health${RESET}"
echo -e "  Stop            : Ctrl+C"
echo ""
echo "  Active modules:"
command -v gitleaks   &>/dev/null \
  && echo -e "  ${GREEN}✓${RESET} Secret scanner        — scans GitHub repos for leaked keys" \
  || echo    "    ✗ Secret scanner        — gitleaks not found"
command -v trufflehog &>/dev/null \
  && echo -e "  ${GREEN}✓${RESET} Credential scanner    — finds verified live credentials" \
  || echo    "    ✗ Credential scanner    — trufflehog not found"
command -v amass      &>/dev/null \
  && echo -e "  ${GREEN}✓${RESET} Subdomain mapper      — full DNS enumeration" \
  || echo -e "  ${CYAN}~${RESET} Subdomain mapper      — using free crt.sh fallback"
python3 -c "import dnstwist" 2>/dev/null \
  && echo -e "  ${GREEN}✓${RESET} Lookalike domains     — detects phishing/typosquat domains" \
  || echo    "    ✗ Lookalike domains     — run: pip install dnstwist"
echo -e "  ${GREEN}✓${RESET} Social monitoring     — Nitter · Reddit · HackerNews"
echo -e "  ${GREEN}✓${RESET} News & media          — Google News RSS · Reddit"
echo -e "  ${GREEN}✓${RESET} OSINT recon           — Shodan · DNS · WHOIS · Paste sites"
echo -e "  ${GREEN}✓${RESET} Infrastructure scan   — crt.sh Certificate Transparency"
echo -e "  ${CYAN}✗${RESET} SpiderFoot            — Docker blocked (not needed, OSINT runs natively)"
echo ""
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo ""

uvicorn brand_monitor:app --host 0.0.0.0 --port 8000 --reload
