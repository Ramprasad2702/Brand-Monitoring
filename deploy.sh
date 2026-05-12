#!/usr/bin/env bash
# deploy.sh — clean deploy, clears cache, verifies new file, starts server
cd "$(dirname "$0")"

RED="\e[31m"; GREEN="\e[32m"; CYAN="\e[36m"; YELLOW="\e[33m"; BOLD="\e[1m"; RESET="\e[0m"

echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "${BOLD}  BrandMonitor v3.0 — Clean Deploy      ${RESET}"
echo -e "${BOLD}════════════════════════════════════════${RESET}"

# Step 1: Kill any running uvicorn
echo -e "\n${CYAN}[1/5] Stopping any running uvicorn...${RESET}"
pkill -f "uvicorn brand_monitor" 2>/dev/null && echo "  Stopped." || echo "  (none running)"
sleep 1

# Step 2: Delete Python cache — THIS is why old version was served
echo -e "${CYAN}[2/5] Clearing Python cache...${RESET}"
rm -rf __pycache__ .pytest_cache
find . -name "*.pyc" -delete 2>/dev/null
echo -e "  ${GREEN}✓ Cache cleared${RESET}"

# Step 3: Verify brand_monitor.py is v3
echo -e "${CYAN}[3/5] Verifying brand_monitor.py is v3...${RESET}"
if [[ ! -f "brand_monitor.py" ]]; then
  echo -e "  ${RED}✗ brand_monitor.py not found!${RESET}"
  echo -e "  Download brand_monitor_v3.py and rename it:"
  echo -e "  ${YELLOW}mv brand_monitor_v3.py brand_monitor.py${RESET}"
  exit 1
fi

LINES=$(python3 -c "print(open('brand_monitor.py').read().count(chr(10)))")
HAS_V3=$(python3 -c "src=open('brand_monitor.py').read(); print('YES' if 'github_code' in src and 'social_protect' in src and 'run_darkweb' in src else 'NO')")

echo -e "  File: brand_monitor.py ($LINES lines)"
if [[ "$HAS_V3" == "YES" ]]; then
  echo -e "  ${GREEN}✓ v3 features confirmed (GitHub Code Search, Social Guard, Dark Web, Visual Clones)${RESET}"
else
  echo -e "  ${RED}✗ This is NOT v3 — still has old code!${RESET}"
  echo -e "  Download brand_monitor_v3.py and run:"
  echo -e "  ${YELLOW}cp ~/Downloads/brand_monitor_v3.py brand_monitor.py && bash deploy.sh${RESET}"
  exit 1
fi

# Step 4: Activate venv and install any missing packages
echo -e "${CYAN}[4/5] Checking dependencies...${RESET}"
if [[ ! -d "venv" ]]; then
  echo "  Creating venv..."
  python3 -m venv venv
fi
source venv/bin/activate
python -m pip install --upgrade pip
pip install fastapi "uvicorn[standard]" httpx feedparser aiofiles python-dotenv pydantic dnstwist
echo -e "  ${GREEN}✓ Dependencies OK${RESET}"

# Step 5: Start with clean state
echo -e "${CYAN}[5/5] Starting BrandMonitor v3...${RESET}"
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "  Dashboard: ${GREEN}http://localhost:8000${RESET}"
echo -e "  Press ${YELLOW}Ctrl+Shift+R${RESET} in Firefox to hard-refresh"
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}v3 modules active:${RESET}"
echo -e "  ${GREEN}✓${RESET} Social Monitoring (Nitter·Reddit·HN)"
echo -e "  ${GREEN}✓${RESET} Secret Detection (GitLeaks)"
echo -e "  ${GREEN}✓${RESET} Deep Credential Scan (TruffleHog)"
echo -e "  ${GREEN}✓${RESET} Domain Impersonation (dnstwist)"
echo -e "  ${GREEN}✓${RESET} Infrastructure Mapping (amass+crt.sh)"
echo -e "  ${GREEN}✓${RESET} Threat Intelligence (Shodan·DNS·WHOIS)"
echo -e "  ${GREEN}✓${RESET} Custom Scraping (Gists·StackOverflow)"
echo -e "  ${GREEN}✓${RESET} ${BOLD}[NEW] GitHub Code Search${RESET}"
echo -e "  ${GREEN}✓${RESET} ${BOLD}[NEW] Social Media Guard${RESET}"
echo -e "  ${GREEN}✓${RESET} ${BOLD}[NEW] Dark Web Monitor${RESET}"
echo -e "  ${GREEN}✓${RESET} ${BOLD}[NEW] Visual Clone Detector${RESET}"
echo ""

echo "Deployment preparation complete."
