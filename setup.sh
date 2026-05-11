#!/usr/bin/env bash
# setup.sh — BrandMonitor complete setup for Kali Linux (Python 3.13)
set -e
cd "$(dirname "$0")"

BOLD="\e[1m"; GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; CYAN="\e[36m"; RESET="\e[0m"
ok()   { echo -e "${GREEN}  ✓ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
fail() { echo -e "${RED}  ✗ $*${RESET}"; }
info() { echo -e "${CYAN}  → $*${RESET}"; }

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
export PATH="$INSTALL_DIR:$PATH"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [[ -f "$rc" ]] && grep -q "\.local/bin" "$rc" 2>/dev/null || \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
done

echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}   BrandMonitor — Kali Linux Setup              ${RESET}"
echo -e "${BOLD}   $(python3 --version 2>&1)                    ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"

# ── [1] Virtual environment ───────────────────────────────────────────────────
echo -e "\n${BOLD}[1/7] Virtual Environment${RESET}"
if [[ -d "venv" ]]; then
  ok "venv already exists"
else
  python3 -m venv venv
  ok "venv created"
fi
source venv/bin/activate
ok "venv activated: $VIRTUAL_ENV"
pip install --upgrade pip --quiet

# ── [2] Python dependencies ───────────────────────────────────────────────────
echo -e "\n${BOLD}[2/7] Python Dependencies${RESET}"
pip install fastapi "uvicorn[standard]" httpx feedparser \
    aiofiles python-dotenv pydantic --quiet
ok "fastapi uvicorn httpx feedparser aiofiles python-dotenv pydantic"

pip install dnstwist --quiet 2>/dev/null && ok "dnstwist" || warn "dnstwist failed — try: pip install dnstwist"

# snscrape is dead on PyPI — skip silently, tool uses httpx instead
ok "social scraping (Nitter·Reddit·HN via httpx — no snscrape needed)"

# scrapy optional
pip install scrapy --quiet 2>/dev/null && ok "scrapy (optional)" || info "scrapy skipped (optional — tool works without it)"

# ── [3] TruffleHog binary ─────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/7] TruffleHog${RESET}"
if command -v trufflehog &>/dev/null; then
  ok "trufflehog already installed: $(trufflehog --version 2>&1 | head -1)"
else
  ARCH="$(uname -m)"; [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"; [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
  TH_VER="3.78.0"
  info "Downloading TruffleHog $TH_VER..."
  curl -sSfL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_linux_${ARCH}.tar.gz" \
    -o /tmp/trufflehog.tar.gz 2>/dev/null \
    && tar -xzf /tmp/trufflehog.tar.gz -C "$INSTALL_DIR" trufflehog \
    && chmod +x "$INSTALL_DIR/trufflehog" \
    && ok "trufflehog installed → $INSTALL_DIR/trufflehog" \
    || warn "trufflehog download failed — credential scanning will be skipped"
fi

# ── [4] GitLeaks binary ───────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/7] GitLeaks${RESET}"
if command -v gitleaks &>/dev/null; then
  ok "gitleaks already installed: $(gitleaks version 2>&1)"
else
  ARCH="$(uname -m)"; [[ "$ARCH" == "x86_64" ]] && GL_ARCH="x64"; [[ "$ARCH" == "aarch64" ]] && GL_ARCH="arm64"
  GL_VER="8.18.4"
  info "Downloading GitLeaks $GL_VER..."
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_${GL_ARCH}.tar.gz" \
    -o /tmp/gitleaks.tar.gz 2>/dev/null \
    && tar -xzf /tmp/gitleaks.tar.gz -C "$INSTALL_DIR" gitleaks \
    && chmod +x "$INSTALL_DIR/gitleaks" \
    && ok "gitleaks installed → $INSTALL_DIR/gitleaks" \
    || warn "gitleaks download failed — secret scanning will be skipped"
fi

# ── [5] Amass ─────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/7] Amass${RESET}"
if command -v amass &>/dev/null; then
  ok "amass already installed"
else
  if sudo apt-get install -y amass -qq 2>/dev/null; then
    ok "amass installed via apt"
  else
    warn "amass not available — crt.sh Certificate Transparency will be used instead (same data, free)"
  fi
fi

# ── [6] SpiderFoot ────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[6/7] SpiderFoot${RESET}"
ok "SpiderFoot NOT required — OSINT module runs these for free without Docker:"
info "Shodan InternetDB  — CVEs and open ports on your IP"
info "DNS analysis       — SPF, DMARC, MX, NS, TXT records"  
info "WHOIS / RDAP       — domain age, registrar, expiry date"
info "Paste site scan    — credential dump detection"
info "Google dork hints  — exposed admin panels and files"

# ── [7] Config ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[7/7] Config${RESET}"
if [[ ! -f ".env" ]]; then
  cp .env.example .env
  ok ".env created from .env.example"
  info "Optional: add GITHUB_TOKEN to .env for higher GitHub API rate limits"
else
  ok ".env already exists"
fi
mkdir -p results
ok "results/ directory ready"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}   Installation Summary                         ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"

source venv/bin/activate
check_bin() { command -v "$1" &>/dev/null && ok "$1" || warn "$1 not found (optional)"; }
check_mod() { python3 -c "import $1" 2>/dev/null && ok "$1 (Python module)" || warn "$1 not installed"; }

check_bin uvicorn
check_bin gitleaks
check_bin trufflehog
check_bin amass
check_mod dnstwist
check_mod feedparser
check_mod fastapi

echo ""
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}   START THE TOOL                               ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo -e ""
echo -e "  ${CYAN}bash start.sh${RESET}"
echo -e ""
echo -e "  Then open: ${GREEN}http://localhost:8000${RESET}"
echo -e ""
