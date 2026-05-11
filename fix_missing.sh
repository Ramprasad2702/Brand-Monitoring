#!/usr/bin/env bash
# fix_missing.sh — installs all optional modules for BrandMonitor v3
# Run inside venv: source venv/bin/activate && bash fix_missing.sh
set -e
GREEN="\e[32m"; YELLOW="\e[33m"; RESET="\e[0m"
ok()   { echo -e "${GREEN}  ✓ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }

echo "Installing optional BrandMonitor v3 modules..."
echo ""

echo "→ Core (dnstwist, imagehash, Pillow)"
pip install dnstwist imagehash Pillow --quiet \
  && ok "dnstwist, imagehash, Pillow" \
  || warn "Some packages failed"

echo "→ Playwright (visual phishing screenshots)"
pip install playwright --quiet \
  && playwright install chromium --with-deps 2>/dev/null \
  && ok "playwright + chromium" \
  || warn "playwright failed — visual phishing will use text similarity fallback"

echo ""
echo "Verification:"
python3 -c "import dnstwist; print('  ✓ dnstwist', dnstwist.__version__)" 2>/dev/null || warn "dnstwist"
python3 -c "import imagehash; print('  ✓ imagehash')" 2>/dev/null || warn "imagehash"
python3 -c "import PIL; print('  ✓ Pillow')" 2>/dev/null || warn "Pillow"
python3 -c "import playwright; print('  ✓ playwright')" 2>/dev/null || warn "playwright (visual phishing fallback active)"

echo ""
echo "Done. Restart uvicorn: bash start.sh"
