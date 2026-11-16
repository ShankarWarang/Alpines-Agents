#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# deploy.sh - Pull, build, and restart Alpines services
# Run from the VPS as zkverify (or root).
# ------------------------------------------------------------------------------
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PROJECT_DIR="/opt/zkverify"

info() { echo -e "${GREEN}[✓]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }

cd "$PROJECT_DIR"
info "Working directory: $PROJECT_DIR"

# -- 1. Pull latest code -----------------------------------------------------
echo ""
echo "-- Pulling latest code --"
git pull origin main
info "Code updated."

# -- 2. Install dependencies -------------------------------------------------
echo ""
echo "-- Installing dependencies --"
npm install
info "Dependencies installed."

# -- 3. Build -----------------------------------------------------------------
echo ""
echo "-- Building --"
npm run build
info "Build succeeded."

# -- 4. Restart services -----------------------------------------------------
echo ""
echo "-- Restarting services --"
sudo systemctl restart alpines-keeper
info "alpines-keeper restarted."

sudo systemctl restart alpines-stealer
info "alpines-stealer restarted."

# -- 5. Health check ----------------------------------------------------------
echo ""
echo "-- Checking service status (waiting 3s) --"
sleep 3

KEEPER_STATUS=$(systemctl is-active alpines-keeper 2>/dev/null || true)
STEALER_STATUS=$(systemctl is-active alpines-stealer 2>/dev/null || true)

if [[ "$KEEPER_STATUS" == "active" ]]; then
  info "alpines-keeper: active ✓"
else
  err "alpines-keeper: $KEEPER_STATUS ✗"
fi

if [[ "$STEALER_STATUS" == "active" ]]; then
  info "alpines-stealer: active ✓"
else
  err "alpines-stealer: $STEALER_STATUS ✗"
fi

# -- 6. Endpoints -------------------------------------------------------------
echo ""
echo "================================================================"
echo "  🏔️  Deployment complete!"
echo ""
echo "  Endpoints:"
echo "    Keeper  → https://opendesign.community/alpines_keeper"
echo "    Stealer → https://opendesign.community/alpines_stealer"
echo "    Landing → https://opendesign.community/"
echo "================================================================"
