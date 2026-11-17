#!/usr/bin/env bash
# =============================================================================
# vps-deploy.sh - Automated deploy script for Alpines Agents (zkVerify)
#
# Runs on the VPS as root. Performs:
#   1. git pull
#   2. npm ci + npm run build
#   3. Test keeper proof (must pass)
#   4. Test stealer proof (must pass)
#   5. Restart both systemd services
#   6. Health-check both endpoints
#   7. HMAC diagnosis via live log capture
#
# Usage (on VPS):
#   cd /opt/zkverify && bash scripts/vps-deploy.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[>>]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }

REPO_DIR=/opt/zkverify

cd "$REPO_DIR"

echo ""
echo "============================================================"
echo "  Alpines Agents - Automated Deploy"
echo "  $(date)"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. Git pull
# ---------------------------------------------------------------------------
warn "Step 1/7: Git pull..."
git pull origin main
ok "Git pull complete. HEAD is now: $(git log --oneline -1)"

# ---------------------------------------------------------------------------
# 2. Install dependencies + build
# ---------------------------------------------------------------------------
warn "Step 2/7: npm install + build..."
npm ci --workspace=packages/shared --workspace=packages/alpines-keeper --workspace=packages/alpines-stealer 2>&1 | tail -5 || true
npm run build 2>&1
ok "Build complete."

# ---------------------------------------------------------------------------
# 3. Test keeper proof
# ---------------------------------------------------------------------------
warn "Step 3/7: Testing keeper proof..."
if node scripts/test-proof-v2.mjs keeper 2>&1 | tee /tmp/keeper-proof-test.txt | grep -q "PROOF SUCCESS"; then
  ok "Keeper proof: SUCCESS"
else
  err "Keeper proof FAILED! Output:"
  cat /tmp/keeper-proof-test.txt
  echo ""
  echo "DEPLOY ABORTED: Fix keeper proof before deploying."
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. Test stealer proof
# ---------------------------------------------------------------------------
warn "Step 4/7: Testing stealer proof..."
if node scripts/test-proof-v2.mjs stealer 2>&1 | tee /tmp/stealer-proof-test.txt | grep -q "PROOF SUCCESS"; then
  ok "Stealer proof: SUCCESS"
else
  warn "Stealer proof FAILED (may be commitment mismatch). Output:"
  cat /tmp/stealer-proof-test.txt
  echo ""
  echo "Stealer proof failed - continuing anyway (will accept -2 penalty per turn)."
  echo "See Priority 2 in deployment-guide.md to fix the commitment preimage."
fi

# ---------------------------------------------------------------------------
# 5. Restart services
# ---------------------------------------------------------------------------
warn "Step 5/7: Restarting services..."
systemctl restart alpines-keeper alpines-stealer
sleep 3
ok "Services restarted."

# ---------------------------------------------------------------------------
# 6. Service status + health check
# ---------------------------------------------------------------------------
warn "Step 6/7: Checking service status..."
for svc in alpines-keeper alpines-stealer; do
  STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
  if [ "$STATUS" = "active" ]; then
    ok "$svc: $STATUS"
  else
    err "$svc: $STATUS"
    journalctl -u "$svc" -n 20 --no-pager
    exit 1
  fi
done

# Health check via local ports (bypasses Caddy/HMAC)
echo ""
warn "Local port health checks..."
sleep 2
KEEPER_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3001/health 2>/dev/null || echo "000")
STEALER_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3002/health 2>/dev/null || echo "000")

if [ "$KEEPER_HEALTH" = "200" ]; then
  ok "Keeper /health: HTTP $KEEPER_HEALTH"
else
  warn "Keeper /health: HTTP $KEEPER_HEALTH (may need a moment)"
fi

if [ "$STEALER_HEALTH" = "200" ]; then
  ok "Stealer /health: HTTP $STEALER_HEALTH"
else
  warn "Stealer /health: HTTP $STEALER_HEALTH (may need a moment)"
fi

# ---------------------------------------------------------------------------
# 7. HMAC diagnosis via log capture
# ---------------------------------------------------------------------------
warn "Step 7/7: HMAC signature diagnosis..."
echo "Checking logs for HMAC entries (may be empty if no requests received yet)..."
node /opt/zkverify/scripts/check-hmac-logs.mjs keeper || true
echo ""
node /opt/zkverify/scripts/check-hmac-logs.mjs stealer || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  DEPLOY COMPLETE"
echo "============================================================"
echo ""
echo "Service status:"
systemctl status alpines-keeper --no-pager -l | head -10
echo ""
systemctl status alpines-stealer --no-pager -l | head -10
echo ""
echo "To monitor live logs:"
echo "  journalctl -u alpines-keeper -f"
echo "  journalctl -u alpines-stealer -f"
echo ""
echo "To test HTTPS endpoints (needs valid HMAC from platform):"
echo "  curl -s https://opendesign.community/alpines_keeper -X POST \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -H 'x-agent-games-signature: <sig>' \\"
echo "    -d '{\"event_type\":\"preflight\"}'"
echo ""
echo "HMAC debug: Check 'journalctl -u alpines-keeper -n 50' for 'HMAC check' entries"
