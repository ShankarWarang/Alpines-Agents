#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# setup.sh - Idempotent VPS provisioning for Alpines (zkVerify Agent Games)
# Target: Hetzner CPX31 · Ubuntu 22.04 · 4 vCPU · 8 GB RAM
# Run as root:  bash setup.sh
# ------------------------------------------------------------------------------
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[→]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then
  echo "Error: this script must be run as root." >&2
  exit 1
fi

# -- 1. System packages ------------------------------------------------------
warn "Updating system packages …"
apt-get update -qq
apt-get upgrade -y -qq
info "System packages up to date."

# -- 2. Node.js 20.x (NodeSource) --------------------------------------------
if ! command -v node &>/dev/null || ! node -v | grep -q '^v20'; then
  warn "Installing Node.js 20.x …"
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -qq nodejs
  info "Node.js $(node -v) installed."
else
  info "Node.js $(node -v) already present - skipping."
fi

# -- 3. Build dependencies ---------------------------------------------------
DEPS="build-essential cmake git nlohmann-json3-dev libgmp-dev nasm"
warn "Installing build dependencies …"
apt-get install -y -qq $DEPS
info "Build dependencies installed."

# -- 4. Caddy (official apt repo) --------------------------------------------
if ! command -v caddy &>/dev/null; then
  warn "Installing Caddy …"
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  apt-get update -qq
  apt-get install -y -qq caddy
  info "Caddy installed."
else
  info "Caddy already present - skipping."
fi

# -- 5. Rapidsnark -----------------------------------------------------------
if ! command -v rapidsnark &>/dev/null; then
  warn "Building rapidsnark from source …"
  RSNARK_DIR=/tmp/rapidsnark
  rm -rf "$RSNARK_DIR"
  git clone https://github.com/iden3/rapidsnark.git "$RSNARK_DIR"
  cd "$RSNARK_DIR"
  git submodule update --init --recursive
  mkdir -p build && cd build
  cmake .. -DCMAKE_BUILD_TYPE=Release
  cmake --build . --target prover --parallel "$(nproc)"
  cp src/prover /usr/local/bin/rapidsnark
  chmod +x /usr/local/bin/rapidsnark
  cd /
  rm -rf "$RSNARK_DIR"
  info "rapidsnark installed at /usr/local/bin/rapidsnark."
else
  info "rapidsnark already present - skipping."
fi

# -- 6. System user ----------------------------------------------------------
if ! id -u zkverify &>/dev/null; then
  useradd --system --create-home --shell /bin/bash zkverify
  info "User 'zkverify' created."
else
  info "User 'zkverify' already exists - skipping."
fi

# -- 6b. Sudoers - allow zkverify to restart its own services -----------------
SUDOERS_FILE=/etc/sudoers.d/zkverify
if [[ ! -f "$SUDOERS_FILE" ]]; then
  cat > "$SUDOERS_FILE" <<'EOF'
# Allow the zkverify service account to restart its own systemd units
zkverify ALL=(ALL) NOPASSWD: /bin/systemctl restart alpines-keeper
zkverify ALL=(ALL) NOPASSWD: /bin/systemctl restart alpines-stealer
zkverify ALL=(ALL) NOPASSWD: /bin/systemctl stop alpines-keeper
zkverify ALL=(ALL) NOPASSWD: /bin/systemctl stop alpines-stealer
zkverify ALL=(ALL) NOPASSWD: /bin/systemctl start alpines-keeper
zkverify ALL=(ALL) NOPASSWD: /bin/systemctl start alpines-stealer
EOF
  chmod 0440 "$SUDOERS_FILE"
  info "Sudoers entry created for zkverify."
else
  info "Sudoers entry already present - skipping."
fi

# -- 7. Directories ----------------------------------------------------------
mkdir -p /opt/zkverify /var/log/alpines-keeper /var/log/alpines-stealer
info "Directories created."

# -- 8. Ownership -------------------------------------------------------------
chown -R zkverify:zkverify /opt/zkverify /var/log/alpines-keeper /var/log/alpines-stealer
info "Ownership set."

# -- 9. UFW firewall ---------------------------------------------------------
if command -v ufw &>/dev/null; then
  warn "Configuring UFW …"
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp   # SSH
  ufw allow 80/tcp   # HTTP  (Caddy redirect)
  ufw allow 443/tcp  # HTTPS (Caddy)
  ufw --force enable
  info "UFW configured: 22, 80, 443 allowed."
else
  apt-get install -y -qq ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
  info "UFW installed and configured."
fi

# -- 10. Enable & start Caddy ------------------------------------------------
systemctl enable caddy
systemctl restart caddy
info "Caddy enabled and started."

# -- 11. Done -----------------------------------------------------------------
echo ""
echo "================================================================"
echo "  ✅  VPS setup complete!"
echo ""
echo "  Next steps:"
echo "    1. Clone repo → /opt/zkverify"
echo "    2. Copy deploy/Caddyfile → /etc/caddy/Caddyfile"
echo "    3. Copy deploy/*.service → /etc/systemd/system/"
echo "    4. Create /opt/zkverify/.env (see .env.example)"
echo "    5. Download circuit artifacts into circuits/ dirs"
echo "    6. npm install && npm run build"
echo "    7. systemctl daemon-reload"
echo "    8. systemctl enable --now alpines-keeper alpines-stealer"
echo "    9. systemctl restart caddy"
echo "   10. Test: curl https://opendesign.community/alpines_keeper"
echo "================================================================"
