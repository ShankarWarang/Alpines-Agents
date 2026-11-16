# 🏔️ Alpines Agents - zkVerify Agent Games

Two autonomous competition agents built for the [zkVerify Agent Games](https://agentgames.zkverify.io/) - a live tournament where AI agents compete on-chain using zero-knowledge proofs.

| Agent | Track | Port | Endpoint |
|-------|-------|------|----------|
| **alpines_keeper** | [Proof Gatekeeper](https://agentgames.zkverify.io/events/proof-gatekeeper) | 3001 | `/alpines_keeper` |
| **alpines_stealer** | [Steal the VFY](https://agentgames.zkverify.io/events/steal-the-vfy) | 3002 | `/alpines_stealer` |

---

## Agents

### 🛡️ Alpines Keeper - Proof Gatekeeper

A deterministic payment-validation engine that reviews incoming payment requests, detects trap transactions (fake proofs, VK mismatches, expired deadlines, replayed proofs, …), and generates Groth16 proofs for every decision.

**Scoring:** +12 correct decision · −6 approve a trap · −3 reject valid payment · −2 missing proof · Timeout (>60s) = failure

### ⚔️ Alpines Stealer - Steal the VFY

A game-theory strategy engine for a 20-turn head-to-head match. Each turn, both agents simultaneously choose FORTIFY (pay cost to protect), EXTRACT (take from opponent's exposed balance), or HOLD (do nothing). Uses Nash equilibrium with Bayesian opponent modeling to adapt strategy while remaining unexploitable.

**Scoring:** Win +18 · Draw +9 · Loss +3 · Verified turn bonus +0 to +2 · Timeout/turn −1 · Invalid proof/turn −2

---

## Architecture

```
┌-------------------------------------------------------┐
│  Hetzner CPX31 - 4 vCPU AMD EPYC · 8 GB RAM          │
│  Ubuntu 22.04 · opendesign.community                  │
│                                                       │
│  ┌-------------------------------------------------┐  │
│  │  Caddy (auto-TLS, reverse proxy)                │  │
│  │  :443 --┬-- /alpines_keeper → localhost:3001     │  │
│  │         ├-- /alpines_stealer → localhost:3002    │  │
│  │         └-- / → static landing page             │  │
│  └-------------------------------------------------┘  │
│                                                       │
│  ┌----------------------┐  ┌----------------------┐  │
│  │  alpines-keeper       │  │  alpines-stealer      │  │
│  │  CPUs 0,1 · 3 GB     │  │  CPUs 2,3 · 3 GB     │  │
│  │  Fastify + snarkjs    │  │  Fastify + snarkjs    │  │
│  │  + rapidsnark         │  │  + rapidsnark         │  │
│  └----------------------┘  └----------------------┘  │
│                                                       │
│  ┌-------------------------------------------------┐  │
│  │  @zkverify/shared - HMAC · Prover · zkVerify    │  │
│  └-------------------------------------------------┘  │
└-------------------------------------------------------┘
```

### Monorepo Layout

```
zkVerify/
├-- packages/
│   ├-- shared/             # Shared library (HMAC, prover, zkVerify client, logger)
│   ├-- alpines-keeper/     # Proof Gatekeeper agent
│   └-- alpines-stealer/    # Steal the VFY agent
├-- deploy/
│   ├-- Caddyfile           # Reverse proxy config
│   ├-- alpines-keeper.service
│   ├-- alpines-stealer.service
│   ├-- setup.sh            # VPS provisioning (run once)
│   └-- deploy.sh           # Pull, build, restart (run on each deploy)
├-- public/
│   └-- index.html          # Landing page served at opendesign.community
├-- package.json            # Root workspace config
└-- tsconfig.base.json      # Shared TypeScript config
```

**Key design decisions:**

- **CPU pinning** - Keeper on CPUs 0,1; Stealer on CPUs 2,3. No contention during proof generation.
- **Memory caps** - 3 GB per service via `MemoryMax=` in systemd. OOM-safe.
- **HMAC on every request/response** - Platform authentication using `x-agent-games-signature`.
- **Dual prover backend** - rapidsnark (native, fast) with snarkjs (WASM) fallback.
- **Idempotent deployment** - `setup.sh` can be re-run safely; `deploy.sh` is a single command.

---

## Quick Start

```bash
# Clone
git clone <repo-url> && cd zkVerify

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env - fill in:
#   AGENT_GAMES_HMAC_SECRET
#   ZKVERIFY_API_URL
#   ZKVERIFY_API_KEY
#   KEEPER_VK_HASH / STEALER_VK_HASH
#   KEEPER_CIRCUIT_WASM / STEALER_CIRCUIT_WASM
#   KEEPER_CIRCUIT_ZKEY / STEALER_CIRCUIT_ZKEY

# Download circuit artifacts
# From: https://agentgames.zkverify.io/build
# Place WASM + zkey files in:
#   packages/alpines-keeper/circuits/
#   packages/alpines-stealer/circuits/

# Build all packages
npm run build

# Run locally
npm run start:keeper   # → http://localhost:3001
npm run start:stealer  # → http://localhost:3002
```

---

## Deployment (Hetzner VPS)

### Prerequisites

- Hetzner CPX31 server (4 vCPU AMD EPYC, 8 GB RAM)
- Domain `opendesign.community` with DNS A record pointing to VPS IP
- SSH access as root

### Step-by-step

```bash
# 1. SSH into the VPS
ssh root@<vps-ip>

# 2. Upload and run the setup script
scp deploy/setup.sh root@<vps-ip>:/tmp/
ssh root@<vps-ip> 'bash /tmp/setup.sh'

# 3. Clone the repo
git clone <repo-url> /opt/zkverify
chown -R zkverify:zkverify /opt/zkverify

# 4. Configure environment
cp /opt/zkverify/.env.example /opt/zkverify/.env
nano /opt/zkverify/.env  # Fill in all secrets

# 5. Download circuit artifacts
# Place .wasm and .zkey files into:
#   /opt/zkverify/packages/alpines-keeper/circuits/
#   /opt/zkverify/packages/alpines-stealer/circuits/

# 6. Install and build
cd /opt/zkverify
sudo -u zkverify npm install
sudo -u zkverify npm run build

# 7. Install systemd units
cp deploy/alpines-keeper.service /etc/systemd/system/
cp deploy/alpines-stealer.service /etc/systemd/system/
systemctl daemon-reload

# 8. Configure Caddy
cp deploy/Caddyfile /etc/caddy/Caddyfile
systemctl restart caddy

# 9. Start services
systemctl enable --now alpines-keeper alpines-stealer

# 10. Verify
curl https://opendesign.community/alpines_keeper
curl https://opendesign.community/alpines_stealer
```

### Subsequent deploys

```bash
ssh root@<vps-ip> 'bash /opt/zkverify/deploy/deploy.sh'
```

---

## Scoring

### Proof Gatekeeper

| Outcome | Points |
|---------|--------|
| ✅ Correct decision (approve valid / reject trap) | **+12** |
| ❌ Approve a trap | **−6** |
| ⚠️ Reject a valid payment | **−3** |
| 🔒 Missing/invalid Groth16 proof | **−2** extra |
| ⏱️ Timeout (>60s) | Failure |

**Trap varieties detected:** VK substitution (~13%), proof reuse (~11%), threshold mismatch (~8%), expired deadline (~6%), recipient mismatch (~6%), amount overflow (~6%), invalid proof.

### Steal the VFY

| Outcome | Points |
|---------|--------|
| 🏆 Match win | **+18** |
| 🤝 Draw | **+9** |
| 💀 Loss | **+3** |
| ✅ Verified turn reliability bonus | **+0 to +2** |
| ⏱️ Timeout per turn | **−1** |
| 🔒 Invalid proof per turn | **−2** |

**Game mechanics:** Two agents face off over 20 simultaneous-move turns. Each turn, choose **FORTIFY** (pay cost, protect balance), **EXTRACT** (take from opponent's exposed balance), or **HOLD** (do nothing). Strategy committed on-chain before match; ZK proof required each turn.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js 20 (LTS) |
| Language | TypeScript 5.7 |
| HTTP Framework | Fastify 5 |
| ZK Proofs | snarkjs + rapidsnark (Groth16) |
| On-chain Verification | zkVerify |
| Reverse Proxy | Caddy (auto-TLS) |
| Process Manager | systemd |
| Server | Hetzner CPX31 (AMD EPYC) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_GAMES_HMAC_SECRET` | Shared HMAC secret for request/response signing |
| `ZKVERIFY_API_URL` | zkVerify network RPC endpoint |
| `ZKVERIFY_API_KEY` | API key for zkVerify |
| `KEEPER_PORT` | Keeper listen port (default: 3001) |
| `STEALER_PORT` | Stealer listen port (default: 3002) |
| `KEEPER_VK_HASH` | Verification key hash for Keeper circuit |
| `STEALER_VK_HASH` | Verification key hash for Stealer circuit |
| `KEEPER_CIRCUIT_WASM` | Path to Keeper circuit WASM file |
| `KEEPER_CIRCUIT_ZKEY` | Path to Keeper circuit proving key |
| `STEALER_CIRCUIT_WASM` | Path to Stealer circuit WASM file |
| `STEALER_CIRCUIT_ZKEY` | Path to Stealer circuit proving key |
| `RAPIDSNARK_BIN` | Path to rapidsnark binary (default: `/usr/local/bin/rapidsnark`) |
| `LOG_LEVEL` | Log level: debug, info, warn, error (default: info) |

---

## License

Apache-2.0
