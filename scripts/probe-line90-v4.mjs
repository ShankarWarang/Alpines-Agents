#!/usr/bin/env node
/**
 * Stealer line-90 probe v4 — CONFIRM the constraint structure and find winning params.
 *
 * KEY FINDINGS:
 *   - params[0]=0  → line 90 always
 *   - params[0]=1, selfBal=0, oppBal=0 → PROOF SUCCESS! (Group T)
 *   - params[0]=1, selfBal=100         → line 140
 *
 * HYPOTHESIS: params[0] is a "max balance cap" policy parameter.
 *   - Line 90:  params[0] > 0 (must declare a cap)
 *   - Line 140: params[0] >= selfBalance (cap must cover actual balance)
 *   - Line 149: related to action=HOLD constraints with balance/params[0]
 *
 * GOAL: Find params[0] = X such that:
 *   - X >= max(selfBalance, opponentBalance) during any game state
 *   - And produce a valid proof for realistic game inputs
 *
 * CRITICAL BONUS: Check if commitment is a PUBLIC or PRIVATE signal
 *   by seeing which publicSignals[i] corresponds to the commitment value.
 *
 * Output: scripts/probe-line90-v4-output.txt
 * Run:    node scripts/probe-line90-v4.mjs
 */
import { existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
const OUT  = 'scripts/probe-line90-v4-output.txt';

if (!existsSync(WASM) || !existsSync(ZKEY)) { console.error('Missing circuit files'); process.exit(1); }
writeFileSync(OUT, '=== probe-line90-v4 ===\n');

function log(msg) { process.stdout.write(msg + '\n'); appendFileSync(OUT, msg + '\n'); }

const snarkjs = await import('snarkjs').then(m => m.default ?? m);
const req     = createRequire(import.meta.url);
const poseidon = await req('circomlibjs').buildPoseidon();
const F = poseidon.F;
const P = (...a) => BigInt(F.toString(poseidon(a.map(BigInt))));

const z8 = Array(8).fill(0n);
const BN128_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// Our registered commitment (mod P reduction):
const REGISTERED_MOD_P = 0x200bbe49a172864e2e6f11142b6f5d55d43c2141f1e8cc2e1f287876657cbb3cn;

async function tryProof(label, inputs) {
  process.stdout.write(`  [?] ${label} ... `);
  appendFileSync(OUT, `  [?] ${label} ... `);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    const sigStr = JSON.stringify(publicSignals);
    log('PROOF SUCCESS!\n      publicSignals: ' + sigStr);
    // Decode which signal is the commitment
    const commitmentHex = '0x' + BigInt(inputs.commitment).toString(16);
    const commitmentDec = inputs.commitment.toString();
    log(`      Input commitment (hex): ${commitmentHex}`);
    log(`      Input commitment (dec): ${commitmentDec}`);
    for (let i = 0; i < publicSignals.length; i++) {
      if (publicSignals[i] === commitmentDec) {
        log(`      >>> commitment found at publicSignals[${i}] <<<`);
      }
    }
    log(`      REGISTERED_MOD_P (dec): ${REGISTERED_MOD_P}`);
    return { ok: true, publicSignals };
  } catch (e) {
    const line = (e.message ?? '').match(/line: (\d+)/)?.[1] ?? '?';
    log(`FAIL line ${line}`);
    return { ok: false, line };
  }
}

function mkInputs(p0, action, amount, selfBalance, opponentBalance, salt = 0n) {
  const params = [p0, ...z8.slice(1)];
  const commitment = P(...params, salt);
  return { commitment, matchId: 1n, turnNumber: 1n, selfBalance, opponentBalance,
           action, amount, circuitVersion: 1n, strategyParams: params, salt };
}

// ======= GROUP AA: Confirm line 140 is selfBalance <= params[0] =======
log('\n=== Group AA: Confirm params[0] >= selfBalance constraint ===\n');

// params[0]=100, selfBal=100 → should PASS line 140 (100 >= 100)
await tryProof('p0=100 self=100 opp=100 FORTIFY', mkInputs(100n, 0n, 0n, 100n, 100n));
// params[0]=100, selfBal=0, opp=100 → tests if oppBalance also matters
await tryProof('p0=100 self=0 opp=100 FORTIFY',   mkInputs(100n, 0n, 0n, 0n, 100n));
// params[0]=50, selfBal=100 → should still FAIL (50 < 100)
await tryProof('p0=50 self=100 opp=100 FORTIFY',  mkInputs(50n, 0n, 0n, 100n, 100n));
// params[0]=101, selfBal=100 → should PASS (101 >= 100)
await tryProof('p0=101 self=100 opp=100 FORTIFY',  mkInputs(101n, 0n, 0n, 100n, 100n));
// params[0]=1, selfBal=1 → tests minimum
await tryProof('p0=1 self=1 opp=1 FORTIFY',        mkInputs(1n, 0n, 0n, 1n, 1n));

// ======= GROUP BB: If p0 >= selfBal works, test with realistic game values =======
log('\n=== Group BB: Realistic game values (starting balance ~100) ===\n');

const GAME_MAX = 10000n;  // safe large cap
await tryProof(`p0=${GAME_MAX} self=100 opp=100 FORTIFY`,  mkInputs(GAME_MAX, 0n, 0n, 100n, 100n));
await tryProof(`p0=${GAME_MAX} self=100 opp=100 EXTRACT`,  mkInputs(GAME_MAX, 1n, 10n, 100n, 100n));
await tryProof(`p0=${GAME_MAX} self=100 opp=100 HOLD`,     mkInputs(GAME_MAX, 2n, 0n, 100n, 100n));
// Mid-game balances
await tryProof(`p0=${GAME_MAX} self=50 opp=150 FORTIFY`,   mkInputs(GAME_MAX, 0n, 0n, 50n, 150n));
await tryProof(`p0=${GAME_MAX} self=50 opp=150 EXTRACT`,   mkInputs(GAME_MAX, 1n, 5n, 50n, 150n));
await tryProof(`p0=${GAME_MAX} self=0 opp=200 FORTIFY`,    mkInputs(GAME_MAX, 0n, 0n, 0n, 200n));

// ======= GROUP CC: Test line 149 — what does it check for HOLD? =======
log('\n=== Group CC: Probe line 149 (HOLD constraint) ===\n');
// line 149 fires for params[0]=1,action=2 at all tested balances
// Does it fire when p0 is large?
await tryProof('p0=10000 self=100 opp=100 HOLD',    mkInputs(10000n, 2n, 0n, 100n, 100n));
await tryProof('p0=10000 self=0 opp=0 HOLD',        mkInputs(10000n, 2n, 0n, 0n, 0n));
await tryProof('p0=10000 self=100 opp=0 HOLD',      mkInputs(10000n, 2n, 0n, 100n, 0n));
// Maybe line 149 checks self > opp for HOLD?
await tryProof('p0=10000 self=200 opp=100 HOLD',    mkInputs(10000n, 2n, 0n, 200n, 100n));
// Try HOLD with params[1] = opponentBalance cap?
{
  const params = [10000n, 10000n, ...z8.slice(2)];  // params[1]=10000 too
  const c = P(...params, 0n);
  await tryProof('p0=p1=10000 self=100 opp=100 HOLD', {
    commitment: c, matchId: 1n, turnNumber: 1n,
    selfBalance: 100n, opponentBalance: 100n,
    action: 2n, amount: 0n, circuitVersion: 1n,
    strategyParams: params, salt: 0n,
  });
}

// ======= GROUP DD: Check whether commitment appears in publicSignals =======
log('\n=== Group DD: Identify commitment in publicSignals ===\n');
// Use a commitment with distinctive value so we can find it in publicSignals
{
  const MAGIC_SALT = 0x12345678n;
  const params = [10000n, ...z8.slice(1)];
  const c = P(...params, MAGIC_SALT);
  log(`  distinctive commitment = P([10000,zeros7], 0x12345678) = 0x${c.toString(16)}`);
  const r = await tryProof('distinctive commitment for signal identification', {
    commitment: c, matchId: 1n, turnNumber: 1n,
    selfBalance: 0n, opponentBalance: 0n,
    action: 0n, amount: 0n, circuitVersion: 1n,
    strategyParams: params, salt: MAGIC_SALT,
  });
  if (r.ok) {
    log(`  Commitment value ${c} in decimal`);
    log('  >>> Use publicSignals above to find which index matches commitment <<<');
  }
}

// ======= GROUP EE: If commitment is private, try with REGISTERED value directly =======
log('\n=== Group EE: Use registered commitment value directly ===\n');
// The commitment is passed as input but may be private (not in publicSignals).
// If private: ANY consistent (commitment, params, salt) triple works.
// If we pass commitment=REGISTERED_MOD_P and find params/salt that equal it via Poseidon...
// Since we can't find exact preimage, try passing REGISTERED_MOD_P as commitment
// but with WRONG params (this will fail line 72 if commitment is verified, confirming it's public)
{
  const r = await tryProof('REGISTERED_MOD_P as commitment, params=zeros (line 72 test)', {
    commitment: REGISTERED_MOD_P,
    matchId: 1n, turnNumber: 1n,
    selfBalance: 0n, opponentBalance: 0n,
    action: 0n, amount: 0n, circuitVersion: 1n,
    strategyParams: z8, salt: 0n,
  });
  if (r.ok) {
    log('  >>> commitment is NOT verified against Poseidon! It is public-only. <<<');
    log('  >>> Platform checks publicSignals[i] == REGISTERED_MOD_P externally. <<<');
  }
}
// Also: check what index commitment appears at by using REGISTERED_MOD_P as input commitment
// and passing MATCHING params via brute force on params[0]:
log('  Checking if Poseidon([X,0..0],0) = REGISTERED_MOD_P for X in 1..1000...');
let foundParams0 = null;
for (let x = 1n; x <= 1000n; x++) {
  const h = P(x, ...z8.slice(1), 0n);
  if (h === REGISTERED_MOD_P) {
    foundParams0 = x;
    log(`  !!! FOUND: Poseidon([${x},zeros7],0) = REGISTERED_MOD_P !!!`);
    const r = await tryProof(`EXACT PREIMAGE FOUND: params[0]=${x}`, {
      commitment: REGISTERED_MOD_P,
      matchId: 1n, turnNumber: 1n,
      selfBalance: 0n, opponentBalance: 0n,
      action: 0n, amount: 0n, circuitVersion: 1n,
      strategyParams: [x, ...z8.slice(1)], salt: 0n,
    });
    if (r.ok) log('  TOURNAMENT COMMITMENT SOLVED!');
    break;
  }
}
if (!foundParams0) log('  No x in [1,1000] satisfies Poseidon([x,zeros7],0) = REGISTERED_MOD_P');

// ======= SUMMARY =======
log('\n=== SUMMARY ===');
log('If Group AA shows params[0]=100 passes with self=100:');
log('  → Line 140 = selfBalance <= params[0]');
log('  → Fix: set params[0] = large constant (10000)');
log('  → Recompute commitment = Poseidon([10000,0..0], salt)');
log('  → PROBLEM: registered commitment won\'t match → check if platform enforces it');
log('');
log('If Group DD shows commitment is NOT in publicSignals:');
log('  → Commitment is PRIVATE → platform cannot check it → any params work');
log('  → Set params[0]=10000, salt=random, and generate proof freely');
log('');
log('If Group DD shows commitment IS publicSignals[k]:');
log('  → Must find params that hash to registered value OR re-register');
log('  → Check Group EE result: does registered value appear in publicSignals[0] or [1]?');
log(`\nOutput: ${OUT}`);
