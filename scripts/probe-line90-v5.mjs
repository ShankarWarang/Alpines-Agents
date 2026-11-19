#!/usr/bin/env node
/**
 * Stealer line-90 probe v5 — Brute-force valid commitment + full constraint map.
 *
 * KEY INSIGHT from v4:
 *   The error chain Num2Bits_?? → LessThan → GreaterEqThan → line 89 means:
 *   - Line 89: GreaterEqThan(N)(commitment, selfBalance) instantiation
 *   - Line 90: GEQ.out === 1 assertion (commitment < selfBalance causes this)
 *   - The GreaterEqThan uses Num2Bits internally. If commitment >= 2^N,
 *     the Num2Bits OVERFLOWS and the error is reported at line 89.
 *   - Poseidon([1,0,...],0) ≈ 2^249 < 2^252 → passes!
 *   - Poseidon([100,0,...],0) or other values can be >= 2^252 → fails!
 *
 * HYPOTHESIS for line 140: params[0] >= selfBalance + opponentBalance
 *   - p0=1 self=0 opp=0: 1 >= 0 ✓ → passes
 *   - p0=1 self=1 opp=1: 1 >= 2 ✗ → fails line 140
 *
 * GOAL: Find X such that:
 *   1. Poseidon([X,0,...,0], salt) < 2^N (doesn't overflow Num2Bits)
 *   2. X >= selfBalance + opponentBalance (passes line 140)
 *   3. Full proof succeeds with self=100, opp=100 (real game state)
 *
 * Output: scripts/probe-line90-v5-output.txt
 * Run:    node scripts/probe-line90-v5.mjs
 */
import { existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
const OUT  = 'scripts/probe-line90-v5-output.txt';

if (!existsSync(WASM) || !existsSync(ZKEY)) { console.error('Missing circuit files'); process.exit(1); }
writeFileSync(OUT, '=== probe-line90-v5 ===\n');

function log(msg) { process.stdout.write(msg + '\n'); appendFileSync(OUT, msg + '\n'); }

const snarkjs = await import('snarkjs').then(m => m.default ?? m);
const req     = createRequire(import.meta.url);
const poseidon = await req('circomlibjs').buildPoseidon();
const F = poseidon.F;
const P = (...a) => BigInt(F.toString(poseidon(a.map(BigInt))));

const z8 = Array(8).fill(0n);
const BN252 = 2n ** 252n;  // common threshold

async function tryProof(label, inputs) {
  process.stdout.write(`  [?] ${label} ... `);
  appendFileSync(OUT, `  [?] ${label} ... `);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    log('SUCCESS!\n      sigs: ' + JSON.stringify(publicSignals));
    return { ok: true, publicSignals };
  } catch (e) {
    const line = (e.message ?? '').match(/line: (\d+)/)?.[1] ?? '?';
    const tmpl = [...(e.message ?? '').matchAll(/template (\w+)/g)].map(m => m[1]).join(' → ');
    log(`FAIL line ${line}  [${tmpl}]`);
    return { ok: false, line };
  }
}

function mkInputs(p0, action, amount, selfBalance, opponentBalance, salt = 0n) {
  const params = [p0, ...z8.slice(1)];
  const commitment = P(...params, salt);
  return { commitment, matchId: 1n, turnNumber: 1n, selfBalance, opponentBalance,
           action, amount, circuitVersion: 1n, strategyParams: params, salt };
}

// ======= GROUP FF: Characterize line 140 — is it params[0] >= self + opp? =======
log('\n=== Group FF: Line 140 characterization — p0 >= self + opp hypothesis ===\n');

// p0=1, self=1, opp=0 → 1 >= 1 ✓ should PASS if hypothesis correct
await tryProof('p0=1 self=1 opp=0 FORTIFY', mkInputs(1n, 0n, 0n, 1n, 0n));
// p0=1, self=0, opp=1 → 1 >= 1 ✓ should PASS
await tryProof('p0=1 self=0 opp=1 FORTIFY', mkInputs(1n, 0n, 0n, 0n, 1n));
// p0=2, self=1, opp=1 → 2 >= 2 ✓ should PASS
await tryProof('p0=2 self=1 opp=1 FORTIFY', mkInputs(2n, 0n, 0n, 1n, 1n));
// p0=3, self=1, opp=1 → 3 >= 2 ✓ should PASS
await tryProof('p0=3 self=1 opp=1 FORTIFY', mkInputs(3n, 0n, 0n, 1n, 1n));
// p0=10, self=5, opp=5 → 10 >= 10 ✓
await tryProof('p0=10 self=5 opp=5 FORTIFY', mkInputs(10n, 0n, 0n, 5n, 5n));

// ======= GROUP GG: Determine the Num2Bits overflow threshold =======
log('\n=== Group GG: Find the Num2Bits overflow threshold ===\n');
// Compute Poseidon for various p0 values and check if they are < 2^252
const thresholds = [
  ['2^248', 2n ** 248n],
  ['2^250', 2n ** 250n],
  ['2^252', 2n ** 252n],
  ['2^253', 2n ** 253n],
];

for (const p0 of [0n, 1n, 2n, 3n, 4n, 5n, 10n, 50n, 100n, 200n]) {
  const c = P(p0, ...z8.slice(1), 0n);  // Poseidon([p0, zeros7], 0)
  const hex = '0x' + c.toString(16).slice(0,16) + '...';
  const checks = thresholds.map(([label, t]) => `${label}:${c < t ? 'Y' : 'N'}`).join(' ');
  log(`  Poseidon([${String(p0).padStart(3)},0..0],0) = ${hex}  ${checks}`);
}

// ======= GROUP HH: Brute force find valid commitment for game state self=100,opp=100 =======
log('\n=== Group HH: Brute force valid params+salt for self=100 opp=100 ===\n');
log('Searching for Poseidon(params, salt) < 2^252 with params[0] >= 200...\n');

let foundSolution = null;
let searchCount = 0;

// Try varying salt with different params[0] values
outerLoop:
for (const p0 of [200n, 201n, 202n, 203n, 205n, 210n, 250n, 300n, 500n, 1000n]) {
  for (let salt = 0n; salt <= 100n; salt++) {
    searchCount++;
    const params = [p0, ...z8.slice(1)];
    const c = P(...params, salt);
    
    if (c < BN252) {
      // Check if commitment is also >= selfBalance (should be trivially true for c~2^249)
      if (c >= 100n) {  // selfBalance
        log(`  FOUND candidate: params[0]=${p0} salt=${salt}`);
        log(`    commitment = 0x${c.toString(16).slice(0,32)}... < 2^252 ✓`);
        log(`    commitment >= 100 (selfBalance) ✓`);
        
        // Test if full proof works with self=100, opp=100
        const r = await tryProof(
          `CANDIDATE: p0=${p0} salt=${salt} self=100 opp=100 FORTIFY`,
          {
            commitment: c, matchId: 1n, turnNumber: 1n,
            selfBalance: 100n, opponentBalance: 100n,
            action: 0n, amount: 0n, circuitVersion: 1n,
            strategyParams: params, salt,
          }
        );
        
        if (r.ok) {
          foundSolution = { p0, salt, commitment: c, publicSignals: r.publicSignals };
          log(`\n*** SOLUTION FOUND! ***`);
          log(`params[0]=${p0}, salt=${salt}`);
          log(`commitment = 0x${c.toString(16)}`);
          log(`Register THIS as your strategy commitment on the platform`);
          break outerLoop;
        } else {
          log(`  But proof still failed. Continue searching...`);
        }
      }
    }
  }
}

log(`\nSearched ${searchCount} combinations.`);

if (!foundSolution) {
  log('\n=== Group II: Extended search — vary ALL params[1..7] too ===\n');
  // If single-element search failed, try non-zero params[1]
  outerLoop2:
  for (const p1 of [1n, 2n, 3n, 5n, 10n]) {
    for (const p0 of [200n, 300n, 500n]) {
      for (let salt = 0n; salt <= 20n; salt++) {
        const params = [p0, p1, ...z8.slice(2)];
        const c = P(...params, salt);
        if (c < BN252 && c >= 100n) {
          log(`  Candidate: p0=${p0} p1=${p1} salt=${salt} → c < 2^252`);
          const r = await tryProof(
            `p0=${p0} p1=${p1} salt=${salt} self=100 opp=100`,
            { commitment: c, matchId: 1n, turnNumber: 1n,
              selfBalance: 100n, opponentBalance: 100n,
              action: 0n, amount: 0n, circuitVersion: 1n,
              strategyParams: params, salt }
          );
          if (r.ok) {
            foundSolution = { p0, p1, salt, commitment: c };
            log(`\n*** SOLUTION FOUND! p0=${p0} p1=${p1} salt=${salt} ***`);
            log(`commitment = 0x${c.toString(16)}`);
            break outerLoop2;
          }
        }
      }
    }
  }
}

// ======= GROUP JJ: If line 140 is p0 >= self+opp, characterize line 149 (HOLD) =======
log('\n=== Group JJ: Line 149 (HOLD action) characterization ===\n');
// Test HOLD with self=0, opp=0, p0=1
await tryProof('p0=1 self=0 opp=0 HOLD(action=2)',   mkInputs(1n, 2n, 0n, 0n, 0n));
// Test HOLD with p0=2, self=1, opp=1 (if hypothesis: p0 >= self+opp holds)
await tryProof('p0=2 self=1 opp=1 HOLD(action=2)',   mkInputs(2n, 2n, 0n, 1n, 1n));
// p0=10 self=5 opp=5 HOLD
await tryProof('p0=10 self=5 opp=5 HOLD(action=2)', mkInputs(10n, 2n, 0n, 5n, 5n));

// ======= GROUP KK: Check EXTRACT with p0 >= self+opp =======
log('\n=== Group KK: EXTRACT characterization ===\n');
await tryProof('p0=2 self=1 opp=1 EXTRACT amount=1', mkInputs(2n, 1n, 1n, 1n, 1n));
await tryProof('p0=10 self=5 opp=5 EXTRACT amount=5', mkInputs(10n, 1n, 5n, 5n, 5n));

// ======= FINAL SUMMARY =======
log('\n=== FINAL SUMMARY ===');
if (foundSolution) {
  const s = foundSolution;
  log(`\nSolution found!`);
  log(`  params[0] = ${s.p0}`);
  if (s.p1) log(`  params[1] = ${s.p1}`);
  log(`  salt = ${s.salt}  (use this SAME salt every turn)`);
  log(`  commitment = 0x${s.commitment.toString(16)}`);
  log(`\nNext steps:`);
  log(`  1. Re-register stealer on platform with commitment = 0x${s.commitment.toString(16)}`);
  log(`  2. Update agent.ts: strategyParams = [${s.p0}n, 0n,...] and salt = ${s.salt}n (fixed)`);
  log(`  3. Update STEALER_STRATEGY_COMMITMENT in .env to 0x${s.commitment.toString(16)}`);
} else {
  log('\nNo solution found in search space. Need larger search or different approach.');
  log('Consider: try commitment values in [selfBalance, 2^248) for safe margin.');
}
log(`\nOutput: ${OUT}`);
