#!/usr/bin/env node
/**
 * Fix stealer line 90 constraint - runs on VPS from /opt/zkverify
 *
 * We know: commitment = Poseidon(params[8], salt=0) passes line 72.
 * Now we probe what constraint fails at line 90.
 *
 * Usage: node scripts/fix-line90.mjs
 */
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';

if (!existsSync(WASM) || !existsSync(ZKEY)) { console.error('No circuit files'); process.exit(1); }

const snarkjs = await import('snarkjs').then(m => m.default ?? m);
const require = createRequire(import.meta.url);
const circomlibjs = require('circomlibjs');
const poseidon = await circomlibjs.buildPoseidon();
const F = poseidon.F;
const P = (...args) => BigInt(F.toString(poseidon(args.map(BigInt))));

// Known good: Poseidon(params[8], salt) = 9 inputs passes line 72
// Compute commitment for whatever params+salt we use
const mk = (params8, salt) => P(...params8, salt);
const zeros8 = [0n,0n,0n,0n,0n,0n,0n,0n];

async function tryProof(label, overrides) {
  const base = {
    commitment:      mk(zeros8, 0n),
    matchId:         1n,
    turnNumber:      1n,
    selfBalance:     100n,
    opponentBalance: 100n,
    action:          2n,
    amount:          0n,
    circuitVersion:  1n,
    strategyParams:  zeros8,
    salt:            0n,
  };
  const inputs = { ...base, ...overrides };
  // Always recompute commitment to match params+salt
  if (overrides.strategyParams || overrides.salt !== undefined) {
    inputs.commitment = mk(inputs.strategyParams ?? zeros8, inputs.salt ?? 0n);
  }
  process.stdout.write(`  [?] ${label} ... `);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    console.log('PROOF SUCCESS!');
    console.log('      publicSignals: ' + JSON.stringify(publicSignals));
    return { success: true, inputs, publicSignals };
  } catch (e) {
    const msg = (e.message ?? '').match(/line: (\d+)/)?.[1];
    console.log('FAIL line ' + (msg ?? '?') + ': ' + (e.message??'').slice(0,80).replace(/\n/g,' '));
    return { success: false };
  }
}

console.log('=== Probing line 90 constraint ===\n');
console.log('Baseline commitment (9-input Poseidon, zeros+salt=0):');
console.log('  0x' + mk(zeros8,0n).toString(16) + '\n');

// --- Probe 1: vary action ---
for (const [action, amount] of [[0n,0n],[1n,0n],[1n,1n],[1n,10n],[2n,0n]]) {
  const r = await tryProof(`action=${action} amount=${amount}`, { action, amount });
  if (r.success) process.exit(0);
}

// --- Probe 2: vary balances ---
for (const [self, opp] of [[0n,0n],[1n,0n],[50n,100n],[200n,100n],[100n,0n]]) {
  const r = await tryProof(`selfBalance=${self} opponentBalance=${opp}`, {
    selfBalance: self, opponentBalance: opp
  });
  if (r.success) process.exit(0);
}

// --- Probe 3: vary matchId / turnNumber ---
for (const [mid, turn, total] of [[0n,1n],[999n,1n],[1n,2n],[1n,10n]]) {
  const r = await tryProof(`matchId=${mid} turn=${turn}`, { matchId: mid, turnNumber: turn });
  if (r.success) process.exit(0);
}

// --- Probe 4: vary circuitVersion ---
for (const cv of [0n, 2n, 100n]) {
  const r = await tryProof(`circuitVersion=${cv}`, { circuitVersion: cv });
  if (r.success) process.exit(0);
}

// --- Probe 5: non-zero strategyParams ---
for (let i = 0; i < 8; i++) {
  const p = [...zeros8]; p[i] = 1n;
  const r = await tryProof(`strategyParams[${i}]=1`, { strategyParams: p });
  if (r.success) process.exit(0);
}

// --- Probe 6: non-zero salt ---
for (const s of [1n, 42n, 12345n, BigInt('0x' + 'ff'.repeat(16))]) {
  const r = await tryProof(`salt=${s}`, { salt: s });
  if (r.success) process.exit(0);
}

// --- Probe 7: registered commitment with varied params (reverse-engineering) ---
// If commitment is Poseidon(params, salt) and registered=0x80d45b2f...
// try salt=1,2,...,100 to see if any produces the registered value
console.log('\n--- Reverse: searching for salt that produces registered commitment ---');
const REG = BigInt('0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e');
for (let s = 0n; s <= 1000n; s++) {
  if (mk(zeros8, s) === REG) {
    console.log(`FOUND: salt=${s} produces registered commitment!`);
    const r = await tryProof(`registered commitment with salt=${s}`, {
      commitment: REG, salt: s
    });
    if (r.success) process.exit(0);
    break;
  }
}
console.log('Salt search 0-1000: no match found for registered commitment.');

console.log('\nAll probes done. Line 90 constraint remains unknown.');
console.log('Paste this output back so we can analyze the pattern of failures.');
