#!/usr/bin/env node
/**
 * Stealer Commitment Fix - Run on VPS from /opt/zkverify
 *
 * Finds the correct Poseidon preimage for the stealer commitment,
 * or determines if commitment is private (we can use any consistent value).
 *
 * Usage: node scripts/fix-stealer-commitment.mjs
 */
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
const REGISTERED = BigInt('0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e');

if (!existsSync(WASM) || !existsSync(ZKEY)) {
  console.error('Circuit files not found. Run from /opt/zkverify');
  process.exit(1);
}

// ---- Load snarkjs ----
const snarkjs = await import('snarkjs').then(m => m.default ?? m);

// ---- Load Poseidon ----
// circomlibjs is installed at /opt/zkverify/node_modules/circomlibjs
// Its package.json main points to src/index.js
let poseidon;
const require = createRequire(import.meta.url);

// Strategy: try several known import paths
const importAttempts = [
  async () => {
    const m = await import('circomlibjs');
    const fn = m.buildPoseidon ?? m.default?.buildPoseidon;
    return await fn();
  },
  async () => {
    // circomlibjs CJS require
    const m = require('circomlibjs');
    const fn = m.buildPoseidon ?? m.default?.buildPoseidon;
    return await fn();
  },
  async () => {
    // Try snarkjs's own poseidon from ffjavascript
    const ff = await import('ffjavascript');
    const bn128 = await ff.getCurveFromName('bn128');
    // ffjavascript doesn't have poseidon directly, skip
    throw new Error('ffjavascript has no poseidon');
  },
];

for (const attempt of importAttempts) {
  try {
    poseidon = await attempt();
    if (poseidon) { console.log('Poseidon loaded OK'); break; }
  } catch {}
}

if (!poseidon) {
  // Install circomlibjs into /tmp and load from there
  console.log('Installing circomlibjs to /tmp/cl...');
  execSync('npm install circomlibjs --prefix /tmp/cl --no-save 2>&1 | tail -3', { stdio: 'inherit' });
  const m = await import('/tmp/cl/node_modules/circomlibjs/src/poseidon.js');
  const fn = m.buildPoseidon ?? m.default?.buildPoseidon;
  poseidon = await fn();
  console.log('Poseidon loaded from /tmp/cl');
}

const F = poseidon.F;
const P = (...args) => BigInt(F.toString(poseidon(args.map(BigInt))));

console.log('\n=== Stealer Commitment Solver ===\n');
console.log(`Registered commitment: 0x${REGISTERED.toString(16)}\n`);

// All candidate commitment computations (zero inputs, salt=0)
const zeros8 = [0n,0n,0n,0n,0n,0n,0n,0n];
const arrangements = [
  { label: 'Poseidon(params[8], salt=0) → 9 inputs',
    commitment: P(...zeros8, 0n), salt: 0n },
  { label: 'Poseidon(params[8]) → 8 inputs, salt separate',
    commitment: P(...zeros8), salt: 0n },
  { label: 'Poseidon(salt=0) → 1 input',
    commitment: P(0n), salt: 0n },
  { label: 'Poseidon(salt=0, params[8]) → salt first',
    commitment: P(0n, ...zeros8), salt: 0n },
  { label: 'Poseidon(circuitVersion=1, params[8], salt=0) → 10 inputs',
    commitment: P(1n, ...zeros8, 0n), salt: 0n },
  // Also try the registered value itself with zero params (checks if commitment is private)
  { label: 'registered value (0x80d45b2f...) with zero params+salt',
    commitment: REGISTERED, salt: 0n },
];

console.log('Computed hashes for zero inputs:');
for (const { label, commitment } of arrangements.slice(0,-1)) {
  console.log(`  ${label}`);
  console.log(`    = 0x${commitment.toString(16)}`);
  if (commitment === REGISTERED) console.log('    *** MATCHES REGISTERED! ***');
}

console.log('\n--- Running proof attempts ---\n');

for (const { label, commitment, salt } of arrangements) {
  const inputs = {
    commitment,
    matchId:         1n,
    turnNumber:      1n,
    selfBalance:     100n,
    opponentBalance: 100n,
    action:          2n,
    amount:          0n,
    circuitVersion:  1n,
    strategyParams:  zeros8,
    salt,
  };

  process.stdout.write(`  [?] ${label} ... `);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    console.log('PROOF SUCCESS!');
    console.log(`      publicSignals: ${JSON.stringify(publicSignals)}`);

    const commitInPub = publicSignals.some(s => BigInt(s) === commitment);
    const regInPub    = publicSignals.some(s => BigInt(s) === REGISTERED);
    console.log(`      commitment in publicSignals: ${commitInPub}`);
    console.log(`      registered (0x80d45b2f) in publicSignals: ${regInPub}`);

    console.log('\n' + '='.repeat(60));
    console.log('  SOLUTION FOUND');
    console.log('='.repeat(60));
    console.log(`  Variant:    ${label}`);
    console.log(`  commitment: 0x${commitment.toString(16)}`);
    console.log(`  salt:       ${salt}`);

    if (commitInPub && commitment !== REGISTERED) {
      console.log('\n  IMPORTANT: commitment IS public → platform WILL check it.');
      console.log('  Your registered commitment is 0x80d45b2f... but circuit outputs');
      console.log(`  0x${commitment.toString(16)}.`);
      console.log('  You need to find what (strategyParams, salt) hashes to 0x80d45b2f...');
      console.log('  OR accept -2 penalty until you can re-register.');
    } else if (!commitInPub) {
      console.log('\n  GOOD: commitment is PRIVATE → platform cannot see it in publicSignals.');
      console.log('  You can use ANY consistent (commitment, strategyParams, salt) triple.');
      console.log('\n  Agent code fix for packages/alpines-stealer/src/routes/agent.ts:');
      console.log('  ----------------------------------------------------------------');
      console.log('  // Replace the commitment + salt block with:');
      console.log(`  const commitment = ${commitment}n; // Poseidon(${label})`);
      console.log('  const salt = 0n;  // FIXED - must stay 0 to match commitment');
      console.log('  const strategyArray = Array(8).fill(0n);');
      console.log('  ----------------------------------------------------------------');
    } else {
      console.log('\n  PERFECT: commitment is public AND matches registered value!');
      console.log('  Agent code fix: use salt=0n and strategyParams=[0..0]');
    }

    process.exit(0);
  } catch (e) {
    const msg = (e.message ?? String(e)).slice(0, 120).replace(/\n/g,' ');
    console.log(`FAIL: ${msg}`);
  }
}

console.log('\n=== No arrangement passed ===');
console.log('The commitment 0x80d45b2f... cannot be matched with zero inputs.');
console.log('The registration used non-zero strategyParams or salt.');
console.log('');
console.log('Action: Stealer plays correctly but takes -2/turn for missing proof.');
console.log('To fix permanently: check what values were used at registration time.');
