#!/usr/bin/env node
/**
 * Stealer Commitment Fix - Run on VPS
 *
 * Step 1: Figure out the correct Poseidon preimage for the stealer commitment.
 * Step 2: Test a valid proof.
 * Step 3: Print the exact agent.ts fix needed.
 *
 * Usage: node scripts/fix-stealer-commitment.mjs
 */
import { existsSync } from 'node:fs';
import { execSync } from 'node:child_process';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
const REGISTERED = BigInt('0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e');

if (!existsSync(WASM) || !existsSync(ZKEY)) {
  console.error('Circuit files not found. Run from /opt/zkverify');
  process.exit(1);
}

// Load snarkjs
const snarkjs = await import('snarkjs').then(m => m.default ?? m);

// Load poseidon via circomlibjs (bundled with snarkjs)
let poseidon;
try {
  const { buildPoseidon } = await import('circomlibjs');
  poseidon = await buildPoseidon();
} catch {
  try {
    // circomlibjs ships with snarkjs in some versions
    const p = await import('/opt/zkverify/node_modules/circomlibjs/src/poseidon.js');
    poseidon = await (p.buildPoseidon ?? p.default.buildPoseidon)();
  } catch {
    execSync('cd /opt/zkverify && npm install circomlibjs --no-save 2>&1', { stdio: 'inherit' });
    const { buildPoseidon } = await import('/opt/zkverify/node_modules/circomlibjs/src/poseidon.js');
    poseidon = await buildPoseidon();
  }
}

const F = poseidon.F;
const hash = (...args) => BigInt(F.toString(poseidon(args.map(BigInt))));

console.log('=== Stealer Commitment Fix ===\n');
console.log(`Registered commitment: 0x${REGISTERED.toString(16)}\n`);

// ---- Phase 1: Determine if commitment is PUBLIC ----
// Try a proof that SKIPS the commitment check by using commitment=Poseidon(zeros,0)
// and see if publicSignals includes the commitment value.
const testHash9 = hash(0,0,0,0,0,0,0,0,0); // Poseidon([params[8]=0, salt=0])
console.log(`Poseidon([0x8 zeros, salt=0]) = 0x${testHash9.toString(16)}`);

// ---- Phase 2: Try all likely Poseidon arrangements ----
const arrangements = [
  { label: 'P([p0..p7, salt])',  commitment: hash(0,0,0,0,0,0,0,0,0), circuitSalt: 0n },
  { label: 'P([p0..p7])',        commitment: hash(0,0,0,0,0,0,0,0),   circuitSalt: 0n },
  { label: 'P([salt, p0..p7])', commitment: hash(0,0,0,0,0,0,0,0,0), circuitSalt: 0n }, // same value as first
  { label: 'P([salt])',          commitment: hash(0),                  circuitSalt: 0n },
  // Also try with commitment = registered value (see which strategyParams+salt satisfies it)
  { label: 'registered (0x80d45b2f...) with zero params+salt',
    commitment: REGISTERED, circuitSalt: 0n },
];

console.log('\n--- Testing proof attempts ---\n');

for (const { label, commitment, circuitSalt } of arrangements) {
  const inputs = {
    commitment,
    matchId:         1n,
    turnNumber:      1n,
    selfBalance:     100n,
    opponentBalance: 100n,
    action:          2n,   // HOLD
    amount:          0n,
    circuitVersion:  1n,
    strategyParams:  [0n,0n,0n,0n,0n,0n,0n,0n],
    salt:            circuitSalt,
  };

  process.stdout.write(`  [?] ${label} ... `);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    console.log('PROOF SUCCESS!');
    console.log(`      commitment input: 0x${commitment.toString(16)}`);
    console.log(`      publicSignals[0]: ${publicSignals[0]}`);

    // Check if commitment appears in publicSignals (is it public?)
    const commitInPublic = publicSignals.some(s => BigInt(s) === commitment);
    const registeredInPublic = publicSignals.some(s => BigInt(s) === REGISTERED);
    console.log(`      commitment in publicSignals: ${commitInPublic}`);
    console.log(`      registered (0x80d45b2f...) in publicSignals: ${registeredInPublic}`);
    console.log(`      full publicSignals: ${JSON.stringify(publicSignals)}`);

    console.log('\n' + '='.repeat(60));
    console.log('SOLUTION:');
    console.log('='.repeat(60));
    console.log(`  Poseidon variant: ${label}`);
    console.log(`  commitment = 0x${commitment.toString(16)}`);
    console.log(`  salt = ${circuitSalt}`);
    console.log('');

    if (commitInPublic && commitment !== REGISTERED) {
      console.log('WARNING: commitment IS a public signal!');
      console.log('The platform will CHECK that publicSignals includes the REGISTERED commitment.');
      console.log(`Registered: 0x${REGISTERED.toString(16)}`);
      console.log(`Computed:   0x${commitment.toString(16)}`);
      console.log('');
      console.log('You need to find the PREIMAGE of the registered commitment.');
      console.log('Since zeros+0 did not produce the registered value, the original');
      console.log('registration used a non-zero salt or params.');
    } else if (!commitInPublic) {
      console.log('GOOD: commitment is PRIVATE. The platform does NOT check it against');
      console.log('the registered value directly in publicSignals.');
      console.log('However the platform likely checks strategy_hash == task.strategy_hash.');
      console.log('If task.strategy_hash != this commitment, the platform may still reject.');
    } else {
      console.log('PERFECT: commitment IS public AND matches registered value!');
    }

    console.log('\nFix for packages/alpines-stealer/src/routes/agent.ts:');
    console.log('  Replace the commitment + salt generation with:');
    console.log('');
    console.log(`  // Commitment: Poseidon(${label})`);
    console.log(`  // strategyParams = [0,0,0,0,0,0,0,0], salt = 0n (FIXED - must match preimage)`);
    console.log(`  const commitment = ${commitment}n;  // 0x${commitment.toString(16)}`);
    console.log(`  const salt = 0n;`);
    console.log(`  const strategyArray = Array(8).fill(0n);`);

    process.exit(0);
  } catch (e) {
    const msg = (e.message ?? String(e)).slice(0, 100).replace(/\n/g, ' ');
    console.log(`FAIL: ${msg}`);
  }
}

console.log('\n=== No arrangement worked with zero inputs ===');
console.log('The commitment 0x80d45b2f... was computed with UNKNOWN non-zero inputs.');
console.log('');
console.log('IMMEDIATE FIX: Accept -2 penalty for stealer proofs.');
console.log('The stealer will still play correctly (FORTIFY/EXTRACT/HOLD)');
console.log('but each turn costs -2 for missing proof.');
console.log('');
console.log('TO INVESTIGATE: What salt/params were used at registration?');
console.log('Check git log for any registration script or previous .env STEALER_SALT entry.');
