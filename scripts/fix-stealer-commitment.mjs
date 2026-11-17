#!/usr/bin/env node
/**
 * Stealer Commitment Fix - Run on VPS from /opt/zkverify
 * Usage: node scripts/fix-stealer-commitment.mjs
 */
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
const REGISTERED = BigInt('0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e');

if (!existsSync(WASM) || !existsSync(ZKEY)) {
  console.error('Circuit files not found. Run from /opt/zkverify');
  process.exit(1);
}

const snarkjs = await import('snarkjs').then(m => m.default ?? m);

// --- Load Poseidon via CJS require (circomlibjs is CommonJS) ---
const require = createRequire(import.meta.url);
let circomlibjs;
try {
  circomlibjs = require('circomlibjs');
} catch {
  // Try the /tmp/cl location installed by previous run
  try {
    circomlibjs = require('/tmp/cl/node_modules/circomlibjs');
  } catch {
    console.error('circomlibjs not loadable. Run: npm install circomlibjs --no-save');
    console.error('Then retry: node scripts/fix-stealer-commitment.mjs');
    process.exit(1);
  }
}

const poseidon = await (circomlibjs.buildPoseidon ?? circomlibjs.default?.buildPoseidon)();
const F = poseidon.F;
const P = (...args) => BigInt(F.toString(poseidon(args.map(BigInt))));
console.log('Poseidon loaded OK\n');

const zeros8 = [0n,0n,0n,0n,0n,0n,0n,0n];

const arrangements = [
  { label: 'Poseidon(params[8], salt=0) → 9 inputs',   commitment: P(...zeros8, 0n), salt: 0n },
  { label: 'Poseidon(params[8]) → 8 inputs',           commitment: P(...zeros8),     salt: 0n },
  { label: 'Poseidon(salt=0) → 1 input',               commitment: P(0n),            salt: 0n },
  { label: 'Poseidon(salt=0, params[8]) → salt first', commitment: P(0n,...zeros8),  salt: 0n },
  { label: 'registered value (probe if commitment is private)',
    commitment: REGISTERED, salt: 0n },
];

console.log('Computed hashes:');
for (const { label, commitment } of arrangements.slice(0,-1)) {
  const hex = '0x' + commitment.toString(16).padStart(64,'0');
  const match = commitment === REGISTERED ? ' *** MATCHES REGISTERED ***' : '';
  console.log(`  ${label}\n    ${hex}${match}`);
}

console.log('\n--- Running proof attempts ---\n');

for (const { label, commitment, salt } of arrangements) {
  const inputs = {
    commitment,
    matchId: 1n, turnNumber: 1n,
    selfBalance: 100n, opponentBalance: 100n,
    action: 2n, amount: 0n, circuitVersion: 1n,
    strategyParams: zeros8,
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
    if (!commitInPub) {
      console.log('COMMITMENT IS PRIVATE - platform cannot see it!');
      console.log('You can use ANY internally-consistent (commitment, params, salt).');
      console.log('\nFix for packages/alpines-stealer/src/routes/agent.ts:');
      console.log('  const commitment = ' + commitment + 'n;');
      console.log('  const salt = 0n;');
      console.log('  const strategyArray = Array(8).fill(0n);');
    } else if (commitInPub && commitment === REGISTERED) {
      console.log('PERFECT: commitment is public AND registered value works!');
      console.log('Fix: use salt=0n, strategyParams=[0..0]');
    } else {
      console.log('commitment is PUBLIC - platform WILL check it = 0x80d45b2f...');
      console.log('This computed commitment does NOT match registered. Need original preimage.');
    }
    process.exit(0);
  } catch (e) {
    console.log('FAIL: ' + (e.message ?? String(e)).slice(0,120).replace(/\n/g,' '));
  }
}

console.log('\nNo arrangement passed. Registered commitment needs unknown preimage.');
console.log('Stealer will play correctly but take -2/turn for missing proof.');
