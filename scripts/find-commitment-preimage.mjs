#!/usr/bin/env node
/**
 * Stealer Commitment Preimage Finder
 *
 * The circuit checks: commitment == Poseidon(strategyParams[0..7], salt)
 * We need to find what (strategyParams, salt) was used when registering
 * the commitment 0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e
 *
 * Run on VPS: node scripts/find-commitment-preimage.mjs
 */

const COMMITMENT_HEX = '0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e';
const COMMITMENT_BI = BigInt(COMMITMENT_HEX);

// Try importing poseidon from snarkjs/circomlibjs
let poseidon;
try {
  const circomlib = await import('circomlibjs');
  poseidon = await circomlib.buildPoseidon();
  console.log('Using circomlibjs poseidon');
} catch {
  try {
    const snarkjs = await import('snarkjs');
    // snarkjs doesn't export poseidon directly - use ffjavascript
    throw new Error('try next');
  } catch {
    try {
      const { buildPoseidon } = await import('@iden3/js-crypto');
      poseidon = await buildPoseidon();
      console.log('Using @iden3/js-crypto poseidon');
    } catch {
      console.error('Could not import poseidon. Install circomlibjs:');
      console.error('  npm install circomlibjs');
      process.exit(1);
    }
  }
}

function poseidonHash(inputs) {
  const h = poseidon(inputs);
  return poseidon.F.toString(h);
}

console.log(`\nTarget commitment: ${COMMITMENT_HEX}`);
console.log(`As BigInt:         ${COMMITMENT_BI}\n`);

// Test combinations:
// 1. Poseidon([0,0,0,0,0,0,0,0, 0]) = all zeros including salt
// 2. Poseidon([0,0,0,0,0,0,0,0])    = just 8 zeros (no salt in hash)
// 3. Poseidon([0])                   = single zero

const testCases = [
  { label: 'Poseidon(8 params + salt=0) = 9 inputs all zero',
    inputs: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n] },
  { label: 'Poseidon(8 params only, salt separate) = 8 zeros',
    inputs: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n] },
  { label: 'Poseidon(salt=0 only) = 1 input',
    inputs: [0n] },
  { label: 'Poseidon(salt=0, params=8zeros) = salt first',
    inputs: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n] }, // same as first but noting order
  // Try with 1 for circuitVersion
  { label: 'Poseidon(params[8], circuitVersion=1, salt=0) = 10 inputs',
    inputs: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 1n, 0n] },
  { label: 'Poseidon(commitment input = hex as field)',
    inputs: [COMMITMENT_BI] }, // just checking
];

console.log('Testing Poseidon hash combinations:\n');
let found = false;
for (const { label, inputs } of testCases) {
  try {
    const hash = BigInt(poseidonHash(inputs));
    const match = hash === COMMITMENT_BI;
    if (match) {
      console.log(`✓ MATCH: ${label}`);
      console.log(`  inputs:  [${inputs.join(', ')}]`);
      console.log(`  hash:    ${hash}`);
      found = true;
    } else {
      console.log(`  [   ] ${label}`);
      console.log(`        hash = ${hash}`);
    }
  } catch (e) {
    console.log(`  [ERR] ${label}: ${e.message}`);
  }
}

if (!found) {
  console.log('\nNo simple zero/constant preimage found.');
  console.log('The commitment was likely computed with non-zero strategyParams or salt.');
  console.log('\nTo fix stealer proofs, you need ONE of:');
  console.log('  A) The exact (strategyParams[8], salt) values used at registration');
  console.log('  B) Re-register with a known preimage (zeros+fixed salt) if allowed');
  console.log('  C) Accept -2 penalty per turn until commitment is known');
  console.log('\nWhat was the salt used when you registered the stealer commitment?');
  console.log('Check if there is a registration receipt or the original registration script.');
}

// Also compute what the commitment WOULD be for all-zeros to show the correct value
console.log('\n--- Correct commitment for all-zeros inputs ---');
const allZeros9 = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
try {
  const correctHash = poseidonHash(allZeros9);
  console.log(`Poseidon([0,0,0,0,0,0,0,0, 0]) = ${correctHash}`);
  console.log(`As hex: 0x${BigInt(correctHash).toString(16)}`);
  console.log('');
  console.log('If you can re-register with this commitment, use:');
  console.log('  strategyParams: [0,0,0,0,0,0,0,0]');
  console.log('  salt: 0');
  console.log(`  commitment: 0x${BigInt(correctHash).toString(16)}`);
} catch (e) {
  console.log(`Error computing: ${e.message}`);
}
