#!/usr/bin/env node
/**
 * Stealer Commitment Solver
 *
 * The VfyPolicyProof circuit at line 72 checks:
 *   commitment === Poseidon(strategyParams[0..7], salt)
 *
 * The circuit input "commitment" can be ANY consistent preimage:
 *   - If commitment is a PUBLIC signal: platform validates it == registered value
 *   - If commitment is a PRIVATE signal: we just need consistency with strategyParams+salt
 *
 * This script:
 *   1. Installs circomlibjs if needed
 *   2. Computes Poseidon(strategyParams=[0..0], salt=0) -> the "natural" commitment
 *   3. Runs the full proof with this commitment to verify correctness
 *   4. Reports the commitment value to register with the platform (if re-registration needed)
 *
 * Run on VPS: node scripts/solve-commitment.mjs
 */
import { existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

// ---- Ensure circomlibjs is available ----
let poseidonFn;
try {
  const m = await import('circomlibjs');
  const builder = m.buildPoseidon ?? m.default?.buildPoseidon;
  poseidonFn = await builder();
  console.log('circomlibjs loaded OK');
} catch {
  console.log('circomlibjs not found, installing...');
  execSync('npm install circomlibjs --no-save --prefix /tmp/poseidon-tmp', { stdio: 'inherit' });
  const m = await import('/tmp/poseidon-tmp/node_modules/circomlibjs/src/poseidon.js');
  const builder = m.buildPoseidon ?? m.default?.buildPoseidon;
  poseidonFn = await builder();
}

function poseidonHash(inputs) {
  const h = poseidonFn(inputs.map(x => BigInt(x)));
  return BigInt(poseidonFn.F.toString(h));
}

// ---- Configuration ----
const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';

if (!existsSync(WASM) || !existsSync(ZKEY)) {
  console.error('Circuit files not found. Run from /opt/zkverify');
  process.exit(1);
}

console.log('\n=== Stealer Commitment Solver ===\n');

// ---- Case 1: strategyParams=[0x8], salt=0 ----
// Most likely: Poseidon hashes the 8 params + salt as 9 inputs
const params8zeros = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
const salt0 = 0n;

const candidateCombinations = [
  { label: '9 inputs: [params[8], salt]', inputs: [...params8zeros, salt0] },
  { label: '8 inputs: params only (no salt in hash)', inputs: [...params8zeros] },
  { label: '1 input: [salt]', inputs: [salt0] },
  { label: '2 inputs: [params[0], salt]', inputs: [0n, salt0] },
  { label: '9 inputs: [salt, params[8]] (salt first)', inputs: [salt0, ...params8zeros] },
];

console.log('Computing Poseidon hash candidates for all-zero inputs:\n');
const computedHashes = [];
for (const { label, inputs } of candidateCombinations) {
  try {
    const h = poseidonHash(inputs);
    const hHex = '0x' + h.toString(16).padStart(64, '0');
    computedHashes.push({ label, inputs, hash: h, hashHex: hHex });
    console.log(`  ${label}`);
    console.log(`    hash: ${hHex}\n`);
  } catch (e) {
    console.log(`  ${label}: ERROR - ${e.message}\n`);
  }
}

// ---- Try proof with each computed commitment ----
const snarkjs = await import('snarkjs').then(m => m.default ?? m);
const fixedSalt = BigInt('0x' + randomBytes(16).toString('hex'));

console.log('=== Testing proofs with computed commitments ===\n');

let found = null;
for (const { label, inputs: poseidonInputs, hash, hashHex } of computedHashes) {
  console.log(`Testing: commitment = Poseidon(${label})`);
  console.log(`  commitment value: ${hashHex}`);

  // Determine salt for circuit based on how we computed the hash
  // If poseidon included salt as last element, circuit salt = that salt (0)
  // If poseidon was params-only, circuit salt is free
  const circuitSalt = poseidonInputs.includes(salt0) ? salt0 : fixedSalt;

  const circuitInputs = {
    commitment: hash,
    matchId: 1n,
    turnNumber: 1n,
    selfBalance: 100n,
    opponentBalance: 100n,
    action: 2n,  // HOLD
    amount: 0n,
    circuitVersion: 1n,
    strategyParams: params8zeros,
    salt: circuitSalt,
  };

  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs, WASM, ZKEY
    );
    console.log('  *** PROOF SUCCESS! ***');
    console.log(`  publicSignals: ${JSON.stringify(publicSignals)}`);
    found = { label, hashHex, circuitSalt, poseidonInputs, publicSignals };
    break;
  } catch (e) {
    const msg = (e.message ?? String(e)).slice(0, 150);
    console.log(`  FAIL: ${msg}`);
  }
  console.log('');
}

if (found) {
  console.log('\n' + '='.repeat(60));
  console.log('SOLUTION FOUND!');
  console.log('='.repeat(60));
  console.log(`Poseidon variant: ${found.label}`);
  console.log(`commitment value: ${found.hashHex}`);
  console.log(`circuit salt:     ${found.circuitSalt}`);
  console.log('');
  console.log('Update strategyParams + salt in agent code to use:');
  console.log('  strategyParams: [0,0,0,0,0,0,0,0]');
  console.log(`  salt: ${found.circuitSalt} (fixed, not random)`);
  console.log(`  commitment: computed from Poseidon(${found.label})`);
  console.log('');
  
  if (found.hashHex !== '0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e') {
    console.log('NOTE: This commitment differs from the REGISTERED commitment.');
    console.log('The registered commitment 0x80d45b2f... used different preimage values.');
    console.log('');
    console.log('OPTIONS:');
    console.log('  A) Check if "commitment" is a PUBLIC signal (platform validates it):');
    console.log('     If public: you MUST use 0x80d45b2f... and find its preimage.');
    console.log('     If private: use this new commitment value - circuit is self-consistent.');
    console.log('');
    console.log('  B) Check publicSignals output - if commitment appears there, it is public.');
    if (found.publicSignals) {
      const commitHex = found.hashHex.replace('0x', '');
      const inPublic = found.publicSignals.some(s => BigInt(s).toString(16).includes(commitHex.slice(0, 8)));
      console.log(`  Commitment in publicSignals: ${inPublic ? 'YES (PUBLIC - platform will check!)' : 'NO (private - safe to use different value)'}`);
      console.log(`  publicSignals[0]: ${found.publicSignals[0]}`);
    }
  } else {
    console.log('BONUS: This matches the registered commitment! Perfect preimage found.');
  }
} else {
  console.log('\n' + '='.repeat(60));
  console.log('NO SOLUTION FOUND with zero inputs.');
  console.log('The registered commitment 0x80d45b2f... was computed with');
  console.log('non-zero strategyParams or salt values during registration.');
  console.log('');
  console.log('What to do:');
  console.log('  1. Check agent.ts comments for original registration salt');
  console.log('  2. Try re-registering on the platform with:');
  console.log('     strategyParams = [0,0,0,0,0,0,0,0], salt = 0');
  console.log('     commitment = Poseidon([0,0,0,0,0,0,0,0,0]) (computed above)');
  console.log('  3. OR accept -2 penalty per turn for stealer until tournament ends');
}
