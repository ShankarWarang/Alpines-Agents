#!/usr/bin/env node
/**
 * Search steal.wasm for the hardcoded field element constant used at line 90.
 *
 * In circom WASM, circuit constants are stored as arrays of 32-bit limbs (little-endian).
 * This script reads the wasm binary and reports all candidate 256-bit field elements,
 * then checks them against our known values.
 *
 * Run on VPS: node scripts/wasm-constants.mjs
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM_PATH = 'packages/alpines-stealer/circuits/steal.wasm';
const BN128_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Known values
const REGISTERED = BigInt('0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e');
const REGISTERED_MODP = REGISTERED % BN128_P;

console.log('=== WASM Constant Finder ===\n');
console.log('Registered commitment:   0x' + REGISTERED.toString(16));
console.log('Registered mod BN128_P:  0x' + REGISTERED_MODP.toString(16));
console.log('BN128_P:                 0x' + BN128_P.toString(16));
console.log('');

const buf = readFileSync(WASM_PATH);
console.log(`WASM size: ${buf.length} bytes\n`);

// Strategy 1: scan for 8-limb (256-bit) little-endian uint32 sequences
// representing field elements. In circom WASM, constants appear as
// sequences of 8 x 32-bit words (little-endian).
const candidates = new Map();

for (let i = 0; i <= buf.length - 32; i++) {
  // Read 8 x uint32 LE = 256-bit number
  let val = 0n;
  for (let j = 7; j >= 0; j--) {
    val = (val << 32n) | BigInt(buf.readUInt32LE(i + j * 4));
  }
  if (val > 0n && val < BN128_P * 2n) {
    const hex = '0x' + val.toString(16).padStart(64, '0');
    if (!candidates.has(hex)) {
      candidates.set(hex, { val, offset: i });
    }
  }
}

console.log(`Found ${candidates.size} candidate 256-bit values in WASM.\n`);

// Check for our known values
const registeredHex = '0x' + REGISTERED.toString(16).padStart(64, '0');
const registeredModPHex = '0x' + REGISTERED_MODP.toString(16).padStart(64, '0');

if (candidates.has(registeredHex)) {
  console.log('✓ Found REGISTERED commitment in WASM at offset:', candidates.get(registeredHex).offset);
}
if (candidates.has(registeredModPHex)) {
  console.log('✓ Found REGISTERED mod P in WASM at offset:', candidates.get(registeredModPHex).offset);
}

// Print all large candidates (likely field element constants, not code)
// Filter: value > 2^200 suggests a real field element, not a small index
const largeCandidates = [...candidates.values()]
  .filter(c => c.val > (1n << 200n) && c.val < BN128_P)
  .sort((a,b) => a.offset - b.offset);

console.log(`\nField-element-sized constants (> 2^200) found in WASM: ${largeCandidates.length}`);
for (const { val, offset } of largeCandidates) {
  const hex = '0x' + val.toString(16).padStart(64, '0');
  const isReg = val === REGISTERED_MODP ? ' *** = REGISTERED mod P ***' : '';
  const isReg2 = val === REGISTERED ? ' *** = REGISTERED (exact) ***' : '';
  console.log(`  offset=${offset}: ${hex}${isReg}${isReg2}`);
}

// Strategy 2: also try poseidon hash of the found constants (reverse lookup)
// - if constant C is in wasm and Poseidon(X) == C for small X, then X is a signal preimage
const require = createRequire(import.meta.url);
let poseidon;
try {
  const circo = require('circomlibjs');
  poseidon = await circo.buildPoseidon();
  const F = poseidon.F;
  const P = (...args) => BigInt(F.toString(poseidon(args.map(BigInt))));

  console.log('\n--- Cross-checking constants against Poseidon of zeros ---');
  const zeros8 = [0n,0n,0n,0n,0n,0n,0n,0n];
  const knownHashes = new Map([
    [P(...zeros8, 0n), 'Poseidon(zeros8, salt=0) [9 inputs]'],
    [P(...zeros8),     'Poseidon(zeros8) [8 inputs]'],
    [P(0n),            'Poseidon(0) [1 input]'],
  ]);

  for (const { val } of largeCandidates) {
    if (knownHashes.has(val)) {
      console.log(`  MATCH: wasm constant = ${knownHashes.get(val)}`);
    }
  }

  // Also: if the REGISTERED_MODP is in wasm, try to find its Poseidon preimage with small values
  if (largeCandidates.some(c => c.val === REGISTERED_MODP)) {
    console.log('\n  REGISTERED_MODP is in WASM! Searching for Poseidon preimage...');
    // Try small single-input values
    for (let x = 0n; x < 1000n; x++) {
      if (P(x) === REGISTERED_MODP) {
        console.log(`  Poseidon(${x}) = REGISTERED_MODP! Use strategyParams[?]=${x} and 1-input hash`);
        break;
      }
    }
  }
} catch (e) {
  console.log('\n(circomlibjs not available for cross-check: ' + e.message + ')');
}

console.log('\nDone. Use the constants above to identify what line 90 is checking.');
