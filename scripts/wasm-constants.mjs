#!/usr/bin/env node
/**
 * Search steal.wasm for the hardcoded field element constant used at line 90.
 * Output is saved to scripts/wasm-constants-output.txt so it can be committed from VPS.
 *
 * Run on VPS: node scripts/wasm-constants.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM_PATH = 'packages/alpines-stealer/circuits/steal.wasm';
const OUT_PATH  = 'scripts/wasm-constants-output.txt';
const BN128_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const REGISTERED = BigInt('0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e');
const REGISTERED_MODP = REGISTERED % BN128_P;

// --- Tee logger: stdout + buffer for file ---
const buf_lines = [];
function say(msg = '') {
  const s = String(msg);
  process.stdout.write(s + '\n');
  buf_lines.push(s);
}
function saveOutput() {
  writeFileSync(OUT_PATH, buf_lines.join('\n') + '\n', 'utf-8');
  process.stdout.write(`\n[Output saved to ${OUT_PATH}]\n`);
}

say('=== WASM Constant Finder ===');
say('Registered commitment:  0x' + REGISTERED.toString(16));
say('Registered mod BN128_P: 0x' + REGISTERED_MODP.toString(16));
say('BN128_P:                0x' + BN128_P.toString(16));
say('');

const wasm = readFileSync(WASM_PATH);
say(`WASM size: ${wasm.length} bytes`);
say('');

// Scan for 8-limb (256-bit) little-endian uint32 field elements embedded in wasm bytecode
const seen = new Map();
for (let i = 0; i <= wasm.length - 32; i++) {
  let val = 0n;
  for (let j = 7; j >= 0; j--) {
    val = (val << 32n) | BigInt(wasm.readUInt32LE(i + j * 4));
  }
  if (val > 0n && val < BN128_P * 2n) {
    const key = val.toString(16);
    if (!seen.has(key)) seen.set(key, { val, offset: i });
  }
}
say(`Found ${seen.size} candidate 256-bit values in WASM.`);

// Check known values
const registeredHex  = REGISTERED.toString(16);
const registeredMPHex = REGISTERED_MODP.toString(16);
say('');
say(seen.has(registeredHex)  ? '*** REGISTERED (exact) found in WASM at offset ' + seen.get(registeredHex).offset  : 'REGISTERED (exact): NOT found in WASM');
say(seen.has(registeredMPHex) ? '*** REGISTERED mod P found in WASM at offset ' + seen.get(registeredMPHex).offset  : 'REGISTERED mod P:   NOT found in WASM');

// Print field-element-sized constants (> 2^200) — these are circuit constants
const large = [...seen.values()]
  .filter(c => c.val > (1n << 200n) && c.val < BN128_P)
  .sort((a, b) => a.offset - b.offset);

say('');
say(`Field-element constants (> 2^200, < BN128_P): ${large.length}`);
for (const { val, offset } of large) {
  const hex = '0x' + val.toString(16).padStart(64, '0');
  const tag = val === REGISTERED_MODP ? ' <-- REGISTERED mod P !!!'
            : val === REGISTERED      ? ' <-- REGISTERED (exact) !!!'
            : '';
  say(`  offset=${String(offset).padStart(8)}: ${hex}${tag}`);
}

// Cross-check with Poseidon hashes
const require = createRequire(import.meta.url);
try {
  const circo = require('circomlibjs');
  const poseidon = await circo.buildPoseidon();
  const F = poseidon.F;
  const P = (...args) => BigInt(F.toString(poseidon(args.map(BigInt))));

  const zeros8 = [0n,0n,0n,0n,0n,0n,0n,0n];
  const knownHashes = {
    [P(...zeros8, 0n).toString()]: 'Poseidon(zeros8, salt=0) 9-input',
    [P(...zeros8).toString()]:     'Poseidon(zeros8) 8-input',
    [P(0n).toString()]:            'Poseidon(0) 1-input',
    [P(0n, ...zeros8).toString()]: 'Poseidon(0, zeros8) salt-first',
  };

  say('');
  say('--- Poseidon cross-check ---');
  let anyMatch = false;
  for (const { val, offset } of large) {
    const h = val.toString();
    if (knownHashes[h]) {
      say(`  MATCH at offset ${offset}: wasm constant = ${knownHashes[h]}`);
      anyMatch = true;
    }
  }
  if (!anyMatch) say('  No wasm constant matches known Poseidon(zeros) hashes.');

  // If REGISTERED_MODP is in wasm, search for its Poseidon preimage with small inputs
  if (large.some(c => c.val === REGISTERED_MODP)) {
    say('');
    say('  REGISTERED_MODP IS in WASM - searching Poseidon preimage (1 input, 0..9999)...');
    let found = false;
    for (let x = 0n; x < 10000n; x++) {
      if (P(x) === REGISTERED_MODP) {
        say(`  Poseidon(${x}) = REGISTERED_MODP! This is the preimage!`);
        found = true; break;
      }
    }
    if (!found) say('  No single-input Poseidon preimage found in 0..9999.');
  }
} catch (e) {
  say('(circomlibjs unavailable: ' + e.message + ')');
  say('Run: npm install circomlibjs --no-save');
}

say('');
say('Done.');
saveOutput();
