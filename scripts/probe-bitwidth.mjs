#!/usr/bin/env node
/**
 * probe-bitwidth.mjs
 *
 * Determines the actual bit-width N of the GreaterEqThan circuit in steal.wasm.
 * Specifically tests: can we generate a valid proof when balance=100?
 *
 * If the circuit uses GreaterEqThan(N) with range-checks on inputs:
 *   - N=6: max balance = 63  → balance=100 IMPOSSIBLE
 *   - N=7: max balance = 127 → balance=100 POSSIBLE, params must be >= balance
 *   - N=8: max balance = 255 → balance=100 POSSIBLE
 *
 * Run on VPS: node scripts/probe-bitwidth.mjs
 */

import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');

const WASM = path.join(__dirname, '../packages/alpines-stealer/circuits/steal.wasm');
const ZKEY = path.join(__dirname, '../packages/alpines-stealer/circuits/steal_final.zkey');

const poseidon = await buildPoseidon();
const F = poseidon.F;

function computeCommitment(params, salt) {
  const inputs = [...params, salt];
  const h = poseidon(inputs);
  return F.toObject(h);
}

async function tryProof(label, params, selfBalance, oppBalance, action = 0n) {
  process.stdout.write(`  [?] ${label} ... `);
  try {
    const commitment = computeCommitment(params, 0n);
    const matchIdBuf = Buffer.from('61aa680ac0e2416d8ddb1005e3a3a79e', 'hex');
    const matchIdNum = BigInt('0x' + matchIdBuf.toString('hex'));
    const extractAmt = action === 2n ? 10n : 0n;

    const inputs = {
      commitment,
      matchId:         matchIdNum,
      turnNumber:      1n,
      selfBalance,
      opponentBalance: oppBalance,
      action,
      amount:          extractAmt,
      circuitVersion:  1n,
      salt:            0n,
      strategyParams:  params,
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    console.log('PROOF SUCCESS');
    return true;
  } catch (e) {
    const msg = String(e.message ?? e).split('\n')[0].slice(0, 80);
    console.log(`FAIL: ${msg}`);
    return false;
  }
}

console.log('\n=== Bit-width probe for steal.wasm GreaterEqThan ===\n');
console.log('Goal: find the max balance value the circuit can handle.\n');

// Test 1: boundary values to find N
console.log('-- Phase 1: Find the bit-width boundary --');
const tests = [
  // [label, params[0], params[1], selfBalance, oppBalance]
  ['p0=63  self=63  opp=0 ',  63n, 0n,  63n,  0n],
  ['p0=64  self=64  opp=0 ',  64n, 0n,  64n,  0n],
  ['p0=100 self=100 opp=0 ', 100n, 0n, 100n,  0n],
  ['p0=127 self=100 opp=0 ', 127n, 0n, 100n,  0n],
  ['p0=127 self=127 opp=0 ', 127n, 0n, 127n,  0n],
  ['p0=200 self=100 opp=0 ', 200n, 0n, 100n,  0n],
  ['p0=255 self=100 opp=0 ', 255n, 0n, 100n,  0n],
];

for (const [label, p0, p1, self, opp] of tests) {
  const params = [p0, p1, 0n, 0n, 0n, 0n, 0n, 0n];
  await tryProof(label, params, self, opp);
}

// Test 2: if any above passed, try full game scenario (balance=100 both sides)
console.log('\n-- Phase 2: Full game scenario (self=100, opp=100) --');
const gameTests = [
  ['p=[127,127,...] self=100 opp=100 FORTIFY', [127n,127n,0n,0n,0n,0n,0n,0n], 100n, 100n, 1n],
  ['p=[100,100,...] self=100 opp=100 FORTIFY', [100n,100n,0n,0n,0n,0n,0n,0n], 100n, 100n, 1n],
  ['p=[127,127,...] self=100 opp=100 HOLD',    [127n,127n,0n,0n,0n,0n,0n,0n], 100n, 100n, 0n],
  ['p=[127,127,...] self=100 opp=100 EXTRACT', [127n,127n,0n,0n,0n,0n,0n,0n], 100n, 100n, 2n],
];

for (const [label, params, self, opp, action] of gameTests) {
  await tryProof(label, params, self, opp, action);
}

// Test 3: if commitment with p=[127,127,...] works, print the hash to register
console.log('\n-- Phase 3: Commitment hashes for re-registration --');
const candidateParams = [
  ['[127,127,0,...] salt=0', [127n,127n,0n,0n,0n,0n,0n,0n], 0n],
  ['[100,100,0,...] salt=0', [100n,100n,0n,0n,0n,0n,0n,0n], 0n],
  ['[200,200,0,...] salt=0', [200n,200n,0n,0n,0n,0n,0n,0n], 0n],
  ['[0,0,0,...]     salt=0', [0n,0n,0n,0n,0n,0n,0n,0n], 0n],
];

for (const [label, params, salt] of candidateParams) {
  const c = computeCommitment(params, salt);
  const hex = '0x' + c.toString(16).padStart(64, '0');
  console.log(`  ${label}: ${hex}`);
}

console.log('\nDone.');
