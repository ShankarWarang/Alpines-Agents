#!/usr/bin/env node
/**
 * Brute-force circuit input discovery.
 * Tests single signals at every common array size to find valid inputs.
 *
 * Usage:
 *   node scripts/probe-circuit.mjs keeper
 *   node scripts/probe-circuit.mjs stealer
 */

import { existsSync } from 'fs';

const snarkjs = await import('snarkjs').then(m => m.default ?? m);

const CONFIGS = {
  keeper: {
    wasm: 'packages/alpines-keeper/circuits/gatekeeper.wasm',
    zkey: 'packages/alpines-keeper/circuits/gatekeeper_final.zkey',
    // Signals we confirmed EXIST (caused "Too many values" = wrong size, not missing)
    // Signals that failed IMMEDIATELY on first = likely wrong name
    knownSignals: ['decision', 'amount', 'recipient', 'deadline', 'min_amount'],
    unknownSignals: ['approve', 'gate', 'in'],
  },
  stealer: {
    wasm: 'packages/alpines-stealer/circuits/steal.wasm',
    zkey: 'packages/alpines-stealer/circuits/steal_final.zkey',
    knownSignals: ['action', 'turn', 'my_balance', 'opponent_balance', 'strategy_hash'],
    unknownSignals: ['policy', 'move', 'in'],
  },
};

const target = process.argv[2];
if (!target || !CONFIGS[target]) {
  console.error('Usage: node scripts/probe-circuit.mjs keeper|stealer');
  process.exit(1);
}

const cfg = CONFIGS[target];
if (!existsSync(cfg.wasm)) { console.error('WASM not found:', cfg.wasm); process.exit(1); }
if (!existsSync(cfg.zkey)) { console.error('zkey not found:', cfg.zkey); process.exit(1); }

console.log(`\n=== Circuit Probe: ${target} ===\n`);

// Step 1: find the correct size for each known signal
// "Too many values for input signal X" = X exists but size is wrong
// Try size 1, then arrays of common circom sizes

const SIZES = [1, 2, 8, 16, 32, 48, 64, 128, 253, 254, 256];

async function tryInput(inputs) {
  try {
    await snarkjs.groth16.fullProve(inputs, cfg.wasm, cfg.zkey);
    return { ok: true };
  } catch (e) {
    return { ok: false, msg: e.message ?? String(e) };
  }
}

function makeArray(size, val = 0) {
  return Array(size).fill(val);
}

console.log('--- Probing signal sizes (using one signal at a time) ---\n');

for (const sigName of cfg.knownSignals) {
  process.stdout.write(`Signal "${sigName}": `);

  // Try scalar first
  let r = await tryInput({ [sigName]: 0 });
  if (!r.msg?.includes('Too many values')) {
    // Either success (!) or a different error (signal doesn't exist or other issue)
    if (r.ok) { console.log('SCALAR - SUCCESS!'); continue; }
    if (r.msg?.includes('Signal') && r.msg?.includes('not found')) {
      console.log('NOT FOUND (wrong name)');
      continue;
    }
    console.log(`scalar -> ${r.msg?.split('\n')[0].slice(0,80)}`);
    continue;
  }

  // "Too many values" - it's an array, find size
  let found = false;
  for (const size of SIZES) {
    r = await tryInput({ [sigName]: makeArray(size) });
    if (r.ok) {
      console.log(`ARRAY[${size}] - SUCCESS (complete proof with just this signal!)`);
      found = true;
      break;
    }
    if (!r.msg?.includes('Too many values') && !r.msg?.includes('not set')) {
      // Different error = size was accepted but other signals missing
      if (r.msg?.includes('not set') || r.msg?.includes('not assigned') || r.msg?.includes('Input') ) {
        console.log(`ARRAY[${size}] - size accepted (other signals still needed): ${r.msg?.split('\n')[0].slice(0,60)}`);
        found = true;
        break;
      }
      console.log(`ARRAY[${size}] -> ${r.msg?.split('\n')[0].slice(0,80)}`);
      found = true;
      break;
    }
  }
  if (!found) console.log(`unknown size (tried ${SIZES.join(',')})`);
}

console.log('\n--- Trying complete input sets ---\n');

// Step 2: once we know sizes, try complete proof
// Common circom pattern: timestamps as 32-bit, amounts as 64-bit, addresses as 160-bit

const KEEPER_TRIES = [
  { label: 'All scalars (0)',
    inputs: { decision: 0, amount: 0, recipient: 0, deadline: 0, min_amount: 0 } },
  { label: 'decision scalar + others as 32-bit arrays',
    inputs: { decision: 0, amount: makeArray(32), recipient: makeArray(32), deadline: makeArray(32), min_amount: makeArray(32) } },
  { label: 'decision scalar + amount/recipient 64-bit + deadline 32-bit + min_amount 64-bit',
    inputs: { decision: 0, amount: makeArray(64), recipient: makeArray(64), deadline: makeArray(32), min_amount: makeArray(64) } },
  { label: 'All 64-bit arrays',
    inputs: { decision: makeArray(64), amount: makeArray(64), recipient: makeArray(64), deadline: makeArray(64), min_amount: makeArray(64) } },
  { label: 'decision 1-bit + amount 64 + recipient 160 + deadline 32 + min_amount 64',
    inputs: { decision: makeArray(1), amount: makeArray(64), recipient: makeArray(160), deadline: makeArray(32), min_amount: makeArray(64) } },
];

const STEALER_TRIES = [
  { label: 'All scalars (0)',
    inputs: { action: 0, turn: 0, my_balance: 0, opponent_balance: 0, strategy_hash: 0 } },
  { label: 'action scalar + others 32-bit',
    inputs: { action: 0, turn: makeArray(32), my_balance: makeArray(32), opponent_balance: makeArray(32), strategy_hash: makeArray(32) } },
  { label: 'action scalar + turn scalar + balances 64-bit + hash 254-bit',
    inputs: { action: 0, turn: 0, my_balance: makeArray(64), opponent_balance: makeArray(64), strategy_hash: makeArray(254) } },
  { label: 'All 64-bit arrays',
    inputs: { action: makeArray(64), turn: makeArray(64), my_balance: makeArray(64), opponent_balance: makeArray(64), strategy_hash: makeArray(64) } },
];

const tries = target === 'keeper' ? KEEPER_TRIES : STEALER_TRIES;

for (const { label, inputs } of tries) {
  process.stdout.write(`  [?] ${label}\n      `);
  const r = await tryInput(inputs);
  if (r.ok) {
    console.log('SUCCESS!');
    console.log('\nWINNING INPUTS:');
    console.log(JSON.stringify(inputs, null, 2));
    process.exit(0);
  }
  console.log(`FAIL: ${r.msg?.split('\n')[0].slice(0,100)}`);
}

console.log('\nProbe inconclusive. Run inspect-circuit.mjs for metadata.');
