#!/usr/bin/env node
/**
 * Auto-discover circuit input signals by passing {} and reading
 * snarkjs error messages that name each missing required signal.
 *
 * Usage:
 *   node scripts/discover-signals.mjs keeper
 *   node scripts/discover-signals.mjs stealer
 *   node scripts/discover-signals.mjs        # both
 */

import { existsSync } from 'fs';

const snarkjs = await import('snarkjs').then(m => m.default ?? m);

const CONFIGS = {
  keeper: {
    label: 'KEEPER (gatekeeper)',
    wasm: 'packages/alpines-keeper/circuits/gatekeeper.wasm',
    zkey: 'packages/alpines-keeper/circuits/gatekeeper_final.zkey',
    nPublic: 13,
  },
  stealer: {
    label: 'STEALER (vfy-policy)',
    wasm: 'packages/alpines-stealer/circuits/steal.wasm',
    zkey: 'packages/alpines-stealer/circuits/steal_final.zkey',
    nPublic: 9,
  },
};

async function discoverSignals(cfg) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`${cfg.label} - nPublic=${cfg.nPublic}`);
  console.log('='.repeat(60));

  if (!existsSync(cfg.wasm)) { console.log('SKIP: wasm not found'); return; }
  if (!existsSync(cfg.zkey)) { console.log('SKIP: zkey not found'); return; }

  const inputs = {};
  let lastError = '';

  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, cfg.wasm, cfg.zkey);
      console.log('\nSUCCESS! Full proof generated!');
      console.log('nPublic check: got', publicSignals.length, 'public signals (expected', cfg.nPublic, ')');
      console.log('\nPublic signals:', JSON.stringify(publicSignals, null, 2));
      console.log('\n*** WINNING INPUTS ***');
      console.log(JSON.stringify(inputs, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));
      return inputs;
    } catch (e) {
      const msg = e.message ?? String(e);
      if (msg === lastError) { console.log('Stuck on same error, breaking'); break; }
      lastError = msg;

      // Pattern 1: "Signal X is not set"
      let sigName = msg.match(/[Ss]ignal\s+"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+(?:is )?not set/)?.[1];
      // Pattern 2: "Input signal X"
      if (!sigName) sigName = msg.match(/[Ii]nput\s+(?:signal\s+)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+(?:is )?not/)?.[1];
      // Pattern 3: "not assigned" 
      if (!sigName) sigName = msg.match(/"([a-zA-Z_][a-zA-Z0-9_]*)"\s+(?:was )?not (?:set|assigned)/)?.[1];
      // Pattern 4: "Signal X" at start
      if (!sigName) sigName = msg.match(/^Signal\s+([a-zA-Z_][a-zA-Z0-9_]*)/)?.[1];
      // Pattern 5: "Too many values for input signal X" - it's array, set to [0]
      const tooMany = msg.match(/Too many values for input signal ([a-zA-Z_][a-zA-Z0-9_]*)/)?.[1];

      if (tooMany) {
        // Find the right array size
        console.log(`[${attempt+1}] "${tooMany}" is array type - finding size...`);
        let sized = false;
        for (const size of [1, 2, 8, 16, 32, 64, 128, 160, 254, 256]) {
          try {
            const testInputs = { ...inputs, [tooMany]: Array(size).fill(0) };
            await snarkjs.groth16.fullProve(testInputs, cfg.wasm, cfg.zkey);
            inputs[tooMany] = Array(size).fill(0);
            console.log(`  -> "${tooMany}": array[${size}]`);
            sized = true; break;
          } catch(e2) {
            const m2 = e2.message ?? '';
            if (!m2.includes('Too many values')) {
              inputs[tooMany] = Array(size).fill(0);
              console.log(`  -> "${tooMany}": array[${size}] (accepted, other signals still needed)`);
              sized = true; break;
            }
          }
        }
        if (!sized) { console.log(`  -> could not determine size for "${tooMany}"`); break; }
      } else if (sigName) {
        console.log(`[${attempt+1}] Missing signal: "${sigName}" -> setting to 0`);
        inputs[sigName] = 0;
      } else {
        console.log(`[${attempt+1}] Unrecognized error:\n  ${msg.split('\n').slice(0,4).join('\n  ')}`);
        break;
      }
    }
  }

  console.log('\nDiscovered inputs so far:', JSON.stringify(inputs, null, 2));
  return inputs;
}

const target = process.argv[2];
const toRun = target ? [target] : Object.keys(CONFIGS);

for (const name of toRun) {
  if (!CONFIGS[name]) { console.error('Unknown:', name); process.exit(1); }
  await discoverSignals(CONFIGS[name]);
}
