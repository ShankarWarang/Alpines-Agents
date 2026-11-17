#!/usr/bin/env node
/**
 * Automated circuit signal discovery using exact circom wasm API.
 * Instantiates wasm directly, probes signal names via FNV-1a hash,
 * then generates a proof to confirm.
 *
 * Usage:
 *   node scripts/discover-signals.mjs keeper
 *   node scripts/discover-signals.mjs stealer
 */

import { readFileSync, existsSync } from 'fs';

// ---- Exact circom FNV-1a 64-bit hash (from snarkjs witness_calculator.js) ----
// setInputSignal(h0, h1, pos) where h0=harray[0], h1=harray[1]
function fnvHash(str) {
  const uint64_max = 2n ** 64n;
  let hash = 0xCBF29CE484222325n;
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash = (hash * 0x100000001B3n) % uint64_max;
  }
  const h0 = Number(hash & 0xFFFFFFFFn);
  const h1 = Number((hash >> 32n) & 0xFFFFFFFFn);
  return { h0, h1 };
}

const CONFIGS = {
  keeper: {
    label: 'KEEPER (gatekeeper)',
    wasm: 'packages/alpines-keeper/circuits/gatekeeper.wasm',
    zkey: 'packages/alpines-keeper/circuits/gatekeeper_final.zkey',
  },
  stealer: {
    label: 'STEALER (vfy-policy)',
    wasm: 'packages/alpines-stealer/circuits/steal.wasm',
    zkey: 'packages/alpines-stealer/circuits/steal_final.zkey',
  },
};

async function buildWasm(wasmPath) {
  const buf = readFileSync(wasmPath);
  const memory = new WebAssembly.Memory({ initial: 32767, maximum: 32767 });
  const result = await WebAssembly.instantiate(buf, {
    env: { memory },
    runtime: {
      exceptionHandler(code) { throw new Error(`WE:${code}`); },
      printErrorMessage() {},
      writeBufferMessage() {},
      showSharedRWMemory() {},
    },
  });
  return { exp: result.instance.exports, memory };
}

function writeZero(exp, memory) {
  const start = exp.getSharedRWMemoryStart();
  const n32 = exp.getFieldNumLen32();
  const mem = new Uint32Array(memory.buffer);
  for (let i = 0; i < n32; i++) mem[(start >> 2) + i] = 0;
}

const CANDIDATES = [
  // Keeper / gatekeeper
  'decision','approve','reject','valid','allow','gate','pass','result','verdict',
  'amount','value','payment','transfer','sum','price',
  'recipient','to','receiver','address','addr','beneficiary','dest',
  'deadline','expiry','expiration','timeout','timestamp','ttl','due',
  'min_amount','max_amount','minimum','maximum','threshold','floor','cap',
  'rule_hash','policy_hash','nonce','salt','commitment','challenge','seed',
  // Stealer / vfy-policy
  'action','move','choice','play','strategy','policy','step',
  'turn','round','tick','phase','epoch','index','sequence',
  'my_balance','opponent_balance','my_score','opponent_score','score','balance',
  'strategy_hash','commitment_hash','agent_hash','policy_commitment',
  'total_turns','match_id','match_id_hash','player','opponent','agent',
  'fortify','extract','hold','attack','defend',
  // Generic
  'in','out','x','y','a','b','c','n','k','r','s',
  ...Array.from({length:16},(_,i)=>`in${i}`),
  ...Array.from({length:8},(_,i)=>`input${i}`),
];

async function discoverSignals(cfg) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(cfg.label);
  console.log('='.repeat(60));

  if (!existsSync(cfg.wasm)) { console.log('SKIP: wasm not found'); return; }

  const { exp, memory } = await buildWasm(cfg.wasm);
  exp.init(0);

  const inputSize  = exp.getInputSize();
  const witnessSize = exp.getWitnessSize();
  console.log(`inputSize=${inputSize}  witnessSize=${witnessSize}`);

  // ---- Probe each candidate ----
  const found = [];
  for (const name of CANDIDATES) {
    const { h0, h1 } = fnvHash(name);
    writeZero(exp, memory);
    try {
      exp.setInputSignal(h0, h1, 0);
      // No throw = signal exists. Query its size.
      let size = 1;
      try {
        const s = exp.getInputSignalSize(h0, h1);
        if (typeof s === 'number' && s > 0 && s < 10000) size = s;
      } catch {}
      found.push({ name, size });
      process.stdout.write(`  FOUND: "${name}" size=${size}\n`);
    } catch {
      // Signal not found - expected for most names
    }
  }

  console.log(`\nTotal: ${found.length} signal(s) found`);
  console.log('Signals:', found.map(f=>`${f.name}[${f.size}]`).join(', '));

  // ---- Attempt proof ----
  if (!existsSync(cfg.zkey)) { console.log('No zkey, skipping proof'); return; }

  const snarkjs = await import('snarkjs').then(m => m.default ?? m);
  const inputs = Object.fromEntries(
    found.map(({name, size}) => [name, size === 1 ? 0 : Array(size).fill(0)])
  );

  console.log('\nAttempting proof with discovered inputs...');
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, cfg.wasm, cfg.zkey);
    console.log('\n*** PROOF SUCCESS! ***');
    console.log('publicSignals:', JSON.stringify(publicSignals));
    console.log('\nWINNING INPUTS:');
    console.log(JSON.stringify(inputs, null, 2));
  } catch(e) {
    console.log('Proof attempt:', (e.message ?? '').split('\n')[0].slice(0, 120));
  }
}

const target = process.argv[2];
const toRun = target ? [target] : Object.keys(CONFIGS);
for (const name of toRun) {
  if (!CONFIGS[name]) { console.error('Unknown agent:', name); process.exit(1); }
  await discoverSignals(CONFIGS[name]);
}
