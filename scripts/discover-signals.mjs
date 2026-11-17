#!/usr/bin/env node
/**
 * Reads snarkjs's own witness_calculator source to extract the exact FNV hash
 * function and wasm calling convention, then brute-forces all circuit signal names.
 *
 * Usage:
 *   node scripts/discover-signals.mjs keeper
 *   node scripts/discover-signals.mjs stealer
 */

import { readFileSync, existsSync, readdirSync } from 'fs';
import { createRequire } from 'module';
import { dirname, join } from 'path';

const require = createRequire(import.meta.url);

// ---- Find snarkjs witness_calculator source on this machine ----
function findSnarkjsWC() {
  try {
    const snarkjsEntry = require.resolve('snarkjs');
    const snarkjsDir = dirname(snarkjsEntry);
    // Search up and around for witness_calculator.js
    const candidates = [
      join(snarkjsDir, 'witness_calculator.js'),
      join(snarkjsDir, '..', 'src', 'witness_calculator.js'),
      join(snarkjsDir, 'src', 'witness_calculator.js'),
      join(snarkjsDir, '..', 'build', 'witness_calculator.js'),
    ];
    for (const p of candidates) {
      if (existsSync(p)) return p;
    }
    // Scan the snarkjs package directory
    const files = readdirSync(snarkjsDir).filter(f => f.includes('witness') || f.includes('calculator'));
    if (files.length) return join(snarkjsDir, files[0]);
  } catch {}
  return null;
}

const wcPath = findSnarkjsWC();
console.log('snarkjs witness_calculator:', wcPath ?? 'NOT FOUND');

// ---- Extract the FNV hash function from snarkjs source ----
let hashFn = null;
if (wcPath) {
  const src = readFileSync(wcPath, 'utf8');
  console.log('\n--- FNV hash code from snarkjs ---');
  // Find the fnvHash function
  const match = src.match(/function fnvHash[\s\S]{0,800}?(?=\nfunction|\nexport|\nmodule|$)/);
  if (match) console.log(match[0]);

  // Extract how setInputSignal is called
  const setMatch = src.match(/setInputSignal[\s\S]{0,300}?(?=\n\s*\})/);
  if (setMatch) {
    console.log('\n--- setInputSignal usage ---');
    console.log(setMatch[0].slice(0, 400));
  }
}

// ---- Exact circom FNV-1a 64-bit hash (from snarkjs witness_calculator.js) ----
// setInputSignal is called as: setInputSignal(harray[0], harray[1], pos)
// where harray[0] = low 32 bits, harray[1] = bits 32-63 of the 64-bit hash
function fnvHash(str) {
  const uint64_max = 2n ** 64n;
  let hash = 0xCBF29CE484222325n;
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash = (hash * 0x100000001B3n) % uint64_max;
  }
  const harray = [];
  let rem = hash;
  for (let i = 0; i < 4; i++) {
    harray.push(Number(rem & 0xFFFFFFFFn));
    rem >>= 32n;
  }
  return { h0: harray[0], h1: harray[1], harray };
}

console.log('\n--- FNV hash test ---');
// Test with a known signal name
const testHash = fnvHash('decision');
console.log('fnvHash("decision"):', `lo=0x${testHash.lo.toString(16)} hi=0x${testHash.hi.toString(16)} full=0x${testHash.full.toString(16)}`);

// ---- Build wasm instance ----
const CONFIGS = {
  keeper: {
    label: 'KEEPER (gatekeeper)',
    wasm: 'packages/alpines-keeper/circuits/gatekeeper.wasm',
    zkey: 'packages/alpines-keeper/circuits/gatekeeper_final.zkey',
    expectedInputs: 13,
  },
  stealer: {
    label: 'STEALER (vfy-policy)',
    wasm: 'packages/alpines-stealer/circuits/steal.wasm',
    zkey: 'packages/alpines-stealer/circuits/steal_final.zkey',
    expectedInputs: 17,
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

// Write a 32-byte zero to shared RW memory (field element = 0)
function writeZeroFieldElement(exp, memory) {
  const sharedStart = exp.getSharedRWMemoryStart();
  const n32 = exp.getFieldNumLen32();
  const mem32 = new Uint32Array(memory.buffer);
  for (let i = 0; i < n32; i++) mem32[(sharedStart >> 2) + i] = 0;
}

async function discoverSignals(cfg) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(cfg.label);
  console.log('='.repeat(60));

  if (!existsSync(cfg.wasm)) { console.log('SKIP: wasm not found'); return; }

  let exp, memory;
  try {
    ({ exp, memory } = await buildWasm(cfg.wasm));
    exp.init(0);
  } catch(e) {
    console.log('Wasm error:', e.message); return;
  }

  const n32 = exp.getFieldNumLen32();
  const sharedStart = exp.getSharedRWMemoryStart();
  const inputSize = exp.getInputSize();
  console.log(`n32=${n32} sharedStart=${sharedStart} inputSize=${inputSize}`);

  // ---- Probe each candidate signal name ----
  const candidates = [
    // Keeper
    'decision','approve','reject','valid','allow','gate','pass','result','verdict',
    'amount','value','payment','transfer','sum','balance','price',
    'recipient','to','receiver','address','addr','beneficiary','dest',
    'deadline','expiry','expiration','timeout','timestamp','ttl','due',
    'min_amount','max_amount','minimum','maximum','threshold','floor','cap',
    'rule_hash','policy_hash','nonce','salt','commitment','challenge','seed',
    // Stealer
    'action','move','choice','play','strategy','policy','step',
    'turn','round','tick','phase','epoch','index','sequence',
    'my_balance','opponent_balance','my_score','opponent_score','score',
    'strategy_hash','commitment_hash','agent_hash','policy_commitment',
    'total_turns','match_id','match_id_hash','player','opponent','agent',
    'fortify','extract','hold','attack','defend',
    // Generic
    'in','out','x','y','a','b','c','n','k','r','s','t','v','w',
    ...Array.from({length:20},(_,i)=>`in${i}`),
    ...Array.from({length:10},(_,i)=>`input${i}`),
    ...Array.from({length:8},(_,i)=>`signal${i}`),
  ];

  const found = [];
  const mem32 = new Uint32Array(memory.buffer);

  for (const name of candidates) {
    const { h0, h1 } = fnvHash(name);

    // Write 0 field element to shared RW memory before calling setInputSignal
    writeZeroFieldElement(exp, memory);

    let matched = false;

    // Convention A: setInputSignal(h0, h1, pos) - exact snarkjs calling convention
    if (!matched) {
      try {
        exp.setInputSignal(h0, h1, 0);
        let size = 1;
        try { size = exp.getInputSignalSize(h0, h1); } catch {}
        if (typeof size !== 'number' || size <= 0 || size > 10000) size = 1;
        found.push({ name, size, conv: 'set(h0,h1)' });
        matched = true;
      } catch {}
    }
    // Convention B: reversed h1, h0
    if (!matched) {
      try {
        writeZeroFieldElement(exp, memory);
        exp.setInputSignal(h1, h0, 0);
        let size = 1;
        try { size = exp.getInputSignalSize(h1, h0); } catch {}
        if (typeof size !== 'number' || size <= 0 || size > 10000) size = 1;
        found.push({ name, size, conv: 'set(h1,h0)' });
        matched = true;
      } catch {}
    }
    // Convention C: getInputSignalSize(h0, h1) directly
    if (!matched) {
      try {
        const size = exp.getInputSignalSize(h0, h1);
        if (typeof size === 'number' && size > 0 && size < 10000) {
          found.push({ name, size, conv: 'size(h0,h1)' });
          matched = true;
        }
      } catch {}
    }
  }

  console.log(`\nFound ${found.length} signal(s):`);
  found.forEach(({ name, size, conv }) => console.log(`  "${name}" size=${size} [${conv}]`));

  // ---- Try snarkjs proof with discovered signals ----
  if (!existsSync(cfg.zkey)) { console.log('No zkey, skipping proof'); return; }
  const snarkjs = await import('snarkjs').then(m => m.default ?? m);
  const inputs = {};
  for (const { name, size } of found) {
    inputs[name] = size === 1 ? 0 : Array(size).fill(0);
  }

  console.log('\nAttempting proof with:', JSON.stringify(inputs));
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, cfg.wasm, cfg.zkey);
    console.log('\n*** SUCCESS! ***');
    console.log('publicSignals:', JSON.stringify(publicSignals));
    console.log('\nWINNING INPUTS:');
    console.log(JSON.stringify(inputs, null, 2));
  } catch(e) {
    const msg = (e.message ?? '').split('\n')[0];
    console.log('Proof failed:', msg);
    // Try snarkjs's OWN probe: pass signals one by one using snarkjs
    console.log('\nFalling back to snarkjs witness probe...');
    await snarkjsProbeEach(snarkjs, cfg, found);
  }
}

// Use snarkjs to test what happens when we pass one signal at a time
async function snarkjsProbeEach(snarkjs, cfg, alreadyFound) {
  for (const { name, size } of alreadyFound) {
    const inputs = { [name]: size === 1 ? 0 : Array(size).fill(0) };
    try {
      await snarkjs.groth16.fullProve(inputs, cfg.wasm, cfg.zkey);
      console.log(`"${name}": SUCCESS alone!`);
    } catch(e) {
      const msg = (e.message ?? '').split('\n')[0].slice(0,100);
      console.log(`"${name}": ${msg}`);
    }
  }
}

const target = process.argv[2];
const toRun = target ? [target] : Object.keys(CONFIGS);
for (const name of toRun) {
  if (!CONFIGS[name]) { console.error('Unknown:', name); process.exit(1); }
  await discoverSignals(CONFIGS[name]);
}
