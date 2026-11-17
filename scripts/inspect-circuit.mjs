#!/usr/bin/env node
/**
 * Deep circom wasm introspector.
 * Instantiates the wasm, queries exported circuit metadata functions,
 * and brute-forces signal names via FNV-1a hash lookup.
 *
 * Usage:
 *   node scripts/inspect-circuit.mjs <path-to.wasm>
 */

import { readFileSync } from 'fs';

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error('Usage: node scripts/inspect-circuit.mjs <path-to.wasm>');
  process.exit(1);
}

const buf = readFileSync(wasmPath);

// ---- FNV-1a hash (same as circom uses for signal name lookup) ----
function fnv1a(str) {
  let hash = 0x811c9dc5n;
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash = (hash * 0x01000193n) & 0xFFFFFFFFn;
  }
  return Number(hash);
}

// ---- Instantiate wasm with required imports ----
const memory = new WebAssembly.Memory({ initial: 32767, maximum: 32767 });
const sharedMem = new Int32Array(memory.buffer);
let msgBuf = '';

const imports = {
  env: { memory },
  runtime: {
    error(code, pstr, a, b, c, d) {
      let str = '';
      let p = pstr;
      while (sharedMem[p >> 2] !== 0) { str += String.fromCharCode(sharedMem[p >> 2] & 0xff); p++; }
      console.error(`WASM error ${code}: ${str} (${a},${b},${c},${d})`);
    },
    log(a) { console.log('WASM log:', a); },
    logGetSignal(signal, pVal) {},
    logSetSignal(signal, pVal) {},
    logStartComponent(cIdx) {},
    logFinishComponent(cIdx) {},
  },
};

let wasm;
try {
  const result = await WebAssembly.instantiate(buf, imports);
  wasm = result.instance.exports;
} catch (e) {
  console.error('Failed to instantiate wasm:', e.message);
  process.exit(1);
}

console.log('\n=== Circom Circuit Introspector ===');
console.log('File:', wasmPath);
console.log('Size:', (buf.length / 1024).toFixed(1), 'KB\n');

// ---- Query circuit metadata ----
console.log('--- Circuit Metadata ---');

const fns = Object.keys(wasm);
console.log('Exported functions:', fns.filter(f => typeof wasm[f] === 'function').join(', '));

// Try standard circom wasm exports
const tryFn = (name, ...args) => {
  if (typeof wasm[name] === 'function') {
    try { return wasm[name](...args); } catch (e) { return `ERROR: ${e.message}`; }
  }
  return 'NOT EXPORTED';
};

const nVars   = tryFn('getNVars');
const nInputs = tryFn('getNInputs');
const nOutputs = tryFn('getNOutputs');
const inputStart = tryFn('getInputSignalStart');

console.log('getNVars():          ', nVars);
console.log('getNInputs():        ', nInputs);
console.log('getNOutputs():       ', nOutputs);
console.log('getInputSignalStart():', inputStart);

// ---- Get sizes of each input signal slot ----
if (typeof nInputs === 'number' && nInputs > 0) {
  console.log(`\n--- Input Signal Sizes (${nInputs} inputs) ---`);
  const sizes = [];
  for (let i = 0; i < nInputs; i++) {
    const size = tryFn('getInputSignalSize', i);
    sizes.push(size);
    console.log(`  Input[${i}]: size = ${size}`);
  }

  // ---- Brute-force signal name matching via FNV hash ----
  console.log('\n--- Signal Name Brute-Force (FNV-1a hash lookup) ---');

  const candidates = [
    // Generic
    'in','out','x','y','a','b','c','n','k','r','s','t','v','w',
    // Keeper / gatekeeper
    'decision','approve','reject','gate','valid','result','allow','pass',
    'amount','value','sum','balance','stake','fee','reward','payment',
    'recipient','to','addr','address','receiver','dest',
    'deadline','expiry','expire','timestamp','time','ttl','epoch',
    'min_amount','max_amount','minimum','maximum','threshold','limit',
    'rule_hash','rule','policy','hash','commitment','nonce','salt','seed',
    'proof','vk','vk_hash','public_input','signal',
    // Stealer / vfy-policy
    'action','move','choice','play','strategy','strategy_hash',
    'turn','round','step','tick','epoch','phase',
    'my_balance','opponent_balance','my_score','opponent_score',
    'fortify','extract','hold','attack','defend',
    'match_id','match_id_hash','player','opponent','agent',
    'total_turns','remaining','score','delta','gain','loss',
    // Bit decompositions
    'decision_bits','amount_bits','deadline_bits','value_bits',
    // Indexed variants
    'in0','in1','in2','in3','in4','in5',
    'amount0','amount1','recipient0','decision0',
  ];

  if (typeof wasm['getInputSignalMapPosition'] === 'function') {
    console.log('Using getInputSignalMapPosition for hash lookup...');
    const matched = [];
    for (const name of candidates) {
      const h = fnv1a(name);
      const pos = tryFn('getInputSignalMapPosition', h);
      if (typeof pos === 'number' && pos >= 0) {
        matched.push({ name, pos, hash: h.toString(16) });
      }
    }
    if (matched.length > 0) {
      console.log('\nMATCHED signal names:');
      matched.sort((a, b) => a.pos - b.pos).forEach(({ name, pos }) => {
        const size = typeof pos === 'number' ? tryFn('getInputSignalSize', pos) : '?';
        console.log(`  [pos=${pos}] "${name}"  (size=${size})`);
      });
    } else {
      console.log('No candidates matched. Try expanding the name list.');
    }
  } else {
    console.log('getInputSignalMapPosition not exported - trying hash table scan...');

    // Try to find the hash table in memory after init
    tryFn('init', 1);

    // Scan wasm memory for FNV hashes of our candidates
    const matched = [];
    for (const name of candidates) {
      const h = fnv1a(name);
      const hBuf = new Uint8Array(4);
      new DataView(hBuf.buffer).setUint32(0, h, true);
      // Search in memory for this hash
      const mem = new Uint8Array(memory.buffer);
      for (let i = 0; i < mem.length - 4; i++) {
        if (mem[i] === hBuf[0] && mem[i+1] === hBuf[1] && mem[i+2] === hBuf[2] && mem[i+3] === hBuf[3]) {
          matched.push({ name, offset: i, hash: h.toString(16) });
          break;
        }
      }
    }
    if (matched.length > 0) {
      console.log('\nSignal hashes found in wasm memory:');
      matched.forEach(({ name, offset, hash }) =>
        console.log(`  "${name}"  fnv=0x${hash} at offset ${offset}`));
    } else {
      console.log('Hash scan inconclusive. Trying snarkjs witness test...');
    }
  }
}

// ---- Try snarkjs fullProve with minimal valid inputs ----
console.log('\n--- snarkjs Probe (single scalar "in") ---');
try {
  const snarkjs = await import('snarkjs').then(m => m.default ?? m);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve({ in: 0 }, wasmPath, wasmPath.replace('.wasm', '_final.zkey'));
  console.log('SUCCESS with {in: 0}');
  console.log('Public signals:', publicSignals);
} catch (e) {
  // Show full error - the signal name is in here
  console.log('Error:', e.message);
}
