#!/usr/bin/env node
/**
 * Circuit signal inspector using snarkjs WitnessCalculator.
 * snarkjs handles all wasm imports correctly and exposes the signal map.
 *
 * Usage:
 *   node scripts/inspect-circuit.mjs packages/alpines-keeper/circuits/gatekeeper.wasm
 *   node scripts/inspect-circuit.mjs packages/alpines-stealer/circuits/steal.wasm
 */

import { readFileSync, existsSync } from 'fs';
import { createRequire } from 'module';

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error('Usage: node scripts/inspect-circuit.mjs <path.wasm>');
  process.exit(1);
}
if (!existsSync(wasmPath)) {
  console.error('File not found:', wasmPath);
  process.exit(1);
}

console.log('\n=== Circuit Signal Inspector ===');
console.log('File:', wasmPath, '(' + (readFileSync(wasmPath).length / 1024).toFixed(1) + ' KB)\n');

// Load snarkjs and use its WitnessCalculator directly
const snarkjs = await import('snarkjs').then(m => m.default ?? m);

// snarkjs exposes WitnessCalculator via wtns.getWC or we can reach it via groth16
// Best path: use snarkjs's internal witness calculator builder
let wc;
try {
  // Try the internal path snarkjs uses
  const require = createRequire(import.meta.url);
  const snarkjsPath = require.resolve('snarkjs');
  const snarkjsDir = snarkjsPath.replace(/\/[^/]+$/, '');

  // Try loading WitnessCalculator directly
  let WC;
  const wcPaths = [
    snarkjsDir + '/witness_calculator.js',
    snarkjsDir + '/../build/witness_calculator.js',
    snarkjsDir + '/src/witness_calculator.js',
  ];
  for (const p of wcPaths) {
    if (existsSync(p)) {
      try {
        const mod = await import(p);
        WC = mod.default ?? mod.WitnessCalculator ?? mod;
        if (typeof WC === 'function') { console.log('Loaded WitnessCalculator from:', p); break; }
      } catch {}
    }
  }

  if (typeof WC === 'function') {
    const wasmBuf = readFileSync(wasmPath);
    wc = await WC(wasmBuf);
    console.log('WitnessCalculator loaded successfully\n');
  }
} catch (e) {
  console.log('Direct WC load failed:', e.message);
}

if (wc) {
  // Dump everything we can from the witness calculator
  console.log('--- WitnessCalculator properties ---');
  for (const key of Object.keys(wc)) {
    const val = wc[key];
    if (typeof val !== 'function') {
      if (key === 'witnessMap' || key === 'inputSignalHandles' || key === 'signalValues') {
        console.log(`${key}: Map/Object with ${typeof val === 'object' ? Object.keys(val).length : '?'} entries`);
        if (val && typeof val === 'object') {
          Object.entries(val).slice(0, 20).forEach(([k, v]) => console.log(`  ${k}: ${JSON.stringify(v)}`));
        }
      } else {
        console.log(`${key}:`, typeof val === 'bigint' ? val.toString() : val);
      }
    }
  }

  // Try to access signal names via the wasm instance's exports
  if (wc.instance?.exports) {
    const exp = wc.instance.exports;
    console.log('\nWasm exports:', Object.keys(exp).join(', '));
    const getNInputs = exp.getNInputs ?? exp.getInputSize;
    if (getNInputs) console.log('nInputs:', getNInputs());
  }
} else {
  // Fallback: use snarkjs groth16.fullProve with a Proxy to intercept signal access
  console.log('Falling back to signal-name probe via error messages...\n');
}

// ---- Always run: probe signal names by reading snarkjs error messages ----
// snarkjs error "Signal X not found" or "Too many values for input signal X"
// tells us exactly which signals exist and their expected sizes.

console.log('\n--- Signal Probe via snarkjs ---');

// FNV-1a hash (same as circom witness calculator uses)
function fnv1a(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 16777619) >>> 0;
  }
  return h;
}

const candidateNames = [
  // Gatekeeper candidates
  'decision','approve','reject','gate','valid','result','allow',
  'amount','value','payment','sum','balance','transfer',
  'recipient','to','receiver','addr','address','beneficiary',
  'deadline','expiry','expiration','timeout','timestamp',
  'min_amount','max_amount','minimum','maximum','threshold',
  'rule_hash','policy_hash','commitment','nonce','salt',
  // Stealer candidates
  'action','move','choice','play','strategy','policy',
  'turn','round','step','tick','phase','epoch',
  'my_balance','opponent_balance','my_score','opponent_score',
  'strategy_hash','commitment_hash','agent_hash',
  'total_turns','match_id','match_id_hash',
  // Generic
  'in','out','x','a','b','c','n','k',
];

const zkeyPath = wasmPath.replace('.wasm', '_final.zkey');
if (!existsSync(zkeyPath)) {
  console.log('zkey not found at', zkeyPath, '- skipping proof probe');
  process.exit(0);
}

// Test each signal name alone with scalar 0
const signalInfo = {};
for (const name of candidateNames) {
  try {
    await snarkjs.groth16.fullProve({ [name]: 0 }, wasmPath, zkeyPath);
    signalInfo[name] = { exists: true, size: 1, complete: true };
  } catch (e) {
    const msg = e.message ?? String(e);
    if (msg.includes('Too many values')) {
      // Signal exists, is array type - find size
      signalInfo[name] = { exists: true, size: 'array', msg: msg.split('\n')[0] };
    } else if (msg.includes('not set') || msg.includes('not assigned') || msg.includes('input') && !msg.includes('not found')) {
      // Signal accepted but circuit needs more inputs
      signalInfo[name] = { exists: true, size: 1, complete: false };
    } else if (msg.includes('not found') || msg.includes('Signal') && msg.includes('not')) {
      signalInfo[name] = { exists: false };
    } else {
      signalInfo[name] = { exists: 'maybe', msg: msg.split('\n')[0].slice(0, 80) };
    }
  }
}

const found = Object.entries(signalInfo).filter(([, v]) => v.exists === true || v.exists === 'maybe');
const notFound = Object.entries(signalInfo).filter(([, v]) => v.exists === false);

console.log('\nSIGNALS FOUND:');
found.forEach(([name, info]) => {
  const sizeStr = info.size === 'array' ? '(array - wrong size)' : info.size === 1 ? '(scalar)' : '';
  console.log(`  "${name}" ${sizeStr}`);
});

console.log('\nSIGNALS NOT FOUND (wrong name):');
notFound.slice(0, 15).forEach(([name]) => console.log(`  "${name}"`));

console.log('\n--- For array signals, checking sizes ---');
const arraySigs = found.filter(([, v]) => v.size === 'array').map(([n]) => n);
for (const name of arraySigs) {
  for (const size of [1, 8, 16, 32, 64, 128, 160, 254, 256]) {
    try {
      await snarkjs.groth16.fullProve({ [name]: Array(size).fill(0) }, wasmPath, zkeyPath);
      console.log(`  "${name}": array of size ${size} (complete proof!)`);
      break;
    } catch (e) {
      const msg = e.message ?? '';
      if (!msg.includes('Too many values')) {
        console.log(`  "${name}": array size ${size} accepted (${msg.split('\n')[0].slice(0, 60)})`);
        break;
      }
    }
  }
}
