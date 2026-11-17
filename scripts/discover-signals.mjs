#!/usr/bin/env node
/**
 * Fully automated circuit signal discovery.
 *
 * How it works:
 *   1. Instantiate wasm with exact known imports
 *   2. For every candidate signal name, compute its FNV hash and call
 *      setInputSignal() - success = signal exists, exception = doesn't
 *   3. Collect all valid signals + their sizes via getInputSignalSize()
 *   4. Generate a full proof with all signals set to 0 to confirm
 *
 * Usage:
 *   node scripts/discover-signals.mjs keeper
 *   node scripts/discover-signals.mjs stealer
 *   node scripts/discover-signals.mjs          # both
 */

import { readFileSync, existsSync } from 'fs';

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

// ---- FNV-1a 32-bit (what circom uses) ----
function fnv1a32(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

// ---- FNV-1 64-bit split as [hMsb, hLsb] (alternate hash some circom versions use) ----
function fnv164(str) {
  let hLo = 2166136261, hHi = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    hLo ^= c;
    // Multiply by FNV prime 16777619 as 64-bit
    const lo = Math.imul(hLo, 16777619) >>> 0;
    const hi = (Math.imul(hHi, 16777619) + Math.imul(hLo >>> 16, 256)) >>> 0;
    hLo = lo; hHi = hi;
  }
  return [hHi >>> 0, hLo >>> 0]; // [MSB, LSB]
}

// ---- Build wasm instance with exact imports ----
async function buildWasm(wasmPath) {
  const buf = readFileSync(wasmPath);
  const memory = new WebAssembly.Memory({ initial: 32767, maximum: 32767 });
  const sharedRW = new Int32Array(memory.buffer);
  let msgBuf = '';

  const imports = {
    env: { memory },
    runtime: {
      exceptionHandler(code) {
        throw new Error(`WasmException:${code}`);
      },
      printErrorMessage() {
        // Read null-terminated string from shared memory
        let p = 0, str = '';
        while (sharedRW[p] !== 0 && p < 1024) str += String.fromCharCode(sharedRW[p++]);
        // Don't throw - just note it
      },
      writeBufferMessage() { msgBuf = ''; },
      showSharedRWMemory() {},
    },
  };

  const result = await WebAssembly.instantiate(buf, imports);
  return { exp: result.instance.exports, memory, sharedRW };
}

// ---- Probe a single signal name ----
function probeSignal(exp, name) {
  // Try both 32-bit hash (single arg) and 64-bit hash (two args)
  const h32 = fnv1a32(name);
  const [hMsb, hLsb] = fnv164(name);

  // getInputSignalSize: check if the signal exists and get its size
  if (typeof exp.getInputSignalSize === 'function') {
    try {
      // Try with 32-bit hash (1 arg)
      const size1 = exp.getInputSignalSize(h32);
      if (size1 > 0 && size1 < 10000) return { exists: true, size: size1, hashType: 'fnv32' };
    } catch {}
    try {
      // Try with 64-bit hash split (2 args: MSB, LSB)
      const size2 = exp.getInputSignalSize(hMsb, hLsb);
      if (size2 > 0 && size2 < 10000) return { exists: true, size: size2, hashType: 'fnv64' };
    } catch {}
  }

  // Fallback: try setInputSignal with a zero value and see if it throws "not found"
  if (typeof exp.setInputSignal === 'function') {
    // Write 0 to shared RW memory position 0 (the value)
    try {
      exp.setInputSignal(h32, 0, 0);
      return { exists: true, size: 1, hashType: 'fnv32-set' };
    } catch (e) {
      if (!e.message?.includes('WasmException')) {
        try {
          exp.setInputSignal(hMsb, hLsb, 0);
          return { exists: true, size: 1, hashType: 'fnv64-set' };
        } catch {}
      }
    }
  }

  return { exists: false };
}

// ---- Exhaustive candidate list ----
function getCandidates() {
  return [
    // Keeper / gatekeeper
    'decision', 'approve', 'reject', 'valid', 'allow', 'gate', 'pass', 'result',
    'amount', 'value', 'payment', 'transfer', 'sum', 'balance',
    'recipient', 'to', 'receiver', 'address', 'addr', 'beneficiary',
    'deadline', 'expiry', 'expiration', 'timeout', 'timestamp', 'ttl',
    'min_amount', 'max_amount', 'minimum', 'maximum', 'threshold',
    'rule_hash', 'policy_hash', 'nonce', 'salt', 'commitment', 'challenge',
    'proof_hash', 'vk_hash', 'task_id', 'round',
    // Stealer / vfy-policy
    'action', 'move', 'choice', 'play', 'strategy', 'policy',
    'turn', 'step', 'tick', 'phase', 'epoch',
    'my_balance', 'opponent_balance', 'my_score', 'opponent_score',
    'strategy_hash', 'commitment_hash', 'agent_hash', 'policy_commitment',
    'total_turns', 'match_id', 'match_id_hash', 'player', 'opponent',
    'fortify', 'extract', 'hold',
    // Generic
    'in', 'out', 'x', 'y', 'a', 'b', 'c', 'n', 'k', 'r', 's',
    'input', 'output', 'signal', 'public_input', 'private_input',
    // Indexed variants
    ...Array.from({length: 20}, (_, i) => `in${i}`),
    ...Array.from({length: 10}, (_, i) => `input${i}`),
    ...Array.from({length: 5}, (_, i) => `amount${i}`),
    ...Array.from({length: 5}, (_, i) => `hash${i}`),
  ];
}

async function discoverSignals(cfg) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(cfg.label);
  console.log('='.repeat(60));

  if (!existsSync(cfg.wasm)) { console.log('SKIP: wasm not found'); return null; }

  // ---- Step 1: Instantiate wasm ----
  let exp;
  try {
    const w = await buildWasm(cfg.wasm);
    exp = w.exp;
    console.log('Wasm loaded OK');
    console.log('Exports:', Object.keys(exp).filter(k => typeof exp[k] === 'function').join(', '));
  } catch (e) {
    console.log('Wasm load error:', e.message);
    return null;
  }

  // ---- Step 2: Init ----
  try {
    exp.init(0);
    console.log('init(0) OK');
  } catch(e) {
    console.log('init error:', e.message);
  }

  // Query metadata
  const inputSize = typeof exp.getInputSize === 'function' ? exp.getInputSize() : 'N/A';
  const witnessSize = typeof exp.getWitnessSize === 'function' ? exp.getWitnessSize() : 'N/A';
  console.log(`getInputSize()=${inputSize}  getWitnessSize()=${witnessSize}`);

  // ---- Step 3: Probe all candidates ----
  console.log('\nProbing signal names...');
  const found = [];
  for (const name of getCandidates()) {
    const result = probeSignal(exp, name);
    if (result.exists) {
      found.push({ name, size: result.size, hashType: result.hashType });
      console.log(`  FOUND: "${name}" (size=${result.size}, hash=${result.hashType})`);
    }
  }

  if (found.length === 0) {
    console.log('No signals found via hash probe. Falling back to snarkjs proof attempt...');
  }

  console.log(`\nTotal found: ${found.length} signal(s)`);
  console.log('Signals:', found.map(f => `${f.name}[${f.size}]`).join(', '));

  // ---- Step 4: Try generating a proof with discovered signals ----
  if (found.length > 0 && existsSync(cfg.zkey)) {
    const snarkjs = await import('snarkjs').then(m => m.default ?? m);
    const inputs = {};
    for (const { name, size } of found) {
      inputs[name] = size === 1 ? 0 : Array(size).fill(0);
    }
    console.log('\nAttempting proof with discovered inputs:', JSON.stringify(inputs));
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, cfg.wasm, cfg.zkey);
      console.log('\n*** PROOF SUCCESS! ***');
      console.log('nPublicSignals:', publicSignals.length);
      console.log('publicSignals:', JSON.stringify(publicSignals));
      console.log('\nWINNING INPUTS:');
      console.log(JSON.stringify(inputs, null, 2));
    } catch(e) {
      console.log('Proof failed:', (e.message ?? '').split('\n')[0]);
    }
  }

  return found;
}

const target = process.argv[2];
const toRun = target ? [target] : Object.keys(CONFIGS);
for (const name of toRun) {
  if (!CONFIGS[name]) { console.error('Unknown agent:', name); process.exit(1); }
  await discoverSignals(CONFIGS[name]);
}
