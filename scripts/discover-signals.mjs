#!/usr/bin/env node
/**
 * Automated circuit signal discovery using exact circom wasm API.
 * Instantiates wasm directly, probes signal names via FNV-1a hash.
 *
 * IMPORTANT: setInputSignal(h1, h0, pos) - h1 is HIGH 32 bits, h0 is LOW 32 bits.
 * This is confirmed correct for both circuits.
 *
 * Usage:
 *   node scripts/discover-signals.mjs keeper
 *   node scripts/discover-signals.mjs stealer
 *
 * CONFIRMED KEEPER SIGNALS (all scalars, inputSize=13):
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   decision, taskId, salt
 *
 * CONFIRMED STEALER SIGNALS (inputSize=17):
 *   commitment(1), matchId(1), turnNumber(1), selfBalance(1),
 *   opponentBalance(1), action(1), amount(1), circuitVersion(1),
 *   [unknown-name](8), salt(1)
 */

import { readFileSync, existsSync } from 'fs';

// ---- Exact circom FNV-1a 64-bit hash ----
// setInputSignal(h1, h0, pos) - h1=high32, h0=low32
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
    // ALL 13 signals confirmed
    confirmed: [
      'registeredVkHash','proofVkHash','minimum','publicBalance','expiryBlock',
      'currentBlock','recipient','conditionRecipient','amount','maxTransfer',
      'decision','taskId','salt',
    ],
  },
  stealer: {
    label: 'STEALER (vfy-policy)',
    wasm: 'packages/alpines-stealer/circuits/steal.wasm',
    zkey: 'packages/alpines-stealer/circuits/steal_final.zkey',
    // 9 of 10 signals confirmed (array name still unknown)
    confirmed: [
      'commitment','matchId','turnNumber','selfBalance','opponentBalance',
      'action','amount','circuitVersion','salt',
      // unknown size=8 array at idx=10, hash=0xc07a189808b648c2
    ],
  },
};

// Extended candidate list for probing new signals
const CANDIDATES = [
  // Keeper confirmed
  'registeredVkHash','proofVkHash','minimum','publicBalance','expiryBlock',
  'currentBlock','recipient','conditionRecipient','amount','maxTransfer',
  'decision','taskId','salt',
  // Stealer confirmed
  'commitment','matchId','turnNumber','selfBalance','opponentBalance',
  'action','circuitVersion',
  // Additional candidates to probe
  'strategy','history','pathElements','policy','secret','private',
  'strategyArray','strategyData','strategyBits','strategyWords',
  'policyData','policyInputs','policyBits',
  ...Array.from({length:16},(_,i)=>`in${i}`),
  ...Array.from({length:8},(_,i)=>`input${i}`),
  ...Array.from({length:8},(_,i)=>`hash${i}`),
];

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

  // Verify confirmed signals
  if (cfg.confirmed?.length) {
    console.log(`\nVerifying ${cfg.confirmed.length} confirmed signals:`);
    for (const name of cfg.confirmed) {
      const { h0, h1 } = fnvHash(name);
      writeZero(exp, memory);
      try {
        exp.setInputSignal(h1, h0, 0);  // h1 first (high 32 bits), h0 second (low 32 bits)
        let size = 1;
        try {
          const s = exp.getInputSignalSize(h1, h0);
          if (typeof s === 'number' && s > 0 && s < 10000) size = s;
        } catch {}
        process.stdout.write(`  OK: "${name}" size=${size}\n`);
      } catch(e) {
        process.stdout.write(`  MISS: "${name}" (${e.message.slice(0,40)})\n`);
      }
    }
  }

  // Probe for additional signals
  console.log('\nProbing for additional/unknown signals...');
  const foundNew = [];
  const confirmedSet = new Set(cfg.confirmed ?? []);
  for (const name of CANDIDATES) {
    if (confirmedSet.has(name)) continue;
    const { h0, h1 } = fnvHash(name);
    writeZero(exp, memory);
    try {
      exp.setInputSignal(h1, h0, 0);
      let size = 1;
      try {
        const s = exp.getInputSignalSize(h1, h0);
        if (typeof s === 'number' && s > 0 && s < 10000) size = s;
      } catch {}
      foundNew.push({ name, size });
      process.stdout.write(`  NEW: "${name}" size=${size}\n`);
    } catch {}
  }

  if (foundNew.length === 0) console.log('  (no new signals found)');

  const totalConfirmed = (cfg.confirmed?.length ?? 0) + foundNew.length;
  console.log(`\nTotal signals found: ${totalConfirmed} / ${inputSize}`);
}

const target = process.argv[2];
const toRun = target ? [target] : Object.keys(CONFIGS);
for (const name of toRun) {
  if (!CONFIGS[name]) { console.error('Unknown agent:', name); process.exit(1); }
  await discoverSignals(CONFIGS[name]);
}
