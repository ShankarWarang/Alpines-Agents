#!/usr/bin/env node
/**
 * Decompile steal.wasm to WAT text format and extract constraint witnesses.
 *
 * Uses: wasm2wat (from wabt), or falls back to wasm-decompile.
 * Saves output to: scripts/steal-decompiled.wat (may be large)
 *
 * Also: uses snarkjs internal APIs to dump the R1CS constraint at line 90.
 *
 * Run: node scripts/decompile-wasm.mjs
 */
import { existsSync, writeFileSync } from 'node:fs';
import { execSync, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const R1CS  = 'packages/alpines-stealer/circuits/steal.r1cs';
const OUT_WAT = 'scripts/steal-circuit-info.txt';

if (!existsSync(WASM)) { console.error('No wasm:', WASM); process.exit(1); }

let out = '=== Stealer Circuit Decompile Report ===\n';
function log(msg) { process.stdout.write(msg + '\n'); out += msg + '\n'; }

// --- 1. Try wasm2wat ---
log('\n--- wasm2wat availability ---');
try {
  const v = execSync('wasm2wat --version 2>&1', { encoding: 'utf8' }).trim();
  log('wasm2wat found: ' + v);
  log('Decompiling (this may take a while)...');
  const result = spawnSync('wasm2wat', [WASM, '-o', 'scripts/steal.wat'], {
    timeout: 120000, maxBuffer: 500 * 1024 * 1024
  });
  if (result.status === 0) {
    log('WAT written to: scripts/steal.wat');
    // Extract just the first references to "assert" or constraint check patterns
    const grep = spawnSync('grep', ['-n', 'assert\\|Error\\|line\\|90', 'scripts/steal.wat'], {
      encoding: 'utf8', maxBuffer: 10 * 1024 * 1024
    });
    if (grep.stdout) {
      const lines = grep.stdout.split('\n').slice(0, 200).join('\n');
      log('\nFirst 200 grep hits for assert/Error/line/90:\n' + lines);
    }
  } else {
    log('wasm2wat failed: ' + (result.stderr?.toString() ?? ''));
  }
} catch (e) {
  log('wasm2wat not found: ' + e.message);
  log('Install with: apt-get install -y wabt');
}

// --- 2. Try wasm-decompile (wabt) ---
log('\n--- wasm-decompile availability ---');
try {
  const result = spawnSync('wasm-decompile', [WASM, '-o', 'scripts/steal-decompiled.dcmp'], {
    timeout: 120000, maxBuffer: 200 * 1024 * 1024
  });
  if (result.status === 0) {
    log('Decompile written to: scripts/steal-decompiled.dcmp');
  } else {
    log('wasm-decompile failed: ' + (result.stderr?.toString() ?? ''));
  }
} catch (e) { log('wasm-decompile not found: ' + e.message); }

// --- 3. Load R1CS and show signal info ---
log('\n--- R1CS info ---');
if (existsSync(R1CS)) {
  try {
    const req = createRequire(import.meta.url);
    const snarkjs = await import('snarkjs').then(m => m.default ?? m);
    const r1csInfo = await snarkjs.r1cs.info(R1CS);
    log('R1CS info: ' + JSON.stringify(r1csInfo, null, 2));
  } catch (e) { log('R1CS load error: ' + e.message); }
} else {
  log('No R1CS file at: ' + R1CS);
  log('Check: ' + 'packages/alpines-stealer/circuits/');
  try {
    const ls = execSync('ls packages/alpines-stealer/circuits/ 2>/dev/null', { encoding: 'utf8' });
    log('Circuit dir contents:\n' + ls);
  } catch(e) { log('Cannot list circuits dir'); }
}

// --- 4. Use snarkjs to load the witness calculator and inspect signals ---
log('\n--- Witness calculator signal names ---');
try {
  const { WitnessCalculatorBuilder } = await import('snarkjs').then(m => m.default ?? m);
  // Use circom_tester approach if available
} catch(e) { log('WC approach N/A: ' + e.message); }

// --- 5. Load wasm and find the witness calculator's internal signal map ---
log('\n--- WASM signal name extraction ---');
try {
  const wasmBytes = await import('node:fs').then(m => m.readFileSync(WASM));
  // Decode strings from the wasm binary
  const text = new TextDecoder('utf-8', { fatal: false }).decode(wasmBytes);
  
  // Find signal names (they appear as null-terminated strings in the data section)
  const signalNames = [];
  const regex = /[\x20-\x7E]{3,}/g;
  let match;
  const asciiStrings = new Set();
  while ((match = regex.exec(text)) !== null) {
    const s = match[0];
    if (s.length >= 3 && s.length <= 50 && /^[a-zA-Z]/.test(s)) {
      asciiStrings.add(s);
    }
  }
  const names = [...asciiStrings].filter(s =>
    /^[a-zA-Z][a-zA-Z0-9_]*$/.test(s) && s.length >= 3
  ).sort();
  log('Potential signal/function names in wasm binary:\n' + names.slice(0, 100).join('\n'));
  
  // Look specifically for strategy-related terms
  const strategyTerms = names.filter(n =>
    /strategy|param|commit|action|balance|salt|turn|match|version|policy|mode|type/i.test(n)
  );
  log('\nStrategy-related terms:\n' + strategyTerms.join('\n'));
  
} catch(e) { log('WASM string extraction error: ' + e.message); }

writeFileSync(OUT_WAT, out);
log('\nReport saved to: ' + OUT_WAT);
