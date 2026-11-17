#!/usr/bin/env node
/**
 * Inspect circom circuit WASM to extract input signal names.
 *
 * Usage:
 *   node scripts/inspect-circuit.mjs <path-to.wasm>
 *
 * Example:
 *   node scripts/inspect-circuit.mjs packages/alpines-stealer/circuits/steal.wasm
 *   node scripts/inspect-circuit.mjs packages/alpines-keeper/circuits/gatekeeper.wasm
 */

import { readFileSync } from 'fs';

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error('Usage: node scripts/inspect-circuit.mjs <path-to.wasm>');
  process.exit(1);
}

const buf = readFileSync(wasmPath);

// circom wasm stores signal names as length-prefixed UTF-8 strings in a
// custom section named "name". We scan for the pattern and extract them.
const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);

// Strategy: find all null-terminated or length-prefixed ASCII strings
// that look like circom signal names (lowercase, underscores, digits)
const text = buf.toString('utf8');

// Extract signal-like tokens: start with letter, contain only word chars,
// 2-40 chars. Filter to plausible input signal names.
const all = new Set();
const re = /\b([a-z][a-z0-9_]{1,39})\b/g;
let m;
while ((m = re.exec(text)) !== null) {
  all.add(m[1]);
}

// Known non-signal strings to exclude
const exclude = new Set([
  'wasm', 'module', 'memory', 'table', 'export', 'import', 'function',
  'global', 'local', 'block', 'loop', 'call', 'return', 'drop', 'select',
  'unreachable', 'type', 'param', 'result', 'mut', 'end', 'else', 'then',
  'data', 'elem', 'offset', 'align', 'name', 'custom', 'section',
  'env', 'signal', 'component', 'template', 'pragma', 'circom',
  'main', 'init', 'alloc', 'free', 'copy', 'move', 'store', 'load',
  'add', 'sub', 'mul', 'div', 'mod', 'and', 'or', 'xor', 'not',
  'eq', 'ne', 'lt', 'gt', 'le', 'ge', 'shl', 'shr',
  'fn', 'in', 'is', 'as', 'by', 'to', 'of', 'at', 'on',
]);

const signals = [...all].filter(s => !exclude.has(s) && s.length >= 3);

// Score by how "circuit-input-like" each token is
const score = (s) => {
  let sc = 0;
  if (/^(action|turn|balance|hash|my_|opponent|strategy|match|round|total|score|commit|nonce|policy|stake|amount|player|state|move|choice)/.test(s)) sc += 10;
  if (/_/.test(s)) sc += 3;
  if (/[0-9]$/.test(s)) sc -= 1;
  if (s.length > 5 && s.length < 25) sc += 2;
  return sc;
};

const ranked = signals
  .map(s => ({ s, sc: score(s) }))
  .filter(x => x.sc > 0)
  .sort((a, b) => b.sc - a.sc)
  .slice(0, 30)
  .map(x => x.s);

console.log('\n=== Circuit Signal Candidates (vfy-policy.wasm) ===\n');
console.log('Top candidates (most likely circuit inputs):');
ranked.forEach(s => console.log('  -', s));

// Also try snarkjs if available
try {
  const { default: snarkjs } = await import('snarkjs');
  // snarkjs doesn't expose a direct signal-list API without full witness calc
  console.log('\nsnarkjs available - try a test witness calculation to confirm signals');
} catch {
  console.log('\nsnarkjs not available for deeper inspection');
}

console.log('\nTo confirm exact signals, try generating a proof with candidate inputs:');
console.log('  node scripts/test-proof.mjs');
