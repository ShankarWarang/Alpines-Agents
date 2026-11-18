#!/usr/bin/env node
/**
 * Final stealer commitment probe.
 *
 * Line 90 fires for all basic input variations.
 * strategyParams[0]=1 hits line 149 (special).
 * strategyParams[4-7]=1 hit lines 75-78 (range checks).
 *
 * Hypothesis: strategyParams[0] might be a "type/mode" field that
 * must be 0, and line 90 checks the relationship between commitment
 * and strategyParams[1..7] + salt (not including params[0]).
 *
 * Run: node scripts/probe-line90-final.mjs
 */
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
if (!existsSync(WASM)||!existsSync(ZKEY)){console.error('No circuit files');process.exit(1);}

const snarkjs = await import('snarkjs').then(m=>m.default??m);
const require = createRequire(import.meta.url);
const poseidon = await require('circomlibjs').buildPoseidon();
const F = poseidon.F;
const P = (...a) => BigInt(F.toString(poseidon(a.map(BigInt))));

async function tryProof(label, inputs) {
  process.stdout.write(`  [?] ${label} ... `);
  try {
    const {proof,publicSignals} = await snarkjs.groth16.fullProve(inputs,WASM,ZKEY);
    console.log('PROOF SUCCESS!');
    console.log('      publicSignals: ' + JSON.stringify(publicSignals));
    return true;
  } catch(e) {
    const line = (e.message??'').match(/line: (\d+)/)?.[1] ?? '?';
    console.log(`FAIL line ${line}`);
    return false;
  }
}

console.log('=== Final Line-90 Probe ===\n');

// Helper: build inputs with computed commitment
const mk = (params, salt) => P(...params, salt);
const z8 = [0n,0n,0n,0n,0n,0n,0n,0n];
const base = (commitment, params, salt, overrides={}) => ({
  commitment, matchId:1n, turnNumber:1n,
  selfBalance:100n, opponentBalance:100n,
  action:2n, amount:0n, circuitVersion:1n,
  strategyParams:params, salt, ...overrides
});

// --- Group A: different Poseidon arities (params[1..7] only, 7 inputs) ---
console.log('Group A: Poseidon arity variations (excluding params[0])');
{
  const p1to7 = [0n,0n,0n,0n,0n,0n,0n];
  const c = P(...p1to7, 0n); // 8 inputs: params[1..7] + salt
  const done = await tryProof('Poseidon(params[1..7], salt) 8-input', base(c, z8, 0n));
  if (done) process.exit(0);
}
{
  const c = P(...[0n,0n,0n,0n,0n,0n,0n]); // 7 inputs: params[1..7] only
  const done = await tryProof('Poseidon(params[1..7]) 7-input', base(c, z8, 0n));
  if (done) process.exit(0);
}

// --- Group B: strategyParams[0] is the commitment itself ---
// Circuit might check: strategyParams[0] == commitment (public registered value)
// and separately: commitment == Poseidon(params[1..7], salt)
console.log('\nGroup B: params[0] = commitment (public hint)');
{
  const c = mk(z8, 0n); // Poseidon(zeros8, 0) - our computable hash
  // Set params[0] = commitment value itself
  const params = [c, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
  // Now commitment must = Poseidon(params[0..7], salt) = Poseidon(c, zeros7, 0)
  const c2 = P(c, 0n,0n,0n,0n,0n,0n,0n, 0n);
  const done = await tryProof('params[0]=commitment, commitment=Poseidon(params[0..7],0)', base(c2, params, 0n));
  if (done) process.exit(0);
}

// --- Group C: MiMC instead of Poseidon ---
// Try MiMCSponge (also in circomlibjs)
console.log('\nGroup C: MiMCSponge hash');
try {
  const { buildMimcSponge } = require('circomlibjs');
  const mimc = await buildMimcSponge();
  const mimcHash = (...inputs) => BigInt(mimc.F.toString(mimc.multiHash(inputs.map(BigInt))));
  
  const c = mimcHash(...z8, 0n);
  const done = await tryProof('MiMCSponge(zeros8, salt=0)', base(c, z8, 0n));
  if (done) process.exit(0);
} catch(e) { console.log('  MiMC unavailable: ' + e.message); }

// --- Group D: What if commitment IS the registered value and line 90 checks action range ---
// Try: action must be 0,1,2 but maybe the circuit uses different encoding
console.log('\nGroup D: action encoding variants with Poseidon(zeros8,0)');
{
  const c = mk(z8, 0n);
  for (const [action, amount, label] of [
    [0n,0n,'FORTIFY=0,amount=0'],
    [1n,5n,'EXTRACT=1,amount=5'],
    [2n,0n,'HOLD=2,amount=0'],
    [3n,0n,'action=3'],
    [0n,0n,'action=0 selfBal=0 oppBal=0'],
  ]) {
    const selfBalance = label.includes('selfBal=0') ? 0n : 100n;
    const opponentBalance = label.includes('oppBal=0') ? 0n : 100n;
    const done = await tryProof(label, base(c, z8, 0n, {action, amount, selfBalance, opponentBalance}));
    if (done) process.exit(0);
  }
}

// --- Group E: Vary turnNumber vs totalTurns relationship ---
console.log('\nGroup E: turn relationships');
{
  const c = mk(z8, 0n);
  for (const [turn, label] of [
    [0n,'turn=0'],
    [20n,'turn=20'],
    [100n,'turn=100'],
  ]) {
    const done = await tryProof(label, base(c, z8, 0n, {turnNumber:turn}));
    if (done) process.exit(0);
  }
}

// --- Group F: matchId as large hash value ---
console.log('\nGroup F: matchId as large value');
{
  const c = mk(z8, 0n);
  const bigId = BigInt('0x' + 'ab'.repeat(16));
  const done = await tryProof('matchId=large hex', base(c, z8, 0n, {matchId: bigId}));
  if (done) process.exit(0);
}

// --- Group G: Try non-zero strategyParams[1..3] with recomputed commitment ---
console.log('\nGroup G: non-zero params[1..3] with consistent commitment');
{
  for (let i = 1; i <= 3; i++) {
    for (const v of [1n, 2n, 100n, 1000n]) {
      const params = [...z8]; params[i] = v;
      const c = mk(params, 0n);
      const done = await tryProof(`params[${i}]=${v} commitment=Poseidon(params,0)`, base(c, params, 0n));
      if (done) process.exit(0);
    }
  }
}

// --- Group H: Try different salt+commitment while keeping params=0 ---
console.log('\nGroup H: non-zero salt variants');
{
  for (const salt of [1n, 2n, 3n, 42n, 1000n, BigInt('0xdeadbeef')]) {
    const c = mk(z8, salt);
    const done = await tryProof(`salt=${salt}`, base(c, z8, salt));
    if (done) process.exit(0);
  }
}

console.log('\n=== All probes exhausted. Line 90 constraint is still unknown. ===');
console.log('The circuit may require a specific non-trivial preimage.');
console.log('Deploy keeper now, accept -2/turn for stealer.');
