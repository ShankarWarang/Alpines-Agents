#!/usr/bin/env node
/**
 * Stealer line-90 probe v2 — one-hot strategy selector hypothesis.
 *
 * Key observations from previous probes:
 *   - params[0]=1   → line 149 (params[0] has special gate)
 *   - params[4-7]=1 → lines 75-78 (per-element range checks, must stay 0)
 *   - Everything else → line 90 fires universally
 *
 * NEW HYPOTHESIS:
 *   params[0..3] is a one-hot strategy-type selector.
 *   Line 90 may require: exactly one of params[0..3] is non-zero,
 *   OR params[0] must equal 1 and params[1..3] control sub-params.
 *
 * Also tests:
 *   - circuitVersion = 0, 2, 3 (maybe baked into circuit)
 *   - Pedersen / SHA256 hash instead of Poseidon
 *   - strategyParams size != 8 (try named variants)
 *   - commitment passed as mod-P reduction
 *   - strategy_hash as a string hash (keccak/sha256) of "0x00..."
 *
 * Output is saved to scripts/probe-line90-v2-output.txt for git commit.
 *
 * Run: node scripts/probe-line90-v2.mjs
 */
import { existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
const OUT  = 'scripts/probe-line90-v2-output.txt';

if (!existsSync(WASM) || !existsSync(ZKEY)) {
  console.error('No circuit files at', WASM, '/', ZKEY);
  process.exit(1);
}

// Init output file
writeFileSync(OUT, '=== probe-line90-v2 ===\n');
function log(msg) {
  process.stdout.write(msg + '\n');
  appendFileSync(OUT, msg + '\n');
}

const snarkjs = await import('snarkjs').then(m => m.default ?? m);
const require  = createRequire(import.meta.url);
const circom   = require('circomlibjs');
const poseidon = await circom.buildPoseidon();
const F        = poseidon.F;
const P        = (...a) => BigInt(F.toString(poseidon(a.map(BigInt))));

// BN128 prime
const BN128_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function tryProof(label, inputs) {
  process.stdout.write(`  [?] ${label} ... `);
  appendFileSync(OUT, `  [?] ${label} ... `);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    const result = `PROOF SUCCESS!\n      publicSignals: ${JSON.stringify(publicSignals)}`;
    log(result);
    return true;
  } catch (e) {
    const line = (e.message ?? '').match(/line: (\d+)/)?.[1] ?? '?';
    const msg  = `FAIL line ${line}`;
    log(msg);
    return false;
  }
}

// base input builder
const z8 = Array(8).fill(0n);
const mk  = (params, salt) => P(...params, salt); // Poseidon(params[8], salt) = 9 inputs

function base(commitment, params, salt, overrides = {}) {
  return {
    commitment,
    matchId:         1n,
    turnNumber:      1n,
    selfBalance:     100n,
    opponentBalance: 100n,
    action:          2n,
    amount:          0n,
    circuitVersion:  1n,
    strategyParams:  params,
    salt,
    ...overrides,
  };
}

log('\n=== Group I: One-hot strategy selector (params[0..3]) ===');
log('Hypothesis: exactly one of params[0..3] must be 1\n');

// params[0]=1 hits line 149 normally, BUT that might be because commitment was wrong.
// Now try params[k]=1 WITH correctly computed commitment.
for (let k = 0; k <= 3; k++) {
  const params = [...z8]; params[k] = 1n;
  const c = mk(params, 0n);
  const done = await tryProof(`one-hot params[${k}]=1, commitment=Poseidon(params,0)`, base(c, params, 0n));
  if (done) { log('\nSOLUTION FOUND: one-hot params[' + k + ']=1'); process.exit(0); }
}

log('\n=== Group J: circuitVersion variants ===');
{
  const c = mk(z8, 0n);
  for (const v of [0n, 2n, 3n, 4n, 100n, 1000n]) {
    const done = await tryProof(`circuitVersion=${v}`, base(c, z8, 0n, { circuitVersion: v }));
    if (done) { log('\nSOLUTION FOUND: circuitVersion=' + v); process.exit(0); }
  }
}

log('\n=== Group K: commitment as SHA-256 of zeros ===');
{
  // Maybe commitment is sha256(strategyParams.join('')) mod P
  const h = createHash('sha256').update(Buffer.alloc(8 * 32)).digest();
  const sha256Val = BigInt('0x' + h.toString('hex')) % BN128_P;
  log(`  sha256(zeros256) mod P = 0x${sha256Val.toString(16)}`);
  const done = await tryProof('commitment=sha256(zeros) mod P', base(sha256Val, z8, 0n));
  if (done) { log('\nSOLUTION FOUND: sha256 commitment'); process.exit(0); }
}

log('\n=== Group L: commitment = mod-P reduction of registered value ===');
{
  const REGISTERED = 0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3en;
  const reduced = REGISTERED % BN128_P;
  log(`  registered mod P = 0x${reduced.toString(16)}`);
  // Try with BOTH commitment=reduced AND trying to find params/salt that hash to reduced
  {
    const done = await tryProof('commitment=registered_mod_P, params=zeros, salt=0', base(reduced, z8, 0n));
    if (done) { log('\nSOLUTION FOUND: reduced commitment with zeros'); process.exit(0); }
  }
  // Brute force: does any single-element non-zero param produce reduced as Poseidon output?
  for (let k = 0; k < 8; k++) {
    for (const v of [1n, 2n, reduced]) {
      const params = [...z8]; params[k] = v;
      const c = P(...params, 0n);
      if (c === reduced) {
        log(`  MATCH: params[${k}]=${v} → Poseidon == reduced`);
        const done = await tryProof(`params[${k}]=${v} → commitment=reduced`, base(reduced, params, 0n));
        if (done) { log('\nSOLUTION FOUND'); process.exit(0); }
      }
    }
  }
}

log('\n=== Group M: MiMCSponge hash ===');
try {
  const mimc = await circom.buildMimcSponge();
  const mimcHash = (...inputs) => BigInt(mimc.F.toString(mimc.multiHash(inputs.map(BigInt))));
  
  const c9 = mimcHash(...z8, 0n);  // 9 inputs
  const c8 = mimcHash(...z8);       // 8 inputs
  log(`  MiMC(zeros8, 0) 9-input = 0x${c9.toString(16)}`);
  log(`  MiMC(zeros8) 8-input    = 0x${c8.toString(16)}`);
  
  for (const [label, c] of [['MiMC(zeros8,0) 9-input', c9], ['MiMC(zeros8) 8-input', c8]]) {
    const done = await tryProof(label, base(c, z8, 0n));
    if (done) { log('\nSOLUTION FOUND: MiMC'); process.exit(0); }
  }
} catch (e) { log('  MiMC unavailable: ' + e.message); }

log('\n=== Group N: Poseidon with different round constants / domain separation ===');
{
  // Maybe domain tag is prepended: Poseidon([domain_tag, params[8], salt])
  for (const tag of [0n, 1n, 2n, 0x12345678n]) {
    const inputs = [tag, ...z8, 0n]; // 10 inputs: tag + 8 params + salt
    const c = P(...inputs);
    const done = await tryProof(`Poseidon(tag=${tag}, zeros8, 0) 10-input`, base(c, z8, 0n));
    if (done) { log('\nSOLUTION FOUND: domain tag=' + tag); process.exit(0); }
  }
  // Also Poseidon(salt, params[8]) - salt first
  const c2 = P(0n, ...z8); // 9 inputs: salt + params
  const done2 = await tryProof('Poseidon(salt=0, zeros8) salt-first', base(c2, z8, 0n));
  if (done2) { log('\nSOLUTION FOUND: salt-first Poseidon'); process.exit(0); }
}

log('\n=== Group O: Extract WASM signal for line 90 — test minimal valid witness ===');
log('  Testing commitment=0 (zero commitment) which the circuit might accept as "no commitment"');
{
  // Some circuits let commitment=0 bypass the check (sentinel value)
  const done = await tryProof('commitment=0 (sentinel), params=zeros, salt=0', base(0n, z8, 0n));
  if (done) { log('\nSOLUTION FOUND: zero commitment'); process.exit(0); }
}
{
  // Try commitment=1 (identity element)
  const done = await tryProof('commitment=1, params=zeros, salt=0', base(1n, z8, 0n));
  if (done) { log('\nSOLUTION FOUND: commitment=1'); process.exit(0); }
}

log('\n=== Group P: params[0] = circuitVersion (maybe commitment links circuitVersion) ===');
{
  // strategyParams[0] = circuitVersion (1) and commitment = Poseidon(params, salt)
  const params = [1n, ...z8.slice(1)]; // params[0]=1
  const c = mk(params, 0n);
  const done = await tryProof('params[0]=circuitVersion=1, commitment=Poseidon(params,0)', base(c, params, 0n, { circuitVersion: 1n }));
  if (done) { log('\nSOLUTION FOUND: params[0]=circuitVersion'); process.exit(0); }
}

log('\n=== Group Q: params[0] as action value (maybe policy encodes allowed actions) ===');
{
  for (const actionVal of [0n, 1n, 2n]) {
    const params = [actionVal, ...z8.slice(1)];
    const c = mk(params, 0n);
    const done = await tryProof(`params[0]=action=${actionVal}, commitment=Poseidon(params,0)`, base(c, params, 0n, { action: actionVal }));
    if (done) { log('\nSOLUTION FOUND: params[0] mirrors action'); process.exit(0); }
  }
}

log('\n=== All probes exhausted ===');
log('Line 90 constraint source is still unknown. Stealer plays without proof (-2/turn).');
log('Run keeper now: it works fully and earns positive score.');
log(`\nOutput saved to: ${OUT}`);
