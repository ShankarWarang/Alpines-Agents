#!/usr/bin/env node
/**
 * Stealer line-90 probe v3 — FOCUSED sweep based on Group Q findings.
 *
 * KEY FINDING from v1/v2:
 *   - params[0]=0  → ALWAYS line 90 (params[0] must be non-zero)
 *   - params[0]=1, action=1 → line 140
 *   - params[0]=1, action=2 → line 149
 *   - params[0]=2, action=2 → line 149
 *
 * UNTESTED (most promising combos):
 *   - params[0]=1, action=0 (FORTIFY)
 *   - params[0]=2, action=0, action=1
 *   - params[0]=3,4,5 with any action
 *
 * HYPOTHESIS: params[0] is a "policy type" that must be non-zero.
 *   - Line 90: params[0] must be in {1..N}
 *   - Line 140/149: action-specific policy constraints for certain params[0] values
 *   - action=0 (FORTIFY) may be unconditionally allowed for any policy type
 *
 * Output: scripts/probe-line90-v3-output.txt
 * Run: node scripts/probe-line90-v3.mjs
 */
import { existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const WASM = 'packages/alpines-stealer/circuits/steal.wasm';
const ZKEY = 'packages/alpines-stealer/circuits/steal_final.zkey';
const OUT  = 'scripts/probe-line90-v3-output.txt';

if (!existsSync(WASM) || !existsSync(ZKEY)) {
  console.error('No circuit files at', WASM); process.exit(1);
}

writeFileSync(OUT, '=== probe-line90-v3 ===\n');
function log(msg) {
  process.stdout.write(msg + '\n');
  appendFileSync(OUT, msg + '\n');
}

const snarkjs = await import('snarkjs').then(m => m.default ?? m);
const req     = createRequire(import.meta.url);
const poseidon = await req('circomlibjs').buildPoseidon();
const F = poseidon.F;
const P = (...a) => BigInt(F.toString(poseidon(a.map(BigInt))));

const z8 = Array(8).fill(0n);

async function tryProof(label, inputs) {
  process.stdout.write(`  [?] ${label} ... `);
  appendFileSync(OUT, `  [?] ${label} ... `);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    const msg = `PROOF SUCCESS!\n      publicSignals: ${JSON.stringify(publicSignals)}`;
    log(msg);
    return { ok: true, publicSignals };
  } catch (e) {
    const line = (e.message ?? '').match(/line: (\d+)/)?.[1] ?? '?';
    const templates = [...(e.message ?? '').matchAll(/template (\w+)/g)].map(m => m[1]).join(',');
    log(`FAIL line ${line}  [${templates}]`);
    return { ok: false, line, templates };
  }
}

function mkInputs(p0, action, amount, selfBalance, opponentBalance, salt, overrides = {}) {
  const params = [p0, ...z8.slice(1)];  // params[0]=p0, rest zero
  const commitment = P(...params, salt);
  return {
    commitment,
    matchId:         1n,
    turnNumber:      1n,
    selfBalance,
    opponentBalance,
    action,
    amount,
    circuitVersion:  1n,
    strategyParams:  params,
    salt,
    ...overrides,
  };
}

// ======= GROUP R: Grid sweep — params[0] in {1..6} × action in {0,1,2} =======
log('\n=== Group R: Grid sweep params[0] × action (the critical untested combos) ===\n');

let found = null;
for (const p0 of [1n, 2n, 3n, 4n, 5n, 6n]) {
  for (const [action, actionName, amount] of [
    [0n, 'FORTIFY', 0n],
    [1n, 'EXTRACT', 10n],
    [2n, 'HOLD',    0n],
  ]) {
    const r = await tryProof(
      `params[0]=${p0} action=${actionName}(${action}) amount=${amount}`,
      mkInputs(p0, action, amount, 100n, 100n, 0n)
    );
    if (r.ok) {
      found = { p0, action, amount };
      log(`\n*** SOLUTION: params[0]=${p0}, action=${action}, amount=${amount} ***`);
    }
  }
}

if (found) {
  log('\n=== Verifying solution with real-looking values ===');
  const r = await tryProof('Verification with realistic inputs', mkInputs(
    found.p0, found.action, found.amount,
    100n, 80n, 0n,
    { matchId: 42n, turnNumber: 5n }
  ));
  if (r.ok) {
    log('\nSOLUTION CONFIRMED. Applying to agent.ts now.');
    log(`Set: strategyParams[0]=${found.p0}, action=${found.action}`);
  }
  process.exit(0);
}

// ======= GROUP S: params[0] non-zero with EXTRACT and varying amounts =======
log('\n=== Group S: params[0]=1, EXTRACT with various amounts ===\n');
for (const amt of [0n, 1n, 5n, 10n, 50n, 100n]) {
  const r = await tryProof(
    `params[0]=1 EXTRACT amount=${amt} selfBal=100`,
    mkInputs(1n, 1n, amt, 100n, 100n, 0n)
  );
  if (r.ok) {
    log(`\nSOLUTION: params[0]=1, EXTRACT, amount=${amt}`);
    process.exit(0);
  }
}

// ======= GROUP T: params[0] non-zero, check if the error is amount-related =======
log('\n=== Group T: params[0]=1, vary selfBalance vs amount ===\n');
for (const [self, opp, amt, action] of [
  [0n, 0n, 0n, 0n],      // zero balances, FORTIFY
  [1000n, 1000n, 0n, 0n], // large balances, FORTIFY
  [1000n, 1000n, 10n, 1n], // large balances, EXTRACT small
]) {
  const r = await tryProof(
    `params[0]=1 selfBal=${self} oppBal=${opp} amt=${amt} action=${action}`,
    mkInputs(1n, action, amt, self, opp, 0n)
  );
  if (r.ok) {
    log(`\nSOLUTION found in Group T`);
    process.exit(0);
  }
}

// ======= GROUP U: params[0] in {1,2,3}, check lines 140/149 with action=0 and non-zero params[1..3] =======
log('\n=== Group U: params[0]=1 action=0 with various params[1..3] non-zero ===\n');
for (let k = 1; k <= 3; k++) {
  for (const v of [1n, 2n, 10n]) {
    const params = [1n, ...z8.slice(1)];
    params[k] = v;
    const commitment = P(...params, 0n);
    const r = await tryProof(
      `params[0]=1 params[${k}]=${v} action=0`,
      {
        commitment, matchId: 1n, turnNumber: 1n,
        selfBalance: 100n, opponentBalance: 100n,
        action: 0n, amount: 0n, circuitVersion: 1n,
        strategyParams: params, salt: 0n,
      }
    );
    if (r.ok) {
      log(`\nSOLUTION: params[0]=1 params[${k}]=${v}`);
      process.exit(0);
    }
  }
}

// ======= GROUP V: params[0] = large values (above 5) =======
log('\n=== Group V: larger params[0] values with action=0 ===\n');
for (const p0 of [7n, 8n, 10n, 16n, 32n, 100n, 255n, 256n]) {
  const r = await tryProof(
    `params[0]=${p0} action=0`,
    mkInputs(p0, 0n, 0n, 100n, 100n, 0n)
  );
  if (r.ok) {
    log(`\nSOLUTION: params[0]=${p0}`);
    process.exit(0);
  }
}

// ======= GROUP W: params[0]=1, different line 149 diagnosis =======
// line 149 fires for params[0]=1,action=2. What if selfBalance or opponentBalance changes it?
log('\n=== Group W: params[0]=1, action=2 (HOLD), vary balances ===\n');
for (const [self, opp] of [[0n,0n],[0n,100n],[100n,0n],[200n,100n],[1n,1n]]) {
  const r = await tryProof(
    `params[0]=1 HOLD selfBal=${self} oppBal=${opp}`,
    mkInputs(1n, 2n, 0n, self, opp, 0n)
  );
  if (r.ok) {
    log(`\nSOLUTION: params[0]=1 HOLD selfBal=${self} oppBal=${opp}`);
    process.exit(0);
  }
}

// ======= GROUP X: params[0]=1, action=1, check line 140 with specific amounts =======
log('\n=== Group X: params[0]=1, action=1 (EXTRACT), probe line 140 ===\n');
for (const [self, opp, amt] of [
  [100n, 100n, 0n],
  [100n, 100n, 50n],
  [200n, 100n, 100n],
  [0n, 100n, 0n],
]) {
  const r = await tryProof(
    `params[0]=1 EXTRACT selfBal=${self} oppBal=${opp} amt=${amt}`,
    mkInputs(1n, 1n, amt, self, opp, 0n)
  );
  if (r.ok) {
    log(`\nSOLUTION: params[0]=1 EXTRACT selfBal=${self} oppBal=${opp} amt=${amt}`);
    process.exit(0);
  }
}

// ======= GROUP Y: exhaustive params[0] in {1..10} × action=0 with salt variants =======
log('\n=== Group Y: exhaustive params[0] 1-10 × salt 0-5 × action=0 ===\n');
for (const p0 of [1n,2n,3n,4n,5n,6n,7n,8n,9n,10n]) {
  for (const salt of [0n, 1n, 2n, 42n]) {
    const r = await tryProof(
      `params[0]=${p0} salt=${salt} action=0`,
      mkInputs(p0, 0n, 0n, 100n, 100n, salt)
    );
    if (r.ok) {
      log(`\nSOLUTION: params[0]=${p0} salt=${salt}`);
      process.exit(0);
    }
  }
}

log('\n=== All v3 probes exhausted ===');
log('See output: scripts/probe-line90-v3-output.txt');
log('Next: decompile wasm to WAT for direct line 90 inspection.');
