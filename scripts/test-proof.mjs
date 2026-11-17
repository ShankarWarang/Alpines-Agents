#!/usr/bin/env node
/**
 * Test proof generation against the real circuit files.
 * Run on VPS after circuit files are in place.
 *
 * Usage:
 *   node scripts/test-proof.mjs keeper   # test gatekeeper circuit
 *   node scripts/test-proof.mjs stealer  # test vfy-policy circuit
 *   node scripts/test-proof.mjs          # test both
 */

import { existsSync } from 'fs';

const snarkjs = await import('snarkjs').then(m => m.default ?? m);

const AGENTS = {
  keeper: {
    label: 'Keeper (gatekeeper.wasm)',
    wasm: 'packages/alpines-keeper/circuits/gatekeeper.wasm',
    zkey: 'packages/alpines-keeper/circuits/gatekeeper_final.zkey',
    // VK hash registered on zkVerify mainnet
    vkHash: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    // Candidates from most to least likely based on circuit name + our implementation
    candidates: [
      {
        label: 'Current code: decision/amount/recipient/deadline/min_amount',
        inputs: { decision: 1, amount: 1000n, recipient: 123456789n, deadline: 9999999999n, min_amount: 100n },
      },
      {
        label: 'decision/amount/recipient/deadline',
        inputs: { decision: 1, amount: 1000n, recipient: 123456789n, deadline: 9999999999n },
      },
      {
        label: 'approve/amount/recipient/deadline/min_amount',
        inputs: { approve: 1, amount: 1000n, recipient: 123456789n, deadline: 9999999999n, min_amount: 100n },
      },
      {
        label: 'decision/value/to/expiry/threshold',
        inputs: { decision: 1, value: 1000n, to: 123456789n, expiry: 9999999999n, threshold: 100n },
      },
      {
        label: 'gate/amount/recipient/deadline',
        inputs: { gate: 1, amount: 1000n, recipient: 123456789n, deadline: 9999999999n },
      },
      {
        label: 'in (single input)',
        inputs: { in: 1n },
      },
    ],
  },
  stealer: {
    label: 'Stealer (vfy-policy.wasm)',
    wasm: 'packages/alpines-stealer/circuits/steal.wasm',
    zkey: 'packages/alpines-stealer/circuits/steal_final.zkey',
    vkHash: '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047',
    candidates: [
      {
        label: 'Current code: action/turn/my_balance/opponent_balance/strategy_hash',
        inputs: {
          action: 1,
          turn: 1,
          my_balance: 100,
          opponent_balance: 90,
          strategy_hash: BigInt('0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e').toString(),
        },
      },
      {
        label: 'action/turn/my_balance/opponent_balance',
        inputs: { action: 1, turn: 1, my_balance: 100, opponent_balance: 90 },
      },
      {
        label: 'action/turn/balance/opponent',
        inputs: { action: 1, turn: 1, balance: 100, opponent: 90 },
      },
      {
        label: 'policy/stake/turn/player',
        inputs: { policy: 1, stake: 100, turn: 1, player: 0 },
      },
      {
        label: 'move/resources/round',
        inputs: { move: 1, resources: 100, round: 1 },
      },
      {
        label: 'in (single)',
        inputs: { in: 1n },
      },
    ],
  },
};

async function testAgent(name, cfg) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Testing: ${cfg.label}`);
  console.log(`VK hash: ${cfg.vkHash}`);
  console.log('='.repeat(60));

  if (!existsSync(cfg.wasm)) {
    console.log(`SKIP - WASM not found: ${cfg.wasm}`);
    console.log('Copy circuit files first, then rerun.');
    return null;
  }
  if (!existsSync(cfg.zkey)) {
    console.log(`SKIP - zkey not found: ${cfg.zkey}`);
    return null;
  }

  for (const { label, inputs } of cfg.candidates) {
    process.stdout.write(`  [?] ${label}\n      -> `);
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, cfg.wasm, cfg.zkey);
      console.log('SUCCESS!');
      console.log(`      Public signals: ${JSON.stringify(publicSignals)}`);
      console.log(`\n${'*'.repeat(60)}`);
      console.log(`WINNING INPUTS for ${name}:`);
      console.log(JSON.stringify(inputs, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));
      console.log('*'.repeat(60));
      return { inputs, publicSignals, proof };
    } catch (err) {
      const msg = String(err.message ?? err);
      // Pull out what signal name the circuit expected
      const sigHint = msg.match(/signal (\w+)|"(\w+)" not found|input (\w+)/i);
      if (sigHint) {
        const name = sigHint[1] ?? sigHint[2] ?? sigHint[3];
        console.log(`FAIL (unexpected signal: "${name}")`);
      } else {
        console.log(`FAIL: ${msg.split('\n')[0].slice(0, 100)}`);
      }
    }
  }

  console.log(`\nAll candidates failed for ${name}.`);
  console.log('Run inspect-circuit.mjs for raw signal extraction:');
  console.log(`  node scripts/inspect-circuit.mjs ${cfg.wasm}`);
  return null;
}

const target = process.argv[2];
const toTest = target
  ? [target]
  : Object.keys(AGENTS);

for (const name of toTest) {
  if (!AGENTS[name]) {
    console.error(`Unknown agent: ${name}. Use "keeper" or "stealer".`);
    process.exit(1);
  }
  await testAgent(name, AGENTS[name]);
}
