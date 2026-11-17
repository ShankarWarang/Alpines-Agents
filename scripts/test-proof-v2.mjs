#!/usr/bin/env node
/**
 * Quick proof test for keeper and stealer circuits.
 * Uses snarkjs locally to validate signal assignments.
 *
 * Usage:
 *   node scripts/test-proof-v2.mjs keeper
 *   node scripts/test-proof-v2.mjs stealer
 */
import { readFileSync, existsSync } from 'fs';
import { randomBytes } from 'crypto';

const CONFIGS = {
  keeper: {
    label: 'KEEPER (gatekeeper)',
    wasm: 'packages/alpines-keeper/circuits/gatekeeper.wasm',
    zkey: 'packages/alpines-keeper/circuits/gatekeeper_final.zkey',
    // All 13 confirmed signals with sample values
    sampleInputs: {
      registeredVkHash: '0',  // platform VK hash
      proofVkHash: '0',       // incoming proof VK hash
      minimum: '100',         // min payment amount
      publicBalance: '5000',  // public balance
      expiryBlock: '99999999', // deadline as block
      currentBlock: String(Math.floor(Date.now() / 12000)),
      recipient: '12345',     // recipient as integer
      conditionRecipient: '12345', // must match recipient
      amount: '500',          // payment amount
      maxTransfer: '10000',   // max allowed transfer
      decision: '1',          // 1=APPROVE
      taskId: '999',          // task ID
      salt: String(BigInt('0x' + randomBytes(16).toString('hex'))),
    },
  },
  stealer: {
    label: 'STEALER (vfy-policy)',
    wasm: 'packages/alpines-stealer/circuits/steal.wasm',
    zkey: 'packages/alpines-stealer/circuits/steal_final.zkey',
    // All confirmed signals; strategy array name is best-guess
    sampleInputs: {
      commitment: '0x80d45b2f63d5c6a19f0f9c812e720e1024a3f1d2e55bad50a6ec639e457cbb3e',
      matchId: '1',
      turnNumber: '1',
      selfBalance: '100',
      opponentBalance: '100',
      action: '2',  // HOLD=2
      amount: '0',
      circuitVersion: '1',
      strategyParams: Array(8).fill('0'),  // confirmed array name
      salt: String(BigInt('0x' + randomBytes(16).toString('hex'))),
    },
  },
};

const target = process.argv[2];
const toRun = target ? [target] : Object.keys(CONFIGS);

for (const name of toRun) {
  const cfg = CONFIGS[name];
  if (!cfg) { console.error('Unknown:', name); process.exit(1); }

  console.log(`\n${'='.repeat(60)}\n${cfg.label}\n${'='.repeat(60)}`);

  if (!existsSync(cfg.wasm) || !existsSync(cfg.zkey)) {
    console.log('SKIP: circuit files not found');
    continue;
  }

  try {
    const snarkjs = await import('snarkjs').then(m => m.default ?? m);
    console.log('Running fullProve with sample inputs...');
    console.log('Inputs:', JSON.stringify(cfg.sampleInputs, null, 2));

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      cfg.sampleInputs, cfg.wasm, cfg.zkey
    );
    console.log('\n*** PROOF SUCCESS! ***');
    console.log('publicSignals:', JSON.stringify(publicSignals));
    console.log('proof.pi_a:', proof.pi_a);
  } catch(e) {
    const msg = (e.message ?? String(e)).slice(0, 200);
    console.log('\nProof FAILED:', msg);
  }
}
