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
    // All 13 confirmed signals with CONSTRAINT-SATISFYING values
    // Key constraints the circuit enforces:
    //   - registeredVkHash == proofVkHash
    //   - recipient == conditionRecipient
    //   - amount >= minimum, amount <= maxTransfer, amount <= publicBalance
    //   - currentBlock <= expiryBlock (not expired)
    //   - decision=1 requires all above to be true
    sampleInputsFn: () => {
      const currentBlock = Math.floor(Date.now() / 12000);
      const vkHash = '54321'; // must match for APPROVE
      const recipient = '12345';
      return {
        registeredVkHash: vkHash,  // must == proofVkHash
        proofVkHash: vkHash,       // must == registeredVkHash
        minimum: '100',
        publicBalance: '5000',     // must >= amount
        expiryBlock: String(currentBlock + 1000000), // must > currentBlock
        currentBlock: String(currentBlock),
        recipient: recipient,
        conditionRecipient: recipient, // must == recipient
        amount: '500',             // must be in [minimum, maxTransfer]
        maxTransfer: '10000',
        decision: '1',             // 1=APPROVE
        taskId: '999',
        salt: String(BigInt('0x' + randomBytes(16).toString('hex'))),
      };
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
    const inputs = cfg.sampleInputsFn ? cfg.sampleInputsFn() : cfg.sampleInputs;
    console.log('Inputs:', JSON.stringify(inputs, null, 2));

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs, cfg.wasm, cfg.zkey
    );
    console.log('\n*** PROOF SUCCESS! ***');
    console.log('publicSignals:', JSON.stringify(publicSignals));
    console.log('proof.pi_a:', proof.pi_a);
  } catch(e) {
    const msg = (e.message ?? String(e)).slice(0, 200);
    console.log('\nProof FAILED:', msg);
  }
}
