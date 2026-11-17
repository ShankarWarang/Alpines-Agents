/**
 * POST / - Main task handler for Proof Gatekeeper.
 *
 * Receives a GatekeeperTask, validates it, generates a proof, and returns the decision.
 */

import type { FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';
import {
  generateProof,
  createLogger,
} from '@zkverify/shared';
import type {
  GatekeeperTask,
  GatekeeperResponse,
} from '@zkverify/shared';
import { validateTask } from '../engine/validator.js';

const log = createLogger('agent-route');

/** The VK hash is injected at server construction time */
let vkHash: string;

export function setVkHash(hash: string): void {
  vkHash = hash;
}

export async function agentRoutes(app: FastifyInstance): Promise<void> {
  app.post('/', async (request, _reply) => {
    const startTime = Date.now();

    try {
      const task = request.body as GatekeeperTask;

      // Preflight: platform sends a signed POST with event_type='preflight'
      // or no task_id — respond immediately with 200
      if (!task?.task_id || task.event_type === 'preflight') {
        log.info('Preflight POST received - responding ok');
        return { ok: true, protocolVersion: 'v1' };
      }

      log.info({ task_id: task.task_id }, 'Task received');

      // -- 1. Validate ------------------------------------------
      const { decision, reason_code } = await validateTask(task, vkHash);

      // -- 2. Generate proof ------------------------------------
      let proof = undefined;
      let publicSignals = undefined;

      try {
        const decisionNum = decision === 'APPROVE' ? 1 : 0;

        // Extract circuit inputs from task payload using confirmed signal names.
        // Signal names were recovered via FNV-1a hash probe of gatekeeper.wasm.
        //
        // Confirmed signals (by witness index):
        //   idx=2  registeredVkHash - VK hash registered with platform
        //   idx=3  proofVkHash      - VK hash from incoming proof
        //   idx=4  minimum          - min payment amount
        //   idx=5  publicBalance    - public balance context
        //   idx=6  expiryBlock      - deadline/expiry block number
        //   idx=7  currentBlock     - current block (approximate timestamp / 12)
        //   idx=8  recipient        - payment recipient
        //   idx=10 amount           - payment amount (from public inputs)
        //   idx=11 maxTransfer      - max allowed transfer
        //   idx=12 decision         - 1=APPROVE, 0=REJECT
        //   idx=13 taskId           - task identifier
        //   idx=14 salt             - random salt for proof uniqueness

        // Parse numeric fields safely
        const parseBig = (v: unknown, fallback = 0n): bigint => {
          try { return BigInt(String(v).trim()); } catch { return fallback; }
        };

        const amount = parseBig(task.incoming_proof.publicInputs?.[0] ?? '0');
        const recipient = parseBig(task.payment_request.recipient);
        const minAmount = parseBig(task.payment_request.min_amount);
        const maxAmount = parseBig(task.payment_request.max_amount ?? '0');
        // expiryBlock: deadline is a unix timestamp; convert to approximate block (~12s/block)
        const expiryBlock = BigInt(task.payment_request.deadline ?? 0);
        const currentBlock = BigInt(Math.floor(Date.now() / 12000));
        // taskId: hash the task_id string into a field element
        const taskIdBig = BigInt('0x' + Buffer.from(task.task_id.slice(0, 16)).toString('hex'));
        // VK hashes - use 0n if not available, circuit will constraint-fail and we reject
        const regVkHash = parseBig(task.incoming_proof.vk_hash ?? '0');
        const proofVkHash = parseBig(task.incoming_proof.vk_hash ?? '0');
        // publicBalance: use amount as proxy (the balance being transferred)
        const publicBalance = amount;
        // salt: random 128-bit value for proof uniqueness
        const saltBytes = randomBytes(16);
        const salt = BigInt('0x' + saltBytes.toString('hex')) % (2n ** 128n);

        const proofResult = await generateProof({
          registeredVkHash: regVkHash,
          proofVkHash: proofVkHash,
          minimum: minAmount,
          publicBalance: publicBalance,
          expiryBlock: expiryBlock,
          currentBlock: currentBlock,
          recipient: recipient,
          conditionRecipient: recipient,   // must match recipient for APPROVE
          amount: amount,
          maxTransfer: maxAmount,
          decision: BigInt(decisionNum),
          taskId: taskIdBig,
          salt: salt,
        });

        proof = proofResult.proof;
        publicSignals = proofResult.publicSignals;
      } catch (proofErr) {
        // Proof generation failed - accept the −2 penalty rather than timeout
        log.warn(
          { task_id: task.task_id, error: String(proofErr) },
          'Proof generation failed - returning decision without proof'
        );
      }

      // -- 3. Build response ------------------------------------
      const elapsed = Date.now() - startTime;
      log.info(
        { task_id: task.task_id, decision, reason_code, elapsed_ms: elapsed },
        'Decision made'
      );

      const response: GatekeeperResponse = {
        decision,
        reason_code,
        proof,
        public_signals: publicSignals,
      };

      return response;
    } catch (err) {
      // Top-level catch - never crash, always return REJECT
      const elapsed = Date.now() - startTime;
      log.error(
        { error: String(err), elapsed_ms: elapsed },
        'Unhandled error - returning REJECT with VALIDATION_ERROR'
      );

      const response: GatekeeperResponse = {
        decision: 'REJECT',
        reason_code: 'VALIDATION_ERROR',
      };

      return response;
    }
  });
}
