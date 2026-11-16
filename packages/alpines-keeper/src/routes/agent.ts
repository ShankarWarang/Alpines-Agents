/**
 * POST / - Main task handler for Proof Gatekeeper.
 *
 * Receives a GatekeeperTask, validates it, generates a proof, and returns the decision.
 */

import type { FastifyInstance } from 'fastify';
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
      log.info({ task_id: task.task_id }, 'Task received');

      // -- 1. Validate ------------------------------------------
      const { decision, reason_code } = await validateTask(task, vkHash);

      // -- 2. Generate proof ------------------------------------
      let proof = undefined;
      let publicSignals = undefined;

      try {
        const decisionNum = decision === 'APPROVE' ? 1 : 0;
        const amount = task.incoming_proof.publicInputs[0] ?? '0';
        const recipient = task.payment_request.recipient;
        const deadline = task.payment_request.deadline;
        const minAmount = task.payment_request.min_amount;

        const proofResult = await generateProof({
          decision: decisionNum,
          amount: BigInt(amount),
          // Recipient may be a hex address (0x...) or a decimal string.
          // BigInt handles both: BigInt('0xABC') = 2748n, BigInt('123') = 123n.
          // Strip any leading/trailing whitespace to avoid parse errors.
          recipient: BigInt(String(recipient).trim()),
          deadline: BigInt(deadline),
          min_amount: BigInt(minAmount),
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
