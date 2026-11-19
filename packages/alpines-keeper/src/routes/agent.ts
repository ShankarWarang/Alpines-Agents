/**
 * POST / - Main task handler for Proof Gatekeeper.
 *
 * Receives a GatekeeperTask, validates it, and returns the decision.
 * Response: { decision, reason_code, proof_tx } per official spec.
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

      // Preflight: platform sends type='agent-games.preflight.v1' - reply immediately
      if (
        task?.type === 'agent-games.preflight.v1' ||
        !task?.task_id
      ) {
        log.info('Preflight POST received - responding ok');
        return { ok: true, protocolVersion: 'v1' };
      }

      log.info(
        { task_id: task.task_id, mode: task.mode },
        'Task received',
      );

      // -- 1. Validate ------------------------------------------
      const { decision, reason_code } = await validateTask(task, vkHash);

      // -- 2. Generate proof (best-effort, no timeout block) ----
      try {
        const inp = task.input;
        const parseBig = (v: unknown, fallback = 0n): bigint => {
          try { return BigInt(String(v).replace(/^0x/, '').trim() || '0'); } catch { return fallback; }
        };

        const decisionNum = decision === 'APPROVE' ? 1 : 0;
        const saltBytes = randomBytes(16);
        const salt = BigInt('0x' + saltBytes.toString('hex'));

        // taskId: derive from task_id (first 15 non-hyphen chars → BigInt)
        const taskIdHex = task.task_id.replace(/[^0-9a-fA-F]/g, '').slice(0, 15).padStart(1, '1');
        const taskIdBig = BigInt('0x' + taskIdHex || '1');

        // All inputs come DIRECTLY from task.input — no conversion needed
        await generateProof({
          registeredVkHash: parseBig(inp.registered_vk),
          proofVkHash:      parseBig(inp.proof_vk),
          minimum:          parseBig(inp.minimum),
          publicBalance:    parseBig(inp.public_balance),
          expiryBlock:      BigInt(inp.expiry_block),
          currentBlock:     BigInt(inp.current_block),
          recipient:        parseBig(inp.recipient),
          conditionRecipient: parseBig(inp.condition_recipient),
          amount:           parseBig(inp.amount),
          maxTransfer:      parseBig(inp.max_transfer),
          decision:         BigInt(decisionNum),
          taskId:           taskIdBig,
          salt,
        });
        // Note: proof is generated but not included in response per spec
        // (platform verifies the on-chain proof referenced by proof_tx)
      } catch (proofErr) {
        log.warn(
          { task_id: task.task_id, error: String(proofErr) },
          'Proof generation failed (non-fatal)',
        );
      }

      // -- 3. Build response ------------------------------------
      const elapsed = Date.now() - startTime;
      log.info(
        { task_id: task.task_id, decision, reason_code, elapsed_ms: elapsed },
        'Decision made',
      );

      const response: GatekeeperResponse = {
        decision,
        reason_code,
        proof_tx: task.input?.proof_tx,  // echo back the incoming proof reference
      };

      return response;
    } catch (err) {
      const elapsed = Date.now() - startTime;
      log.error(
        { error: String(err), elapsed_ms: elapsed },
        'Unhandled error - returning REJECT',
      );

      return {
        decision: 'REJECT',
        reason_code: 'VALIDATION_ERROR',
      } as GatekeeperResponse;
    }
  });
}
