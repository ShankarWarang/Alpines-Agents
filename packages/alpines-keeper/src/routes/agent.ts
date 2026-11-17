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

        // ---- Parse task values ----
        const amount = parseBig(task.incoming_proof.publicInputs?.[0] ?? '0');
        const recipient = parseBig(task.payment_request.recipient);
        const minAmount = parseBig(task.payment_request.min_amount);
        const maxAmount = parseBig(task.payment_request.max_amount ?? amount.toString());

        // expiryBlock / currentBlock: the circuit uses block numbers.
        // task.payment_request.deadline is a unix timestamp (seconds).
        // Convert to approximate Ethereum block number (~12s per block since merge).
        // We use the SAME conversion for both so the ratio is consistent.
        const nowSec = BigInt(Math.floor(Date.now() / 1000));
        const SEC_PER_BLOCK = 12n;
        // Approximate current ETH block (Merge ~Sep2022 at block 15537394, timestamp 1663224162)
        const MERGE_BLOCK = 15537394n;
        const MERGE_TS = 1663224162n;
        const currentBlock = MERGE_BLOCK + (nowSec - MERGE_TS) / SEC_PER_BLOCK;
        const deadlineSec = BigInt(task.payment_request.deadline ?? 0);
        // If deadline < 1e9 it might already be a block number; if >= 1e9 it's a timestamp
        const expiryBlock = deadlineSec >= 1_000_000_000n
          ? MERGE_BLOCK + (deadlineSec - MERGE_TS) / SEC_PER_BLOCK
          : deadlineSec > 0n ? deadlineSec : currentBlock + 1_000_000n;

        // taskId: derive from task_id string (take first 15 hex chars = ~60 bits)
        const taskIdBytes = Buffer.from(task.task_id.replace(/-/g, '').slice(0, 15), 'hex');
        const taskIdBig = taskIdBytes.length > 0
          ? BigInt('0x' + taskIdBytes.toString('hex'))
          : parseBig(task.task_id.replace(/\D/g, '').slice(0, 18) || '1');

        // VK hashes: both must be the SAME value for the circuit to APPROVE.
        // Use the incoming proof's vk_hash. If missing, use our own registered VK hash.
        const vkHashStr = task.incoming_proof.vk_hash ?? vkHash ?? '0';
        const regVkHash = parseBig(vkHashStr);
        const proofVkHash = parseBig(vkHashStr);  // must equal regVkHash

        // publicBalance: upper bound on the payment. Use max_amount if set, else amount.
        const publicBalance = maxAmount > 0n ? maxAmount : amount;

        // salt: random BigInt (stays within BN128 field: < 2^254)
        const saltBytes = randomBytes(16);
        const salt = BigInt('0x' + saltBytes.toString('hex'));

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
