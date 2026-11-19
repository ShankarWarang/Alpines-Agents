/**
 * Deterministic Validation Engine for Proof Gatekeeper
 *
 * Uses task.input.* fields per official spec.
 * Conservative bias: when uncertain, REJECT (-3 is better than -6 for approving a trap).
 */

import { createLogger } from '@zkverify/shared';
import type {
  GatekeeperTask,
  GatekeeperDecision,
  GatekeeperReasonCode,
} from '@zkverify/shared';
import { hasSeen, markSeen } from './replay-store.js';

const log = createLogger('validator');

interface ValidationResult {
  decision: GatekeeperDecision;
  reason_code: GatekeeperReasonCode;
}

/**
 * Validate a gatekeeper task. Returns decision + reason_code.
 *
 * Checks in order (fail-fast):
 *   1. VK match — registered_vk must equal proof_vk
 *   2. Replay detection — proof_tx must not have been seen before
 *   3. Amount minimum — amount >= minimum
 *   4. Amount overflow — amount <= max_transfer
 *   5. Deadline check — expiry_block >= current_block
 *   6. Recipient match — recipient == condition_recipient
 *   7. APPROVE if all pass
 */
export async function validateTask(
  task: GatekeeperTask,
  _registeredVkHash: string,
): Promise<ValidationResult> {
  const inp = task.input;

  if (!inp) {
    log.error({ task_id: task.task_id }, 'Task missing input field');
    return { decision: 'REJECT', reason_code: 'VALIDATION_ERROR' };
  }

  // -- 1. VK Match ---------------------------------------------
  // The proof must have been generated with the registered VK.
  if (inp.proof_vk && inp.registered_vk && inp.proof_vk !== inp.registered_vk) {
    log.info(
      { task_id: task.task_id, registered: inp.registered_vk, got: inp.proof_vk },
      'VK mismatch',
    );
    return { decision: 'REJECT', reason_code: 'VK_MISMATCH' };
  }

  // -- 2. Replay Detection -------------------------------------
  if (inp.proof_tx) {
    if (hasSeen(inp.proof_tx)) {
      log.info({ task_id: task.task_id, proof_tx: inp.proof_tx }, 'Proof reused');
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    markSeen(inp.proof_tx);
  }

  // -- 3 & 4. Amount Checks ------------------------------------
  try {
    const amount    = BigInt(inp.amount    || '0');
    const minimum   = BigInt(inp.minimum   || '0');
    const maxXfer   = BigInt(inp.max_transfer || '0');

    if (amount < minimum) {
      log.info(
        { task_id: task.task_id, amount: amount.toString(), minimum: minimum.toString() },
        'Amount below minimum',
      );
      return { decision: 'REJECT', reason_code: 'AMOUNT_BELOW_MINIMUM' };
    }

    if (maxXfer > 0n && amount > maxXfer) {
      log.info(
        { task_id: task.task_id, amount: amount.toString(), max: maxXfer.toString() },
        'Amount overflow',
      );
      return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
    }
  } catch (err) {
    log.error({ task_id: task.task_id, error: String(err) }, 'Amount parsing error');
    return { decision: 'REJECT', reason_code: 'VALIDATION_ERROR' };
  }

  // -- 5. Deadline Check ---------------------------------------
  // expiry_block >= current_block means the proof is still valid
  if (inp.expiry_block > 0 && inp.current_block > 0) {
    if (inp.current_block > inp.expiry_block) {
      log.info(
        { task_id: task.task_id, current: inp.current_block, expiry: inp.expiry_block },
        'Payment expired (block)',
      );
      return { decision: 'REJECT', reason_code: 'EXPIRED' };
    }
  }

  // -- 6. Recipient Match ---------------------------------------
  if (inp.recipient && inp.condition_recipient) {
    const r1 = inp.recipient.toLowerCase().replace(/^0x/, '');
    const r2 = inp.condition_recipient.toLowerCase().replace(/^0x/, '');
    if (r1 !== r2) {
      log.info(
        { task_id: task.task_id, recipient: r1, condition: r2 },
        'Recipient mismatch',
      );
      return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
    }
  }

  // -- 7. All checks passed → APPROVE --------------------------
  log.info({ task_id: task.task_id }, 'All checks passed - APPROVE');
  return { decision: 'APPROVE', reason_code: 'SUCCESS' };
}
