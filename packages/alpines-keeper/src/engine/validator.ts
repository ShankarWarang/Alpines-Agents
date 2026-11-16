/**
 * Deterministic Validation Engine for Proof Gatekeeper
 *
 * Covers all 7 trap varieties with fail-fast, ordered checks.
 * NEVER uses an LLM - pure deterministic code.
 *
 * Conservative bias: when uncertain, REJECT (−3 is better than −6 for approving a trap).
 */

import {
  verifyProof,
  checkFinalization,
  createLogger,
} from '@zkverify/shared';
import type {
  GatekeeperTask,
  GatekeeperDecision,
  GatekeeperReasonCode,
} from '@zkverify/shared';
import { hasSeen, markSeen } from './replay-store.js';

const log = createLogger('validator');

// -- Public Input Indices --------------------------------------
// These should be adjusted based on the actual circuit spec from the platform.
const PUBLIC_INPUT_AMOUNT_INDEX = 0;
const PUBLIC_INPUT_RECIPIENT_INDEX = 1;
const PUBLIC_INPUT_DEADLINE_INDEX = 2;

interface ValidationResult {
  decision: GatekeeperDecision;
  reason_code: GatekeeperReasonCode;
}

/**
 * Validate a gatekeeper task. Returns decision + reason_code.
 *
 * Checks run in this exact order (fail-fast, most common traps first):
 *   1. VK match
 *   2. Proving system check
 *   3. Proof cryptographic verification
 *   4. Replay detection
 *   5. Amount minimum check
 *   6. Amount overflow check
 *   7. Deadline check
 *   8. Recipient match
 *   9. Finalization check
 *  10. APPROVE if all pass
 */
export async function validateTask(
  task: GatekeeperTask,
  vkHash: string
): Promise<ValidationResult> {
  const { incoming_proof, payment_request } = task;

  // -- 1. VK Match (~13% of traps) -----------------------------
  if (incoming_proof.vk_hash !== undefined && incoming_proof.vk_hash !== vkHash) {
    log.info({ task_id: task.task_id, check: 'vk_match', expected: vkHash, got: incoming_proof.vk_hash }, 'VK mismatch');
    return { decision: 'REJECT', reason_code: 'VK_MISMATCH' };
  }

  // -- 2. Proving System Check ----------------------------------
  if (incoming_proof.proving_system !== undefined && incoming_proof.proving_system !== 'groth16') {
    log.info({ task_id: task.task_id, check: 'proving_system', got: incoming_proof.proving_system }, 'Invalid proving system');
    return { decision: 'REJECT', reason_code: 'INVALID_PROOF_SYSTEM' };
  }

  // -- 3. Proof Cryptographic Verification ----------------------
  try {
    const verifyResult = await verifyProof(
      incoming_proof.proof,
      incoming_proof.publicInputs,
      vkHash
    );
    if (!verifyResult.valid) {
      log.info({ task_id: task.task_id, check: 'crypto_verify' }, 'Invalid proof');
      return { decision: 'REJECT', reason_code: 'INVALID_PROOF' };
    }
  } catch (err) {
    log.error({ task_id: task.task_id, check: 'crypto_verify', error: String(err) }, 'Proof verification error');
    return { decision: 'REJECT', reason_code: 'INVALID_PROOF' };
  }

  // -- 4. Replay Detection (~11% of traps) ----------------------
  if (incoming_proof.proof_tx) {
    if (hasSeen(incoming_proof.proof_tx)) {
      log.info({ task_id: task.task_id, check: 'replay', proof_tx: incoming_proof.proof_tx }, 'Proof reused');
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    markSeen(incoming_proof.proof_tx);
  }

  // -- 5. Amount Minimum Check (~8% of traps) -------------------
  try {
    const amount = BigInt(incoming_proof.publicInputs[PUBLIC_INPUT_AMOUNT_INDEX] ?? '0');
    const minAmount = BigInt(payment_request.min_amount);
    if (amount < minAmount) {
      log.info({ task_id: task.task_id, check: 'amount_min', amount: amount.toString(), min: minAmount.toString() }, 'Amount below minimum');
      return { decision: 'REJECT', reason_code: 'AMOUNT_BELOW_MINIMUM' };
    }

    // -- 6. Amount Overflow Check (~6% of traps) ------------------
    if (payment_request.max_amount !== undefined) {
      const maxAmount = BigInt(payment_request.max_amount);
      if (amount > maxAmount) {
        log.info({ task_id: task.task_id, check: 'amount_max', amount: amount.toString(), max: maxAmount.toString() }, 'Amount overflow');
        return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
      }
    }
  } catch (err) {
    log.error({ task_id: task.task_id, check: 'amount', error: String(err) }, 'Amount parsing error');
    return { decision: 'REJECT', reason_code: 'VALIDATION_ERROR' };
  }

  // -- 7. Deadline Check (~6% of traps) -------------------------
  const nowSec = Math.floor(Date.now() / 1000);
  if (payment_request.deadline > 0 && nowSec > payment_request.deadline) {
    log.info({ task_id: task.task_id, check: 'deadline', now: nowSec, deadline: payment_request.deadline }, 'Payment expired');
    return { decision: 'REJECT', reason_code: 'EXPIRED' };
  }

  // -- 8. Recipient Match (~6% of traps) ------------------------
  if (incoming_proof.publicInputs[PUBLIC_INPUT_RECIPIENT_INDEX] !== undefined) {
    const proofRecipient = incoming_proof.publicInputs[PUBLIC_INPUT_RECIPIENT_INDEX].toLowerCase();
    const expectedRecipient = payment_request.recipient.toLowerCase();
    if (proofRecipient !== expectedRecipient) {
      log.info({ task_id: task.task_id, check: 'recipient', expected: expectedRecipient, got: proofRecipient }, 'Recipient mismatch');
      return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
    }
  }

  // -- 9. Finalization Check ------------------------------------
  if (incoming_proof.proof_tx) {
    try {
      const finalized = await checkFinalization(incoming_proof.proof_tx);
      if (!finalized) {
        log.info({ task_id: task.task_id, check: 'finalization', proof_tx: incoming_proof.proof_tx }, 'Not finalized');
        return { decision: 'REJECT', reason_code: 'NOT_FINALIZED' };
      }
    } catch (err) {
      log.error({ task_id: task.task_id, check: 'finalization', error: String(err) }, 'Finalization check error');
      return { decision: 'REJECT', reason_code: 'NOT_FINALIZED' };
    }
  }

  // -- 10. All checks passed → APPROVE --------------------------
  log.info({ task_id: task.task_id }, 'All checks passed - APPROVE');
  return { decision: 'APPROVE', reason_code: 'SUCCESS' };
}
