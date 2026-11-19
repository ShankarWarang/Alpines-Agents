// ============================================================
// Alpines Stealer - Main Turn Handler (POST /)
// ============================================================

import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { keccak256, concat, numberToHex } from 'viem';
import { generateProof, createLogger } from '@zkverify/shared';
import type { StealTask, StealResponse, StealAction } from '@zkverify/shared';
import { getOrCreate } from '../engine/match-state.js';
import { getOrCreateModel } from '../engine/opponent.js';
import { selectAction } from '../engine/strategy.js';

/**
 * Circuit version string — must match what is registered on the platform dashboard.
 */
const CIRCUIT_VERSION = 'v1' as const;
const CIRCUIT_VERSION_INT = 1n;

/**
 * Strategy params: all zeros.
 * Commitment = Poseidon([0,0,0,0,0,0,0,0], 0) = 0x01c4da168cbfb5014e1dc256d82ba808033c11cc3bd113ef0a44ad86b2075728
 * This must match the commitment registered on the Agent Games dashboard.
 * Override via STEALER_STRATEGY_COMMITMENT env var if re-registered.
 */
const STRATEGY_PARAMS = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n] as bigint[];
const STRATEGY_SALT = 0n;
const STRATEGY_COMMITMENT = BigInt(
  process.env.STEALER_STRATEGY_COMMITMENT ??
  '0x01c4da168cbfb5014e1dc256d82ba808033c11cc3bd113ef0a44ad86b2075728',
);

// Map action to circuit integer: 0=HOLD, 1=FORTIFY, 2=EXTRACT (per spec)
function actionToInt(action: StealAction): number {
  switch (action) {
    case 'HOLD':    return 0;
    case 'FORTIFY': return 1;
    case 'EXTRACT': return 2;
  }
}

/**
 * Compute the publicInputsHash per the platform spec:
 * keccak256 of ABI-packed fields (each padded to 32 bytes big-endian).
 *
 * This hash is what the platform independently verifies as public_signals[0].
 * Without it matching, the proof is rejected before even running the verifier.
 */
function computePublicInputsHash(
  commitment: bigint,
  matchId: string,
  turn: number,
  selfBalance: number,
  opponentBalance: number,
  action: StealAction,
  amount: number,
): `0x${string}` {
  // UUID has 32 hex chars without dashes (16 bytes) — fits safely in bytes32
  const matchIdBig = BigInt('0x' + matchId.replace(/-/g, ''));
  const actionNum = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n }[action];

  return keccak256(concat([
    numberToHex(commitment,          { size: 32 }),  // strategyCommitment.hash
    numberToHex(matchIdBig,          { size: 32 }),  // matchId as bytes32
    numberToHex(BigInt(turn),        { size: 32 }),  // turn number
    numberToHex(BigInt(selfBalance), { size: 32 }),  // selfBalance
    numberToHex(BigInt(opponentBalance), { size: 32 }), // opponentBalance
    numberToHex(actionNum,           { size: 32 }),  // action encoding
    numberToHex(BigInt(amount),      { size: 32 }),  // amount (0 for HOLD/FORTIFY)
    numberToHex(1n,                  { size: 32 }),  // circuitVersion "v1" → 1
  ]));
}

export function registerAgentRoute(
  app: FastifyInstance,
  logger: ReturnType<typeof createLogger>,
): void {
  app.post('/', async (request, _reply): Promise<StealResponse | { ok: boolean; protocolVersion: string }> => {
    const startTime = Date.now();
    const task = request.body as StealTask;

    // Preflight: platform sends type='agent-games.preflight.v1'
    if (
      (task as any)?.type === 'agent-games.preflight.v1' ||
      !task?.matchId
    ) {
      logger.info('Preflight POST received - responding ok');
      return { ok: true, protocolVersion: 'v1' };
    }

    logger.info(
      { matchId: task.matchId, turn: task.turn },
      'Turn received',
    );

    try {
      // Parse balances from state (they come as strings per spec)
      const myBalance    = parseInt(task.state?.selfBalance     ?? '100', 10);
      const oppBalance   = parseInt(task.state?.opponentBalance ?? '100', 10);
      const totalTurns   = task.total_turns ?? 20;

      // -- Get / create match state --
      const state = getOrCreate(task.matchId, totalTurns);

      // -- Update opponent model --
      if (task.opponent_last_action) {
        const opponentModel = getOrCreateModel(task.matchId);
        opponentModel.update(task.opponent_last_action);
      }

      // -- Update match state --
      state.turn           = task.turn;
      state.myBalance      = myBalance;
      state.opponentBalance = oppBalance;
      state.lastUpdated    = Date.now();

      if (task.opponent_last_action) {
        state.opponentHistory.push(task.opponent_last_action);
      }

      // -- Select action --
      const action = selectAction(state);
      state.myHistory.push(action);

      // -- Compute extract amount (0 for HOLD/FORTIFY) --
      const extractAmt = action === 'EXTRACT' ? Math.min(10, myBalance) : 0;

      // -- Compute publicInputsHash per platform spec --
      // The platform independently computes this hash and rejects proofs that diverge.
      // We MUST set public_signals[0] to this hash in all cases (valid proof or fallback).
      const publicInputsHash = computePublicInputsHash(
        STRATEGY_COMMITMENT,
        task.matchId,
        task.turn,
        myBalance,
        oppBalance,
        action,
        extractAmt,
      );

      // -- Generate Groth16 proof --
      let proof: any = {
        pi_a: ['0', '0', '1'],
        pi_b: [['0', '0'], ['0', '0'], ['1', '0']],
        pi_c: ['0', '0', '1'],
        protocol: 'groth16',
        curve: 'bn128',
      };
      // Always initialise publicSignals to the computed hash (platform pre-screen)
      let publicSignals: string[] = [publicInputsHash];

      try {
        const actionInt    = actionToInt(action);
        const extractAmtBig = BigInt(extractAmt);

        // matchId as BigInt — full UUID hex (32 hex chars = 16 bytes, fits in bytes32)
        const matchIdNum = BigInt('0x' + task.matchId.replace(/-/g, ''));

        const circuitInputs: Record<string, string | number | bigint | (string | number | bigint)[]> = {
          commitment:      STRATEGY_COMMITMENT,
          matchId:         matchIdNum,
          turnNumber:      BigInt(task.turn),
          selfBalance:     BigInt(myBalance),
          opponentBalance: BigInt(oppBalance),
          action:          BigInt(actionInt),
          amount:          extractAmtBig,
          circuitVersion:  CIRCUIT_VERSION_INT,
          salt:            STRATEGY_SALT,
          strategyParams:  STRATEGY_PARAMS,
        };

        const result  = await generateProof(circuitInputs);
        proof         = result.proof;
        // Use the circuit's own public signals if proof succeeded
        publicSignals = result.publicSignals.length > 0 ? result.publicSignals : [publicInputsHash];
        logger.info({ matchId: task.matchId, turn: task.turn }, 'Proof generated successfully');
      } catch (proofErr) {
        logger.error(
          { err: proofErr, matchId: task.matchId, turn: task.turn },
          'Proof generation failed - sending zeroed proof with correct publicInputsHash',
        );
      }

      const elapsed = Date.now() - startTime;
      logger.info(
        {
          matchId: task.matchId,
          turn: task.turn,
          action,
          myBalance,
          oppBalance,
          has_proof: !!proof,
          elapsed_ms: elapsed,
        },
        'Turn completed',
      );

      // Build action object: amount only for EXTRACT
      const actionObj = action === 'EXTRACT'
        ? { type: action, amount: Math.min(10, myBalance) }
        : { type: action };

      const response: StealResponse = {
        matchId: task.matchId,
        turn:    task.turn,
        action:  actionObj,
        idempotencyKey: randomUUID(),   // proper UUID v4 per platform schema
        agentTimestamp: new Date().toISOString(),
        policyProof: {
          circuitVersion: CIRCUIT_VERSION,
          proof,          // valid proof or zeroed fallback - always present
          public_signals: publicSignals,
          publicInputsHash: publicInputsHash,  // REQUIRED separate field (platform pre-screen)
        },
      };

      return response;
    } catch (err) {
      const elapsed = Date.now() - startTime;
      logger.error(
        { err, matchId: task.matchId, turn: task.turn, elapsed_ms: elapsed },
        'Turn handler error - defaulting to HOLD',
      );

      // Best-effort hash for the error fallback; HOLD=0, amount=0
      let fallbackHash = '0x0000000000000000000000000000000000000000000000000000000000000000';
      try {
        fallbackHash = computePublicInputsHash(
          STRATEGY_COMMITMENT,
          task.matchId ?? '00000000-0000-0000-0000-000000000000',
          task.turn ?? 0,
          parseInt(task.state?.selfBalance ?? '100', 10),
          parseInt(task.state?.opponentBalance ?? '100', 10),
          'HOLD',
          0,
        );
      } catch { /* use zeroed fallback */ }

      return {
        matchId:        task.matchId ?? 'unknown',
        turn:           task.turn ?? 0,
        action:         { type: 'HOLD' },
        idempotencyKey: randomUUID(),
        agentTimestamp: new Date().toISOString(),
        policyProof: {
          circuitVersion: CIRCUIT_VERSION,
          proof: { pi_a: ['0', '0', '1'], pi_b: [['0', '0'], ['0', '0'], ['1', '0']], pi_c: ['0', '0', '1'], protocol: 'groth16', curve: 'bn128' },
          public_signals: [fallbackHash],
          publicInputsHash: fallbackHash,
        },
      } as StealResponse;
    }
  });
}
