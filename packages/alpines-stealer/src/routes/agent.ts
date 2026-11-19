// ============================================================
// Alpines Stealer - Main Turn Handler (POST /)
// ============================================================

import type { FastifyInstance } from 'fastify';
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
 */
const STRATEGY_PARAMS = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n] as bigint[];
const STRATEGY_SALT = 0n;
const STRATEGY_COMMITMENT = BigInt('0x01c4da168cbfb5014e1dc256d82ba808033c11cc3bd113ef0a44ad86b2075728');

// Map action to circuit integer: 0=HOLD, 1=FORTIFY, 2=EXTRACT (per spec)
function actionToInt(action: StealAction): number {
  switch (action) {
    case 'HOLD':    return 0;
    case 'FORTIFY': return 1;
    case 'EXTRACT': return 2;
  }
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

      // -- Generate Groth16 proof --
      let proof       = undefined;
      let publicSignals = undefined;

      try {
        const actionInt    = actionToInt(action);
        const extractAmt   = action === 'EXTRACT' ? BigInt(Math.min(10, myBalance)) : 0n;

        // matchId as BigInt (strip hyphens, take first 32 hex chars)
        const matchHex  = task.matchId.replace(/-/g, '').slice(0, 32).padStart(32, '0');
        const matchIdNum = BigInt('0x' + matchHex);

        const circuitInputs: Record<string, unknown> = {
          commitment:      STRATEGY_COMMITMENT,
          matchId:         matchIdNum,
          turnNumber:      BigInt(task.turn),
          selfBalance:     BigInt(myBalance),
          opponentBalance: BigInt(oppBalance),
          action:          BigInt(actionInt),
          amount:          extractAmt,
          circuitVersion:  CIRCUIT_VERSION_INT,
          salt:            STRATEGY_SALT,
          strategyParams:  STRATEGY_PARAMS,
        };

        const result  = await generateProof(circuitInputs);
        proof         = result.proof;
        publicSignals = result.publicSignals;
        logger.info({ matchId: task.matchId, turn: task.turn }, 'Proof generated successfully');
      } catch (proofErr) {
        logger.error(
          { err: proofErr, matchId: task.matchId, turn: task.turn },
          'Proof generation failed - accepting -2 penalty',
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
        idempotencyKey: `${task.matchId}-${task.turn}`,
        agentTimestamp: new Date().toISOString(),
        ...(proof
          ? {
              policyProof: {
                circuitVersion: CIRCUIT_VERSION,
                proof,
                public_signals: publicSignals as string[],
              },
            }
          : {}),
      };

      return response;
    } catch (err) {
      const elapsed = Date.now() - startTime;
      logger.error(
        { err, matchId: task.matchId, turn: task.turn, elapsed_ms: elapsed },
        'Turn handler error - defaulting to HOLD',
      );

      return {
        matchId:        task.matchId ?? 'unknown',
        turn:           task.turn ?? 0,
        action:         { type: 'HOLD' },
        idempotencyKey: `${task.matchId ?? 'unknown'}-${task.turn ?? 0}`,
        agentTimestamp: new Date().toISOString(),
      } as StealResponse;
    }
  });
}
