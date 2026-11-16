// ============================================================
// Alpines Stealer - Main Turn Handler (POST /)
// ============================================================

import type { FastifyInstance } from 'fastify';
import { generateProof, createLogger } from '@zkverify/shared';
import type { StealTask, StealResponse, StealAction } from '@zkverify/shared';
import { getOrCreate } from '../engine/match-state.js';
import { getOrCreateModel } from '../engine/opponent.js';
import { selectAction } from '../engine/strategy.js';

// Hash a string to a BigInt-compatible numeric string for circuit input
function hashToBigInt(s: string): string {
  let hash = 0n;
  for (let i = 0; i < s.length; i++) {
    hash = (hash * 31n + BigInt(s.charCodeAt(i))) % (2n ** 128n);
  }
  return hash.toString();
}

// Map action to circuit integer
function actionToInt(action: StealAction): number {
  switch (action) {
    case 'FORTIFY': return 0;
    case 'EXTRACT': return 1;
    case 'HOLD':    return 2;
  }
}

export function registerAgentRoute(
  app: FastifyInstance,
  logger: ReturnType<typeof createLogger>,
): void {
  app.post('/', async (request, _reply): Promise<StealResponse | { ok: boolean; protocolVersion: string }> => {
    const startTime = Date.now();
    const task = request.body as StealTask;

    // Preflight: platform sends a signed POST with event_type='preflight'
    // or no match_id - respond immediately with 200
    if (!task?.match_id || (task as any).event_type === 'preflight') {
      logger.info('Preflight POST received - responding ok');
      return { ok: true, protocolVersion: 'v1' };
    }

    logger.info(
      { match_id: task.match_id, turn: task.turn, total_turns: task.total_turns },
      'Turn received',
    );

    try {
      // -- Get / create match state --
      const state = getOrCreate(task.match_id, task.total_turns);

      // -- Update opponent model with opponent's last action --
      if (task.opponent_last_action) {
        const opponentModel = getOrCreateModel(task.match_id);
        opponentModel.update(task.opponent_last_action);
      }

      // -- Update match state from task data --
      state.turn = task.turn;
      state.myBalance = task.my_balance;
      state.opponentBalance = task.opponent_balance;
      state.lastUpdated = Date.now();

      if (task.opponent_last_action) {
        state.opponentHistory.push(task.opponent_last_action);
      }

      // -- Select action via strategy engine --
      const action = selectAction(state);

      // -- Record our action --
      state.myHistory.push(action);

      // -- Generate Groth16 proof --
      let proof = undefined;
      let publicSignals = undefined;

      try {
        const circuitInputs = {
          action: actionToInt(action),
          turn: task.turn,
          match_id_hash: hashToBigInt(task.match_id),
          my_balance: task.my_balance,
          strategy_hash: hashToBigInt(task.strategy_hash ?? 'default'),
        };

        const result = await generateProof(circuitInputs);
        proof = result.proof;
        publicSignals = result.publicSignals;
        logger.info({ match_id: task.match_id, turn: task.turn }, 'Proof generated successfully');
      } catch (proofErr) {
        logger.error(
          { err: proofErr, match_id: task.match_id, turn: task.turn },
          'Proof generation failed - accepting -2 penalty',
        );
      }

      const elapsed = Date.now() - startTime;
      logger.info(
        {
          match_id: task.match_id,
          turn: task.turn,
          action,
          opponent_action: task.opponent_last_action ?? 'none',
          my_balance: task.my_balance,
          opponent_balance: task.opponent_balance,
          has_proof: !!proof,
          elapsed_ms: elapsed,
        },
        'Turn completed',
      );

      return {
        action,
        reason_code: 'STRATEGY',
        proof,
        public_signals: publicSignals,
      };
    } catch (err) {
      const elapsed = Date.now() - startTime;
      logger.error(
        { err, match_id: task.match_id, turn: task.turn, elapsed_ms: elapsed },
        'Turn handler error - defaulting to HOLD',
      );

      return {
        action: 'HOLD',
        reason_code: 'ERROR_FALLBACK',
      };
    }
  });
}
