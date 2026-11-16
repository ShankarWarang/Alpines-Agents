// ============================================================
// Alpines Stealer - Nash Equilibrium + Bayesian Adaptive Strategy
// ============================================================
//
// Game-theory engine for a 3-action set (FORTIFY, EXTRACT, HOLD) over
// a finite number of turns. Combines a pre-computed Nash equilibrium
// base strategy with Bayesian opponent modelling and situational
// adjustments for endgame, balance, and pattern exploitation.
//
// All computation is O(1) - no iterative solvers, no LLM calls.
// ============================================================

import { getOrCreateModel } from './opponent.js';
import type { StealAction, ActionProbabilities, MatchState } from '@zkverify/shared';

// -- Payoff Matrix ------------------------------------------
// Row = my action, Column = opponent action. Value = my expected payoff.
const PAYOFF_MATRIX: Record<StealAction, Record<StealAction, number>> = {
  FORTIFY: { FORTIFY: -2, EXTRACT: 3, HOLD: -2 },
  EXTRACT: { FORTIFY: 1, EXTRACT: -1, HOLD: 5 },
  HOLD: { FORTIFY: 0, EXTRACT: -4, HOLD: 0 },
};

// -- Nash Equilibrium Base Strategy -------------------------
// Pre-computed approximate equilibrium for the payoff matrix above.
const NASH_BASE: ActionProbabilities = {
  FORTIFY: 0.30,
  EXTRACT: 0.45,
  HOLD: 0.25,
};

// Maximum allowed deviation from Nash (anti-exploitation safety bound)
const MAX_DEVIATION = 0.20;

// Endgame threshold - final N turns trigger aggression shift
const ENDGAME_TURNS = 3;

// ------------------------------------------------------------
// Public API
// ------------------------------------------------------------

/**
 * Select the best action for the current match state.
 *
 * Pipeline:
 *  1. Compute best response to opponent's estimated strategy
 *  2. Blend Nash base with best response (weighted by confidence)
 *  3. Endgame aggression adjustment
 *  4. Balance-aware adjustment
 *  5. Clamp deviations from Nash within safety bound
 *  6. Sample action from final probability distribution
 */
export function selectAction(state: MatchState): StealAction {
  const model = getOrCreateModel(state.matchId);
  const confidence = model.getConfidence();
  const opponentEstimate = model.getEstimate();

  // Phase 1: Best response to opponent's estimated distribution
  const bestResponse = computeBestResponse(opponentEstimate);

  // Phase 2: Blend Nash ↔ best response based on confidence
  let blended = blendStrategies(NASH_BASE, bestResponse, confidence);

  // Phase 2b: Pattern exploitation - if opponent has a dominant pattern (>60%
  // of recent 5 turns), boost the counter-action weight directly.
  const dominantPattern = model.detectPattern();
  if (dominantPattern !== null) {
    // Counter-map: best counter to each dominant action
    const counter: Record<StealAction, StealAction> = {
      FORTIFY: 'HOLD',    // opponent is wasting cost - just HOLD
      EXTRACT: 'FORTIFY', // opponent is extracting - protect yourself
      HOLD:    'EXTRACT', // opponent is idle and exposed - take from them
    };
    const counterAction = counter[dominantPattern];
    // Shift 15% probability mass toward counter-action (bounded by clamp later)
    const shift = 0.15;
    blended = {
      ...blended,
      [counterAction]: Math.min(0.80, blended[counterAction] + shift),
      FORTIFY: counterAction === 'FORTIFY' ? Math.min(0.80, blended.FORTIFY + shift) : Math.max(0.05, blended.FORTIFY - shift / 2),
      EXTRACT: counterAction === 'EXTRACT' ? Math.min(0.80, blended.EXTRACT + shift) : Math.max(0.05, blended.EXTRACT - shift / 2),
      HOLD:    counterAction === 'HOLD'    ? Math.min(0.80, blended.HOLD    + shift) : Math.max(0.05, blended.HOLD    - shift / 2),
    };
    // Re-normalize
    const total = blended.FORTIFY + blended.EXTRACT + blended.HOLD;
    blended = { FORTIFY: blended.FORTIFY / total, EXTRACT: blended.EXTRACT / total, HOLD: blended.HOLD / total };
  }

  // Phase 3: Endgame adjustment
  const turnsLeft = state.totalTurns - state.turn;
  let finalStrategy = blended;
  if (turnsLeft <= ENDGAME_TURNS) {
    finalStrategy = endgameAdjust(blended, turnsLeft);
  }

  // Phase 4: Balance-aware adjustment
  finalStrategy = balanceAdjust(finalStrategy, state);

  // Phase 5: Clamp deviations from Nash (anti-exploitation safety bound)
  finalStrategy = clampDeviation(finalStrategy, NASH_BASE, MAX_DEVIATION);

  // Phase 6: Sample
  return sampleAction(finalStrategy);
}

// ------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------

/**
 * Compute best-response probabilities against opponent's estimated
 * action distribution using softmax over expected payoffs.
 */
function computeBestResponse(opponentProbs: ActionProbabilities): ActionProbabilities {
  const actions: StealAction[] = ['FORTIFY', 'EXTRACT', 'HOLD'];
  const expectedPayoffs: Record<StealAction, number> = { FORTIFY: 0, EXTRACT: 0, HOLD: 0 };

  for (const myAction of actions) {
    for (const oppAction of actions) {
      expectedPayoffs[myAction] += PAYOFF_MATRIX[myAction][oppAction] * opponentProbs[oppAction];
    }
  }

  // Softmax with temperature to control exploration vs exploitation
  const temperature = 2.0;
  const maxPayoff = Math.max(...Object.values(expectedPayoffs));
  const expPayoffs: Record<StealAction, number> = { FORTIFY: 0, EXTRACT: 0, HOLD: 0 };
  let sumExp = 0;

  for (const action of actions) {
    expPayoffs[action] = Math.exp((expectedPayoffs[action] - maxPayoff) / temperature);
    sumExp += expPayoffs[action];
  }

  return {
    FORTIFY: expPayoffs.FORTIFY / sumExp,
    EXTRACT: expPayoffs.EXTRACT / sumExp,
    HOLD: expPayoffs.HOLD / sumExp,
  };
}

/**
 * Blend two strategy vectors. `weight` controls how much we lean
 * toward the best response (0 = pure Nash, 0.6 = max exploitation).
 */
function blendStrategies(
  nash: ActionProbabilities,
  bestResponse: ActionProbabilities,
  confidence: number,
): ActionProbabilities {
  // Even at full confidence, cap exploitation weight at 60%
  const weight = confidence * 0.6;
  return {
    FORTIFY: nash.FORTIFY * (1 - weight) + bestResponse.FORTIFY * weight,
    EXTRACT: nash.EXTRACT * (1 - weight) + bestResponse.EXTRACT * weight,
    HOLD: nash.HOLD * (1 - weight) + bestResponse.HOLD * weight,
  };
}

/**
 * In the final turns, shift probability mass toward EXTRACT.
 * Less future to protect → more aggressive extraction.
 */
function endgameAdjust(strategy: ActionProbabilities, turnsLeft: number): ActionProbabilities {
  const aggression = 0.10 * (ENDGAME_TURNS - turnsLeft + 1) / ENDGAME_TURNS;
  return {
    FORTIFY: Math.max(0.05, strategy.FORTIFY - aggression * 0.5),
    EXTRACT: Math.min(0.80, strategy.EXTRACT + aggression),
    HOLD: Math.max(0.05, strategy.HOLD - aggression * 0.5),
  };
}

/**
 * Adjust strategy based on the balance differential.
 * Behind → more aggressive (EXTRACT). Ahead → more defensive (FORTIFY).
 */
function balanceAdjust(strategy: ActionProbabilities, state: MatchState): ActionProbabilities {
  const balanceDiff = state.myBalance - state.opponentBalance;

  if (balanceDiff < -20) {
    // Significantly behind - push EXTRACT
    return {
      FORTIFY: Math.max(0.05, strategy.FORTIFY - 0.10),
      EXTRACT: Math.min(0.80, strategy.EXTRACT + 0.15),
      HOLD: Math.max(0.05, strategy.HOLD - 0.05),
    };
  }

  if (balanceDiff > 20) {
    // Significantly ahead - protect the lead
    return {
      FORTIFY: Math.min(0.60, strategy.FORTIFY + 0.15),
      EXTRACT: Math.max(0.10, strategy.EXTRACT - 0.10),
      HOLD: Math.max(0.05, strategy.HOLD - 0.05),
    };
  }

  return strategy;
}

/**
 * Clamp each probability within ±MAX_DEVIATION of the Nash base,
 * then re-normalize so probabilities sum to 1.
 */
function clampDeviation(
  strategy: ActionProbabilities,
  base: ActionProbabilities,
  maxDev: number,
): ActionProbabilities {
  const clamped = {
    FORTIFY: Math.max(base.FORTIFY - maxDev, Math.min(base.FORTIFY + maxDev, strategy.FORTIFY)),
    EXTRACT: Math.max(base.EXTRACT - maxDev, Math.min(base.EXTRACT + maxDev, strategy.EXTRACT)),
    HOLD: Math.max(base.HOLD - maxDev, Math.min(base.HOLD + maxDev, strategy.HOLD)),
  };

  // Normalize to ensure probabilities sum to 1
  const total = clamped.FORTIFY + clamped.EXTRACT + clamped.HOLD;
  return {
    FORTIFY: clamped.FORTIFY / total,
    EXTRACT: clamped.EXTRACT / total,
    HOLD: clamped.HOLD / total,
  };
}

/**
 * Sample a single action from a probability distribution.
 */
function sampleAction(probs: ActionProbabilities): StealAction {
  const rand = Math.random();
  if (rand < probs.FORTIFY) return 'FORTIFY';
  if (rand < probs.FORTIFY + probs.EXTRACT) return 'EXTRACT';
  return 'HOLD';
}
