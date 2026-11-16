// ============================================================
// Alpines Stealer - Bayesian Opponent Modeler
// ============================================================

import type { StealAction, ActionProbabilities } from '@zkverify/shared';

/**
 * Bayesian opponent model using Dirichlet-Categorical conjugate prior.
 * Starts with a uniform prior (alpha = 1 for each action) and updates
 * incrementally as opponent actions are observed.
 */
export class OpponentModel {
  // Dirichlet prior parameters (start uniform)
  private alpha: { FORTIFY: number; EXTRACT: number; HOLD: number };

  // Sliding window size for pattern detection
  private readonly windowSize = 5;

  // Full history for pattern detection
  private history: StealAction[] = [];

  constructor() {
    this.alpha = { FORTIFY: 1, EXTRACT: 1, HOLD: 1 };
  }

  /**
   * Update the model after observing an opponent action.
   */
  update(action: StealAction): void {
    this.alpha[action] += 1;
    this.history.push(action);
  }

  /**
   * Get estimated opponent action probabilities (posterior mean of Dirichlet).
   */
  getEstimate(): ActionProbabilities {
    const total = this.alpha.FORTIFY + this.alpha.EXTRACT + this.alpha.HOLD;
    return {
      FORTIFY: this.alpha.FORTIFY / total,
      EXTRACT: this.alpha.EXTRACT / total,
      HOLD: this.alpha.HOLD / total,
    };
  }

  /**
   * Detect if opponent has a dominant pattern in recent history.
   * Returns the dominant action if one exceeds 60% of recent plays.
   */
  detectPattern(): StealAction | null {
    if (this.history.length < 3) return null;
    const recent = this.history.slice(-this.windowSize);
    const counts: Record<StealAction, number> = { FORTIFY: 0, EXTRACT: 0, HOLD: 0 };
    for (const a of recent) counts[a]++;

    for (const action of ['FORTIFY', 'EXTRACT', 'HOLD'] as StealAction[]) {
      if (counts[action] / recent.length > 0.6) {
        return action;
      }
    }
    return null;
  }

  /**
   * Get confidence level (0-1) based on the number of observations.
   * Reaches 1.0 after 10 observations.
   */
  getConfidence(): number {
    const observations = this.alpha.FORTIFY + this.alpha.EXTRACT + this.alpha.HOLD - 3; // subtract initial priors
    return Math.min(observations / 10, 1);
  }

  /**
   * Get the full action history for this opponent.
   */
  getHistory(): StealAction[] {
    return this.history;
  }
}

// -- Per-match opponent model registry --

const models = new Map<string, OpponentModel>();

/**
 * Get or create an opponent model for a given match.
 */
export function getOrCreateModel(matchId: string): OpponentModel {
  let model = models.get(matchId);
  if (!model) {
    model = new OpponentModel();
    models.set(matchId, model);
  }
  return model;
}

/**
 * Remove the opponent model for a completed match.
 */
export function removeModel(matchId: string): void {
  models.delete(matchId);
}
