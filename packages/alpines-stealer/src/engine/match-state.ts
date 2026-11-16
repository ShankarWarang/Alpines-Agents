// ============================================================
// Alpines Stealer - In-Memory Match State Manager
// ============================================================

import type { MatchState, StealAction } from '@zkverify/shared';

// -- State store keyed by match_id --
const matches = new Map<string, MatchState & { lastUpdated: number }>();

/**
 * Get an existing match state or create a fresh one.
 */
export function getOrCreate(matchId: string, totalTurns: number): MatchState {
  let state = matches.get(matchId);
  if (!state) {
    state = {
      matchId,
      turn: 0,
      totalTurns,
      myBalance: 0,
      opponentBalance: 0,
      myHistory: [],
      opponentHistory: [],
      lastUpdated: Date.now(),
    };
    matches.set(matchId, state);
  }
  state.lastUpdated = Date.now();
  return state;
}

/**
 * Update match state after a turn.
 */
export function updateState(
  matchId: string,
  myAction: StealAction,
  opponentAction: StealAction | undefined,
  myBalance: number,
  opponentBalance: number,
): void {
  const state = matches.get(matchId);
  if (!state) return;

  state.myHistory.push(myAction);
  if (opponentAction) {
    state.opponentHistory.push(opponentAction);
  }
  state.myBalance = myBalance;
  state.opponentBalance = opponentBalance;
  state.turn = state.myHistory.length;
  state.lastUpdated = Date.now();
}

/**
 * Get match state by ID.
 */
export function getState(matchId: string): MatchState | undefined {
  return matches.get(matchId);
}

/**
 * Cleanup completed matches older than 1 hour.
 */
export function cleanup(): void {
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  for (const [id, state] of matches) {
    if (state.turn >= state.totalTurns && state.lastUpdated < oneHourAgo) {
      matches.delete(id);
    }
  }
}

// Run cleanup every 30 minutes
setInterval(cleanup, 30 * 60 * 1000).unref();
