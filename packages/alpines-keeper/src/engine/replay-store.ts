/**
 * In-memory replay detection store.
 *
 * Tracks proof_tx hashes to detect proof reuse attacks.
 * Entries are automatically cleaned up after 24 hours.
 */

const store = new Map<string, number>();

let cleanupTimer: ReturnType<typeof setInterval> | undefined;

/**
 * Check whether a proof_tx has been seen before.
 */
export function hasSeen(proofTx: string): boolean {
  return store.has(proofTx);
}

/**
 * Mark a proof_tx as seen (records current timestamp).
 */
export function markSeen(proofTx: string): void {
  store.set(proofTx, Date.now());
}

/**
 * Remove entries older than maxAgeMs (default 24 hours).
 */
export function cleanup(maxAgeMs: number = 86_400_000): void {
  const cutoff = Date.now() - maxAgeMs;
  for (const [key, timestamp] of store) {
    if (timestamp < cutoff) {
      store.delete(key);
    }
  }
}

/**
 * Start the periodic cleanup interval (every 1 hour).
 * Call once at startup. Safe to call multiple times - only one timer runs.
 */
export function startCleanupInterval(): void {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => cleanup(), 3_600_000);
  // Allow the process to exit even if the timer is still running
  if (cleanupTimer.unref) {
    cleanupTimer.unref();
  }
}

/**
 * Stop the cleanup interval (for graceful shutdown).
 */
export function stopCleanupInterval(): void {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = undefined;
  }
}
