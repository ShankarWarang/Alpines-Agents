/**
 * HMAC-SHA256 authentication for Agent Games platform.
 *
 * - Verify every inbound request BEFORE JSON parsing (use raw body).
 * - Sign every outbound response body and set x-agent-games-signature header.
 * - Uses timing-safe comparison to prevent timing attacks.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

let cachedKeyBuffer: Buffer | null = null;

/**
 * Initialize the HMAC module with the shared secret.
 * Call once at startup - caches the key buffer for performance.
 */
export function initHmac(secret: string): void {
  // Support both hex-encoded and raw string secrets
  cachedKeyBuffer = secret.length === 64 && /^[0-9a-f]+$/i.test(secret)
    ? Buffer.from(secret, 'hex')
    : Buffer.from(secret, 'utf-8');
}

/**
 * Compute HMAC-SHA256 signature of a payload.
 */
export function signHmac(body: string | Buffer): string {
  if (!cachedKeyBuffer) {
    throw new Error('HMAC not initialized - call initHmac() at startup');
  }
  return createHmac('sha256', cachedKeyBuffer)
    .update(body)
    .digest('hex');
}

/**
 * Verify an HMAC-SHA256 signature using timing-safe comparison.
 * Returns true if the signature matches, false otherwise.
 */
export function verifyHmac(body: string | Buffer, signature: string): boolean {
  if (!cachedKeyBuffer) {
    throw new Error('HMAC not initialized - call initHmac() at startup');
  }

  const computed = signHmac(body);

  // Normalize to buffers for timing-safe comparison
  const sigBuf = Buffer.from(signature, 'hex');
  const compBuf = Buffer.from(computed, 'hex');

  // Length mismatch → reject (timingSafeEqual requires equal lengths)
  if (sigBuf.length !== compBuf.length) {
    return false;
  }

  return timingSafeEqual(compBuf, sigBuf);
}
