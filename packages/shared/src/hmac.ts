/**
 * HMAC-SHA256 authentication for Agent Games platform.
 *
 * - Verify every inbound request BEFORE JSON parsing (use raw body).
 * - Sign every outbound response body and set x-agent-games-signature header.
 * - Uses timing-safe comparison to prevent timing attacks.
 *
 * Key-encoding auto-detection order:
 *   1. 64 hex chars (32-byte key) -> decoded as hex
 *   2. base64 string with valid base64 chars -> decoded as base64
 *   3. fallback -> treated as raw UTF-8
 *
 * Signature format tolerance:
 *   - Plain hex:         "abc123..."
 *   - Prefixed hex:      "sha256=abc123..." (webhook convention)
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

let cachedKeyBuffer: Buffer | null = null;

/**
 * Initialize the HMAC module with the shared secret.
 * Call once at startup - caches the key buffer for performance.
 *
 * Auto-detects key encoding:
 *   - 64 lowercase/uppercase hex chars -> decoded as hex (32-byte key)
 *   - Valid base64 string              -> decoded as base64
 *   - Everything else                  -> treated as UTF-8
 */
export function initHmac(secret: string): void {
  const trimmed = secret.trim();

  if (trimmed.length === 64 && /^[0-9a-fA-F]+$/.test(trimmed)) {
    // 64 hex chars = 32 raw bytes - most common for Agent Games
    cachedKeyBuffer = Buffer.from(trimmed, 'hex');
  } else if (trimmed.length % 4 === 0 && /^[A-Za-z0-9+/]+=*$/.test(trimmed)) {
    // base64-encoded key (e.g. 44 chars = 32 bytes, 88 chars = 64 bytes)
    cachedKeyBuffer = Buffer.from(trimmed, 'base64');
  } else {
    // Raw UTF-8 string key
    cachedKeyBuffer = Buffer.from(trimmed, 'utf-8');
  }
}

/**
 * Compute HMAC-SHA256 signature of a payload.
 * Returns lowercase hex string.
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
 *
 * Accepts:
 *   - Plain hex signature:    "abc123..."
 *   - Prefixed signature:     "sha256=abc123..."
 *
 * Returns true if the signature matches, false otherwise.
 */
export function verifyHmac(body: string | Buffer, signature: string): boolean {
  if (!cachedKeyBuffer) {
    throw new Error('HMAC not initialized - call initHmac() at startup');
  }

  // Strip optional "sha256=" prefix (webhook convention used by GitHub, Stripe, etc.)
  const normalizedSig = signature.startsWith('sha256=')
    ? signature.slice(7)
    : signature;

  const computed = signHmac(body);

  // Guard: if signature is not valid hex, comparison will always fail safely
  if (!/^[0-9a-fA-F]+$/.test(normalizedSig)) {
    return false;
  }

  const sigBuf = Buffer.from(normalizedSig, 'hex');
  const compBuf = Buffer.from(computed, 'hex');

  // Length mismatch -> reject (timingSafeEqual requires equal lengths)
  if (sigBuf.length !== compBuf.length) {
    return false;
  }

  return timingSafeEqual(compBuf, sigBuf);
}
