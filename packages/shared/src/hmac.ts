/**
 * HMAC-SHA256 authentication for Agent Games platform.
 *
 * - Verify every inbound request BEFORE JSON parsing (use raw body).
 * - Sign every outbound response body and set x-agent-games-signature header.
 * - Uses timing-safe comparison to prevent timing attacks.
 *
 * Key-encoding: verification tries all three common encodings (UTF-8, hex, base64)
 * so it works regardless of how the platform formats its secret token.
 * Signing uses UTF-8 (raw string) which is the platform's convention.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

let cachedSecret = '';

/**
 * Initialize the HMAC module with the shared secret.
 * Call once at startup.
 */
export function initHmac(secret: string): void {
  cachedSecret = secret.trim();
}

/**
 * Returns all plausible key buffers to try when verifying.
 * Platform may use the secret as raw UTF-8, hex-decoded, or base64-decoded.
 */
function getKeyVariants(): Buffer[] {
  const s = cachedSecret;
  const variants: Buffer[] = [];
  // 1. Raw UTF-8 — most common for randomly-generated tokens
  variants.push(Buffer.from(s, 'utf8'));
  // 2. Hex-decoded (e.g. 64-char hex -> 32 bytes)
  if (s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s)) {
    variants.push(Buffer.from(s, 'hex'));
  }
  // 3. Base64-decoded
  try {
    const decoded = Buffer.from(s, 'base64');
    if (decoded.length > 0) variants.push(decoded);
  } catch { /* ignore */ }
  return variants;
}

/**
 * Compute HMAC-SHA256 signature of a payload using the primary key (raw UTF-8).
 * Returns lowercase hex string — used for SIGNING outbound responses.
 */
export function signHmac(body: string | Buffer): string {
  if (!cachedSecret) {
    throw new Error('HMAC not initialized - call initHmac() at startup');
  }
  const keyBuf = Buffer.from(cachedSecret, 'utf8');
  return createHmac('sha256', keyBuf)
    .update(body)
    .digest('hex');
}

/**
 * Verify an HMAC-SHA256 signature using timing-safe comparison.
 * Tries all key encoding variants (UTF-8, hex-decoded, base64-decoded).
 *
 * Accepts:
 *   - Plain hex signature:    "abc123..."
 *   - Prefixed signature:     "sha256=abc123..."
 *
 * Returns true if any variant matches, false otherwise.
 */
export function verifyHmac(body: string | Buffer, signature: string): boolean {
  if (!cachedSecret) {
    throw new Error('HMAC not initialized - call initHmac() at startup');
  }

  // Strip optional "sha256=" prefix
  const normalizedSig = signature.startsWith('sha256=')
    ? signature.slice(7)
    : signature;

  // Guard: if signature is not valid hex, reject safely
  if (!/^[0-9a-fA-F]+$/.test(normalizedSig)) {
    return false;
  }

  const sigBuf = Buffer.from(normalizedSig, 'hex');

  for (const keyBuf of getKeyVariants()) {
    const computed = createHmac('sha256', keyBuf).update(body).digest('hex');
    const compBuf = Buffer.from(computed, 'hex');
    if (sigBuf.length === compBuf.length && timingSafeEqual(compBuf, sigBuf)) {
      return true;
    }
  }

  return false;
}
