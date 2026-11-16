#!/usr/bin/env node
/**
 * HMAC Secret Diagnostic Tool
 *
 * Run on the VPS:
 *   node /opt/zkverify/scripts/hmac-diagnose.mjs
 *
 * This tests HMAC computation with EVERY possible key-encoding
 * of AGENT_GAMES_HMAC_SECRET, so you can compare against the platform.
 *
 * Usage with captured body+sig (paste from logs):
 *   BODY='{"event_type":"preflight"}' SIG='fd8b509e...' \
 *     node /opt/zkverify/scripts/hmac-diagnose.mjs
 */

import 'dotenv/config';
import { createHmac } from 'node:crypto';

// Accept agent-specific or legacy shared secret name
const rawSecret =
  process.env.KEEPER_HMAC_SECRET ??
  process.env.STEALER_HMAC_SECRET ??
  process.env.AGENT_GAMES_HMAC_SECRET ??
  '';
const capturedBody = process.env.BODY ?? '';
const capturedSig = process.env.SIG ?? '';

if (!rawSecret) {
  console.error('ERROR: AGENT_GAMES_HMAC_SECRET not set in .env');
  process.exit(1);
}

console.log('\n=== HMAC Secret Diagnostic ===\n');
console.log(`Secret length  : ${rawSecret.length} chars`);
console.log(`Secret preview : ${rawSecret.slice(0, 8)}...${rawSecret.slice(-4)}`);
console.log(`Secret (full)  : ${rawSecret}`);

// Detect encoding
const isHex64 = rawSecret.length === 64 && /^[0-9a-fA-F]+$/.test(rawSecret.trim());
const isBase64 = rawSecret.length % 4 === 0 && /^[A-Za-z0-9+/]+=*$/.test(rawSecret.trim());
console.log(`\nDetected as    : ${isHex64 ? 'HEX (64 chars -> 32 bytes)' : isBase64 ? 'BASE64' : 'UTF-8 string'}`);

// Build all candidate key buffers
const candidates = [
  { label: 'utf-8 (use string as-is)', buf: Buffer.from(rawSecret, 'utf-8') },
  { label: 'utf-8 trimmed',            buf: Buffer.from(rawSecret.trim(), 'utf-8') },
];

if (isHex64 || /^[0-9a-fA-F]+$/.test(rawSecret.trim())) {
  candidates.push({
    label: 'hex decoded (hex string -> raw bytes)',
    buf: Buffer.from(rawSecret.trim(), 'hex'),
  });
}

if (isBase64 || /^[A-Za-z0-9+/]+=*$/.test(rawSecret.trim())) {
  candidates.push({
    label: 'base64 decoded (base64 -> raw bytes)',
    buf: Buffer.from(rawSecret.trim(), 'base64'),
  });
}

console.log('\n=== Key Buffer Sizes ===');
candidates.forEach(({ label, buf }) => {
  console.log(`  [${buf.length} bytes] ${label}`);
});

// If a captured body is provided, compute HMAC for each candidate
if (capturedBody) {
  console.log(`\n=== HMAC-SHA256 Results for body (${capturedBody.length} chars) ===`);
  if (capturedSig) {
    const normSig = capturedSig.startsWith('sha256=') ? capturedSig.slice(7) : capturedSig;
    console.log(`Platform sig   : ${normSig}`);
    console.log('');
  }

  candidates.forEach(({ label, buf }) => {
    const computed = createHmac('sha256', buf)
      .update(capturedBody)
      .digest('hex');
    const match = capturedSig
      ? computed === (capturedSig.startsWith('sha256=') ? capturedSig.slice(7) : capturedSig)
      : null;
    const matchStr = match === null ? '' : match ? ' <-- MATCH!' : '';
    console.log(`  ${label}\n    HMAC: ${computed}${matchStr}\n`);
  });

  if (capturedSig) {
    const anyMatch = candidates.some(({ buf }) => {
      const computed = createHmac('sha256', buf).update(capturedBody).digest('hex');
      const normSig = capturedSig.startsWith('sha256=') ? capturedSig.slice(7) : capturedSig;
      return computed === normSig;
    });
    if (!anyMatch) {
      console.log('NONE matched. The secret in .env is likely wrong (copy-paste error or wrong secret).');
      console.log('Ask the platform to show/reset the HMAC secret and try again.');
    }
  }
} else {
  console.log('\nTip: Re-run with BODY and SIG env vars from the journalctl logs to verify:');
  console.log('  BODY=\'{"event_type":"preflight",...}\' SIG=\'fd8b509e...\' node scripts/hmac-diagnose.mjs');
}

console.log('\n=== Current initHmac() behavior ===');
const { label: chosenLabel, buf: chosenBuf } = (() => {
  const s = rawSecret.trim();
  if (s.length === 64 && /^[0-9a-fA-F]+$/.test(s)) return candidates.find(c => c.label.startsWith('hex')) ?? candidates[0];
  if (s.length % 4 === 0 && /^[A-Za-z0-9+/]+=*$/.test(s)) return candidates.find(c => c.label.startsWith('base64')) ?? candidates[0];
  return candidates[0];
})();
console.log(`  initHmac() will use: ${chosenLabel} (${chosenBuf.length} bytes)`);
console.log('');
