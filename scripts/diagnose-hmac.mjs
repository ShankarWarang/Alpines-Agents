#!/usr/bin/env node
/**
 * diagnose-hmac.mjs
 *
 * Uses the ACTUAL body + signature captured from VPS logs to test every
 * possible HMAC key encoding and signing convention until one matches.
 *
 * Run on VPS:
 *   node scripts/diagnose-hmac.mjs
 *
 * It reads KEEPER_HMAC_SECRET and STEALER_HMAC_SECRET from the environment.
 */

import { createHmac } from 'node:crypto';
import { config } from 'dotenv';
config();

// ---- Real body+sig pairs captured from VPS logs ----
// (replace these with the most recent pair from logs if needed)
const KEEPER_BODY = '{"type":"agent-games.preflight.v1","agent_id":"bbd202a0-999b-4f41-818c-2f3dc5d3ebd2","issued_at":"2026-11-19T05:48:12.251Z","nonce":"97a1ec50-71ef-4322-a354-d236b85ea3fa"}';
const KEEPER_SIG  = 'd41eb21debc7ba69c6c0a708b1ea76f7809b7ec544c65f410ca599cc4b6d13d1';

const STEALER_BODY = '{"type":"agent-games.preflight.v1","agent_id":"9b5edcc2-218d-42ab-8806-6d9659d9c580","issued_at":"2026-11-19T05:48:12.251Z","nonce":"35edef3b-4e6a-4166-a10b-ed08d2ccf63c"}';
const STEALER_SIG  = '8bd530dfba997a00c84581bbc05ab16b75d67c2484fa3059bb376742c1e952fa';

// ----------------------------------------------------

function tryAll(label, secret, body, expectedSig) {
  if (!secret) {
    console.log(`\n[${label}] SECRET NOT SET IN ENV — skipping`);
    return;
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`[${label}] Secret length: ${secret.length} chars`);
  console.log(`[${label}] Secret preview: ${secret.slice(0, 8)}...${secret.slice(-4)}`);
  console.log(`[${label}] Expected sig:   ${expectedSig}`);

  const keyEncodings = [
    ['utf8  (raw string)', Buffer.from(secret.trim(), 'utf8')],
    ['hex   (decoded)',    /^[0-9a-fA-F]+$/.test(secret.trim()) && secret.trim().length % 2 === 0
      ? Buffer.from(secret.trim(), 'hex') : null],
    ['base64 (decoded)',  Buffer.from(secret.trim(), 'base64')],
  ];

  const bodyVariants = [
    ['raw body (as-is)',           body],
    ['body + newline',             body + '\n'],
    ['trimmed body',               body.trim()],
  ];

  const sigFormats = [
    ['hex',    (h) => h],
    ['sha256=hex', (h) => 'sha256=' + h],
  ];

  let found = false;
  for (const [encLabel, keyBuf] of keyEncodings) {
    if (!keyBuf) continue;
    for (const [bodyLabel, bodyVariant] of bodyVariants) {
      const computed = createHmac('sha256', keyBuf).update(bodyVariant).digest('hex');
      const match = computed === expectedSig.replace(/^sha256=/, '');
      if (match) {
        console.log(`\n  *** MATCH FOUND ***`);
        console.log(`  Key encoding : ${encLabel}`);
        console.log(`  Body variant : ${bodyLabel}`);
        found = true;
      }
    }
  }

  if (!found) {
    console.log(`\n  NO MATCH with any combination.`);
    console.log(`  Trying partial key lengths (in case secret has extra chars)...`);
    const trimVariants = [
      secret.trim(),
      secret.trim().replace(/\s+/g, ''),
      secret.slice(0, 64),   // first 64 chars
      secret.slice(-64),     // last 64 chars
    ];
    for (const tv of trimVariants) {
      for (const enc of ['utf8', 'hex', 'base64']) {
        try {
          const kbuf = Buffer.from(tv, enc);
          const c = createHmac('sha256', kbuf).update(body).digest('hex');
          if (c === expectedSig) {
            console.log(`  *** MATCH: enc=${enc} variant="${tv.slice(0,8)}..." ***`);
            found = true;
          }
        } catch {}
      }
    }
    if (!found) console.log(`  DEFINITIVE FAIL: secret in .env does not match platform.`);
    console.log(`\n  Action: Rotate Secret on dashboard again and paste the EXACT plaintext into .env`);
  }
}

tryAll(
  'KEEPER',
  process.env.KEEPER_HMAC_SECRET ?? '',
  KEEPER_BODY,
  KEEPER_SIG,
);

tryAll(
  'STEALER',
  process.env.STEALER_HMAC_SECRET ?? '',
  STEALER_BODY,
  STEALER_SIG,
);

console.log('\nDone.');
