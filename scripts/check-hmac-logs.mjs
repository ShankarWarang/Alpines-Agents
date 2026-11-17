#!/usr/bin/env node
/**
 * Extract the last HMAC check entry from journalctl (Pino JSON format)
 * and run hmac-diagnose.mjs with the captured sig+body.
 *
 * Usage:
 *   node scripts/check-hmac-logs.mjs keeper
 *   node scripts/check-hmac-logs.mjs stealer
 */
import { execSync, spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

const agent = process.argv[2] ?? 'keeper';
const service = agent === 'keeper' ? 'alpines-keeper' : 'alpines-stealer';
const secretEnv = agent === 'keeper' ? 'KEEPER_HMAC_SECRET' : 'STEALER_HMAC_SECRET';

// Load .env manually
let envVars = {};
try {
  const raw = readFileSync('/opt/zkverify/.env', 'utf-8');
  for (const line of raw.split('\n')) {
    const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (m) envVars[m[1]] = m[2].trim();
  }
} catch {
  console.error('Could not read /opt/zkverify/.env');
  process.exit(1);
}

const secret = envVars[secretEnv];
if (!secret) {
  console.error(`${secretEnv} not found in .env`);
  process.exit(1);
}

// Get last 500 log lines from journalctl
let logLines;
try {
  logLines = execSync(`journalctl -u ${service} -n 500 --no-pager --output=cat 2>/dev/null`, {
    encoding: 'utf-8',
  }).split('\n');
} catch {
  console.error('Could not read journalctl logs');
  process.exit(1);
}

// Find the last JSON line containing "fullSig" (keeper) or "sigPrefix" (stealer)
let lastEntry = null;
for (const line of logLines.reverse()) {
  try {
    const obj = JSON.parse(line);
    if (obj.fullSig || obj.sigPrefix) {
      lastEntry = obj;
      break;
    }
  } catch {}
}

if (!lastEntry) {
  console.log(`No HMAC check log entry found for ${service}.`);
  console.log('The service has not received any POST requests yet.');
  console.log('Send a request to the endpoint and re-run this script.');
  process.exit(0);
}

console.log(`\nLast HMAC check entry for ${service}:`);
console.log(JSON.stringify(lastEntry, null, 2));

const sig = lastEntry.fullSig ?? lastEntry.sigPrefix ?? '';
const body = lastEntry.fullBody ?? '';
const hmacOk = lastEntry.hmacOk;

console.log(`\nhmacOk from service: ${hmacOk}`);

if (!body) {
  console.log('\nNo fullBody in log (stealer only logs sigPrefix). Cannot diagnose further.');
  console.log(`Make sure KEEPER_HMAC_SECRET is correct in /opt/zkverify/.env`);
  process.exit(0);
}

// Run all encoding variants
const candidates = [
  { label: 'utf-8', buf: Buffer.from(secret, 'utf-8') },
  { label: 'utf-8 trimmed', buf: Buffer.from(secret.trim(), 'utf-8') },
];
if (/^[0-9a-fA-F]+$/.test(secret.trim())) {
  candidates.push({ label: 'hex decoded', buf: Buffer.from(secret.trim(), 'hex') });
}
if (/^[A-Za-z0-9+/]+=*$/.test(secret.trim())) {
  candidates.push({ label: 'base64 decoded', buf: Buffer.from(secret.trim(), 'base64') });
}

const normSig = sig.startsWith('sha256=') ? sig.slice(7) : sig;

console.log(`\nSignature from request: ${normSig}`);
console.log(`Body (${body.length} chars): ${body.slice(0, 100)}...`);
console.log('\nHMAC candidates:');

let anyMatch = false;
for (const { label, buf } of candidates) {
  const computed = createHmac('sha256', buf).update(body).digest('hex');
  const match = computed === normSig;
  if (match) anyMatch = true;
  console.log(`  [${match ? 'MATCH' : '    '}] ${label} (${buf.length} bytes): ${computed}`);
}

if (anyMatch) {
  console.log('\n✓ At least one encoding matches! The correct key encoding is shown above with [MATCH].');
  console.log('Update initHmac() to force that specific encoding if needed.');
} else {
  console.log('\n✗ NO ENCODING MATCHED.');
  console.log('The secret in .env is wrong. Steps to fix:');
  console.log(`  1. Go to Agent Games dashboard → alpines_${agent} → show HMAC secret`);
  console.log(`  2. Copy the EXACT secret value (no extra spaces/newlines)`);
  console.log(`  3. Update /opt/zkverify/.env: ${secretEnv}=<new-value>`);
  console.log('  4. Run: systemctl restart alpines-' + agent);
}
