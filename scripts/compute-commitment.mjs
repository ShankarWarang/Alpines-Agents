#!/usr/bin/env node
/**
 * compute-commitment.mjs
 *
 * Prints the Poseidon commitment hash for the stealer strategy params + salt.
 * Use this to find the value to register on the Agent Games dashboard.
 *
 * Usage:
 *   node scripts/compute-commitment.mjs
 *
 * Output: the commitment hex (Poseidon(params, salt)) -- safe to share.
 * Does NOT print the params or salt values.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { buildPoseidon } = require('circomlibjs');

// ---- CONFIGURE THESE ----
// Must match STRATEGY_PARAMS and STRATEGY_SALT in agent.ts
const params = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
const salt   = 0n;
// -------------------------

const poseidon = await buildPoseidon();
const F = poseidon.F;

const inputs = [...params, salt];  // 9-element array: 8 params + salt
const hash = poseidon(inputs);
const hex = '0x' + F.toObject(hash).toString(16).padStart(64, '0');

console.log('Commitment (register this on the dashboard):');
console.log(hex);
