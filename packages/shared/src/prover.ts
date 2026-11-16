/**
 * Groth16 Proof Generator
 *
 * Two backends:
 *   1. rapidsnark (native C++ binary) - PRIMARY, ~5-10x faster
 *   2. snarkjs WASM - FALLBACK, pure JavaScript
 *
 * rapidsnark flow:
 *   snarkjs.wtns.calculate() → temp .wtns file → rapidsnark binary → proof JSON
 *
 * Both backends produce identical Groth16 proofs. The circuit artifacts
 * (WASM + zkey) are kept on disk and referenced by path.
 */

import { readFile, rm, access, constants, mkdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import type { ProofResult, ProverConfig } from './types.js';

const execFileAsync = promisify(execFile);

// Module state
let config: ProverConfig;
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- snarkjs lacks proper ESM type declarations
let snarkjs: any;
let useRapidsnark = false;
let initialized = false;

/**
 * Initialize the prover. Call once at startup.
 * Validates circuit artifacts exist and checks for rapidsnark binary.
 */
export async function initProver(cfg: ProverConfig): Promise<{
  backend: 'rapidsnark' | 'snarkjs';
}> {
  config = { ...cfg };

  // Validate circuit artifacts
  await access(config.wasmPath, constants.R_OK).catch(() => {
    throw new Error(`Circuit WASM not found: ${config.wasmPath}`);
  });
  await access(config.zkeyPath, constants.R_OK).catch(() => {
    throw new Error(`Circuit zkey not found: ${config.zkeyPath}`);
  });

  // Lazy-import snarkjs (always needed for witness calculation)
  snarkjs = await import('snarkjs');

  // Check rapidsnark availability
  if (config.rapidsnarkBin) {
    try {
      await access(config.rapidsnarkBin, constants.X_OK);
      useRapidsnark = true;
    } catch {
      console.warn(
        `⚠ rapidsnark binary not found at ${config.rapidsnarkBin}, falling back to snarkjs WASM`
      );
      useRapidsnark = false;
    }
  }

  initialized = true;
  return { backend: useRapidsnark ? 'rapidsnark' : 'snarkjs' };
}

/**
 * Generate a Groth16 proof for the given circuit inputs.
 * Uses rapidsnark if available, otherwise falls back to snarkjs.
 */
export async function generateProof(
  inputs: Record<string, bigint | string | number | (bigint | string | number)[]>
): Promise<ProofResult> {
  if (!initialized) {
    throw new Error('Prover not initialized - call initProver() at startup');
  }

  if (useRapidsnark) {
    return rapidsnarkProve(inputs);
  }
  return snarkjsProve(inputs);
}

/**
 * snarkjs WASM backend - simpler, ~1-3s per proof.
 */
async function snarkjsProve(
  inputs: Record<string, bigint | string | number | (bigint | string | number)[]>
): Promise<ProofResult> {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    config.wasmPath,
    config.zkeyPath
  );
  return { proof, publicSignals };
}

/**
 * rapidsnark backend - native C++, ~200ms per proof.
 *
 * Flow:
 *   1. Calculate witness (snarkjs, in-process)
 *   2. Generate proof (rapidsnark binary, subprocess)
 *   3. Read output files
 *   4. Cleanup temp directory
 */
async function rapidsnarkProve(
  inputs: Record<string, bigint | string | number | (bigint | string | number)[]>
): Promise<ProofResult> {
  // Create isolated temp directory per proof (safe for concurrent calls)
  const tempId = randomBytes(8).toString('hex');
  const tempDir = join(tmpdir(), `zkp-${tempId}`);
  await mkdir(tempDir, { recursive: true });

  const witnessPath = join(tempDir, 'witness.wtns');
  const proofPath = join(tempDir, 'proof.json');
  const publicPath = join(tempDir, 'public.json');

  try {
    // Step 1: Calculate witness using snarkjs
    await snarkjs.wtns.calculate(inputs, config.wasmPath, witnessPath);

    // Step 2: Generate proof using rapidsnark (native C++)
    await execFileAsync(config.rapidsnarkBin!, [
      config.zkeyPath,
      witnessPath,
      proofPath,
      publicPath,
    ], {
      timeout: 30_000,    // 30s hard timeout
      maxBuffer: 10_000_000, // 10MB output buffer
    });

    // Step 3: Read proof output files
    const [proofRaw, publicRaw] = await Promise.all([
      readFile(proofPath, 'utf-8'),
      readFile(publicPath, 'utf-8'),
    ]);

    return {
      proof: JSON.parse(proofRaw),
      publicSignals: JSON.parse(publicRaw),
    };
  } finally {
    // Step 4: Cleanup temp directory (fire-and-forget)
    rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}
