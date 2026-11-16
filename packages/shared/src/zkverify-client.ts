/**
 * zkVerify / Kurier REST Client
 *
 * Handles:
 *   - Proof verification via Kurier REST API
 *   - Transaction finalization status checks
 *   - Automatic retry with exponential backoff
 *   - Connection keep-alive for reduced latency
 */

import type { Groth16Proof, ZkVerifyConfig, ZkVerifyVerifyResult } from './types.js';

let apiUrl: string;
let apiKey: string | undefined;
let initialized = false;

// Keep-alive agent for connection reuse
const keepAliveHeaders = {
  'Connection': 'keep-alive',
};

/**
 * Initialize the zkVerify client. Call once at startup.
 */
export function initZkVerify(config: ZkVerifyConfig): void {
  apiUrl = config.apiUrl.replace(/\/+$/, '');
  apiKey = config.apiKey;
  initialized = true;
}

/**
 * Fetch with automatic retry and exponential backoff.
 */
async function fetchRetry(
  url: string,
  options: RequestInit,
  maxRetries = 3
): Promise<Response> {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(15_000), // 15s timeout per attempt
      });

      // Retry on 5xx server errors
      if (response.status >= 500 && attempt < maxRetries) {
        await sleep(1000 * Math.pow(2, attempt));
        continue;
      }

      return response;
    } catch (err) {
      lastError = err as Error;
      if (attempt < maxRetries) {
        await sleep(1000 * Math.pow(2, attempt));
      }
    }
  }

  throw lastError ?? new Error('Fetch failed after retries');
}

/**
 * Verify a Groth16 proof via zkVerify's Kurier API.
 */
export async function verifyProof(
  proof: Groth16Proof,
  publicSignals: string[],
  vkHash?: string
): Promise<ZkVerifyVerifyResult> {
  if (!initialized) {
    throw new Error('zkVerify client not initialized - call initZkVerify()');
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...keepAliveHeaders,
  };
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }

  try {
    const response = await fetchRetry(`${apiUrl}/verify`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        proof,
        public_inputs: publicSignals,
        vk_hash: vkHash,
        proving_system: 'groth16',
        curve: 'bn128',
      }),
    });

    if (!response.ok) {
      return { valid: false, finalized: false };
    }

    const result = (await response.json()) as Record<string, unknown>;
    return {
      valid: (result.valid as boolean) ?? false,
      finalized: (result.finalized as boolean) ?? false,
      txHash: result.tx_hash as string | undefined,
    };
  } catch {
    return { valid: false, finalized: false };
  }
}

/**
 * Check if a proof transaction has been finalized on-chain.
 */
export async function checkFinalization(txHash: string): Promise<boolean> {
  if (!initialized) return false;

  const headers: Record<string, string> = { ...keepAliveHeaders };
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }

  try {
    const response = await fetchRetry(`${apiUrl}/tx/${txHash}/status`, {
      method: 'GET',
      headers,
    });

    if (!response.ok) return false;

    const result = (await response.json()) as Record<string, unknown>;
    return result.status === 'Finalized';
  } catch {
    return false;
  }
}

/**
 * Submit a proof for on-chain verification and wait for the tx hash.
 */
export async function submitProof(
  proof: Groth16Proof,
  publicSignals: string[]
): Promise<string | null> {
  if (!initialized) return null;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...keepAliveHeaders,
  };
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }

  try {
    const response = await fetchRetry(`${apiUrl}/submit`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        proof,
        public_inputs: publicSignals,
        proving_system: 'groth16',
        curve: 'bn128',
      }),
    });

    if (!response.ok) return null;

    const result = (await response.json()) as Record<string, unknown>;
    return (result.tx_hash as string) ?? null;
  } catch {
    return null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
