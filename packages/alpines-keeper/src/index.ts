/**
 * Alpines Keeper - Entry Point
 *
 * Proof Gatekeeper agent for zkVerify Agent Games.
 * Deterministic rule engine, Groth16 proof generation, HMAC-authenticated Fastify server.
 */

import 'dotenv/config';
import {
  initHmac,
  initProver,
  initZkVerify,
  createLogger,
} from '@zkverify/shared';
import { buildServer } from './server.js';
import { startCleanupInterval, stopCleanupInterval } from './engine/replay-store.js';

const log = createLogger('keeper');

async function main(): Promise<void> {
  // -- Read environment variables ------------------------------
  const hmacSecret = process.env.KEEPER_HMAC_SECRET;
  if (!hmacSecret) {
    throw new Error('KEEPER_HMAC_SECRET is required - set it to the HMAC secret for alpines_keeper from the Agent Games dashboard');
  }

  const zkVerifyUrl = process.env.ZKVERIFY_API_URL;
  if (!zkVerifyUrl) {
    throw new Error('ZKVERIFY_API_URL is required');
  }

  const zkVerifyApiKey = process.env.ZKVERIFY_API_KEY;
  const port = parseInt(process.env.KEEPER_PORT ?? '3001', 10);
  const circuitWasm = process.env.KEEPER_CIRCUIT_WASM ?? './circuits/gatekeeper.wasm';
  const circuitZkey = process.env.KEEPER_CIRCUIT_ZKEY ?? './circuits/gatekeeper_final.zkey';
  const vkHash = process.env.KEEPER_VK_HASH ?? '';
  if (!vkHash) {
    log.warn('KEEPER_VK_HASH not set - VK mismatch check will REJECT all inbound proofs with a vk_hash field');
  }
  const rapidsnarkBin = process.env.RAPIDSNARK_BIN;

  // -- Initialize shared modules -------------------------------
  log.info('Initializing HMAC...');
  initHmac(hmacSecret);

  log.info('Initializing prover...');
  const { backend } = await initProver({
    wasmPath: circuitWasm,
    zkeyPath: circuitZkey,
    rapidsnarkBin,
  });
  log.info({ backend }, `Prover backend: ${backend}`);

  log.info('Initializing zkVerify client...');
  initZkVerify({
    apiUrl: zkVerifyUrl,
    apiKey: zkVerifyApiKey,
  });

  // -- Start replay store cleanup ------------------------------
  startCleanupInterval();

  // -- Build and start server ----------------------------------
  const app = await buildServer({ vkHash });

  await app.listen({ port, host: '0.0.0.0' });
  log.info({ port, backend, vkHash: vkHash ? vkHash.slice(0, 12) + '...' : 'not set' }, `Alpines Keeper listening on port ${port}`);

  // -- Graceful shutdown ---------------------------------------
  const shutdown = async (signal: string) => {
    log.info({ signal }, 'Shutting down...');
    stopCleanupInterval();
    await app.close();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  console.error('Fatal error starting Alpines Keeper:', err);
  process.exit(1);
});
