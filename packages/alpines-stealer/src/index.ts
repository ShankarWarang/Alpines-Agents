// ============================================================
// Alpines Stealer - Entry Point
// Steal the VFY agent for zkVerify Agent Games
// ============================================================

import 'dotenv/config';
import { initHmac, initProver, initZkVerify, createLogger } from '@zkverify/shared';
import { createServer } from './server.js';

const logger = createLogger('alpines-stealer', 'stealer.log');

async function main(): Promise<void> {
  // -- Read environment --
  const hmacSecret = process.env.STEALER_HMAC_SECRET;
  if (!hmacSecret) {
    logger.error('STEALER_HMAC_SECRET is required - set it to the HMAC secret for alpines_stealer from the Agent Games dashboard');
    process.exit(1);
  }

  const port = parseInt(process.env.STEALER_PORT ?? '3002', 10);
  const wasmPath = process.env.STEALER_CIRCUIT_WASM ?? '';
  const zkeyPath = process.env.STEALER_CIRCUIT_ZKEY ?? '';
  const rapidsnarkBin = process.env.RAPIDSNARK_BIN;
  const zkVerifyApiUrl = process.env.ZKVERIFY_API_URL ?? '';
  const zkVerifyApiKey = process.env.ZKVERIFY_API_KEY;

  // -- Initialize shared modules --
  initHmac(hmacSecret);
  logger.info('HMAC authentication initialized');

  const { backend } = await initProver({ wasmPath, zkeyPath, rapidsnarkBin });
  logger.info(`Prover initialized (backend: ${backend})`);

  if (zkVerifyApiUrl) {
    initZkVerify({ apiUrl: zkVerifyApiUrl, apiKey: zkVerifyApiKey });
    logger.info('zkVerify client initialized');
  }

  // -- Start server --
  const server = createServer(logger);

  try {
    await server.listen({ port, host: '0.0.0.0' });
    logger.info(`Alpines Stealer listening on port ${port}`);
  } catch (err) {
    logger.error({ err }, 'Failed to start server');
    process.exit(1);
  }

  // -- Graceful shutdown --
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down gracefully…`);
    await server.close();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  logger.error({ err }, 'Fatal error during startup');
  process.exit(1);
});
