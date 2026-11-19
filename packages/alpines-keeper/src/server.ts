/**
 * Fastify server factory for Alpines Keeper.
 *
 * Creates a Fastify instance with:
 *   - Custom JSON content type parser that preserves raw body for HMAC verification
 *   - preHandler hook: verifies HMAC signature on every inbound request
 *   - onSend hook: signs every outbound response body with HMAC
 *   - Health and agent routes
 */

import Fastify, { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import { verifyHmac, signHmac, createLogger } from '@zkverify/shared';
import { healthRoutes } from './routes/health.js';
import { agentRoutes, setVkHash } from './routes/agent.js';

const log = createLogger('server');

// Extend FastifyRequest to carry rawBody
declare module 'fastify' {
  interface FastifyRequest {
    rawBody?: string;
  }
}

export interface ServerOptions {
  vkHash: string;
}

export async function buildServer(options: ServerOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: true,
  });

  // -- Custom JSON parser that stores raw body -----------------
  app.addContentTypeParser(
    'application/json',
    { parseAs: 'string' },
    (req: any, body: string, done: (err: Error | null, result?: unknown) => void) => {
      req.rawBody = body;
      try {
        const parsed = JSON.parse(body);
        done(null, parsed);
      } catch (err) {
        done(err as Error);
      }
    }
  );

  // -- preHandler: verify inbound HMAC -------------------------
  app.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    // Skip HMAC check for read-only methods
    if (request.method === 'GET' || request.method === 'HEAD') return;

    const signature = request.headers['x-agent-games-signature'] as string | undefined;

    // No signature at all - reject
    if (!signature) {
      log.warn({ url: request.url, method: request.method }, 'Missing HMAC signature');
      return reply.code(401).send({ error: 'Missing HMAC signature' });
    }

    // rawBody is undefined when content-type is not application/json;
    // fall back to empty string so HMAC('', secret) can still match
    const rawBody = request.rawBody ?? '';

    const ok = verifyHmac(rawBody, signature);
    log.info(
      { url: request.url, method: request.method, bodyLen: rawBody.length, hmacOk: ok },
      'HMAC check',
    );

    if (!ok) {
      return reply.code(401).send({ error: 'Invalid HMAC signature' });
    }
  });

  // -- onSend: sign outbound response --------------------------
  app.addHook('onSend', async (_request: FastifyRequest, reply: FastifyReply, payload: string) => {
    if (payload && typeof payload === 'string') {
      const signature = signHmac(payload);
      reply.header('x-agent-games-signature', signature);
    }
    return payload;
  });

  // -- Register routes -----------------------------------------
  setVkHash(options.vkHash);
  await app.register(healthRoutes);
  await app.register(agentRoutes);

  return app;
}
