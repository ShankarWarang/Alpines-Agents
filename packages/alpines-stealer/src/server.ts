// ============================================================
// Alpines Stealer - Fastify Server Factory
// ============================================================

import Fastify, { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import { verifyHmac, signHmac } from '@zkverify/shared';
import { registerHealthRoutes } from './routes/health.js';
import { registerAgentRoute } from './routes/agent.js';

// Extend FastifyRequest to carry rawBody (same pattern as keeper)
declare module 'fastify' {
  interface FastifyRequest {
    rawBody?: string;
  }
}

export function createServer(logger: ReturnType<typeof import('@zkverify/shared').createLogger>): FastifyInstance {
  const app = Fastify({ logger: false });

  // -- Custom JSON parser - store raw body on request for HMAC verification --
  app.addContentTypeParser(
    'application/json',
    { parseAs: 'string' },
    (req: any, body: string, done: (err: Error | null, result?: unknown) => void) => {
      req.rawBody = body;
      try {
        done(null, JSON.parse(body));
      } catch (err) {
        done(err as Error);
      }
    },
  );

  // -- preHandler: verify inbound HMAC signature --
  app.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    // Skip HMAC for read-only methods
    if (request.method === 'GET' || request.method === 'HEAD') return;

    const signature = request.headers['x-agent-games-signature'] as string | undefined;

    if (!signature) {
      logger.warn({ url: request.url, method: request.method }, 'Missing HMAC signature');
      return reply.code(401).send({ error: 'Missing HMAC signature' });
    }

    // rawBody undefined when content-type is not application/json - fall back to ''
    const rawBody = request.rawBody ?? '';

    const ok = verifyHmac(rawBody, signature);
    // Debug: log full sig + body for HMAC secret diagnosis
    // TODO: remove fullSig/fullBody after HMAC is confirmed working
    logger.info({
      url: request.url,
      method: request.method,
      fullSig: signature,
      fullBody: rawBody,
      bodyLen: rawBody.length,
      hmacOk: ok,
    }, 'HMAC check');

    if (!ok) {
      return reply.code(401).send({ error: 'Invalid HMAC signature' });
    }
  });

  // -- onSend: sign outbound responses --
  app.addHook('onSend', async (_request, reply, payload) => {
    if (typeof payload === 'string' || Buffer.isBuffer(payload)) {
      const sig = signHmac(payload);
      reply.header('x-agent-games-signature', sig);
    }
    return payload;
  });

  // -- Register routes --
  registerHealthRoutes(app);
  registerAgentRoute(app, logger);

  return app;
}
