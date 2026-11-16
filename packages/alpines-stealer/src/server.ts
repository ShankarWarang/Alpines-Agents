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
    // Skip HMAC for GET (preflight / health checks)
    if (request.method === 'GET') return;

    const signature = request.headers['x-agent-games-signature'] as string | undefined;
    const rawBody = request.rawBody;

    if (!signature || !rawBody) {
      logger.warn({ url: request.url }, 'Missing HMAC signature or body');
      return reply.code(401).send({ error: 'Missing HMAC signature' });
    }

    if (!verifyHmac(rawBody, signature)) {
      logger.warn({ url: request.url }, 'Invalid HMAC signature');
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
