/**
 * Health / preflight routes for Alpines Keeper.
 */

import type { FastifyInstance } from 'fastify';
import type { PreflightResponse } from '@zkverify/shared';

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  /**
   * GET / - Preflight check for the Agent Games platform.
   */
  app.get('/', async (_request, _reply) => {
    const response: PreflightResponse = {
      ok: true,
      protocolVersion: 'v1',
    };
    return response;
  });

  /**
   * GET /health - Service health check.
   */
  app.get('/health', async (_request, _reply) => {
    return {
      status: 'healthy',
      service: 'alpines_keeper',
      uptime: process.uptime(),
    };
  });
}
