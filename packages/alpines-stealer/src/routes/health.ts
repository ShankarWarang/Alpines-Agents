// ============================================================
// Alpines Stealer - Health & Preflight Routes
// ============================================================

import type { FastifyInstance } from 'fastify';
import type { PreflightResponse } from '@zkverify/shared';

export function registerHealthRoutes(app: FastifyInstance): void {
  // Preflight check - platform verifies agent is alive
  app.get('/', async (_request, _reply): Promise<PreflightResponse> => {
    return { ok: true, protocolVersion: 'v1' };
  });

  // Health check endpoint
  app.get('/health', async () => {
    return {
      status: 'healthy',
      service: 'alpines_stealer',
      uptime: process.uptime(),
    };
  });
}
