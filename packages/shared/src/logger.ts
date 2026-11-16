/**
 * Structured JSON logger powered by Pino.
 *
 * - Console output for development
 * - File output for production (persistent, rotatable)
 * - Automatic request/response logging in Fastify integration
 */

import pino from 'pino';
import { resolve } from 'node:path';

export function createLogger(name: string, logFile?: string): pino.Logger {
  const targets: pino.TransportTargetOptions[] = [
    // Always log to stdout
    {
      target: 'pino/file',
      options: { destination: 1 },
      level: process.env.LOG_LEVEL || 'info',
    },
  ];

  // In production, also log to a persistent file
  // Use absolute path to avoid CWD issues with Pino transport worker threads
  if (logFile) {
    const absoluteLogPath = resolve(process.cwd(), logFile);
    targets.push({
      target: 'pino/file',
      options: {
        destination: absoluteLogPath,
        mkdir: true,
      },
      level: 'debug', // File gets everything for post-round analysis
    });
  }

  return pino({
    name,
    level: process.env.LOG_LEVEL || 'info',
    transport: { targets },
    serializers: {
      err: pino.stdSerializers.err,
      req: pino.stdSerializers.req,
      res: pino.stdSerializers.res,
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}
