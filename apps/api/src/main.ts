#!/usr/bin/env node
/**
 * Bin entry for the DL Sentinel API server. Binds the configured port and
 * starts serving. Configuration comes entirely from the environment
 * (SENTINEL_API_TOKEN, SENTINEL_SCAN_ROOT, SENTINEL_DATA_DIR, PORT, rate-limit
 * and body-size vars); see docs/architecture.md and docs/api.md.
 *
 * Graceful shutdown: on SIGINT/SIGTERM the scheduler stops enqueuing, the
 * server stops accepting connections, in-flight scan jobs and notification
 * deliveries drain, then the process exits 0. A second signal forces exit 130.
 */
import { startServer } from './server.js';

const server = startServer();

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) {
    process.stderr.write(`[dl-sentinel:api] second ${signal}; forcing exit\n`);
    process.exit(130);
  }
  shuttingDown = true;
  process.stderr.write(`[dl-sentinel:api] ${signal} received; shutting down gracefully\n`);
  try {
    server.scheduler.stop();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      // Idle keep-alive sockets would otherwise hold close() open.
      (server as unknown as { closeIdleConnections?: () => void }).closeIdleConnections?.();
    });
    await server.queue.stop();
    await server.notifier.drain();
    process.exit(0);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown error';
    process.stderr.write(`[dl-sentinel:api] shutdown error: ${message}\n`);
    process.exit(1);
  }
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
