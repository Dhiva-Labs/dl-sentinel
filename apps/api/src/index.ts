/**
 * DL Sentinel HTTP API server (`@dl-sentinel/api-server`).
 *
 * A self-hosted, framework-free server built on `node:http`. It runs scans
 * through the default engine, persists reports under a local data directory,
 * serves the dashboard from `@dl-sentinel/web`, and exposes the `/api` contract
 * fixed in docs/architecture.md (§API server). Use {@link createServer} to build
 * a server without listening (tests drive it on an ephemeral port) and
 * {@link startServer} to bind the configured port.
 *
 * Concurrency note: a scan runs synchronously within its request. The server
 * stays responsive to other requests, but a scan holds its own request open
 * until the report is ready. This is acceptable for the self-hosted MVP.
 */
export { createServer, startServer } from './server.js';
export type {
  ServerOptions,
  RateLimitOptions,
  SentinelRuntime,
  SentinelApiServer,
  ServerLogger,
} from './types.js';
