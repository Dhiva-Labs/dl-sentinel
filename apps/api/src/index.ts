/**
 * DL Sentinel HTTP API server (`@dl-sentinel/api-server`).
 *
 * A self-hosted, framework-free server built on `node:http`. It runs scans as
 * asynchronous background jobs through the default engine, persists their records
 * under a local data directory, serves the dashboard from `@dl-sentinel/web`, and
 * exposes the `/api` contract fixed in docs/architecture.md (§API server). Use
 * {@link createServer} to build a server without listening (tests drive it on an
 * ephemeral port) and {@link startServer} to bind the configured port.
 *
 * Concurrency note: `POST /api/scans` enqueues a job and returns `202` with
 * `{ id, status: "queued" }` immediately. A bounded in-process worker pool
 * (`SENTINEL_SCAN_CONCURRENCY`, default 2) runs jobs off the request path, so the
 * HTTP event loop is never blocked on a scan. Callers poll `GET /api/scans/:id`
 * for status and the report; the `queue` control surface on the returned server
 * (`waitForJob`, `drain`, `stop`) makes this deterministic for tests and enables
 * graceful shutdown.
 */
export { createServer, startServer } from './server.js';
export type {
  ServerOptions,
  RateLimitOptions,
  SentinelRuntime,
  SentinelApiServer,
  ScanQueueControls,
  SchedulerControls,
  ScanRecord,
  ScanStatus,
  ScanSummary,
  ScheduleRecord,
  HistoryEntry,
  TrendPoint,
  ServerLogger,
} from './types.js';
