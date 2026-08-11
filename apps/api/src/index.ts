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
 *
 * Auth note: authentication is token-only (no passwords anywhere). The bootstrap
 * token (`SENTINEL_API_TOKEN`, or the generated one) is the root admin and always
 * works, so a single-token deployment is unaffected by roles. Admins may
 * additionally create users at `/api/users`, each with their own token and a role
 * (`viewer` / `operator` / `admin`) that gates what they may call; an
 * under-privileged request is a `403`. See docs/api.md.
 *
 * Notification note: the server makes no outbound requests of its own unless an
 * admin configures a channel at `/api/notifications`. Deliveries then go out
 * after a job has reached and persisted its terminal state, through an
 * injectable `fetch` with a 5 s deadline; a failed delivery is recorded on the
 * channel and never affects the scan.
 */
export { createServer, startServer } from './server.js';
export {
  NOTIFICATION_EVENTS,
  CHANNEL_TYPES,
  DELIVERY_TIMEOUT_MS,
  SIGNATURE_HEADER,
  isValidChannelUrl,
  signBody,
  slackText,
} from './notifications.js';
export type {
  ServerOptions,
  RateLimitOptions,
  SentinelRuntime,
  SentinelApiServer,
  ScanQueueControls,
  SchedulerControls,
  NotifierControls,
  ScanRecord,
  ScanStatus,
  ScanSummary,
  ScheduleRecord,
  HistoryEntry,
  TrendPoint,
  ServerLogger,
  UserRole,
  UserRecord,
  PublicUser,
  AuthContext,
  AuditEntry,
  FetchLike,
  ChannelType,
  NotificationEvent,
  NotificationChannel,
  NotificationPayload,
  PublicChannel,
  DeliveryResult,
} from './types.js';
