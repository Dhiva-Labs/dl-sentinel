import type { Server } from 'node:http';
import type { Report, ScannerPlugin, SeverityStats, RuleMeta } from '@dl-sentinel/core';
import type { ScanEngine } from '@dl-sentinel/engine';

/** Minimal logging sink. Defaults to stderr; tests can supply a silent one. */
export interface ServerLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export interface RateLimitOptions {
  /** Fixed window length in milliseconds. */
  windowMs?: number;
  /** Maximum requests permitted per key per window. */
  max?: number;
}

/**
 * Options for {@link createServer}. Every field is optional and overrides the
 * corresponding environment variable, which in turn overrides a built-in
 * default. Passing options (rather than mutating `process.env`) keeps parallel
 * tests isolated.
 */
export interface ServerOptions {
  /** Bearer token. Overrides `SENTINEL_API_TOKEN`; generated if neither is set. */
  token?: string;
  /** Allowlisted base directory for scans. Overrides `SENTINEL_SCAN_ROOT` (default: cwd). */
  scanRoot?: string;
  /** Directory for persisted scans and the audit log. Overrides `SENTINEL_DATA_DIR`. */
  dataDir?: string;
  /**
   * Explicit dashboard asset root. Overrides `@dl-sentinel/web`'s `getWebRoot()`.
   * When unset, the web package is consulted; when neither yields a real
   * directory, a placeholder page is served.
   */
  webRoot?: string;
  /** Maximum accepted request body size in bytes. Overrides `SENTINEL_MAX_BODY_BYTES`. */
  maxBodyBytes?: number;
  /** In-memory rate-limit configuration. */
  rateLimit?: RateLimitOptions;
  /** TCP port for {@link startServer}. Overrides `PORT` (default: 8752). */
  port?: number;
  /**
   * Maximum scans executed concurrently by the background worker pool. Overrides
   * `SENTINEL_SCAN_CONCURRENCY` (default: 2). Must be a positive integer.
   */
  scanConcurrency?: number;
  /**
   * How often the scheduler wakes to enqueue due schedules, in milliseconds.
   * Overrides `SENTINEL_SCHEDULER_INTERVAL_MS` (default: 15000). The scheduler
   * still only ever enqueues a schedule once its own `nextRunAt` has passed, so
   * this is just the polling granularity, not the scan interval.
   */
  schedulerIntervalMs?: number;
  /**
   * Clock used by the scheduler and by schedule creation (`nextRunAt`
   * arithmetic). Injectable so tests drive time deterministically instead of
   * waiting for real timers. Defaults to `Date.now`.
   */
  now?: () => number;
  /**
   * Environment the server reads its configuration from. Defaults to
   * `process.env`. Injectable so a test can exercise the env-driven paths
   * (notably `SENTINEL_PLUGINS`) without mutating the real environment.
   */
  env?: NodeJS.ProcessEnv;
  /**
   * Already-constructed scanner plugins to register after the built-ins.
   *
   * This is the injection point for embedders and tests: it bypasses
   * `SENTINEL_PLUGINS` and the dynamic import entirely. {@link startServer} uses
   * it internally for the plugins it loaded from the environment. Supplying it
   * suppresses env-based loading, so a caller is never surprised by extra
   * scanners it did not pass.
   */
  plugins?: ScannerPlugin[];
  /** Logging sink. Defaults to a stderr logger. */
  logger?: ServerLogger;
  /**
   * Engine factory, injectable for tests. Defaults to the built-in scanners plus
   * {@link ServerOptions.plugins}; a caller that supplies its own factory owns
   * the whole roster, including any plugins.
   */
  engineFactory?: () => ScanEngine;
  /**
   * `fetch` implementation used for outbound notification delivery. Injectable
   * so tests never touch the network; defaults to the global `fetch`. This is
   * the only outbound HTTP path the server itself initiates (besides the opt-in
   * OSV data source inside the dependency scanner).
   */
  fetch?: FetchLike;
}

/**
 * The subset of the global `fetch` signature the notifier uses. Declared
 * structurally so a test can pass a plain function without pulling in DOM lib
 * types, and so nothing in this package depends on a real network stack.
 */
export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{ ok: boolean; status: number }>;

/** Fully resolved runtime configuration, exposed on the server for tests. */
export interface SentinelRuntime {
  /** The active bearer token (never logged in full). */
  token: string;
  /** True when the token was randomly generated because none was configured. */
  tokenGenerated: boolean;
  /** Canonical (realpath'd) allowlisted scan root. */
  scanRoot: string;
  /** Absolute data directory. */
  dataDir: string;
  /** Maximum accepted request body size in bytes. */
  maxBodyBytes: number;
  /** Resolved rate-limit configuration. */
  rateLimit: { windowMs: number; max: number };
  /** Resolved default listen port for {@link startServer}. */
  port: number;
  /** Resolved background worker-pool concurrency (positive integer). */
  scanConcurrency: number;
  /** Resolved scheduler polling interval in milliseconds (positive integer). */
  schedulerIntervalMs: number;
  /**
   * Ids of the external scanner plugins registered alongside the built-ins, in
   * registration order. Empty on a deployment without plugins.
   */
  pluginIds: string[];
}

/**
 * Control surface for the background scan queue, exposed on the server for tests
 * and graceful shutdown. Assertions still go over HTTP; these helpers only make
 * waiting deterministic (no fixed sleeps) and let a caller stop workers cleanly.
 */
export interface ScanQueueControls {
  /**
   * Resolve when the given job reaches a terminal state (`completed`/`failed`),
   * returning the settled record. Rejects if `timeoutMs` elapses first.
   */
  waitForJob(id: string, timeoutMs?: number): Promise<ScanRecord>;
  /** Resolve when every queued and in-flight job has reached a terminal state. */
  drain(): Promise<void>;
  /** Start no further jobs and resolve once in-flight jobs have settled. */
  stop(): Promise<void>;
}

/**
 * Control surface for the background scheduler, exposed on the server for tests
 * and graceful shutdown. `tick()` runs one due-check pass (returning how many
 * scans it enqueued) so tests can drive scheduling deterministically via an
 * injected clock instead of waiting for the real timer.
 */
export interface SchedulerControls {
  /**
   * Enqueue a scan for every enabled schedule whose `nextRunAt` has passed,
   * advancing each fired schedule's `nextRunAt`. Returns the number enqueued.
   * Never throws: a single schedule's failure is logged and skipped.
   */
  tick(): number;
  /** Begin the periodic timer (idempotent). Does not keep the process alive. */
  start(): void;
  /** Stop the periodic timer (idempotent). */
  stop(): void;
}

/**
 * Control surface for outbound notification delivery, exposed on the server for
 * tests and graceful shutdown. Deliveries are deliberately started off the
 * queue's critical path (a job reaches its terminal state, is persisted, and
 * *then* notifications go out), so `drain()` is the only way to observe
 * quiescence — it mirrors {@link ScanQueueControls.drain} and is awaited during
 * a controlled shutdown so no delivery outlives the process that started it.
 */
export interface NotifierControls {
  /** Resolve once every in-flight delivery has settled (success or failure). */
  drain(): Promise<void>;
  /** Start no further deliveries and resolve once in-flight ones have settled. */
  stop(): Promise<void>;
}

/**
 * A Node HTTP server augmented with its resolved runtime configuration, the
 * background scan-queue controls, the scheduler controls, and the notifier
 * controls.
 */
export type SentinelApiServer = Server & {
  readonly sentinel: SentinelRuntime;
  readonly queue: ScanQueueControls;
  readonly scheduler: SchedulerControls;
  readonly notifier: NotifierControls;
};

/** Lifecycle status of a scan job. */
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

/** The set of terminal statuses a job settles into. */
export const TERMINAL_STATUSES: ReadonlySet<ScanStatus> = new Set(['completed', 'failed']);

/**
 * A persisted scan job. Created `queued`; a worker moves it to `running`, then to
 * `completed` (with `report`) or `failed` (with a sanitized `error`). Every
 * transition is written to the on-disk store so listing and status survive a
 * restart; the report lives on the record once completed.
 */
export interface ScanRecord {
  id: string;
  status: ScanStatus;
  /** Canonical (realpath'd) target directory validated at enqueue time. */
  path: string;
  /** Optional subset of scanner ids to run; absent means all registered. */
  scanners?: string[];
  /** ISO timestamp the job was enqueued. */
  createdAt: string;
  /** ISO timestamp a worker began the scan (absent while queued). */
  startedAt?: string;
  /** ISO timestamp the job reached a terminal state (absent until terminal). */
  finishedAt?: string;
  /** The engine report; present iff `status === 'completed'`. */
  report?: Report;
  /** A client-safe failure message; present iff `status === 'failed'`. */
  error?: string;
  /**
   * Id of the {@link ScheduleRecord} that enqueued this job, absent for an
   * ad-hoc scan. Carried so a scheduled scan that ends `failed` can raise
   * `schedule.failed` (with the schedule's id) alongside `scan.failed`.
   */
  scheduleId?: string;
}

/** Compact scan listing entry (`GET /api/scans`). */
export interface ScanSummary {
  id: string;
  status: ScanStatus;
  path: string;
  createdAt: string;
  /** Present once the job has started/finished. */
  startedAt?: string;
  finishedAt?: string;
  /** Report-derived fields, present only when `status === 'completed'`. */
  project?: string;
  durationMs?: number;
  scannersRun?: string[];
  stats?: SeverityStats;
  findingCount?: number;
}

/**
 * A persisted scheduled scan. The scheduler enqueues a scan for this `path`
 * (through the same {@link ScanQueue} used by ad-hoc scans) every `intervalMs`
 * while `enabled`, advancing `nextRunAt` each time it fires. Schedules are
 * persisted under the data directory alongside scan records, so they resume
 * across a restart.
 */
export interface ScheduleRecord {
  id: string;
  /** Canonical (realpath'd) target directory, validated at creation time. */
  path: string;
  /** Optional subset of scanner ids to run; absent means all registered. */
  scanners?: string[];
  /** Interval between runs in milliseconds (never below the enforced minimum). */
  intervalMs: number;
  /** Whether the scheduler considers this schedule when it ticks. */
  enabled: boolean;
  /** ISO timestamp the schedule was created. */
  createdAt: string;
  /** ISO timestamp the scheduler last enqueued a scan for it (absent until then). */
  lastRunAt?: string;
  /** Id of the last scan the scheduler enqueued for it (absent until then). */
  lastScanId?: string;
  /** ISO timestamp at/after which the next run is due. */
  nextRunAt: string;
}

/** One entry of `GET /api/history`: a completed scan reduced to its outcome. */
export interface HistoryEntry {
  id: string;
  /** Canonical target that was scanned. */
  path: string;
  /** Project name (report-derived). */
  project: string;
  /** ISO timestamp the scan completed. */
  finishedAt: string;
  stats: SeverityStats;
  findingCount: number;
}

/** One point of `GET /api/trends`: severity counts at a completed scan's time. */
export interface TrendPoint {
  /** ISO timestamp the scan completed. */
  finishedAt: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  /** Total findings (sum of the severity buckets). */
  total: number;
}

/** A rule as returned by `GET /api/rules`: rule metadata plus its owning scanner id. */
export interface ApiRule extends RuleMeta {
  scanner: string;
}

/**
 * What an authenticated caller may do (docs/architecture.md §API server, "Users
 * and RBAC"): `viewer` reads, `operator` additionally starts scans, `admin` may
 * do everything including schedule and user management. The bootstrap token is
 * always `admin`, so every existing single-token deployment keeps working.
 */
export type UserRole = 'admin' | 'operator' | 'viewer';

/**
 * A persisted API user, stored under `<dataDir>/users/<id>.json` alongside scans
 * and schedules, so users survive a restart. Authentication stays token-only —
 * there is no password field anywhere in the system. The token is generated
 * server-side, returned exactly once by create/rotate, and kept **only** as the
 * SHA-256 hex digest in {@link UserRecord.tokenHash}; it is never logged,
 * re-served, or recoverable from this record.
 */
export interface UserRecord {
  id: string;
  /** Display name, shown in the dashboard and used for `GET /api/me`. */
  name: string;
  role: UserRole;
  /** SHA-256 hex digest of the user's bearer token. Never served over the API. */
  tokenHash: string;
  /** ISO timestamp the user was created. */
  createdAt: string;
  /** When true the user's token authenticates as invalid (401), like a deletion. */
  disabled?: boolean;
}

/**
 * A user as served by `/api/users*`: the record minus its token hash. Built
 * field by field (never by spreading a {@link UserRecord}) so a hash can never
 * leak into a response through a later field addition.
 */
export interface PublicUser {
  id: string;
  name: string;
  role: UserRole;
  createdAt: string;
  disabled: boolean;
}

/**
 * The resolved caller of one authenticated request. Attached to the request
 * context by the server; drives authorization and audit attribution.
 */
export interface AuthContext {
  /** `root` for the bootstrap token, else the user record's id. */
  userId: string;
  /** `root` for the bootstrap token, else the user's name. */
  name: string;
  role: UserRole;
}

// ---------------------------------------------------------------------------
// Notifications (docs/architecture.md §API server, "Notifications")
// ---------------------------------------------------------------------------

/** Where a notification is delivered. */
export type ChannelType = 'webhook' | 'slack';

/** The scan-lifecycle events a channel may subscribe to. */
export type NotificationEvent =
  'scan.completed' | 'scan.failed' | 'policy.violated' | 'schedule.failed';

/**
 * A configured outbound notification channel, persisted under
 * `<dataDir>/notifications/<id>.json`. Admin-only to create, read, or change.
 *
 * The `secret` is the one credential in the system the server must *keep*
 * rather than hash: it signs each webhook body so the receiver can verify it
 * (`X-Sentinel-Signature`), which is impossible from a digest. It is therefore
 * held in this record but never served — {@link PublicChannel} is what every
 * response carries — and never written to a log or the audit trail.
 */
export interface NotificationChannel {
  id: string;
  type: ChannelType;
  /** Delivery endpoint: https, or http only for a loopback host. */
  url: string;
  /** Non-empty subset of the four lifecycle events. */
  events: NotificationEvent[];
  enabled: boolean;
  /** HMAC signing key for webhook deliveries. Never returned by the API. */
  secret?: string;
  /** ISO timestamp the channel was created. */
  createdAt: string;
  /**
   * Sanitized description of the most recent failed delivery (a status code or
   * a short message — never a response body, URL credential, or secret). Cleared
   * on the next successful delivery.
   */
  lastError?: string;
}

/**
 * A channel as served by `/api/notifications*`: the record with its `secret`
 * replaced by a boolean. Built field by field (never by spreading a
 * {@link NotificationChannel}) so a secret can never leak into a response
 * through a later field addition — the same discipline `toPublicUser` applies
 * to token hashes.
 */
export interface PublicChannel {
  id: string;
  type: ChannelType;
  url: string;
  events: NotificationEvent[];
  enabled: boolean;
  /** Whether a signing secret is configured. The value itself is never served. */
  hasSecret: boolean;
  createdAt: string;
  lastError?: string;
}

/**
 * The JSON body POSTed to a `webhook` channel, and the value signed by
 * `X-Sentinel-Signature`. Field-for-field the shape fixed in
 * docs/architecture.md; `scheduleId` is present only on `schedule.failed`.
 *
 * It carries counts and identifiers only: no finding evidence, no file
 * contents, and nothing that was not already derivable from the scan record.
 */
export interface NotificationPayload {
  /** The lifecycle event, or `test` for a connectivity check. */
  event: NotificationEvent | 'test';
  scanId: string;
  path: string;
  project: string;
  stats: SeverityStats;
  findingCount: number;
  finishedAt: string;
  /** Present only for `schedule.failed`. */
  scheduleId?: string;
}

/** Outcome of one delivery attempt, as returned by `POST /api/notifications/:id/test`. */
export interface DeliveryResult {
  ok: boolean;
  /** HTTP status, when a response was received at all. */
  status?: number;
  /** Sanitized failure description; absent when `ok`. */
  error?: string;
}

/** One line of the JSONL audit log. Never contains a token or secret in full. */
export interface AuditEntry {
  ts: string;
  method: string;
  path: string;
  status: number;
  /** Short hash prefix identifying the caller's token; never the token itself. */
  tokenId: string;
  /**
   * The acting user: `root` for the bootstrap token, a user id for a user token,
   * `-` when the request was not authenticated (health, static assets, a 401).
   */
  userId: string;
  ip: string;
}

/** Machine-readable error codes carried in `{ error: { code, message } }`. */
export type ErrorCode =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'method_not_allowed'
  | 'validation_error'
  | 'invalid_json'
  | 'payload_too_large'
  | 'rate_limited'
  | 'scan_not_ready'
  | 'internal_error';
