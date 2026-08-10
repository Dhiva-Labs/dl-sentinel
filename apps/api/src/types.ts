import type { Server } from 'node:http';
import type { Report, SeverityStats, RuleMeta } from '@dl-sentinel/core';
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
  /** Logging sink. Defaults to a stderr logger. */
  logger?: ServerLogger;
  /** Engine factory, injectable for tests. Defaults to `createDefaultEngine`. */
  engineFactory?: () => ScanEngine;
}

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
 * A Node HTTP server augmented with its resolved runtime configuration, the
 * background scan-queue controls, and the scheduler controls.
 */
export type SentinelApiServer = Server & {
  readonly sentinel: SentinelRuntime;
  readonly queue: ScanQueueControls;
  readonly scheduler: SchedulerControls;
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

/** One line of the JSONL audit log. Never contains a token or secret in full. */
export interface AuditEntry {
  ts: string;
  method: string;
  path: string;
  status: number;
  /** Short hash prefix identifying the caller's token; never the token itself. */
  tokenId: string;
  ip: string;
}

/** Machine-readable error codes carried in `{ error: { code, message } }`. */
export type ErrorCode =
  | 'unauthorized'
  | 'not_found'
  | 'method_not_allowed'
  | 'validation_error'
  | 'invalid_json'
  | 'payload_too_large'
  | 'rate_limited'
  | 'scan_not_ready'
  | 'internal_error';
