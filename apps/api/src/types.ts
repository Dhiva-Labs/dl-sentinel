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
}

/** A Node HTTP server augmented with its resolved runtime configuration. */
export type SentinelApiServer = Server & { readonly sentinel: SentinelRuntime };

/** Lifecycle status of a stored scan. Scans run synchronously to completion. */
export type ScanStatus = 'completed';

/** A persisted scan: a server-assigned id plus the engine's Report. */
export interface StoredScan {
  id: string;
  status: ScanStatus;
  report: Report;
}

/** Compact scan listing entry (`GET /api/scans`). */
export interface ScanSummary {
  id: string;
  project: string;
  startedAt: string;
  stats: SeverityStats;
  findingCount: number;
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
  | 'internal_error';
