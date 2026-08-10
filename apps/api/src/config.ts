import { randomBytes } from 'node:crypto';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import type { ServerLogger, ServerOptions, SentinelRuntime } from './types.js';

const DEFAULT_PORT = 8752;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024; // 1 MiB
const DEFAULT_RATE_WINDOW_MS = 60_000;
const DEFAULT_RATE_MAX = 60;
const DEFAULT_SCAN_CONCURRENCY = 2;
const DEFAULT_SCHEDULER_INTERVAL_MS = 15_000;

/** A logger that writes to stderr. Never used for request bodies or tokens. */
export function stderrLogger(): ServerLogger {
  const write = (level: string, message: string): void => {
    process.stderr.write(`[dl-sentinel:api] ${level} ${message}\n`);
  };
  return {
    info: (message) => write('info', message),
    warn: (message) => write('warn', message),
    error: (message) => write('error', message),
  };
}

function parseIntEnv(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Resolve a scan root to its canonical (symlink-free) absolute path. */
function canonicalScanRoot(input: string, logger: ServerLogger): string {
  const resolved = path.resolve(input);
  try {
    return realpathSync(resolved);
  } catch {
    // A non-existent scan root is a misconfiguration; the server still starts,
    // but every scan request will fail the within-root check.
    logger.warn(`Scan root ${resolved} does not exist; scans will be rejected until it does`);
    return resolved;
  }
}

/**
 * Merge options, environment, and defaults into the fully resolved runtime.
 * Precedence: explicit option > environment variable > built-in default.
 */
export function resolveRuntime(options: ServerOptions, logger: ServerLogger): SentinelRuntime {
  const env = process.env;

  const configuredToken = options.token ?? env.SENTINEL_API_TOKEN;
  const tokenGenerated = configuredToken === undefined || configuredToken === '';
  const token = tokenGenerated ? randomBytes(32).toString('hex') : configuredToken;

  const scanRootInput = options.scanRoot ?? env.SENTINEL_SCAN_ROOT ?? process.cwd();
  const scanRoot = canonicalScanRoot(scanRootInput, logger);

  const dataDirInput =
    options.dataDir ?? env.SENTINEL_DATA_DIR ?? path.join(process.cwd(), '.dl-sentinel');
  const dataDir = path.resolve(dataDirInput);

  const maxBodyBytes =
    options.maxBodyBytes ?? parseIntEnv(env.SENTINEL_MAX_BODY_BYTES, DEFAULT_MAX_BODY_BYTES);

  const rateLimit = {
    windowMs:
      options.rateLimit?.windowMs ??
      parseIntEnv(env.SENTINEL_RATE_LIMIT_WINDOW_MS, DEFAULT_RATE_WINDOW_MS),
    max: options.rateLimit?.max ?? parseIntEnv(env.SENTINEL_RATE_LIMIT_MAX, DEFAULT_RATE_MAX),
  };

  const port = options.port ?? parseIntEnv(env.PORT, DEFAULT_PORT);

  const scanConcurrency =
    options.scanConcurrency ?? parseIntEnv(env.SENTINEL_SCAN_CONCURRENCY, DEFAULT_SCAN_CONCURRENCY);

  const schedulerIntervalMs =
    options.schedulerIntervalMs ??
    parseIntEnv(env.SENTINEL_SCHEDULER_INTERVAL_MS, DEFAULT_SCHEDULER_INTERVAL_MS);

  return {
    token,
    tokenGenerated,
    scanRoot,
    dataDir,
    maxBodyBytes,
    rateLimit,
    port,
    scanConcurrency,
    schedulerIntervalMs,
  };
}
