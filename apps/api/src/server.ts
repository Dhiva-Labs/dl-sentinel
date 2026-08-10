import { createServer as httpCreateServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { TOOL_VERSION } from '@dl-sentinel/core';
import { createDefaultEngine } from '@dl-sentinel/preset';
import { extractBearer, tokenId, tokenMatches } from './auth.js';
import { resolveRuntime, stderrLogger } from './config.js';
import { HttpError, methodNotAllowed, sendError, sendJson } from './http.js';
import { ScanQueue } from './queue.js';
import { RateLimiter } from './rate-limit.js';
import { routeApi } from './router.js';
import { createStaticServer } from './static.js';
import type { StaticServer } from './static.js';
import { ReportStore } from './store.js';
import type { SentinelApiServer, SentinelRuntime, ServerLogger, ServerOptions } from './types.js';

interface RequestDeps {
  runtime: SentinelRuntime;
  store: ReportStore;
  queue: ScanQueue;
  limiter: RateLimiter;
  staticServer: StaticServer;
  logger: ServerLogger;
}

/**
 * Handle one request through the pipeline: audit hook → health (no auth) →
 * `/api/*` (auth, then rate limit, then routing) → dashboard static assets (no
 * auth). Any thrown {@link HttpError} becomes a structured error response; any
 * other error becomes a generic 500 without leaking internals.
 */
async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  deps: RequestDeps,
): Promise<void> {
  const { runtime, store, queue, limiter, staticServer, logger } = deps;
  const method = req.method ?? 'GET';
  const url = new URL(req.url ?? '/', 'http://localhost');
  const pathname = url.pathname;
  const ip = req.socket.remoteAddress ?? '-';
  let auditToken = '-';

  res.on('finish', () => {
    void store.audit({
      ts: new Date().toISOString(),
      method,
      path: pathname,
      status: res.statusCode,
      tokenId: auditToken,
      ip,
    });
  });

  try {
    if (pathname === '/health') {
      if (method !== 'GET') throw methodNotAllowed('GET');
      sendJson(res, 200, { status: 'ok', version: TOOL_VERSION });
      return;
    }

    const isApi = pathname === '/api' || pathname.startsWith('/api/');
    if (isApi) {
      const provided = extractBearer(req.headers.authorization);
      if (provided === undefined) {
        throw new HttpError(401, 'unauthorized', 'Missing or malformed Authorization header', {
          'WWW-Authenticate': 'Bearer',
        });
      }
      auditToken = tokenId(provided);
      if (!tokenMatches(provided, runtime.token)) {
        throw new HttpError(401, 'unauthorized', 'Invalid bearer token', {
          'WWW-Authenticate': 'Bearer',
        });
      }

      const limit = limiter.check(auditToken);
      if (!limit.allowed) {
        const retryAfter = Math.max(1, Math.ceil(limit.retryAfterMs / 1000));
        throw new HttpError(429, 'rate_limited', 'Rate limit exceeded; slow down', {
          'Retry-After': String(retryAfter),
        });
      }

      await routeApi({ req, res, url, runtime, store, queue, logger });
      return;
    }

    // Dashboard and its assets — no authentication required.
    staticServer.serve(res, pathname);
  } catch (error) {
    sendError(res, error, logger);
  }
}

/**
 * Build the HTTP server without listening. The returned object is a Node
 * `http.Server` augmented with a `sentinel` property carrying the fully resolved
 * runtime (token, scan root, data dir, limits, concurrency) and a `queue`
 * property exposing background-worker controls (`waitForJob`, `drain`, `stop`)
 * for tests and graceful shutdown.
 *
 * Existing scan records are loaded synchronously during construction, then
 * reconciled: any record left `running` by a previous process is marked `failed`
 * ("interrupted by restart"), and any record still `queued` is re-enqueued so the
 * background worker resumes it. Completed and failed records are never re-run.
 */
export function createServer(options: ServerOptions = {}): SentinelApiServer {
  const logger = options.logger ?? stderrLogger();
  const runtime = resolveRuntime(options, logger);
  if (runtime.tokenGenerated) {
    // Required: print the generated token once so the operator can use it.
    logger.warn(
      `No SENTINEL_API_TOKEN configured; generated an ephemeral token for this run: ${runtime.token}`,
    );
  }

  const store = new ReportStore(runtime.dataDir, logger);
  const engineFactory = options.engineFactory ?? createDefaultEngine;
  const queue = new ScanQueue(store, engineFactory, runtime.scanConcurrency, logger);
  const limiter = new RateLimiter(runtime.rateLimit.windowMs, runtime.rateLimit.max);
  const staticServer = createStaticServer(logger, options.webRoot);

  // Recover from an unclean shutdown before accepting traffic: fail interrupted
  // jobs and re-enqueue ones that never started.
  for (const id of store.reconcile(new Date().toISOString())) {
    queue.enqueue(id);
  }

  const server = httpCreateServer((req, res) => {
    void handleRequest(req, res, { runtime, store, queue, limiter, staticServer, logger });
  });
  Object.defineProperty(server, 'sentinel', { value: runtime, enumerable: true });
  Object.defineProperty(server, 'queue', { value: queue, enumerable: true });
  return server as SentinelApiServer;
}

/**
 * Create the server and bind it to the resolved port (option `port`, else `PORT`,
 * else 8752). Returns the listening server. Called by the bin entry (`main.ts`).
 */
export function startServer(options: ServerOptions = {}): SentinelApiServer {
  const server = createServer(options);
  const port = server.sentinel.port;
  server.listen(port, () => {
    const address = server.address();
    const shownPort = typeof address === 'object' && address !== null ? address.port : port;
    process.stderr.write(
      `[dl-sentinel:api] listening on http://localhost:${shownPort} (scanRoot=${server.sentinel.scanRoot}, dataDir=${server.sentinel.dataDir})\n`,
    );
  });
  return server;
}
