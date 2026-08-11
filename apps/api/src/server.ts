import { createServer as httpCreateServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ScannerPlugin } from '@dl-sentinel/core';
import { TOOL_VERSION } from '@dl-sentinel/core';
import type { ScanEngine } from '@dl-sentinel/engine';
import { loadScannerPlugins, validateScannerPlugin } from '@dl-sentinel/engine';
import { BUILTIN_SCANNERS, createDefaultEngine } from '@dl-sentinel/preset';
import { extractBearer, resolveAuth, tokenId } from './auth.js';
import { pluginSpecsFromEnv, resolveRuntime, stderrLogger } from './config.js';
import { HttpError, methodNotAllowed, sendError, sendJson } from './http.js';
import { Notifier } from './notifier.js';
import { ScanQueue } from './queue.js';
import { RateLimiter } from './rate-limit.js';
import { routeApi } from './router.js';
import { Scheduler } from './scheduler.js';
import { createStaticServer } from './static.js';
import type { StaticServer } from './static.js';
import { ReportStore } from './store.js';
import type {
  FetchLike,
  SentinelApiServer,
  SentinelRuntime,
  ServerLogger,
  ServerOptions,
} from './types.js';

interface RequestDeps {
  runtime: SentinelRuntime;
  /** The full scanner roster (built-ins, then plugins) the API reports on. */
  scanners: readonly ScannerPlugin[];
  store: ReportStore;
  queue: ScanQueue;
  notifier: Notifier;
  limiter: RateLimiter;
  staticServer: StaticServer;
  logger: ServerLogger;
  now: () => number;
}

/**
 * Register `plugins` on top of the built-in scanners. A plugin whose id
 * collides with a built-in (or with an earlier plugin) makes this throw, which
 * — because it runs during {@link createServer} — is a startup failure rather
 * than a surprise at scan time.
 */
function engineWithPlugins(plugins: readonly ScannerPlugin[]): ScanEngine {
  const engine = createDefaultEngine();
  for (const plugin of plugins) {
    engine.register(plugin);
  }
  return engine;
}

/**
 * Handle one request through the pipeline: audit hook → health (no auth) →
 * `/api/*` (authenticate, then rate limit, then route — which authorizes by
 * role) → dashboard static assets (no auth). Any thrown {@link HttpError}
 * becomes a structured error response; any other error becomes a generic 500
 * without leaking internals.
 */
async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  deps: RequestDeps,
): Promise<void> {
  const { runtime, scanners, store, queue, notifier, limiter, staticServer, logger, now } = deps;
  const method = req.method ?? 'GET';
  const url = new URL(req.url ?? '/', 'http://localhost');
  const pathname = url.pathname;
  const ip = req.socket.remoteAddress ?? '-';
  let auditToken = '-';
  let auditUserId = '-';

  res.on('finish', () => {
    void store.audit({
      ts: new Date().toISOString(),
      method,
      path: pathname,
      status: res.statusCode,
      tokenId: auditToken,
      userId: auditUserId,
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
      // The bootstrap token resolves to the root admin; any other token is
      // matched against the user store. A disabled or unknown token is a 401,
      // exactly as before users existed.
      const auth = resolveAuth(provided, runtime.token, store.listUsers());
      if (auth === undefined) {
        throw new HttpError(401, 'unauthorized', 'Invalid bearer token', {
          'WWW-Authenticate': 'Bearer',
        });
      }
      auditUserId = auth.userId;

      // Keyed by the token's hash prefix, so every caller — root and each user —
      // gets an independent budget and one noisy user cannot starve another.
      const limit = limiter.check(auditToken);
      if (!limit.allowed) {
        const retryAfter = Math.max(1, Math.ceil(limit.retryAfterMs / 1000));
        throw new HttpError(429, 'rate_limited', 'Rate limit exceeded; slow down', {
          'Retry-After': String(retryAfter),
        });
      }

      await routeApi({
        req,
        res,
        url,
        runtime,
        scanners,
        store,
        queue,
        notifier,
        logger,
        auth,
        now,
      });
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
 * runtime (token, scan root, data dir, limits, concurrency), a `queue` property
 * exposing background-worker controls (`waitForJob`, `drain`, `stop`), and a
 * `scheduler` property exposing scheduling controls (`tick`, `start`, `stop`),
 * and a `notifier` property exposing delivery controls (`drain`, `stop`) for
 * tests and graceful shutdown.
 *
 * Existing scan records are loaded synchronously during construction, then
 * reconciled: any record left `running` by a previous process is marked `failed`
 * ("interrupted by restart"), and any record still `queued` is re-enqueued so the
 * background worker resumes it. Completed and failed records are never re-run.
 * Persisted schedules are likewise reloaded, their `nextRunAt` recomputed so an
 * overdue schedule runs once promptly (not once per missed interval), and the
 * scheduler timer is started.
 *
 * Scanner roster: the built-ins plus `options.plugins`, which are validated and
 * registered here so their rules appear in `/api/rules` and their findings in
 * reports. Because importing a module is asynchronous, `SENTINEL_PLUGINS` is
 * resolved by {@link startServer}, not here.
 */
export function createServer(options: ServerOptions = {}): SentinelApiServer {
  const logger = options.logger ?? stderrLogger();
  const plugins = resolvePlugins(options, logger);
  const runtime = resolveRuntime({ ...options, plugins }, logger);
  const scanners: readonly ScannerPlugin[] = [...BUILTIN_SCANNERS, ...plugins];
  const now = options.now ?? Date.now;
  if (runtime.tokenGenerated) {
    // Required: print the generated token once so the operator can use it.
    logger.warn(
      `No SENTINEL_API_TOKEN configured; generated an ephemeral token for this run: ${runtime.token}`,
    );
  }

  const store = new ReportStore(runtime.dataDir, logger);
  let engineFactory = options.engineFactory;
  if (engineFactory === undefined) {
    const build = (): ScanEngine => engineWithPlugins(plugins);
    // Build one engine now: a plugin id that collides with a built-in must fail
    // the server's startup, not every scan it later runs. A caller-supplied
    // factory is left alone — it owns its own roster, and may have side effects.
    build();
    engineFactory = build;
  }
  const queue = new ScanQueue(store, engineFactory, runtime.scanConcurrency, logger);
  const limiter = new RateLimiter(runtime.rateLimit.windowMs, runtime.rateLimit.max);
  const staticServer = createStaticServer(logger, options.webRoot);
  const scheduler = new Scheduler(store, queue, logger, runtime.schedulerIntervalMs, now);

  // Outbound notifications. `fetch` is injected (tests never touch the network),
  // and with no channels configured the notifier never calls it at all.
  const fetchImpl: FetchLike =
    options.fetch ?? ((input, init) => fetch(input, init as RequestInit));
  const notifier = new Notifier(store, logger, fetchImpl);
  // Delivery hangs off the queue's post-terminal-state hook, not off the job
  // itself: the record is persisted, then notifications are started and the
  // worker moves on without awaiting them.
  queue.setOnSettled((record) => notifier.emitForSettledScan(record));
  scheduler.setNotifier(notifier);

  // Recover from an unclean shutdown before accepting traffic: fail interrupted
  // jobs and re-enqueue ones that never started.
  for (const id of store.reconcile(new Date().toISOString())) {
    queue.enqueue(id);
  }
  // Reload schedules, recompute overdue nextRunAt sanely, then start ticking.
  scheduler.resume();
  scheduler.start();

  const server = httpCreateServer((req, res) => {
    void handleRequest(req, res, {
      runtime,
      scanners,
      store,
      queue,
      notifier,
      limiter,
      staticServer,
      logger,
      now,
    });
  });
  Object.defineProperty(server, 'sentinel', { value: runtime, enumerable: true });
  Object.defineProperty(server, 'queue', { value: queue, enumerable: true });
  Object.defineProperty(server, 'scheduler', { value: scheduler, enumerable: true });
  Object.defineProperty(server, 'notifier', { value: notifier, enumerable: true });
  // Non-enumerable, off the public type: exposed only so a controlled shutdown
  // (see test support) can await outstanding writes before removing the data dir.
  Object.defineProperty(server, 'store', { value: store, enumerable: false });
  return server as SentinelApiServer;
}

/**
 * The plugins a synchronously created server runs with: exactly the ones the
 * caller passed. Each is validated with the same rules the dynamic loader
 * applies, so an embedder cannot smuggle a half-built scanner past the checks
 * a `SENTINEL_PLUGINS` plugin has to pass.
 *
 * Importing a module is asynchronous, so `SENTINEL_PLUGINS` cannot be honoured
 * here — {@link startServer} resolves it and hands the results back through
 * `options.plugins`. If the variable is set and no plugins were passed, the
 * server would silently run with fewer scanners than the operator configured,
 * so that combination is called out loudly.
 */
function resolvePlugins(options: ServerOptions, logger: ServerLogger): ScannerPlugin[] {
  const plugins = options.plugins;
  if (plugins === undefined) {
    const configured = pluginSpecsFromEnv(options.env ?? process.env);
    if (configured.length > 0) {
      logger.warn(
        `SENTINEL_PLUGINS names ${configured.length} plugin(s) but this server was built with createServer(); use startServer() to load them, or pass ServerOptions.plugins`,
      );
    }
    return [];
  }
  plugins.forEach((plugin, index) =>
    validateScannerPlugin(plugin, `ServerOptions.plugins[${index}]`),
  );
  return [...plugins];
}

/**
 * Create the server and bind it to the resolved port (option `port`, else `PORT`,
 * else 8752). Returns the listening server. Called by the bin entry (`main.ts`).
 *
 * This is where `SENTINEL_PLUGINS` is honoured: its specs are imported and
 * validated *before* the server exists, and any failure rejects instead of
 * starting. Refusing to boot is deliberate — a security scanner that quietly
 * runs with fewer scanners than the operator configured reports a clean result
 * it never actually checked for. `main.ts` turns the rejection into a stderr
 * message and a non-zero exit.
 */
export async function startServer(options: ServerOptions = {}): Promise<SentinelApiServer> {
  const specs = options.plugins === undefined ? pluginSpecsFromEnv(options.env ?? process.env) : [];
  const loaded = specs.length === 0 ? undefined : await loadScannerPlugins(specs);
  const server = createServer(loaded === undefined ? options : { ...options, plugins: loaded });
  const port = server.sentinel.port;
  server.listen(port, () => {
    const address = server.address();
    const shownPort = typeof address === 'object' && address !== null ? address.port : port;
    const pluginNote =
      server.sentinel.pluginIds.length === 0
        ? ''
        : `, plugins=${server.sentinel.pluginIds.join(',')}`;
    process.stderr.write(
      `[dl-sentinel:api] listening on http://localhost:${shownPort} (scanRoot=${server.sentinel.scanRoot}, dataDir=${server.sentinel.dataDir}${pluginNote})\n`,
    );
  });
  return server;
}
