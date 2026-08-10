import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { TOOL_VERSION } from '@dl-sentinel/core';
import type { ScanEngine } from '@dl-sentinel/engine';
import { createServer } from '../src/index.js';
import type {
  AuditEntry,
  ScanRecord,
  ServerLogger,
  ServerOptions,
  SentinelApiServer,
  UserRole,
} from '../src/index.js';
import { fixturePath } from '../../../tests/support/index.js';

/** A logger that discards everything, keeping test output clean. */
export const silentLogger: ServerLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

/** Absolute path to tests/fixtures — the default scan root for tests. */
export function fixturesRoot(): string {
  return fixturePath();
}

/** Absolute path to the vulnerable-app fixture (a valid, in-root scan target). */
export function vulnerableApp(): string {
  return fixturePath('vulnerable-app');
}

export interface TestServer {
  server: SentinelApiServer;
  base: string;
  token: string;
  dataDir: string;
  cleanup(): Promise<void>;
}

/**
 * Start a server on an ephemeral loopback port. Defaults: a fixed token, the
 * fixtures directory as scan root, a fresh temp data dir, and a silent logger.
 * Any of these can be overridden. Supplying `dataDir` reuses that directory
 * (and leaves it in place on cleanup) so persistence across restarts can be
 * exercised.
 */
export async function startTestServer(overrides: ServerOptions = {}): Promise<TestServer> {
  const ownsDataDir = overrides.dataDir === undefined;
  const dataDir = overrides.dataDir ?? mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-'));

  const options: ServerOptions = {
    token: 'test-token-abcdefghijklmnop',
    scanRoot: fixturesRoot(),
    logger: silentLogger,
    ...overrides,
    dataDir,
  };

  const server = createServer(options);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address() as AddressInfo;

  return {
    server,
    base: `http://127.0.0.1:${address.port}`,
    token: server.sentinel.token,
    dataDir,
    async cleanup() {
      // Deterministic teardown: nothing must write to the data dir after this
      // point, or rmSync races the worker (intermittent ENOTEMPTY in the full
      // suite). Order matters:
      //   1. Stop the scheduler so it can't enqueue (and persist) new scans.
      //   2. Close the server so no new request can enqueue work or start an
      //      audit append.
      //   3. Drain the queue so every queued/in-flight job finishes its writes,
      //      then stop the pool.
      //   4. Flush outstanding async writes (audit-log appends).
      // Only then is it safe to remove the directory.
      server.scheduler.stop();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        // Force idle keep-alive sockets closed so close() settles promptly.
        const withClose = server as unknown as { closeAllConnections?: () => void };
        withClose.closeAllConnections?.();
      });
      await server.queue.drain();
      await server.queue.stop();
      await (server as unknown as { store: { flushWrites(): Promise<void> } }).store.flushWrites();
      if (ownsDataDir) rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/**
 * Await a job reaching a terminal state deterministically (no fixed sleeps), via
 * the in-process queue control surface. Assertions still go over HTTP.
 */
export function waitForScan(ctx: TestServer, id: string, timeoutMs = 10_000): Promise<ScanRecord> {
  return ctx.server.queue.waitForJob(id, timeoutMs);
}

/**
 * Poll `GET /api/scans/:id` over HTTP until the scan reaches a terminal status or
 * the deadline elapses. Exercises the real polling flow a client would use.
 */
export async function pollScanHttp(
  base: string,
  token: string,
  id: string,
  timeoutMs = 10_000,
): Promise<ScanRecord> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const res = await fetch(`${base}/api/scans/${id}`, { headers: bearer(token) });
    if (res.status === 200) {
      const record = (await res.json()) as ScanRecord;
      if (record.status === 'completed' || record.status === 'failed') return record;
    }
    if (Date.now() > deadline) throw new Error(`Timed out polling scan ${id}`);
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
}

/** Authorization header for a bearer token. */
export function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/** POST a JSON body with the given bearer token. */
export function postJson(
  base: string,
  route: string,
  token: string,
  body: unknown,
): Promise<Response> {
  return sendJsonRequest(base, route, token, 'POST', body);
}

/** Send a JSON body with an arbitrary method (POST/PATCH/DELETE/...). */
export function sendJsonRequest(
  base: string,
  route: string,
  token: string,
  method: string,
  body?: unknown,
): Promise<Response> {
  return fetch(`${base}${route}`, {
    method,
    headers: { ...bearer(token), 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

/** DELETE with a bearer token (no body). */
export function deleteRequest(base: string, route: string, token: string): Promise<Response> {
  return sendJsonRequest(base, route, token, 'DELETE');
}

/**
 * An engine that completes instantly with an empty report. RBAC tests call
 * `POST /api/scans` purely as a permission probe — whether it answers 202 or
 * 403 is the whole assertion — so running a real scan there would only add
 * seconds. Behaviour of actual scanning is covered by scans.test.ts.
 */
export function instantEngine(): ScanEngine {
  return {
    register: () => {},
    plugins: () => [],
    scan: async (options) => {
      const at = new Date().toISOString();
      return {
        tool: { name: 'dl-sentinel', version: TOOL_VERSION },
        project: path.basename(options.target),
        target: options.target,
        startedAt: at,
        finishedAt: at,
        durationMs: 0,
        scannersRun: [],
        stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [],
        errors: [],
      };
    },
  };
}

/** A user as returned by `POST /api/users`, including its one-time token. */
export interface CreatedUser {
  id: string;
  name: string;
  role: UserRole;
  createdAt: string;
  /** Shown exactly once by the API; the server keeps only its hash. */
  token: string;
}

/**
 * Create a user through the API and return it with its one-time token. Uses the
 * root token by default (only an admin may create users).
 */
export async function createUser(
  ctx: TestServer,
  input: { name: string; role: UserRole },
  adminToken: string = ctx.token,
): Promise<CreatedUser> {
  const res = await postJson(ctx.base, '/api/users', adminToken, input);
  if (res.status !== 201) {
    throw new Error(`Expected 201 creating user, got ${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as CreatedUser;
}

/** Read and parse the JSONL audit log written under a test server's data dir. */
export function readAuditLog(dataDir: string): AuditEntry[] {
  let raw: string;
  try {
    raw = readFileSync(path.join(dataDir, 'audit.log'), 'utf8');
  } catch {
    return [];
  }
  return raw
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as AuditEntry);
}

/**
 * Poll the audit log until an entry matching `predicate` appears (the append is
 * fire-and-forget, so it can lag the response by a tick) or the deadline passes.
 */
export async function waitForAuditEntry(
  dataDir: string,
  predicate: (entry: AuditEntry) => boolean,
  timeoutMs = 2000,
): Promise<AuditEntry> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const match = readAuditLog(dataDir).find(predicate);
    if (match !== undefined) return match;
    if (Date.now() > deadline) throw new Error('Timed out waiting for a matching audit entry');
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
}

/**
 * A mutable clock for driving the scheduler deterministically. `now()` reads the
 * current value; `advance(ms)` moves it forward; `set(ms)` jumps to an instant.
 * Pass `now` into `startTestServer` as the server's injected clock.
 */
export function mutableClock(start = Date.UTC(2026, 0, 1)): {
  now: () => number;
  advance: (ms: number) => void;
  set: (ms: number) => void;
} {
  let current = start;
  return {
    now: () => current,
    advance: (ms) => {
      current += ms;
    },
    set: (ms) => {
      current = ms;
    },
  };
}
