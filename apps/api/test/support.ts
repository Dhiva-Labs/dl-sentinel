import { mkdtempSync, rmSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from '../src/index.js';
import type { ServerLogger, ServerOptions, SentinelApiServer } from '../src/index.js';
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
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        // Force idle keep-alive sockets closed so close() settles promptly.
        const withClose = server as unknown as { closeAllConnections?: () => void };
        withClose.closeAllConnections?.();
      });
      if (ownsDataDir) rmSync(dataDir, { recursive: true, force: true });
    },
  };
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
  return fetch(`${base}${route}`, {
    method: 'POST',
    headers: { ...bearer(token), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
