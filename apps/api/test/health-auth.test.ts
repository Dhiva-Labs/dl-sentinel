import { mkdtempSync, rmSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { TOOL_VERSION } from '@dl-sentinel/core';
import { createServer } from '../src/index.js';
import { bearer, fixturesRoot, silentLogger, startTestServer } from './support.js';
import type { TestServer } from './support.js';

describe('health and authentication', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer();
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('serves /health without authentication', async () => {
    const res = await fetch(`${ctx.base}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; version: string };
    expect(body).toEqual({ status: 'ok', version: TOOL_VERSION });
  });

  it('rejects a non-GET /health with 405', async () => {
    const res = await fetch(`${ctx.base}/health`, { method: 'POST' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET');
  });

  it('rejects an /api request with no token (401)', async () => {
    const res = await fetch(`${ctx.base}/api/rules`);
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('Bearer');
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe('unauthorized');
    expect(typeof body.error.message).toBe('string');
  });

  it('rejects a malformed Authorization header (401)', async () => {
    const res = await fetch(`${ctx.base}/api/rules`, {
      headers: { Authorization: 'Basic abc123' },
    });
    expect(res.status).toBe(401);
  });

  it('rejects a wrong token of equal length (401)', async () => {
    // Same length as the real token, different content — exercises the
    // constant-time comparison to completion.
    const wrong = 'x'.repeat(ctx.token.length);
    const res = await fetch(`${ctx.base}/api/rules`, { headers: bearer(wrong) });
    expect(res.status).toBe(401);
  });

  it('rejects a wrong token of a different length without error (401)', async () => {
    // A shorter token must not throw from timingSafeEqual (length-safe path).
    const res = await fetch(`${ctx.base}/api/rules`, { headers: bearer('short') });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('unauthorized');
  });

  it('accepts the correct token (200)', async () => {
    const res = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    expect(Array.isArray(await res.json())).toBe(true);
  });
});

describe('token generation when unconfigured', () => {
  let dataDir: string;
  let savedToken: string | undefined;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-gen-'));
    savedToken = process.env.SENTINEL_API_TOKEN;
    delete process.env.SENTINEL_API_TOKEN;
  });

  afterEach(() => {
    if (savedToken !== undefined) process.env.SENTINEL_API_TOKEN = savedToken;
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('generates a usable random token and prints it once', async () => {
    const warnings: string[] = [];
    const server = createServer({
      scanRoot: fixturesRoot(),
      dataDir,
      logger: { ...silentLogger, warn: (m) => warnings.push(m) },
    });
    try {
      expect(server.sentinel.tokenGenerated).toBe(true);
      expect(server.sentinel.token).toMatch(/^[0-9a-f]{64}$/);
      // The token is announced exactly once at startup.
      expect(warnings.filter((m) => m.includes(server.sentinel.token))).toHaveLength(1);

      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
      const address = server.address() as AddressInfo;
      const base = `http://127.0.0.1:${address.port}`;

      const unauth = await fetch(`${base}/api/rules`);
      expect(unauth.status).toBe(401);
      const authed = await fetch(`${base}/api/rules`, { headers: bearer(server.sentinel.token) });
      expect(authed.status).toBe(200);
    } finally {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        (server as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      });
    }
  });
});
