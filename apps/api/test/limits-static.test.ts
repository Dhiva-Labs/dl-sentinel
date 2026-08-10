import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { bearer, startTestServer } from './support.js';
import type { TestServer } from './support.js';

describe('rate limiting', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer({ rateLimit: { max: 2, windowMs: 60_000 } });
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('returns 429 with Retry-After once the window limit is exceeded', async () => {
    const first = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });
    const second = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });
    const third = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(third.status).toBe(429);
    expect(third.headers.get('retry-after')).toBeTruthy();
    const body = (await third.json()) as { error: { code: string } };
    expect(body.error.code).toBe('rate_limited');
  });
});

describe('static dashboard: placeholder when web root is absent', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    // The web package is a stub here (no getWebRoot), so no root resolves.
    ctx = await startTestServer();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('serves an HTML placeholder at / without authentication', async () => {
    const res = await fetch(`${ctx.base}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain('DL Sentinel');
  });

  it('returns 404 for an asset path when there is no web root', async () => {
    const res = await fetch(`${ctx.base}/app.js`);
    expect(res.status).toBe(404);
  });
});

describe('static dashboard: serving a real web root', () => {
  let ctx: TestServer;
  let parentDir: string;
  let webRoot: string;
  const secret = 'TOP-SECRET-OUTSIDE-WEBROOT';

  beforeEach(async () => {
    parentDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-web-'));
    webRoot = path.join(parentDir, 'public');
    // Create web root with an index and a nested asset.
    mkdirSync(path.join(webRoot, 'assets'), { recursive: true });
    writeFileSync(path.join(webRoot, 'index.html'), '<h1>Dashboard Home</h1>');
    writeFileSync(path.join(webRoot, 'assets', 'app.js'), 'console.log("dash");');
    // A sensitive file that lives OUTSIDE the web root.
    writeFileSync(path.join(parentDir, 'secret.txt'), secret);

    ctx = await startTestServer({ webRoot });
  });

  afterEach(async () => {
    await ctx.cleanup();
    rmSync(parentDir, { recursive: true, force: true });
  });

  it('serves index.html at /', async () => {
    const res = await fetch(`${ctx.base}/`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('Dashboard Home');
  });

  it('serves a nested asset with a sensible content type', async () => {
    const res = await fetch(`${ctx.base}/assets/app.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/javascript');
    expect(await res.text()).toContain('dash');
  });

  it('never serves a file outside the web root via traversal', async () => {
    const res = await fetch(`${ctx.base}/%2e%2e/secret.txt`);
    expect(res.status).not.toBe(200);
    expect(await res.text()).not.toContain(secret);
  });

  it('returns 404 for a missing asset', async () => {
    const res = await fetch(`${ctx.base}/missing.html`);
    expect(res.status).toBe(404);
  });
});
