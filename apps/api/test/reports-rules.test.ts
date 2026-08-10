import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BUILTIN_SCANNERS } from '@dl-sentinel/preset';
import { bearer, postJson, startTestServer, vulnerableApp, waitForScan } from './support.js';
import type { TestServer } from './support.js';

describe('rules endpoint', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('lists every built-in rule with its scanner', async () => {
    const res = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const rules = (await res.json()) as Array<{ id: string; scanner: string; severity: string }>;

    const expectedCount = BUILTIN_SCANNERS.reduce((sum, s) => sum + s.rules.length, 0);
    expect(rules.length).toBe(expectedCount);

    const scannerIds = new Set(BUILTIN_SCANNERS.map((s) => s.id));
    expect(rules.every((r) => scannerIds.has(r.scanner))).toBe(true);
    expect(rules.every((r) => typeof r.id === 'string' && r.id.length > 0)).toBe(true);
  });
});

describe('rendered reports', () => {
  let ctx: TestServer;
  let scanId: string;

  beforeAll(async () => {
    ctx = await startTestServer();
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
    expect(res.status).toBe(202);
    const created = (await res.json()) as { id: string };
    scanId = created.id;
    // Reports render only from a completed scan; wait for the worker to finish.
    await waitForScan(ctx, scanId);
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('renders JSON by default', async () => {
    const res = await fetch(`${ctx.base}/api/reports/${scanId}`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
    const report = (await res.json()) as { tool: { name: string }; findings: unknown[] };
    expect(report.tool.name).toBeTruthy();
    expect(Array.isArray(report.findings)).toBe(true);
  });

  it('renders Markdown', async () => {
    const res = await fetch(`${ctx.base}/api/reports/${scanId}?format=markdown`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/markdown');
    const text = await res.text();
    expect(text).toContain('#');
  });

  it('renders SARIF', async () => {
    const res = await fetch(`${ctx.base}/api/reports/${scanId}?format=sarif`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(200);
    const sarif = (await res.json()) as { version: string; runs: unknown[] };
    expect(sarif.version).toBe('2.1.0');
    expect(Array.isArray(sarif.runs)).toBe(true);
  });

  it('rejects an unknown format with 400', async () => {
    const res = await fetch(`${ctx.base}/api/reports/${scanId}?format=terminal`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('validation_error');
  });

  it('returns 404 for a report of an unknown scan', async () => {
    const res = await fetch(`${ctx.base}/api/reports/missing-id`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(404);
  });
});
