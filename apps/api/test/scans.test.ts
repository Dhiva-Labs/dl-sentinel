import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Finding, Report, SeverityStats } from '@dl-sentinel/core';
import { bearer, postJson, startTestServer, vulnerableApp } from './support.js';
import type { TestServer } from './support.js';

interface CreateResponse {
  id: string;
  status: string;
  stats: SeverityStats;
}

function totalFindings(stats: SeverityStats): number {
  return stats.critical + stats.high + stats.medium + stats.low + stats.info;
}

describe('scans lifecycle', () => {
  let ctx: TestServer;
  let created: CreateResponse;

  beforeAll(async () => {
    ctx = await startTestServer();
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
    expect(res.status).toBe(201);
    created = (await res.json()) as CreateResponse;
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('POST /api/scans returns 201 with id, status and stats', () => {
    expect(typeof created.id).toBe('string');
    expect(created.id.length).toBeGreaterThan(0);
    expect(created.status).toBe('completed');
    expect(totalFindings(created.stats)).toBeGreaterThan(0);
  });

  it('GET /api/scans lists the created scan as a summary', async () => {
    const res = await fetch(`${ctx.base}/api/scans`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const summaries = (await res.json()) as Array<{
      id: string;
      project: string;
      startedAt: string;
      stats: SeverityStats;
    }>;
    const summary = summaries.find((s) => s.id === created.id);
    expect(summary).toBeDefined();
    expect(summary?.project).toBe('vulnerable-app');
    expect(typeof summary?.startedAt).toBe('string');
    expect(summary?.stats).toEqual(created.stats);
  });

  it('GET /api/scans/:id returns the full stored report', async () => {
    const res = await fetch(`${ctx.base}/api/scans/${created.id}`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const report = (await res.json()) as Report;
    expect(report.project).toBe('vulnerable-app');
    expect(report.tool.name).toBeTruthy();
    expect(report.findings.length).toBe(totalFindings(created.stats));
    expect(report.scannersRun.length).toBeGreaterThan(0);
  });

  it('GET /api/scans/:id/findings returns the findings array', async () => {
    const res = await fetch(`${ctx.base}/api/scans/${created.id}/findings`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(200);
    const findings = (await res.json()) as Finding[];
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBe(totalFindings(created.stats));
  });

  it('filters findings by severity', async () => {
    const all = (await (
      await fetch(`${ctx.base}/api/scans/${created.id}/findings`, { headers: bearer(ctx.token) })
    ).json()) as Finding[];
    const severity = all[0]?.severity;
    expect(severity).toBeDefined();
    const expected = all.filter((f) => f.severity === severity).length;

    const res = await fetch(`${ctx.base}/api/scans/${created.id}/findings?severity=${severity}`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(200);
    const filtered = (await res.json()) as Finding[];
    expect(filtered.length).toBe(expected);
    expect(filtered.every((f) => f.severity === severity)).toBe(true);
  });

  it('filters findings by scanner', async () => {
    const all = (await (
      await fetch(`${ctx.base}/api/scans/${created.id}/findings`, { headers: bearer(ctx.token) })
    ).json()) as Finding[];
    const scanner = all[0]?.scanner;
    expect(scanner).toBeDefined();
    const expected = all.filter((f) => f.scanner === scanner).length;

    const res = await fetch(`${ctx.base}/api/scans/${created.id}/findings?scanner=${scanner}`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(200);
    const filtered = (await res.json()) as Finding[];
    expect(filtered.length).toBe(expected);
    expect(filtered.every((f) => f.scanner === scanner)).toBe(true);
  });

  it('GET /api/findings returns findings across all scans', async () => {
    const res = await fetch(`${ctx.base}/api/findings`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const findings = (await res.json()) as Finding[];
    expect(findings.length).toBe(totalFindings(created.stats));
  });

  it('GET /api/findings honours the scanner filter', async () => {
    const res = await fetch(`${ctx.base}/api/findings?scanner=secrets`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(200);
    const findings = (await res.json()) as Finding[];
    expect(findings.every((f) => f.scanner === 'secrets')).toBe(true);
  });

  it('returns 404 for an unknown scan id', async () => {
    const res = await fetch(`${ctx.base}/api/scans/does-not-exist`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('not_found');
  });

  it('rejects an invalid severity filter with 400', async () => {
    const res = await fetch(`${ctx.base}/api/findings?severity=nope`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('validation_error');
  });

  it('rejects an unknown scanner filter with 400', async () => {
    const res = await fetch(`${ctx.base}/api/findings?scanner=bogus`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(400);
  });
});

describe('scan request validation', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('rejects a path that traverses outside the scan root (400)', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, {
      path: '../../../../etc',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe('validation_error');
  });

  it('rejects an absolute path outside the scan root (400)', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: '/etc' });
    expect(res.status).toBe(400);
  });

  it('rejects a non-existent path (400)', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, {
      path: 'this-directory-does-not-exist',
    });
    expect(res.status).toBe(400);
  });

  it('rejects an unknown scanner id (400)', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, {
      path: vulnerableApp(),
      scanners: ['secrets', 'not-a-scanner'],
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe('validation_error');
    expect(body.error.message).toContain('not-a-scanner');
  });

  it('rejects a missing path field (400)', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { scanners: ['secrets'] });
    expect(res.status).toBe(400);
  });

  it('rejects a non-object body (400)', async () => {
    const res = await fetch(`${ctx.base}/api/scans`, {
      method: 'POST',
      headers: { ...bearer(ctx.token), 'Content-Type': 'application/json' },
      body: JSON.stringify(['not', 'an', 'object']),
    });
    expect(res.status).toBe(400);
  });

  it('rejects invalid JSON (400 invalid_json)', async () => {
    const res = await fetch(`${ctx.base}/api/scans`, {
      method: 'POST',
      headers: { ...bearer(ctx.token), 'Content-Type': 'application/json' },
      body: '{ not json',
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('invalid_json');
  });

  it('honours an explicit scanner subset', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, {
      path: vulnerableApp(),
      scanners: ['secrets'],
    });
    expect(res.status).toBe(201);
    const created = (await res.json()) as CreateResponse;

    const findings = (await (
      await fetch(`${ctx.base}/api/scans/${created.id}/findings`, { headers: bearer(ctx.token) })
    ).json()) as Finding[];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.scanner === 'secrets')).toBe(true);
  });
});

describe('request body size limit', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer({ maxBodyBytes: 128 });
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('rejects an oversized request body with 413', async () => {
    const bigPath = 'x'.repeat(2048);
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: bigPath });
    expect(res.status).toBe(413);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('payload_too_large');
  });
});
