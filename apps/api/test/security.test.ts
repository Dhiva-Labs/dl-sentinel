import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { ScanEngine } from '@dl-sentinel/engine';
import { bearer, postJson, startTestServer, vulnerableApp, waitForScan } from './support.js';
import type { TestServer } from './support.js';
import type { ScanRecord } from '../src/index.js';
import { PLANTED_SECRET_VALUES } from '../../../tests/support/index.js';

/** Poll a file until it is non-empty or the timeout elapses. */
async function waitForFile(filePath: string, timeoutMs = 2000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const content = readFileSync(filePath, 'utf8');
      if (content.trim() !== '') return content;
    } catch {
      // not written yet
    }
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${filePath}`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

describe('secret redaction across the API', () => {
  let ctx: TestServer;
  let scanId: string;

  beforeAll(async () => {
    ctx = await startTestServer();
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
    scanId = ((await res.json()) as { id: string }).id;
    // Findings/reports are only served for completed scans; wait for the worker.
    await waitForScan(ctx, scanId);
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('never returns a planted secret value in findings or reports', async () => {
    const findingsText = await (
      await fetch(`${ctx.base}/api/scans/${scanId}/findings`, { headers: bearer(ctx.token) })
    ).text();
    const reportText = await (
      await fetch(`${ctx.base}/api/reports/${scanId}?format=json`, { headers: bearer(ctx.token) })
    ).text();
    const allFindingsText = await (
      await fetch(`${ctx.base}/api/findings`, { headers: bearer(ctx.token) })
    ).text();

    // The scan must have produced findings (otherwise this asserts nothing).
    expect(JSON.parse(findingsText).length).toBeGreaterThan(0);

    for (const secret of PLANTED_SECRET_VALUES) {
      expect(findingsText, `leaked into scan findings: ${secret}`).not.toContain(secret);
      expect(reportText, `leaked into rendered report: ${secret}`).not.toContain(secret);
      expect(allFindingsText, `leaked into cross-scan findings: ${secret}`).not.toContain(secret);
    }
  });
});

describe('persistence across restart', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-persist-'));
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('a fresh server on the same data dir lists prior completed scans', async () => {
    const first = await startTestServer({ dataDir });
    const created = (await (
      await postJson(first.base, '/api/scans', first.token, { path: vulnerableApp() })
    ).json()) as { id: string };
    // Let the scan complete and persist before restarting.
    await waitForScan(first, created.id);
    await first.cleanup();

    const second = await startTestServer({ dataDir });
    try {
      const summaries = (await (
        await fetch(`${second.base}/api/scans`, { headers: bearer(second.token) })
      ).json()) as Array<{ id: string; status: string }>;
      const summary = summaries.find((s) => s.id === created.id);
      expect(summary?.status).toBe('completed');

      // The full record and its report survive the restart.
      const detail = await fetch(`${second.base}/api/scans/${created.id}`, {
        headers: bearer(second.token),
      });
      expect(detail.status).toBe(200);
      const record = (await detail.json()) as ScanRecord;
      expect(record.status).toBe('completed');
      expect(record.report).toBeDefined();
    } finally {
      await second.cleanup();
    }
  });
});

describe('error responses', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  function assertCleanError(body: unknown): void {
    expect(body).toHaveProperty('error');
    const record = body as { error: Record<string, unknown> };
    expect(Object.keys(record)).toEqual(['error']);
    expect(typeof record.error.code).toBe('string');
    expect(typeof record.error.message).toBe('string');
    // No stack traces or internal fields leak.
    expect(record.error).not.toHaveProperty('stack');
    const serialized = JSON.stringify(body);
    expect(serialized).not.toMatch(/\bat\s+\S+\s+\(.*:\d+:\d+\)/);
    expect(serialized).not.toContain('.ts:');
  }

  it('uses the { error: { code, message } } envelope for 401/404/400', async () => {
    const unauthorized = await fetch(`${ctx.base}/api/rules`);
    expect(unauthorized.status).toBe(401);
    assertCleanError(await unauthorized.json());

    const notFound = await fetch(`${ctx.base}/api/scans/nope`, { headers: bearer(ctx.token) });
    expect(notFound.status).toBe(404);
    assertCleanError(await notFound.json());

    const badRequest = await postJson(ctx.base, '/api/scans', ctx.token, {});
    expect(badRequest.status).toBe(400);
    assertCleanError(await badRequest.json());
  });

  it('a failed background scan never leaks internal error detail', async () => {
    // The scan now runs asynchronously, so a thrown scan() surfaces as a failed
    // record rather than a synchronous 500. The record's error must be sanitized:
    // no raw thrown message, no stack trace, no source paths.
    const boom = 'INTERNAL-SECRET-DETAIL-should-not-leak';
    const badEngine: ScanEngine = {
      register: () => {},
      plugins: () => [],
      scan: async () => {
        throw new Error(boom);
      },
    };
    const broken = await startTestServer({ engineFactory: () => badEngine });
    try {
      const post = await postJson(broken.base, '/api/scans', broken.token, {
        path: vulnerableApp(),
      });
      expect(post.status).toBe(202);
      const { id } = (await post.json()) as { id: string };
      const settled = await waitForScan(broken, id);
      expect(settled.status).toBe('failed');

      const res = await fetch(`${broken.base}/api/scans/${id}`, {
        headers: bearer(broken.token),
      });
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).not.toContain(boom);
      expect(text).not.toMatch(/\bat\s+\S+\s+\(.*:\d+:\d+\)/);
      expect(text).not.toContain('.ts:');
      const record = JSON.parse(text) as ScanRecord;
      expect(record.status).toBe('failed');
      expect(record.error).toBe('Scan failed due to an internal error');
    } finally {
      await broken.cleanup();
    }
  });
});

describe('audit log', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('appends a JSONL record per request without logging the token', async () => {
    const res = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);

    const auditPath = path.join(ctx.dataDir, 'audit.log');
    const content = await waitForFile(auditPath);

    // The raw token must never appear in the audit log.
    expect(content).not.toContain(ctx.token);

    const lines = content.trim().split('\n');
    const entry = JSON.parse(lines[lines.length - 1] ?? '{}') as {
      ts: string;
      method: string;
      path: string;
      status: number;
      tokenId: string;
      ip: string;
    };
    expect(entry.method).toBe('GET');
    expect(entry.path).toBe('/api/rules');
    expect(entry.status).toBe(200);
    expect(entry.tokenId).toMatch(/^[0-9a-f]{12}$/);
    expect(typeof entry.ts).toBe('string');
  });
});
