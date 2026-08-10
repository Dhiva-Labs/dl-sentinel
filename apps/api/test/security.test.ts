import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { ScanEngine } from '@dl-sentinel/engine';
import { bearer, postJson, startTestServer, vulnerableApp } from './support.js';
import type { TestServer } from './support.js';
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

  it('a fresh server on the same data dir lists prior scans', async () => {
    const first = await startTestServer({ dataDir });
    const created = (await (
      await postJson(first.base, '/api/scans', first.token, { path: vulnerableApp() })
    ).json()) as { id: string };
    await first.cleanup();

    const second = await startTestServer({ dataDir });
    try {
      const summaries = (await (
        await fetch(`${second.base}/api/scans`, { headers: bearer(second.token) })
      ).json()) as Array<{ id: string }>;
      expect(summaries.some((s) => s.id === created.id)).toBe(true);

      // The full report survives too.
      const detail = await fetch(`${second.base}/api/scans/${created.id}`, {
        headers: bearer(second.token),
      });
      expect(detail.status).toBe(200);
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

  it('returns a generic 500 without leaking internal error detail', async () => {
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
      const res = await postJson(broken.base, '/api/scans', broken.token, {
        path: vulnerableApp(),
      });
      expect(res.status).toBe(500);
      const text = await res.text();
      expect(text).not.toContain(boom);
      const body = JSON.parse(text) as { error: { code: string; message: string } };
      expect(body.error.code).toBe('internal_error');
      expect(body.error.message).toBe('Internal server error');
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
