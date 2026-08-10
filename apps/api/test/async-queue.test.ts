import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Report } from '@dl-sentinel/core';
import type { ScanEngine } from '@dl-sentinel/engine';
import {
  bearer,
  pollScanHttp,
  postJson,
  startTestServer,
  vulnerableApp,
  waitForScan,
} from './support.js';
import type { TestServer } from './support.js';
import type { ScanRecord } from '../src/index.js';

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

/** A minimal, valid Report the fake engines can return on completion. */
function fakeReport(target: string): Report {
  const now = new Date().toISOString();
  return {
    tool: { name: 'dl-sentinel', version: '0.0.0-test' },
    project: path.basename(target),
    target,
    startedAt: now,
    finishedAt: now,
    durationMs: 0,
    scannersRun: ['secrets'],
    stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings: [],
    errors: [],
  };
}

/**
 * A fake engine whose every scan blocks on a shared gate until released, while
 * tracking how many run concurrently. The factory returns the *same* instance,
 * so the counters observe the whole worker pool.
 */
function gatedEngine(): {
  factory: () => ScanEngine;
  release: () => void;
  active: () => number;
  max: () => number;
} {
  let active = 0;
  let maxActive = 0;
  const gate = deferred();
  const engine: ScanEngine = {
    register: () => {},
    plugins: () => [],
    scan: async (options) => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await gate.promise;
      active -= 1;
      return fakeReport(options.target);
    },
  };
  return {
    factory: () => engine,
    release: () => gate.resolve(),
    active: () => active,
    max: () => maxActive,
  };
}

/** Await a predicate becoming true (condition-based, not a fixed sleep). */
async function waitUntil(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('waitUntil: condition not met before timeout');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe('background worker pool', () => {
  it('polling GET /api/scans/:id transitions a real scan to completed with a report', async () => {
    const ctx = await startTestServer({ rateLimit: { max: 10_000 } });
    try {
      const post = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
      expect(post.status).toBe(202);
      const body = (await post.json()) as { id: string; status: string };
      expect(body.status).toBe('queued');

      const record = await pollScanHttp(ctx.base, ctx.token, body.id);
      expect(record.status).toBe('completed');
      expect(record.report).toBeDefined();
      expect(record.report?.project).toBe('vulnerable-app');
    } finally {
      await ctx.cleanup();
    }
  });

  it('runs no more than SENTINEL_SCAN_CONCURRENCY scans at once', async () => {
    const engine = gatedEngine();
    const ctx = await startTestServer({
      scanConcurrency: 2,
      engineFactory: engine.factory,
      rateLimit: { max: 10_000 },
    });
    try {
      const ids: string[] = [];
      for (let i = 0; i < 5; i += 1) {
        const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
        expect(res.status).toBe(202);
        ids.push(((await res.json()) as { id: string }).id);
      }

      // The pool saturates at the cap; the rest wait as queued.
      await waitUntil(() => engine.active() === 2);
      // Let the scheduler run again — it must not exceed the cap.
      await new Promise((resolve) => setImmediate(resolve));
      expect(engine.active()).toBe(2);
      expect(engine.max()).toBe(2);

      // Over HTTP: exactly two running, three still queued.
      const summaries = (await (
        await fetch(`${ctx.base}/api/scans`, { headers: bearer(ctx.token) })
      ).json()) as Array<{ id: string; status: string }>;
      const mine = summaries.filter((s) => ids.includes(s.id));
      expect(mine.filter((s) => s.status === 'running')).toHaveLength(2);
      expect(mine.filter((s) => s.status === 'queued')).toHaveLength(3);

      // Release everything and let the queue drain; the cap was never exceeded.
      engine.release();
      await ctx.server.queue.drain();
      expect(engine.max()).toBe(2);
      for (const id of ids) {
        const record = await waitForScan(ctx, id);
        expect(record.status).toBe('completed');
      }
    } finally {
      engine.release();
      await ctx.cleanup();
    }
  });

  it('report endpoints return 409 while running and 200 once completed', async () => {
    const engine = gatedEngine();
    const ctx = await startTestServer({
      scanConcurrency: 1,
      engineFactory: engine.factory,
      rateLimit: { max: 10_000 },
    });
    try {
      const id = (
        (await (
          await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() })
        ).json()) as { id: string }
      ).id;
      await waitUntil(() => engine.active() === 1);

      // The record itself is readable and shows `running` (no report/error yet).
      const running = (await (
        await fetch(`${ctx.base}/api/scans/${id}`, { headers: bearer(ctx.token) })
      ).json()) as ScanRecord;
      expect(running.status).toBe('running');
      expect(running.report).toBeUndefined();
      expect(running.error).toBeUndefined();

      // Endpoints needing a finished report reject with 409 scan_not_ready.
      for (const route of [`/api/scans/${id}/findings`, `/api/reports/${id}`]) {
        const res = await fetch(`${ctx.base}${route}`, { headers: bearer(ctx.token) });
        expect(res.status, route).toBe(409);
        const body = (await res.json()) as { error: { code: string } };
        expect(body.error.code).toBe('scan_not_ready');
      }

      // The cross-scan aggregate is not tied to one scan: it serves completed
      // scans only, so with none completed it is an empty 200 (never 409).
      const aggregate = await fetch(`${ctx.base}/api/findings`, { headers: bearer(ctx.token) });
      expect(aggregate.status).toBe(200);
      expect((await aggregate.json()) as unknown[]).toEqual([]);

      engine.release();
      await waitForScan(ctx, id);

      for (const route of [`/api/scans/${id}/findings`, `/api/reports/${id}`, `/api/findings`]) {
        const res = await fetch(`${ctx.base}${route}`, { headers: bearer(ctx.token) });
        expect(res.status, route).toBe(200);
      }
    } finally {
      engine.release();
      await ctx.cleanup();
    }
  });

  it('a scan whose engine throws ends failed and does not crash the server', async () => {
    const badEngine: ScanEngine = {
      register: () => {},
      plugins: () => [],
      scan: async () => {
        throw new Error('boom: bad path or internal failure');
      },
    };
    const ctx = await startTestServer({
      engineFactory: () => badEngine,
      rateLimit: { max: 10_000 },
    });
    try {
      const post = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
      expect(post.status).toBe(202);
      const { id } = (await post.json()) as { id: string };

      const settled = await waitForScan(ctx, id);
      expect(settled.status).toBe('failed');
      expect(settled.report).toBeUndefined();
      expect(settled.error).toBe('Scan failed due to an internal error');
      expect(settled.finishedAt).toBeDefined();

      // A failed scan has no report, so report endpoints stay 409.
      const report = await fetch(`${ctx.base}/api/reports/${id}`, { headers: bearer(ctx.token) });
      expect(report.status).toBe(409);

      // Crucially, the server is still alive and handling requests.
      expect((await fetch(`${ctx.base}/health`)).status).toBe(200);
      const ok = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });
      expect(ok.status).toBe(200);
    } finally {
      await ctx.cleanup();
    }
  });
});

describe('restart recovery', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-recover-'));
    mkdirSync(path.join(dataDir, 'scans'), { recursive: true });
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  function writeRecord(record: ScanRecord): void {
    writeFileSync(
      path.join(dataDir, 'scans', `${record.id}.json`),
      JSON.stringify(record, null, 2),
    );
  }

  it('marks a persisted running scan as failed (interrupted) on reload', async () => {
    const now = new Date().toISOString();
    writeRecord({
      id: 'was-running',
      status: 'running',
      path: vulnerableApp(),
      createdAt: now,
      startedAt: now,
    });

    const ctx = await startTestServer({ dataDir });
    try {
      const res = await fetch(`${ctx.base}/api/scans/was-running`, { headers: bearer(ctx.token) });
      expect(res.status).toBe(200);
      const record = (await res.json()) as ScanRecord;
      expect(record.status).toBe('failed');
      expect(record.error).toBe('interrupted by restart');
      expect(record.finishedAt).toBeDefined();
    } finally {
      await ctx.cleanup();
    }
  });

  it('re-enqueues a persisted queued scan on reload and runs it to completion', async () => {
    writeRecord({
      id: 'was-queued',
      status: 'queued',
      path: vulnerableApp(),
      createdAt: new Date().toISOString(),
    });

    // Real engine: the re-enqueued job actually scans vulnerable-app.
    const ctx = await startTestServer({ dataDir });
    try {
      const record = await waitForScan(ctx, 'was-queued', 15_000);
      expect(record.status).toBe('completed');
      expect(record.report).toBeDefined();
    } finally {
      await ctx.cleanup();
    }
  });

  it('never re-runs a completed scan on reload', async () => {
    const report = fakeReport(vulnerableApp());
    writeRecord({
      id: 'already-done',
      status: 'completed',
      path: vulnerableApp(),
      createdAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      report,
    });

    // A throwing engine would flip the record to failed if it were re-run.
    const badEngine: ScanEngine = {
      register: () => {},
      plugins: () => [],
      scan: async () => {
        throw new Error('should never be called for a completed scan');
      },
    };
    const ctx = await startTestServer({ dataDir, engineFactory: () => badEngine });
    try {
      const res = await fetch(`${ctx.base}/api/scans/already-done`, { headers: bearer(ctx.token) });
      const record = (await res.json()) as ScanRecord;
      expect(record.status).toBe('completed');
      expect(record.report).toBeDefined();
    } finally {
      await ctx.cleanup();
    }
  });
});
