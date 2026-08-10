import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { SeverityStats } from '@dl-sentinel/core';
import { bearer, startTestServer } from './support.js';
import type { TestServer } from './support.js';
import type { HistoryEntry, TrendPoint } from '../src/index.js';

let dataDir: string;

/** Write a completed scan record straight to disk, so seeding is deterministic. */
function seedCompleted(id: string, target: string, finishedAt: string, stats: SeverityStats): void {
  const total = stats.critical + stats.high + stats.medium + stats.low + stats.info;
  const findings = Array.from({ length: total }, (_, i) => ({ id: `${id}-f${i}` }));
  const record = {
    id,
    status: 'completed',
    path: target,
    createdAt: finishedAt,
    startedAt: finishedAt,
    finishedAt,
    report: {
      tool: { name: 'dl-sentinel', version: '0.0.0-test' },
      project: path.basename(target),
      target,
      startedAt: finishedAt,
      finishedAt,
      durationMs: 5,
      scannersRun: ['secrets'],
      stats,
      findings,
      errors: [],
    },
  };
  writeFileSync(path.join(dataDir, 'scans', `${id}.json`), JSON.stringify(record, null, 2));
}

/** Write a non-completed scan record (excluded from history/trends). */
function seedPending(id: string, target: string, status: 'queued' | 'running' | 'failed'): void {
  const record = {
    id,
    status,
    path: target,
    createdAt: '2026-01-01T00:00:00.000Z',
  };
  writeFileSync(path.join(dataDir, 'scans', `${id}.json`), JSON.stringify(record, null, 2));
}

const PROJECT_A = '/projects/alpha';
const PROJECT_B = '/projects/bravo';

function stats(c: number, h: number, m: number, l: number, i: number): SeverityStats {
  return { critical: c, high: h, medium: m, low: l, info: i };
}

describe('history and trends endpoints', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-hist-'));
    mkdirSync(path.join(dataDir, 'scans'), { recursive: true });
    // Seed out of chronological order to prove the endpoints sort, not rely on
    // insertion order.
    seedCompleted('a-mid', PROJECT_A, '2026-02-02T00:00:00.000Z', stats(1, 2, 0, 0, 0));
    seedCompleted('a-old', PROJECT_A, '2026-02-01T00:00:00.000Z', stats(0, 1, 1, 0, 0));
    seedCompleted('a-new', PROJECT_A, '2026-02-03T00:00:00.000Z', stats(2, 0, 0, 1, 3));
    seedCompleted('b-one', PROJECT_B, '2026-02-04T00:00:00.000Z', stats(0, 0, 5, 0, 0));
    // These must never appear in history/trends.
    seedPending('pending-queued', PROJECT_A, 'queued');
    seedPending('pending-running', PROJECT_A, 'running');
    seedPending('pending-failed', PROJECT_A, 'failed');

    ctx = await startTestServer({ dataDir, rateLimit: { max: 10_000 } });
  });

  afterEach(async () => {
    await ctx.cleanup();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('GET /api/history returns completed scans oldest-first with the documented shape', async () => {
    const res = await fetch(`${ctx.base}/api/history`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const history = (await res.json()) as HistoryEntry[];
    // Four completed scans, none of the three pending ones.
    expect(history.map((h) => h.id)).toEqual(['a-old', 'a-mid', 'a-new', 'b-one']);
    const first = history[0] as HistoryEntry;
    expect(first).toMatchObject({
      id: 'a-old',
      path: PROJECT_A,
      project: 'alpha',
      finishedAt: '2026-02-01T00:00:00.000Z',
      findingCount: 2,
    });
    expect(first.stats).toEqual(stats(0, 1, 1, 0, 0));
  });

  it('GET /api/history?target= filters to one project', async () => {
    const res = await fetch(`${ctx.base}/api/history?target=${encodeURIComponent(PROJECT_A)}`, {
      headers: bearer(ctx.token),
    });
    const history = (await res.json()) as HistoryEntry[];
    expect(history.map((h) => h.id)).toEqual(['a-old', 'a-mid', 'a-new']);
    expect(history.every((h) => h.path === PROJECT_A)).toBe(true);
  });

  it('GET /api/history?limit= returns the most recent N, still chronological', async () => {
    const res = await fetch(
      `${ctx.base}/api/history?target=${encodeURIComponent(PROJECT_A)}&limit=2`,
      { headers: bearer(ctx.token) },
    );
    const history = (await res.json()) as HistoryEntry[];
    expect(history.map((h) => h.id)).toEqual(['a-mid', 'a-new']);
  });

  it('GET /api/history rejects a non-positive limit (400)', async () => {
    const res = await fetch(`${ctx.base}/api/history?limit=0`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('validation_error');
  });

  it('GET /api/trends returns a per-scan severity time series oldest-first', async () => {
    const res = await fetch(`${ctx.base}/api/trends?target=${encodeURIComponent(PROJECT_A)}`, {
      headers: bearer(ctx.token),
    });
    expect(res.status).toBe(200);
    const trends = (await res.json()) as TrendPoint[];
    expect(trends).toEqual([
      {
        finishedAt: '2026-02-01T00:00:00.000Z',
        critical: 0,
        high: 1,
        medium: 1,
        low: 0,
        info: 0,
        total: 2,
      },
      {
        finishedAt: '2026-02-02T00:00:00.000Z',
        critical: 1,
        high: 2,
        medium: 0,
        low: 0,
        info: 0,
        total: 3,
      },
      {
        finishedAt: '2026-02-03T00:00:00.000Z',
        critical: 2,
        high: 0,
        medium: 0,
        low: 1,
        info: 3,
        total: 6,
      },
    ]);
  });

  it('GET /api/trends across all targets includes every completed scan', async () => {
    const res = await fetch(`${ctx.base}/api/trends`, { headers: bearer(ctx.token) });
    const trends = (await res.json()) as TrendPoint[];
    expect(trends.length).toBe(4);
    expect(trends.map((t) => t.finishedAt)).toEqual([
      '2026-02-01T00:00:00.000Z',
      '2026-02-02T00:00:00.000Z',
      '2026-02-03T00:00:00.000Z',
      '2026-02-04T00:00:00.000Z',
    ]);
  });

  it('history and trends require authentication (401)', async () => {
    expect((await fetch(`${ctx.base}/api/history`)).status).toBe(401);
    expect((await fetch(`${ctx.base}/api/trends`)).status).toBe(401);
  });
});
