import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  bearer,
  fixturesRoot,
  mutableClock,
  postJson,
  sendJsonRequest,
  startTestServer,
  vulnerableApp,
  waitForScan,
} from './support.js';
import type { TestServer } from './support.js';
import type { ScheduleRecord } from '../src/index.js';

const MINUTE = 60_000;

async function createSchedule(ctx: TestServer, body: unknown): Promise<Response> {
  return postJson(ctx.base, '/api/schedules', ctx.token, body);
}

describe('schedule CRUD', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer({ rateLimit: { max: 10_000 } });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('POST /api/schedules creates a schedule (201) with a computed nextRunAt', async () => {
    const res = await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE });
    expect(res.status).toBe(201);
    const schedule = (await res.json()) as ScheduleRecord;
    expect(typeof schedule.id).toBe('string');
    expect(schedule.id.length).toBeGreaterThan(0);
    expect(schedule.path).toContain('vulnerable-app');
    expect(schedule.intervalMs).toBe(MINUTE);
    expect(schedule.enabled).toBe(true);
    expect(typeof schedule.createdAt).toBe('string');
    expect(Number.isNaN(Date.parse(schedule.nextRunAt))).toBe(false);
    expect(schedule.lastRunAt).toBeUndefined();
    expect(schedule.lastScanId).toBeUndefined();
  });

  it('persists an optional scanner subset', async () => {
    const res = await createSchedule(ctx, {
      path: vulnerableApp(),
      intervalMs: MINUTE,
      scanners: ['secrets'],
    });
    expect(res.status).toBe(201);
    const schedule = (await res.json()) as ScheduleRecord;
    expect(schedule.scanners).toEqual(['secrets']);
  });

  it('GET /api/schedules lists created schedules', async () => {
    await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE });
    await createSchedule(ctx, { path: fixturesRoot(), intervalMs: 2 * MINUTE });
    const res = await fetch(`${ctx.base}/api/schedules`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const list = (await res.json()) as ScheduleRecord[];
    expect(list.length).toBe(2);
    expect(list.every((s) => typeof s.id === 'string')).toBe(true);
  });

  it('GET /api/schedules/:id returns one, 404 for unknown', async () => {
    const created = (await (
      await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE })
    ).json()) as ScheduleRecord;

    const found = await fetch(`${ctx.base}/api/schedules/${created.id}`, {
      headers: bearer(ctx.token),
    });
    expect(found.status).toBe(200);
    expect(((await found.json()) as ScheduleRecord).id).toBe(created.id);

    const missing = await fetch(`${ctx.base}/api/schedules/does-not-exist`, {
      headers: bearer(ctx.token),
    });
    expect(missing.status).toBe(404);
    const body = (await missing.json()) as { error: { code: string } };
    expect(body.error.code).toBe('not_found');
  });

  it('DELETE /api/schedules/:id returns 204, then 404 for a second delete', async () => {
    const created = (await (
      await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE })
    ).json()) as ScheduleRecord;

    const del = await sendJsonRequest(
      ctx.base,
      `/api/schedules/${created.id}`,
      ctx.token,
      'DELETE',
    );
    expect(del.status).toBe(204);
    expect(await del.text()).toBe('');

    const again = await sendJsonRequest(
      ctx.base,
      `/api/schedules/${created.id}`,
      ctx.token,
      'DELETE',
    );
    expect(again.status).toBe(404);
    const gone = await fetch(`${ctx.base}/api/schedules/${created.id}`, {
      headers: bearer(ctx.token),
    });
    expect(gone.status).toBe(404);
  });

  it('PATCH /api/schedules/:id disables and re-enables', async () => {
    const created = (await (
      await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE })
    ).json()) as ScheduleRecord;

    const disabled = (await (
      await sendJsonRequest(ctx.base, `/api/schedules/${created.id}`, ctx.token, 'PATCH', {
        enabled: false,
      })
    ).json()) as ScheduleRecord;
    expect(disabled.enabled).toBe(false);

    const reEnabled = (await (
      await sendJsonRequest(ctx.base, `/api/schedules/${created.id}`, ctx.token, 'PATCH', {
        enabled: true,
      })
    ).json()) as ScheduleRecord;
    expect(reEnabled.enabled).toBe(true);
  });

  it('PATCH /api/schedules/:id changes the interval and recomputes nextRunAt', async () => {
    const created = (await (
      await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE })
    ).json()) as ScheduleRecord;

    const res = await sendJsonRequest(
      ctx.base,
      `/api/schedules/${created.id}`,
      ctx.token,
      'PATCH',
      {
        intervalMs: 5 * MINUTE,
      },
    );
    expect(res.status).toBe(200);
    const updated = (await res.json()) as ScheduleRecord;
    expect(updated.intervalMs).toBe(5 * MINUTE);
    expect(Date.parse(updated.nextRunAt)).toBeGreaterThan(Date.parse(created.nextRunAt));
  });

  it('PATCH returns 404 for an unknown schedule', async () => {
    const res = await sendJsonRequest(ctx.base, '/api/schedules/nope', ctx.token, 'PATCH', {
      enabled: false,
    });
    expect(res.status).toBe(404);
  });
});

describe('schedule validation', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer({ rateLimit: { max: 10_000 } });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('rejects a path outside the scan root (400)', async () => {
    const res = await createSchedule(ctx, { path: '/etc', intervalMs: MINUTE });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('validation_error');
  });

  it('rejects an interval below the minimum (400)', async () => {
    const res = await createSchedule(ctx, { path: vulnerableApp(), intervalMs: 5_000 });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe('validation_error');
    expect(body.error.message).toContain('60');
  });

  it('rejects a missing interval (400)', async () => {
    const res = await createSchedule(ctx, { path: vulnerableApp() });
    expect(res.status).toBe(400);
  });

  it('rejects a non-numeric interval (400)', async () => {
    const res = await createSchedule(ctx, { path: vulnerableApp(), intervalMs: 'soon' });
    expect(res.status).toBe(400);
  });

  it('rejects an unknown scanner id (400)', async () => {
    const res = await createSchedule(ctx, {
      path: vulnerableApp(),
      intervalMs: MINUTE,
      scanners: ['secrets', 'not-a-scanner'],
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain('not-a-scanner');
  });

  it('rejects a non-object body (400)', async () => {
    const res = await sendJsonRequest(ctx.base, '/api/schedules', ctx.token, 'POST', [1, 2, 3]);
    expect(res.status).toBe(400);
  });

  it('requires authentication for every schedule route (401)', async () => {
    const routes: Array<[string, string]> = [
      ['GET', '/api/schedules'],
      ['POST', '/api/schedules'],
      ['GET', '/api/schedules/x'],
      ['PATCH', '/api/schedules/x'],
      ['DELETE', '/api/schedules/x'],
    ];
    for (const [method, route] of routes) {
      const res = await fetch(`${ctx.base}${route}`, { method });
      expect(res.status, `${method} ${route}`).toBe(401);
    }
  });
});

describe('scheduler execution (injected clock)', () => {
  let ctx: TestServer;
  let clock: ReturnType<typeof mutableClock>;

  beforeEach(async () => {
    clock = mutableClock();
    // A huge polling interval keeps the real timer from firing mid-test; the
    // injected clock + manual tick() drive scheduling deterministically.
    ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      now: clock.now,
      schedulerIntervalMs: 3_600_000,
    });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('tick() enqueues a due schedule, which runs through the queue to completed', async () => {
    const created = (await (
      await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE })
    ).json()) as ScheduleRecord;

    // Not yet due: ticking now does nothing.
    expect(ctx.server.scheduler.tick()).toBe(0);

    // Advance past nextRunAt; one tick enqueues exactly one scan.
    clock.advance(MINUTE + 1);
    expect(ctx.server.scheduler.tick()).toBe(1);
    // Advancing state advanced nextRunAt too, so an immediate re-tick is a no-op.
    expect(ctx.server.scheduler.tick()).toBe(0);

    const after = (await (
      await fetch(`${ctx.base}/api/schedules/${created.id}`, { headers: bearer(ctx.token) })
    ).json()) as ScheduleRecord;
    expect(after.lastScanId).toBeDefined();
    expect(after.lastRunAt).toBeDefined();
    expect(Date.parse(after.nextRunAt)).toBeGreaterThan(clock.now());

    // The enqueued scan actually runs to completion via the real engine.
    const record = await waitForScan(ctx, after.lastScanId as string);
    expect(record.status).toBe('completed');
    expect(record.report).toBeDefined();
  });

  it('does not enqueue a disabled schedule', async () => {
    const created = (await (
      await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE })
    ).json()) as ScheduleRecord;
    await sendJsonRequest(ctx.base, `/api/schedules/${created.id}`, ctx.token, 'PATCH', {
      enabled: false,
    });

    clock.advance(10 * MINUTE);
    expect(ctx.server.scheduler.tick()).toBe(0);

    const after = (await (
      await fetch(`${ctx.base}/api/schedules/${created.id}`, { headers: bearer(ctx.token) })
    ).json()) as ScheduleRecord;
    expect(after.lastScanId).toBeUndefined();
  });

  it('smoke: schedule → tick → completed scan → /api/trends shows a point', async () => {
    const created = (await (
      await createSchedule(ctx, { path: vulnerableApp(), intervalMs: MINUTE })
    ).json()) as ScheduleRecord;

    clock.advance(MINUTE + 1);
    expect(ctx.server.scheduler.tick()).toBe(1);

    const after = (await (
      await fetch(`${ctx.base}/api/schedules/${created.id}`, { headers: bearer(ctx.token) })
    ).json()) as ScheduleRecord;
    const record = await waitForScan(ctx, after.lastScanId as string);
    expect(record.status).toBe('completed');

    const trends = (await (
      await fetch(`${ctx.base}/api/trends`, { headers: bearer(ctx.token) })
    ).json()) as Array<{ finishedAt: string; total: number }>;
    expect(trends.length).toBe(1);
    expect(trends[0]?.total ?? 0).toBeGreaterThan(0);
  });
});

describe('scheduler persistence across restart', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-sched-'));
    mkdirSync(path.join(dataDir, 'schedules'), { recursive: true });
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('a fresh server on the same data dir keeps the schedule with a sane nextRunAt', async () => {
    const first = await startTestServer({ dataDir, rateLimit: { max: 10_000 } });
    const created = (await (
      await postJson(first.base, '/api/schedules', first.token, {
        path: vulnerableApp(),
        intervalMs: MINUTE,
      })
    ).json()) as ScheduleRecord;
    await first.cleanup();

    const second = await startTestServer({ dataDir, rateLimit: { max: 10_000 } });
    try {
      const res = await fetch(`${second.base}/api/schedules/${created.id}`, {
        headers: bearer(second.token),
      });
      expect(res.status).toBe(200);
      const reloaded = (await res.json()) as ScheduleRecord;
      expect(reloaded.id).toBe(created.id);
      expect(reloaded.intervalMs).toBe(MINUTE);
      expect(reloaded.enabled).toBe(true);
      expect(Number.isNaN(Date.parse(reloaded.nextRunAt))).toBe(false);
    } finally {
      await second.cleanup();
    }
  });

  it('resumes an overdue schedule so it runs once promptly, not once per missed interval', async () => {
    const clock = mutableClock();
    // Seed a schedule whose nextRunAt is far in the past relative to the clock.
    const overdue: ScheduleRecord = {
      id: 'seeded-overdue',
      path: vulnerableApp(),
      intervalMs: MINUTE,
      enabled: true,
      createdAt: new Date(clock.now() - 10 * MINUTE).toISOString(),
      nextRunAt: new Date(clock.now() - 10 * MINUTE).toISOString(),
    };
    writeFileSync(
      path.join(dataDir, 'schedules', `${overdue.id}.json`),
      JSON.stringify(overdue, null, 2),
    );

    const ctx = await startTestServer({
      dataDir,
      rateLimit: { max: 10_000 },
      now: clock.now,
      schedulerIntervalMs: 3_600_000,
    });
    try {
      // resume() (run at construction) clamped nextRunAt to ~now; the first tick
      // fires exactly once and pushes nextRunAt a full interval out.
      expect(ctx.server.scheduler.tick()).toBe(1);
      expect(ctx.server.scheduler.tick()).toBe(0);

      const reloaded = (await (
        await fetch(`${ctx.base}/api/schedules/${overdue.id}`, { headers: bearer(ctx.token) })
      ).json()) as ScheduleRecord;
      expect(reloaded.lastScanId).toBeDefined();
      expect(Date.parse(reloaded.nextRunAt)).toBeGreaterThan(clock.now());

      const record = await waitForScan(ctx, reloaded.lastScanId as string);
      expect(record.status).toBe('completed');
    } finally {
      await ctx.cleanup();
    }
  });
});
