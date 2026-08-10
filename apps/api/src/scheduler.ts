import type { ScanQueue } from './queue.js';
import type { ReportStore } from './store.js';
import type { ScheduleRecord, SchedulerControls, ServerLogger } from './types.js';

/**
 * Drives scheduled scans. On each {@link tick} it enqueues a scan — through the
 * shared {@link ScanQueue}, never running the scan itself — for every enabled
 * schedule whose `nextRunAt` has passed, then advances that schedule's
 * `nextRunAt` a full interval past *now*. Advancing past now (rather than past
 * the old `nextRunAt`) means a schedule that fell behind during downtime fires
 * once when it comes due, not once per missed interval.
 *
 * Time comes from an injected `now()` so tests advance a clock and call
 * `tick()` directly instead of waiting for the real timer. The periodic timer
 * (started by {@link start}) is `unref`'d so it never keeps the process alive,
 * and every tick is wrapped so a scheduling error is logged and swallowed,
 * never crashing the server.
 */
export class Scheduler implements SchedulerControls {
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(
    private readonly store: ReportStore,
    private readonly queue: ScanQueue,
    private readonly logger: ServerLogger,
    private readonly checkIntervalMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * Recompute `nextRunAt` for persisted schedules after a (re)start. A schedule
   * with an unparseable `nextRunAt` is reset a full interval out; one that is
   * overdue is set to run promptly on the next tick — exactly once, because the
   * tick then pushes `nextRunAt` a full interval past now.
   */
  resume(): void {
    const nowMs = this.now();
    for (const schedule of this.store.listSchedules()) {
      const due = Date.parse(schedule.nextRunAt);
      if (Number.isNaN(due)) {
        this.store.updateSchedule({
          ...schedule,
          nextRunAt: new Date(nowMs + schedule.intervalMs).toISOString(),
        });
      } else if (due < nowMs) {
        this.store.updateSchedule({ ...schedule, nextRunAt: new Date(nowMs).toISOString() });
      }
    }
  }

  tick(): number {
    const nowMs = this.now();
    let enqueued = 0;
    for (const schedule of this.store.listSchedules()) {
      if (!schedule.enabled) continue;
      const due = Date.parse(schedule.nextRunAt);
      if (!Number.isNaN(due) && due > nowMs) continue;
      if (this.fire(schedule, nowMs)) enqueued += 1;
    }
    return enqueued;
  }

  /** Enqueue one scan for a due schedule and advance it. Never throws. */
  private fire(schedule: ScheduleRecord, nowMs: number): boolean {
    try {
      const scan = this.store.create(
        schedule.scanners === undefined
          ? { path: schedule.path }
          : { path: schedule.path, scanners: schedule.scanners },
      );
      this.queue.enqueue(scan.id);
      this.store.updateSchedule({
        ...schedule,
        lastRunAt: new Date(nowMs).toISOString(),
        lastScanId: scan.id,
        nextRunAt: new Date(nowMs + schedule.intervalMs).toISOString(),
      });
      return true;
    } catch (error) {
      this.logger.error(
        `Scheduler failed to enqueue schedule ${schedule.id}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return false;
    }
  }

  start(): void {
    if (this.timer !== undefined) return;
    this.timer = setInterval(() => {
      try {
        this.tick();
      } catch (error) {
        // tick() already swallows per-schedule errors; this guards the loop
        // itself so a scheduling fault can never take the server down.
        this.logger.error(
          `Scheduler tick failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }, this.checkIntervalMs);
    // Do not keep the process alive solely for the scheduler.
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer === undefined) return;
    clearInterval(this.timer);
    this.timer = undefined;
  }
}
