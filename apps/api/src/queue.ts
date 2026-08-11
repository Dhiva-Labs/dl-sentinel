import type { ScanEngine, ScanOptions } from '@dl-sentinel/engine';
import type { ScanQueueControls, ScanRecord, ServerLogger } from './types.js';
import { TERMINAL_STATUSES } from './types.js';
import type { ReportStore } from './store.js';

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Turn a thrown `scan()` error into a message that is safe to persist and return
 * to clients. Engine `UsageError`s are caller-facing validation feedback and are
 * surfaced verbatim (the same messages the synchronous path returned as 400s);
 * any other failure collapses to a generic message so internal detail and stack
 * traces never leak. The full error is logged server-side by the caller.
 */
function sanitizeScanError(error: unknown): string {
  if (error instanceof Error && error.name === 'UsageError') {
    return error.message;
  }
  return 'Scan failed due to an internal error';
}

interface Waiter {
  resolve: (record: ScanRecord) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const DEFAULT_WAIT_TIMEOUT_MS = 15_000;

/**
 * A bounded, in-process worker pool that runs scans as background jobs. Jobs are
 * enqueued by id; up to `concurrency` run at once. Each job is marked `running`
 * (persisted), executed via a fresh engine, then marked `completed` with its
 * report or `failed` with a sanitized error — every transition written through
 * the {@link ReportStore}. A thrown `scan()` becomes a `failed` record, never an
 * unhandled rejection or a crashed server. Scheduling never blocks the HTTP event
 * loop: {@link enqueue} returns immediately and work proceeds on the microtask
 * queue.
 */
export class ScanQueue implements ScanQueueControls {
  private readonly queued: string[] = [];
  private active = 0;
  private stopped = false;
  private readonly waiters = new Map<string, Waiter[]>();
  private idleWaiters: Array<() => void> = [];
  private drainWaiters: Array<() => void> = [];
  /**
   * Called once per job, with the settled record, after its terminal state has
   * been persisted. This is the notification hook: it is invoked synchronously
   * and its own work must not be awaited here, so a slow or broken receiver can
   * never delay a job's completion (see {@link Notifier.emit}).
   */
  private onSettled: ((record: ScanRecord) => void) | undefined;

  constructor(
    private readonly store: ReportStore,
    private readonly engineFactory: () => ScanEngine,
    private readonly concurrency: number,
    private readonly logger: ServerLogger,
  ) {}

  /** Register the post-terminal-state hook (see {@link onSettled}). */
  setOnSettled(hook: (record: ScanRecord) => void): void {
    this.onSettled = hook;
  }

  /**
   * Run the settled hook. Wrapped so a fault in a notification path is logged
   * and dropped rather than surfacing as a failed job or an unhandled rejection
   * — the scan has already completed and persisted by this point.
   */
  private notifySettled(record: ScanRecord): void {
    if (this.onSettled === undefined) return;
    try {
      this.onSettled(record);
    } catch (error) {
      this.logger.warn(
        `Post-completion hook for scan ${record.id} failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  /** Add a queued job id to the pool and start work if a slot is free. */
  enqueue(id: string): void {
    if (this.stopped) return;
    this.queued.push(id);
    this.pump();
  }

  private pump(): void {
    while (!this.stopped && this.active < this.concurrency && this.queued.length > 0) {
      const id = this.queued.shift();
      if (id === undefined) break;
      this.active += 1;
      void this.runJob(id).finally(() => {
        this.active -= 1;
        if (!this.stopped) this.pump();
        this.settleWaiters();
      });
    }
    this.settleWaiters();
  }

  private async runJob(id: string): Promise<void> {
    const record = this.store.get(id);
    if (record === undefined) return; // vanished before we reached it
    const running: ScanRecord = { ...record, status: 'running', startedAt: nowIso() };
    delete running.error;
    this.store.update(running);

    try {
      const engine = this.engineFactory();
      const options: ScanOptions =
        running.scanners === undefined
          ? { target: running.path }
          : { target: running.path, scanners: running.scanners };
      const report = await engine.scan(options);
      const completed: ScanRecord = {
        ...running,
        status: 'completed',
        finishedAt: nowIso(),
        report,
      };
      this.store.update(completed);
      // Terminal state is on disk before anything outbound is attempted.
      this.notifySettled(completed);
      this.resolveWaiters(id, completed);
    } catch (error) {
      // The engine isolates individual scanner failures; reaching here means the
      // whole scan threw (e.g. a bad target). Record it as failed — never crash.
      this.logger.error(
        `Scan ${id} failed: ${
          error instanceof Error ? (error.stack ?? error.message) : String(error)
        }`,
      );
      const failed: ScanRecord = {
        ...running,
        status: 'failed',
        finishedAt: nowIso(),
        error: sanitizeScanError(error),
      };
      this.store.update(failed);
      this.notifySettled(failed);
      this.resolveWaiters(id, failed);
    }
  }

  waitForJob(id: string, timeoutMs: number = DEFAULT_WAIT_TIMEOUT_MS): Promise<ScanRecord> {
    const existing = this.store.get(id);
    if (existing !== undefined && TERMINAL_STATUSES.has(existing.status)) {
      return Promise.resolve(existing);
    }
    return new Promise<ScanRecord>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.removeWaiter(id, waiter);
        reject(new Error(`Timed out waiting for scan ${id} after ${timeoutMs}ms`));
      }, timeoutMs);
      // Do not keep the process alive solely to honour a pending waiter.
      timer.unref?.();
      const waiter: Waiter = { resolve, reject, timer };
      const list = this.waiters.get(id) ?? [];
      list.push(waiter);
      this.waiters.set(id, list);
    });
  }

  private resolveWaiters(id: string, record: ScanRecord): void {
    const list = this.waiters.get(id);
    if (list === undefined) return;
    this.waiters.delete(id);
    for (const waiter of list) {
      clearTimeout(waiter.timer);
      waiter.resolve(record);
    }
  }

  private removeWaiter(id: string, waiter: Waiter): void {
    const list = this.waiters.get(id);
    if (list === undefined) return;
    const next = list.filter((entry) => entry !== waiter);
    if (next.length === 0) this.waiters.delete(id);
    else this.waiters.set(id, next);
  }

  private settleWaiters(): void {
    if (this.active !== 0) return;
    // No job is executing: release stop() waiters unconditionally, and drain()
    // waiters only when nothing remains queued either.
    const idle = this.idleWaiters;
    this.idleWaiters = [];
    for (const resolve of idle) resolve();
    if (this.queued.length === 0) {
      const drained = this.drainWaiters;
      this.drainWaiters = [];
      for (const resolve of drained) resolve();
    }
  }

  drain(): Promise<void> {
    if (this.active === 0 && this.queued.length === 0) return Promise.resolve();
    return new Promise<void>((resolve) => this.drainWaiters.push(resolve));
  }

  stop(): Promise<void> {
    this.stopped = true;
    if (this.active === 0) return Promise.resolve();
    return new Promise<void>((resolve) => this.idleWaiters.push(resolve));
  }
}
