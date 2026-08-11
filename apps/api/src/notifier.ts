import { defaultConfig, evaluatePolicy } from '@dl-sentinel/core';
import type { SeverityStats } from '@dl-sentinel/core';
import {
  DELIVERY_TIMEOUT_MS,
  SIGNATURE_HEADER,
  buildPayload,
  sanitizeDeliveryError,
  serializeBody,
  signBody,
  statusError,
} from './notifications.js';
import type { ReportStore } from './store.js';
import type {
  DeliveryResult,
  FetchLike,
  NotificationChannel,
  NotificationEvent,
  NotificationPayload,
  NotifierControls,
  ScanRecord,
  ServerLogger,
} from './types.js';

const EMPTY_STATS: SeverityStats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

/**
 * An abort signal that fires after `ms`. `AbortSignal.timeout` is used where
 * available (its timer is unref'd, so a pending delivery never keeps the process
 * alive); the fallback keeps the module working on a runtime without it.
 */
function timeoutSignal(ms: number): AbortSignal | undefined {
  const factory: unknown = (AbortSignal as { timeout?: (ms: number) => AbortSignal }).timeout;
  if (typeof factory === 'function') return AbortSignal.timeout(ms);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  (timer as { unref?: () => void }).unref?.();
  return controller.signal;
}

/**
 * Delivers scan-lifecycle notifications to the configured channels.
 *
 * Three properties are load-bearing and are the reason this is a class rather
 * than a function:
 *
 * 1. **Off the critical path.** {@link emit} returns synchronously. A job's
 *    terminal state is persisted first and delivery is started afterwards, so
 *    no scan ever waits on — or fails because of — notification IO.
 * 2. **Observable quiescence.** Because nothing awaits a delivery inline, the
 *    in-flight promises are tracked here and exposed through {@link drain}, so
 *    tests and graceful shutdown can wait for silence instead of sleeping. This
 *    is also what keeps a delivery from outliving the data directory it writes
 *    `lastError` into.
 * 3. **Failures are inert.** Every delivery outcome is recorded on the channel
 *    (`lastError` set on failure, cleared on success) and logged at warn level.
 *    Nothing throws out of {@link emit}, so a broken receiver cannot produce an
 *    unhandled rejection, let alone fail a scan.
 *
 * With no channels configured — the default — {@link emit} does no work and the
 * injected `fetch` is never called: zero configuration means zero outbound
 * requests.
 */
export class Notifier implements NotifierControls {
  private readonly pending = new Set<Promise<unknown>>();
  private stopped = false;

  constructor(
    private readonly store: ReportStore,
    private readonly logger: ServerLogger,
    private readonly fetchImpl: FetchLike,
  ) {}

  /**
   * Fan a payload out to every enabled channel subscribed to `event`. Deliveries
   * run concurrently; the aggregate promise is tracked for {@link drain} but is
   * deliberately not returned, so no caller can accidentally await it on a
   * request or job path.
   */
  emit(event: NotificationEvent, payload: NotificationPayload): void {
    if (this.stopped) return;
    const channels = this.store
      .listChannels()
      .filter((channel) => channel.enabled && channel.events.includes(event));
    if (channels.length === 0) return;
    this.track(Promise.all(channels.map((channel) => this.deliver(channel, payload))));
  }

  /**
   * Raise the events a settled job implies, from the persisted record:
   *
   * - `completed` → `scan.completed`, plus `policy.violated` when the report's
   *   severity counts breach the policy.
   * - `failed` → `scan.failed`, plus `schedule.failed` when the job was started
   *   by a schedule (the schedule's id travels on the record).
   *
   * **Policy source.** The engine surfaces the policy it resolved for the run
   * on `report.policy` (the target's own `sentinel.yml` policy, or the
   * defaults). Older persisted reports predate that field, so it falls back to
   * `defaultConfig().policy` for them.
   */
  emitForSettledScan(record: ScanRecord): void {
    if (this.stopped) return;
    if (record.status === 'completed' && record.report !== undefined) {
      const payload = buildPayload({
        event: 'scan.completed',
        scanId: record.id,
        path: record.path,
        project: record.report.project,
        stats: record.report.stats,
        findingCount: record.report.findings.length,
        finishedAt: record.finishedAt ?? record.createdAt,
      });
      this.emit('scan.completed', payload);
      const policy = record.report.policy ?? defaultConfig().policy;
      if (!evaluatePolicy(record.report.stats, policy).pass) {
        this.emit('policy.violated', { ...payload, event: 'policy.violated' });
      }
      return;
    }
    if (record.status === 'failed') {
      const payload = buildPayload({
        event: 'scan.failed',
        scanId: record.id,
        path: record.path,
        project: basename(record.path),
        stats: EMPTY_STATS,
        findingCount: 0,
        finishedAt: record.finishedAt ?? record.createdAt,
      });
      this.emit('scan.failed', payload);
      if (record.scheduleId !== undefined) {
        this.emit('schedule.failed', {
          ...payload,
          event: 'schedule.failed',
          scheduleId: record.scheduleId,
        });
      }
    }
  }

  /**
   * Raise `schedule.failed` for a schedule that could not even be enqueued (so
   * no scan record exists). `scanId` is empty for exactly that reason.
   */
  emitScheduleFailure(scheduleId: string, target: string, at: string, reason: string): void {
    this.emit('schedule.failed', {
      event: 'schedule.failed',
      scanId: '',
      path: target,
      project: basename(target),
      stats: EMPTY_STATS,
      findingCount: 0,
      finishedAt: at,
      scheduleId,
    });
    this.logger.warn(`Schedule ${scheduleId} failed to start a scan: ${reason}`);
  }

  /**
   * Send one delivery through the real path and report the outcome. Used by
   * `POST /api/notifications/:id/test`, which is an admin's connectivity check —
   * so it must exercise exactly the code a live event would, signature included,
   * rather than a simplified probe. Awaited by the handler (that is the point of
   * the endpoint), but still tracked so shutdown cannot race it.
   */
  async sendTest(channel: NotificationChannel): Promise<DeliveryResult> {
    const payload = buildPayload({
      event: 'test',
      scanId: 'test-scan',
      path: '/example/project',
      project: 'example-project',
      stats: EMPTY_STATS,
      findingCount: 0,
      finishedAt: new Date().toISOString(),
    });
    const delivery = this.deliver(channel, payload);
    this.track(delivery);
    return delivery;
  }

  /**
   * POST one payload to one channel. Never throws: a transport failure, an
   * abort, or a `>= 400` response all resolve to a failed {@link DeliveryResult}
   * and are recorded on the channel.
   */
  private async deliver(
    channel: NotificationChannel,
    payload: NotificationPayload,
  ): Promise<DeliveryResult> {
    const body = serializeBody(channel, payload);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    // Signed over the exact bytes below — a receiver must verify against the raw
    // body it read, not a re-serialization of the parsed JSON.
    if (channel.type === 'webhook' && channel.secret !== undefined && channel.secret !== '') {
      headers[SIGNATURE_HEADER] = signBody(channel.secret, body);
    }

    try {
      const signal = timeoutSignal(DELIVERY_TIMEOUT_MS);
      const response = await this.fetchImpl(channel.url, {
        method: 'POST',
        headers,
        body,
        ...(signal === undefined ? {} : { signal }),
      });
      if (response.status >= 400) {
        return this.recordFailure(channel, statusError(response.status), response.status);
      }
      this.store.clearChannelError(channel.id);
      return { ok: true, status: response.status };
    } catch (error) {
      return this.recordFailure(channel, sanitizeDeliveryError(error));
    }
  }

  /** Persist a sanitized failure on the channel and log it. Never throws. */
  private recordFailure(
    channel: NotificationChannel,
    message: string,
    status?: number,
  ): DeliveryResult {
    this.store.setChannelError(channel.id, message);
    // The channel id and type identify it; the URL is not logged, since a Slack
    // incoming-webhook URL is itself a credential.
    this.logger.warn(
      `Notification delivery to ${channel.type} channel ${channel.id} failed: ${message}`,
    );
    return status === undefined
      ? { ok: false, error: message }
      : { ok: false, status, error: message };
  }

  /** Hold a delivery for {@link drain}, and drop it once it settles. */
  private track(promise: Promise<unknown>): void {
    // deliver() never rejects, but tracking a rejected promise here would still
    // be an unhandled rejection if it ever did, so it is neutralised first.
    const tracked = promise.then(
      () => undefined,
      (error: unknown) => {
        this.logger.warn(`Notification delivery error: ${sanitizeDeliveryError(error)}`);
      },
    );
    this.pending.add(tracked);
    void tracked.finally(() => {
      this.pending.delete(tracked);
    });
  }

  async drain(): Promise<void> {
    // A settling delivery can still be writing its lastError, so loop until the
    // set is genuinely empty rather than snapshotting once.
    while (this.pending.size > 0) {
      await Promise.allSettled([...this.pending]);
    }
  }

  async stop(): Promise<void> {
    this.stopped = true;
    await this.drain();
  }
}

/** Last path segment of a target, used as a project name when no report exists. */
function basename(target: string): string {
  const parts = target.split(/[\\/]/).filter((part) => part !== '');
  return parts[parts.length - 1] ?? target;
}
