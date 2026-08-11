import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { appendFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding } from '@dl-sentinel/core';
import type {
  AuditEntry,
  NotificationChannel,
  NotificationEvent,
  ScanRecord,
  ScanStatus,
  ScanSummary,
  ScheduleRecord,
  ServerLogger,
  UserRecord,
} from './types.js';
import { isChannelType, isNotificationEvent } from './notifications.js';
import { isUserRole } from './permissions.js';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const VALID_STATUSES: ReadonlySet<string> = new Set<ScanStatus>([
  'queued',
  'running',
  'completed',
  'failed',
]);

function toSummary(scan: ScanRecord): ScanSummary {
  const summary: ScanSummary = {
    id: scan.id,
    status: scan.status,
    path: scan.path,
    createdAt: scan.createdAt,
  };
  if (scan.startedAt !== undefined) summary.startedAt = scan.startedAt;
  if (scan.finishedAt !== undefined) summary.finishedAt = scan.finishedAt;
  // Report-derived fields are only meaningful for a completed scan.
  if (scan.status === 'completed' && scan.report !== undefined) {
    summary.project = scan.report.project;
    summary.durationMs = scan.report.durationMs;
    summary.scannersRun = scan.report.scannersRun;
    summary.stats = scan.report.stats;
    summary.findingCount = scan.report.findings.length;
  }
  return summary;
}

/**
 * Persists scan records as individual JSON files under `<dataDir>/scans/` and
 * appends request records to a JSONL audit log at `<dataDir>/audit.log`. Records
 * are loaded synchronously at construction so a fresh server sees prior scans
 * (listing and status survive a restart). Findings are already redacted by the
 * engine and are stored as-is; the store never writes tokens or raw request
 * bodies. Records mutate through {@link create} and {@link update}, and every
 * mutation is written through to disk.
 *
 * Schedules (`<dataDir>/schedules/`), users (`<dataDir>/users/`) and
 * notification channels (`<dataDir>/notifications/`) persist the same way. A
 * user record holds only the SHA-256 hash of its bearer token — the token itself
 * is never written to disk, to the audit log, or to a response after the one
 * create/rotate that returned it. A channel record does hold its signing secret
 * (it must, to sign), but that field never leaves this process except as an
 * HMAC.
 */
export class ReportStore {
  private readonly scans = new Map<string, ScanRecord>();
  private readonly schedules = new Map<string, ScheduleRecord>();
  private readonly users = new Map<string, UserRecord>();
  private readonly channels = new Map<string, NotificationChannel>();
  private readonly scansDir: string;
  private readonly schedulesDir: string;
  private readonly usersDir: string;
  private readonly channelsDir: string;
  private readonly auditPath: string;
  private readonly logger: ServerLogger;
  /** In-flight async writes (audit-log appends), so shutdown can await them. */
  private readonly pendingWrites = new Set<Promise<unknown>>();

  constructor(dataDir: string, logger: ServerLogger) {
    this.scansDir = path.join(dataDir, 'scans');
    this.schedulesDir = path.join(dataDir, 'schedules');
    this.usersDir = path.join(dataDir, 'users');
    this.channelsDir = path.join(dataDir, 'notifications');
    this.auditPath = path.join(dataDir, 'audit.log');
    this.logger = logger;
    this.loadExisting();
    this.loadSchedules();
    this.loadUsers();
    this.loadChannels();
  }

  private loadExisting(): void {
    mkdirSync(this.scansDir, { recursive: true });
    let names: string[];
    try {
      names = readdirSync(this.scansDir);
    } catch (error) {
      this.logger.warn(`Could not read data directory: ${errorMessage(error)}`);
      return;
    }
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      try {
        const raw = readFileSync(path.join(this.scansDir, name), 'utf8');
        const parsed = JSON.parse(raw) as ScanRecord;
        if (
          parsed !== null &&
          typeof parsed === 'object' &&
          typeof parsed.id === 'string' &&
          typeof parsed.path === 'string' &&
          typeof parsed.createdAt === 'string' &&
          VALID_STATUSES.has(parsed.status)
        ) {
          this.scans.set(parsed.id, parsed);
        }
      } catch (error) {
        this.logger.warn(`Skipping unreadable scan file ${name}: ${errorMessage(error)}`);
      }
    }
  }

  private persist(record: ScanRecord): void {
    try {
      writeFileSync(path.join(this.scansDir, `${record.id}.json`), JSON.stringify(record, null, 2));
    } catch (error) {
      this.logger.error(`Failed to persist scan ${record.id}: ${errorMessage(error)}`);
    }
  }

  /** Create and persist a new `queued` record for a validated target. */
  create(input: { path: string; scanners?: string[]; scheduleId?: string }): ScanRecord {
    const record: ScanRecord = {
      id: randomUUID(),
      status: 'queued',
      path: input.path,
      createdAt: new Date().toISOString(),
    };
    if (input.scanners !== undefined) record.scanners = input.scanners;
    if (input.scheduleId !== undefined) record.scheduleId = input.scheduleId;
    this.scans.set(record.id, record);
    this.persist(record);
    return record;
  }

  /** Replace a record in memory and write it through to disk. */
  update(record: ScanRecord): void {
    this.scans.set(record.id, record);
    this.persist(record);
  }

  get(id: string): ScanRecord | undefined {
    return this.scans.get(id);
  }

  /** All records, newest first (by creation time). */
  list(): ScanRecord[] {
    return [...this.scans.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  summaries(): ScanSummary[] {
    return this.list().map(toSummary);
  }

  /** Findings across every completed scan (newest scan first). */
  allFindings(): Finding[] {
    return this.list()
      .filter((scan) => scan.status === 'completed' && scan.report !== undefined)
      .flatMap((scan) => scan.report?.findings ?? []);
  }

  /**
   * Completed scans (those with a report and a `finishedAt`), oldest first, so
   * history and trend series read left-to-right in time. Ordering is
   * deterministic — ties on `finishedAt` break by id. When `target` is given,
   * only scans of that exact (canonical) path are returned.
   */
  completedScans(target?: string): ScanRecord[] {
    return this.list()
      .filter(
        (scan) =>
          scan.status === 'completed' &&
          scan.report !== undefined &&
          scan.finishedAt !== undefined &&
          (target === undefined || scan.path === target),
      )
      .sort((a, b) => {
        const byTime = (a.finishedAt ?? '').localeCompare(b.finishedAt ?? '');
        return byTime !== 0 ? byTime : a.id.localeCompare(b.id);
      });
  }

  /**
   * Reconcile persisted state on startup after a possible unclean shutdown. Any
   * record left `running` is failed (nothing was actually executing in this fresh
   * process). Returns the ids of records still `queued` so the caller can
   * re-enqueue them. Completed and failed records are never touched.
   */
  reconcile(now: string): string[] {
    const requeue: string[] = [];
    for (const record of this.scans.values()) {
      if (record.status === 'running') {
        this.update({
          ...record,
          status: 'failed',
          finishedAt: now,
          error: 'interrupted by restart',
        });
      } else if (record.status === 'queued') {
        requeue.push(record.id);
      }
    }
    return requeue;
  }

  // -------------------------------------------------------------------------
  // Schedules — persisted like scans, under `<dataDir>/schedules/<id>.json`.
  // -------------------------------------------------------------------------

  private loadSchedules(): void {
    mkdirSync(this.schedulesDir, { recursive: true });
    let names: string[];
    try {
      names = readdirSync(this.schedulesDir);
    } catch (error) {
      this.logger.warn(`Could not read schedules directory: ${errorMessage(error)}`);
      return;
    }
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      try {
        const parsed = JSON.parse(
          readFileSync(path.join(this.schedulesDir, name), 'utf8'),
        ) as ScheduleRecord;
        if (
          parsed !== null &&
          typeof parsed === 'object' &&
          typeof parsed.id === 'string' &&
          typeof parsed.path === 'string' &&
          typeof parsed.intervalMs === 'number' &&
          typeof parsed.enabled === 'boolean' &&
          typeof parsed.createdAt === 'string' &&
          typeof parsed.nextRunAt === 'string'
        ) {
          this.schedules.set(parsed.id, parsed);
        }
      } catch (error) {
        this.logger.warn(`Skipping unreadable schedule file ${name}: ${errorMessage(error)}`);
      }
    }
  }

  private persistSchedule(record: ScheduleRecord): void {
    try {
      writeFileSync(
        path.join(this.schedulesDir, `${record.id}.json`),
        JSON.stringify(record, null, 2),
      );
    } catch (error) {
      this.logger.error(`Failed to persist schedule ${record.id}: ${errorMessage(error)}`);
    }
  }

  /** Create and persist a new schedule (enabled by default). */
  createSchedule(input: {
    path: string;
    scanners?: string[];
    intervalMs: number;
    nextRunAt: string;
    enabled?: boolean;
    createdAt?: string;
  }): ScheduleRecord {
    const record: ScheduleRecord = {
      id: randomUUID(),
      path: input.path,
      intervalMs: input.intervalMs,
      enabled: input.enabled ?? true,
      createdAt: input.createdAt ?? new Date().toISOString(),
      nextRunAt: input.nextRunAt,
    };
    if (input.scanners !== undefined) record.scanners = input.scanners;
    this.schedules.set(record.id, record);
    this.persistSchedule(record);
    return record;
  }

  /** Replace a schedule in memory and write it through to disk. */
  updateSchedule(record: ScheduleRecord): void {
    this.schedules.set(record.id, record);
    this.persistSchedule(record);
  }

  getSchedule(id: string): ScheduleRecord | undefined {
    return this.schedules.get(id);
  }

  /** All schedules, newest first (by creation time). */
  listSchedules(): ScheduleRecord[] {
    return [...this.schedules.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  /** Remove a schedule and its file. Returns whether it existed. */
  deleteSchedule(id: string): boolean {
    if (!this.schedules.delete(id)) return false;
    try {
      rmSync(path.join(this.schedulesDir, `${id}.json`), { force: true });
    } catch (error) {
      this.logger.warn(`Failed to remove schedule file ${id}: ${errorMessage(error)}`);
    }
    return true;
  }

  // -------------------------------------------------------------------------
  // Users — persisted like schedules, under `<dataDir>/users/<id>.json`. The
  // stored record carries a token *hash*, never a token.
  // -------------------------------------------------------------------------

  private loadUsers(): void {
    mkdirSync(this.usersDir, { recursive: true });
    let names: string[];
    try {
      names = readdirSync(this.usersDir);
    } catch (error) {
      this.logger.warn(`Could not read users directory: ${errorMessage(error)}`);
      return;
    }
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      try {
        const parsed = JSON.parse(readFileSync(path.join(this.usersDir, name), 'utf8')) as
          UserRecord | undefined;
        if (
          parsed !== null &&
          typeof parsed === 'object' &&
          typeof parsed.id === 'string' &&
          typeof parsed.name === 'string' &&
          typeof parsed.tokenHash === 'string' &&
          parsed.tokenHash !== '' &&
          typeof parsed.createdAt === 'string' &&
          isUserRole(parsed.role)
        ) {
          this.users.set(parsed.id, parsed);
        }
      } catch (error) {
        this.logger.warn(`Skipping unreadable user file ${name}: ${errorMessage(error)}`);
      }
    }
  }

  private persistUser(record: UserRecord): void {
    try {
      writeFileSync(path.join(this.usersDir, `${record.id}.json`), JSON.stringify(record, null, 2));
    } catch (error) {
      this.logger.error(`Failed to persist user ${record.id}: ${errorMessage(error)}`);
    }
  }

  /**
   * Create and persist a user. The caller has already minted the token and
   * hashed it — this store only ever sees the digest.
   */
  createUser(input: { name: string; role: UserRecord['role']; tokenHash: string }): UserRecord {
    const record: UserRecord = {
      id: randomUUID(),
      name: input.name,
      role: input.role,
      tokenHash: input.tokenHash,
      createdAt: new Date().toISOString(),
    };
    this.users.set(record.id, record);
    this.persistUser(record);
    return record;
  }

  /** Replace a user in memory and write it through to disk. */
  updateUser(record: UserRecord): void {
    this.users.set(record.id, record);
    this.persistUser(record);
  }

  getUser(id: string): UserRecord | undefined {
    return this.users.get(id);
  }

  /** All users, newest first (by creation time). */
  listUsers(): UserRecord[] {
    return [...this.users.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  /** Remove a user and its file. Returns whether it existed. */
  deleteUser(id: string): boolean {
    if (!this.users.delete(id)) return false;
    try {
      rmSync(path.join(this.usersDir, `${id}.json`), { force: true });
    } catch (error) {
      this.logger.warn(`Failed to remove user file ${id}: ${errorMessage(error)}`);
    }
    return true;
  }

  // -------------------------------------------------------------------------
  // Notification channels — `<dataDir>/notifications/<id>.json`. Unlike a user
  // record, a channel keeps its `secret` in plaintext: it signs webhook bodies,
  // which a digest cannot do. It is never served (see `toPublicChannel`) and
  // never logged.
  // -------------------------------------------------------------------------

  private loadChannels(): void {
    mkdirSync(this.channelsDir, { recursive: true });
    let names: string[];
    try {
      names = readdirSync(this.channelsDir);
    } catch (error) {
      this.logger.warn(`Could not read notifications directory: ${errorMessage(error)}`);
      return;
    }
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      try {
        const parsed = JSON.parse(readFileSync(path.join(this.channelsDir, name), 'utf8')) as
          NotificationChannel | undefined;
        if (
          parsed !== null &&
          typeof parsed === 'object' &&
          typeof parsed.id === 'string' &&
          typeof parsed.url === 'string' &&
          typeof parsed.enabled === 'boolean' &&
          typeof parsed.createdAt === 'string' &&
          isChannelType(parsed.type) &&
          Array.isArray(parsed.events) &&
          parsed.events.length > 0 &&
          parsed.events.every((event) => isNotificationEvent(event))
        ) {
          this.channels.set(parsed.id, parsed);
        }
      } catch (error) {
        this.logger.warn(`Skipping unreadable notification file ${name}: ${errorMessage(error)}`);
      }
    }
  }

  private persistChannel(record: NotificationChannel): void {
    try {
      writeFileSync(
        path.join(this.channelsDir, `${record.id}.json`),
        JSON.stringify(record, null, 2),
      );
    } catch (error) {
      // The id is safe to log; the record is not (it may carry a secret).
      this.logger.error(
        `Failed to persist notification channel ${record.id}: ${errorMessage(error)}`,
      );
    }
  }

  /** Create and persist a channel (enabled by default). */
  createChannel(input: {
    type: NotificationChannel['type'];
    url: string;
    events: NotificationEvent[];
    enabled?: boolean;
    secret?: string;
  }): NotificationChannel {
    const record: NotificationChannel = {
      id: randomUUID(),
      type: input.type,
      url: input.url,
      events: input.events,
      enabled: input.enabled ?? true,
      createdAt: new Date().toISOString(),
    };
    if (input.secret !== undefined) record.secret = input.secret;
    this.channels.set(record.id, record);
    this.persistChannel(record);
    return record;
  }

  /** Replace a channel in memory and write it through to disk. */
  updateChannel(record: NotificationChannel): void {
    this.channels.set(record.id, record);
    this.persistChannel(record);
  }

  getChannel(id: string): NotificationChannel | undefined {
    return this.channels.get(id);
  }

  /** All channels, newest first (by creation time). */
  listChannels(): NotificationChannel[] {
    return [...this.channels.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  /** Remove a channel and its file. Returns whether it existed. */
  deleteChannel(id: string): boolean {
    if (!this.channels.delete(id)) return false;
    try {
      rmSync(path.join(this.channelsDir, `${id}.json`), { force: true });
    } catch (error) {
      this.logger.warn(`Failed to remove notification file ${id}: ${errorMessage(error)}`);
    }
    return true;
  }

  /**
   * Record a delivery failure against a channel. Looked up by id rather than
   * taking a record, because a delivery outlives the request that triggered it:
   * the channel may have been edited or deleted in between, and a stale copy
   * must never be written back (or resurrect a deleted channel).
   */
  setChannelError(id: string, message: string): void {
    const current = this.channels.get(id);
    if (current === undefined) return;
    if (current.lastError === message) return;
    this.updateChannel({ ...current, lastError: message });
  }

  /** Clear a channel's `lastError` after a successful delivery. */
  clearChannelError(id: string): void {
    const current = this.channels.get(id);
    if (current === undefined || current.lastError === undefined) return;
    const cleared: NotificationChannel = { ...current };
    delete cleared.lastError;
    this.updateChannel(cleared);
  }

  /**
   * Append one audit record. Failures are logged, never thrown. The write is
   * tracked in {@link pendingWrites} so a clean shutdown can await it — callers
   * `void` this promise, so without tracking the append could still be in flight
   * when the data directory is removed, racing the append against teardown.
   */
  async audit(entry: AuditEntry): Promise<void> {
    const write = appendFile(this.auditPath, `${JSON.stringify(entry)}\n`, 'utf8').catch(
      (error) => {
        this.logger.warn(`Failed to append audit log: ${errorMessage(error)}`);
      },
    );
    this.pendingWrites.add(write);
    const forget = (): void => {
      this.pendingWrites.delete(write);
    };
    write.then(forget, forget);
    await write;
  }

  /**
   * Resolve once every in-flight async write has settled. Synchronous writes
   * (scan/schedule persistence) already complete before their method returns;
   * this covers the fire-and-forget audit appends. Used for deterministic
   * shutdown so teardown never races a pending write against directory removal.
   */
  async flushWrites(): Promise<void> {
    await Promise.allSettled([...this.pendingWrites]);
  }
}
