import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { appendFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding } from '@dl-sentinel/core';
import type { AuditEntry, ScanRecord, ScanStatus, ScanSummary, ServerLogger } from './types.js';

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
 */
export class ReportStore {
  private readonly scans = new Map<string, ScanRecord>();
  private readonly scansDir: string;
  private readonly auditPath: string;
  private readonly logger: ServerLogger;

  constructor(dataDir: string, logger: ServerLogger) {
    this.scansDir = path.join(dataDir, 'scans');
    this.auditPath = path.join(dataDir, 'audit.log');
    this.logger = logger;
    this.loadExisting();
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
  create(input: { path: string; scanners?: string[] }): ScanRecord {
    const record: ScanRecord = {
      id: randomUUID(),
      status: 'queued',
      path: input.path,
      createdAt: new Date().toISOString(),
    };
    if (input.scanners !== undefined) record.scanners = input.scanners;
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

  /** Append one audit record. Failures are logged, never thrown. */
  async audit(entry: AuditEntry): Promise<void> {
    try {
      await appendFile(this.auditPath, `${JSON.stringify(entry)}\n`, 'utf8');
    } catch (error) {
      this.logger.warn(`Failed to append audit log: ${errorMessage(error)}`);
    }
  }
}
