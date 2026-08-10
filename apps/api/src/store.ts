import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { appendFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding, Report } from '@dl-sentinel/core';
import type { AuditEntry, ScanSummary, ServerLogger, StoredScan } from './types.js';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toSummary(scan: StoredScan): ScanSummary {
  return {
    id: scan.id,
    project: scan.report.project,
    startedAt: scan.report.startedAt,
    stats: scan.report.stats,
    findingCount: scan.report.findings.length,
  };
}

/**
 * Persists scans as individual JSON files under `<dataDir>/scans/` and appends
 * request records to a JSONL audit log at `<dataDir>/audit.log`. Existing scans
 * are loaded synchronously at construction so a fresh server sees prior scans
 * (listing survives a restart). Findings are already redacted by the engine and
 * are stored as-is; the store never writes tokens or raw request bodies.
 */
export class ReportStore {
  private readonly scans = new Map<string, StoredScan>();
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
        const parsed = JSON.parse(raw) as StoredScan;
        if (
          parsed !== null &&
          typeof parsed === 'object' &&
          typeof parsed.id === 'string' &&
          parsed.report !== undefined
        ) {
          this.scans.set(parsed.id, parsed);
        }
      } catch (error) {
        this.logger.warn(`Skipping unreadable scan file ${name}: ${errorMessage(error)}`);
      }
    }
  }

  /** Persist a report under a new id and return the stored record. */
  create(report: Report): StoredScan {
    const id = randomUUID();
    const record: StoredScan = { id, status: 'completed', report };
    this.scans.set(id, record);
    try {
      writeFileSync(path.join(this.scansDir, `${id}.json`), JSON.stringify(record, null, 2));
    } catch (error) {
      this.logger.error(`Failed to persist scan ${id}: ${errorMessage(error)}`);
    }
    return record;
  }

  get(id: string): StoredScan | undefined {
    return this.scans.get(id);
  }

  /** All scans, newest first. */
  list(): StoredScan[] {
    return [...this.scans.values()].sort((a, b) =>
      b.report.startedAt.localeCompare(a.report.startedAt),
    );
  }

  summaries(): ScanSummary[] {
    return this.list().map(toSummary);
  }

  /** Findings across every scan (newest scan first). */
  allFindings(): Finding[] {
    return this.list().flatMap((scan) => scan.report.findings);
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
