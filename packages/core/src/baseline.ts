/**
 * Baselines: a saved set of known findings so a later scan can report only
 * what is NEW. Because every finding carries a stable fingerprint id
 * (fingerprint.ts), a baseline is essentially a set of those ids; the extra
 * fields recorded per entry are context for a human reading the file.
 *
 * Typical use: generate a baseline once (`createBaseline`), commit it, then
 * scan with it applied so pre-existing findings don't fail CI while any newly
 * introduced finding does.
 */

import { sortFindings } from './stats.js';
import type { Baseline, BaselineEntry, Finding } from './types.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

/**
 * Build a baseline from a set of findings. `generatedAt` is injected rather
 * than read from the clock so the result is deterministic and testable.
 */
export function createBaseline(
  findings: readonly Finding[],
  meta: { target: string; generatedAt: string; tool?: { name: string; version: string } },
): Baseline {
  const entries: BaselineEntry[] = sortFindings(findings).map((f) => ({
    id: f.id,
    ruleId: f.ruleId,
    file: f.file,
    severity: f.severity,
  }));
  return {
    tool: meta.tool ?? { name: TOOL_NAME, version: TOOL_VERSION },
    generatedAt: meta.generatedAt,
    target: meta.target,
    count: entries.length,
    findings: entries,
  };
}

/** The set of finding ids recorded in a baseline. */
export function baselineIds(baseline: Baseline): Set<string> {
  return new Set(baseline.findings.map((entry) => entry.id));
}

export interface BaselineResult {
  /** Findings not present in the baseline (newly introduced). */
  newFindings: Finding[];
  /** Findings already present in the baseline. */
  baselined: Finding[];
}

/** Partition findings by whether their id is present in the baseline. */
export function applyBaseline(findings: readonly Finding[], baseline: Baseline): BaselineResult {
  const known = baselineIds(baseline);
  const newFindings: Finding[] = [];
  const baselined: Finding[] = [];
  for (const finding of findings) {
    if (known.has(finding.id)) {
      baselined.push(finding);
    } else {
      newFindings.push(finding);
    }
  }
  return { newFindings, baselined };
}

/**
 * Validate an untrusted parsed value as a Baseline (e.g. a file read from
 * disk). Returns a typed baseline or throws with a clear message — a security
 * tool must not trust a baseline file's shape blindly.
 */
export function parseBaseline(value: unknown): Baseline {
  if (typeof value !== 'object' || value === null) {
    throw new Error('baseline must be a JSON object');
  }
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.findings)) {
    throw new Error('baseline.findings must be an array');
  }
  const findings: BaselineEntry[] = record.findings.map((raw, index) => {
    if (typeof raw !== 'object' || raw === null) {
      throw new Error(`baseline.findings[${index}] must be an object`);
    }
    const entry = raw as Record<string, unknown>;
    if (typeof entry.id !== 'string' || entry.id.length === 0) {
      throw new Error(`baseline.findings[${index}].id must be a non-empty string`);
    }
    return {
      id: entry.id,
      ruleId: typeof entry.ruleId === 'string' ? entry.ruleId : '',
      file: typeof entry.file === 'string' ? entry.file : '',
      severity: (entry.severity as BaselineEntry['severity']) ?? 'info',
    };
  });
  const tool = record.tool as { name?: unknown; version?: unknown } | undefined;
  return {
    tool: {
      name: typeof tool?.name === 'string' ? tool.name : TOOL_NAME,
      version: typeof tool?.version === 'string' ? tool.version : TOOL_VERSION,
    },
    generatedAt: typeof record.generatedAt === 'string' ? record.generatedAt : '',
    target: typeof record.target === 'string' ? record.target : '',
    count: findings.length,
    findings,
  };
}
