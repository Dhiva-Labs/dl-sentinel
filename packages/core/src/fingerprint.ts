import { createHash } from 'node:crypto';
import type { Finding } from './types.js';

/**
 * Stable short fingerprint over an ordered list of parts. Parts are
 * NUL-separated so ("ab","c") and ("a","bc") hash differently.
 */
export function fingerprint(...parts: ReadonlyArray<string | number | undefined>): string {
  const hash = createHash('sha256');
  for (const part of parts) {
    hash.update(String(part ?? ''));
    hash.update('\u0000');
  }
  return hash.digest('hex').slice(0, 16);
}

/**
 * Canonical fingerprint for a finding. Evidence participates so that two
 * distinct matches of the same rule on the same line stay distinct — evidence
 * is already redacted, so no secret material enters the hash input.
 */
export function findingFingerprint(
  finding: Pick<Finding, 'ruleId' | 'scanner' | 'file' | 'line' | 'column' | 'evidence'>,
): string {
  return fingerprint(
    finding.scanner,
    finding.ruleId,
    finding.file,
    finding.line ?? 0,
    finding.column ?? 0,
    finding.evidence,
  );
}

/** Build a complete Finding, computing its id fingerprint. */
export function createFinding(input: Omit<Finding, 'id'>): Finding {
  return { id: findingFingerprint(input), ...input };
}

/** Drop findings whose id was already seen, preserving first-seen order. */
export function dedupeFindings(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    out.push(finding);
  }
  return out;
}
