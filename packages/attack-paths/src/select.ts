/**
 * Deterministic selection helpers shared by the correlation rules.
 *
 * Correlation is a search over sets of findings, and a rule that picks "a"
 * finding must always pick the *same* one for the same report — otherwise path
 * ids move between runs. Every candidate list is therefore put through
 * {@link sortCandidates}, which is a total order (the finding id breaks the
 * last tie), and rules take the head of it.
 */
import type { Finding, Severity } from '@dl-sentinel/core';
import { severityRank } from '@dl-sentinel/core';

/**
 * The most paths a single correlation rule may contribute to one report.
 *
 * Every rule is already bounded by construction — at most one path per service
 * unit, per exposed surface, or per API document — but a pathological
 * repository can still have hundreds of services. This is the backstop: the
 * highest-severity matches survive, in the same deterministic order the report
 * uses, and the rest are dropped rather than flooding the section that is
 * supposed to be read by a human.
 */
export const MAX_PATHS_PER_RULE = 10;

/**
 * Total order over findings: severity (critical first), then file, line,
 * ruleId, and finally id so the order never depends on input order.
 */
export function sortCandidates(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      compare(a.file, b.file) ||
      (a.line ?? 0) - (b.line ?? 0) ||
      compare(a.ruleId, b.ruleId) ||
      compare(a.id, b.id),
  );
}

/** Codepoint ordering: locale-independent, so output is stable everywhere. */
export function compare(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/** The most severe of two severities. */
export function moreSevere(a: Severity, b: Severity): Severity {
  return severityRank(a) <= severityRank(b) ? a : b;
}

/** The most severe severity among `findings`; `info` when there are none. */
export function maxSeverity(findings: readonly Finding[]): Severity {
  return findings.reduce<Severity>((worst, finding) => moreSevere(worst, finding.severity), 'info');
}

/** `file:line` when a line is known, else just the file. */
export function locationOf(finding: Finding): string {
  return finding.line === undefined ? finding.file : `${finding.file}:${String(finding.line)}`;
}

/** Group findings by an arbitrary key, preserving each group's input order. */
export function groupBy<T>(items: readonly T[], key: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const bucket = groups.get(key(item));
    if (bucket === undefined) groups.set(key(item), [item]);
    else bucket.push(item);
  }
  return groups;
}
