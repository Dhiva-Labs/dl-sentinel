import type { Finding, PolicyConfig, Severity, SeverityStats } from './types.js';

/** Most severe first. */
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** 0 = most severe. */
export function severityRank(severity: Severity): number {
  const rank = SEVERITY_ORDER.indexOf(severity);
  return rank === -1 ? SEVERITY_ORDER.length : rank;
}

export function emptyStats(): SeverityStats {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function computeStats(findings: readonly Finding[]): SeverityStats {
  const stats = emptyStats();
  for (const finding of findings) {
    stats[finding.severity] += 1;
  }
  return stats;
}

/** Sort by severity (critical first), then file, line, ruleId. Stable copy. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    const byFile = a.file.localeCompare(b.file);
    if (byFile !== 0) return byFile;
    const byLine = (a.line ?? 0) - (b.line ?? 0);
    if (byLine !== 0) return byLine;
    return a.ruleId.localeCompare(b.ruleId);
  });
}

export interface PolicyResult {
  pass: boolean;
  /** Severities from policy.failOn that have at least one finding. */
  violations: Severity[];
}

export function evaluatePolicy(stats: SeverityStats, policy: PolicyConfig): PolicyResult {
  const violations = policy.failOn.filter((severity) => stats[severity] > 0);
  return { pass: violations.length === 0, violations };
}
