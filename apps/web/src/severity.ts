import type { Severity } from './types.js';

/** Most severe first — matches packages/core/src/stats.ts SEVERITY_ORDER. */
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * CSS class suffix for a severity value, e.g. `sev-critical`. Used to color
 * badges and cards consistently (see public/styles.css `.sev-*` rules).
 */
export function severityClass(severity: Severity): string {
  return `sev-${severity}`;
}

/** Human-readable label, e.g. "critical" -> "Critical". */
export function severityLabel(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

/** 0 = most severe, matching SEVERITIES order; unknown values sort last. */
export function severityRank(severity: Severity): number {
  const rank = SEVERITIES.indexOf(severity);
  return rank === -1 ? SEVERITIES.length : rank;
}
