import type { Severity, SeverityStats } from './types.js';

export function emptySeverityStats(): SeverityStats {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/** Count items by severity. Pure — works on any array of `{ severity }`. */
export function summarizeSeverity(items: readonly { severity: Severity }[]): SeverityStats {
  const stats = emptySeverityStats();
  for (const item of items) {
    stats[item.severity] += 1;
  }
  return stats;
}

export function totalFindings(stats: SeverityStats): number {
  return stats.critical + stats.high + stats.medium + stats.low + stats.info;
}

/**
 * Group items by their `scanner` field and count them, most findings first.
 * Powers the dashboard's "risk by scanner" panel.
 */
export function countByScanner(
  items: readonly { scanner: string }[],
): Array<{ scanner: string; count: number }> {
  const counts = new Map<string, number>();
  for (const item of items) {
    counts.set(item.scanner, (counts.get(item.scanner) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([scanner, count]) => ({ scanner, count }))
    .sort((a, b) => b.count - a.count || a.scanner.localeCompare(b.scanner));
}
