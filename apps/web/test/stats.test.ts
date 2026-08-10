import { describe, expect, it } from 'vitest';
import {
  countByScanner,
  emptySeverityStats,
  summarizeSeverity,
  totalFindings,
} from '../src/stats.js';
import type { Severity } from '../src/types.js';

function item(severity: Severity, scanner = 'secrets'): { severity: Severity; scanner: string } {
  return { severity, scanner };
}

describe('emptySeverityStats', () => {
  it('returns all-zero counts', () => {
    expect(emptySeverityStats()).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });
});

describe('summarizeSeverity', () => {
  it('counts items by severity', () => {
    const stats = summarizeSeverity([item('critical'), item('high'), item('high'), item('info')]);
    expect(stats).toEqual({ critical: 1, high: 2, medium: 0, low: 0, info: 1 });
  });

  it('returns all-zero for an empty list', () => {
    expect(summarizeSeverity([])).toEqual(emptySeverityStats());
  });
});

describe('totalFindings', () => {
  it('sums every severity bucket', () => {
    expect(totalFindings({ critical: 1, high: 2, medium: 3, low: 4, info: 5 })).toBe(15);
  });

  it('is zero for empty stats', () => {
    expect(totalFindings(emptySeverityStats())).toBe(0);
  });
});

describe('countByScanner', () => {
  it('groups and counts by scanner, most findings first', () => {
    const out = countByScanner([
      item('low', 'source'),
      item('critical', 'secrets'),
      item('high', 'secrets'),
      item('medium', 'dependencies'),
    ]);
    expect(out).toEqual([
      { scanner: 'secrets', count: 2 },
      { scanner: 'dependencies', count: 1 },
      { scanner: 'source', count: 1 },
    ]);
  });

  it('breaks ties alphabetically', () => {
    const out = countByScanner([item('low', 'source'), item('low', 'infra')]);
    expect(out).toEqual([
      { scanner: 'infra', count: 1 },
      { scanner: 'source', count: 1 },
    ]);
  });

  it('returns an empty array for no items', () => {
    expect(countByScanner([])).toEqual([]);
  });
});
