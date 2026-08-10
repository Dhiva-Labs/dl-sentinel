import { describe, expect, it } from 'vitest';
import { createFinding } from '../src/fingerprint.js';
import {
  computeStats,
  emptyStats,
  evaluatePolicy,
  severityRank,
  sortFindings,
} from '../src/stats.js';
import type { Finding, Severity } from '../src/types.js';

function finding(severity: Severity, file = 'a.ts', line = 1, ruleId = 'C001'): Finding {
  return createFinding({
    ruleId,
    title: 't',
    description: 'd',
    severity,
    confidence: 'medium',
    category: 'source',
    file,
    line,
    evidence: 'e',
    recommendation: 'r',
    references: [],
    scanner: 'source',
  });
}

describe('severityRank', () => {
  it('orders critical before info', () => {
    expect(severityRank('critical')).toBeLessThan(severityRank('high'));
    expect(severityRank('high')).toBeLessThan(severityRank('medium'));
    expect(severityRank('medium')).toBeLessThan(severityRank('low'));
    expect(severityRank('low')).toBeLessThan(severityRank('info'));
  });
});

describe('computeStats', () => {
  it('counts by severity', () => {
    const stats = computeStats([
      finding('critical'),
      finding('high'),
      finding('high'),
      finding('info'),
    ]);
    expect(stats).toEqual({ critical: 1, high: 2, medium: 0, low: 0, info: 1 });
  });

  it('returns all-zero for no findings', () => {
    expect(computeStats([])).toEqual(emptyStats());
  });
});

describe('sortFindings', () => {
  it('sorts by severity, then file, then line', () => {
    const out = sortFindings([
      finding('low', 'z.ts', 1),
      finding('critical', 'b.ts', 9),
      finding('critical', 'a.ts', 5),
      finding('critical', 'a.ts', 2),
    ]);
    expect(out.map((f) => [f.severity, f.file, f.line])).toEqual([
      ['critical', 'a.ts', 2],
      ['critical', 'a.ts', 5],
      ['critical', 'b.ts', 9],
      ['low', 'z.ts', 1],
    ]);
  });

  it('does not mutate the input', () => {
    const input = [finding('low'), finding('critical')];
    sortFindings(input);
    expect(input[0]?.severity).toBe('low');
  });
});

describe('evaluatePolicy', () => {
  it('fails when a failOn severity is present', () => {
    const stats = computeStats([finding('high')]);
    const result = evaluatePolicy(stats, { failOn: ['critical', 'high'] });
    expect(result.pass).toBe(false);
    expect(result.violations).toEqual(['high']);
  });

  it('passes when no failOn severity is present', () => {
    const stats = computeStats([finding('medium')]);
    expect(evaluatePolicy(stats, { failOn: ['critical', 'high'] }).pass).toBe(true);
  });
});
