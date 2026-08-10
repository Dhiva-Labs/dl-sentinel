import { describe, expect, it } from 'vitest';
import type { Finding, Severity } from '@dl-sentinel/core';
import { computeStats, createFinding } from '@dl-sentinel/core';
import { PLANTED_SECRET_VALUES, fixturePath } from '../../../tests/support/index.js';
import { scanTarget } from '../src/scan.js';
import { COMMENT_MARKER, buildSummary } from '../src/summary.js';
import { defaultActionConfig } from './support.js';

function makeFinding(severity: Severity, ruleId: string, file: string, line: number): Finding {
  return createFinding({
    ruleId,
    title: `${ruleId} title`,
    description: 'desc',
    severity,
    confidence: 'high',
    category: 'secrets',
    file,
    line,
    evidence: '[REDACTED]',
    recommendation: 'fix it',
    references: [],
    scanner: 'secrets',
  });
}

describe('buildSummary', () => {
  const findings = [
    makeFinding('critical', 'S001', 'app/.env', 3),
    makeFinding('high', 'C010', 'src/a.js', 12),
  ];
  const stats = computeStats(findings);

  it('includes the hidden marker, a heading, and the severity counts', () => {
    const body = buildSummary({
      newFindings: findings,
      stats,
      totalFindings: 5,
      baselined: 3,
      baselineApplied: true,
      failOn: ['critical', 'high'],
      failed: true,
    });
    expect(body.startsWith(COMMENT_MARKER)).toBe(true);
    expect(body).toContain('## DL Sentinel — 2 new findings');
    expect(body).toContain('| Critical | 1 |');
    expect(body).toContain('| High | 1 |');
    // Top-findings list renders file:line and rule id.
    expect(body).toContain('`S001` app/.env:3');
    expect(body).toContain('`C010` src/a.js:12');
    // Baseline context and the redaction note are present.
    expect(body).toContain('3 pre-existing findings hidden');
    expect(body).toContain('Evidence is redacted and never posted');
    expect(body).toContain('Status: **failing**');
  });

  it('reports a clean PR when there are no new findings', () => {
    const body = buildSummary({
      newFindings: [],
      stats: computeStats([]),
      totalFindings: 0,
      baselined: 0,
      baselineApplied: false,
      failOn: ['critical', 'high'],
      failed: false,
    });
    expect(body).toContain('introduces no new findings');
    expect(body).not.toContain('### Top');
  });

  it('caps the detail list and notes how many more there are', () => {
    const many = Array.from({ length: 15 }, (_, i) =>
      makeFinding('high', `C${String(i).padStart(3, '0')}`, `src/f${i}.js`, i + 1),
    );
    const body = buildSummary({
      newFindings: many,
      stats: computeStats(many),
      totalFindings: 15,
      baselined: 0,
      baselineApplied: false,
      failOn: ['critical', 'high'],
      failed: true,
      topN: 10,
    });
    expect(body).toContain('### Top 10 new findings');
    expect(body).toContain('…and 5 more.');
  });

  it('never contains a planted secret when summarizing a real scan', async () => {
    const report = await scanTarget({
      target: fixturePath('vulnerable-app'),
      config: defaultActionConfig(),
    });
    const body = buildSummary({
      newFindings: report.findings,
      stats: report.stats,
      totalFindings: report.findings.length,
      baselined: 0,
      baselineApplied: false,
      failOn: ['critical', 'high'],
      failed: true,
    });
    for (const secret of PLANTED_SECRET_VALUES) {
      expect(body, `planted secret leaked into summary: ${secret}`).not.toContain(secret);
    }
  });
});
