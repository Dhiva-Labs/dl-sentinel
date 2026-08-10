import { describe, expect, it } from 'vitest';
import type { Report } from '@dl-sentinel/core';
import { computeStats, createFinding } from '@dl-sentinel/core';
import {
  renderJson,
  renderMarkdown,
  renderReport,
  renderSarif,
  renderTerminal,
} from '../src/index.js';

function sampleReport(): Report {
  const findings = [
    createFinding({
      ruleId: 'S001',
      title: 'Hardcoded credential detected',
      description: 'A credential-like value was detected.',
      severity: 'critical',
      confidence: 'high',
      category: 'secrets',
      file: 'config/app.env',
      line: 14,
      evidence: 'API_KEY=[REDACTED]',
      recommendation: 'Move the credential to a secret store.',
      references: ['https://owasp.org/'],
      scanner: 'secrets',
    }),
    createFinding({
      ruleId: 'C003',
      title: 'Disabled TLS verification',
      description: 'TLS certificate verification is turned off.',
      severity: 'medium',
      confidence: 'medium',
      category: 'source',
      file: 'src/http.ts',
      line: 3,
      evidence: 'rejectUnauthorized: false',
      recommendation: 'Enable certificate verification.',
      references: [],
      scanner: 'source',
    }),
  ];
  return {
    tool: { name: 'DL Sentinel', version: '0.1.0' },
    project: 'sample',
    target: '/tmp/sample',
    startedAt: '2026-08-10T10:00:00.000Z',
    finishedAt: '2026-08-10T10:00:01.500Z',
    durationMs: 1500,
    scannersRun: ['secrets', 'source', 'docker'],
    stats: computeStats(findings),
    findings,
    errors: [{ scanner: 'docker', message: 'parse failure in Dockerfile' }],
  };
}

describe('renderJson', () => {
  it('round-trips the report', () => {
    const parsed = JSON.parse(renderJson(sampleReport())) as Report;
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.stats.critical).toBe(1);
    expect(parsed.errors[0]?.scanner).toBe('docker');
  });
});

describe('renderTerminal', () => {
  it('shows tool name, per-scanner counts, severity summary, and errors', () => {
    const out = renderTerminal(sampleReport());
    expect(out).toContain('DL Sentinel v0.1.0');
    expect(out).toContain('Scanning: /tmp/sample');
    expect(out).toMatch(/secrets\s+1 finding/);
    expect(out).toMatch(/docker\s+0 findings/);
    expect(out).toContain('Critical: 1');
    expect(out).toContain('Medium:   1');
    expect(out).toContain('docker: parse failure in Dockerfile');
    expect(out).toContain('Scan completed.');
  });
});

describe('renderMarkdown', () => {
  it('includes summary table and findings ordered by severity', () => {
    const out = renderMarkdown(sampleReport());
    expect(out).toContain('# DL Sentinel Report');
    expect(out).toContain('| Critical | 1 |');
    expect(out.indexOf('S001')).toBeLessThan(out.indexOf('C003'));
    expect(out).toContain('`config/app.env:14`');
    expect(out).toContain('## Scanner Errors');
  });
});

describe('renderSarif', () => {
  it('produces valid SARIF 2.1.0 structure with level mapping', () => {
    const out = renderSarif(sampleReport());
    const sarif = JSON.parse(out) as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string; rules: Array<{ id: string }> } };
        results: Array<{ ruleId: string; level: string }>;
      }>;
    };
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run?.tool.driver.name).toBe('DL Sentinel');
    expect(run?.tool.driver.rules.map((r) => r.id)).toEqual(['S001', 'C003']);
    expect(run?.results.find((r) => r.ruleId === 'S001')?.level).toBe('error');
    expect(run?.results.find((r) => r.ruleId === 'C003')?.level).toBe('warning');
  });
});

describe('renderReport', () => {
  it('dispatches each format', () => {
    const report = sampleReport();
    expect(renderReport(report, 'json')).toBe(renderJson(report));
    expect(renderReport(report, 'terminal')).toBe(renderTerminal(report));
    expect(renderReport(report, 'markdown')).toBe(renderMarkdown(report));
    expect(renderReport(report, 'sarif')).toBe(renderSarif(report));
  });
});
