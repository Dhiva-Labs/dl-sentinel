import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { ScanContext } from '@dl-sentinel/core';
import { noopLogger } from '@dl-sentinel/core';
import { PLANTED_SECRET_VALUES } from '../../../tests/support/index.js';
import { infraScanner } from '../src/index.js';
import { fileRef, fixturePath, scanRealFixtureApp } from './helpers.js';

describe('vulnerable-app (READ-ONLY shared fixture): expected rules fire', () => {
  it('finds exactly the expected rule set across Dockerfile, compose, k8s, and terraform', async () => {
    const findings = await scanRealFixtureApp('vulnerable-app');

    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toEqual(
      [
        'I001',
        'I002',
        'I003',
        'I004',
        'I010',
        'I011',
        'I012',
        'I014',
        'I015',
        'I020',
        'I021',
        'I022',
        'I023',
        'I024',
        'I026',
        'I027',
        'I030',
        'I031',
      ].sort(),
    );

    // Every rule id above should appear exactly once in this small fixture.
    for (const ruleId of new Set(ruleIds)) {
      expect(findings.filter((f) => f.ruleId === ruleId)).toHaveLength(1);
    }

    // Generic YAML that is neither Kubernetes nor compose (config/settings.yml,
    // openapi.yaml) must contribute nothing.
    expect(findings.some((f) => f.file.endsWith('openapi.yaml'))).toBe(false);
    expect(findings.some((f) => f.file.endsWith('config/settings.yml'))).toBe(false);
  });

  it('never leaks a planted secret value into the serialized findings', async () => {
    const findings = await scanRealFixtureApp('vulnerable-app');
    const serialized = JSON.stringify(findings);
    for (const value of PLANTED_SECRET_VALUES) {
      expect(serialized).not.toContain(value);
    }
    // Sanity: the redaction rules did actually fire on this fixture (I004 in
    // the Dockerfile, I014 in compose both carry the planted npm token), so
    // this isn't a vacuously-true check.
    expect(findings.some((f) => f.ruleId === 'I004')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'I014')).toBe(true);
  });
});

describe('clean-app (READ-ONLY shared fixture): no actionable infra findings', () => {
  it('produces no critical/high/medium/low findings', async () => {
    const findings = await scanRealFixtureApp('clean-app');
    const actionable = findings.filter((f) => f.severity !== 'info');
    expect(actionable).toEqual([]);
  });

  it('produces exactly the one known info-level gap: clean-app/docker-compose.yml has no deploy.resources.limits', async () => {
    // clean-app is owned by another branch (READ-ONLY here) and its compose
    // fixture doesn't set deploy.resources.limits, so I015 (info severity —
    // a hygiene gap, not a security risk) legitimately fires once. This is
    // asserted explicitly, rather than filtered away, so a regression that
    // introduces any *other* finding on clean-app still fails this test.
    const findings = await scanRealFixtureApp('clean-app');
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'I015',
      severity: 'info',
      file: 'docker-compose.yml',
    });
  });
});

describe('determinism', () => {
  it('produces identical findings across repeated scans of the same input', async () => {
    const first = await scanRealFixtureApp('vulnerable-app');
    const second = await scanRealFixtureApp('vulnerable-app');
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });

  it('produces output stabilized by severity (most severe first)', async () => {
    const findings = await scanRealFixtureApp('vulnerable-app');
    expect(findings.length).toBeGreaterThan(1);
    const severityRank: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };
    // Severity rank must never decrease (i.e. never go from less severe back
    // to more severe) as the array is walked — proving the scanner sorts its
    // own output rather than relying on incidental iteration order.
    for (let i = 1; i < findings.length; i++) {
      expect(severityRank[findings[i]!.severity]).toBeGreaterThanOrEqual(
        severityRank[findings[i - 1]!.severity]!,
      );
    }
  });
});

describe('cancellation', () => {
  it('rejects immediately when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const context: ScanContext = {
      rootDir: fixturePath(),
      files: [fileRef('compose/privileged/docker-compose.yml')],
      config: {},
      signal: controller.signal,
      logger: noopLogger,
      readFile: (ref) => Promise.resolve(readFileSync(ref.absPath, 'utf8')),
    };
    await expect(infraScanner.scan(context)).rejects.toThrow();
  });

  it('stops scanning further files once aborted mid-scan', async () => {
    const controller = new AbortController();
    const files = [
      fileRef('compose/privileged/docker-compose.yml'),
      fileRef('compose/host-network/docker-compose.yml'),
    ];
    let readCount = 0;
    const context: ScanContext = {
      rootDir: fixturePath(),
      files,
      config: {},
      signal: controller.signal,
      logger: noopLogger,
      readFile: (ref) => {
        readCount++;
        if (readCount === 1) controller.abort();
        return Promise.resolve(readFileSync(ref.absPath, 'utf8'));
      },
    };
    await expect(infraScanner.scan(context)).rejects.toThrow();
    expect(readCount).toBe(1);
  });
});
