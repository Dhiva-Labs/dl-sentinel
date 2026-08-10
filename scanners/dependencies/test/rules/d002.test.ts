import { describe, expect, it } from 'vitest';
import { dependenciesScanner } from '../../src/index.js';
import { contextFor, fileRef, fixturePath } from '../support.js';

describe('D002 dependency vulnerability check skipped', () => {
  it('emits exactly one info/high-confidence finding per discovered manifest file when dataSource is "none" (default)', async () => {
    const goRef = fileRef(fixturePath('go', 'well-formed', 'go.mod'), 'go.mod');
    const pipRef = fileRef(
      fixturePath('pip', 'well-formed', 'requirements.txt'),
      'requirements.txt',
    );
    const context = contextFor('/fake-root', [goRef, pipRef], { config: {} });

    const findings = await dependenciesScanner.scan(context);
    const d002 = findings.filter((f) => f.ruleId === 'D002');

    expect(d002.length).toBe(2);
    const byFile = new Map(d002.map((f) => [f.file, f]));
    expect(byFile.has('go.mod')).toBe(true);
    expect(byFile.has('requirements.txt')).toBe(true);
    for (const finding of d002) {
      expect(finding.severity).toBe('info');
      expect(finding.confidence).toBe('high');
      expect(finding.category).toBe('dependencies');
      expect(finding.recommendation).toMatch(/dataSource/);
    }

    // No data source configured: never claim a vulnerability finding, and
    // neither of these two file types participates in D003.
    expect(findings.some((f) => f.ruleId === 'D001')).toBe(false);
    expect(findings.some((f) => f.ruleId === 'D003')).toBe(false);
  });

  it('fires for a manifest with zero declared dependencies (still "discovered", still not checked)', async () => {
    const ref = fileRef(fixturePath('npm', 'empty', 'package.json'), 'package.json');
    const context = contextFor('/fake-root', [ref], { config: { dataSource: 'none' } });

    const findings = await dependenciesScanner.scan(context);
    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('D002');
  });

  it('fires even for a manifest that fails to parse — "not checked" must never silently disappear', async () => {
    const ref = fileRef(fixturePath('npm', 'malformed', 'package.json'), 'package.json');
    const context = contextFor('/fake-root', [ref], { config: {} });

    const findings = await dependenciesScanner.scan(context);
    const d002 = findings.filter((f) => f.ruleId === 'D002');
    expect(d002.length).toBe(1);
    expect(d002[0]?.file).toBe('package.json');
  });

  it('does not fire when a data source is configured', async () => {
    const ref = fileRef(fixturePath('go', 'well-formed', 'go.mod'), 'go.mod');
    const context = contextFor('/fake-root', [ref], {
      config: { dataSource: 'file', advisoryDbPath: fixturePath('advisory-db', 'valid.json') },
    });

    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D002')).toBe(false);
  });

  it('produces no findings at all when no files are discovered', async () => {
    const context = contextFor('/fake-root', [], { config: {} });
    expect(await dependenciesScanner.scan(context)).toEqual([]);
  });
});
