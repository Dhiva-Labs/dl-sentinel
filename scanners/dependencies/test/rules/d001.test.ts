import { describe, expect, it } from 'vitest';
import { dependenciesScanner } from '../../src/index.js';
import { contextFor, fileRef, fixturePath } from '../support.js';

const ADVISORY_DB = fixturePath('advisory-db', 'valid.json');

function configFor(dbPath: string): Record<string, unknown> {
  return { dataSource: 'file', advisoryDbPath: dbPath };
}

describe('D001 known-vulnerable dependency', () => {
  it('flags an exact lockfile version inside an advisory window at high confidence, and leaves an out-of-range version alone', async () => {
    const dir = fixturePath('rules', 'd001');
    const lockRef = fileRef(`${dir}/package-lock.json`, 'package-lock.json');
    const context = contextFor(dir, [lockRef], { config: configFor(ADVISORY_DB) });

    const findings = await dependenciesScanner.scan(context);
    const d001 = findings.filter((f) => f.ruleId === 'D001');

    // dl-fixture-vulnpkg@1.5.0 (direct, top-level) is NOT flagged: 1.5.0 is
    // past TEST-0001's fixed version (1.3.0).
    expect(d001.some((f) => f.evidence.startsWith('dl-fixture-vulnpkg@1.5.0'))).toBe(false);

    // dl-fixture-vulnpkg@1.1.0 (nested, transitive) IS inside [1.0.0, 1.3.0).
    const transitive = d001.find((f) => f.evidence.startsWith('dl-fixture-vulnpkg@1.1.0'));
    expect(transitive).toBeDefined();
    expect(transitive?.severity).toBe('medium'); // TEST-0001's declared severity
    expect(transitive?.confidence).toBe('high'); // exact, locked version
    expect(transitive?.metadata).toEqual({ direct: false });
    expect(transitive?.recommendation).toContain('1.3.0');
    expect(transitive?.references).toEqual(['https://example.invalid/advisories/TEST-0001']);

    // lodash@4.17.15 (direct) matches BOTH real lodash advisories in the db —
    // two distinct findings, not deduplicated away.
    const lodashFindings = d001.filter((f) => f.evidence.startsWith('lodash@4.17.15'));
    expect(lodashFindings.length).toBe(2);
    const lodashIds = lodashFindings.map((f) => f.evidence.match(/\(([^)]+)\)/)?.[1]).sort();
    expect(lodashIds).toEqual(['GHSA-35jh-r3h4-6jhm', 'GHSA-p6mc-m468-83gw']);
    for (const finding of lodashFindings) {
      expect(finding.confidence).toBe('high');
      expect(finding.severity).toBe('high');
      expect(finding.metadata).toEqual({ direct: true });
    }
    // Distinct advisories on the same package/file/line must fingerprint distinctly.
    expect(lodashFindings[0]?.id).not.toBe(lodashFindings[1]?.id);

    expect(d001.length).toBe(3);
  });

  it('flags a declared range only when it overlaps an advisory window, at medium confidence', async () => {
    const dir = fixturePath('npm', 'well-formed');
    const manifestRef = fileRef(`${dir}/package.json`, 'package.json');
    const context = contextFor(dir, [manifestRef], { config: configFor(ADVISORY_DB) });

    const findings = await dependenciesScanner.scan(context);
    const d001 = findings.filter((f) => f.ruleId === 'D001');

    // Only dl-fixture-vulnpkg ("^1.2.0") has any advisory in the db at all;
    // left-pad and dl-fixture-devpkg have none, so neither can ever fire.
    expect(d001.length).toBe(1);
    const finding = d001[0];
    expect(finding?.evidence).toBe('dl-fixture-vulnpkg@^1.2.0 (TEST-0001)');
    expect(finding?.confidence).toBe('medium'); // declared range, not a lockfile-exact version
    expect(finding?.severity).toBe('medium');
    expect(finding?.metadata).toEqual({ direct: true });
    expect(finding?.description).toContain('dl-fixture-vulnpkg');
    expect(finding?.description).toContain('TEST-0001');
  });

  it('never fires when dataSource is "none", regardless of what the advisory db would say', async () => {
    const dir = fixturePath('rules', 'd001');
    const lockRef = fileRef(`${dir}/package-lock.json`, 'package-lock.json');
    const context = contextFor(dir, [lockRef], { config: { dataSource: 'none' } });

    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D001')).toBe(false);
  });
});
