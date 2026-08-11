/**
 * `sentinel scan --paths` against the fixture apps.
 *
 * Assertions are by `AP` id presence, never by exact counts: the catalog's
 * output on a fixture is allowed to grow as rules are added, but the classes of
 * chain the vulnerable fixture demonstrates must keep appearing, and the clean
 * fixture must keep producing none.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import type { AttackPath, Report } from '@dl-sentinel/core';
import { fixturePath } from '../../../tests/support/index.js';
import { EXIT } from '../src/exit-codes.js';
import { runCli, type CaptureResult } from './helpers.js';

const VULNERABLE = fixturePath('vulnerable-app');
const CLEAN = fixturePath('clean-app');

/** The `AP00x` correlation ids present in a set of paths. */
function correlationIds(paths: readonly AttackPath[]): Set<string> {
  return new Set(paths.map((path) => path.id.split(':')[0] ?? path.id));
}

describe('scan --paths — vulnerable-app terminal output', () => {
  let result: CaptureResult;
  beforeAll(async () => {
    result = await runCli(['scan', VULNERABLE, '--paths', '--quiet']);
  });

  it('renders an Attack paths section after the findings summary', () => {
    expect(result.stdout).toContain('Scan completed.');
    expect(result.stdout).toContain('Attack paths (');
    expect(result.stdout.indexOf('Attack paths (')).toBeGreaterThan(
      result.stdout.indexOf('Scan completed.'),
    );
    expect(result.stdout).toContain('DL Sentinel does not verify exploitability.');
  });

  it('shows the chain classes this fixture demonstrates', () => {
    for (const id of ['AP001', 'AP002', 'AP004']) {
      expect(result.stdout).toContain(id);
    }
  });

  it('numbers the steps with file:line references', () => {
    expect(result.stdout).toMatch(/1\. entry\s+I\d{3}\s+docker-compose\.yml:\d+/);
    expect(result.stdout).toMatch(/2\. escalation\s+I\d{3}\s+docker-compose\.yml:\d+/);
  });

  it('states severity, confidence, and a "could allow" narrative', () => {
    expect(result.stdout).toMatch(/AP001\s+critical\s+likely/);
    expect(result.stdout).toContain('could allow');
    expect(result.stdout).not.toContain('exploitable');
  });

  it('leaves the exit code exactly where the policy put it', () => {
    expect(result.code).toBe(EXIT.POLICY);
  });
});

describe('scan --paths — json output', () => {
  it('carries attackPaths on the report object', async () => {
    const { code, stdout } = await runCli([
      'scan',
      VULNERABLE,
      '--paths',
      '--quiet',
      '--format',
      'json',
    ]);
    expect(code).toBe(EXIT.POLICY);

    const report = JSON.parse(stdout) as Report;
    const paths = report.attackPaths ?? [];
    expect(Array.isArray(report.attackPaths)).toBe(true);
    expect(paths.length).toBeGreaterThan(0);

    const ids = correlationIds(paths);
    for (const id of ['AP001', 'AP002', 'AP004']) {
      expect(ids.has(id)).toBe(true);
    }

    const findingIds = new Set(report.findings.map((item) => item.id));
    for (const path of paths) {
      expect(path.id).toMatch(/^AP\d{3}:[0-9a-f]{16}$/);
      expect(path.confidence).not.toBe('high');
      expect(path.narrative.toLowerCase()).toContain('could allow');
      expect(path.steps.length).toBeGreaterThan(0);
      for (const step of path.steps) {
        // Every step must point at a finding the report actually reports.
        expect(findingIds.has(step.findingId)).toBe(true);
      }
    }
  });

  it('omits attackPaths entirely without --paths', async () => {
    const { stdout } = await runCli(['scan', VULNERABLE, '--quiet', '--format', 'json']);
    const report = JSON.parse(stdout) as Report;
    expect(report.attackPaths).toBeUndefined();
  });
});

describe('scan --paths — markdown output', () => {
  it('adds an equivalent section with a step table', async () => {
    const { stdout } = await runCli([
      'scan',
      VULNERABLE,
      '--paths',
      '--quiet',
      '--format',
      'markdown',
    ]);
    expect(stdout).toContain('## Attack paths');
    expect(stdout).toContain('| # | Role | Rule | Location | Note |');
    expect(stdout).toMatch(/### CRITICAL AP00\d — /);
    expect(stdout).toContain('- **Confidence:** likely');
  });
});

describe('scan --paths — sarif output is unchanged', () => {
  it('produces the same document with and without --paths', async () => {
    const withFlag = await runCli(['scan', VULNERABLE, '--paths', '--quiet', '--format', 'sarif']);
    const without = await runCli(['scan', VULNERABLE, '--quiet', '--format', 'sarif']);
    expect(withFlag.code).toBe(without.code);
    expect(withFlag.stdout).toBe(without.stdout);
  });
});

describe('scan --paths — clean-app', () => {
  it('reports no candidates, renders no section, and still exits 0', async () => {
    const { code, stdout, stderr } = await runCli(['scan', CLEAN, '--paths', '--quiet']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).not.toContain('Attack paths');
    expect(stdout).toContain('Scan completed.');
    // --quiet suppresses the informational stderr note as well.
    expect(stderr).toBe('');
  });

  it('notes the empty result on stderr when not quiet', async () => {
    const { stderr } = await runCli(['scan', CLEAN, '--paths']);
    expect(stderr).toContain('No attack-path candidates found.');
  });

  it('serializes an empty attackPaths array in json', async () => {
    const { stdout } = await runCli(['scan', CLEAN, '--paths', '--quiet', '--format', 'json']);
    const report = JSON.parse(stdout) as Report;
    expect(report.attackPaths).toEqual([]);
  });
});

describe('scan --paths — exit codes are unaffected', () => {
  it('matches the exit code of the same scan without --paths', async () => {
    const vulnerable = await runCli(['scan', VULNERABLE, '--quiet']);
    const vulnerableWithPaths = await runCli(['scan', VULNERABLE, '--paths', '--quiet']);
    const clean = await runCli(['scan', CLEAN, '--quiet']);
    const cleanWithPaths = await runCli(['scan', CLEAN, '--paths', '--quiet']);

    expect(vulnerable.code).toBe(EXIT.POLICY);
    expect(vulnerableWithPaths.code).toBe(EXIT.POLICY);
    expect(clean.code).toBe(EXIT.OK);
    expect(cleanWithPaths.code).toBe(EXIT.OK);
  });
});

describe('scan --paths — flag handling', () => {
  it('is documented in scan --help', async () => {
    const { stdout } = await runCli(['scan', '--help']);
    expect(stdout).toContain('--paths');
    expect(stdout).toContain('docs/attack-paths.md');
  });

  it('rejects a value given to the boolean flag', async () => {
    const { code, stderr } = await runCli(['scan', CLEAN, '--paths=yes']);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('does not take a value');
  });
});
