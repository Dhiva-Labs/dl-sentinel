import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Report } from '@dl-sentinel/core';
import { fixturePath, PLANTED_SECRET_VALUES } from '../../../tests/support/index.js';
import { EXIT } from '../src/exit-codes.js';
import { runCli } from './helpers.js';

const VULNERABLE = fixturePath('vulnerable-app');
const CLEAN = fixturePath('clean-app');

describe('scan — exit-code matrix', () => {
  it('exits 1 on vulnerable-app with the default policy', async () => {
    const { code } = await runCli(['scan', VULNERABLE, '--format', 'json']);
    expect(code).toBe(EXIT.POLICY);
  });

  it('exits 0 on clean-app with the default policy', async () => {
    const { code } = await runCli(['scan', CLEAN, '--format', 'json']);
    expect(code).toBe(EXIT.OK);
  });

  it('--fail-on with a severity present in clean-app turns it into a violation', async () => {
    // clean-app produces only info-level findings, so --fail-on info fails.
    const { code } = await runCli(['scan', CLEAN, '--fail-on', 'info', '--format', 'json']);
    expect(code).toBe(EXIT.POLICY);
  });

  it('--fail-on with a severity absent from clean-app keeps it passing', async () => {
    const { code } = await runCli(['scan', CLEAN, '--fail-on', 'low', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
  });

  it('maps a nonexistent target to a usage error (64)', async () => {
    const { code } = await runCli(['scan', join(tmpdir(), 'dl-sentinel-does-not-exist-xyz')]);
    expect(code).toBe(EXIT.USAGE);
  });
});

describe('scan — flag validation (exit 64)', () => {
  it('rejects an invalid --format', async () => {
    const { code, stderr } = await runCli(['scan', CLEAN, '--format', 'xml']);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('Invalid --format');
  });

  it('rejects an unknown scanner id', async () => {
    const { code, stderr } = await runCli(['scan', CLEAN, '--scanners', 'nope']);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('Unknown scanner');
  });

  it('rejects an invalid severity in --fail-on', async () => {
    const { code } = await runCli(['scan', CLEAN, '--fail-on', 'sky-high']);
    expect(code).toBe(EXIT.USAGE);
  });

  it('rejects a missing --config file', async () => {
    const { code } = await runCli([
      'scan',
      CLEAN,
      '--config',
      join(tmpdir(), 'no-such-config.yml'),
    ]);
    expect(code).toBe(EXIT.USAGE);
  });
});

describe('scan — --scanners subset', () => {
  it('runs only the requested scanners', async () => {
    const { code, stdout } = await runCli([
      'scan',
      VULNERABLE,
      '--scanners',
      'secrets',
      '--format',
      'json',
    ]);
    const report = JSON.parse(stdout) as Report;
    expect(report.scannersRun).toEqual(['secrets']);
    expect(report.findings.every((finding) => finding.scanner === 'secrets')).toBe(true);
    // secrets alone still trips the default critical/high policy.
    expect(code).toBe(EXIT.POLICY);
  });
});

describe('scan — output formats', () => {
  it('--format json emits a parseable Report on stdout and nothing on stderr', async () => {
    const { stdout, stderr } = await runCli(['scan', VULNERABLE, '--format', 'json']);
    expect(stderr).toBe('');
    const report = JSON.parse(stdout) as Report;
    expect(report.tool.name).toBeTruthy();
    expect(report.tool.version).toBeTruthy();
    expect(typeof report.project).toBe('string');
    expect(typeof report.target).toBe('string');
    expect(typeof report.startedAt).toBe('string');
    expect(typeof report.finishedAt).toBe('string');
    expect(typeof report.durationMs).toBe('number');
    expect(Array.isArray(report.scannersRun)).toBe(true);
    expect(Array.isArray(report.findings)).toBe(true);
    expect(Array.isArray(report.errors)).toBe(true);
    for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
      expect(typeof report.stats[severity]).toBe('number');
    }
  });

  it('--format sarif emits a SARIF 2.1.0 document', async () => {
    const { stdout } = await runCli(['scan', VULNERABLE, '--format', 'sarif']);
    const sarif = JSON.parse(stdout) as { version: string; runs: unknown[] };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs.length).toBeGreaterThan(0);
  });

  it('--format markdown emits the report title', async () => {
    const { stdout } = await runCli(['scan', VULNERABLE, '--format', 'markdown']);
    expect(stdout).toContain('# DL Sentinel Report');
  });

  it('default terminal output carries the header and closing line', async () => {
    const { stdout } = await runCli(['scan', VULNERABLE]);
    expect(stdout).toContain('DL Sentinel v0.1.0');
    expect(stdout).toContain('Scan completed.');
  });
});

describe('scan — redaction (no planted secret leaks)', () => {
  it('never leaks a planted secret into any rendered format', async () => {
    for (const format of ['json', 'terminal', 'markdown', 'sarif'] as const) {
      const { stdout } = await runCli(['scan', VULNERABLE, '--format', format]);
      for (const secret of PLANTED_SECRET_VALUES) {
        expect(stdout, `planted secret leaked into ${format} output: ${secret}`).not.toContain(
          secret,
        );
      }
    }
  });
});

describe('scan — --output', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'dl-sentinel-cli-scan-'));
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('writes the report to a file and leaves stdout empty', async () => {
    const dest = join(tmp, 'report.json');
    const { code, stdout } = await runCli([
      'scan',
      VULNERABLE,
      '--format',
      'json',
      '--output',
      dest,
    ]);
    expect(stdout).toBe('');
    // Exit code still reflects the policy, not the write.
    expect(code).toBe(EXIT.POLICY);
    const written = JSON.parse(readFileSync(dest, 'utf8')) as Report;
    expect(written.findings.length).toBeGreaterThan(0);
  });

  it('reports a write error to an unwritable path as exit 2', async () => {
    const dest = join(tmp, 'no-such-dir', 'report.json');
    const { code, stderr } = await runCli(['scan', CLEAN, '--format', 'json', '--output', dest]);
    expect(code).toBe(EXIT.ERROR);
    expect(stderr).toContain('cannot write');
  });
});
