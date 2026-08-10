import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Baseline, Report } from '@dl-sentinel/core';
import { fixturePath } from '../../../tests/support/index.js';
import { EXIT } from '../src/exit-codes.js';
import { runCli } from './helpers.js';

const VULNERABLE = fixturePath('vulnerable-app');
const CLEAN = fixturePath('clean-app');

describe('baseline command', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'dl-sentinel-cli-baseline-'));
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('writes a baseline of the current findings and exits 0', async () => {
    const dest = join(tmp, 'baseline.json');
    const { code, stdout, stderr } = await runCli(['baseline', VULNERABLE, '--output', dest]);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toBe('');
    expect(stderr).toContain('Wrote baseline');

    const baseline = JSON.parse(readFileSync(dest, 'utf8')) as Baseline;
    expect(baseline.count).toBeGreaterThan(0);
    expect(baseline.findings.length).toBe(baseline.count);
    expect(baseline.findings.every((entry) => typeof entry.id === 'string')).toBe(true);
  });

  it('honors --scanners like scan does', async () => {
    const dest = join(tmp, 'secrets-only.json');
    const { code } = await runCli([
      'baseline',
      VULNERABLE,
      '--scanners',
      'secrets',
      '--output',
      dest,
    ]);
    expect(code).toBe(EXIT.OK);
    const baseline = JSON.parse(readFileSync(dest, 'utf8')) as Baseline;
    expect(baseline.findings.every((entry) => entry.ruleId.startsWith('S'))).toBe(true);
  });

  it('prints nothing on stderr with --quiet', async () => {
    const dest = join(tmp, 'quiet.json');
    const { code, stderr } = await runCli(['baseline', VULNERABLE, '--output', dest, '--quiet']);
    expect(code).toBe(EXIT.OK);
    expect(stderr).toBe('');
  });

  it('reports a write error to an unwritable path as exit 2', async () => {
    const dest = join(tmp, 'no-such-dir', 'baseline.json');
    const { code, stderr } = await runCli(['baseline', CLEAN, '--output', dest]);
    expect(code).toBe(EXIT.ERROR);
    expect(stderr).toContain('cannot write');
  });

  it('maps an unknown scanner id to a usage error (64)', async () => {
    const { code } = await runCli(['baseline', CLEAN, '--scanners', 'nope']);
    expect(code).toBe(EXIT.USAGE);
  });

  it('routes to help without scanning', async () => {
    const { code, stdout } = await runCli(['baseline', '--help']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toContain('Usage: sentinel baseline');
  });
});

describe('scan --baseline / --write-baseline', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'dl-sentinel-cli-baseline-apply-'));
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('round-trip: a fresh baseline makes an unchanged rescan report zero new findings and exit 0', async () => {
    const dest = join(tmp, 'roundtrip.json');
    const write = await runCli(['baseline', VULNERABLE, '--output', dest]);
    expect(write.code).toBe(EXIT.OK);

    const { code, stdout } = await runCli([
      'scan',
      VULNERABLE,
      '--baseline',
      dest,
      '--format',
      'json',
    ]);
    const report = JSON.parse(stdout) as Report;
    expect(report.findings).toEqual([]);
    expect(report.baseline?.newFindings).toBe(0);
    expect(report.baseline?.baselined).toBeGreaterThan(0);
    // No NEW findings ⇒ the policy passes even though the target is vulnerable.
    expect(code).toBe(EXIT.OK);
  });

  it('an empty baseline leaves every finding new and keeps the policy exit code', async () => {
    const empty = join(tmp, 'empty.json');
    writeFileSync(
      empty,
      JSON.stringify({
        tool: { name: 'DL Sentinel', version: '0.1.0' },
        generatedAt: '2026-01-01T00:00:00.000Z',
        target: VULNERABLE,
        count: 0,
        findings: [],
      }),
    );

    const { code, stdout } = await runCli([
      'scan',
      VULNERABLE,
      '--baseline',
      empty,
      '--format',
      'json',
    ]);
    const report = JSON.parse(stdout) as Report;
    expect(report.baseline?.baselined).toBe(0);
    expect(report.baseline?.newFindings).toBeGreaterThan(0);
    expect(report.findings.length).toBe(report.baseline?.newFindings);
    // NEW findings still trip the default critical/high policy.
    expect(code).toBe(EXIT.POLICY);
  });

  it('--write-baseline writes a baseline after reporting and still exits on policy', async () => {
    const dest = join(tmp, 'written.json');
    const { code, stderr } = await runCli([
      'scan',
      VULNERABLE,
      '--write-baseline',
      dest,
      '--format',
      'json',
    ]);
    expect(code).toBe(EXIT.POLICY);
    expect(stderr).toContain('Wrote baseline');
    const baseline = JSON.parse(readFileSync(dest, 'utf8')) as Baseline;
    expect(baseline.count).toBeGreaterThan(0);
  });

  it('--baseline and --write-baseline together regenerate: reports zero new yet records everything', async () => {
    const first = join(tmp, 'regen-first.json');
    expect((await runCli(['baseline', VULNERABLE, '--output', first])).code).toBe(EXIT.OK);

    const regen = join(tmp, 'regen-second.json');
    const { code, stdout } = await runCli([
      'scan',
      VULNERABLE,
      '--baseline',
      first,
      '--write-baseline',
      regen,
      '--format',
      'json',
    ]);
    const report = JSON.parse(stdout) as Report;
    expect(report.baseline?.newFindings).toBe(0);
    expect(code).toBe(EXIT.OK);

    // The regenerated baseline still captures the full current finding set.
    const regenerated = JSON.parse(readFileSync(regen, 'utf8')) as Baseline;
    const original = JSON.parse(readFileSync(first, 'utf8')) as Baseline;
    expect(regenerated.count).toBe(original.count);
  });

  it('rejects a malformed baseline file with exit 64 and never echoes its contents', async () => {
    const bad = join(tmp, 'bad.json');
    const secretish = 'NOTAREALSECRET_planted_marker_1234567890';
    writeFileSync(bad, `totally not json ${secretish}`);
    const { code, stderr } = await runCli(['scan', CLEAN, '--baseline', bad]);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('not valid JSON');
    expect(stderr).not.toContain(secretish);
  });

  it('rejects a JSON baseline of the wrong shape with exit 64', async () => {
    const wrong = join(tmp, 'wrong.json');
    writeFileSync(wrong, JSON.stringify({ findings: 'nope' }));
    const { code, stderr } = await runCli(['scan', CLEAN, '--baseline', wrong]);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('not a valid DL Sentinel baseline');
  });

  it('exits 64 when the baseline file does not exist', async () => {
    const { code } = await runCli(['scan', CLEAN, '--baseline', join(tmp, 'missing.json')]);
    expect(code).toBe(EXIT.USAGE);
  });
});
