import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Report } from '@dl-sentinel/core';
import { fixturePath } from '../../../tests/support/index.js';
import { EXIT } from '../src/exit-codes.js';
import { runCli } from './helpers.js';

const VULNERABLE = fixturePath('vulnerable-app');

describe('report command', () => {
  let tmp: string;
  let savedReport: string;

  beforeAll(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'dl-sentinel-cli-report-'));
    savedReport = join(tmp, 'scan.json');
    // Produce a real saved report via `scan --format json --output`.
    const { code } = await runCli([
      'scan',
      VULNERABLE,
      '--format',
      'json',
      '--output',
      savedReport,
    ]);
    expect(code).toBe(EXIT.POLICY);
  });

  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('re-renders a saved JSON report as markdown (round-trip)', async () => {
    const { code, stdout } = await runCli(['report', savedReport, '--format', 'markdown']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toContain('# DL Sentinel Report');
  });

  it('re-renders a saved JSON report as SARIF 2.1.0', async () => {
    const { code, stdout } = await runCli(['report', savedReport, '--format', 'sarif']);
    expect(code).toBe(EXIT.OK);
    const sarif = JSON.parse(stdout) as { version: string };
    expect(sarif.version).toBe('2.1.0');
  });

  it('re-renders attack paths saved by scan --paths', async () => {
    // A report produced with --paths carries `attackPaths`; re-rendering it as
    // text must not silently drop that section.
    const withPaths = join(tmp, 'scan-paths.json');
    const scan = await runCli([
      'scan',
      VULNERABLE,
      '--paths',
      '--format',
      'json',
      '--output',
      withPaths,
    ]);
    expect(scan.code).toBe(EXIT.POLICY);
    const saved = JSON.parse(readFileSync(withPaths, 'utf8')) as Report;
    expect(saved.attackPaths?.length ?? 0).toBeGreaterThan(0);

    const terminal = await runCli(['report', withPaths, '--format', 'terminal']);
    expect(terminal.code).toBe(EXIT.OK);
    expect(terminal.stdout).toContain('Attack paths');

    const markdown = await runCli(['report', withPaths, '--format', 'markdown']);
    expect(markdown.stdout).toContain('Attack paths');
  });

  it('omits the attack-paths section for a report saved without --paths', async () => {
    const { stdout } = await runCli(['report', savedReport, '--format', 'terminal']);
    expect(stdout).not.toContain('Attack paths');
  });

  it('round-trips JSON back to an equivalent Report', async () => {
    const { stdout } = await runCli(['report', savedReport, '--format', 'json']);
    const original = JSON.parse(readFileSync(savedReport, 'utf8')) as Report;
    const rerendered = JSON.parse(stdout) as Report;
    expect(rerendered.findings.length).toBe(original.findings.length);
    expect(rerendered.stats).toEqual(original.stats);
  });

  it('writes to --output and leaves stdout empty', async () => {
    const dest = join(tmp, 'out.md');
    const { code, stdout } = await runCli([
      'report',
      savedReport,
      '--format',
      'markdown',
      '--output',
      dest,
    ]);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toBe('');
    expect(readFileSync(dest, 'utf8')).toContain('# DL Sentinel Report');
  });

  it('exits 64 when the file argument is missing', async () => {
    const { code } = await runCli(['report']);
    expect(code).toBe(EXIT.USAGE);
  });

  it('exits 64 when the file does not exist', async () => {
    const { code } = await runCli(['report', join(tmp, 'nope.json')]);
    expect(code).toBe(EXIT.USAGE);
  });

  it('exits 64 when the file is not valid JSON', async () => {
    const bad = join(tmp, 'bad.json');
    writeFileSync(bad, 'not json at all');
    const { code } = await runCli(['report', bad]);
    expect(code).toBe(EXIT.USAGE);
  });

  it('exits 64 when the JSON is not a Report', async () => {
    const notReport = join(tmp, 'wrong.json');
    writeFileSync(notReport, JSON.stringify({ hello: 'world' }));
    const { code } = await runCli(['report', notReport]);
    expect(code).toBe(EXIT.USAGE);
  });
});
