import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Report } from '@dl-sentinel/core';
import { fixturePath, PLANTED_SECRET_VALUES } from '../support/index.js';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const CLI_ENTRY = join(REPO_ROOT, 'apps/cli/dist/main.js');
const cliReady = existsSync(CLI_ENTRY);

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): CliResult {
  const result = spawnSync(process.execPath, [CLI_ENTRY, ...args], {
    encoding: 'utf8',
    timeout: 20000,
  });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

// Gated the same way as engine.integration.test.ts: `npm run build` must
// have produced the CLI's binary entry point (apps/cli/dist/main.js, per
// apps/cli/package.json's "bin") before any of this can run for real.
describe.skipIf(!cliReady)('cli e2e (apps/cli/dist/main.js)', () => {
  it('exits 1 (policy violation) scanning vulnerable-app with the default policy', () => {
    const { status } = runCli(['scan', fixturePath('vulnerable-app')]);
    expect(status).toBe(1);
  });

  it('exits 0 scanning clean-app with the default policy', () => {
    const { status } = runCli(['scan', fixturePath('clean-app')]);
    expect(status).toBe(0);
  });

  it('--format json parses to a valid Report shape', () => {
    const { status, stdout } = runCli(['scan', fixturePath('vulnerable-app'), '--format', 'json']);
    expect(status).toBe(1);

    const report = JSON.parse(stdout) as Report;
    expect(report.tool?.name).toBeTruthy();
    expect(report.tool?.version).toBeTruthy();
    expect(typeof report.project).toBe('string');
    expect(typeof report.target).toBe('string');
    expect(typeof report.startedAt).toBe('string');
    expect(typeof report.finishedAt).toBe('string');
    expect(typeof report.durationMs).toBe('number');
    expect(Array.isArray(report.scannersRun)).toBe(true);
    expect(Array.isArray(report.findings)).toBe(true);
    expect(Array.isArray(report.errors)).toBe(true);
    expect(typeof report.stats.critical).toBe('number');
    expect(typeof report.stats.high).toBe('number');
    expect(typeof report.stats.medium).toBe('number');
    expect(typeof report.stats.low).toBe('number');
    expect(typeof report.stats.info).toBe('number');
  });

  it('--format sarif produces a SARIF 2.1.0 document', () => {
    const { status, stdout } = runCli(['scan', fixturePath('vulnerable-app'), '--format', 'sarif']);
    expect(status).toBe(1);

    const sarif = JSON.parse(stdout) as { version: string; runs: unknown[] };
    expect(sarif.version).toBe('2.1.0');
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs.length).toBeGreaterThan(0);
  });

  it('never leaks a planted secret value into json scan output', () => {
    const { stdout } = runCli(['scan', fixturePath('vulnerable-app'), '--format', 'json']);
    for (const secret of PLANTED_SECRET_VALUES) {
      expect(stdout, `planted secret leaked into CLI json output: ${secret}`).not.toContain(secret);
    }
  });

  it('sentinel version exits 0 and prints something', () => {
    const { status, stdout } = runCli(['version']);
    expect(status).toBe(0);
    expect(stdout.trim().length).toBeGreaterThan(0);
  });
});
