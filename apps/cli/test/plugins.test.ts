import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { Report } from '@dl-sentinel/core';
import { runCli } from './helpers.js';

/**
 * The engine's committed fixture plugins, loaded here through the real
 * `--plugin` path: plain ESM modules, imported by the CLI exactly as a
 * published plugin package would be.
 */
const PLUGIN_DIR = fileURLToPath(
  new URL('../../../packages/engine/test/fixtures/plugins/', import.meta.url),
);

function fixture(name: string): string {
  return path.join(PLUGIN_DIR, name);
}

const VALID = fixture('valid.mjs');

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  }
});

/** A scannable directory holding one innocuous text file the fixture reports on. */
async function scanTarget(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'dl-sentinel-cli-plugins-'));
  tempDirs.push(dir);
  await writeFile(path.join(dir, 'notes.txt'), 'nothing sensitive in here\n');
  return dir;
}

describe('sentinel rules --plugin', () => {
  it("lists a plugin's rules alongside the built-ins", async () => {
    const { code, stdout } = await runCli(['rules', '--plugin', VALID]);
    expect(code).toBe(0);
    expect(stdout).toContain('fixture-plugin');
    expect(stdout).toContain('FX001');
    // The built-ins are still there, and still first.
    expect(stdout).toContain('secrets');
    expect(stdout.indexOf('secrets')).toBeLessThan(stdout.indexOf('fixture-plugin'));
  });

  it('includes plugin rules in --format json, attributed to the plugin', async () => {
    const { code, stdout } = await runCli(['rules', '--plugin', VALID, '--format', 'json']);
    expect(code).toBe(0);
    const rows = JSON.parse(stdout) as { id: string; scanner: string; severity: string }[];
    const rule = rows.find((row) => row.id === 'FX001');
    expect(rule).toBeDefined();
    expect(rule?.scanner).toBe('fixture-plugin');
    expect(rule?.severity).toBe('high');
  });

  it('accepts a plugin id in --scanners once the plugin is loaded', async () => {
    const { code, stdout } = await runCli([
      'rules',
      '--plugin',
      VALID,
      '--scanners',
      'fixture-plugin',
      '--format',
      'json',
    ]);
    expect(code).toBe(0);
    const rows = JSON.parse(stdout) as { scanner: string }[];
    expect(rows.every((row) => row.scanner === 'fixture-plugin')).toBe(true);
  });

  it('rejects a plugin id in --scanners when the plugin was not loaded', async () => {
    const { code, stderr } = await runCli(['rules', '--scanners', 'fixture-plugin']);
    expect(code).toBe(64);
    expect(stderr).toContain('Unknown scanner');
  });
});

describe('sentinel scan --plugin', () => {
  it('runs the plugin and reports its findings under the policy', async () => {
    const target = await scanTarget();
    const { code, stdout } = await runCli(['scan', target, '--plugin', VALID, '--format', 'json']);

    const report = JSON.parse(stdout) as Report;
    expect(report.scannersRun).toContain('fixture-plugin');
    const finding = report.findings.find((entry) => entry.ruleId === 'FX001');
    expect(finding).toBeDefined();
    expect(finding?.scanner).toBe('fixture-plugin');
    expect(finding?.file).toBe('notes.txt');
    // The plugin's finding is `high`, which the default policy fails on: the
    // exit-code policy applies to plugin findings exactly as to built-in ones.
    expect(report.stats.high).toBeGreaterThanOrEqual(1);
    expect(code).toBe(1);
  });

  it('exits 0 for the same target without the plugin', async () => {
    const target = await scanTarget();
    const { code } = await runCli(['scan', target, '--format', 'json']);
    expect(code).toBe(0);
  });

  it('registers built-ins first, then plugins in flag order', async () => {
    const target = await scanTarget();
    const order = async (specs: string[]): Promise<string[]> => {
      const { stdout } = await runCli([
        'scan',
        target,
        ...specs.flatMap((spec) => ['--plugin', spec]),
        '--format',
        'json',
      ]);
      return (JSON.parse(stdout) as Report).scannersRun;
    };

    const forward = await order([VALID, fixture('valid-second.mjs')]);
    expect(forward.slice(-2)).toEqual(['fixture-plugin', 'fixture-plugin-two']);
    expect(forward[0]).toBe('secrets');

    const reversed = await order([fixture('valid-second.mjs'), VALID]);
    expect(reversed.slice(-2)).toEqual(['fixture-plugin-two', 'fixture-plugin']);
  });

  it('records the plugin in a baseline written by `sentinel baseline`', async () => {
    const target = await scanTarget();
    const output = path.join(target, 'baseline.json');
    const { code } = await runCli(['baseline', target, '--plugin', VALID, '--output', output]);
    expect(code).toBe(0);

    const { code: scanCode } = await runCli([
      'scan',
      target,
      '--plugin',
      VALID,
      '--baseline',
      output,
      '--format',
      'json',
    ]);
    // Everything the plugin found is already baselined, so nothing is new.
    expect(scanCode).toBe(0);
  });
});

describe('--plugin failures exit 64 with the loader message', () => {
  it('reports a spec that cannot be resolved', async () => {
    const { code, stdout, stderr } = await runCli(['scan', '.', '--plugin', './nope.mjs']);
    expect(code).toBe(64);
    expect(stderr).toContain('Cannot load plugin');
    expect(stderr).toContain('./nope.mjs');
    expect(stdout).toBe('');
  });

  it('reports a module with no default export', async () => {
    const { code, stderr } = await runCli(['rules', '--plugin', fixture('no-default.mjs')]);
    expect(code).toBe(64);
    expect(stderr).toContain('no default export');
  });

  it('reports a malformed plugin, naming the field', async () => {
    const { code, stderr } = await runCli(['rules', '--plugin', fixture('bad-rules.mjs')]);
    expect(code).toBe(64);
    expect(stderr).toContain('rules[0].severity');
  });

  it('refuses a plugin whose id collides with a built-in scanner', async () => {
    const { code, stderr } = await runCli([
      'scan',
      '.',
      '--plugin',
      fixture('collides-with-builtin.mjs'),
    ]);
    expect(code).toBe(64);
    expect(stderr).toContain('secrets');
    expect(stderr).toContain('built-in');
  });

  it('refuses two plugins that claim the same id', async () => {
    const { code, stderr } = await runCli([
      'rules',
      '--plugin',
      VALID,
      '--plugin',
      fixture('duplicate-id.mjs'),
    ]);
    expect(code).toBe(64);
    expect(stderr).toContain('Duplicate plugin id "fixture-plugin"');
  });

  it('reports a plugin that throws while importing, without a stack', async () => {
    const { code, stderr } = await runCli(['plugins', '--plugin', fixture('throws-on-import.mjs')]);
    expect(code).toBe(64);
    expect(stderr).toContain('fixture plugin exploded during import');
    expect(stderr).not.toMatch(/\n\s+at\s/);
  });
});

describe('sentinel plugins', () => {
  it('lists id, name, version, rule count and resolved source', async () => {
    const { code, stdout } = await runCli(['plugins', '--plugin', VALID]);
    expect(code).toBe(0);
    expect(stdout).toContain('fixture-plugin');
    expect(stdout).toContain('Fixture Plugin');
    expect(stdout).toContain('1.2.3');
    expect(stdout).toContain('1 rule');
    expect(stdout).toContain(VALID);
    expect(stdout).toContain('Loaded 1 plugin');
  });

  it('does not scan anything', async () => {
    const { stdout } = await runCli(['plugins', '--plugin', VALID]);
    expect(stdout).not.toContain('Findings');
    expect(stdout).not.toContain('FX001');
  });

  it('resolves a relative spec against the cwd it is given', async () => {
    const { code, stdout } = await runCli(['plugins', '--plugin', './valid.mjs'], {
      cwd: PLUGIN_DIR,
    });
    expect(code).toBe(0);
    expect(stdout).toContain(path.join(PLUGIN_DIR, 'valid.mjs'));
  });

  it('supports --format json', async () => {
    const { code, stdout } = await runCli([
      'plugins',
      '--plugin',
      VALID,
      '--plugin',
      fixture('scan-not-a-function.mjs'),
      '--format',
      'json',
    ]);
    // The second plugin is invalid, so the whole listing fails.
    expect(code).toBe(64);
    expect(stdout).toBe('');

    const ok = await runCli(['plugins', '--plugin', VALID, '--format', 'json']);
    expect(ok.code).toBe(0);
    const rows = JSON.parse(ok.stdout) as {
      id: string;
      name: string;
      version: string;
      rules: number;
      spec: string;
      source: string;
      categories: string[];
    }[];
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({
      id: 'fixture-plugin',
      name: 'Fixture Plugin',
      version: '1.2.3',
      categories: ['other'],
      rules: 1,
      spec: VALID,
      source: VALID,
    });
  });

  it('with no --plugin, explains where plugins come from and exits 64', async () => {
    const { code, stdout, stderr } = await runCli(['plugins']);
    expect(code).toBe(64);
    expect(stdout).toBe('');
    expect(stderr).toContain('--plugin');
    expect(stderr).toContain('sentinel.yml');
  });

  it('rejects positional arguments', async () => {
    const { code, stderr } = await runCli(['plugins', './some-plugin.mjs']);
    expect(code).toBe(64);
    expect(stderr).toContain('--plugin');
  });

  it('is listed in the top-level help and has its own help', async () => {
    const top = await runCli(['--help']);
    expect(top.stdout).toContain('plugins');

    const { code, stdout } = await runCli(['plugins', '--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('Usage: sentinel plugins');
    expect(stdout).toContain('NEVER loaded');
  });
});
