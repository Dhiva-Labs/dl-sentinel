import { describe, expect, it } from 'vitest';
import { BUILTIN_SCANNERS } from '@dl-sentinel/preset';
import { EXIT } from '../src/exit-codes.js';
import { runCli } from './helpers.js';

const TOTAL_RULES = BUILTIN_SCANNERS.reduce((sum, scanner) => sum + scanner.rules.length, 0);
const SECRETS_RULES = BUILTIN_SCANNERS.find((s) => s.id === 'secrets')?.rules.length ?? 0;

interface RuleRow {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  category: string;
  scanner: string;
}

describe('rules command', () => {
  it('lists every rule as JSON with the documented shape', async () => {
    const { code, stdout } = await runCli(['rules', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    const rows = JSON.parse(stdout) as RuleRow[];
    expect(rows).toHaveLength(TOTAL_RULES);
    const first = rows[0];
    expect(first).toBeDefined();
    expect(Object.keys(first ?? {}).sort()).toEqual([
      'category',
      'confidence',
      'id',
      'scanner',
      'severity',
      'title',
    ]);
    // Rule ids are namespaced and every row is attributed to a scanner.
    for (const row of rows) {
      expect(row.id).toMatch(/^(S|D|C|I|A|SC)\d+$/);
      expect(row.scanner.length).toBeGreaterThan(0);
    }
  });

  it('filters to a scanner subset', async () => {
    const { code, stdout } = await runCli(['rules', '--scanners', 'secrets', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    const rows = JSON.parse(stdout) as RuleRow[];
    expect(rows).toHaveLength(SECRETS_RULES);
    expect(rows.every((row) => row.scanner === 'secrets')).toBe(true);
  });

  it('renders a grouped table by default', async () => {
    const { code, stdout } = await runCli(['rules']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toContain('secrets');
    expect(stdout).toContain('S001');
    expect(stdout).toContain(`Total: ${TOTAL_RULES} rules`);
  });

  it('rejects an unknown scanner id with exit 64', async () => {
    const { code } = await runCli(['rules', '--scanners', 'nope']);
    expect(code).toBe(EXIT.USAGE);
  });

  it('rejects a format it does not support (sarif) with exit 64', async () => {
    const { code } = await runCli(['rules', '--format', 'sarif']);
    expect(code).toBe(EXIT.USAGE);
  });

  it('rejects stray positional arguments with exit 64', async () => {
    const { code } = await runCli(['rules', 'extra']);
    expect(code).toBe(EXIT.USAGE);
  });
});
