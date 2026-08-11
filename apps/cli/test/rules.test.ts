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
  compliance?: { cwe?: string[]; owasp?: string[] };
}

describe('rules command', () => {
  it('lists every rule as JSON with the documented shape', async () => {
    const { code, stdout } = await runCli(['rules', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    const rows = JSON.parse(stdout) as RuleRow[];
    expect(rows).toHaveLength(TOTAL_RULES);
    const first = rows[0];
    expect(first).toBeDefined();
    // S001 (the first secrets rule) carries a compliance mapping, so it is
    // present on the very first row.
    expect(Object.keys(first ?? {}).sort()).toEqual([
      'category',
      'compliance',
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

describe('compliance mapping', () => {
  it('json format carries the compliance object verbatim for a mapped rule', async () => {
    const { code, stdout } = await runCli(['rules', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    const rows = JSON.parse(stdout) as RuleRow[];
    const s001 = rows.find((row) => row.id === 'S001');
    expect(s001).toBeDefined();
    expect(s001?.compliance).toEqual({ cwe: ['CWE-798'], owasp: ['A07:2021'] });
  });

  it('json format omits the compliance key for a rule with no canonical mapping', async () => {
    const { code, stdout } = await runCli(['rules', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    const rows = JSON.parse(stdout) as RuleRow[];
    // D002 ("dependency vulnerability check skipped") is an informational
    // rule about scanner configuration, not a target weakness -- it
    // deliberately carries no CWE/OWASP mapping.
    const d002 = rows.find((row) => row.id === 'D002');
    expect(d002).toBeDefined();
    expect(d002).not.toHaveProperty('compliance');
  });

  it('at least one rule from every built-in scanner carries a compliance mapping', async () => {
    const { code, stdout } = await runCli(['rules', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    const rows = JSON.parse(stdout) as RuleRow[];
    for (const scanner of BUILTIN_SCANNERS) {
      const mapped = rows.filter((row) => row.scanner === scanner.id && row.compliance);
      expect(mapped.length).toBeGreaterThan(0);
    }
  });

  it('terminal output appends compliance ids to a mapped rule line', async () => {
    const { code, stdout } = await runCli(['rules']);
    expect(code).toBe(EXIT.OK);
    const line = stdout.split('\n').find((l) => l.trim().startsWith('S001'));
    expect(line).toBeDefined();
    expect(line).toContain('CWE-798');
    expect(line).toContain('A07:2021');
  });

  it('terminal output omits the compliance segment for an unmapped rule line', async () => {
    const { code, stdout } = await runCli(['rules']);
    expect(code).toBe(EXIT.OK);
    const line = stdout.split('\n').find((l) => l.trim().startsWith('D002'));
    expect(line).toBeDefined();
    expect(line).not.toContain('CWE-');
    expect(line).not.toMatch(/A\d{2}:2021/);
  });
});
