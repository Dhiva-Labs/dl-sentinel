import { describe, expect, it } from 'vitest';
import { scanFixtures } from './helpers.js';
import { fixtureFile, RULE_CASES } from './rule-cases.js';

describe.each(RULE_CASES)('$ruleId ($dir)', (rule) => {
  const positive = fixtureFile(rule, 'positive');
  const negative = fixtureFile(rule, 'negative');

  it('reports the planted credential on every expected line', async () => {
    const findings = await scanFixtures([positive]);
    const own = findings.filter((finding) => finding.ruleId === rule.ruleId);

    expect(own.map((finding) => finding.line)).toEqual(rule.lines);
    for (const finding of own) {
      expect(finding.file).toBe(positive);
      expect(finding.severity).toBe(rule.severity);
      expect(finding.confidence).toBe(rule.confidence);
      expect(finding.category).toBe('secrets');
      expect(finding.scanner).toBe('secrets');
      if (rule.evidenceMarker !== false) {
        expect(finding.evidence).toContain('[REDACTED]');
      }
      expect(finding.evidence.length).toBeLessThanOrEqual(200);
      expect(finding.column ?? 0).toBeGreaterThan(0);
    }
  });

  it('reports nothing else in the positive fixture', async () => {
    const findings = await scanFixtures([positive]);
    expect([...new Set(findings.map((finding) => finding.ruleId))]).toEqual([rule.ruleId]);
  });

  it('never leaks a planted value into the findings', async () => {
    const findings = await scanFixtures([positive]);
    const serialized = JSON.stringify(findings);
    for (const secret of rule.secrets) {
      expect(serialized, `${rule.ruleId} leaked ${secret.slice(0, 6)}…`).not.toContain(secret);
    }
  });

  it('stays silent on the look-alike negative fixture', async () => {
    const findings = await scanFixtures([negative]);
    expect(findings).toEqual([]);
  });
});

describe('rule coverage', () => {
  it('exercises every rule the scanner declares', async () => {
    const { secretsRules } = await import('@dl-sentinel/scanner-secrets');
    const declared = secretsRules.map((rule) => rule.id).sort();
    const covered = RULE_CASES.map((rule) => rule.ruleId).sort();
    expect(covered).toEqual(declared);
  });

  it('agrees with each rule’s declared severity and confidence', async () => {
    const { secretsRules } = await import('@dl-sentinel/scanner-secrets');
    for (const rule of RULE_CASES) {
      const declared = secretsRules.find((meta) => meta.id === rule.ruleId);
      expect(declared, `rule ${rule.ruleId} is not declared`).toBeDefined();
      expect(declared?.severity).toBe(rule.severity);
      expect(declared?.defaultConfidence).toBe(rule.confidence);
    }
  });
});
