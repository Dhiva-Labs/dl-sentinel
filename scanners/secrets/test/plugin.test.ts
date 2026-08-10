import { describe, expect, it } from 'vitest';
import secretsDefault, {
  RULE_IDS,
  secretsRules,
  secretsScanner,
} from '@dl-sentinel/scanner-secrets';

describe('plugin contract', () => {
  it('is the package default export, and the named export is the same object', () => {
    expect(secretsDefault).toBe(secretsScanner);
  });

  it('declares the identity the engine and config key rely on', () => {
    expect(secretsScanner.id).toBe('secrets');
    expect(secretsScanner.name).toBe('Secrets Scanner');
    expect(secretsScanner.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(secretsScanner.categories).toEqual(['secrets']);
    // Secrets appear in any text file, so the scanner opts into all of them.
    expect(secretsScanner.supportedFiles).toEqual([]);
    expect(typeof secretsScanner.scan).toBe('function');
  });
});

describe('declared rules', () => {
  it('uses zero-padded S-namespaced ids with no gaps or duplicates', () => {
    const ids = secretsRules.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^S\d{3}$/);
    const expected = ids.map((_id, index) => `S${String(index + 1).padStart(3, '0')}`);
    expect([...ids].sort()).toEqual(expected);
  });

  it('exposes the same ids through RULE_IDS', () => {
    expect([...Object.values(RULE_IDS)].sort()).toEqual(secretsRules.map((rule) => rule.id).sort());
  });

  it('fills in every field reports and the rules command render', () => {
    for (const rule of secretsRules) {
      expect(rule.category).toBe('secrets');
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.description.length).toBeGreaterThan(20);
      expect(rule.recommendation.length).toBeGreaterThan(20);
      expect(Array.isArray(rule.references)).toBe(true);
      expect(rule.references?.length ?? 0).toBeGreaterThan(0);
    }
  });

  it('avoids low-confidence rules, which would flood reports', () => {
    for (const rule of secretsRules) {
      expect(rule.defaultConfidence).not.toBe('low');
    }
  });

  it('reserves critical severity for credentials that are usable as found', () => {
    const bySeverity = new Map(secretsRules.map((rule) => [rule.id, rule.severity]));
    expect(bySeverity.get(RULE_IDS.stripeLiveKey)).toBe('critical');
    // A test-mode key cannot move money, so it is deliberately not critical.
    expect(bySeverity.get(RULE_IDS.stripeTestKey)).toBe('medium');
    // Committed JWTs are usually documentation samples.
    expect(bySeverity.get(RULE_IDS.jsonWebToken)).toBe('medium');
    expect(bySeverity.get(RULE_IDS.basicAuthUrl)).toBe('high');
  });
});
