import { describe, expect, it } from 'vitest';
import { sc011Deprecated } from '../../src/rules/sc011-deprecated.js';
import { parseFixture } from '../helpers.js';

describe('SC011 deprecated constructs', () => {
  it('fires once per deprecated construct: sha3, var, throw, suicide, callcode', () => {
    const relPath = 'sc011-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc011Deprecated.evaluate({ relPath, file });
    expect(findings).toHaveLength(5);
    for (const f of findings) {
      expect(f).toMatchObject({ ruleId: 'SC011', severity: 'low', confidence: 'high' });
    }
    const constructs = findings.map((f) => f.metadata?.construct);
    expect(constructs).toEqual([
      'sha3(...)',
      'var declaration',
      'throw;',
      'suicide(...)',
      'callcode(...)',
    ]);
    expect(findings.map((f) => f.line)).toEqual([7, 11, 17, 22, 26]);
  });

  it('does not fire on the modern equivalents', () => {
    const relPath = 'sc011-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc011Deprecated.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
