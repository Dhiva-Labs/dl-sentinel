import { describe, expect, it } from 'vitest';
import { sc008UncheckedArithmetic } from '../../src/rules/sc008-unchecked-arithmetic.js';
import { parseFixture } from '../helpers.js';

describe('SC008 pre-0.8 unchecked arithmetic', () => {
  it('fires once for a pre-0.8 contract with raw arithmetic on state, no SafeMath', () => {
    const relPath = 'sc008-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc008UncheckedArithmetic.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC008',
      severity: 'medium',
      confidence: 'low',
      line: 9,
    });
  });

  it('does not fire when SafeMath is used, even pre-0.8', () => {
    const relPath = 'sc008-negative-safemath.sol';
    const file = parseFixture(relPath);
    const findings = sc008UncheckedArithmetic.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });

  it('does not fire on the same raw-arithmetic shape when pragma is pinned to 0.8+', () => {
    const relPath = 'sc008-negative-pinned08.sol';
    const file = parseFixture(relPath);
    const findings = sc008UncheckedArithmetic.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
