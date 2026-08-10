import { describe, expect, it } from 'vitest';
import { sc006Initializer } from '../../src/rules/sc006-initializer.js';
import { parseFixture } from '../helpers.js';

describe('SC006 unprotected initializer', () => {
  it('fires on an unguarded initialize() function', () => {
    const relPath = 'sc006-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc006Initializer.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC006',
      severity: 'high',
      confidence: 'medium',
      line: 9,
    });
  });

  it('does not fire when initialize() is behind an onlyOwner modifier', () => {
    const relPath = 'sc006-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc006Initializer.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
