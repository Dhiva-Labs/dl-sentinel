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

  it('does not fire on the OpenZeppelin `initializer` modifier imported from another file', () => {
    // The gap the original name-only heuristic could not close: the modifier
    // is declared outside this file, so guards.ts assumes it protects rather
    // than reporting a correctly-guarded upgradeable contract.
    const relPath = 'sc006-negative-imported-initializer.sol';
    const file = parseFixture(relPath);
    expect(sc006Initializer.evaluate({ relPath, file })).toHaveLength(0);
  });
});
