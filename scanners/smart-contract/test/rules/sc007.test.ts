import { describe, expect, it } from 'vitest';
import { sc007Mint } from '../../src/rules/sc007-mint.js';
import { parseFixture } from '../helpers.js';

describe('SC007 unprotected mint', () => {
  it('fires on an unguarded mint() function', () => {
    const relPath = 'sc007-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc007Mint.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC007',
      severity: 'high',
      confidence: 'medium',
      line: 8,
    });
  });

  it('does not fire when mint() is behind an onlyOwner modifier', () => {
    const relPath = 'sc007-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc007Mint.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
