import { describe, expect, it } from 'vitest';
import { sc005Selfdestruct } from '../../src/rules/sc005-selfdestruct.js';
import { parseFixture } from '../helpers.js';

describe('SC005 unprotected selfdestruct', () => {
  it('fires when selfdestruct is reachable with no guard', () => {
    const relPath = 'sc005-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc005Selfdestruct.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC005',
      severity: 'critical',
      confidence: 'medium',
      line: 7,
    });
  });

  it('does not fire when selfdestruct is behind an onlyOwner modifier', () => {
    const relPath = 'sc005-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc005Selfdestruct.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
