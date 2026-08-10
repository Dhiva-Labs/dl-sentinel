import { describe, expect, it } from 'vitest';
import { sc010Randomness } from '../../src/rules/sc010-randomness.js';
import { parseFixture } from '../helpers.js';

describe('SC010 block timestamp/number as randomness', () => {
  it('fires when block.timestamp modulo feeds a winner selection', () => {
    const relPath = 'sc010-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc010Randomness.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC010',
      severity: 'medium',
      confidence: 'medium',
      line: 9,
    });
  });

  it('does not fire when block.timestamp is just recorded, with no selection context', () => {
    const relPath = 'sc010-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc010Randomness.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
