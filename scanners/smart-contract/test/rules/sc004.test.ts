import { describe, expect, it } from 'vitest';
import { sc004Delegatecall } from '../../src/rules/sc004-delegatecall.js';
import { parseFixture } from '../helpers.js';

describe('SC004 delegatecall to non-constant target', () => {
  it('fires when the target derives from a function parameter', () => {
    const relPath = 'sc004-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc004Delegatecall.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC004',
      severity: 'high',
      confidence: 'medium',
      line: 7,
    });
    expect(findings[0]!.description).toContain('target');
  });

  it('does not fire when the target is an immutable address', () => {
    const relPath = 'sc004-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc004Delegatecall.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
