import { describe, expect, it } from 'vitest';
import { sc002TxOrigin } from '../../src/rules/sc002-tx-origin.js';
import { parseFixture } from '../helpers.js';

describe('SC002 tx.origin authorization', () => {
  it('fires on tx.origin used inside a require(...) comparison', () => {
    const relPath = 'sc002-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc002TxOrigin.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC002',
      severity: 'high',
      confidence: 'high',
      line: 13,
    });
    expect(findings[0]!.evidence).toContain('tx.origin');
  });

  it('does not fire when msg.sender is used instead', () => {
    const relPath = 'sc002-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc002TxOrigin.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
