import { describe, expect, it } from 'vitest';
import { sc001Reentrancy } from '../../src/rules/sc001-reentrancy.js';
import { parseFixture } from '../helpers.js';

describe('SC001 reentrancy', () => {
  it('fires on the classic vulnerable withdraw (call before state write)', () => {
    const relPath = 'sc001-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc001Reentrancy.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC001',
      severity: 'high',
      confidence: 'medium',
      file: relPath,
    });
    expect(findings[0]!.line).toBe(10); // the .call{value:...} line
    expect(findings[0]!.evidence).toContain('.call{value: amount}');
  });

  it('does not fire on checks-effects-interactions (state write before the call)', () => {
    const relPath = 'sc001-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc001Reentrancy.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });

  it('is suppressed by a nonReentrant modifier even on the vulnerable shape', () => {
    const relPath = 'sc001-suppressed.sol';
    const file = parseFixture(relPath);
    const findings = sc001Reentrancy.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
