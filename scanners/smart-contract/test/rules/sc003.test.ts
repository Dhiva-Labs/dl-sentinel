import { describe, expect, it } from 'vitest';
import { sc003UncheckedCall } from '../../src/rules/sc003-unchecked-call.js';
import { parseFixture } from '../helpers.js';

describe('SC003 unchecked low-level call', () => {
  it('fires on a .call(...) whose result is discarded', () => {
    const relPath = 'sc003-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc003UncheckedCall.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC003',
      severity: 'medium',
      confidence: 'medium',
      line: 7,
    });
  });

  it('does not fire when the result is captured and required, or when .transfer( is used', () => {
    const relPath = 'sc003-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc003UncheckedCall.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
