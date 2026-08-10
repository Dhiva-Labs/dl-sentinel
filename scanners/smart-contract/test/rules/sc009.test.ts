import { describe, expect, it } from 'vitest';
import { sc009Pragma } from '../../src/rules/sc009-pragma.js';
import { parseFixture } from '../helpers.js';

describe('SC009 floating or outdated pragma', () => {
  it('fires on a floating (caret) pragma even when otherwise recent', () => {
    const relPath = 'sc009-positive-floating.sol';
    const file = parseFixture(relPath);
    const findings = sc009Pragma.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC009',
      severity: 'low',
      confidence: 'high',
      line: 2,
    });
    expect(findings[0]!.metadata).toMatchObject({ floating: true, outdated: false });
  });

  it('fires on an exact-pinned but outdated (pre-0.8 reach) pragma', () => {
    const relPath = 'sc009-positive-outdated.sol';
    const file = parseFixture(relPath);
    const findings = sc009Pragma.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.metadata).toMatchObject({ floating: false, outdated: true });
  });

  it('does not fire on an exact-pinned recent pragma', () => {
    const relPath = 'sc009-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc009Pragma.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
