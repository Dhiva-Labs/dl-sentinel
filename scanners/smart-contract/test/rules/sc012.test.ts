import { describe, expect, it } from 'vitest';
import { sc012SetterEvents } from '../../src/rules/sc012-setter-events.js';
import { parseFixture } from '../helpers.js';

describe('SC012 access-control setter without an event', () => {
  it('fires on setOwner() with no emit', () => {
    const relPath = 'sc012-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc012SetterEvents.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC012',
      severity: 'low',
      confidence: 'low',
      line: 8,
    });
  });

  it('does not fire when setOwner() emits an event', () => {
    const relPath = 'sc012-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc012SetterEvents.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});
