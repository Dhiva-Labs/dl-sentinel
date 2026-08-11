import { describe, expect, it } from 'vitest';
import { sc016ZeroAddressCheck } from '../../src/rules/sc016-zero-address-check.js';
import { parseFixture } from '../helpers.js';

function evaluate(relPath: string) {
  return sc016ZeroAddressCheck.evaluate({ relPath, file: parseFixture(relPath) });
}

describe('SC016 privileged address setter without a zero-address check', () => {
  const findings = evaluate('sc016-positive.sol');

  it('fires on transferOwnership assigning the parameter unvalidated', () => {
    const owner = findings.find((f) => f.metadata?.function === 'transferOwnership')!;
    expect(owner).toMatchObject({
      ruleId: 'SC016',
      severity: 'low',
      confidence: 'low',
      line: 20, // the `owner = newOwner;` line
    });
    expect(owner.metadata).toMatchObject({ parameter: 'newOwner' });
  });

  it('fires on a treasury setter as well as an ownership one', () => {
    expect(findings.find((f) => f.metadata?.function === 'setTreasury')).toBeDefined();
  });

  it('reports one finding per function', () => {
    expect(findings).toHaveLength(2);
  });

  it('does not fire when a require or a custom-error revert rejects address(0)', () => {
    expect(evaluate('sc016-negative.sol')).toHaveLength(0);
  });

  it('does not fire on setters for non-privileged state', () => {
    // setValue(uint256) is neither privileged-named nor address-typed.
    expect(evaluate('parser/nested-contracts.sol')).toHaveLength(0);
  });

  it('carries no compliance mapping (a hygiene check, like SC009 and SC012)', () => {
    expect(sc016ZeroAddressCheck.meta.compliance).toBeUndefined();
  });
});
