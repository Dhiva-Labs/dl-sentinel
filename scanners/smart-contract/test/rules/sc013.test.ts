import { describe, expect, it } from 'vitest';
import { sc001Reentrancy } from '../../src/rules/sc001-reentrancy.js';
import { sc013CrossFunctionReentrancy } from '../../src/rules/sc013-cross-function-reentrancy.js';
import { parseFixture } from '../helpers.js';

function evaluate(relPath: string) {
  return sc013CrossFunctionReentrancy.evaluate({ relPath, file: parseFixture(relPath) });
}

describe('SC013 cross-function reentrancy', () => {
  it('fires when the external call is direct and the state write is one hop away', () => {
    const relPath = 'sc013-positive-write-via-hop.sol';
    const findings = evaluate(relPath);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC013',
      severity: 'high',
      confidence: 'medium',
      file: relPath,
      line: 13, // the .call{value:...} line in withdraw()
    });
    expect(findings[0]!.metadata).toMatchObject({ function: 'withdraw', stateWriteVia: '_settle' });
  });

  it('fires in the other direction: the external call is one hop away and the write is direct', () => {
    const relPath = 'sc013-positive-call-via-hop.sol';
    const findings = evaluate(relPath);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'SC013', line: 12 }); // the _payout(...) call site
    expect(findings[0]!.metadata).toMatchObject({
      function: 'withdraw',
      externalCallVia: '_payout',
    });
  });

  it('does not fire when checks-effects-interactions holds across the hop', () => {
    expect(evaluate('sc013-negative-checks-effects.sol')).toHaveLength(0);
  });

  it('is suppressed by a reentrancy guard on the entry function', () => {
    expect(evaluate('sc013-negative-nonreentrant.sol')).toHaveLength(0);
  });

  it('stays out of functions SC001 already covers (no double reporting)', () => {
    const relPath = 'sc001-positive.sol';
    const file = parseFixture(relPath);
    expect(sc001Reentrancy.evaluate({ relPath, file })).toHaveLength(1);
    expect(sc013CrossFunctionReentrancy.evaluate({ relPath, file })).toHaveLength(0);
  });

  it('never fires where SC001 does on the shared vulnerable-app shape either', () => {
    const relPath = 'sc001-negative.sol';
    const file = parseFixture(relPath);
    expect(sc001Reentrancy.evaluate({ relPath, file })).toHaveLength(0);
    expect(sc013CrossFunctionReentrancy.evaluate({ relPath, file })).toHaveLength(0);
  });

  it('respects the traversal bound: a write three hops out is found, four hops out is not', () => {
    const relPath = 'sc013-depth.sol';
    const findings = evaluate(relPath);
    expect(findings).toHaveLength(1);
    // Line 13 is inside DepthWithinBound; DepthBeyondBound has the identical
    // shape one hop deeper and is deliberately not reported.
    expect(findings[0]!.line).toBe(13);
  });

  it('only considers public/external entry points, not internal helpers', () => {
    const findings = evaluate('sc013-positive-write-via-hop.sol');
    expect(findings.map((f) => f.metadata?.function)).toEqual(['withdraw']);
  });
});
