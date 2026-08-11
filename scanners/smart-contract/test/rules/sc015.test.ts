import { describe, expect, it } from 'vitest';
import { sc015UncheckedErc20Transfer } from '../../src/rules/sc015-unchecked-erc20-transfer.js';
import { parseFixture } from '../helpers.js';

function evaluate(relPath: string) {
  return sc015UncheckedErc20Transfer.evaluate({ relPath, file: parseFixture(relPath) });
}

describe('SC015 unchecked ERC20 transfer', () => {
  const findings = evaluate('sc015-positive.sol');

  it('fires on a bare token.transfer(to, amount) statement', () => {
    const transfer = findings.find((f) => f.metadata?.method === 'transfer')!;
    expect(transfer).toMatchObject({
      ruleId: 'SC015',
      severity: 'medium',
      confidence: 'medium',
      line: 14,
    });
  });

  it('fires on a bare transferFrom through an IERC20 cast', () => {
    const transferFrom = findings.find((f) => f.metadata?.method === 'transferFrom')!;
    expect(transferFrom).toMatchObject({ ruleId: 'SC015', line: 18 });
  });

  it('reports each discarded call exactly once', () => {
    expect(findings).toHaveLength(2);
  });

  it('stays quiet on require-wrapped, captured, and SafeERC20 forms, and on ETH .transfer', () => {
    expect(evaluate('sc015-negative.sol')).toHaveLength(0);
  });

  it('specifically: a one-argument payable .transfer is never mistaken for the ERC20 shape', () => {
    // Both shared fixtures send ETH with payable(...).transfer(amount).
    expect(evaluate('sc002-positive.sol')).toHaveLength(0);
  });
});
