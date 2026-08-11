import { describe, expect, it } from 'vitest';
import { sc017DelegatecallInLoop } from '../../src/rules/sc017-delegatecall-in-loop.js';
import { parseSolidityFile } from '../../src/parser.js';
import { parseFixture } from '../helpers.js';

function evaluate(relPath: string) {
  return sc017DelegatecallInLoop.evaluate({ relPath, file: parseFixture(relPath) });
}

describe('SC017 delegatecall inside a loop', () => {
  it('fires on a payable multicall that delegatecalls per iteration', () => {
    const relPath = 'sc017-positive.sol';
    const findings = evaluate(relPath);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC017',
      severity: 'high',
      confidence: 'medium',
      line: 15,
    });
    expect(findings[0]!.metadata).toMatchObject({ function: 'multicall', readsMsgValue: true });
  });

  it('does not fire on a lone delegatecall, nor on a loop without one', () => {
    expect(evaluate('sc017-negative.sol')).toHaveLength(0);
  });

  it('closes the loop scope correctly: a delegatecall after the loop is not reported', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    address public impl;',
      '    function run(bytes calldata data, uint256 n) external {',
      '        for (uint256 i = 0; i < n; i++) {',
      '            impl.staticcall(data);',
      '        }',
      '        impl.delegatecall(data);',
      '    }',
      '}',
    ].join('\n');
    const file = parseSolidityFile('t.sol', source);
    expect(sc017DelegatecallInLoop.evaluate({ relPath: 't.sol', file })).toHaveLength(0);
  });

  it('detects the brace-less same-line loop body', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    address public impl;',
      '    function run(bytes calldata data, uint256 n) external {',
      '        for (uint256 i = 0; i < n; i++) impl.delegatecall(data);',
      '    }',
      '}',
    ].join('\n');
    const file = parseSolidityFile('t.sol', source);
    const findings = sc017DelegatecallInLoop.evaluate({ relPath: 't.sol', file });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(5);
  });

  it('flags a non-payable loop too, but records that msg.value is not in play', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    address public impl;',
      '    function run(bytes[] calldata data) external {',
      '        while (data.length > 0) {',
      '            impl.delegatecall(data[0]);',
      '        }',
      '    }',
      '}',
    ].join('\n');
    const file = parseSolidityFile('t.sol', source);
    const findings = sc017DelegatecallInLoop.evaluate({ relPath: 't.sol', file });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.metadata).toMatchObject({ readsMsgValue: false });
  });
});
