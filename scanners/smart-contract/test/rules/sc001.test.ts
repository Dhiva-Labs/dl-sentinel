import { describe, expect, it } from 'vitest';
import { parseSolidityFile } from '../../src/parser.js';
import { sc001Reentrancy } from '../../src/rules/sc001-reentrancy.js';
import { parseFixture } from '../helpers.js';

function evaluateSource(source: string) {
  return sc001Reentrancy.evaluate({ relPath: 't.sol', file: parseSolidityFile('t.sol', source) });
}

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

describe('SC001 precision under the contract model', () => {
  it('does not fire when effects come first and only bookkeeping follows the call', () => {
    // The accounting write happens before the interaction, so the trailing
    // write is not the reentrancy hazard. This shape used to be reported.
    const findings = evaluateSource(
      [
        'pragma solidity 0.8.19;',
        'contract C {',
        '    mapping(address => uint256) public balances;',
        '    mapping(address => uint256) public lastWithdrawal;',
        '    function withdraw(uint256 amount) external {',
        '        balances[msg.sender] -= amount;',
        '        (bool ok, ) = msg.sender.call{value: amount}("");',
        '        require(ok, "transfer failed");',
        '        lastWithdrawal[msg.sender] = block.timestamp;',
        '    }',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(0);
  });

  it('does not fire when the effects are performed by a helper called before the call', () => {
    const findings = evaluateSource(
      [
        'pragma solidity 0.8.19;',
        'contract C {',
        '    mapping(address => uint256) public balances;',
        '    uint256 public totalPaid;',
        '    function withdraw(uint256 amount) external {',
        '        _debit(msg.sender, amount);',
        '        (bool ok, ) = msg.sender.call{value: amount}("");',
        '        require(ok, "transfer failed");',
        '        totalPaid += amount;',
        '    }',
        '    function _debit(address account, uint256 amount) internal {',
        '        balances[account] -= amount;',
        '    }',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(0);
  });

  it('still fires when nothing is written before the call', () => {
    const findings = evaluateSource(
      [
        'pragma solidity 0.8.19;',
        'contract C {',
        '    mapping(address => uint256) public balances;',
        '    function withdraw(uint256 amount) external {',
        '        (bool ok, ) = msg.sender.call{value: amount}("");',
        '        balances[msg.sender] -= amount;',
        '    }',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(5);
  });

  it('sees a state variable inherited from a base contract in the same file', () => {
    const findings = evaluateSource(
      [
        'pragma solidity 0.8.19;',
        'contract Ledger {',
        '    mapping(address => uint256) public balances;',
        '}',
        'contract Vault is Ledger {',
        '    function withdraw(uint256 amount) external {',
        '        (bool ok, ) = msg.sender.call{value: amount}("");',
        '        require(ok, "transfer failed");',
        '        balances[msg.sender] -= amount;',
        '    }',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(7);
  });
});
