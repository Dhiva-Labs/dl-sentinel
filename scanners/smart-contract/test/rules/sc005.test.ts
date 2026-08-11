import { describe, expect, it } from 'vitest';
import { parseSolidityFile } from '../../src/parser.js';
import { sc005Selfdestruct } from '../../src/rules/sc005-selfdestruct.js';
import { parseFixture } from '../helpers.js';

describe('SC005 unprotected selfdestruct', () => {
  it('fires when selfdestruct is reachable with no guard', () => {
    const relPath = 'sc005-positive.sol';
    const file = parseFixture(relPath);
    const findings = sc005Selfdestruct.evaluate({ relPath, file });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'SC005',
      severity: 'critical',
      confidence: 'medium',
      line: 7,
    });
  });

  it('does not fire when selfdestruct is behind an onlyOwner modifier', () => {
    const relPath = 'sc005-negative.sol';
    const file = parseFixture(relPath);
    const findings = sc005Selfdestruct.evaluate({ relPath, file });
    expect(findings).toHaveLength(0);
  });
});

describe('SC005 under modifier-body analysis', () => {
  function evaluateSource(source: string) {
    return sc005Selfdestruct.evaluate({
      relPath: 't.sol',
      file: parseSolidityFile('t.sol', source),
    });
  }

  it('fires when the modifier is protective in name only', () => {
    const findings = evaluateSource(
      [
        'pragma solidity 0.8.19;',
        'contract C {',
        '    modifier onlyOwner() { _; }',
        '    function destroy() external onlyOwner {',
        '        selfdestruct(payable(msg.sender));',
        '    }',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(1);
  });

  it('does not fire when the modifier delegates its check to an in-file helper', () => {
    const findings = evaluateSource(
      [
        'pragma solidity 0.8.19;',
        'contract C {',
        '    address public owner;',
        '    function isOwner() internal view returns (bool) { return msg.sender == owner; }',
        '    modifier onlyOwner() { require(isOwner(), "not owner"); _; }',
        '    function destroy() external onlyOwner {',
        '        selfdestruct(payable(owner));',
        '    }',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(0);
  });

  it('does not fire when the modifier checks a caller mapping rather than an equality', () => {
    const findings = evaluateSource(
      [
        'pragma solidity 0.8.19;',
        'contract C {',
        '    mapping(address => uint256) public wards;',
        '    modifier auth() { require(wards[msg.sender] == 1, "not authorized"); _; }',
        '    function destroy() external auth {',
        '        selfdestruct(payable(msg.sender));',
        '    }',
        '}',
      ].join('\n'),
    );
    expect(findings).toHaveLength(0);
  });
});
