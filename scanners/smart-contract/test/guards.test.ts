import { describe, expect, it } from 'vitest';
import { analyzeModifier, functionGuardVerdict } from '../src/guards.js';
import type { ContractInfo } from '../src/model.js';
import { parseSolidityFile } from '../src/parser.js';
import { resolveFile, type ResolvedContract } from '../src/resolve.js';
import { parseFixture } from './helpers.js';

function resolvedContract(rel: string, name: string): ResolvedContract {
  return resolveFile(parseFixture(rel)).contracts.get(name)!;
}

function fnIn(contract: ContractInfo, name: string) {
  return contract.functions.find((f) => f.name === name)!;
}

describe('analyzeModifier: proven guards', () => {
  const bodies = resolvedContract('guards-modifier-bodies.sol', 'ModifierBodies');

  it('proves a direct msg.sender equality', () => {
    expect(analyzeModifier(bodies, 'onlyOwner')).toMatchObject({ status: 'proven' });
  });

  it('proves a mapping-based auth check where msg.sender is not the compared operand', () => {
    expect(analyzeModifier(bodies, 'auth')).toMatchObject({ status: 'proven' });
  });

  it('proves a call to a recognized authorization helper (_checkRole)', () => {
    expect(analyzeModifier(bodies, 'onlyRole')).toMatchObject({ status: 'proven' });
  });

  it('proves a check that lives one hop away in an in-file helper', () => {
    expect(analyzeModifier(bodies, 'onlyOwnerIndirect')).toMatchObject({ status: 'proven' });
  });
});

describe('analyzeModifier: unproven guards', () => {
  const bodies = resolvedContract('guards-modifier-bodies.sol', 'ModifierBodies');

  it('returns none for a protective-sounding modifier whose body checks nothing', () => {
    expect(analyzeModifier(bodies, 'onlyOwnerButEmpty')).toMatchObject({
      status: 'none',
      modifier: 'onlyOwnerButEmpty',
    });
  });

  it('returns none for a real modifier that is not an access-control one', () => {
    expect(analyzeModifier(bodies, 'whenNotPaused')).toMatchObject({ status: 'none' });
  });
});

describe('analyzeModifier: unresolvable guards are assumed protective', () => {
  it('assumes a modifier this file never declares (an imported one)', () => {
    const bodies = resolvedContract('guards-modifier-bodies.sol', 'ModifierBodies');
    expect(analyzeModifier(bodies, 'initializer')).toMatchObject({
      status: 'assumed',
      reason: 'modifier-not-declared-in-file',
    });
  });

  it('assumes a modifier declared without a body', () => {
    const abstractGuard = resolvedContract('guards-modifier-bodies.sol', 'AbstractGuard');
    expect(analyzeModifier(abstractGuard, 'onlyGovernor')).toMatchObject({
      status: 'assumed',
      reason: 'modifier-declared-without-body',
    });
  });
});

describe('functionGuardVerdict', () => {
  it('counts a modifier declared in a base contract in the same file', () => {
    const parsed = parseFixture('sc007-negative-inherited-modifier.sol');
    const token = parsed.contracts.find((c) => c.name === 'InheritedGuardToken')!;
    const resolved = resolveFile(parsed).contracts.get('InheritedGuardToken')!;
    expect(functionGuardVerdict(resolved, fnIn(token, 'mint'))).toMatchObject({
      status: 'proven',
      modifier: 'onlyOwner',
    });
  });

  it('counts an inline msg.sender check with no modifier at all', () => {
    const parsed = parseSolidityFile(
      't.sol',
      [
        'contract C {',
        '    address public owner;',
        '    function destroy() external {',
        '        require(msg.sender == owner, "not owner");',
        '        selfdestruct(payable(owner));',
        '    }',
        '}',
      ].join('\n'),
    );
    const resolved = resolveFile(parsed).contracts.get('C')!;
    expect(functionGuardVerdict(resolved, fnIn(parsed.contracts[0]!, 'destroy'))).toMatchObject({
      status: 'proven',
      reason: 'function-body-checks-caller',
    });
  });

  it('reports none when neither a modifier nor an inline check exists', () => {
    const parsed = parseFixture('sc007-positive.sol');
    const resolved = resolveFile(parsed).contracts.get('MintPositive')!;
    expect(functionGuardVerdict(resolved, fnIn(parsed.contracts[0]!, 'mint'))).toMatchObject({
      status: 'none',
    });
  });

  it('prefers a proven modifier over an assumed one when both are applied', () => {
    const parsed = parseSolidityFile(
      't.sol',
      [
        'contract C {',
        '    address public owner;',
        '    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }',
        '    function mint(address to) external initializer onlyOwner {',
        '        owner = to;',
        '    }',
        '}',
      ].join('\n'),
    );
    const resolved = resolveFile(parsed).contracts.get('C')!;
    expect(functionGuardVerdict(resolved, fnIn(parsed.contracts[0]!, 'mint'))).toMatchObject({
      status: 'proven',
      modifier: 'onlyOwner',
    });
  });
});
