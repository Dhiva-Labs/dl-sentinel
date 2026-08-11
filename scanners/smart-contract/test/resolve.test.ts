import { describe, expect, it } from 'vitest';
import { parseSolidityFile } from '../src/parser.js';
import { findCallSites, reachableFunctions, resolveFile } from '../src/resolve.js';
import { parseFixture } from './helpers.js';

const CHAIN_FIXTURE = 'parser/inheritance-chain.sol';

function resolveFixture(rel: string) {
  return resolveFile(parseFixture(rel));
}

describe('parser: base contract names', () => {
  it('records the `is` list in source order', () => {
    const parsed = parseFixture(CHAIN_FIXTURE);
    const vault = parsed.contracts.find((c) => c.name === 'Vault')!;
    expect(vault.baseNames).toEqual(['Pausable', 'Imported']);
  });

  it('strips constructor arguments from a base entry', () => {
    const parsed = parseSolidityFile(
      't.sol',
      ['contract A is Owned(msg.sender), ERC20("Name", "SYM") {', '}'].join('\n'),
    );
    expect(parsed.contracts[0]!.baseNames).toEqual(['Owned', 'ERC20']);
  });

  it('is empty for a contract with no `is` clause', () => {
    const parsed = parseSolidityFile('t.sol', 'contract A {\n}\n');
    expect(parsed.contracts[0]!.baseNames).toEqual([]);
  });
});

describe('parser: modifier bodies', () => {
  it('captures each modifier declaration with its body lines', () => {
    const parsed = parseFixture(CHAIN_FIXTURE);
    const ownership = parsed.contracts.find((c) => c.name === 'Ownership')!;
    expect(ownership.modifierNames).toEqual(['onlyOwner']);
    const onlyOwner = ownership.modifiers[0]!;
    expect(onlyOwner.name).toBe('onlyOwner');
    expect(onlyOwner.hasBody).toBe(true);
    expect(onlyOwner.body.some((l) => l.stripped.includes('msg.sender == owner'))).toBe(true);
  });

  it('records a body-less `modifier X() virtual;` declaration as having no body', () => {
    const parsed = parseFixture('guards-modifier-bodies.sol');
    const abstractGuard = parsed.contracts.find((c) => c.name === 'AbstractGuard')!;
    const governor = abstractGuard.modifiers.find((m) => m.name === 'onlyGovernor')!;
    expect(governor.hasBody).toBe(false);
    expect(governor.body).toEqual([]);
  });

  it('does not leak a modifier body into the functions of the same contract', () => {
    const parsed = parseFixture(CHAIN_FIXTURE);
    const ownership = parsed.contracts.find((c) => c.name === 'Ownership')!;
    expect(ownership.functions.map((f) => f.name)).toEqual([
      'constructor',
      'transferOwnershipInternal',
    ]);
  });
});

describe('parser: declared parameter types', () => {
  it('recovers each named parameter with its type, dropping data locations', () => {
    const parsed = parseSolidityFile(
      't.sol',
      [
        'contract C {',
        '    function f(address to, uint256 amount, bytes calldata data, IERC20 token) external {',
        '    }',
        '}',
      ].join('\n'),
    );
    const fn = parsed.contracts[0]!.functions[0]!;
    expect(fn.declaredParameters).toEqual([
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'data', type: 'bytes' },
      { name: 'token', type: 'IERC20' },
    ]);
    // The name-only projection is unchanged.
    expect(fn.parameters).toEqual(['to', 'amount', 'data', 'token']);
  });
});

describe('parser: state variable declared types', () => {
  it('records the leading type token', () => {
    const parsed = parseSolidityFile(
      't.sol',
      [
        'contract C {',
        '    IERC20 public token;',
        '    address public owner;',
        '    mapping(address => uint256) public balances;',
        '}',
      ].join('\n'),
    );
    const types = Object.fromEntries(
      parsed.contracts[0]!.stateVariables.map((v) => [v.name, v.declaredType]),
    );
    expect(types).toEqual({ token: 'IERC20', owner: 'address', balances: 'mapping' });
  });
});

describe('resolveFile: inheritance', () => {
  const resolved = resolveFixture(CHAIN_FIXTURE);
  const vault = resolved.contracts.get('Vault')!;

  it('linearizes self-first, then bases depth-first left to right', () => {
    expect(vault.linearization.map((c) => c.name)).toEqual(['Vault', 'Pausable', 'Ownership']);
  });

  it('reports a base declared outside this file as unresolved rather than dropping it', () => {
    expect(vault.unknownBaseNames).toEqual(['Imported']);
  });

  it('resolves a modifier declared two levels up the chain', () => {
    const onlyOwner = vault.modifiers.get('onlyOwner')!;
    expect(onlyOwner.declaringContract.name).toBe('Ownership');
    expect(onlyOwner.inherited).toBe(true);
  });

  it('resolves inherited functions and state variables into the effective view', () => {
    expect(vault.functions.get('pause')?.declaringContract.name).toBe('Pausable');
    expect(vault.functions.get('transferOwnershipInternal')?.declaringContract.name).toBe(
      'Ownership',
    );
    expect([...vault.stateVariableNames]).toEqual(['balances', 'paused', 'owner']);
  });

  it('gives a base contract only its own members', () => {
    const ownership = resolved.contracts.get('Ownership')!;
    expect(ownership.linearization.map((c) => c.name)).toEqual(['Ownership']);
    expect(ownership.functions.has('pause')).toBe(false);
    expect([...ownership.stateVariableNames]).toEqual(['owner']);
  });
});

describe('resolveFile: call graph', () => {
  const vault = resolveFixture(CHAIN_FIXTURE).contracts.get('Vault')!;

  it('records one edge per in-contract call, excluding the declaration header', () => {
    expect(vault.callGraph.get('entry')).toEqual(['levelOne']);
    expect(vault.callGraph.get('levelOne')).toEqual(['levelTwo']);
    expect(vault.callGraph.get('levelThree')).toEqual(['levelFour']);
  });

  it('records an empty edge list for a function that calls nothing', () => {
    expect(vault.callGraph.get('levelFour')).toEqual([]);
    expect(vault.callGraph.get('drain')).toEqual([]);
  });

  it('caps traversal at the requested depth', () => {
    expect([...reachableFunctions(vault, 'entry', 1)]).toEqual(['levelOne']);
    expect([...reachableFunctions(vault, 'entry', 3)].sort()).toEqual([
      'levelOne',
      'levelThree',
      'levelTwo',
    ]);
    // levelFour is four hops out and stays invisible at depth 3.
    expect(reachableFunctions(vault, 'entry', 3).has('levelFour')).toBe(false);
    expect(reachableFunctions(vault, 'entry', 4).has('levelFour')).toBe(true);
  });

  it('terminates on a call cycle instead of recursing forever', () => {
    const parsed = parseSolidityFile(
      't.sol',
      [
        'contract C {',
        '    uint256 public v;',
        '    function a() internal { b(); }',
        '    function b() internal { a(); }',
        '}',
      ].join('\n'),
    );
    const c = resolveFile(parsed).contracts.get('C')!;
    // The entry itself is never reported as reachable-from-itself, so the
    // a -> b -> a cycle terminates with just b.
    expect([...reachableFunctions(c, 'a', 5)]).toEqual(['b']);
  });
});

describe('findCallSites', () => {
  it('ignores member calls on another object and the declaration header itself', () => {
    const parsed = parseSolidityFile(
      't.sol',
      [
        'contract C {',
        '    function settle() internal {}',
        '    function run(address token) external {',
        '        token.settle();',
        '        this.settle();',
        '        settle();',
        '    }',
        '}',
      ].join('\n'),
    );
    const run = parsed.contracts[0]!.functions.find((f) => f.name === 'run')!;
    const sites = findCallSites(run.body, new Set(['settle', 'run']));
    expect(sites).toHaveLength(1);
    expect(sites[0]!.callee).toBe('settle');
    expect(run.body[sites[0]!.bodyIndex]!.stripped.trim()).toBe('settle();');
  });
});

describe('resolveFile: resilience', () => {
  it('resolves a malformed file without throwing', () => {
    const parsed = parseFixture('parser/malformed-truncated.sol');
    expect(() => resolveFile(parsed)).not.toThrow();
  });

  it('returns the same object for repeated resolution of one parse (memoized, deterministic)', () => {
    const parsed = parseFixture(CHAIN_FIXTURE);
    expect(resolveFile(parsed)).toBe(resolveFile(parsed));
  });

  it('resolves an unknown-base-only contract to just itself', () => {
    const parsed = parseSolidityFile('t.sol', 'contract A is OnlyImported {\n}\n');
    const a = resolveFile(parsed).contracts.get('A')!;
    expect(a.linearization.map((c) => c.name)).toEqual(['A']);
    expect(a.unknownBaseNames).toEqual(['OnlyImported']);
  });
});
