import { describe, expect, it } from 'vitest';
import { parseSolidityFile } from '../src/parser.js';
import { parseFixture, readFixture } from './helpers.js';

describe('parseSolidityFile: pragma extraction', () => {
  it('extracts the raw constraint and line', () => {
    const parsed = parseSolidityFile(
      't.sol',
      '// license\npragma solidity ^0.8.0;\ncontract C {}\n',
    );
    expect(parsed.pragmas).toHaveLength(1);
    expect(parsed.pragmas[0]).toMatchObject({ raw: '^0.8.0', line: 2 });
    expect(parsed.pragmas[0]!.fullStatement).toContain('pragma solidity ^0.8.0;');
  });
});

describe('parseSolidityFile: contract/function extraction', () => {
  it('parses a simple contract with one function, its visibility, and its body', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    uint256 public value;',
      '    function setValue(uint256 v) external {',
      '        value = v;',
      '    }',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    expect(parsed.contracts).toHaveLength(1);
    const c = parsed.contracts[0]!;
    expect(c.name).toBe('C');
    expect(c.kind).toBe('contract');
    expect(c.stateVariables.map((v) => v.name)).toEqual(['value']);
    expect(c.functions).toHaveLength(1);
    const fn = c.functions[0]!;
    expect(fn.name).toBe('setValue');
    expect(fn.visibility).toBe('external');
    expect(fn.hasBody).toBe(true);
    expect(fn.parameters).toEqual(['v']);
    expect(fn.body.map((l) => l.line)).toEqual([4, 5, 6]);
  });

  it('extracts modifiers applied to a function, in order, ignoring virtual/override', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    modifier onlyOwner() { _; }',
      '    modifier whenNotPaused() { _; }',
      '    function act() public virtual onlyOwner whenNotPaused {',
      '        uint256 x = 1;',
      '    }',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    const c = parsed.contracts[0]!;
    expect(c.modifierNames).toEqual(['onlyOwner', 'whenNotPaused']);
    const fn = c.functions[0]!;
    expect(fn.modifiers).toEqual(['onlyOwner', 'whenNotPaused']);
    expect(fn.visibility).toBe('public');
  });

  it('extracts a modifier with call-style arguments applied to a function', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");',
      '    function act() external onlyRole(ADMIN_ROLE) {',
      '        uint256 x = 1;',
      '    }',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    const fn = parsed.contracts[0]!.functions[0]!;
    expect(fn.modifiers).toEqual(['onlyRole']);
  });

  it('extracts state mutability and defaults to nonpayable when unspecified', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    function readOnly() external view returns (uint256) { return 1; }',
      '    function payMe() external payable {}',
      '    function plain() external {}',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    const [readOnly, payMe, plain] = parsed.contracts[0]!.functions;
    expect(readOnly!.stateMutability).toBe('view');
    expect(payMe!.stateMutability).toBe('payable');
    expect(plain!.stateMutability).toBe('nonpayable');
  });

  it('extracts a constructor, recognizing it by keyword rather than a name', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    address public owner;',
      '    constructor(address initialOwner) {',
      '        owner = initialOwner;',
      '    }',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    const fn = parsed.contracts[0]!.functions[0]!;
    expect(fn.name).toBe('constructor');
    expect(fn.isConstructor).toBe(true);
    expect(fn.parameters).toEqual(['initialOwner']);
  });

  it('does not treat the mapping type arrow (=>) as a variable initializer', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    mapping(address => uint256) public balances;',
      '    mapping(address => mapping(address => uint256)) public allowances;',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    const names = parsed.contracts[0]!.stateVariables.map((v) => v.name);
    expect(names).toEqual(['balances', 'allowances']);
  });

  it('flags constant/immutable state variables', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    uint256 public constant MAX_SUPPLY = 1000000;',
      '    address public immutable owner;',
      '    uint256 public mutableValue;',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    const vars = parsed.contracts[0]!.stateVariables;
    expect(vars.find((v) => v.name === 'MAX_SUPPLY')?.isConstantOrImmutable).toBe(true);
    expect(vars.find((v) => v.name === 'owner')?.isConstantOrImmutable).toBe(true);
    expect(vars.find((v) => v.name === 'mutableValue')?.isConstantOrImmutable).toBe(false);
  });

  it('does not extract events, structs, or using-directives as state variables', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    event Transfer(address indexed from, address indexed to, uint256 value);',
      '    struct Info { uint256 a; uint256 b; }',
      '    using SafeMathLike for uint256;',
      '    uint256 public realVar;',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    expect(parsed.contracts[0]!.stateVariables.map((v) => v.name)).toEqual(['realVar']);
  });

  it('does not treat a struct field as a contract-level state variable', () => {
    const source = [
      'pragma solidity 0.8.19;',
      'contract C {',
      '    struct Info {',
      '        uint256 amount;',
      '        address holder;',
      '    }',
      '    uint256 public total;',
      '}',
    ].join('\n');
    const parsed = parseSolidityFile('t.sol', source);
    expect(parsed.contracts[0]!.stateVariables.map((v) => v.name)).toEqual(['total']);
  });
});

describe('parseSolidityFile: nested/sequential contracts fixture', () => {
  const parsed = parseFixture('parser/nested-contracts.sol');

  it('parses all three top-level declarations without leaking state across them', () => {
    expect(parsed.contracts.map((c) => c.name)).toEqual([
      'IGreeter',
      'Math',
      'Greeter',
      'SecondContract',
    ]);
    const [iGreeter, math, greeter, second] = parsed.contracts;
    expect(iGreeter!.kind).toBe('interface');
    expect(math!.kind).toBe('library');
    expect(greeter!.kind).toBe('contract');
    expect(second!.kind).toBe('contract');
  });

  it('does not leak Greeter state/functions into SecondContract or vice versa', () => {
    const greeter = parsed.contracts.find((c) => c.name === 'Greeter')!;
    const second = parsed.contracts.find((c) => c.name === 'SecondContract')!;
    expect(greeter.stateVariables.map((v) => v.name)).toEqual(['message', 'counter']);
    expect(second.stateVariables.map((v) => v.name)).toEqual(['value']);
    expect(greeter.functions.map((f) => f.name)).toEqual(['constructor', 'greet', 'bump']);
    expect(second.functions.map((f) => f.name)).toEqual(['setValue']);
  });
});

describe('parseSolidityFile: interfaces and abstract contracts', () => {
  const parsed = parseFixture('parser/interfaces-and-abstract.sol');

  it('parses interface functions as body-less stubs', () => {
    const iToken = parsed.contracts.find((c) => c.name === 'IToken')!;
    expect(iToken.kind).toBe('interface');
    expect(iToken.functions).toHaveLength(2);
    for (const fn of iToken.functions) {
      expect(fn.hasBody).toBe(false);
      expect(fn.body).toEqual([]);
    }
    expect(iToken.functions.map((f) => f.name)).toEqual(['transfer', 'balanceOf']);
  });

  it('parses an abstract contract, distinguishing its unimplemented stub from its implemented function', () => {
    const base = parsed.contracts.find((c) => c.name === 'BaseToken')!;
    expect(base.kind).toBe('abstract');
    const balanceOf = base.functions.find((f) => f.name === 'balanceOf')!;
    const mint = base.functions.find((f) => f.name === 'mint')!;
    expect(balanceOf.hasBody).toBe(false);
    expect(mint.hasBody).toBe(true);
    expect(mint.body.length).toBeGreaterThan(0);
  });
});

describe('parseSolidityFile: visibility defaults', () => {
  it('defaults an omitted visibility to public under a pre-0.5 pragma', () => {
    const parsed = parseFixture('parser/visibility-default-pre05.sol');
    const c = parsed.contracts[0]!;
    const setValue = c.functions.find((f) => f.name === 'setValue')!;
    const explicitInternal = c.functions.find((f) => f.name === 'explicitInternal')!;
    expect(setValue.visibility).toBe('public');
    expect(explicitInternal.visibility).toBe('internal');
  });
});

describe('parseSolidityFile: malformed input', () => {
  it('does not throw on a truncated file and still returns partial results', () => {
    const source = readFixture('parser/malformed-truncated.sol');
    expect(() => parseSolidityFile('parser/malformed-truncated.sol', source)).not.toThrow();
    const parsed = parseSolidityFile('parser/malformed-truncated.sol', source);
    expect(parsed.warnings.length).toBeGreaterThan(0);
    const c = parsed.contracts[0]!;
    expect(c.name).toBe('Truncated');
    // The well-formed function before the truncation point is still recovered.
    expect(c.functions.some((f) => f.name === 'setValue')).toBe(true);
  });

  it('does not throw on unbalanced (extra) closing braces', () => {
    const source = readFixture('parser/malformed-unbalanced-braces.sol');
    expect(() => parseSolidityFile('parser/malformed-unbalanced-braces.sol', source)).not.toThrow();
    const parsed = parseSolidityFile('parser/malformed-unbalanced-braces.sol', source);
    expect(parsed.warnings.length).toBeGreaterThan(0);
    expect(parsed.contracts[0]!.name).toBe('UnbalancedBraces');
  });

  it('does not throw on empty input', () => {
    expect(() => parseSolidityFile('empty.sol', '')).not.toThrow();
    expect(parseSolidityFile('empty.sol', '').contracts).toEqual([]);
  });
});
