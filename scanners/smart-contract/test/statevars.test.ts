import { describe, expect, it } from 'vitest';
import { findStateWrite, hasBinaryArithmetic, isArithmeticCompoundOp } from '../src/statevars.js';

describe('findStateWrite', () => {
  const names = ['balances', 'owner', 'totalSupply'];

  it('detects a compound-assignment write on a mapping index', () => {
    const m = findStateWrite('balances[msg.sender] -= amount;', names);
    expect(m).toEqual({ name: 'balances', isCompound: true, isDelete: false });
  });

  it('detects a plain assignment and returns the RHS', () => {
    const m = findStateWrite('totalSupply = totalSupply + amount;', names);
    expect(m?.name).toBe('totalSupply');
    expect(m?.isCompound).toBe(false);
    expect(m?.rhs?.trim()).toBe('totalSupply + amount');
  });

  it('detects delete', () => {
    const m = findStateWrite('delete balances[msg.sender];', names);
    expect(m).toEqual({ name: 'balances', isCompound: false, isDelete: true });
  });

  it('does not confuse a mapping type declaration arrow (=>) with an assignment', () => {
    // Not a write at all — just confirms scanning a declaration-shaped line
    // doesn't crash or misfire; findStateWrite is normally only used on
    // function-body lines, but must still behave sanely here.
    const m = findStateWrite('mapping(address => uint256) public balances;', names);
    expect(m).toBeNull();
  });

  it('does not match on == (comparison, not assignment)', () => {
    const m = findStateWrite('if (totalSupply == 0) { return; }', names);
    expect(m).toBeNull();
  });

  it('does not match an unrelated local variable', () => {
    const m = findStateWrite('uint256 localBalances = 5;', names);
    expect(m).toBeNull();
  });

  it('returns null when nothing matches', () => {
    expect(findStateWrite('emit Transfer(msg.sender, to, amount);', names)).toBeNull();
  });

  it('matches struct-field-style writes via the accessor suffix', () => {
    const m = findStateWrite('owner.wallet = msg.sender;', ['owner']);
    expect(m?.name).toBe('owner');
  });
});

describe('isArithmeticCompoundOp', () => {
  it('true for +=, -=, *=', () => {
    expect(isArithmeticCompoundOp('x += 1;', 'x')).toBe(true);
    expect(isArithmeticCompoundOp('x -= 1;', 'x')).toBe(true);
    expect(isArithmeticCompoundOp('x *= 2;', 'x')).toBe(true);
  });

  it('false for /=, %=, and bitwise compounds', () => {
    expect(isArithmeticCompoundOp('x /= 2;', 'x')).toBe(false);
    expect(isArithmeticCompoundOp('x %= 2;', 'x')).toBe(false);
    expect(isArithmeticCompoundOp('x |= 2;', 'x')).toBe(false);
  });
});

describe('hasBinaryArithmetic', () => {
  it('detects a spaced binary operator', () => {
    expect(hasBinaryArithmetic('totalSupply + amount')).toBe(true);
  });

  it('detects an unspaced binary operator', () => {
    expect(hasBinaryArithmetic('a-b')).toBe(true);
  });

  it('does not flag ++ / -- as binary arithmetic', () => {
    expect(hasBinaryArithmetic('i++')).toBe(false);
    expect(hasBinaryArithmetic('--i')).toBe(false);
  });

  it('does not flag ** (exponent) as binary arithmetic', () => {
    expect(hasBinaryArithmetic('a ** b')).toBe(false);
  });

  it('false for an expression with no arithmetic', () => {
    expect(hasBinaryArithmetic('newOwner')).toBe(false);
  });
});
