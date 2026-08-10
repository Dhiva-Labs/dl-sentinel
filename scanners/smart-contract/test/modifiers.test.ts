import { describe, expect, it } from 'vitest';
import {
  hasMsgSenderGuard,
  hasProtectiveModifier,
  hasReentrancyGuardModifier,
  isProtectiveModifierName,
} from '../src/modifiers.js';

describe('isProtectiveModifierName', () => {
  it('recognizes each documented substring, case-insensitively', () => {
    expect(isProtectiveModifierName('onlyOwner')).toBe(true);
    expect(isProtectiveModifierName('onlyAdmin')).toBe(true);
    expect(isProtectiveModifierName('onlyRole')).toBe(true);
    expect(isProtectiveModifierName('AUTHORIZED')).toBe(true);
    expect(isProtectiveModifierName('isGuarded')).toBe(true);
  });

  it('does not recognize "restricted" — a documented gap', () => {
    // The mission brief's prose lists "restricted" alongside onlyOwner/auth
    // as an example protective name, but its own parenthetical operational
    // rule ("case-insensitive contains 'only'/'auth'/'admin'/'owner'/'role'/
    // 'guard'") is what this module implements literally, and "restricted"
    // contains none of those substrings. Same category of gap as
    // OpenZeppelin's `initializer` modifier — see modifiers.ts doc comment.
    expect(isProtectiveModifierName('restricted')).toBe(false);
  });

  it('rejects an unrelated modifier name', () => {
    expect(isProtectiveModifierName('whenNotPaused')).toBe(false);
  });
});

describe('hasProtectiveModifier', () => {
  it('true if any modifier in the list is protective', () => {
    expect(hasProtectiveModifier(['whenNotPaused', 'onlyOwner'])).toBe(true);
  });

  it('false for an empty or unrelated list', () => {
    expect(hasProtectiveModifier([])).toBe(false);
    expect(hasProtectiveModifier(['whenNotPaused'])).toBe(false);
  });
});

describe('hasMsgSenderGuard', () => {
  it('detects require(msg.sender == x)', () => {
    expect(hasMsgSenderGuard([{ stripped: 'require(msg.sender == owner, "not owner");' }])).toBe(
      true,
    );
  });

  it('detects the reversed operand order', () => {
    expect(hasMsgSenderGuard([{ stripped: 'require(owner == msg.sender, "not owner");' }])).toBe(
      true,
    );
  });

  it('detects an if-based guard', () => {
    expect(hasMsgSenderGuard([{ stripped: 'if (msg.sender != owner) revert();' }])).toBe(true);
  });

  it('false when msg.sender is not part of an equality/inequality check', () => {
    expect(hasMsgSenderGuard([{ stripped: 'balances[msg.sender] += amount;' }])).toBe(false);
  });

  it('false for an empty body', () => {
    expect(hasMsgSenderGuard([])).toBe(false);
  });
});

describe('hasReentrancyGuardModifier', () => {
  it('recognizes nonReentrant', () => {
    expect(hasReentrancyGuardModifier(['nonReentrant'])).toBe(true);
  });

  it('is case-insensitive and substring-based', () => {
    expect(hasReentrancyGuardModifier(['NoReentrantCalls'])).toBe(true);
  });

  it('false for unrelated modifiers', () => {
    expect(hasReentrancyGuardModifier(['onlyOwner', 'whenNotPaused'])).toBe(false);
  });
});
