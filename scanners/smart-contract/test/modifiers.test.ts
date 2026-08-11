import { describe, expect, it } from 'vitest';
import {
  hasGuardHelperCall,
  hasMsgSenderGuard,
  hasProtectiveModifier,
  hasReentrancyGuardModifier,
  hasSenderConditionCheck,
  hasSenderIdentityComparison,
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

describe('hasSenderConditionCheck (modifier-body tier)', () => {
  it('accepts a caller reference anywhere inside a revert-shaped condition', () => {
    expect(hasSenderConditionCheck([{ stripped: 'require(wards[msg.sender] == 1, "no");' }])).toBe(
      true,
    );
    expect(
      hasSenderConditionCheck([{ stripped: 'require(hasRole(ADMIN, _msgSender()), "no");' }]),
    ).toBe(true);
  });

  it('rejects a condition that never mentions the caller', () => {
    expect(hasSenderConditionCheck([{ stripped: 'require(!locked, "reentrant call");' }])).toBe(
      false,
    );
  });

  it('rejects a bare caller reference outside any condition', () => {
    expect(hasSenderConditionCheck([{ stripped: 'balances[msg.sender] += msg.value;' }])).toBe(
      false,
    );
  });
});

describe('hasSenderIdentityComparison (helper-body tier)', () => {
  it('accepts a comparison outside a condition, e.g. a returned expression', () => {
    expect(hasSenderIdentityComparison([{ stripped: 'return msg.sender == owner;' }])).toBe(true);
    expect(hasSenderIdentityComparison([{ stripped: 'return owner != _msgSender();' }])).toBe(true);
  });

  it('rejects a caller reference that is not a comparison', () => {
    expect(hasSenderIdentityComparison([{ stripped: 'balances[msg.sender] += msg.value;' }])).toBe(
      false,
    );
  });
});

describe('hasGuardHelperCall', () => {
  it('recognizes the OpenZeppelin authorization helpers', () => {
    expect(hasGuardHelperCall([{ stripped: '_checkOwner();' }])).toBe(true);
    expect(hasGuardHelperCall([{ stripped: '_checkRole(role);' }])).toBe(true);
  });

  it('recognizes the same shape under other naming', () => {
    expect(hasGuardHelperCall([{ stripped: '_requireCallerIsAdmin();' }])).toBe(true);
    expect(hasGuardHelperCall([{ stripped: 'validateAuthorized(user);' }])).toBe(true);
  });

  it('rejects unrelated helper calls', () => {
    expect(hasGuardHelperCall([{ stripped: '_beforeTokenTransfer(from, to, amount);' }])).toBe(
      false,
    );
    expect(hasGuardHelperCall([{ stripped: '_checkBalance(account);' }])).toBe(false);
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
