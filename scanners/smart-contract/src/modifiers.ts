/**
 * Low-level access-control text predicates.
 *
 * This module holds only the regex/name heuristics. The model-aware decision
 * of whether a *function* is guarded — which resolves a modifier to its
 * declaration (possibly in a base contract) and reads its body — lives in
 * `guards.ts` and is what SC005/SC006/SC007/SC014 actually call.
 *
 * The name-only heuristic below (`isProtectiveModifierName`) is no longer the
 * primary protection test: it is retained as the tie-breaker for a modifier
 * whose declaration this file does not contain, and as the documented
 * fallback shape. Its known gaps stay worth recording:
 * - OpenZeppelin's `initializer`/`reinitializer` modifiers do not contain any
 *   of the recognized substrings. Under `guards.ts` this no longer matters
 *   for an imported OpenZeppelin base — an unresolvable modifier is assumed
 *   protective — but the substring list itself is still the naive rule.
 * - "restricted" contains none of the six substrings even though it reads as
 *   a protective name; that gap likewise now resolves through the modifier's
 *   body rather than its name.
 *
 * Three tiers of sender-check strictness are exported, used in different
 * contexts on purpose:
 * - `hasMsgSenderGuard` (strictest: an explicit `require`/`assert`/`if`
 *   equality against `msg.sender`) is what a *function body* must contain to
 *   count as self-guarding. Unchanged from the original catalog.
 * - `hasSenderConditionCheck` (a revert-shaped condition that mentions
 *   `msg.sender`/`_msgSender()` at all) is applied only to *modifier bodies*,
 *   where guarding is the construct's entire purpose, so
 *   `require(wards[msg.sender] == 1)` correctly counts.
 * - `hasSenderIdentityComparison` (any `msg.sender` identity comparison,
 *   condition or not) is applied only to *helper bodies reached from a
 *   guard*, so `function isOwner() { return msg.sender == owner; }` counts.
 */

import type { SourceLine } from './model.js';

const PROTECTIVE_SUBSTRINGS = ['only', 'auth', 'admin', 'owner', 'role', 'guard'] as const;

export function isProtectiveModifierName(name: string): boolean {
  const lower = name.toLowerCase();
  return PROTECTIVE_SUBSTRINGS.some((s) => lower.includes(s));
}

export function hasProtectiveModifier(modifiers: readonly string[]): boolean {
  return modifiers.some(isProtectiveModifierName);
}

/** `require`/`assert`/`if` referencing `msg.sender` in an equality/inequality check, either operand order. */
const MSG_SENDER_GUARD_RE =
  /\b(?:require|assert|if)\s*\([^;]*?(?:msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender)/;

export function hasMsgSenderGuard(bodyLines: readonly Pick<SourceLine, 'stripped'>[]): boolean {
  return bodyLines.some((l) => MSG_SENDER_GUARD_RE.test(l.stripped));
}

/**
 * A `require`/`assert`/`if`/`revert` condition that mentions the caller at all
 * — `require(wards[msg.sender] == 1)`, `require(hasRole(ADMIN, _msgSender()))`.
 * Applied to modifier bodies only (see the module doc comment).
 */
const SENDER_CONDITION_RE =
  /\b(?:require|assert|if|revert)\s*\([^;]*(?:msg\.sender|_msgSender\s*\(\s*\))/;

export function hasSenderConditionCheck(
  bodyLines: readonly Pick<SourceLine, 'stripped'>[],
): boolean {
  return bodyLines.some((l) => SENDER_CONDITION_RE.test(l.stripped));
}

/**
 * Any identity comparison against the caller, in or out of a condition —
 * `return msg.sender == owner;` included. Applied to helper bodies reached
 * from a guard (see the module doc comment).
 */
const SENDER_IDENTITY_RE =
  /(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)|(?:==|!=)\s*(?:msg\.sender|_msgSender\s*\(\s*\))/;

export function hasSenderIdentityComparison(
  bodyLines: readonly Pick<SourceLine, 'stripped'>[],
): boolean {
  return bodyLines.some((l) => SENDER_IDENTITY_RE.test(l.stripped));
}

/**
 * A call to a conventionally-named authorization helper — OpenZeppelin's
 * `_checkOwner()`/`_checkRole(...)` and the same shape under other naming
 * (`_requireAdmin`, `validateCaller`, `enforceAuthorized`, ...). This is the
 * fallback for when the helper itself is inherited from a base this file does
 * not declare; when the helper IS in the file, its body is read instead.
 */
const GUARD_HELPER_CALL_RE =
  /\b_?(?:check|require|assert|enforce|validate|only)(?:Owner|Ownership|Admin|Role|Auth|Authorized|Authorization|Access|Sender|Caller|Governance|Operator|Minter)\w*\s*\(/i;

export function hasGuardHelperCall(bodyLines: readonly Pick<SourceLine, 'stripped'>[]): boolean {
  return bodyLines.some((l) => GUARD_HELPER_CALL_RE.test(l.stripped));
}

const REENTRANCY_MODIFIER_RE = /reentrant/i;

export function hasReentrancyGuardModifier(modifiers: readonly string[]): boolean {
  return modifiers.some((m) => REENTRANCY_MODIFIER_RE.test(m));
}
