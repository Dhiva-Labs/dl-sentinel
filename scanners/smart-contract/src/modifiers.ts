/**
 * Shared access-control heuristics used by SC001/SC005/SC006/SC007.
 *
 * Per the rule catalog: a modifier "counts as protection" if its name
 * case-insensitively contains one of a fixed set of substrings. This is a
 * name-only heuristic — we never resolve what a modifier's body actually
 * does, so a modifier named `onlyOwner` that (incorrectly) has an empty body
 * would still be treated as protective. That is a deliberate, documented
 * trade-off for a source-text scanner with no compiler behind it.
 *
 * Known gaps (both flagged in the handover, neither silently special-cased
 * because the substring list is given explicitly and shared across three
 * rules):
 * - OpenZeppelin's `initializer`/`reinitializer` modifiers (the standard
 *   guard for upgradeable-proxy initializer functions) do not contain any of
 *   the recognized substrings, so SC006 can false-positive on a
 *   correctly-guarded upgradeable contract.
 * - The mission brief's own prose lists "restricted" alongside onlyOwner/
 *   auth as an example protective name, but "restricted" itself contains
 *   none of the six recognized substrings — its worked example and its
 *   operational rule disagree. This module implements the literal
 *   operational rule (the substring list).
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

const REENTRANCY_MODIFIER_RE = /reentrant/i;

export function hasReentrancyGuardModifier(modifiers: readonly string[]): boolean {
  return modifiers.some((m) => REENTRANCY_MODIFIER_RE.test(m));
}
