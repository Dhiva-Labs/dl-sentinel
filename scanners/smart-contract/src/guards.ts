/**
 * Model-aware access-control analysis: "is this function actually guarded?"
 *
 * This replaces the original name-only modifier heuristic used by SC005,
 * SC006 and SC007 (and is what the new SC014 uses). Instead of asking whether
 * a modifier is *called* something protective, it resolves the modifier to its
 * declaration — in this contract or in a base declared in the same file — and
 * reads its body.
 *
 * Three outcomes, deliberately distinguished:
 *
 * - `proven`   — a guard was demonstrated: the modifier body reverts on a
 *                condition involving the caller, calls a recognized
 *                authorization helper, or calls an in-file helper whose body
 *                compares the caller's identity. This is a *high-certainty
 *                negative*: the rule stays silent and it is right to.
 * - `assumed`  — a modifier is applied but its body cannot be read: it is
 *                declared in a base this file does not contain (an
 *                OpenZeppelin import, typically), or declared body-less
 *                (`modifier onlyOwner() virtual;`). Treated as protected —
 *                under-reporting is the house rule — but this is a *guess*,
 *                and each affected rule's `RuleMeta` says so.
 * - `none`     — no modifier and no in-body caller check, or a modifier whose
 *                body IS readable and provably does no caller check at all
 *                (the `modifier onlyOwner() { _; }` bug). The rule fires.
 *
 * The `none`-on-a-readable-empty-modifier case is the behavior change versus
 * the old name-only heuristic: `modifier onlyOwner() { _; }` used to silence
 * SC005/SC006/SC007 purely because of its name, and now does not. Everything
 * that resolves to a real check — including mapping lookups
 * (`require(wards[msg.sender] == 1)`), role checks
 * (`require(hasRole(ADMIN, _msgSender()))`), and helper indirection
 * (`require(isOwner())`) — still resolves to `proven`.
 *
 * Bounded depth: a modifier or function body is inlined one hop deep (its
 * direct in-contract callees' bodies are read, but not *their* callees).
 */

import {
  hasGuardHelperCall,
  hasMsgSenderGuard,
  hasProtectiveModifier,
  hasSenderConditionCheck,
  hasSenderIdentityComparison,
} from './modifiers.js';
import type { FunctionInfo, SourceLine } from './model.js';
import { findCallSites, statementLines, type ResolvedContract } from './resolve.js';

export type GuardStatus = 'proven' | 'assumed' | 'none';

export interface GuardVerdict {
  status: GuardStatus;
  /** Short machine-ish reason, surfaced in finding metadata. */
  reason: string;
  /** Modifier the verdict came from, when it came from one. */
  modifier?: string;
}

const NO_GUARD: GuardVerdict = { status: 'none', reason: 'no-modifier-no-inline-check' };

/**
 * Bodies of the direct in-contract callees of `body`, one hop only. Takes the
 * RAW body: `findCallSites` blanks the declaration header itself, and blanking
 * it twice would swallow any statement sharing the header's line.
 */
function directCalleeBodies(
  resolved: ResolvedContract,
  body: readonly SourceLine[],
): SourceLine[][] {
  const knownNames = new Set(resolved.functions.keys());
  const bodies: SourceLine[][] = [];
  const seen = new Set<string>();
  for (const site of findCallSites(body, knownNames)) {
    if (seen.has(site.callee)) continue;
    seen.add(site.callee);
    const callee = resolved.functions.get(site.callee);
    if (callee?.fn.hasBody) bodies.push(callee.fn.body);
  }
  return bodies;
}

/**
 * True when a helper's own body demonstrates a caller check. The declaration
 * header is excluded first — a function *named* `_checkOwner` must prove
 * itself by what it does, not by what it is called.
 */
function helperBodyProvesGuard(body: readonly SourceLine[]): boolean {
  const statements = statementLines(body);
  return hasSenderIdentityComparison(statements) || hasGuardHelperCall(statements);
}

/**
 * Verdict for a single modifier name applied to a function.
 * Exported for direct unit testing of the three outcomes.
 */
export function analyzeModifier(resolved: ResolvedContract, modifierName: string): GuardVerdict {
  const found = resolved.modifiers.get(modifierName);

  if (!found || !found.modifier.hasBody) {
    return {
      status: 'assumed',
      reason: found ? 'modifier-declared-without-body' : 'modifier-not-declared-in-file',
      modifier: modifierName,
    };
  }

  const statements = statementLines(found.modifier.body);
  if (
    hasSenderConditionCheck(statements) ||
    hasSenderIdentityComparison(statements) ||
    hasGuardHelperCall(statements)
  ) {
    return { status: 'proven', reason: 'modifier-body-checks-caller', modifier: modifierName };
  }
  if (directCalleeBodies(resolved, found.modifier.body).some(helperBodyProvesGuard)) {
    return { status: 'proven', reason: 'modifier-body-calls-caller-check', modifier: modifierName };
  }

  return { status: 'none', reason: 'modifier-body-has-no-caller-check', modifier: modifierName };
}

/**
 * Whether `fn` is access-controlled, considering (in order): its modifiers'
 * resolved bodies, an explicit `msg.sender` guard in its own body, and a
 * caller check in a helper it directly calls.
 *
 * A `proven` verdict from any one modifier wins outright; otherwise an
 * `assumed` verdict from any modifier is carried, so a function wearing both
 * an unresolvable `initializer` and a body-less local modifier is still
 * treated as protected.
 */
export function functionGuardVerdict(resolved: ResolvedContract, fn: FunctionInfo): GuardVerdict {
  let assumed: GuardVerdict | undefined;

  for (const modifierName of fn.modifiers) {
    const verdict = analyzeModifier(resolved, modifierName);
    if (verdict.status === 'proven') return verdict;
    if (verdict.status === 'assumed' && !assumed) assumed = verdict;
  }

  const statements = fn.hasBody ? statementLines(fn.body) : [];
  if (hasMsgSenderGuard(statements)) {
    return { status: 'proven', reason: 'function-body-checks-caller' };
  }
  if (hasGuardHelperCall(statements)) {
    return { status: 'proven', reason: 'function-body-calls-guard-helper' };
  }
  if (fn.hasBody && directCalleeBodies(resolved, fn.body).some(helperBodyProvesGuard)) {
    return { status: 'proven', reason: 'function-calls-caller-check' };
  }

  if (assumed) return assumed;

  // Last resort: a protective-sounding modifier name that resolution could
  // not attach to any declaration at all. `analyzeModifier` already returns
  // `assumed` for that case, so reaching here with modifiers present means
  // every one of them was read and none checked the caller.
  if (fn.modifiers.length > 0 && hasProtectiveModifier(fn.modifiers)) {
    return { status: 'none', reason: 'protective-name-but-body-has-no-check' };
  }

  return NO_GUARD;
}

/** Convenience: `proven` or `assumed` both count as "do not report". */
export function isFunctionGuarded(resolved: ResolvedContract, fn: FunctionInfo): boolean {
  return functionGuardVerdict(resolved, fn).status !== 'none';
}
