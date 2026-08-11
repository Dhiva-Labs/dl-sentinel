/**
 * Checks-effects-interactions flow analysis, shared by SC001 (single-function
 * reentrancy) and SC013 (cross-function reentrancy).
 *
 * The unit of analysis is an ordered list of *flow events* over one function's
 * body: "an external call happens here", "state is written here". An event is
 * either **direct** (the statement is in this function) or **via** a callee
 * (the statement is inside an in-contract function this one calls, attributed
 * to the call site's line). The reentrancy shape is then a single question:
 * does a write event come after an external-call event?
 *
 * Heuristic limits:
 * - **Line ordering, not control flow.** Events are ordered by body line
 *   index. A branch that makes the "later" write unreachable, or a loop that
 *   reorders execution, is not modeled. Real formatted Solidity is one
 *   statement per line, so intra-line ordering is likewise not modeled — as in
 *   the original SC001.
 * - **Bounded depth.** A callee's effect set is computed over calls reachable
 *   within `maxDepth` hops (`DEFAULT_MAX_DEPTH` = 3). Deeper effects are
 *   invisible: under-reporting, by design.
 * - **Whole-callee attribution.** When a callee both writes state and makes an
 *   external call, the ordering *inside* that callee is not projected onto the
 *   caller — both events land on the same call-site index and therefore never
 *   form a pair. That case belongs to the callee's own SC001 analysis.
 * - **Known state variables only**, as resolved by `resolve.ts` (own +
 *   same-file inherited). A write through a local storage pointer is not
 *   traced.
 */

import type { FunctionInfo, SourceLine } from './model.js';
import { findCallSites, statementLines, type ResolvedContract } from './resolve.js';
import { findStateWrite } from './statevars.js';

/** Value-transferring / arbitrary-callee external call. Same shape SC001 has always used. */
export const EXTERNAL_CALL_RE = /\.call\s*[({]|\.send\s*\(|\.transfer\s*\(/;

/** Traversal bound for cross-function effect propagation. */
export const DEFAULT_MAX_DEPTH = 3;

export interface FlowEvent {
  kind: 'external-call' | 'state-write';
  /** Index into the analyzed function's `body` array. */
  bodyIndex: number;
  /** Set when the effect happens inside this callee rather than directly here. */
  via?: string;
  /** State variable name, for `state-write` events found directly. */
  stateVariable?: string;
}

export interface Sc001Match {
  /** Body index of the external call. */
  callIndex: number;
  /** Body index of the state write that follows it. */
  writeIndex: number;
  stateVariable: string;
}

interface EffectSummary {
  externalCall: boolean;
  stateWrite: boolean;
}

const NO_EFFECT: EffectSummary = { externalCall: false, stateWrite: false };

function directEffects(
  body: readonly SourceLine[],
  stateVarNames: readonly string[],
): EffectSummary {
  let externalCall = false;
  let stateWrite = false;
  for (const line of statementLines(body)) {
    if (!externalCall && EXTERNAL_CALL_RE.test(line.stripped)) externalCall = true;
    if (!stateWrite && findStateWrite(line.stripped, stateVarNames) !== null) stateWrite = true;
    if (externalCall && stateWrite) break;
  }
  return { externalCall, stateWrite };
}

/**
 * What a callee does, directly or through calls of its own, within `maxDepth`
 * hops. Cycle-safe: a function already on the current path contributes
 * nothing further.
 */
export function calleeEffects(
  resolved: ResolvedContract,
  name: string,
  maxDepth: number,
  visited: Set<string> = new Set(),
): EffectSummary {
  if (maxDepth < 0 || visited.has(name)) return NO_EFFECT;
  const target = resolved.functions.get(name);
  if (!target?.fn.hasBody) return NO_EFFECT;

  visited.add(name);
  const own = directEffects(target.fn.body, resolved.stateVariableNames);
  let externalCall = own.externalCall;
  let stateWrite = own.stateWrite;

  if (maxDepth > 0 && !(externalCall && stateWrite)) {
    for (const callee of resolved.callGraph.get(name) ?? []) {
      const deeper = calleeEffects(resolved, callee, maxDepth - 1, visited);
      externalCall = externalCall || deeper.externalCall;
      stateWrite = stateWrite || deeper.stateWrite;
      if (externalCall && stateWrite) break;
    }
  }

  return { externalCall, stateWrite };
}

/**
 * Every flow event in `fn`, in body order. Direct events come before `via`
 * events at the same index, which only matters for tie-breaking and never
 * produces a pair (pairs require a strictly later index).
 */
export function flowEvents(
  resolved: ResolvedContract,
  fn: FunctionInfo,
  maxDepth: number = DEFAULT_MAX_DEPTH,
): FlowEvent[] {
  if (!fn.hasBody) return [];
  const stateVarNames = resolved.stateVariableNames;
  const events: FlowEvent[] = [];
  const statements = statementLines(fn.body);

  for (let i = 0; i < statements.length; i++) {
    const text = statements[i]!.stripped;
    if (EXTERNAL_CALL_RE.test(text)) {
      events.push({ kind: 'external-call', bodyIndex: i });
    }
    const write = findStateWrite(text, stateVarNames);
    if (write) {
      events.push({ kind: 'state-write', bodyIndex: i, stateVariable: write.name });
    }
  }

  const knownNames = new Set(resolved.functions.keys());
  for (const site of findCallSites(fn.body, knownNames)) {
    if (site.callee === fn.name) continue; // direct recursion adds no new hop
    const effects = calleeEffects(resolved, site.callee, maxDepth - 1);
    if (effects.externalCall) {
      events.push({ kind: 'external-call', bodyIndex: site.bodyIndex, via: site.callee });
    }
    if (effects.stateWrite) {
      events.push({ kind: 'state-write', bodyIndex: site.bodyIndex, via: site.callee });
    }
  }

  events.sort((a, b) => {
    if (a.bodyIndex !== b.bodyIndex) return a.bodyIndex - b.bodyIndex;
    if (a.kind !== b.kind) return a.kind === 'external-call' ? -1 : 1;
    return (a.via ?? '').localeCompare(b.via ?? '');
  });
  return events;
}

/**
 * The classic single-function shape SC001 has always detected: the first
 * external call in the body, and the first direct state write after it.
 * Shared with SC013, which uses it purely to stay out of SC001's territory.
 */
export function findSc001Pattern(
  fn: FunctionInfo,
  stateVarNames: readonly string[],
): Sc001Match | null {
  if (!fn.hasBody) return null;
  const statements = statementLines(fn.body);

  let callIndex = -1;
  for (let i = 0; i < statements.length; i++) {
    if (EXTERNAL_CALL_RE.test(statements[i]!.stripped)) {
      callIndex = i;
      break;
    }
  }
  if (callIndex === -1) return null;

  for (let i = callIndex + 1; i < statements.length; i++) {
    const write = findStateWrite(statements[i]!.stripped, stateVarNames);
    if (write) return { callIndex, writeIndex: i, stateVariable: write.name };
  }
  return null;
}

/**
 * True when the effective flow writes state *before* `callIndex` — directly,
 * or inside a callee invoked before that point (one hop; see SC001's doc
 * comment for why the effects-first shape is treated as compliant even when a
 * later bookkeeping write follows the call).
 */
export function hasEffectiveWriteBefore(
  resolved: ResolvedContract,
  fn: FunctionInfo,
  callIndex: number,
): boolean {
  // Depth 1 = direct callees' own bodies inlined, nothing deeper.
  return flowEvents(resolved, fn, 1).some(
    (e) => e.kind === 'state-write' && e.bodyIndex < callIndex,
  );
}
