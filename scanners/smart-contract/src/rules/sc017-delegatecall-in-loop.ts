/**
 * SC017 — delegatecall inside a loop.
 *
 * The canonical bug is a payable multicall: a `payable` function loops over
 * caller-supplied calldata and `delegatecall`s each entry. Because
 * `delegatecall` preserves `msg.value`, every iteration sees the *same*
 * deposit, so a single payment is counted once per iteration. Contracts that
 * credit `msg.value` have been drained exactly this way.
 *
 * Detection is structural rather than name-based: brace depth is tracked
 * across the function body, and a `delegatecall` is reported when it sits
 * inside an open `for`/`while` body. When the enclosing function is `payable`
 * or the body reads `msg.value`, that is called out in the finding and
 * recorded in metadata — that is the variant with a direct fund-drain path.
 *
 * Heuristic limits:
 * - A brace-less loop body written on a *following* line
 *   (`for (...)\n    target.delegatecall(d);`) is not detected; only the
 *   braced form and the same-line brace-less form are. Under-reporting, as
 *   usual, rather than guessing at statement extents.
 * - Recursion that re-enters a delegatecall is not a loop as far as this rule
 *   is concerned.
 * - The rule says nothing about whether the target is trusted — that is
 *   SC004's job, and a loop over a constant implementation still earns this
 *   finding because the msg.value reuse is independent of the target.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { SourceLine } from '../model.js';
import type { RuleContext, RuleDefinition } from './types.js';

const LOOP_HEADER_RE = /\b(?:for|while)\s*\(/g;
const DELEGATECALL_RE = /\.\s*delegatecall\s*[({]/g;
const MSG_VALUE_RE = /\bmsg\.value\b/;

function positionsOf(text: string, pattern: RegExp): number[] {
  const re = new RegExp(pattern.source, 'g');
  const out: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) out.push(m.index);
  return out;
}

/**
 * Body lines holding a `delegatecall` that is lexically inside a loop.
 * A single pass tracks brace depth; `loopDepths` holds the depths at which a
 * loop body is currently open, and `pendingLoop` covers a loop header whose
 * body has not opened a brace yet (the same-line brace-less form).
 */
function delegatecallsInLoops(body: readonly SourceLine[]): SourceLine[] {
  const hits: SourceLine[] = [];
  let depth = 0;
  const loopDepths: number[] = [];

  for (const line of body) {
    const text = line.stripped;
    const loopStarts = positionsOf(text, LOOP_HEADER_RE);
    const delegateStarts = positionsOf(text, DELEGATECALL_RE);
    if (
      loopStarts.length === 0 &&
      delegateStarts.length === 0 &&
      !text.includes('{') &&
      !text.includes('}')
    ) {
      continue;
    }

    let pendingLoop = false;
    let nextLoop = 0;
    let nextDelegate = 0;
    let reported = false;

    for (let col = 0; col < text.length; col++) {
      if (nextLoop < loopStarts.length && loopStarts[nextLoop] === col) {
        pendingLoop = true;
        nextLoop++;
      }
      if (nextDelegate < delegateStarts.length && delegateStarts[nextDelegate] === col) {
        nextDelegate++;
        if (!reported && (loopDepths.length > 0 || pendingLoop)) {
          hits.push(line);
          reported = true;
        }
      }

      const ch = text.charAt(col);
      if (ch === '{') {
        depth++;
        if (pendingLoop) {
          loopDepths.push(depth);
          pendingLoop = false;
        }
      } else if (ch === '}') {
        while (loopDepths.length > 0 && loopDepths[loopDepths.length - 1] === depth) {
          loopDepths.pop();
        }
        depth = Math.max(0, depth - 1);
      }
    }
  }

  return hits;
}

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;

      const hits = delegatecallsInLoops(fn.body);
      if (hits.length === 0) continue;

      const readsValue =
        fn.stateMutability === 'payable' || fn.body.some((l) => MSG_VALUE_RE.test(l.stripped));
      const valueNote = readsValue
        ? ' This function is payable or reads msg.value, so each iteration observes the same deposit — a single payment can be credited once per loop iteration.'
        : ' Even without msg.value in play, repeating a delegatecall executes foreign code against this contract’s storage once per iteration.';

      for (const hit of hits) {
        findings.push(
          createFinding({
            ruleId: 'SC017',
            title: 'delegatecall inside a loop',
            description: `Function '${fn.name}' performs a delegatecall inside a loop. delegatecall preserves msg.sender and msg.value across every iteration.${valueNote}`,
            severity: 'high',
            confidence: 'medium',
            category: 'smart-contract',
            file: ctx.relPath,
            line: hit.line,
            evidence: redactEvidence(hit.original.trim(), []),
            recommendation:
              'Do not delegatecall in a loop while relying on msg.value: read the deposit once into a local variable and account for it explicitly, or drop the loop in favour of a single delegated call.',
            references: [],
            scanner: 'smart-contract',
            metadata: { function: fn.name, readsMsgValue: readsValue },
          }),
        );
      }
    }
  }

  return findings;
}

export const sc017DelegatecallInLoop: RuleDefinition = {
  meta: {
    id: 'SC017',
    title: 'delegatecall inside a loop',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'A delegatecall appears inside a for/while body. Because delegatecall preserves msg.value, a payable multicall built this way lets one deposit be counted once per iteration.',
    recommendation:
      'Avoid delegatecall in a loop when msg.value matters; capture the deposit once and account for it explicitly.',
    references: [],
    // No compliance mapping: the weakness is the reuse of msg.value across
    // iterations, which has no single canonical CWE. CWE-829 belongs to SC004
    // (untrusted delegatecall target), which is a different problem and fires
    // independently when the target is not constant.
  },
  evaluate,
};
