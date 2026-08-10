/**
 * SC001 — reentrancy pattern.
 *
 * Fires when a function makes an external value call and then, LATER in the
 * same function body, writes a known state variable — the classic
 * checks-effects-interactions violation. Suppressed entirely when the
 * function carries a modifier whose name contains "reentrant"
 * (case-insensitive), e.g. OpenZeppelin's `nonReentrant`.
 *
 * Heuristic limits:
 * - Line-based ordering: a write that occurs earlier on the SAME physical
 *   line as the external call (or vice versa) is not detected relative to
 *   it. Real formatted Solidity is essentially always one statement per
 *   line, so this is a rare miss, not a rare false alarm — the trade-off is
 *   deliberate (prefer under- over over-reporting).
 * - "Known state variable" means the parser found it as a top-level
 *   contract declaration; a write through an intermediate local
 *   alias/pointer is not traced.
 * - Only the first qualifying call and first qualifying write after it are
 *   reported — one finding per function, not one per write.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { hasReentrancyGuardModifier } from '../modifiers.js';
import { findStateWrite } from '../statevars.js';
import type { RuleContext, RuleDefinition } from './types.js';

const EXTERNAL_CALL_RE = /\.call\s*[({]|\.send\s*\(|\.transfer\s*\(/;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const stateVarNames = contract.stateVariables.map((v) => v.name);
    if (stateVarNames.length === 0) continue;

    for (const fn of contract.functions) {
      if (!fn.hasBody || fn.body.length === 0) continue;
      if (hasReentrancyGuardModifier(fn.modifiers)) continue;

      let callLineIndex = -1;
      for (let i = 0; i < fn.body.length; i++) {
        if (EXTERNAL_CALL_RE.test(fn.body[i]!.stripped)) {
          callLineIndex = i;
          break;
        }
      }
      if (callLineIndex === -1) continue;

      for (let i = callLineIndex + 1; i < fn.body.length; i++) {
        const write = findStateWrite(fn.body[i]!.stripped, stateVarNames);
        if (!write) continue;

        const callLine = fn.body[callLineIndex]!;
        findings.push(
          createFinding({
            ruleId: 'SC001',
            title: 'Reentrancy: state write after external call',
            description: `Function '${fn.name}' makes an external call and only writes state variable '${write.name}' afterward. A malicious callee can re-enter before this contract's own state reflects the effects of the call.`,
            severity: 'high',
            confidence: 'medium',
            category: 'smart-contract',
            file: ctx.relPath,
            line: callLine.line,
            evidence: redactEvidence(callLine.original.trim(), []),
            recommendation:
              'Apply checks-effects-interactions: update state before the external call, and/or guard the function with a reentrancy modifier (e.g. nonReentrant).',
            references: ['https://swcregistry.io/docs/SWC-107'],
            scanner: 'smart-contract',
            metadata: { function: fn.name, stateVariable: write.name, writeLine: fn.body[i]!.line },
          }),
        );
        break;
      }
    }
  }

  return findings;
}

export const sc001Reentrancy: RuleDefinition = {
  meta: {
    id: 'SC001',
    title: 'Reentrancy: state write after external call',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'An external value call (.call/.send/.transfer) is followed, later in the same function, by a write to a known state variable — the classic reentrancy shape.',
    recommendation:
      'Apply checks-effects-interactions (write state before the external call) or guard the function with a reentrancy modifier.',
    references: ['https://swcregistry.io/docs/SWC-107'],
  },
  evaluate,
};
