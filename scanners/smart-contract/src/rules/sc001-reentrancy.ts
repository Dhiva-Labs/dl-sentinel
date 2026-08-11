/**
 * SC001 — reentrancy pattern.
 *
 * Fires when a function makes an external value call and then, LATER in the
 * same function body, writes a known state variable — the classic
 * checks-effects-interactions violation. Suppressed entirely when the
 * function carries a modifier whose name contains "reentrant"
 * (case-insensitive), e.g. OpenZeppelin's `nonReentrant`.
 *
 * Contract-model refinements (see resolve.ts / flow.ts):
 * - "Known state variable" now includes variables inherited from a base
 *   contract declared in the SAME file, not just the contract's own
 *   declarations, so a write to inherited accounting is no longer invisible.
 * - The rule no longer fires when the effective flow already writes state
 *   BEFORE the external call — including a write performed by a helper the
 *   function calls before the call (one hop). That is the checks-effects
 *   -interactions shape, and the trailing write is bookkeeping after the
 *   accounting is settled. Previously a function that wrote state both before
 *   AND after the call was reported; that was a false positive, and this is
 *   the one behavior change to SC001's firing conditions.
 *
 * Heuristic limits:
 * - Line-based ordering: a write that occurs earlier on the SAME physical
 *   line as the external call (or vice versa) is not detected relative to
 *   it. Real formatted Solidity is essentially always one statement per
 *   line, so this is a rare miss, not a rare false alarm — the trade-off is
 *   deliberate (prefer under- over over-reporting).
 * - A write through an intermediate local alias/pointer is not traced.
 * - Only the first qualifying call and first qualifying write after it are
 *   reported — one finding per function, not one per write.
 * - The call and the write must both be statements of THIS function. When
 *   they are separated by an internal call hop, SC013 covers it instead.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { findSc001Pattern, hasEffectiveWriteBefore } from '../flow.js';
import { hasReentrancyGuardModifier } from '../modifiers.js';
import { resolveContractIn } from '../resolve.js';
import type { RuleContext, RuleDefinition } from './types.js';

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);
    const stateVarNames = resolved.stateVariableNames;
    if (stateVarNames.length === 0) continue;

    for (const fn of contract.functions) {
      if (!fn.hasBody || fn.body.length === 0) continue;
      if (hasReentrancyGuardModifier(fn.modifiers)) continue;

      const match = findSc001Pattern(fn, stateVarNames);
      if (!match) continue;
      if (hasEffectiveWriteBefore(resolved, fn, match.callIndex)) continue;

      const callLine = fn.body[match.callIndex]!;
      findings.push(
        createFinding({
          ruleId: 'SC001',
          title: 'Reentrancy: state write after external call',
          description: `Function '${fn.name}' makes an external call and only writes state variable '${match.stateVariable}' afterward. A malicious callee can re-enter before this contract's own state reflects the effects of the call.`,
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
          metadata: {
            function: fn.name,
            stateVariable: match.stateVariable,
            writeLine: fn.body[match.writeIndex]!.line,
          },
        }),
      );
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
    // SWC-107's own "Relationships" entry cites this exact CWE (verified against
    // the SWC Registry's published CWE mapping table).
    compliance: { cwe: ['CWE-841'] },
  },
  evaluate,
};
