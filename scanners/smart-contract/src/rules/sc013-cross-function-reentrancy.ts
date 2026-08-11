/**
 * SC013 — cross-function reentrancy (external call and state write separated
 * by an internal call hop).
 *
 * SC001 only sees the checks-effects-interactions violation when both halves
 * are statements of the same function. The common real-world shape splits
 * them across a helper, in either direction:
 *
 *   function withdraw() external {          function withdraw() external {
 *       payable(msg.sender).transfer(x);        _send(msg.sender, x);   // ext. call
 *       _settle(msg.sender);  // writes             balances[msg.sender] = 0;
 *   }                                       }
 *
 * Both are reported here. The trigger is an external-call flow event followed,
 * strictly later in the entry function's body, by a state-write flow event,
 * where at least one of the two happens inside a callee (`via`). See flow.ts
 * for how those events are derived and for the traversal bound (3 hops).
 *
 * Negatives, in the order they are applied:
 * - `nonReentrant`-style modifier on the ENTRY function suppresses entirely.
 *   A guard on the helper alone does not — the re-entry happens at the entry
 *   point.
 * - If SC001's single-function shape is present in the same function, SC013
 *   stays out of it entirely, whether or not SC001 actually emitted (it may
 *   have been suppressed by its own checks-effects rule). One reentrancy
 *   finding per function, never two.
 * - Checks-effects ordering across the hop: any state write — direct or in a
 *   callee — before the external call means the effects are already settled,
 *   and nothing is reported.
 * - Both halves direct (no `via`) is SC001's territory by definition.
 *
 * Entry points are public/external functions only: an internal helper cannot
 * itself be re-entered from outside, so reporting it would double-count the
 * same call path.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { DEFAULT_MAX_DEPTH, findSc001Pattern, flowEvents } from '../flow.js';
import { hasReentrancyGuardModifier } from '../modifiers.js';
import { resolveContractIn } from '../resolve.js';
import type { RuleContext, RuleDefinition } from './types.js';

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);
    if (resolved.stateVariableNames.length === 0) continue;

    for (const fn of contract.functions) {
      if (!fn.hasBody || fn.body.length === 0) continue;
      if (fn.visibility !== 'public' && fn.visibility !== 'external') continue;
      if (hasReentrancyGuardModifier(fn.modifiers)) continue;
      if (findSc001Pattern(fn, resolved.stateVariableNames) !== null) continue;

      const events = flowEvents(resolved, fn, DEFAULT_MAX_DEPTH);
      const call = events.find((e) => e.kind === 'external-call');
      if (!call) continue;
      if (events.some((e) => e.kind === 'state-write' && e.bodyIndex < call.bodyIndex)) continue;

      const write = events.find((e) => e.kind === 'state-write' && e.bodyIndex > call.bodyIndex);
      if (!write) continue;
      if (!call.via && !write.via) continue;

      const callLine = fn.body[call.bodyIndex]!;
      const writeLine = fn.body[write.bodyIndex]!;
      const callDesc = call.via
        ? `calls '${call.via}', which makes an external call,`
        : 'makes an external call and';
      const writeDesc = write.via
        ? `then calls '${write.via}', which writes contract state`
        : `then writes state variable '${write.stateVariable}'`;

      findings.push(
        createFinding({
          ruleId: 'SC013',
          title: 'Cross-function reentrancy: state write after external call via an internal call',
          description: `Function '${fn.name}' ${callDesc} ${writeDesc}. The external call and the state update are separated by an internal call, so the checks-effects-interactions violation spans two functions: a malicious callee can re-enter before the effects are applied.`,
          severity: 'high',
          confidence: 'medium',
          category: 'smart-contract',
          file: ctx.relPath,
          line: callLine.line,
          evidence: redactEvidence(callLine.original.trim(), []),
          recommendation:
            'Apply checks-effects-interactions across the whole call path: perform every state update (including those done by helper functions) before the external call, and/or guard the entry function with a reentrancy modifier such as nonReentrant.',
          references: ['https://swcregistry.io/docs/SWC-107'],
          scanner: 'smart-contract',
          metadata: {
            function: fn.name,
            writeLine: writeLine.line,
            ...(call.via ? { externalCallVia: call.via } : {}),
            ...(write.via ? { stateWriteVia: write.via } : {}),
          },
        }),
      );
    }
  }

  return findings;
}

export const sc013CrossFunctionReentrancy: RuleDefinition = {
  meta: {
    id: 'SC013',
    title: 'Cross-function reentrancy: state write after external call via an internal call',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'A public/external function makes an external call and updates state afterwards, with the two separated by an internal call hop (either the call or the write happens inside a helper). Suppressed by a nonReentrant-style modifier on the entry function, by checks-effects ordering across the hop, and wherever SC001 already covers the function.',
    recommendation:
      'Perform every state update across the call path before the external call, and/or guard the entry function with a reentrancy modifier.',
    references: ['https://swcregistry.io/docs/SWC-107'],
    // Same weakness as SC001, one call hop further out: SWC-107's own
    // "Relationships" entry cites this exact CWE.
    compliance: { cwe: ['CWE-841'] },
  },
  evaluate,
};
