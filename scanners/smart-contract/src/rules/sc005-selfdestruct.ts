/**
 * SC005 — unprotected selfdestruct.
 *
 * Fires when a public/external function reaches `selfdestruct(`/`suicide(`
 * with no protective modifier (see modifiers.ts heuristic) and no
 * `msg.sender` guard anywhere in the function body.
 *
 * Heuristic limit: reachability is evaluated per-function only. A
 * selfdestruct hidden behind an internal helper that an unguarded public
 * function calls is not traced (no call-graph analysis in a line-based
 * scanner).
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { hasMsgSenderGuard, hasProtectiveModifier } from '../modifiers.js';
import type { RuleContext, RuleDefinition } from './types.js';

const SELFDESTRUCT_RE = /\b(?:selfdestruct|suicide)\s*\(/;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      if (fn.visibility !== 'public' && fn.visibility !== 'external') continue;
      if (hasProtectiveModifier(fn.modifiers)) continue;
      if (hasMsgSenderGuard(fn.body)) continue;

      for (const bl of fn.body) {
        if (!SELFDESTRUCT_RE.test(bl.stripped)) continue;
        findings.push(
          createFinding({
            ruleId: 'SC005',
            title: 'Unprotected selfdestruct',
            description: `Function '${fn.name}' is ${fn.visibility} and reaches selfdestruct with no access-control modifier and no msg.sender guard, so anyone can destroy the contract and force-send its balance.`,
            severity: 'critical',
            confidence: 'medium',
            category: 'smart-contract',
            file: ctx.relPath,
            line: bl.line,
            evidence: redactEvidence(bl.original.trim(), []),
            recommendation:
              'Guard selfdestruct behind an owner/admin-only modifier or an explicit msg.sender check.',
            references: ['https://swcregistry.io/docs/SWC-106'],
            scanner: 'smart-contract',
            metadata: { function: fn.name },
          }),
        );
      }
    }
  }

  return findings;
}

export const sc005Selfdestruct: RuleDefinition = {
  meta: {
    id: 'SC005',
    title: 'Unprotected selfdestruct',
    severity: 'critical',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'A public/external function reaches selfdestruct/suicide with no access-control modifier and no msg.sender guard.',
    recommendation:
      'Guard selfdestruct behind an owner/admin-only modifier or an explicit msg.sender check.',
    references: ['https://swcregistry.io/docs/SWC-106'],
    // More specific than the SWC-106 registry's own CWE-284 ("Improper Access
    // Control", a broad parent): the finding is precisely "no authorization
    // check at all guards this sensitive function", i.e. CWE-862.
    compliance: { cwe: ['CWE-862'] },
  },
  evaluate,
};
