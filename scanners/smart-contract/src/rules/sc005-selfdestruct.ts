/**
 * SC005 — unprotected selfdestruct.
 *
 * Fires when a public/external function reaches `selfdestruct(`/`suicide(`
 * with no proven or assumed access-control guard (see guards.ts: the
 * modifier's resolved BODY decides, not its name).
 *
 * Heuristic limits:
 * - Reachability is evaluated per-function: a selfdestruct hidden behind an
 *   internal helper is not traced. (The call graph exists now, but widening
 *   reachability would change what this rule reports rather than how
 *   precisely it reports it, so it is left alone.)
 * - A modifier declared in a base contract this file does not contain (an
 *   OpenZeppelin import) is *assumed* protective. That is a guess in favour of
 *   silence; a contract whose only guard is an imported modifier is therefore
 *   never reported here, correct or not.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { isFunctionGuarded } from '../guards.js';
import { resolveContractIn } from '../resolve.js';
import type { RuleContext, RuleDefinition } from './types.js';

const SELFDESTRUCT_RE = /\b(?:selfdestruct|suicide)\s*\(/;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);

    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      if (fn.visibility !== 'public' && fn.visibility !== 'external') continue;
      if (isFunctionGuarded(resolved, fn)) continue;

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
      'A public/external function reaches selfdestruct/suicide with no access-control guard: no applied modifier whose body checks the caller, and no msg.sender guard of its own. A modifier inherited from outside this file is assumed protective, so such contracts are not reported.',
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
