/**
 * SC007 — unprotected mint.
 *
 * Fires when a function whose name CONTAINS "mint" (substring, case
 * insensitive — deliberately broader than SC006's exact-name match, since
 * real mint functions are named things like `mint`, `mintTo`, `mintBatch`)
 * is public/external with no proven or assumed access-control guard.
 *
 * Protection is decided by guards.ts against the resolved contract, so a
 * `onlyMinter` modifier inherited from a base declared in the same file
 * counts, and a locally-declared `onlyOwner` whose body never checks the
 * caller does not.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { isFunctionGuarded } from '../guards.js';
import { resolveContractIn } from '../resolve.js';
import { lineOriginal } from '../util.js';
import type { RuleContext, RuleDefinition } from './types.js';

const MINT_NAME_RE = /mint/i;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);

    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      if (!MINT_NAME_RE.test(fn.name)) continue;
      if (fn.visibility !== 'public' && fn.visibility !== 'external') continue;
      if (isFunctionGuarded(resolved, fn)) continue;

      findings.push(
        createFinding({
          ruleId: 'SC007',
          title: 'Unprotected mint function',
          description: `Function '${fn.name}' is ${fn.visibility} with no access-control modifier and no msg.sender guard, so anyone can mint arbitrary amounts.`,
          severity: 'high',
          confidence: 'medium',
          category: 'smart-contract',
          file: ctx.relPath,
          line: fn.headerLine,
          evidence: redactEvidence(lineOriginal(ctx.file, fn.headerLine), []),
          recommendation:
            'Restrict minting to an access-controlled role (e.g. onlyOwner/onlyMinter).',
          references: [],
          scanner: 'smart-contract',
          metadata: { function: fn.name },
        }),
      );
    }
  }

  return findings;
}

export const sc007Mint: RuleDefinition = {
  meta: {
    id: 'SC007',
    title: 'Unprotected mint function',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'A function whose name contains "mint" is public/external with no access-control guard: no applied modifier whose body checks the caller, and no msg.sender guard of its own. A modifier inherited from outside this file is assumed protective.',
    recommendation: 'Restrict minting to an access-controlled role (e.g. onlyOwner/onlyMinter).',
    references: [],
    // No SWC reference to anchor to, but the description is a direct, textbook
    // match for "no authorization check guards this sensitive function".
    compliance: { cwe: ['CWE-862'] },
  },
  evaluate,
};
