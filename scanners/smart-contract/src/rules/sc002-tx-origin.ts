/**
 * SC002 — authorization via tx.origin.
 *
 * Fires when `tx.origin` appears inside a `require`/`assert`/`if` condition,
 * or is assigned to a variable (a common precursor to using it for auth a
 * few lines later). `msg.sender` is the correct alternative and is simply
 * never matched by these patterns — there is no separate "negative" check
 * needed.
 *
 * This is a high-confidence rule: `tx.origin` is an unambiguous token, and
 * there is no legitimate authorization use of it in Solidity.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { RuleContext, RuleDefinition } from './types.js';

const TX_ORIGIN_CONDITION_RE = /\b(?:require|assert|if)\s*\([^;{}]*tx\.origin/;
const TX_ORIGIN_ASSIGN_RE = /=\s*tx\.origin\b/;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      for (const bl of fn.body) {
        if (!TX_ORIGIN_CONDITION_RE.test(bl.stripped) && !TX_ORIGIN_ASSIGN_RE.test(bl.stripped))
          continue;
        findings.push(
          createFinding({
            ruleId: 'SC002',
            title: 'Authorization via tx.origin',
            description: `Function '${fn.name}' uses tx.origin in an authorization check or assignment. A malicious contract can relay a call through a legitimate user's transaction to pass this check, since tx.origin is the original EOA regardless of intermediate call layers.`,
            severity: 'high',
            confidence: 'high',
            category: 'smart-contract',
            file: ctx.relPath,
            line: bl.line,
            evidence: redactEvidence(bl.original.trim(), []),
            recommendation: 'Use msg.sender for authorization checks; never tx.origin.',
            references: ['https://swcregistry.io/docs/SWC-115'],
            scanner: 'smart-contract',
            metadata: { function: fn.name },
          }),
        );
      }
    }
  }

  return findings;
}

export const sc002TxOrigin: RuleDefinition = {
  meta: {
    id: 'SC002',
    title: 'Authorization via tx.origin',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'smart-contract',
    description:
      'tx.origin is used inside an authorization condition or assigned for later use in one, which is unsafe against relayed/phished transactions.',
    recommendation: 'Use msg.sender for authorization checks; never tx.origin.',
    references: ['https://swcregistry.io/docs/SWC-115'],
    // Deliberately NOT the SWC-115 registry's own CWE-477 ("Use of Obsolete
    // Function") — tx.origin is not obsolete, and that mapping does not match
    // this weakness. CWE-346 ("Origin Validation Error": the software does not
    // properly verify the source of a communication) is the accurate fit: the
    // bug is trusting tx.origin as a spoofable proxy for "who is calling me".
    compliance: { cwe: ['CWE-346'] },
  },
  evaluate,
};
