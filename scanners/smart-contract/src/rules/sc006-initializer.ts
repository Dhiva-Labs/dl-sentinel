/**
 * SC006 — unprotected initializer function.
 *
 * Upgradeable-proxy contracts skip constructors (they don't run in a proxy's
 * storage context) and use a plain function — conventionally named
 * `initialize`/`init`/`setup` — instead. Fires when such a function is
 * public/external with no protective modifier and no msg.sender guard, so
 * anyone can call (or re-call) it.
 *
 * Exact name match only (`initialize`/`init`/`setup`, case-insensitive) —
 * not a substring match — to avoid flagging unrelated functions like
 * `initiateTransfer`.
 *
 * Previously-documented gap, now closed by the contract model: OpenZeppelin's
 * `initializer`/`reinitializer` modifiers are declared in an imported base,
 * which `guards.ts` resolves to "modifier applied but unreadable" and
 * therefore *assumes* protective. A correctly-guarded upgradeable contract is
 * no longer reported. The cost of that is stated plainly rather than hidden:
 * any applied-but-unreadable modifier now silences this rule, whether or not
 * it really guards anything.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { isFunctionGuarded } from '../guards.js';
import { resolveContractIn } from '../resolve.js';
import { lineOriginal } from '../util.js';
import type { RuleContext, RuleDefinition } from './types.js';

const INITIALIZER_NAMES = new Set(['initialize', 'init', 'setup']);

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);

    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      if (!INITIALIZER_NAMES.has(fn.name.toLowerCase())) continue;
      if (fn.visibility !== 'public' && fn.visibility !== 'external') continue;
      if (isFunctionGuarded(resolved, fn)) continue;

      findings.push(
        createFinding({
          ruleId: 'SC006',
          title: 'Unprotected initializer function',
          description: `Function '${fn.name}' looks like a proxy-pattern initializer (used in place of a constructor) but is ${fn.visibility} with no access-control modifier and no msg.sender guard, so anyone can call or re-call it.`,
          severity: 'high',
          confidence: 'medium',
          category: 'smart-contract',
          file: ctx.relPath,
          line: fn.headerLine,
          evidence: redactEvidence(lineOriginal(ctx.file, fn.headerLine), []),
          recommendation:
            "Guard the initializer with an access-control modifier (e.g. onlyOwner) and/or a one-time-call guard (e.g. OpenZeppelin's initializer modifier).",
          references: [],
          scanner: 'smart-contract',
          metadata: { function: fn.name },
        }),
      );
    }
  }

  return findings;
}

export const sc006Initializer: RuleDefinition = {
  meta: {
    id: 'SC006',
    title: 'Unprotected initializer function',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'A function named initialize/init/setup (proxy-pattern constructor substitute) is public/external with no access-control guard: no applied modifier whose body checks the caller (including a one-time-call guard such as OpenZeppelin’s initializer, which is assumed protective when imported) and no msg.sender guard of its own.',
    recommendation:
      'Guard the initializer with an access-control modifier and/or a one-time-call guard.',
    references: [],
    // No SWC reference to anchor to, but the description is a direct, textbook
    // match for "no authorization check guards this sensitive function".
    compliance: { cwe: ['CWE-862'] },
  },
  evaluate,
};
