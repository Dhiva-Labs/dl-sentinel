/**
 * SC012 — access-control setter without an event (narrowed scope).
 *
 * The general "state-changing function without an event" idea was explicitly
 * flagged as a likely flood in the mission brief and dropped in favor of a
 * narrow slice: a public/external function named like `setOwner`/`setAdmin`/
 * `updateOwner`/`changeAdmin`/etc., taking at least one (named) parameter,
 * that never emits an event anywhere in its own body. Everything broader
 * (arbitrary state-changing setters in general) is intentionally NOT
 * implemented — that decision is recorded here rather than silently
 * dropped, per the mission brief.
 *
 * Heuristic limit: only the function's OWN body is checked for `emit`; an
 * event emitted by a helper it calls would not be seen (no call-graph
 * analysis), which is a plausible source of false positives. Given that,
 * this rule is rated low/low.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { lineOriginal } from '../util.js';
import type { RuleContext, RuleDefinition } from './types.js';

const SETTER_NAME_RE = /^(?:set|update|change)(?:owner|admin)$/i;
const EMIT_RE = /\bemit\s+/;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      if (!SETTER_NAME_RE.test(fn.name)) continue;
      if (fn.visibility !== 'public' && fn.visibility !== 'external') continue;
      if (fn.parameters.length === 0) continue;
      if (fn.body.some((bl) => EMIT_RE.test(bl.stripped))) continue;

      findings.push(
        createFinding({
          ruleId: 'SC012',
          title: 'Access-control setter without an event',
          description: `Function '${fn.name}' changes a privileged address (owner/admin) but never emits an event, making the change invisible to off-chain monitoring.`,
          severity: 'low',
          confidence: 'low',
          category: 'smart-contract',
          file: ctx.relPath,
          line: fn.headerLine,
          evidence: redactEvidence(lineOriginal(ctx.file, fn.headerLine), []),
          recommendation:
            'Emit an event (e.g. OwnerChanged(oldOwner, newOwner)) whenever a privileged address is updated.',
          references: [],
          scanner: 'smart-contract',
          metadata: { function: fn.name },
        }),
      );
    }
  }

  return findings;
}

export const sc012SetterEvents: RuleDefinition = {
  meta: {
    id: 'SC012',
    title: 'Access-control setter without an event',
    severity: 'low',
    defaultConfidence: 'low',
    category: 'smart-contract',
    description:
      'A public/external owner/admin address setter (setOwner/setAdmin/updateOwner/changeAdmin/...) never emits an event.',
    recommendation: 'Emit an event whenever a privileged address is updated.',
    references: [],
  },
  evaluate,
};
