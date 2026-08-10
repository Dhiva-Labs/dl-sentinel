/**
 * SC009 — floating or outdated pragma.
 *
 * Floating: the raw constraint text contains `^` or `>=`. Outdated: the
 * constraint's upper reach never gets to 0.8.0 (every version it permits is
 * pre-0.8). Either alone is enough to fire. An exact pin at a recent version
 * (`=0.8.x` or bare `0.8.x`) triggers neither. See pragma.ts for the range
 * arithmetic.
 *
 * High confidence: pragma syntax is unambiguous, so once parsed there is no
 * interpretation ambiguity.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { isFloatingPragma, isOutdatedPragma } from '../pragma.js';
import type { RuleContext, RuleDefinition } from './types.js';

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const p of ctx.file.pragmas) {
    const floating = isFloatingPragma(p.raw);
    const outdated = isOutdatedPragma(p.raw);
    if (!floating && !outdated) continue;

    const reasons: string[] = [];
    if (floating) {
      reasons.push(
        'floating (uses ^ or >=, so different builds/deployments may end up compiled with different compiler versions)',
      );
    }
    if (outdated) {
      reasons.push(
        "outdated (its upper reach never includes Solidity 0.8, missing 0.8's built-in overflow checks and later compiler security fixes)",
      );
    }

    findings.push(
      createFinding({
        ruleId: 'SC009',
        title: 'Floating or outdated pragma',
        description: `Pragma '${p.raw}' is ${reasons.join(' and ')}.`,
        severity: 'low',
        confidence: 'high',
        category: 'smart-contract',
        file: ctx.relPath,
        line: p.line,
        evidence: redactEvidence(p.fullStatement.trim(), []),
        recommendation:
          'Pin the compiler to a single, current, exact version (e.g. "pragma solidity 0.8.24;").',
        references: ['https://swcregistry.io/docs/SWC-103'],
        scanner: 'smart-contract',
        metadata: { floating, outdated },
      }),
    );
  }

  return findings;
}

export const sc009Pragma: RuleDefinition = {
  meta: {
    id: 'SC009',
    title: 'Floating or outdated pragma',
    severity: 'low',
    defaultConfidence: 'high',
    category: 'smart-contract',
    description:
      'The pragma is floating (^ or >=) or outdated (its upper reach never includes Solidity 0.8).',
    recommendation: 'Pin the compiler to a single, current, exact version.',
    references: ['https://swcregistry.io/docs/SWC-103'],
  },
  evaluate,
};
