/**
 * SC010 — block timestamp/number as randomness.
 *
 * Fires when `block.timestamp`, `block.number`, or `blockhash(...)` is used
 * in a context that suggests it is feeding a random/lottery/winner/seed
 * selection: either (a) the same line also names one of those concepts or
 * uses modulo arithmetic, or (b) the enclosing function's own name suggests
 * a selection (e.g. `pickWinner`) even if the block-attribute usage is on a
 * different line within it.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { RuleContext, RuleDefinition } from './types.js';

const BLOCK_ENTROPY_RE = /\bblock\.(?:timestamp|number)\b|\bblockhash\s*\(/;
const RANDOM_NAMING_RE = /random|lottery|winner|seed/i;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      const fnNameSuggestsSelection = RANDOM_NAMING_RE.test(fn.name);

      for (const bl of fn.body) {
        if (!BLOCK_ENTROPY_RE.test(bl.stripped)) continue;
        const sameLineNaming = RANDOM_NAMING_RE.test(bl.stripped);
        const sameLineModulo = bl.stripped.includes('%');
        if (!sameLineNaming && !sameLineModulo && !fnNameSuggestsSelection) continue;

        findings.push(
          createFinding({
            ruleId: 'SC010',
            title: 'Weak randomness from block attributes',
            description: `Function '${fn.name}' derives a selection/random value from a block attribute (block.timestamp, block.number, or blockhash), which a miner/validator can influence or predict.`,
            severity: 'medium',
            confidence: 'medium',
            category: 'smart-contract',
            file: ctx.relPath,
            line: bl.line,
            evidence: redactEvidence(bl.original.trim(), []),
            recommendation:
              'Use a verifiable randomness source (e.g. Chainlink VRF) instead of block attributes for anything security-sensitive.',
            references: ['https://swcregistry.io/docs/SWC-120'],
            scanner: 'smart-contract',
            metadata: { function: fn.name },
          }),
        );
      }
    }
  }

  return findings;
}

export const sc010Randomness: RuleDefinition = {
  meta: {
    id: 'SC010',
    title: 'Weak randomness from block attributes',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'block.timestamp/block.number/blockhash is used alongside random/lottery/winner/seed naming or modulo arithmetic feeding a selection.',
    recommendation:
      'Use a verifiable randomness source (e.g. Chainlink VRF) instead of block attributes.',
    references: ['https://swcregistry.io/docs/SWC-120'],
  },
  evaluate,
};
