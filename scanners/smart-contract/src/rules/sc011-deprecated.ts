/**
 * SC011 — deprecated Solidity constructs.
 *
 * Lexically unambiguous, removed-or-discouraged keywords/functions:
 * `suicide(`, `throw;`, implicit `var` declarations, `sha3(`, `.callcode(`.
 * High confidence — these are plain token matches, no structural reasoning
 * involved. One finding per occurrence (not deduped per contract, unlike
 * SC008) since each is independently actionable.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { RuleContext, RuleDefinition } from './types.js';

interface DeprecatedPattern {
  re: RegExp;
  name: string;
  recommendation: string;
}

const DEPRECATED_PATTERNS: DeprecatedPattern[] = [
  {
    re: /\bsuicide\s*\(/,
    name: 'suicide(...)',
    recommendation: 'Use selfdestruct(...) instead of the removed suicide(...) alias.',
  },
  {
    re: /\bthrow\s*;/,
    name: 'throw;',
    recommendation:
      'Use require(...), revert(...), or a custom error instead of the removed throw statement.',
  },
  {
    re: /\bvar\s+[A-Za-z_$][\w$]*\s*=/,
    name: 'var declaration',
    recommendation:
      'Declare the variable with its explicit type instead of the removed var keyword.',
  },
  {
    re: /\bsha3\s*\(/,
    name: 'sha3(...)',
    recommendation: 'Use keccak256(...) instead of the removed sha3(...) alias.',
  },
  {
    re: /\.\s*callcode\s*\(/,
    name: 'callcode(...)',
    recommendation:
      'Use delegatecall(...) instead of the removed callcode(...), with the same target-trust caveats.',
  },
];

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      for (const bl of fn.body) {
        for (const pat of DEPRECATED_PATTERNS) {
          if (!pat.re.test(bl.stripped)) continue;
          findings.push(
            createFinding({
              ruleId: 'SC011',
              title: 'Deprecated Solidity construct',
              description: `Function '${fn.name}' uses the deprecated construct '${pat.name}', which is removed or discouraged in modern Solidity.`,
              severity: 'low',
              confidence: 'high',
              category: 'smart-contract',
              file: ctx.relPath,
              line: bl.line,
              evidence: redactEvidence(bl.original.trim(), []),
              recommendation: pat.recommendation,
              references: ['https://swcregistry.io/docs/SWC-111'],
              scanner: 'smart-contract',
              metadata: { function: fn.name, construct: pat.name },
            }),
          );
        }
      }
    }
  }

  return findings;
}

export const sc011Deprecated: RuleDefinition = {
  meta: {
    id: 'SC011',
    title: 'Deprecated Solidity construct',
    severity: 'low',
    defaultConfidence: 'high',
    category: 'smart-contract',
    description:
      'Use of a removed-or-discouraged construct: suicide(, throw;, var declarations, sha3(, callcode.',
    recommendation:
      'Replace with the modern equivalent (selfdestruct, revert/require, explicit types, keccak256, call).',
    references: ['https://swcregistry.io/docs/SWC-111'],
    // SWC-111's own "Relationships" entry cites this exact CWE.
    compliance: { cwe: ['CWE-477'] },
  },
  evaluate,
};
