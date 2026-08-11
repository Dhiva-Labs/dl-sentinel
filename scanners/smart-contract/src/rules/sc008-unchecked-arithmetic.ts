/**
 * SC008 — pre-0.8 unchecked arithmetic.
 *
 * Solidity <0.8 has no built-in overflow/underflow checks. Fires once per
 * contract (not per operation) when: the file's pragma allows a pre-0.8
 * compiler, the contract has no SafeMath usage (`using SafeMath` or
 * `.add(`/`.sub(`/`.mul(`/`.div(`), and at least one function writes a
 * known state variable using arithmetic — either a `+=`/`-=`/`*=` compound
 * assignment, or a plain assignment whose right-hand side contains a binary
 * `+`, `-`, or `*`.
 *
 * The SafeMath check is scanned file-wide rather than per-contract: in a
 * multi-contract file this means SafeMath usage in one contract suppresses
 * SC008 for all contracts in that file. That coarseness is deliberate and
 * matches this rule's already-low confidence rating.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { SourceLine } from '../model.js';
import { allowsPreVersion } from '../pragma.js';
import { findStateWrite, hasBinaryArithmetic, isArithmeticCompoundOp } from '../statevars.js';
import type { RuleContext, RuleDefinition } from './types.js';

const SAFEMATH_USING_RE = /\busing\s+SafeMath\b/i;
const SAFEMATH_CALL_RE = /\.(?:add|sub|mul|div)\s*\(/;

function lineHasStateArithmetic(line: string, stateVarNames: readonly string[]): boolean {
  const write = findStateWrite(line, stateVarNames);
  if (!write) return false;
  if (write.isDelete) return false;
  if (write.isCompound) return isArithmeticCompoundOp(line, write.name);
  return hasBinaryArithmetic(write.rhs ?? '');
}

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  const allowsOld = ctx.file.pragmas.some((p) => allowsPreVersion(p.raw, 0, 8));
  if (!allowsOld) return findings;

  const wholeFileText = ctx.file.lines.map((l) => l.stripped).join('\n');
  if (SAFEMATH_USING_RE.test(wholeFileText) || SAFEMATH_CALL_RE.test(wholeFileText))
    return findings;

  for (const contract of ctx.file.contracts) {
    const stateVarNames = contract.stateVariables.map((v) => v.name);
    if (stateVarNames.length === 0) continue;

    let hit: SourceLine | null = null;
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      for (const bl of fn.body) {
        if (lineHasStateArithmetic(bl.stripped, stateVarNames)) {
          hit = bl;
          break;
        }
      }
      if (hit) break;
    }

    if (hit) {
      findings.push(
        createFinding({
          ruleId: 'SC008',
          title: 'Unchecked arithmetic on a pre-0.8 pragma',
          description: `Contract '${contract.name}' allows compilation with a pre-0.8 Solidity version (no built-in overflow/underflow checks) and performs raw arithmetic on state variables without SafeMath. Shown here is one example line; other similar operations may exist elsewhere in the contract.`,
          severity: 'medium',
          confidence: 'low',
          category: 'smart-contract',
          file: ctx.relPath,
          line: hit.line,
          evidence: redactEvidence(hit.original.trim(), []),
          recommendation:
            'Upgrade to Solidity >=0.8.0 for built-in overflow checks, or use SafeMath consistently for all arithmetic on state variables.',
          references: ['https://swcregistry.io/docs/SWC-101'],
          scanner: 'smart-contract',
          metadata: { contract: contract.name },
        }),
      );
    }
  }

  return findings;
}

export const sc008UncheckedArithmetic: RuleDefinition = {
  meta: {
    id: 'SC008',
    title: 'Unchecked arithmetic on a pre-0.8 pragma',
    severity: 'medium',
    defaultConfidence: 'low',
    category: 'smart-contract',
    description:
      'The pragma allows a pre-0.8 Solidity compiler (no built-in overflow checks) and the contract performs raw arithmetic on state variables without SafeMath.',
    recommendation:
      'Upgrade to Solidity >=0.8.0, or use SafeMath consistently for state-variable arithmetic.',
    references: ['https://swcregistry.io/docs/SWC-101'],
    // More specific than the SWC-101 registry's own CWE-682 ("Incorrect
    // Calculation", a broad parent): CWE-190 is the standard, widely-used CWE
    // for integer overflow/underflow specifically.
    compliance: { cwe: ['CWE-190'] },
  },
  evaluate,
};
