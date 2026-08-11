/**
 * SC016 — privileged address setter without a zero-address check.
 *
 * `transferOwnership(address(0))` is not reversible: the contract's owner
 * slot is set to an address nobody controls, and every owner-only function is
 * bricked for good. The same mistake on a treasury or beneficiary address
 * sends funds to a black hole.
 *
 * Deliberately narrow, because "validate your inputs" as a general rule is a
 * noise machine. All of the following must hold:
 * - the function is public/external and named like a privileged setter
 *   (`set`/`update`/`change`/`transfer` + `owner`/`ownership`/`admin`/
 *   `beneficiary`/`treasury`);
 * - it takes an `address` parameter;
 * - it assigns that exact parameter to a known state variable whose own name
 *   is one of those privileged concepts;
 * - and no line of the body mentions both the parameter and `address(0)`.
 *
 * The last condition is deliberately loose: any `require`, `if`, custom-error
 * revert, or assert that names the parameter alongside `address(0)` counts as
 * a check, in whichever direction it is written. Missing a real check by being
 * too generous is the failure mode this rule prefers.
 *
 * Rated low/low: this is a hardening gap, not an exploitable weakness, and the
 * detection is name-driven.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { resolveContractIn } from '../resolve.js';
import { escapeRegExp } from '../util.js';
import type { RuleContext, RuleDefinition } from './types.js';

const SETTER_NAME_RE =
  /^(?:set|update|change|transfer)(?:owner|ownership|admin|beneficiary|treasury)/i;
const PRIVILEGED_TARGET_RE = /owner|admin|beneficiary|treasury/i;
const ZERO_ADDRESS_RE = /address\s*\(\s*0x?0*\s*\)/;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);
    const privilegedState = new Set(
      resolved.stateVariables
        .filter((v) => !v.isConstantOrImmutable && PRIVILEGED_TARGET_RE.test(v.name))
        .map((v) => v.name),
    );
    if (privilegedState.size === 0) continue;

    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      if (fn.visibility !== 'public' && fn.visibility !== 'external') continue;
      if (!SETTER_NAME_RE.test(fn.name)) continue;

      const addressParams = fn.declaredParameters.filter((p) => p.type === 'address');
      if (addressParams.length === 0) continue;

      for (const param of addressParams) {
        const paramRe = new RegExp(`(?:^|[^.\\w$])${escapeRegExp(param.name)}(?![\\w$])`);
        const validated = fn.body.some(
          (l) => ZERO_ADDRESS_RE.test(l.stripped) && paramRe.test(l.stripped),
        );
        if (validated) continue;

        const assignment = fn.body.find((l) =>
          [...privilegedState].some((name) =>
            new RegExp(
              `(?:^|[^.\\w$])${escapeRegExp(name)}\\s*=\\s*${escapeRegExp(param.name)}\\s*;`,
            ).test(l.stripped),
          ),
        );
        if (!assignment) continue;

        findings.push(
          createFinding({
            ruleId: 'SC016',
            title: 'Privileged address setter without a zero-address check',
            description: `Function '${fn.name}' assigns the caller-supplied address parameter '${param.name}' to privileged contract state without rejecting address(0). Passing the zero address here is irreversible: it permanently removes whoever holds that role, bricking every function gated on it.`,
            severity: 'low',
            confidence: 'low',
            category: 'smart-contract',
            file: ctx.relPath,
            line: assignment.line,
            evidence: redactEvidence(assignment.original.trim(), []),
            recommendation: `Reject the zero address before assigning it, e.g. require(${param.name} != address(0), "zero address").`,
            references: [],
            scanner: 'smart-contract',
            metadata: { function: fn.name, parameter: param.name },
          }),
        );
        break; // one finding per function, not one per parameter
      }
    }
  }

  return findings;
}

export const sc016ZeroAddressCheck: RuleDefinition = {
  meta: {
    id: 'SC016',
    title: 'Privileged address setter without a zero-address check',
    severity: 'low',
    defaultConfidence: 'low',
    category: 'smart-contract',
    description:
      'A public/external owner/admin/beneficiary/treasury setter assigns an address parameter straight to privileged state without ever comparing it against address(0), so a mistyped call can irreversibly remove the role.',
    recommendation:
      'Reject the zero address before assigning it to privileged state (require(newValue != address(0))).',
    references: [],
    // No compliance mapping on purpose: like SC009 and SC012 this is a
    // hygiene/hardening check with no single canonical CWE. "Improper input
    // validation" (CWE-20) is a broad parent that would describe half the
    // catalog, and docs/rules.md binds this field to canonical mappings only.
  },
  evaluate,
};
