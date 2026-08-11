/**
 * SC004 — delegatecall to a non-constant target.
 *
 * `delegatecall` runs the target's code with THIS contract's storage and
 * `msg.sender`; if the target is attacker-influenced, that is a full
 * takeover. Fires unless the receiver resolves to an immutable/constant
 * state variable or a literal address. Always medium confidence, even when
 * the target is a mutable state variable only ever set by access-controlled
 * functions — that guarantee cannot be verified from source text alone, so
 * we say why in the description rather than silently upgrading confidence.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { RuleContext, RuleDefinition } from './types.js';

const DELEGATECALL_RE = /([\w$]+(?:\.[\w$]+)*)\s*\.\s*delegatecall\s*[({]/g;
const HEX_LITERAL_RE = /^(?:address\s*\(\s*)?0x[0-9a-fA-F]+\)?$/;

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const constNames = new Set(
      contract.stateVariables.filter((v) => v.isConstantOrImmutable).map((v) => v.name),
    );
    const mutableStateNames = new Set(
      contract.stateVariables.filter((v) => !v.isConstantOrImmutable).map((v) => v.name),
    );

    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      const paramNames = new Set(fn.parameters);

      for (const bl of fn.body) {
        const re = new RegExp(DELEGATECALL_RE.source, 'g');
        let m: RegExpExecArray | null;
        while ((m = re.exec(bl.stripped)) !== null) {
          const receiverChain = m[1]!;
          const base = receiverChain.split('.')[0]!;

          if (HEX_LITERAL_RE.test(receiverChain.trim())) continue;
          if (constNames.has(base)) continue;

          let reason: string;
          if (paramNames.has(base)) {
            reason = `derives from function parameter '${base}', which callers fully control`;
          } else if (mutableStateNames.has(base)) {
            reason = `is mutable state variable '${base}'; even if every setter is access-controlled, that cannot be verified from source text alone`;
          } else {
            reason = `derives from '${base}', a non-constant expression whose provenance cannot be verified statically`;
          }

          findings.push(
            createFinding({
              ruleId: 'SC004',
              title: 'Delegatecall to non-constant target',
              description: `Function '${fn.name}' performs a delegatecall whose target ${reason}. delegatecall executes the target's code in this contract's own storage context, so an attacker-influenced target is a full compromise.`,
              severity: 'high',
              confidence: 'medium',
              category: 'smart-contract',
              file: ctx.relPath,
              line: bl.line,
              evidence: redactEvidence(bl.original.trim(), []),
              recommendation:
                'Restrict delegatecall targets to an immutable/constant address fixed at deployment, or add strict access control and validation before the call.',
              references: ['https://swcregistry.io/docs/SWC-112'],
              scanner: 'smart-contract',
              metadata: { function: fn.name, target: base },
            }),
          );
        }
      }
    }
  }

  return findings;
}

export const sc004Delegatecall: RuleDefinition = {
  meta: {
    id: 'SC004',
    title: 'Delegatecall to non-constant target',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'delegatecall is used with a target that is not an immutable/constant address, so the executed code cannot be statically verified as trusted.',
    recommendation:
      'Restrict delegatecall targets to an immutable/constant address, or add strict access control and validation before the call.',
    references: ['https://swcregistry.io/docs/SWC-112'],
    // SWC-112's own "Relationships" entry cites this exact CWE.
    compliance: { cwe: ['CWE-829'] },
  },
  evaluate,
};
