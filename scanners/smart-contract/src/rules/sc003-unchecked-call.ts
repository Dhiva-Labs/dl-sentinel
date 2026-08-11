/**
 * SC003 — unchecked low-level call return value.
 *
 * `.call`/`.delegatecall`/`.staticcall`/`.send` all return a boolean success
 * flag that Solidity does NOT auto-revert on. Fires when that flag is
 * neither captured (`(bool ok, ) = x.call(...)` / `bool ok = x.send(...)`),
 * nor the call is wrapped directly in `require(...)`/`assert(...)`/`if(...)`.
 * `.transfer(...)` is excluded entirely — it already reverts on failure.
 *
 * Detection is index-based (checking the text immediately BEFORE the match,
 * anchored to end with `$`) rather than one large regex spanning the whole
 * call expression, specifically to avoid the ambiguity of a greedy receiver
 * pattern accidentally swallowing the `.call` token itself.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { RuleContext, RuleDefinition } from './types.js';

const CALL_LIKE_RE = /[\w$]+(?:\.[\w$]+)*\s*\.\s*(call|delegatecall|staticcall|send)\s*[({]/g;

const CAPTURE_TUPLE_RE = /\(\s*bool\s+\w+\s*(?:,[^)]*)?\)\s*=\s*$/;
const CAPTURE_BOOL_RE = /\bbool\s+\w+\s*=\s*$/;
const WRAP_RE = /\b(?:require|assert|if)\s*\(\s*!?\s*$/;

function isChecked(line: string, matchStart: number): boolean {
  const before = line.slice(0, matchStart);
  return CAPTURE_TUPLE_RE.test(before) || CAPTURE_BOOL_RE.test(before) || WRAP_RE.test(before);
}

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      for (const bl of fn.body) {
        const re = new RegExp(CALL_LIKE_RE.source, 'g');
        let m: RegExpExecArray | null;
        while ((m = re.exec(bl.stripped)) !== null) {
          if (isChecked(bl.stripped, m.index)) continue;
          const kind = m[1]!;
          findings.push(
            createFinding({
              ruleId: 'SC003',
              title: 'Unchecked low-level call return value',
              description: `Function '${fn.name}' calls .${kind}(...) without checking the returned success boolean. A failed call is silently ignored and execution continues as if it succeeded.`,
              severity: 'medium',
              confidence: 'medium',
              category: 'smart-contract',
              file: ctx.relPath,
              line: bl.line,
              evidence: redactEvidence(bl.original.trim(), []),
              recommendation:
                'Capture the returned boolean and require() it, or check it with an if statement, before proceeding.',
              references: ['https://swcregistry.io/docs/SWC-104'],
              scanner: 'smart-contract',
              metadata: { function: fn.name, callKind: kind },
            }),
          );
        }
      }
    }
  }

  return findings;
}

export const sc003UncheckedCall: RuleDefinition = {
  meta: {
    id: 'SC003',
    title: 'Unchecked low-level call return value',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      '.call/.delegatecall/.staticcall/.send is used without checking the returned success boolean (captured, required, or if-checked).',
    recommendation:
      'Capture and check the boolean result before proceeding, or use .transfer(...) where applicable.',
    references: ['https://swcregistry.io/docs/SWC-104'],
    // SWC-104's own "Relationships" entry cites this exact CWE.
    compliance: { cwe: ['CWE-252'] },
  },
  evaluate,
};
