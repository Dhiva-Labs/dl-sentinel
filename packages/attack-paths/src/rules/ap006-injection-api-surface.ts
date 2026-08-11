/**
 * AP006 — Injection-class code with an API surface in front of it.
 *
 * **Conditions (both must hold).**
 * 1. At least one injection-class source finding: `C001` (shell), `C002`
 *    (dynamic evaluation) or `C003` (SQL built by concatenation).
 * 2. At least one API-scanner finding (`A001`-`A010`), i.e. this repository
 *    ships an API definition the scanner could read.
 *
 * **Bound — the strict one.** Exactly **one** path, ever. Pairing every
 * injection site with every endpoint would produce a quadratic wall of
 * near-identical paths that says nothing an aggregate does not; the single path
 * carries the most severe injection finding, one API document, and the counts
 * of both in its narrative.
 *
 * **Confidence.** Always `potential`. The analyzer has no call graph from an
 * HTTP handler to the offending line — the co-occurrence is the entire claim.
 *
 * **Severity.** Derived from the two constituent findings, never inflated.
 */
import type { Finding, Severity } from '@dl-sentinel/core';
import type { CorrelationContext, CorrelationRule, PathMatch } from '../types.js';
import { REPO_PHRASE } from '../linkage.js';
import { maxSeverity, sortCandidates } from '../select.js';
import { API_RULE_ID, INJECTION_RULES, reasonFor } from '../rule-sets.js';
import { asNote, narrative, plural } from '../text.js';

function find(ctx: CorrelationContext): PathMatch[] {
  const sorted = sortCandidates(ctx.findings);
  const injections = sorted.filter((finding) => INJECTION_RULES.has(finding.ruleId));
  const apiFindings = sorted.filter((finding) => API_RULE_ID.test(finding.ruleId));
  const injection: Finding | undefined = injections[0];
  const api: Finding | undefined = apiFindings[0];
  if (injection === undefined || api === undefined) return [];

  const apiDocuments = new Set(apiFindings.map((finding) => finding.file)).size;
  return [
    {
      steps: [
        {
          finding: api,
          role: 'entry',
          note: asNote(
            'this repository ships an API definition, so some code is reachable by request',
          ),
        },
        {
          finding: injection,
          role: 'impact',
          note: asNote(reasonFor(INJECTION_RULES, injection.ruleId)),
        },
      ],
      confidence: 'potential',
      linkage: REPO_PHRASE,
      facts: {
        injections: injections.length,
        apiDocuments,
        injectionFiles: new Set(injections.map((finding) => finding.file)).size,
      },
    },
  ];
}

export const AP006: CorrelationRule = {
  id: 'AP006',
  title: 'Injection-class code alongside an API surface',
  severity: (match: PathMatch): Severity => maxSeverity(match.steps.map((step) => step.finding)),
  conditions:
    'At least one C001/C002/C003 injection finding and at least one API-scanner finding. ' +
    'Capped at exactly one aggregate path per report.',
  find,
  buildNarrative: (match) => {
    const injections = match.facts?.['injections'] ?? 1;
    const files = match.facts?.['injectionFiles'] ?? 1;
    const documents = match.facts?.['apiDocuments'] ?? 1;
    return narrative(
      `This repository has ${plural(injections, 'injection-class finding')} across ${plural(files, 'file')} and ${plural(documents, 'API definition')}.`,
      'If any of that code sits on a request path, untrusted input reaching it could allow an interpreter — a shell, an evaluator, or a database — to run something the caller chose.',
      `These findings are connected only by ${REPO_PHRASE}; this path is a single summary rather than one entry per pairing, and it does not claim that any specific endpoint reaches any specific line.`,
      'Trace one representative endpoint to the flagged code to decide whether this is real.',
    );
  },
};
