/**
 * AP005 — Unauthenticated operation over cleartext transport.
 *
 * **Conditions (both must hold, in the same API document).**
 * 1. `A001` (no effective authentication) or `A005` (a state-changing
 *    operation with no effective authentication).
 * 2. `A003` — the document declares a plain-http server URL, excluding the
 *    loopback case the API scanner downgrades to `info`.
 *
 * **Steps.** entry = the cleartext transport, impact = the unauthenticated
 * operation (`A005` preferred over `A001`, since a state-changing operation is
 * the sharper of the two).
 *
 * **Bound.** At most one path per API document (`finding.file`).
 *
 * **Confidence.** `likely`. Both halves are read out of the same document by
 * the same scanner, so "same file" here is not co-location — it is one
 * artifact describing one API.
 */
import type { Finding } from '@dl-sentinel/core';
import type { CorrelationContext, CorrelationRule, PathMatch } from '../types.js';
import { compare, groupBy, sortCandidates } from '../select.js';
import { UNAUTHENTICATED_API_RULES, isCleartextTransport, reasonFor } from '../rule-sets.js';
import { asNote, narrative } from '../text.js';

function find(ctx: CorrelationContext): PathMatch[] {
  const sorted = sortCandidates(ctx.findings);
  const byFile = groupBy(
    sorted.filter(
      (finding) => isCleartextTransport(finding) || UNAUTHENTICATED_API_RULES.has(finding.ruleId),
    ),
    (finding) => finding.file,
  );

  const matches: PathMatch[] = [];
  for (const file of [...byFile.keys()].sort(compare)) {
    const inFile = byFile.get(file) ?? [];
    const transport: Finding | undefined = inFile.find(isCleartextTransport);
    // A005 (state-changing) is the sharper signal; fall back to A001.
    const unauthenticated: Finding | undefined =
      inFile.find((finding) => finding.ruleId === 'A005') ??
      inFile.find((finding) => finding.ruleId === 'A001');
    if (transport === undefined || unauthenticated === undefined) continue;

    matches.push({
      steps: [
        {
          finding: transport,
          role: 'entry',
          note: asNote('the document declares a plain-http server URL'),
        },
        {
          finding: unauthenticated,
          role: 'impact',
          note: asNote(reasonFor(UNAUTHENTICATED_API_RULES, unauthenticated.ruleId)),
        },
      ],
      confidence: 'likely',
      linkage: `the same API document \`${file}\``,
    });
  }
  return matches;
}

export const AP005: CorrelationRule = {
  id: 'AP005',
  title: 'Unauthenticated operation reachable over cleartext',
  severity: 'high',
  conditions:
    'A001 or A005 together with a non-loopback A003 in the same API document (same finding.file).',
  find,
  buildNarrative: (match) =>
    narrative(
      `An operation with no effective authentication is served over plain http in ${match.linkage}.`,
      'That combination could allow anyone who can reach the network path to call the operation, and could allow anyone who can observe the traffic to read what is sent.',
      'Require authentication on the operation and serve the API only over https.',
    ),
};
