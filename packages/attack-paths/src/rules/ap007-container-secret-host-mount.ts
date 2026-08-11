/**
 * AP007 — Credential in the container environment plus a host mount.
 *
 * **Conditions (both must hold, in the same service unit).**
 * 1. A credential handed to the container through its environment: `I004`
 *    (image `ENV`/`ARG`), `I014` (compose `environment:`) or `I028`
 *    (Kubernetes container `env:`).
 * 2. A sensitive host mount on the same unit: `I012` (compose bind mount) or
 *    `I022` (Kubernetes `hostPath` volume).
 *
 * **Steps.** entry = the environment credential, escalation = the host mount.
 *
 * **Bound.** At most one path per service unit.
 *
 * **Confidence.** `likely` — the two are linked by the graph when it is
 * available and by the declaring document otherwise. Both halves are declared
 * on the same service in the same file, which is a stronger link than AP001's
 * privilege/exposure pairing needs to establish, because here the mount and
 * the environment belong to one container by construction.
 */
import type { Finding } from '@dl-sentinel/core';
import type { CorrelationContext, CorrelationRule, PathMatch } from '../types.js';
import { unitPhrase } from '../linkage.js';
import { compare, groupBy, sortCandidates } from '../select.js';
import { ENV_SECRET_RULES, HOST_MOUNT_RULES, reasonFor } from '../rule-sets.js';
import { asNote, narrative } from '../text.js';

function find(ctx: CorrelationContext): PathMatch[] {
  const sorted = sortCandidates(ctx.findings);
  const relevant = sorted.filter(
    (finding) => ENV_SECRET_RULES.has(finding.ruleId) || HOST_MOUNT_RULES.has(finding.ruleId),
  );
  const byUnit = groupBy(relevant, (finding) => ctx.linkage.unitOf(finding).id);

  const matches: PathMatch[] = [];
  for (const unitId of [...byUnit.keys()].sort(compare)) {
    const inUnit = byUnit.get(unitId) ?? [];
    const secret: Finding | undefined = inUnit.find((finding) =>
      ENV_SECRET_RULES.has(finding.ruleId),
    );
    const mount: Finding | undefined = inUnit.find((finding) =>
      HOST_MOUNT_RULES.has(finding.ruleId),
    );
    if (secret === undefined || mount === undefined) continue;

    matches.push({
      steps: [
        {
          finding: secret,
          role: 'entry',
          note: asNote(reasonFor(ENV_SECRET_RULES, secret.ruleId)),
        },
        {
          finding: mount,
          role: 'escalation',
          note: asNote(reasonFor(HOST_MOUNT_RULES, mount.ruleId)),
        },
      ],
      confidence: 'likely',
      linkage: unitPhrase(ctx.linkage.unitOf(secret)),
    });
  }
  return matches;
}

export const AP007: CorrelationRule = {
  id: 'AP007',
  title: 'Container credential with a host mount',
  severity: 'critical',
  conditions:
    'An environment-credential finding (I004, I014, I028) and a sensitive host mount ' +
    '(I012, I022) on the same service unit — graph-linked when a graph is available, ' +
    'same-file otherwise.',
  find,
  buildNarrative: (match) =>
    narrative(
      `A credential is placed in the container environment and the host filesystem is mounted into it — both declared in ${match.linkage}.`,
      'Anything that runs inside this container could allow that credential to be read, and the mount could allow the same process to reach host state outside the container boundary.',
      'Move the credential to a secret store and narrow or drop the mount.',
    ),
};
