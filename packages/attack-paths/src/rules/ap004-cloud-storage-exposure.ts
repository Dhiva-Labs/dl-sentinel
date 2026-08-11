/**
 * AP004 — Public bucket plus committed AWS credential.
 *
 * **Conditions (both must hold).**
 * 1. `I031` — a bucket ACL that grants public read.
 * 2. `S001` or `S002` — AWS key material committed to the repository.
 *
 * **Steps.** entry = the public ACL, escalation = the credential.
 *
 * **Bound.** At most one path per `I031` finding, paired with the most severe
 * AWS credential finding.
 *
 * **Confidence.** `likely`, and deliberately not graph-dependent: the
 * infrastructure graph models containers, not cloud IAM, so it has nothing to
 * add here. What makes the pairing strong is that both halves describe the
 * same account's storage — a public bucket declared by this repository and a
 * key for the provider that hosts it.
 */
import type { Finding } from '@dl-sentinel/core';
import type { CorrelationContext, CorrelationRule, PathMatch } from '../types.js';
import { REPO_PHRASE } from '../linkage.js';
import { sortCandidates } from '../select.js';
import { AWS_CREDENTIAL_RULES, PUBLIC_BUCKET_RULE, reasonFor } from '../rule-sets.js';
import { asNote, narrative } from '../text.js';

function find(ctx: CorrelationContext): PathMatch[] {
  const sorted = sortCandidates(ctx.findings);
  const credential: Finding | undefined = sorted.find((finding) =>
    AWS_CREDENTIAL_RULES.has(finding.ruleId),
  );
  if (credential === undefined) return [];

  return sorted
    .filter((finding) => finding.ruleId === PUBLIC_BUCKET_RULE)
    .map((bucket) => ({
      steps: [
        {
          finding: bucket,
          role: 'entry' as const,
          note: asNote('the bucket ACL grants read access to anyone'),
        },
        {
          finding: credential,
          role: 'escalation' as const,
          note: asNote(reasonFor(AWS_CREDENTIAL_RULES, credential.ruleId)),
        },
      ],
      confidence: 'likely' as const,
      linkage: REPO_PHRASE,
    }));
}

export const AP004: CorrelationRule = {
  id: 'AP004',
  title: 'Cloud storage exposure with committed credentials',
  severity: 'critical',
  conditions: 'An I031 public bucket ACL and an AWS credential finding (S001 or S002).',
  find,
  buildNarrative: () =>
    narrative(
      'A bucket declared by this repository grants public read, and AWS key material for the same provider is committed alongside it.',
      'Together they could allow an unauthorized party both to read whatever the bucket holds and to change the bucket configuration itself.',
      'Rotate the key and confirm the ACL is deliberate before assuming the data is non-sensitive.',
    ),
};
