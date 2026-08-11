/**
 * AP002 — Leaked credential in front of a reachable service.
 *
 * **Conditions (all must hold).**
 * 1. A secrets finding at critical or high severity (`S001`-`S022`; the
 *    anchored id pattern keeps `SC0xx` smart-contract rules out).
 * 2. An exposed surface: an infrastructure exposure finding, a graph `exposes`
 *    edge, or a plain-http API surface (`A003`, excluding the loopback case the
 *    API scanner downgrades to `info`).
 *
 * **Steps.** entry = the credential, impact = the exposed surface (absent when
 * the surface is graph-only, in which case the narrative names the port).
 *
 * **Bound.** At most one path per exposed surface — the credential that is
 * closest to that surface represents it, and the narrative says how many other
 * credential findings the repository holds.
 *
 * **Confidence.** `likely` when the credential file and the surface's
 * definition are the same file or share a directory (a compose project reads
 * its `.env` from exactly there); otherwise `potential`.
 */
import type { Finding } from '@dl-sentinel/core';
import type { CorrelationContext, CorrelationRule, MatchStep, PathMatch } from '../types.js';
import { REPO_PHRASE, sameDirectory } from '../linkage.js';
import { exposureSurfaces, portClause, type ExposureSurface } from '../exposure.js';
import { sortCandidates } from '../select.js';
import { isStrongSecret } from '../rule-sets.js';
import { asNote, narrative, plural } from '../text.js';

/**
 * The credential to pair with a surface: one declared in the surface's own
 * file first, then one in the same directory, then the most severe anywhere.
 * Deterministic at every tier because the candidate list is totally ordered.
 */
function pickCredential(
  secrets: readonly Finding[],
  surface: ExposureSurface,
): { finding: Finding; linkage: string; likely: boolean } | undefined {
  const file = surface.finding?.file ?? surface.unit.file;
  const sameFile = secrets.find((secret) => secret.file === file);
  if (sameFile !== undefined) {
    return { finding: sameFile, linkage: `the same file \`${file}\``, likely: true };
  }
  const sameDir = secrets.find((secret) => sameDirectory(secret.file, file));
  if (sameDir !== undefined) {
    return {
      finding: sameDir,
      linkage: `the same directory as \`${file}\``,
      likely: true,
    };
  }
  const anywhere = secrets[0];
  return anywhere === undefined
    ? undefined
    : { finding: anywhere, linkage: REPO_PHRASE, likely: false };
}

function find(ctx: CorrelationContext): PathMatch[] {
  const sorted = sortCandidates(ctx.findings);
  const secrets = sorted.filter(isStrongSecret);
  if (secrets.length === 0) return [];

  const matches: PathMatch[] = [];
  for (const surface of exposureSurfaces(ctx, { includeCleartextTransport: true })) {
    const credential = pickCredential(secrets, surface);
    if (credential === undefined) continue;
    // A credential finding that *is* the surface finding would be one finding
    // playing both roles; the conditions require two distinct signals.
    if (surface.finding?.id === credential.finding.id) continue;

    const steps: MatchStep[] = [
      {
        finding: credential.finding,
        role: 'entry',
        note: asNote('a usable-looking credential is committed to the repository'),
      },
    ];
    if (surface.finding !== undefined) {
      steps.push({ finding: surface.finding, role: 'impact', note: asNote(surface.reason) });
    }

    matches.push({
      steps,
      confidence: credential.likely ? 'likely' : 'potential',
      linkage: credential.linkage,
      facts: { credentials: secrets.length },
      ...(surface.ports.length > 0 ? { graphNote: portClause(surface) } : {}),
    });
  }
  return matches;
}

export const AP002: CorrelationRule = {
  id: 'AP002',
  title: 'Leaked credential and a reachable service',
  severity: 'critical',
  conditions:
    'A critical/high secrets finding (S001-S022) and an exposed surface — an infra exposure ' +
    'finding, a graph `exposes` edge, or a non-loopback plain-http API surface (A003).',
  find,
  buildNarrative: (match) => {
    const others = (match.facts?.['credentials'] ?? 1) - 1;
    return narrative(
      'A credential committed to this repository could allow authenticated access to a service this scan also found reachable.',
      match.graphNote ?? '',
      `The two are associated by ${match.linkage} — where the findings sit, not a confirmed deployment relationship.`,
      others > 0
        ? `${plural(others, 'other credential finding')} in this repository could apply the same way.`
        : '',
      'Rotate the credential and confirm which surface actually accepts it.',
    );
  },
};
