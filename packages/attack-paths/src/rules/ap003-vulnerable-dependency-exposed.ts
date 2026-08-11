/**
 * AP003 — Known-vulnerable dependency behind an exposed surface.
 *
 * **Conditions (both must hold).**
 * 1. A `D001` finding — a dependency with a known advisory.
 * 2. An exposed surface, the same set AP002 accepts (infra exposure finding,
 *    graph `exposes` edge, or a non-loopback `A003`).
 *
 * **Steps.** entry = the exposed surface (absent for a graph-only surface),
 * impact = the vulnerable dependency.
 *
 * **Bound.** At most one path per exposed surface, carrying the most severe
 * `D001` finding.
 *
 * **Confidence.** Always `potential`. Nothing static links a lockfile entry to
 * a listening port: whether the vulnerable code path is reachable from that
 * surface is exactly the question a reviewer has to answer.
 *
 * **Severity.** The `D001` severity, floored at `high` — a reachable service is
 * the context in which an advisory matters most, but the advisory's own rating
 * is never inflated past `critical` or invented.
 */
import type { Finding, Severity } from '@dl-sentinel/core';
import type { CorrelationContext, CorrelationRule, MatchStep, PathMatch } from '../types.js';
import { REPO_PHRASE } from '../linkage.js';
import { exposureSurfaces, portClause } from '../exposure.js';
import { maxSeverity, moreSevere, sortCandidates } from '../select.js';
import { VULNERABLE_DEPENDENCY_RULE } from '../rule-sets.js';
import { asNote, narrative } from '../text.js';

function find(ctx: CorrelationContext): PathMatch[] {
  const sorted = sortCandidates(ctx.findings);
  const vulnerable: Finding | undefined = sorted.find(
    (finding) => finding.ruleId === VULNERABLE_DEPENDENCY_RULE,
  );
  if (vulnerable === undefined) return [];

  const matches: PathMatch[] = [];
  for (const surface of exposureSurfaces(ctx, { includeCleartextTransport: true })) {
    const steps: MatchStep[] = [];
    if (surface.finding !== undefined) {
      steps.push({ finding: surface.finding, role: 'entry', note: asNote(surface.reason) });
    }
    steps.push({
      finding: vulnerable,
      role: 'impact',
      note: asNote('a dependency with a published advisory ships with this project'),
    });
    matches.push({
      steps,
      confidence: 'potential',
      linkage: REPO_PHRASE,
      ...(surface.ports.length > 0 ? { graphNote: portClause(surface) } : {}),
    });
  }
  return matches;
}

export const AP003: CorrelationRule = {
  id: 'AP003',
  title: 'Known-vulnerable dependency behind an exposed surface',
  severity: (match: PathMatch): Severity =>
    moreSevere(
      'high',
      maxSeverity(
        match.steps
          .filter((step) => step.finding.ruleId === VULNERABLE_DEPENDENCY_RULE)
          .map((step) => step.finding),
      ),
    ),
  conditions:
    'A D001 known-vulnerable dependency finding and an exposed surface (infra exposure finding, ' +
    'graph `exposes` edge, or a non-loopback plain-http API surface).',
  find,
  buildNarrative: (match) =>
    narrative(
      'A dependency with a published advisory ships alongside a service this scan found reachable, which could allow the advisory to be reached from outside the deployment.',
      match.graphNote ?? '',
      'Nothing here shows the vulnerable code path is actually served by that surface — the two are only known to be present together in this repository.',
      'Confirm whether the affected package is on the request path before treating this as urgent.',
    ),
};
