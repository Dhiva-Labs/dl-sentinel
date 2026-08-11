/**
 * AP001 — Privileged workload on an exposed surface.
 *
 * **Conditions (all must hold).**
 * 1. A privileged / host-namespace infrastructure finding: `I010`, `I011`,
 *    `I013`, `I020`, `I021` or `I025` (`PRIVILEGED_RULES`).
 * 2. In the *same service unit*, an exposed-surface signal that is a
 *    **different** finding — `I006`, `I016`, or host networking (`I011`, and
 *    `I021` only when its `field` metadata is `hostNetwork`) — or, when the
 *    infrastructure graph is available, an `exposes` edge on that unit.
 *
 * A lone host-network finding therefore cannot pair with itself: the two roles
 * must be filled by two different findings, or by one finding plus a
 * graph-observed published port.
 *
 * **Steps.** entry = the exposure, escalation = the privilege, and — when the
 * same unit also mounts the host filesystem (`I012`/`I022`) — impact = that
 * mount.
 *
 * **Bound.** At most one path per service unit.
 *
 * **Confidence.** `likely` only when the infrastructure graph resolved the
 * findings to the same service/workload node. File co-location alone stays
 * `potential`: one compose file can declare several unrelated services, so
 * "same document" is not evidence that the privilege and the exposure belong
 * to the same container.
 */
import type { Finding } from '@dl-sentinel/core';
import type { CorrelationContext, CorrelationRule, MatchStep, PathMatch } from '../types.js';
import { unitPhrase } from '../linkage.js';
import { exposureSurfaces, portClause } from '../exposure.js';
import { compare, groupBy, sortCandidates } from '../select.js';
import { HOST_MOUNT_RULES, PRIVILEGED_RULES, reasonFor } from '../rule-sets.js';
import { asNote, narrative } from '../text.js';

function find(ctx: CorrelationContext): PathMatch[] {
  const sorted = sortCandidates(ctx.findings);
  const unitIdOf = (finding: Finding): string => ctx.linkage.unitOf(finding).id;

  const privilegedByUnit = groupBy(
    sorted.filter((finding) => PRIVILEGED_RULES.has(finding.ruleId)),
    unitIdOf,
  );
  const surfacesByUnit = new Map(
    exposureSurfaces(ctx, { includeCleartextTransport: false }).map((surface) => [
      surface.unit.id,
      surface,
    ]),
  );

  const matches: PathMatch[] = [];
  for (const unitId of [...privilegedByUnit.keys()].sort(compare)) {
    const escalation = (privilegedByUnit.get(unitId) ?? [])[0];
    if (escalation === undefined) continue;

    const unit = ctx.linkage.unitOf(escalation);
    const surface = surfacesByUnit.get(unitId);
    // The exposure must be a *different* finding than the privilege it is
    // paired with; a graph-observed published port is an acceptable stand-in.
    const exposureFinding =
      surface?.finding !== undefined && surface.finding.id !== escalation.id
        ? surface.finding
        : undefined;
    const graphPorts = surface?.ports ?? [];
    if (exposureFinding === undefined && graphPorts.length === 0) continue;

    const steps: MatchStep[] = [];
    if (exposureFinding !== undefined && surface !== undefined) {
      steps.push({ finding: exposureFinding, role: 'entry', note: asNote(surface.reason) });
    }
    steps.push({
      finding: escalation,
      role: 'escalation',
      note: asNote(reasonFor(PRIVILEGED_RULES, escalation.ruleId)),
    });

    const used = new Set(steps.map((step) => step.finding.id));
    const mount = sorted.find(
      (finding) =>
        HOST_MOUNT_RULES.has(finding.ruleId) &&
        !used.has(finding.id) &&
        unitIdOf(finding) === unitId,
    );
    if (mount !== undefined) {
      steps.push({
        finding: mount,
        role: 'impact',
        note: asNote(reasonFor(HOST_MOUNT_RULES, mount.ruleId)),
      });
    }

    matches.push({
      steps,
      confidence: unit.graphLinked ? 'likely' : 'potential',
      linkage: unitPhrase(unit),
      ...(surface !== undefined && graphPorts.length > 0 ? { graphNote: portClause(surface) } : {}),
    });
  }
  return matches;
}

export const AP001: CorrelationRule = {
  id: 'AP001',
  title: 'Privileged workload on an exposed surface',
  severity: 'critical',
  conditions:
    'A privileged/host-namespace infra finding (I010, I011, I013, I020, I021, I025) and a ' +
    'separate exposed-surface signal (I006, I016, host networking, or a graph `exposes` edge) ' +
    'resolved to the same service unit.',
  find,
  buildNarrative: (match) => {
    const hasMount = match.steps.some((step) => step.role === 'impact');
    return narrative(
      `A container that is not separated from its host sits on an exposed surface: the privilege and the exposure are declared in ${match.linkage}.`,
      match.graphNote ?? '',
      hasMount
        ? 'Together with the host filesystem mounted into it, a foothold in this container could allow an attacker to read or change host state rather than staying confined.'
        : 'A foothold in this container could allow an attacker to act with host-level privilege rather than staying confined to the container.',
      'Review whether the exposure is intended and whether the privilege can be dropped.',
    );
  },
};
