/**
 * Exposed-surface detection shared by AP001/AP002/AP003.
 *
 * "Exposed" here means exactly one of three observed things, never an
 * inference:
 *
 * - an infrastructure finding that says a port or namespace is reachable
 *   (`I006`, `I016`, and host networking via `I011`/`I021` — see
 *   {@link EXPOSURE_RULES});
 * - an `exposes` edge in the infrastructure graph, i.e. a published port the
 *   graph actually parsed out of a compose/Kubernetes/Dockerfile declaration;
 * - for the rules that accept it, a plain-http API surface (`A003`, excluding
 *   the localhost/loopback case the API scanner downgrades to `info`).
 *
 * A graph-derived surface has no finding behind it, so a path built on one
 * carries fewer steps and says so in its narrative — the analyzer will not
 * invent a finding to fill a step.
 */
import type { Finding } from '@dl-sentinel/core';
import type { CorrelationContext } from './types.js';
import type { ServiceUnit } from './linkage.js';
import { compare, sortCandidates } from './select.js';
import { EXPOSURE_RULES, isCleartextTransport, isNetworkExposure, reasonFor } from './rule-sets.js';

/** One reachable surface, attributed to the unit it belongs to. */
export interface ExposureSurface {
  readonly unit: ServiceUnit;
  /** The finding evidencing the exposure — absent for a graph-only surface. */
  readonly finding?: Finding;
  /** Port labels the graph shows this unit publishing (e.g. `5432/tcp`). */
  readonly ports: readonly string[];
  /** Lowercase clause describing the surface, for step notes and narratives. */
  readonly reason: string;
}

export interface ExposureOptions {
  /** Whether a plain-http API surface (`A003`) counts. AP001 says no; AP002/AP003 say yes. */
  readonly includeCleartextTransport: boolean;
}

function reasonForFinding(finding: Finding): string {
  return isCleartextTransport(finding)
    ? 'the API definition declares a plain-http server URL'
    : reasonFor(EXPOSURE_RULES, finding.ruleId);
}

/**
 * Every exposed surface in the report, at most one per service unit (a unit
 * with several exposure findings is still one surface — the highest-severity
 * finding represents it). Sorted by unit id, so callers iterate
 * deterministically.
 */
export function exposureSurfaces(
  ctx: CorrelationContext,
  options: ExposureOptions,
): ExposureSurface[] {
  const byUnit = new Map<string, ExposureSurface>();

  for (const finding of sortCandidates(ctx.findings)) {
    const isSurface =
      isNetworkExposure(finding) ||
      (options.includeCleartextTransport && isCleartextTransport(finding));
    if (!isSurface) continue;
    const unit = ctx.linkage.unitOf(finding);
    if (byUnit.has(unit.id)) continue; // first (most severe) finding represents the unit
    byUnit.set(unit.id, {
      unit,
      finding,
      ports: ctx.linkage.exposedPortsOf(unit),
      reason: reasonForFinding(finding),
    });
  }

  // Graph-only surfaces: a published port with no finding attached to it.
  for (const unit of ctx.linkage.exposedUnits()) {
    if (byUnit.has(unit.id)) continue;
    const ports = ctx.linkage.exposedPortsOf(unit);
    if (ports.length === 0) continue;
    byUnit.set(unit.id, {
      unit,
      ports,
      reason: `the infrastructure graph shows this ${unit.kind} publishing ${ports.join(', ')}`,
    });
  }

  return [...byUnit.values()].sort((a, b) => compare(a.unit.id, b.unit.id));
}

/** Clause naming the ports the graph observed, or `''` when it observed none. */
export function portClause(surface: ExposureSurface): string {
  if (surface.ports.length === 0) return '';
  return `The infrastructure graph shows ${surface.unit.graphLinked ? `\`${surface.unit.label}\`` : 'this surface'} publishing ${surface.ports.join(', ')}.`;
}
