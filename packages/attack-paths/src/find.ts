/**
 * `findAttackPaths` — the package's one entry point.
 *
 * Pure and deterministic: same report (in any finding order) plus the same
 * graph always yields the same array, with the same path ids. Nothing is read
 * from disk, no clock is consulted, and the report is never mutated.
 */
import type { AttackPath, AttackPathStep, Report, Severity } from '@dl-sentinel/core';
import { fingerprint, severityRank } from '@dl-sentinel/core';
import type { InfraGraph } from '@dl-sentinel/scanner-infra';
import { CORRELATION_RULES } from './catalog.js';
import { createLinkage } from './linkage.js';
import { MAX_PATHS_PER_RULE, compare, sortCandidates } from './select.js';
import {
  PATH_CONFIDENCE,
  type CorrelationContext,
  type CorrelationRule,
  type PathMatch,
} from './types.js';

/** 0 = the stronger claim. Paths never reach `high`, so it never ranks. */
function confidenceRank(confidence: AttackPath['confidence']): number {
  return confidence === PATH_CONFIDENCE.likely ? 0 : 1;
}

function toStep(step: PathMatch['steps'][number]): AttackPathStep {
  return {
    findingId: step.finding.id,
    ruleId: step.finding.ruleId,
    file: step.finding.file,
    role: step.role,
    note: step.note,
  };
}

/**
 * Stable path id: the correlation rule id plus a fingerprint of the constituent
 * finding ids. The ids are sorted before hashing so that re-ordering a path's
 * steps (a presentation choice) never changes its identity, while a different
 * set of findings always does.
 */
function pathId(rule: CorrelationRule, match: PathMatch): string {
  const findingIds = match.steps.map((step) => step.finding.id).sort(compare);
  return `${rule.id}:${fingerprint(...findingIds)}`;
}

function severityOf(rule: CorrelationRule, match: PathMatch): Severity {
  return typeof rule.severity === 'function' ? rule.severity(match) : rule.severity;
}

function toPath(rule: CorrelationRule, match: PathMatch): AttackPath {
  return {
    id: pathId(rule, match),
    title: rule.title,
    severity: severityOf(rule, match),
    confidence: PATH_CONFIDENCE[match.confidence],
    steps: match.steps.map(toStep),
    narrative: rule.buildNarrative(match),
  };
}

function comparePaths(a: AttackPath, b: AttackPath): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    confidenceRank(a.confidence) - confidenceRank(b.confidence) ||
    compare(a.id, b.id)
  );
}

/**
 * Correlate a completed report — plus the infrastructure graph when one is
 * available — into candidate attack paths.
 *
 * Every returned path is a *candidate*: a combination of findings that already
 * exist in `report.findings`, worth a reviewer's attention. None of them is a
 * verified exploit, confidence never exceeds `likely`
 * ({@link PATH_CONFIDENCE}), and narratives say "could allow".
 *
 * Passing the graph is what allows same-service linkage; without it, rules that
 * depend on that linkage degrade to `potential` rather than assuming findings
 * in one file belong to one deployment.
 */
export function findAttackPaths(report: Report, graph?: InfraGraph): AttackPath[] {
  const linkage = createLinkage(graph);
  const ctx: CorrelationContext = {
    report,
    findings: sortCandidates(report.findings),
    linkage,
    ...(graph === undefined ? {} : { graph }),
  };

  const paths: AttackPath[] = [];
  const seen = new Set<string>();
  for (const rule of CORRELATION_RULES) {
    const fromRule = rule
      .find(ctx)
      .filter((match) => match.steps.length > 0)
      .map((match) => toPath(rule, match))
      .sort(comparePaths);
    // Each rule is bounded by construction (one path per service unit, per
    // exposed surface, or per document); MAX_PATHS_PER_RULE is the backstop for
    // a repository with a pathological number of those.
    for (const path of fromRule.slice(0, MAX_PATHS_PER_RULE)) {
      if (seen.has(path.id)) continue; // identical finding set matched twice
      seen.add(path.id);
      paths.push(path);
    }
  }

  return paths.sort(comparePaths);
}
