/**
 * Internal data model for attack-path correlation.
 *
 * Contract: docs/architecture.md "## Attack paths" and docs/attack-paths.md.
 * The analyzer proposes review-worthy combinations of findings that already
 * exist in the report — it never claims exploitability, never invents a
 * finding, and never asserts more than "could allow".
 */
import type { AttackPathStep, Confidence, Finding, Report, Severity } from '@dl-sentinel/core';
import type { InfraGraph } from '@dl-sentinel/scanner-infra';
import type { Linkage } from './linkage.js';

/**
 * Assertion strength of a path, in the analyzer's own vocabulary.
 *
 * - `likely` — the constituent findings are linked by something concrete: the
 *   infrastructure graph resolves them to the same service/workload, or they
 *   are declared in the same document.
 * - `potential` — the findings only co-occur in the same repository. Nothing
 *   observed says they belong to the same deployment.
 *
 * There is deliberately no level above `likely`: confirming a chain would
 * require executing it, which this tool never does.
 */
export type PathConfidenceLevel = 'likely' | 'potential';

/**
 * How the two levels land in `AttackPath.confidence` (a core {@link Confidence}).
 * `high` is never produced — that absence is what makes the "never above
 * likely" cap observable in a serialized report, and it is asserted by the
 * package's tests.
 */
export const PATH_CONFIDENCE: Readonly<Record<PathConfidenceLevel, Confidence>> = {
  likely: 'medium',
  potential: 'low',
};

/** The analyzer's own word for a path's confidence, for human-facing output. */
export function pathConfidenceLabel(confidence: Confidence): PathConfidenceLevel {
  return confidence === PATH_CONFIDENCE.likely ? 'likely' : 'potential';
}

/** One step of a candidate chain, still holding the finding it was built from. */
export interface MatchStep {
  /** A finding that is genuinely present in the report being correlated. */
  readonly finding: Finding;
  readonly role: AttackPathStep['role'];
  /** One line saying what this step contributes to the chain. */
  readonly note: string;
}

/** One match of a correlation rule's conditions, before it becomes an `AttackPath`. */
export interface PathMatch {
  /** 1-3 steps, each referencing a real finding. */
  readonly steps: readonly MatchStep[];
  readonly confidence: PathConfidenceLevel;
  /**
   * Narrative-ready phrase naming what links the steps, e.g. "the same compose
   * service `app` (docker-compose.yml)" or "co-located in this repository".
   */
  readonly linkage: string;
  /**
   * Facts a narrative needs that are not carried by the steps themselves —
   * `AP006`'s aggregate counts, for example.
   */
  readonly facts?: Readonly<Record<string, number>>;
  /**
   * Extra clause naming graph-derived context that is not itself a finding,
   * e.g. the port the graph shows the service publishing.
   */
  readonly graphNote?: string;
}

/** Everything a correlation rule may look at. Read-only: rules never mutate the report. */
export interface CorrelationContext {
  readonly report: Report;
  /** The report's findings in a stable order (severity, file, line, ruleId, id). */
  readonly findings: readonly Finding[];
  /** Present only when the caller supplied one; rules must degrade without it. */
  readonly graph?: InfraGraph;
  /** Graph/file linkage helpers. Degrades to file-level linkage with no graph. */
  readonly linkage: Linkage;
}

/**
 * A declared correlation rule. The catalog of these (see `catalog.ts`) is the
 * whole of the analyzer's knowledge: there is no implicit correlation
 * anywhere else.
 */
export interface CorrelationRule {
  /** Namespaced `AP` id, e.g. `AP001`. */
  readonly id: string;
  readonly title: string;
  /**
   * Severity every path from this rule carries: a fixed value, or a function
   * deriving it from the matched findings.
   */
  readonly severity: Severity | ((match: PathMatch) => Severity);
  /**
   * The co-occurrence this rule requires, in one sentence. Mirrored in the
   * docs/attack-paths.md catalog table so the code and the documentation
   * cannot drift.
   */
  readonly conditions: string;
  /**
   * Every match of {@link conditions} in `ctx`. Must be deterministic and
   * bounded — see each rule's own JSDoc for the bound it observes.
   */
  readonly find: (ctx: CorrelationContext) => PathMatch[];
  /** 1-3 sentences, "could allow" phrasing, naming the linkage basis honestly. */
  readonly buildNarrative: (match: PathMatch) => string;
}
