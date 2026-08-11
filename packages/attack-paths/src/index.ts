/**
 * `@dl-sentinel/attack-paths` — attack-path analysis.
 *
 * Contract: docs/architecture.md "## Attack paths", catalog and honesty
 * contract in docs/attack-paths.md. `findAttackPaths(report, graph?)`
 * correlates findings already present in a completed report (and the
 * infrastructure graph when available) into candidate attack chains.
 *
 * The discipline this package exists to hold: it proposes review-worthy
 * combinations, it never claims exploitability, confidence never exceeds
 * `likely`, and narratives say "could allow".
 */
export { findAttackPaths } from './find.js';
export { CORRELATION_RULES, AP001, AP002, AP003, AP004, AP005, AP006, AP007 } from './catalog.js';
export { PATH_CONFIDENCE, pathConfidenceLabel } from './types.js';
export type {
  CorrelationContext,
  CorrelationRule,
  MatchStep,
  PathConfidenceLevel,
  PathMatch,
} from './types.js';
export { createLinkage, sameDirectory, sameGraphUnit, unitPhrase } from './linkage.js';
export type { Linkage, ServiceUnit } from './linkage.js';
export { MAX_PATHS_PER_RULE } from './select.js';
