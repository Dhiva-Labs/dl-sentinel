/**
 * Ecosystem dispatch for the comparator: picks the right parse/compare pair
 * for the dependency's ecosystem and delegates to the generic engine in
 * range.ts. This is the single entry point scan.ts uses to decide whether a
 * DependencyRecord is affected by an Advisory, and at what confidence.
 */

import type { AffectedRange, Ecosystem, VersionKind } from '../types.js';
import { comparePipVersion, parsePipRange, parsePipVersion } from './pip.js';
import { compareGoVersion, parseGoVersion } from './go.js';
import { matchExact, matchRange, type MatchResult } from './range.js';
import { compareSemVer, parseSemVer, parseSemVerRange } from './semver.js';

export type { MatchOutcome, MatchResult } from './range.js';

export interface MatchQuery {
  ecosystem: Ecosystem;
  version: string;
  versionKind: VersionKind;
}

/**
 * Decide whether `query` (an installed version or a declared range) falls
 * inside any of `ranges`. Returns 'unknown' rather than guessing whenever
 * the version or range spec isn't confidently parseable.
 */
export function matchAffected(query: MatchQuery, ranges: readonly AffectedRange[]): MatchResult {
  if (ranges.length === 0) return { outcome: 'clear' };

  switch (query.ecosystem) {
    case 'npm':
      return matchSemverEcosystem(query, ranges, 'exact');
    case 'cargo':
      return matchSemverEcosystem(query, ranges, 'caret');
    case 'pip':
      return matchPip(query, ranges);
    case 'go':
      // go.mod always names one version token; there is no range concept for
      // this ecosystem in this scanner's scope, so versionKind is always
      // 'exact' in practice. Fall through to the exact matcher regardless of
      // the tag, since there is no meaningful "range" parser to fall back to.
      return matchExact(query.version, ranges, parseGoVersion, compareGoVersion);
    default:
      return { outcome: 'unknown' };
  }
}

function matchSemverEcosystem(
  query: MatchQuery,
  ranges: readonly AffectedRange[],
  bareMeans: 'exact' | 'caret',
): MatchResult {
  if (query.versionKind === 'exact') {
    return matchExact(query.version, ranges, parseSemVer, compareSemVer);
  }
  return matchRange(
    query.version,
    ranges,
    (spec) => parseSemVerRange(spec, bareMeans),
    parseSemVer,
    compareSemVer,
  );
}

function matchPip(query: MatchQuery, ranges: readonly AffectedRange[]): MatchResult {
  if (query.versionKind === 'exact') {
    return matchExact(query.version, ranges, parsePipVersion, comparePipVersion);
  }
  return matchRange(query.version, ranges, parsePipRange, parsePipVersion, comparePipVersion);
}
