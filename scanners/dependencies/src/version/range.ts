/**
 * Generic, ecosystem-agnostic matching engine shared by every version
 * comparator. Operates over any comparable type `T` via an injected
 * `compare` function, so the same logic backs npm/Cargo semver, pip's
 * dotted-int versions, and Go versions without duplication.
 */

import type { AffectedRange } from '../types.js';

export type MatchOutcome = 'vulnerable-exact' | 'vulnerable-range' | 'clear' | 'unknown';

export interface MatchResult {
  outcome: MatchOutcome;
  /** The fixed version from whichever advisory range matched, when known. */
  fixedVersion?: string;
}

/** A bound on one side of an interval. `value: null` means unbounded. */
export interface Bound<T> {
  value: T | null;
  inclusive: boolean;
}

/** True if the closed/open intervals [aLow,aHigh] and [bLow,bHigh] overlap. */
export function boundsOverlap<T>(
  aLow: Bound<T>,
  aHigh: Bound<T>,
  bLow: Bound<T>,
  bHigh: Bound<T>,
  compare: (a: T, b: T) => number,
): boolean {
  if (aHigh.value !== null && bLow.value !== null) {
    const cmp = compare(aHigh.value, bLow.value);
    if (cmp < 0) return false;
    if (cmp === 0 && !(aHigh.inclusive && bLow.inclusive)) return false;
  }
  if (bHigh.value !== null && aLow.value !== null) {
    const cmp = compare(bHigh.value, aLow.value);
    if (cmp < 0) return false;
    if (cmp === 0 && !(bHigh.inclusive && aLow.inclusive)) return false;
  }
  return true;
}

/**
 * Match one exact, resolved version against a list of advisory ranges.
 * `parseVersion` must return `null` for anything not confidently parseable
 * (prerelease/build metadata, malformed tokens) — such input is treated as
 * unknown, never as a match. A range whose own `introduced`/`fixed` bound
 * fails to parse is skipped (unknown for that range only); the overall
 * result is only 'unknown' if no other range produced a definite match.
 */
export function matchExact<T>(
  versionStr: string,
  ranges: readonly AffectedRange[],
  parseVersion: (s: string) => T | null,
  compare: (a: T, b: T) => number,
): MatchResult {
  const version = parseVersion(versionStr);
  if (version === null) return { outcome: 'unknown' };

  let sawUnknown = false;
  for (const range of ranges) {
    const introduced = range.introduced === undefined ? undefined : parseVersion(range.introduced);
    if (range.introduced !== undefined && introduced === null) {
      sawUnknown = true;
      continue;
    }
    const fixed = range.fixed === undefined ? undefined : parseVersion(range.fixed);
    if (range.fixed !== undefined && fixed === null) {
      sawUnknown = true;
      continue;
    }
    const aboveIntroduced = introduced == null ? true : compare(version, introduced) >= 0;
    const belowFixed = fixed == null ? true : compare(version, fixed) < 0;
    if (aboveIntroduced && belowFixed) {
      return { outcome: 'vulnerable-exact', fixedVersion: range.fixed };
    }
  }
  return sawUnknown ? { outcome: 'unknown' } : { outcome: 'clear' };
}

export interface RangeSpecLike<T> {
  min?: T;
  minInclusive: boolean;
  max?: T;
  maxInclusive: boolean;
}

/**
 * Match a declared range spec (e.g. an npm caret range or a pip `>=` spec)
 * against a list of advisory ranges by interval overlap. A declared range
 * that can't be parsed at all (compound, wildcard, tag, url, ...) is
 * unknown. Overlap with any advisory range is only ever "possible" exposure
 * — callers should treat this as medium confidence, never high.
 */
export function matchRange<T>(
  spec: string,
  ranges: readonly AffectedRange[],
  parseRangeSpec: (s: string) => RangeSpecLike<T> | null,
  parseVersion: (s: string) => T | null,
  compare: (a: T, b: T) => number,
): MatchResult {
  const declared = parseRangeSpec(spec);
  if (!declared) return { outcome: 'unknown' };
  const declaredLow: Bound<T> = { value: declared.min ?? null, inclusive: declared.minInclusive };
  const declaredHigh: Bound<T> = { value: declared.max ?? null, inclusive: declared.maxInclusive };

  let sawUnknown = false;
  for (const range of ranges) {
    const introduced = range.introduced === undefined ? undefined : parseVersion(range.introduced);
    if (range.introduced !== undefined && introduced === null) {
      sawUnknown = true;
      continue;
    }
    const fixed = range.fixed === undefined ? undefined : parseVersion(range.fixed);
    if (range.fixed !== undefined && fixed === null) {
      sawUnknown = true;
      continue;
    }
    const advisoryLow: Bound<T> = { value: introduced ?? null, inclusive: true };
    const advisoryHigh: Bound<T> = { value: fixed ?? null, inclusive: false };
    if (boundsOverlap(declaredLow, declaredHigh, advisoryLow, advisoryHigh, compare)) {
      return { outcome: 'vulnerable-range', fixedVersion: range.fixed };
    }
  }
  return sawUnknown ? { outcome: 'unknown' } : { outcome: 'clear' };
}
