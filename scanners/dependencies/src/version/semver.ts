/**
 * Minimal, conservative semver support for npm and Cargo. Deliberately not a
 * full semver/range implementation: anything outside the shapes recognized
 * here (x-ranges, "||" alternatives, hyphen ranges, compound space-separated
 * comparators, prerelease/build metadata, tags, git/http/path specifiers)
 * returns `null` so callers treat it as unclear rather than guess.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

const PLAIN_VERSION_RE = /^(\d+)\.(\d+)\.(\d+)$/;

/**
 * Parse a plain `X.Y.Z` version. Returns `null` for anything else, including
 * versions carrying prerelease (`-beta.1`) or build (`+001`) metadata — per
 * the project's conservative-matching rule, such versions are never claimed
 * to match an advisory.
 */
export function parseSemVer(input: string): SemVer | null {
  const m = PLAIN_VERSION_RE.exec(input.trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

/** Compare two plain semvers: negative if a<b, 0 if equal, positive if a>b. */
export function compareSemVer(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

/** What a bare version with no operator prefix means for this ecosystem. */
export type SemVerBareMeans = 'exact' | 'caret';

export interface SemVerRangeSpec {
  min?: SemVer;
  minInclusive: boolean;
  max?: SemVer;
  maxInclusive: boolean;
}

const RANGE_RE = /^(\^|~|>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)$/;

/**
 * Parse a single declared-range spec into a min/max window. Supports exactly
 * one leading operator (`^ ~ >= <= > < =`) or none, applied to one plain
 * version — nothing compound. `bareMeans` controls what a bare version (no
 * operator) is taken to mean: npm treats `"1.2.3"` in package.json as an
 * exact-only match; Cargo treats bare `"1.2.3"` as a caret requirement
 * (`^1.2.3`). Returns `null` for anything the regex doesn't cleanly match —
 * including x-ranges ("1.2.x"), wildcards ("*"), OR ranges ("1.0.0 ||
 * 2.0.0"), hyphen ranges ("1.0.0 - 2.0.0"), compound comparators (">=1.0.0
 * <2.0.0"), tags ("latest"), and non-registry specifiers (git/http/path/
 * workspace urls).
 */
export function parseSemVerRange(
  input: string,
  bareMeans: SemVerBareMeans,
): SemVerRangeSpec | null {
  const m = RANGE_RE.exec(input.trim());
  if (!m) return null;
  const op = m[1];
  const versionStr = m[2];
  if (versionStr === undefined) return null;
  const version = parseSemVer(versionStr);
  if (!version) return null;

  switch (op) {
    case undefined:
      return bareMeans === 'exact' ? exactRange(version) : caretRange(version);
    case '=':
      return exactRange(version);
    case '^':
      return caretRange(version);
    case '~':
      return {
        min: version,
        minInclusive: true,
        max: { major: version.major, minor: version.minor + 1, patch: 0 },
        maxInclusive: false,
      };
    case '>=':
      return { min: version, minInclusive: true, maxInclusive: false };
    case '<=':
      return { max: version, maxInclusive: true, minInclusive: false };
    case '>':
      return { min: version, minInclusive: false, maxInclusive: false };
    case '<':
      return { max: version, maxInclusive: false, minInclusive: false };
    default:
      return null;
  }
}

function exactRange(v: SemVer): SemVerRangeSpec {
  return { min: v, minInclusive: true, max: v, maxInclusive: true };
}

/** Standard node-semver caret semantics: ^1.2.3 <2.0.0, ^0.2.3 <0.3.0, ^0.0.3 <0.0.4. */
function caretRange(v: SemVer): SemVerRangeSpec {
  let max: SemVer;
  if (v.major > 0) max = { major: v.major + 1, minor: 0, patch: 0 };
  else if (v.minor > 0) max = { major: 0, minor: v.minor + 1, patch: 0 };
  else max = { major: 0, minor: 0, patch: v.patch + 1 };
  return { min: v, minInclusive: true, max, maxInclusive: false };
}
