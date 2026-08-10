/**
 * Minimal, conservative pip/PyPI version support: dotted non-negative
 * integers only (no epochs, pre/post/dev releases, or local version
 * segments — those return `null`, treated as unclear).
 */

const DOTTED_INT_RE = /^\d+(?:\.\d+)*$/;

/** Parse `"2.6.0"` into `[2, 6, 0]`. Anything with a non-numeric segment (`"2.0rc1"`, `"1.0.dev0"`, `"1.0+local"`) returns `null`. */
export function parsePipVersion(input: string): number[] | null {
  const trimmed = input.trim();
  if (!DOTTED_INT_RE.test(trimmed)) return null;
  return trimmed.split('.').map((part) => Number(part));
}

/** Compare two dotted-int version tuples, padding the shorter with zeros. */
export function comparePipVersion(a: readonly number[], b: readonly number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) return av - bv;
  }
  return 0;
}

export interface PipRangeSpec {
  min?: number[];
  minInclusive: boolean;
  max?: number[];
  maxInclusive: boolean;
}

const RANGE_RE = /^(>=|<=|>|<)\s*(\d+(?:\.\d+)*)$/;

/**
 * Parse a single pip range specifier: `>=`, `<=`, `>`, or `<` applied to one
 * dotted-int version. Returns `null` for `==` (callers handle that as an
 * exact pin directly), `~=`, `!=`, comma-compound specs (e.g. ">=1.0,<2.0"),
 * and anything else unclear — conservative by design.
 */
export function parsePipRange(spec: string): PipRangeSpec | null {
  const m = RANGE_RE.exec(spec.trim());
  if (!m) return null;
  const op = m[1];
  const verStr = m[2];
  if (verStr === undefined) return null;
  const version = parsePipVersion(verStr);
  if (!version) return null;
  switch (op) {
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
