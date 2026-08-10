/**
 * Solidity `pragma solidity <constraint>;` version-range analysis.
 *
 * This is a small, self-contained semver-ish evaluator for the subset of the
 * expression grammar Solidity pragmas actually use in practice: a
 * space-separated (AND) list of `<op><major>[.<minor>[.<patch>]]` clauses,
 * optionally split into `||` (OR) groups. Operators: `^`, `~`, `>=`, `>`,
 * `<=`, `<`, `=`, or no operator (exact pin).
 *
 * Heuristic limits (documented per docs/scanner-interface.md rule 8):
 * - `>` / `<` exclusivity is tracked, but a strictly-exclusive lower bound is
 *   treated the same as inclusive at the same value when deciding "does this
 *   allow version X.Y" — the wiggle room within a patch/minor series makes
 *   the distinction immaterial for the major.minor thresholds these rules
 *   care about.
 * - `||` (OR) is supported by taking the loosest bound across groups, but is
 *   rare in real pragmas and only lightly tested here.
 * - Unparsable input never throws; callers get conservative ("don't flag")
 *   answers instead.
 */

export interface VersionBound {
  /** major*1_000_000 + minor*1_000 + patch, for simple numeric comparison. */
  value: number;
  inclusive: boolean;
}

export interface PragmaRange {
  low?: VersionBound;
  high?: VersionBound;
  /** True if the raw text contains `^` or `>=` anywhere (SC009's "floating" trigger). */
  floating: boolean;
  /** False if no clause could be parsed at all. */
  parsedOk: boolean;
}

interface ParsedClause {
  op: '^' | '~' | '>=' | '>' | '<=' | '<' | '=' | '';
  major: number;
  minor: number;
  patch: number;
}

interface Range {
  low?: VersionBound;
  high?: VersionBound;
}

function encode(major: number, minor: number, patch: number): number {
  return major * 1_000_000 + minor * 1_000 + patch;
}

const VERSION_08 = encode(0, 8, 0);

const CLAUSE_RE = /(\^|~|>=|<=|>|<|=)?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?/g;

/** Parse the individual version clauses out of one AND-group of a pragma constraint. */
export function parsePragmaClauses(raw: string): ParsedClause[] {
  const clauses: ParsedClause[] = [];
  for (const m of raw.matchAll(CLAUSE_RE)) {
    const major = Number(m[2]);
    if (!Number.isFinite(major)) continue;
    const op = (m[1] ?? '') as ParsedClause['op'];
    const minor = m[3] !== undefined ? Number(m[3]) : 0;
    const patch = m[4] !== undefined ? Number(m[4]) : 0;
    clauses.push({ op, major, minor, patch });
  }
  return clauses;
}

function clauseRange(clause: ParsedClause): Range {
  const v = encode(clause.major, clause.minor, clause.patch);
  switch (clause.op) {
    case '^': {
      const highVal =
        clause.major > 0
          ? encode(clause.major + 1, 0, 0)
          : clause.minor > 0
            ? encode(0, clause.minor + 1, 0)
            : encode(0, 0, clause.patch + 1);
      return { low: { value: v, inclusive: true }, high: { value: highVal, inclusive: false } };
    }
    case '~': {
      const highVal = encode(clause.major, clause.minor + 1, 0);
      return { low: { value: v, inclusive: true }, high: { value: highVal, inclusive: false } };
    }
    case '>=':
      return { low: { value: v, inclusive: true } };
    case '>':
      return { low: { value: v, inclusive: false } };
    case '<=':
      return { high: { value: v, inclusive: true } };
    case '<':
      return { high: { value: v, inclusive: false } };
    case '=':
    case '':
    default:
      return { low: { value: v, inclusive: true }, high: { value: v, inclusive: true } };
  }
}

function tighterLow(a?: VersionBound, b?: VersionBound): VersionBound | undefined {
  if (!a) return b;
  if (!b) return a;
  if (a.value !== b.value) return a.value > b.value ? a : b;
  return a.inclusive ? b : a;
}

function tighterHigh(a?: VersionBound, b?: VersionBound): VersionBound | undefined {
  if (!a) return b;
  if (!b) return a;
  if (a.value !== b.value) return a.value < b.value ? a : b;
  return a.inclusive ? b : a;
}

function looserLow(a?: VersionBound, b?: VersionBound): VersionBound | undefined {
  if (!a || !b) return undefined;
  if (a.value !== b.value) return a.value < b.value ? a : b;
  return a.inclusive ? a : b;
}

function looserHigh(a?: VersionBound, b?: VersionBound): VersionBound | undefined {
  if (!a || !b) return undefined;
  if (a.value !== b.value) return a.value > b.value ? a : b;
  return a.inclusive ? a : b;
}

/** Analyze a raw pragma constraint string (without the `pragma solidity`/`;`). */
export function analyzePragma(raw: string): PragmaRange {
  const floating = /\^|>=/.test(raw);
  const orGroups = raw
    .split('||')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  let combinedLow: VersionBound | undefined;
  let combinedHigh: VersionBound | undefined;
  let any = false;

  for (const group of orGroups) {
    const clauses = parsePragmaClauses(group);
    if (clauses.length === 0) continue;
    let range: Range = {};
    for (let i = 0; i < clauses.length; i++) {
      const r = clauseRange(clauses[i]!);
      range =
        i === 0 ? r : { low: tighterLow(range.low, r.low), high: tighterHigh(range.high, r.high) };
    }
    if (!any) {
      combinedLow = range.low;
      combinedHigh = range.high;
      any = true;
    } else {
      combinedLow = looserLow(combinedLow, range.low);
      combinedHigh = looserHigh(combinedHigh, range.high);
    }
  }

  return { low: combinedLow, high: combinedHigh, floating, parsedOk: any };
}

/** `^` or `>=` anywhere in the raw constraint text (SC009). */
export function isFloatingPragma(raw: string): boolean {
  return /\^|>=/.test(raw);
}

/**
 * True if the constraint's upper reach never gets to 0.8.0 — i.e. every
 * version it permits is pre-0.8 (SC009's "outdated" trigger).
 */
export function isOutdatedPragma(raw: string): boolean {
  const { high, parsedOk } = analyzePragma(raw);
  if (!parsedOk || !high) return false;
  return high.inclusive ? high.value < VERSION_08 : high.value <= VERSION_08;
}

/**
 * True if the constraint permits some version strictly below
 * `thresholdMajor.thresholdMinor.0` (used by SC008 with 0.8).
 */
export function allowsPreVersion(
  raw: string,
  thresholdMajor: number,
  thresholdMinor: number,
): boolean {
  const { low, parsedOk } = analyzePragma(raw);
  if (!parsedOk) return false;
  const threshold = encode(thresholdMajor, thresholdMinor, 0);
  if (!low) return true;
  return low.value < threshold;
}
