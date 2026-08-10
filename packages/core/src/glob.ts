/**
 * Minimal glob matching for repo-relative posix paths.
 *
 * Semantics (documented in docs/scanner-interface.md):
 * - Patterns are anchored: they match against the full repo-relative path.
 *   Use a leading `**` / `**\/` to match at any depth.
 * - `**` matches any number of path segments (including none when written as
 *   a `**\/` prefix); `*` matches within a segment; `?` matches one non-slash
 *   character; `{a,b}` expands alternatives (non-nested).
 * - A trailing `/` is shorthand for `/**` (the whole directory).
 * - Dotfiles are matched like any other file — a security scanner must not
 *   skip .env and friends.
 * - `createMatcher` applies patterns in order with gitignore-style `!`
 *   negation: the last matching pattern wins.
 */

function escapeRegExpChar(ch: string): string {
  return /[.*+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
}

function expandBraces(pattern: string): string[] {
  const open = pattern.indexOf('{');
  if (open === -1) return [pattern];
  const close = pattern.indexOf('}', open);
  if (close === -1) return [pattern];
  const before = pattern.slice(0, open);
  const body = pattern.slice(open + 1, close);
  const after = pattern.slice(close + 1);
  const out: string[] = [];
  for (const alt of body.split(',')) {
    out.push(...expandBraces(before + alt + after));
  }
  return out;
}

function translate(pattern: string): RegExp {
  let source = '';
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern.charAt(i);
    if (ch === '*') {
      if (pattern.charAt(i + 1) === '*') {
        if (pattern.charAt(i + 2) === '/') {
          // '**/' — zero or more whole segments.
          source += '(?:[^/]*/)*';
          i += 3;
        } else {
          source += '.*';
          i += 2;
        }
      } else {
        source += '[^/]*';
        i += 1;
      }
    } else if (ch === '?') {
      source += '[^/]';
      i += 1;
    } else {
      source += escapeRegExpChar(ch);
      i += 1;
    }
  }
  return new RegExp(`^${source}$`);
}

export function normalizePath(p: string): string {
  let out = p.replace(/\\/g, '/');
  while (out.startsWith('./')) out = out.slice(2);
  while (out.startsWith('/')) out = out.slice(1);
  return out;
}

function normalizePattern(pattern: string): string {
  let out = normalizePath(pattern);
  if (out.endsWith('/')) out += '**';
  return out;
}

/** Compile a single glob (no negation) to a RegExp over normalized paths. */
export function globToRegExp(pattern: string): RegExp {
  const expanded = expandBraces(normalizePattern(pattern));
  if (expanded.length === 1 && expanded[0] !== undefined) {
    return translate(expanded[0]);
  }
  const sources = expanded.map((p) => translate(p).source.replace(/^\^|\$$/g, ''));
  return new RegExp(`^(?:${sources.join('|')})$`);
}

/** True if the path matches the single pattern (negation not supported here). */
export function matchGlob(relPath: string, pattern: string): boolean {
  return globToRegExp(pattern).test(normalizePath(relPath));
}

export type PathMatcher = (relPath: string) => boolean;

/**
 * Compile an ordered pattern list into a matcher with gitignore-style
 * negation: a path is included if the last pattern that matches it is
 * positive, excluded if that pattern is negated, and excluded if nothing
 * matches.
 */
export function createMatcher(patterns: readonly string[]): PathMatcher {
  const compiled = patterns.map((raw) => {
    const negated = raw.startsWith('!');
    const pattern = negated ? raw.slice(1) : raw;
    const regexps = expandBraces(normalizePattern(pattern)).map(translate);
    return { negated, regexps };
  });
  return (relPath: string): boolean => {
    const path = normalizePath(relPath);
    let included = false;
    for (const { negated, regexps } of compiled) {
      if (regexps.some((r) => r.test(path))) {
        included = !negated;
      }
    }
    return included;
  };
}

/** Convenience: does the path match any of the patterns (with negation)? */
export function matchAny(relPath: string, patterns: readonly string[]): boolean {
  return createMatcher(patterns)(relPath);
}
