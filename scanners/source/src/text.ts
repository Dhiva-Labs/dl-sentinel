/**
 * Lexical helpers shared by every rule. This is a deliberately lightweight,
 * regex-and-scanning based approximation of source structure -- there is no
 * real parser or AST here. Every function documents the corner cases it does
 * not handle so rule authors (and reviewers) know the boundaries.
 */

import { type Lang, usesSlashStarBlocks, usesTripleQuoteDocstrings } from './language.js';

/**
 * Per-line comment classification for a whole file. `skip[i] === true` means
 * line `i` (0-based) must not be considered for rule matching.
 *
 * Algorithm (documented, intentionally simple):
 *  1. A line whose trimmed text starts with a line-comment marker, a
 *     block-comment opener, a JSDoc-style continuation asterisk, or a
 *     triple-quote is always treated as comment-only, regardless of block
 *     state.
 *  2. In addition, a small amount of block state is tracked across lines so
 *     that plain prose lines inside a slash-star block or a triple-quoted
 *     docstring (lines that don't themselves start with one of the markers
 *     above) are also skipped.
 *
 * This is a line-heuristic, not a tokenizer: it does not handle nested block
 * comments, a block comment that both opens and closes with real code after
 * it on the same line, a trailing end-of-line block comment after code, or a
 * string literal that happens to contain comment-like punctuation. Those are
 * accepted gaps -- see docs/development.md's "precision over recall"
 * guidance for why we did not chase full tokenization.
 */
export function buildCommentMask(lines: readonly string[], lang: Lang): boolean[] {
  const mask: boolean[] = new Array(lines.length).fill(false);
  const slashStar = usesSlashStarBlocks(lang);
  const tripleQuote = usesTripleQuoteDocstrings(lang);
  let inSlashStarBlock = false;
  let inTripleQuoteBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = (lines[i] ?? '').trim();
    const blockActiveAtStart = inSlashStarBlock || inTripleQuoteBlock;
    const startsWithMarker =
      trimmed.startsWith('//') ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('/*') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('"""') ||
      trimmed.startsWith("'''");

    mask[i] = blockActiveAtStart || startsWithMarker;

    if (slashStar) {
      if (!inSlashStarBlock) {
        const openIdx = trimmed.indexOf('/*');
        if (openIdx !== -1) {
          const closeIdx = trimmed.indexOf('*/', openIdx + 2);
          if (closeIdx === -1) inSlashStarBlock = true;
        }
      } else if (trimmed.includes('*/')) {
        inSlashStarBlock = false;
      }
    }

    if (tripleQuote) {
      const tripleCount =
        (trimmed.match(/"""/g) ?? []).length + (trimmed.match(/'''/g) ?? []).length;
      if (tripleCount % 2 === 1) {
        inTripleQuoteBlock = !inTripleQuoteBlock;
      }
    }
  }

  return mask;
}

/** True if `token` is a single fully-quoted literal with no interpolation. */
export function isFullyQuotedLiteral(token: string): boolean {
  const t = token.trim();
  if (t.length < 2) return false;
  const quote = t[0];
  if (quote !== '"' && quote !== "'" && quote !== '`') return false;
  if (t[t.length - 1] !== quote) return false;
  const inner = t.slice(1, -1);
  if (quote === '`' && (inner.includes('${') || inner.includes('\n'))) return false;
  // Reject if an unescaped quote character appears before the end (would mean
  // the literal actually ends earlier and what follows isn't part of it).
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '\\') {
      i++;
      continue;
    }
    if (inner[i] === quote) return false;
  }
  return true;
}

/** True if `token` is a single bare identifier (optionally `$`-prefixed for PHP). */
export function isBareIdentifier(token: string): boolean {
  return /^\$?[A-Za-z_][A-Za-z0-9_]*$/.test(token.trim());
}

/**
 * True if `token` is an inert constant: a fully-quoted literal, a bare
 * number, or one of a small set of language keyword literals. Used by rules
 * that only want to fire on a non-literal argument (e.g. C002's Python
 * branch, C004).
 */
export function isSimpleLiteral(token: string): boolean {
  const t = token.trim();
  if (t.length === 0) return false;
  if (isFullyQuotedLiteral(t)) return true;
  if (/^-?\d+(\.\d+)?$/.test(t)) return true;
  return ['True', 'False', 'None', 'true', 'false', 'null', 'nil'].includes(t);
}

/**
 * Split `text` on a single-character top-level separator, respecting quotes
 * (single/double/backtick, backslash-escaped) and nested (), [], {} groups
 * (all three bracket kinds share one depth counter -- we only need to know
 * "inside some nested group", not validate matching bracket kinds).
 */
export function splitTopLevel(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = '';

  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;

    if (quote) {
      current += ch;
      if (ch === '\\' && i + 1 < text.length) {
        current += text[i + 1] as string;
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }

    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      current += ch;
      continue;
    }

    if (ch === '(' || ch === '[' || ch === '{') {
      depth++;
      current += ch;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth = Math.max(0, depth - 1);
      current += ch;
      continue;
    }

    if (depth === 0 && ch === separator) {
      parts.push(current);
      current = '';
      continue;
    }

    current += ch;
  }
  parts.push(current);
  return parts;
}

/**
 * Does `expr` show textual evidence of being built dynamically (as opposed
 * to a fixed constant)? Covers: template-literal / Ruby interpolation,
 * Python f-strings, `%`-style string formatting, `.format(...)` calls, and
 * `+` concatenation where at least one operand is not itself a literal.
 * A concatenation of literals only (`'a' + 'b'`) is still constant and
 * returns false, matching the "NOT flagged: constant strings" requirement.
 */
export function isDynamicExpression(exprRaw: string, lang: Lang): boolean {
  const expr = exprRaw.trim();
  if (expr.length === 0) return false;

  if (expr.includes('${') || expr.includes('#{')) return true;

  if (lang === 'py') {
    // f-strings: f"..." / f'...' containing a `{` placeholder.
    if (/(?:^|[^A-Za-z0-9_])[fF](['"])(?:(?!\1).)*\{/.test(expr)) return true;
    // %-formatting: a string literal followed by a top-level `%`.
    const percentParts = splitTopLevel(expr, '%');
    if (percentParts.length > 1 && /%[sdifr]/.test(expr)) return true;
  }

  if (/\.format\s*\(/.test(expr)) return true;

  const concatParts = splitTopLevel(expr, '+')
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  if (concatParts.length > 1 && concatParts.some((p) => !isFullyQuotedLiteral(p))) {
    return true;
  }

  return false;
}

/** Case-insensitive, word-bounded search for any of `words` inside `text`. */
export function hasContextWord(text: string, words: readonly string[]): boolean {
  if (words.length === 0) return false;
  const pattern = words.map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  return new RegExp(`\\b(?:${pattern})\\b`, 'i').test(text);
}

/** Join a window of raw lines around `index` (inclusive), for context checks. */
export function contextWindow(
  lines: readonly string[],
  index: number,
  before: number,
  after: number,
): string {
  const start = Math.max(0, index - before);
  const end = Math.min(lines.length - 1, index + after);
  return lines.slice(start, end + 1).join('\n');
}

/**
 * Find the offset (relative to `text`, starting the scan at `openIndex`,
 * which must point at an opening `(`) of the matching closing `)`, tracking
 * nested parens and skipping quoted content. Scans across newlines inside
 * `text` (the caller may pass the whole remaining file) so calls whose
 * arguments span multiple lines (e.g. a multi-line callback) still resolve.
 * Returns null if unbalanced within `maxScan` characters (defensive cap).
 */
export function extractBalancedParens(
  text: string,
  openIndex: number,
  maxScan = 8000,
): { content: string; endIndex: number } | null {
  if (text[openIndex] !== '(') return null;
  let depth = 0;
  let quote: string | null = null;
  const limit = Math.min(text.length, openIndex + maxScan);

  for (let i = openIndex; i < limit; i++) {
    const ch = text[i] as string;
    if (quote) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(') {
      depth++;
      continue;
    }
    if (ch === ')') {
      depth--;
      if (depth === 0) {
        return { content: text.slice(openIndex + 1, i), endIndex: i };
      }
    }
  }
  return null;
}

export interface CallSite {
  /** The literal text that matched the head pattern (e.g. "exec", "os.system"). */
  matched: string;
  /** 0-based index into the line where the match starts. */
  index: number;
  /** Extracted, comma-unaware argument text between the parens. */
  args: string;
}

/**
 * Find every call whose "head" (name, optionally dotted, immediately
 * followed by optional whitespace and `(`) matches one of `names` on a
 * single line, extracting the (possibly multi-line) argument text for each.
 * `fullText` / `lineStartOffset` let the paren-matcher look past the end of
 * `line` for calls whose arguments continue on later lines.
 */
export function findCallSites(
  line: string,
  names: readonly string[],
  fullText?: string,
  lineStartOffset?: number,
): CallSite[] {
  if (names.length === 0) return [];
  const pattern = names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const re = new RegExp(`\\b(?:${pattern})\\s*\\(`, 'g');
  const sites: CallSite[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) {
    const matchText = m[0];
    const parenLocalIndex = m.index + matchText.length - 1;
    let args: string | null = null;
    if (fullText !== undefined && lineStartOffset !== undefined) {
      const absOpen = lineStartOffset + parenLocalIndex;
      const balanced = extractBalancedParens(fullText, absOpen);
      args = balanced?.content ?? null;
    } else {
      const balanced = extractBalancedParens(line, parenLocalIndex);
      args = balanced?.content ?? null;
    }
    if (args === null) continue;
    sites.push({
      matched: matchText.slice(0, matchText.length - 1).trimEnd(),
      index: m.index,
      args,
    });
  }
  return sites;
}
