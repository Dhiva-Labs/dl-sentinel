/**
 * Comment and string-literal stripping, line-preserving.
 *
 * Produces one `SourceLine` per physical source line: `original` is untouched
 * (used only for evidence text), `stripped` has every `//` line comment,
 * `/* *\/` block comment (which may span multiple lines), and quoted string
 * body replaced with spaces — same length, same line count, so line/column
 * numbers computed against `stripped` still point at the right place in
 * `original`.
 *
 * Known heuristic limits (documented per docs/scanner-interface.md rule 8):
 * - A quoted string is assumed to end on the same physical line it opens on.
 *   Solidity does not allow a raw (unescaped) newline inside a normal string
 *   literal, so this is safe for well-formed input; for malformed/truncated
 *   input it just means recovery resets per line, which is the safer failure
 *   mode (bounded, not cascading).
 * - `hex"..."`/`unicode"..."` prefixes are left as plain text; only the
 *   quoted body is blanked. That is harmless: the prefix words are not
 *   matched by any rule.
 */

import type { SourceLine } from './model.js';

export function stripCommentsAndStrings(source: string): SourceLine[] {
  const rawLines = source.split(/\r\n|\r|\n/);
  const out: SourceLine[] = [];
  let inBlockComment = false;

  for (let i = 0; i < rawLines.length; i++) {
    const original = rawLines[i] ?? '';
    let result = '';
    let inString: '"' | "'" | null = null;

    for (let j = 0; j < original.length; j++) {
      const ch = original.charAt(j);
      const next = j + 1 < original.length ? original.charAt(j + 1) : undefined;

      if (inBlockComment) {
        if (ch === '*' && next === '/') {
          inBlockComment = false;
          result += '  ';
          j++;
        } else {
          result += ' ';
        }
        continue;
      }

      if (inString) {
        if (ch === '\\' && next !== undefined) {
          result += '  ';
          j++;
          continue;
        }
        if (ch === inString) {
          inString = null;
        }
        result += ' ';
        continue;
      }

      if (ch === '/' && next === '/') {
        result += ' '.repeat(original.length - j);
        break;
      }
      if (ch === '/' && next === '*') {
        inBlockComment = true;
        result += '  ';
        j++;
        continue;
      }
      if (ch === '"' || ch === "'") {
        inString = ch;
        result += ' ';
        continue;
      }
      result += ch;
    }

    out.push({ line: i + 1, original, stripped: result });
  }

  return out;
}
