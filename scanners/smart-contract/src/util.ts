/** Small, dependency-free text-parsing helpers shared across the parser and rules. */

import type { ParsedSolidityFile } from './model.js';

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Find the index of the `)` matching the `(` at `openIndex`. Returns -1 if
 * the text runs out before the parens balance (truncated/malformed input) —
 * callers must treat that as "give up on this construct", never throw.
 */
export function findMatchingParen(text: string, openIndex: number): number {
  let depth = 0;
  for (let i = openIndex; i < text.length; i++) {
    const ch = text.charAt(i);
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Split on a top-level separator character, ignoring separators nested inside (), [], {}. */
export function splitTopLevel(text: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (const ch of text) {
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
    if (ch === sep && depth === 0) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts;
}

/** Original (unstripped) text of a 1-based line number, or '' if out of range. */
export function lineOriginal(file: ParsedSolidityFile, lineNumber: number): string {
  return file.lines[lineNumber - 1]?.original ?? '';
}
