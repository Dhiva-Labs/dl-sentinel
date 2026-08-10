/**
 * Per-file analysis context built once per scanned file and shared by every
 * rule. Building this once avoids every rule re-splitting lines, re-deriving
 * the comment mask, and re-scanning for "variable built from a dynamic
 * expression" assignments.
 */

import { detectLanguage, type Lang } from './language.js';
import { buildCommentMask, isBareIdentifier, isDynamicExpression } from './text.js';

export interface DynamicAssignment {
  /** Variable name exactly as captured (PHP keeps its leading `$`). */
  name: string;
  /** 0-based line index of the assignment. */
  line: number;
  /** Right-hand-side expression text, trimmed. */
  rhs: string;
}

export interface FileContext {
  relPath: string;
  lang: Lang;
  /** Raw lines, `\r` stripped, no trailing newline. */
  lines: readonly string[];
  /** Absolute char offset (into `text`) where each line starts. */
  lineStarts: readonly number[];
  /** Full raw file text, used for paren-matching across line breaks. */
  text: string;
  /** `commentMask[i] === true` means line `i` must not be flagged. */
  commentMask: readonly boolean[];
  /** Every "name = dynamic expression" assignment found, in file order. */
  dynamicAssignments: readonly DynamicAssignment[];
}

function splitLines(text: string): string[] {
  return text.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
}

function computeLineStarts(lines: readonly string[]): number[] {
  const starts: number[] = [];
  let offset = 0;
  for (const line of lines) {
    starts.push(offset);
    offset += line.length + 1; // +1 for the '\n' joiner
  }
  return starts;
}

/**
 * Assignment patterns are intentionally narrow: only simple
 * `<decl>? name = expr` statements starting at the beginning of a line (the
 * common case for the "build a string, then pass it to a sink" idiom this
 * scanner targets). Reassignment without a declaration keyword, destructuring,
 * and multi-variable assignment are not tracked -- documented limitation.
 */
function assignmentPattern(lang: Lang): RegExp | null {
  switch (lang) {
    case 'js':
      return /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=(?!=)\s*(.+?);?\s*$/;
    case 'py':
    case 'rb':
      return /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*(.+?)\s*$/;
    case 'php':
      return /^\s*(\$[A-Za-z_]\w*)\s*=(?!=)\s*(.+?);?\s*$/;
    case 'go':
      return /^\s*([A-Za-z_]\w*)\s*:?=(?!=)\s*(.+?)\s*$/;
    case 'java':
      return /^\s*(?:[A-Za-z_$][\w$.<>[\],\s]*\s)([A-Za-z_$]\w*)\s*=(?!=)\s*(.+?);?\s*$/;
    default:
      return null;
  }
}

function collectDynamicAssignments(
  lines: readonly string[],
  commentMask: readonly boolean[],
  lang: Lang,
): DynamicAssignment[] {
  const pattern = assignmentPattern(lang);
  if (!pattern) return [];
  const out: DynamicAssignment[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (commentMask[i]) continue;
    const line = lines[i] ?? '';
    const m = pattern.exec(line);
    if (!m) continue;
    const name = m[1];
    const rhs = m[2]?.trim();
    if (!name || !rhs) continue;
    if (!isBareIdentifier(name)) continue;
    if (isDynamicExpression(rhs, lang)) {
      out.push({ name, line: i, rhs });
    }
  }
  return out;
}

export function buildFileContext(relPath: string, text: string): FileContext {
  const lang = detectLanguage(relPath);
  const lines = splitLines(text);
  const lineStarts = computeLineStarts(lines);
  const commentMask = buildCommentMask(lines, lang);
  const dynamicAssignments = collectDynamicAssignments(lines, commentMask, lang);
  return { relPath, lang, lines, lineStarts, text, commentMask, dynamicAssignments };
}

/**
 * Look up the most recent dynamic assignment of `name` at or before
 * `atLine`, within `maxLookback` lines. Returns undefined if none found --
 * callers treat that as "cannot prove this argument is dynamic".
 */
export function findDynamicSource(
  ctx: FileContext,
  name: string,
  atLine: number,
  maxLookback = 40,
): DynamicAssignment | undefined {
  let best: DynamicAssignment | undefined;
  for (const ev of ctx.dynamicAssignments) {
    if (ev.name !== name) continue;
    if (ev.line > atLine) continue;
    if (atLine - ev.line > maxLookback) continue;
    if (!best || ev.line > best.line) best = ev;
  }
  return best;
}

export interface DynamismResult {
  dynamic: boolean;
  /** The text to inspect further (e.g. for SQL keywords): the resolved
   *  assignment's RHS when resolved via a bare identifier, else `argExpr`
   *  itself. */
  text: string;
  /** Line the dynamism evidence came from (the resolved assignment's line,
   *  or the usage line itself when the argument was directly dynamic). */
  sourceLine: number;
}

/**
 * Decide whether a call argument is "dynamically built": either it shows
 * direct evidence (template literal, concatenation with a non-literal
 * operand, f-string, `%`/`.format` formatting), or it is a single bare
 * identifier that resolves to a prior dynamic assignment (see
 * `findDynamicSource`). Anything else (function calls, member access,
 * numeric/boolean literals, unresolved identifiers) is treated as not
 * dynamic -- precision over recall.
 */
export function resolveArgDynamism(
  ctx: FileContext,
  argExprRaw: string,
  atLine: number,
): DynamismResult {
  const argExpr = argExprRaw.trim();
  if (isDynamicExpression(argExpr, ctx.lang)) {
    return { dynamic: true, text: argExpr, sourceLine: atLine };
  }
  if (isBareIdentifier(argExpr)) {
    const source = findDynamicSource(ctx, argExpr, atLine);
    if (source) {
      return { dynamic: true, text: source.rhs, sourceLine: source.line };
    }
  }
  return { dynamic: false, text: argExpr, sourceLine: atLine };
}
