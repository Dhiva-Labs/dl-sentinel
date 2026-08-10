/** Line helpers shared by the detectors. */

/** Split file text into lines, tolerating CRLF and a missing trailing newline. */
export function splitLines(text: string): string[] {
  return text.split(/\r?\n/);
}

/**
 * Join the lines around `index` (inclusive, clamped to the file) into one
 * string, so a rule can require that nearby lines mention e.g. AWS. Used for
 * context checks only — never for evidence.
 */
export function contextWindow(lines: readonly string[], index: number, radius: number): string {
  if (radius <= 0) return lines[index] ?? '';
  const from = Math.max(0, index - radius);
  const to = Math.min(lines.length, index + radius + 1);
  return lines.slice(from, to).join('\n');
}
