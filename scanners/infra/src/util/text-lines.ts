/**
 * Minimal offset<->line bookkeeping for the Dockerfile and Terraform
 * parsers, which work over raw text rather than through a library that
 * already tracks source positions (as `yaml` does for compose/Kubernetes).
 */

/** Precompute the character offset each line starts at (0-based line index). */
export function buildLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/** 1-based line number containing `offset`, via binary search over `lineStarts`. */
export function lineForOffset(lineStarts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if ((lineStarts[mid] ?? 0) <= offset) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return lo + 1;
}

/** Split text into physical lines, tolerating both \n and \r\n. */
export function splitLines(text: string): string[] {
  return text.split(/\r\n|\n/);
}

/** The full text of the 1-based `line`, or '' if out of range. */
export function lineText(lines: readonly string[], line: number | undefined): string {
  if (line === undefined) return '';
  return lines[line - 1] ?? '';
}
