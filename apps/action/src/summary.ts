/**
 * Build the concise, PR-comment-shaped Markdown summary. This is deliberately
 * smaller than reporting's full `renderMarkdown`: counts by severity, the top N
 * new findings as `file:line`, and a redaction note — the shape that reads well
 * as a sticky PR comment and as a Step Summary.
 *
 * The body opens with a hidden HTML-comment marker so the comment can be found
 * and updated on later runs (see github.ts). Only already-redacted finding
 * fields are rendered; no evidence text or file contents are included, and the
 * note states so explicitly.
 */

import type { Finding, Severity, SeverityStats } from '@dl-sentinel/core';
import { TOOL_NAME, TOOL_VERSION, sortFindings } from '@dl-sentinel/core';

/** Hidden marker identifying a comment as this action's, for sticky updates. */
export const COMMENT_MARKER = '<!-- dl-sentinel -->';

const DEFAULT_TOP_N = 10;

export interface SummaryInput {
  /** The findings the PR introduced (already narrowed to "new"). */
  newFindings: readonly Finding[];
  /** Severity counts of `newFindings`. */
  stats: SeverityStats;
  /** Total findings in the scanned tree, before baseline narrowing. */
  totalFindings: number;
  /** How many findings were hidden by the baseline (0 when none applied). */
  baselined: number;
  /** True when a baseline (file or base scan) was applied. */
  baselineApplied: boolean;
  /** Severities that fail the check. */
  failOn: readonly Severity[];
  /** True when the new findings violate the fail-on policy. */
  failed: boolean;
  /** How many findings to list in detail. Default 10. */
  topN?: number;
}

function location(finding: Finding): string {
  return finding.line === undefined ? finding.file : `${finding.file}:${finding.line}`;
}

function statusLine(input: SummaryInput): string {
  const threshold = input.failOn.join(', ');
  if (input.failed) {
    return `Status: **failing** — new findings at or above the fail threshold (${threshold}).`;
  }
  if (input.newFindings.length > 0) {
    return `Status: **passing** — new findings were introduced, but none at the fail threshold (${threshold}).`;
  }
  return 'Status: **passing** — this pull request introduces no new findings.';
}

/** Render the summary body. Deterministic: no timestamps, findings sorted. */
export function buildSummary(input: SummaryInput): string {
  const topN = input.topN ?? DEFAULT_TOP_N;
  const count = input.newFindings.length;
  const lines: string[] = [];

  lines.push(COMMENT_MARKER);
  lines.push(`## ${TOOL_NAME} — ${count} new finding${count === 1 ? '' : 's'}`);
  lines.push('');
  lines.push(statusLine(input));
  lines.push('');
  lines.push('| Severity | New |');
  lines.push('| --- | --- |');
  lines.push(`| Critical | ${input.stats.critical} |`);
  lines.push(`| High | ${input.stats.high} |`);
  lines.push(`| Medium | ${input.stats.medium} |`);
  lines.push(`| Low | ${input.stats.low} |`);
  lines.push(`| Info | ${input.stats.info} |`);
  lines.push('');

  if (input.baselineApplied) {
    lines.push(
      `Compared against a baseline: ${input.baselined} pre-existing finding${
        input.baselined === 1 ? '' : 's'
      } hidden, out of ${input.totalFindings} total.`,
    );
    lines.push('');
  }

  if (count > 0) {
    const sorted = sortFindings(input.newFindings);
    const shown = sorted.slice(0, topN);
    lines.push(`### Top ${shown.length} new finding${shown.length === 1 ? '' : 's'}`);
    lines.push('');
    for (const finding of shown) {
      lines.push(
        `- **${finding.severity.toUpperCase()}** \`${finding.ruleId}\` ${location(finding)} — ${finding.title}`,
      );
    }
    if (sorted.length > shown.length) {
      lines.push(`- …and ${sorted.length - shown.length} more.`);
    }
    lines.push('');
  }

  lines.push(
    'Evidence is redacted and never posted. DL Sentinel scans locally and only calls the ' +
      'GitHub API to publish this comment; your source is never uploaded.',
  );
  lines.push('');
  lines.push(`<sub>${TOOL_NAME} v${TOOL_VERSION}</sub>`);

  return lines.join('\n');
}
