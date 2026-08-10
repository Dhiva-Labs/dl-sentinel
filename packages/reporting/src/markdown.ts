import type { Report } from '@dl-sentinel/core';
import { sortFindings } from '@dl-sentinel/core';

export function renderMarkdown(report: Report): string {
  const lines: string[] = [];
  lines.push(`# ${report.tool.name} Report`);
  lines.push('');
  lines.push(`- **Project:** ${report.project}`);
  lines.push(`- **Target:** \`${report.target}\``);
  lines.push(`- **Scanned:** ${report.startedAt} (${report.durationMs} ms)`);
  lines.push(`- **Scanners:** ${report.scannersRun.join(', ') || 'none'}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  lines.push(`| Critical | ${report.stats.critical} |`);
  lines.push(`| High | ${report.stats.high} |`);
  lines.push(`| Medium | ${report.stats.medium} |`);
  lines.push(`| Low | ${report.stats.low} |`);
  lines.push(`| Info | ${report.stats.info} |`);
  if (report.suppressed !== undefined) {
    lines.push('');
    lines.push(`- **Suppressed:** ${report.suppressed}`);
  }
  if (report.baseline !== undefined) {
    lines.push('');
    lines.push(
      `- **New:** ${report.baseline.newFindings} · **Baselined:** ${report.baseline.baselined}`,
    );
  }
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('No findings.');
  }
  for (const finding of sortFindings(report.findings)) {
    const location = finding.line === undefined ? finding.file : `${finding.file}:${finding.line}`;
    lines.push(`### ${finding.severity.toUpperCase()} ${finding.ruleId} — ${finding.title}`);
    lines.push('');
    lines.push(`- **File:** \`${location}\``);
    lines.push(`- **Confidence:** ${finding.confidence}`);
    if (finding.qualifier) {
      lines.push(`- **Assertion:** ${finding.qualifier}`);
    }
    lines.push(`- **Scanner:** ${finding.scanner}`);
    lines.push('');
    lines.push(finding.description);
    lines.push('');
    lines.push(`Evidence: \`${finding.evidence}\``);
    lines.push('');
    lines.push(`**Recommendation:** ${finding.recommendation}`);
    if (finding.references.length > 0) {
      lines.push('');
      lines.push('References:');
      for (const reference of finding.references) {
        lines.push(`- ${reference}`);
      }
    }
    lines.push('');
  }

  if (report.errors.length > 0) {
    lines.push('## Scanner Errors');
    lines.push('');
    for (const error of report.errors) {
      lines.push(`- **${error.scanner}:** ${error.message}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
