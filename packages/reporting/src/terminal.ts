import type { Report } from '@dl-sentinel/core';

function countByScanner(report: Report): Map<string, number> {
  const counts = new Map<string, number>();
  for (const scanner of report.scannersRun) {
    counts.set(scanner, 0);
  }
  for (const finding of report.findings) {
    counts.set(finding.scanner, (counts.get(finding.scanner) ?? 0) + 1);
  }
  return counts;
}

export function renderTerminal(report: Report): string {
  const lines: string[] = [];
  lines.push(`${report.tool.name} v${report.tool.version}`);
  lines.push('');
  lines.push(`Scanning: ${report.target}`);
  lines.push('');

  const counts = countByScanner(report);
  const width = Math.max(12, ...[...counts.keys()].map((s) => s.length));
  for (const [scanner, count] of counts) {
    const noun = count === 1 ? 'finding' : 'findings';
    lines.push(`${scanner.padEnd(width + 4)}${count} ${noun}`);
  }
  lines.push('');
  lines.push(`Critical: ${report.stats.critical}`);
  lines.push(`High:     ${report.stats.high}`);
  lines.push(`Medium:   ${report.stats.medium}`);
  lines.push(`Low:      ${report.stats.low}`);
  lines.push(`Info:     ${report.stats.info}`);

  if (report.errors.length > 0) {
    lines.push('');
    lines.push('Scanner errors:');
    for (const error of report.errors) {
      lines.push(`  ${error.scanner}: ${error.message}`);
    }
  }

  lines.push('');
  lines.push('Scan completed.');
  return lines.join('\n');
}
