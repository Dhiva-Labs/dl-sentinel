import type { Report, Severity } from '@dl-sentinel/core';

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

export function severityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

export function renderSarif(report: Report): string {
  const ruleIds = new Map<string, { id: string; title: string; severity: Severity }>();
  for (const finding of report.findings) {
    if (!ruleIds.has(finding.ruleId)) {
      ruleIds.set(finding.ruleId, {
        id: finding.ruleId,
        title: finding.title,
        severity: finding.severity,
      });
    }
  }

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: report.tool.name,
            version: report.tool.version,
            informationUri: 'https://github.com/Dhiva-Labs/dl-sentinel',
            rules: [...ruleIds.values()].map((rule) => ({
              id: rule.id,
              name: rule.id,
              shortDescription: { text: rule.title },
              defaultConfiguration: { level: severityToSarifLevel(rule.severity) },
            })),
          },
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: severityToSarifLevel(finding.severity),
          message: { text: `${finding.title}. ${finding.recommendation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: {
                  startLine: finding.line ?? 1,
                  startColumn: finding.column ?? 1,
                },
              },
            },
          ],
          partialFingerprints: { dlSentinelFindingId: finding.id },
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
