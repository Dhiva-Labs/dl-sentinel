import type { Report, ReportFormat } from '@dl-sentinel/core';
import { renderJson } from './json.js';
import { renderMarkdown } from './markdown.js';
import { renderSarif } from './sarif.js';
import { renderTerminal } from './terminal.js';

export { renderJson } from './json.js';
export { renderMarkdown } from './markdown.js';
export { renderSarif, severityToSarifLevel } from './sarif.js';
export { renderTerminal } from './terminal.js';

/** Render a report in the requested format. */
export function renderReport(report: Report, format: ReportFormat): string {
  switch (format) {
    case 'terminal':
      return renderTerminal(report);
    case 'json':
      return renderJson(report);
    case 'markdown':
      return renderMarkdown(report);
    case 'sarif':
      return renderSarif(report);
  }
}
