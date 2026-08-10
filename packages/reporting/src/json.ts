import type { Report } from '@dl-sentinel/core';

export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}
