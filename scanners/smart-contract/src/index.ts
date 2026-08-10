// smart-contract scanner plugin. Implemented on feature/sentinel-smart-contract.
// Contract: docs/scanner-interface.md — export a ScannerPlugin as the default entry point.

import type { Finding, ScanContext, ScannerPlugin } from '@dl-sentinel/core';
import { sortFindings } from '@dl-sentinel/core';
import { parseSolidityFile } from './parser.js';
import { allRules } from './rules/index.js';

const SCANNER_ID = 'smart-contract';

async function scan(context: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of context.files) {
    if (context.signal.aborted) {
      throw new Error('smart-contract scan aborted');
    }

    let source: string;
    try {
      source = await context.readFile(file);
    } catch (err) {
      context.logger.warn(
        `smart-contract: failed to read ${file.relPath}: ${err instanceof Error ? err.message : String(err)}`,
      );
      continue;
    }

    try {
      const parsed = parseSolidityFile(file.relPath, source);
      for (const warning of parsed.warnings) {
        context.logger.warn(`smart-contract: ${file.relPath}: ${warning}`);
      }
      for (const rule of allRules) {
        findings.push(...rule.evaluate({ relPath: file.relPath, file: parsed }));
      }
    } catch (err) {
      context.logger.warn(
        `smart-contract: skipping unparseable file ${file.relPath}: ${err instanceof Error ? err.message : String(err)}`,
      );
      continue;
    }
  }

  return sortFindings(findings);
}

export const smartContractScanner: ScannerPlugin = {
  id: SCANNER_ID,
  name: 'Smart Contract Scanner',
  version: '0.1.0',
  categories: ['smart-contract'],
  supportedFiles: ['**/*.sol'],
  rules: allRules.map((r) => r.meta),
  scan,
};

export default smartContractScanner;
