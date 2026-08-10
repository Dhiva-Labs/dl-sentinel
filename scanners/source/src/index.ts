import type { Finding, ScanContext, ScannerPlugin } from '@dl-sentinel/core';
import { createFinding, dedupeFindings, redactEvidence, sortFindings } from '@dl-sentinel/core';
import { buildFileContext } from './context.js';
import { rules } from './rules/index.js';

const SUPPORTED_FILES = [
  '**/*.js',
  '**/*.jsx',
  '**/*.ts',
  '**/*.tsx',
  '**/*.mjs',
  '**/*.cjs',
  '**/*.py',
  '**/*.go',
  '**/*.rb',
  '**/*.php',
  '**/*.java',
];

async function scan(context: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of context.files) {
    if (context.signal.aborted) {
      throw new Error('source scan aborted');
    }

    let text: string;
    try {
      text = await context.readFile(file);
    } catch (err) {
      if (context.signal.aborted) throw err;
      context.logger.warn(
        `source: could not read ${file.relPath}: ${err instanceof Error ? err.message : String(err)}`,
      );
      continue;
    }

    const fileCtx = buildFileContext(file.relPath, text);
    if (fileCtx.lang === 'other') continue;

    for (const rule of rules) {
      if (!rule.languages.includes(fileCtx.lang)) continue;

      let hits;
      try {
        hits = rule.check(fileCtx);
      } catch (err) {
        context.logger.warn(
          `source: rule ${rule.meta.id} failed on ${file.relPath}: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
        continue;
      }

      for (const hit of hits) {
        const lineText = hit.evidenceLine ?? fileCtx.lines[hit.line] ?? '';
        findings.push(
          createFinding({
            ruleId: rule.meta.id,
            title: rule.meta.title,
            description: rule.meta.description,
            severity: hit.severity ?? rule.meta.severity,
            confidence: rule.meta.defaultConfidence,
            category: 'source',
            file: file.relPath,
            line: hit.line + 1,
            column: hit.column === undefined ? undefined : hit.column + 1,
            evidence: redactEvidence(lineText, []),
            recommendation: rule.meta.recommendation,
            references: rule.meta.references ?? [],
            scanner: sourceScanner.id,
          }),
        );
      }
    }
  }

  return sortFindings(dedupeFindings(findings));
}

export const sourceScanner: ScannerPlugin = {
  id: 'source',
  name: 'Source Code Scanner',
  version: '0.1.0',
  categories: ['source'],
  supportedFiles: SUPPORTED_FILES,
  rules: rules.map((rule) => rule.meta),
  scan,
};

export default sourceScanner;
