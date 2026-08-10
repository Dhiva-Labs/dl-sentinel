import type { Finding, RuleMeta } from '@dl-sentinel/core';
import type { ParsedSolidityFile } from '../model.js';

export interface RuleContext {
  relPath: string;
  file: ParsedSolidityFile;
}

export interface RuleDefinition {
  meta: RuleMeta;
  evaluate(ctx: RuleContext): Finding[];
}
