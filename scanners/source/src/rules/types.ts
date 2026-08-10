import type { RuleMeta, Severity } from '@dl-sentinel/core';
import type { Lang } from '../language.js';
import type { FileContext } from '../context.js';

/** One occurrence a rule wants reported. Positions are 0-based internally;
 * the scanner converts to 1-based when building the `Finding`. */
export interface RuleHit {
  line: number;
  column?: number;
  /** Overrides the rule's declared severity for this specific occurrence
   * (used by C009, whose severity depends on whether credentials are set). */
  severity?: Severity;
  /** Raw text to redact-and-report as evidence; defaults to the hit's line. */
  evidenceLine?: string;
}

export interface RuleModule {
  meta: RuleMeta;
  /** Language families this rule inspects; `check` is not called otherwise. */
  languages: readonly Lang[];
  check(ctx: FileContext): RuleHit[];
}
