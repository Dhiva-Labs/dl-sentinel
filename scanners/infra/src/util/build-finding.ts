import type { Category, Confidence, Finding, Severity } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';

/** Short stable id for this scanner plugin; also the config key and Finding.scanner value. */
export const SCANNER_ID = 'infra';

export interface FindingInput {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  file: string;
  /** 1-based line number, when known. Omit rather than guess. */
  line?: number;
  column?: number;
  /** Raw (unredacted) evidence text; secret values are stripped before the Finding is built. */
  evidence: string;
  /** Matched secret values (if any) to redact out of `evidence`. */
  secrets?: readonly string[];
  recommendation: string;
  references?: string[];
  metadata?: Record<string, string | number | boolean>;
}

/**
 * Build a Finding for the infra scanner. Centralizes redaction so every rule
 * goes through `redactEvidence` — there is no path here that can emit an
 * un-redacted secret value into a finding.
 */
export function buildFinding(input: FindingInput): Finding {
  const evidence = redactEvidence(input.evidence, input.secrets ?? []);
  return createFinding({
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    file: input.file,
    line: input.line,
    column: input.column,
    evidence,
    recommendation: input.recommendation,
    references: input.references ?? [],
    scanner: SCANNER_ID,
    metadata: input.metadata,
  });
}
