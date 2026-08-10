import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { Confidence, Finding, Qualifier, Severity } from '@dl-sentinel/core';

export interface ApiFindingInput {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  qualifier: Qualifier;
  file: string;
  line?: number;
  column?: number;
  /**
   * Fully-formed evidence text. If it may contain a secret/credential value,
   * the caller MUST pre-redact it with redactEvidence(text, [values]) before
   * passing it in here — this helper only applies the final trim/truncate
   * pass and never has access to raw secret values itself.
   */
  evidence: string;
  recommendation: string;
  references?: string[];
  metadata?: Finding['metadata'];
}

/** Construct a Finding for the api scanner with category/scanner fixed and evidence safety-netted. */
export function buildFinding(input: ApiFindingInput): Finding {
  return createFinding({
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: input.confidence,
    qualifier: input.qualifier,
    category: 'api',
    file: input.file,
    line: input.line,
    column: input.column,
    evidence: redactEvidence(input.evidence, []),
    recommendation: input.recommendation,
    references: input.references ?? [],
    scanner: 'api',
    metadata: input.metadata,
  });
}
