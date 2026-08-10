/**
 * Dashboard-side data shapes.
 *
 * These mirror `Finding` / `Severity` / `SeverityStats` in
 * `packages/core/src/types.ts` field-for-field (see docs/finding-schema.md),
 * but are declared locally rather than imported. `@dl-sentinel/web` ships
 * with zero runtime dependencies by design (see apps/web/package.json), and
 * the dashboard receives this data as untyped JSON over HTTP from the API
 * server anyway — a compile-time import of @dl-sentinel/core's types would
 * not add any runtime safety, only a coupling this package does not need.
 *
 * If `packages/core/src/types.ts` changes, update this file to match.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Confidence = 'high' | 'medium' | 'low';

/** Assertion strength; optional, mainly used by the API scanner. */
export type Qualifier = 'confirmed' | 'likely' | 'potential';

export interface SeverityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Shape of a finding as rendered by the dashboard. `category` and `scanner`
 * are kept as `string` (rather than a closed union) so the dashboard never
 * fails to render a value the server sends that predates a local copy of an
 * enum — this package only ever displays these fields, it never branches on
 * a specific category.
 */
export interface FindingLike {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  qualifier?: Qualifier;
  category: string;
  /** Repo-relative posix path. */
  file: string;
  line?: number;
  column?: number;
  endLine?: number;
  /** Always pre-redacted by the producer; render verbatim, never "unredact". */
  evidence: string;
  recommendation: string;
  references: string[];
  scanner: string;
  metadata?: Record<string, string | number | boolean>;
}
