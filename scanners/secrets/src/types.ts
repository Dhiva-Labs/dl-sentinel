import type { Confidence, Severity } from '@dl-sentinel/core';

/**
 * Detection tiers, in the order they are applied.
 *
 * - `structured` — the match is a vendor-defined credential format (an AWS key
 *   id, a PEM block, a URL with an embedded password). The format itself is the
 *   evidence, so these rules are never suppressed by placeholder markers.
 * - `heuristic` — the match is inferred from naming and entropy. These rules
 *   are suppressed by placeholder markers and by any overlapping structured
 *   match, so a token that a structured rule already reported is not reported
 *   twice.
 */
export type DetectorTier = 'structured' | 'heuristic';

/** Half-open `[start, end)` offsets of a value inside its line (0-based). */
export interface Span {
  start: number;
  end: number;
}

/** A file handed to the detectors, pre-split and pre-classified. */
export interface FileInput {
  /** Repo-relative posix path (what ends up in the finding). */
  relPath: string;
  lines: readonly string[];
  /** `.env`, `.env.local`, `app.env`, `.envrc`, … */
  isEnvLike: boolean;
  /** yaml/json/toml/ini/properties/… or anything under a `config/` directory. */
  isConfigLike: boolean;
  /** Lockfile, minified bundle, or similar generated noise. */
  isNoisy: boolean;
  /** 1-based line numbers inside a PEM block body (never scanned heuristically). */
  pemBodyLines: ReadonlySet<number>;
}

/**
 * A raw detection, before allowlisting, suppression, redaction, and finding
 * assembly. `secrets` holds RAW credential material and must never be copied
 * into a Finding, a log line, or an error — it exists so the scan pass can
 * redact every occurrence out of the evidence line.
 */
export interface Detection {
  ruleId: string;
  tier: DetectorTier;
  /**
   * Raw values that must not survive into evidence. May be empty when the
   * evidence string is synthesized and provably free of secret material (the
   * PEM rule, whose evidence is the BEGIN marker line only).
   */
  secrets: readonly string[];
  /** Value compared against `config.allowlist`. Defaults to `secrets[0]`. */
  allowlistValue?: string;
  /** 1-based. */
  line: number;
  /** 1-based. */
  column: number;
  /** 1-based; set for multi-line matches (PEM blocks). */
  endLine?: number;
  /** Text the evidence is built from — normally the raw line. */
  evidenceSource: string;
  /** Where the value sits on its line, used to suppress overlapping matches. */
  span: Span;
  /** Overrides the rule's declared severity (e.g. live vs test keys). */
  severity?: Severity;
  /** Overrides the rule's declared default confidence. */
  confidence?: Confidence;
  /** Non-secret triage detail only: format names, lengths, entropy. */
  metadata?: Record<string, string | number | boolean>;
}

/** A detector turns one file into zero or more raw detections. */
export type Detector = (file: FileInput) => Detection[];
