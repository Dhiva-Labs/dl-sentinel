/**
 * Shared data model for DL Sentinel.
 *
 * This file is the integration contract between the engine, scanners, apps,
 * and reporting. Changes here must be coordinated by the lead instance and
 * reflected in docs/finding-schema.md and docs/scanner-interface.md.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Confidence = 'high' | 'medium' | 'low';

/**
 * How firmly a finding is asserted. Used mainly by the API scanner, which must
 * distinguish confirmed issues from likely/potential ones. A finding without a
 * qualifier is a plain static detection.
 */
export type Qualifier = 'confirmed' | 'likely' | 'potential';

export type Category =
  | 'secrets'
  | 'dependencies'
  | 'source'
  | 'docker'
  | 'infrastructure'
  | 'api'
  | 'smart-contract'
  | 'config'
  | 'other';

export interface Finding {
  /** Stable fingerprint of the finding (see findingFingerprint). */
  id: string;
  /** Namespaced rule id, e.g. "S001" (secrets), "D001" (dependencies). */
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  qualifier?: Qualifier;
  category: Category;
  /** Repo-relative posix path. */
  file: string;
  /** 1-based line number. */
  line?: number;
  /** 1-based column number. */
  column?: number;
  endLine?: number;
  /**
   * Human-readable evidence. MUST already be redacted: secret values are never
   * allowed in this field. Use redactEvidence() from @dl-sentinel/core.
   */
  evidence: string;
  recommendation: string;
  references: string[];
  /** Id of the scanner plugin that produced this finding. */
  scanner: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface RuleMeta {
  id: string;
  title: string;
  severity: Severity;
  defaultConfidence: Confidence;
  category: Category;
  description: string;
  recommendation: string;
  references?: string[];
  /**
   * Optional mapping to established compliance frameworks. Only well-known,
   * canonical mappings belong here (e.g. cwe: ['CWE-798'], owasp:
   * ['A07:2021']); when a mapping is uncertain the field is omitted — it is
   * never guessed.
   */
  compliance?: {
    /** CWE identifiers, e.g. "CWE-798". */
    cwe?: string[];
    /** OWASP Top 10 (2021) identifiers, e.g. "A05:2021". */
    owasp?: string[];
  };
}

/** A file discovered by the engine and offered to scanners. */
export interface FileRef {
  /** Absolute path on disk. */
  absPath: string;
  /** Repo-relative posix path (what appears in findings). */
  relPath: string;
  /** Size in bytes. */
  size: number;
}

export interface ScanLogger {
  debug(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

/** Logger that discards everything; useful in tests. */
export const noopLogger: ScanLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

export interface ScanContext {
  /** Absolute path of the scan target root. */
  rootDir: string;
  /**
   * Files pre-filtered by the engine: ignore rules applied, binaries and
   * oversized files excluded, then narrowed to the scanner's supportedFiles.
   */
  files: readonly FileRef[];
  /** Scanner-specific configuration section (config.scanners[scanner.id]). */
  config: Record<string, unknown>;
  /** Cooperative cancellation. Scanners should check aborted periodically. */
  signal: AbortSignal;
  logger: ScanLogger;
  /** Read a file as UTF-8. The engine caps sizes at discovery time. */
  readFile(ref: FileRef): Promise<string>;
}

export interface ScannerPlugin {
  /** Short stable id, e.g. "secrets". Used in findings and configuration. */
  id: string;
  name: string;
  version: string;
  categories: Category[];
  /**
   * Glob patterns (repo-relative) this scanner wants to receive.
   * Empty array means "all discovered files".
   */
  supportedFiles: string[];
  rules: RuleMeta[];
  scan(context: ScanContext): Promise<Finding[]>;
}

export interface ScannerError {
  scanner: string;
  message: string;
  stack?: string;
}

export interface SeverityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** Progress events emitted by the engine during a scan. */
export type ScanEvent =
  | { type: 'scan:start'; target: string; scanners: string[] }
  | { type: 'files:discovered'; count: number }
  | { type: 'scanner:start'; scanner: string }
  | { type: 'scanner:complete'; scanner: string; findings: number; durationMs: number }
  | { type: 'scanner:error'; scanner: string; message: string }
  | { type: 'scan:complete'; findings: number; durationMs: number };

export interface Report {
  tool: { name: string; version: string };
  /** Project name (basename of the target by default). */
  project: string;
  /** Absolute path or identifier of what was scanned. */
  target: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  scannersRun: string[];
  stats: SeverityStats;
  findings: Finding[];
  errors: ScannerError[];
  /**
   * Count of findings removed by suppression rules before this report was
   * assembled. Absent (not 0) when no suppression was configured, so existing
   * consumers and serialized reports are unaffected.
   */
  suppressed?: number;
  /** Baseline comparison summary, present only when a baseline was applied. */
  baseline?: { newFindings: number; baselined: number };
  /**
   * The policy the scan was evaluated under (resolved from sentinel.yml or
   * defaults). Lets consumers (CLI exit codes, the API's policy.violated
   * notification) apply the target's own policy instead of assuming defaults.
   */
  policy?: PolicyConfig;
}

export type ReportFormat = 'terminal' | 'json' | 'markdown' | 'sarif';

export interface PolicyConfig {
  /** Severities that cause a non-zero exit / failed policy when present. */
  failOn: Severity[];
}

export interface ScannerSettings {
  enabled?: boolean;
  [key: string]: unknown;
}

/**
 * A rule for suppressing findings (declared in sentinel.yml under `suppress`).
 * A finding is suppressed when it matches an ACTIVE rule: every field the rule
 * specifies must match, and a rule that specifies no matcher matches nothing
 * (so an empty rule can never suppress everything by accident). `expires` lets
 * a suppression lapse so the finding resurfaces instead of being hidden
 * forever.
 */
export interface SuppressionRule {
  /** Match findings emitted by this rule id, e.g. "S001". */
  rule?: string;
  /** Match findings produced by this scanner id, e.g. "secrets". */
  scanner?: string;
  /** Match findings whose file matches this repo-relative glob. */
  path?: string;
  /** Match a single finding by its fingerprint id. */
  id?: string;
  /** Audit trail: why this finding is suppressed. */
  reason?: string;
  /** ISO-8601 date; on/after this instant the rule no longer suppresses. */
  expires?: string;
}

export interface SentinelConfig {
  include: string[];
  exclude: string[];
  maxFileSizeBytes: number;
  scanners: Record<string, ScannerSettings>;
  policy: PolicyConfig;
  /**
   * Suppression rules applied to findings after scanning. Optional for
   * backward compatibility; `defaultConfig()` always populates it with `[]`.
   */
  suppress?: SuppressionRule[];
}

/** A finding recorded in a baseline: its id plus human-readable context. */
export interface BaselineEntry {
  id: string;
  ruleId: string;
  file: string;
  severity: Severity;
}

/**
 * A saved set of known findings. Because finding ids are stable fingerprints,
 * a baseline is effectively a set of ids; the extra fields are for humans
 * reading the file. Produced by `createBaseline`, consumed by `applyBaseline`.
 */
export interface Baseline {
  tool: { name: string; version: string };
  /** ISO-8601 timestamp the baseline was generated. */
  generatedAt: string;
  /** What was scanned to produce it (informational). */
  target: string;
  count: number;
  findings: BaselineEntry[];
}

/**
 * Directories/files excluded from scanning by default. Note that dotfiles in
 * general are NOT excluded — files like .env are prime scan targets.
 */
export const DEFAULT_EXCLUDES: readonly string[] = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/coverage/**',
  '**/.next/**',
  '**/.venv/**',
  '**/venv/**',
  '**/__pycache__/**',
  '**/target/debug/**',
  '**/target/release/**',
  '**/.dl-sentinel/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
];

export function defaultConfig(): SentinelConfig {
  return {
    include: ['**/*'],
    exclude: [...DEFAULT_EXCLUDES],
    maxFileSizeBytes: 1024 * 1024,
    scanners: {},
    policy: { failOn: ['critical', 'high'] },
    suppress: [],
  };
}
