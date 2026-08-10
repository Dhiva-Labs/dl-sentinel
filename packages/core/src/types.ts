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

export interface SentinelConfig {
  include: string[];
  exclude: string[];
  maxFileSizeBytes: number;
  scanners: Record<string, ScannerSettings>;
  policy: PolicyConfig;
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
  };
}
