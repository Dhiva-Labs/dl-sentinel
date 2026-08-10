/**
 * Internal types for the dependencies scanner. Not part of the core contract
 * (packages/core/src/types.ts) — these describe data that only this scanner
 * produces and consumes: parsed manifest/lockfile entries, the pluggable
 * vulnerability data source, and the advisory shape it returns.
 */

import type { Severity } from '@dl-sentinel/core';

export type Ecosystem = 'npm' | 'pip' | 'go' | 'cargo';

/**
 * How precisely `DependencyRecord.version` pins the installed code:
 * - 'exact': a single resolved version from a lockfile (or a pip `==` pin, or
 *   a go.mod require line, which always names one version token). Matching
 *   against this is a real version comparison → high confidence.
 * - 'range': a declared constraint from a manifest (npm/cargo range syntax,
 *   pip `>=`/`<=`/`>`/`<`) that could resolve to more than one real version.
 *   Matching against this only proves *possible* exposure → medium confidence.
 */
export type VersionKind = 'exact' | 'range';

/** One dependency entry discovered in a manifest or lockfile. */
export interface DependencyRecord {
  ecosystem: Ecosystem;
  name: string;
  /** Exact version (lockfiles) or a declared range spec (manifests), verbatim. */
  version: string;
  versionKind: VersionKind;
  /** True for a project's own declared dependency; false for a transitive one. */
  direct: boolean;
  /** Repo-relative posix path of the file this record came from. */
  sourceFile: string;
  /** 1-based line number, when it could be determined. */
  line?: number;
}

/** Vulnerability severities. Advisories never carry 'info' — that's reserved
 * for the scanner's own "not checked" observation (D002). */
export type AdvisorySeverity = Exclude<Severity, 'info'>;

/**
 * One vulnerable version window. `introduced` is inclusive, `fixed` is
 * exclusive (versions >= fixed are patched). Either bound may be absent:
 * no `introduced` means "from the beginning"; no `fixed` means "no fix yet".
 * Both come from the data source verbatim — never invented by this scanner.
 */
export interface AffectedRange {
  introduced?: string;
  fixed?: string;
}

/** A known vulnerability affecting a specific package, from a data source. */
export interface Advisory {
  /** Advisory identifier as published by the source (e.g. a GHSA or TEST- id). */
  id: string;
  ecosystem: Ecosystem;
  name: string;
  affectedRanges: AffectedRange[];
  severity: AdvisorySeverity;
  summary: string;
  references: string[];
}

/** A package instance to look up advisories for. */
export interface PackageQuery {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

/**
 * Pluggable vulnerability data source. Implementations return every advisory
 * that could apply to the requested packages, keyed by (ecosystem, name)
 * only — they do not need to interpret `version`; the scanner's own
 * conservative comparator (src/version/) decides whether a specific
 * installed version or declared range actually falls inside an advisory's
 * affected ranges, and at what confidence.
 */
export interface VulnDataSource {
  query(packages: readonly PackageQuery[]): Promise<Advisory[]>;
}

export type DataSourceKind = 'none' | 'file' | 'osv';

/** Shape of `config.scanners.dependencies` (docs/architecture.md). */
export interface DependenciesScannerSettings {
  enabled?: boolean;
  dataSource?: DataSourceKind;
  advisoryDbPath?: string | null;
  [key: string]: unknown;
}
