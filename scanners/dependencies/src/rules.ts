import type { RuleMeta } from '@dl-sentinel/core';

/**
 * Static rule metadata for `sentinel rules`. Per-finding severity/confidence
 * for D001 vary (see scan.ts); the values below are the representative
 * defaults docs/scanner-interface.md asks every rule to declare.
 */
export const rules: RuleMeta[] = [
  {
    id: 'D001',
    title: 'Known-vulnerable dependency',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'dependencies',
    description:
      'A dependency version resolved from a manifest or lockfile matches a publicly known ' +
      'vulnerability advisory returned by the configured vulnerability data source.',
    recommendation:
      'Upgrade the affected package to the fixed version named in the advisory, or another ' +
      'version outside every affected range.',
    references: [],
    compliance: { cwe: ['CWE-1395'], owasp: ['A06:2021'] },
  },
  {
    id: 'D002',
    title: 'Dependency vulnerability check skipped',
    severity: 'info',
    defaultConfidence: 'high',
    category: 'dependencies',
    description:
      'Dependencies were inventoried from a manifest file but not checked against any ' +
      'vulnerability database, because scanners.dependencies.dataSource is "none".',
    recommendation:
      'Set scanners.dependencies.dataSource to "file" (with advisoryDbPath) or "osv" in ' +
      'sentinel.yml to enable vulnerability checks.',
    references: [],
  },
  {
    id: 'D003',
    title: 'Manifest present without a lockfile',
    severity: 'low',
    defaultConfidence: 'medium',
    category: 'dependencies',
    description:
      'A dependency manifest (package.json or Cargo.toml) declares dependencies but no ' +
      'corresponding lockfile was found, so installed versions are not pinned or ' +
      'reproducible across installs.',
    recommendation:
      'Commit the ecosystem lockfile alongside the manifest: package-lock.json, yarn.lock, ' +
      'or pnpm-lock.yaml for npm; Cargo.lock for Cargo.',
    references: [],
  },
];
