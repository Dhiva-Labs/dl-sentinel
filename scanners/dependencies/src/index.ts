// Dependencies scanner plugin.
// Contract: docs/scanner-interface.md — export a ScannerPlugin as the default entry point.
import type { ScannerPlugin } from '@dl-sentinel/core';
import { rules } from './rules.js';
import { scan } from './scan.js';

export type {
  AdvisorySeverity,
  Advisory,
  AffectedRange,
  DataSourceKind,
  DependenciesScannerSettings,
  DependencyRecord,
  Ecosystem,
  PackageQuery,
  VersionKind,
  VulnDataSource,
} from './types.js';
export { FileDataSource } from './datasource/file.js';
export { OsvDataSource, type FetchFn } from './datasource/osv.js';
export { rules } from './rules.js';

export const dependenciesScanner: ScannerPlugin = {
  id: 'dependencies',
  name: 'Dependency Scanner',
  version: '0.1.0',
  categories: ['dependencies'],
  supportedFiles: [
    '**/package.json',
    '**/package-lock.json',
    '**/requirements.txt',
    '**/requirements-*.txt',
    '**/go.mod',
    '**/Cargo.toml',
    '**/Cargo.lock',
  ],
  rules,
  scan,
};

export default dependenciesScanner;
