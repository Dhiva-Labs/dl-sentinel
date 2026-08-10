/**
 * Shared value-flag validators. Each returns a strongly-typed value or throws
 * {@link CliUsageError} (exit 64) so unknown formats / scanners / severities
 * fail fast with a helpful message before any scanning starts.
 */
import type { Severity } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';
import { BUILTIN_SCANNERS } from '@dl-sentinel/preset';
import { CliUsageError } from './args.js';

/** Split a comma-separated flag value, trimming and dropping empties. */
export function splitCsv(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

/** Validate `--format`, defaulting to the first allowed value when unset. */
export function parseFormat<T extends string>(value: string | undefined, allowed: readonly T[]): T {
  const fallback = allowed[0];
  if (fallback === undefined) {
    // Never happens: every caller passes a non-empty list.
    throw new CliUsageError('no output formats are configured');
  }
  if (value === undefined) return fallback;
  if ((allowed as readonly string[]).includes(value)) return value as T;
  throw new CliUsageError(`Invalid --format "${value}" (expected one of ${allowed.join(', ')})`);
}

/** Validate `--scanners` against the built-in scanner ids. */
export function parseScannerList(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  const ids = splitCsv(value);
  if (ids.length === 0) {
    throw new CliUsageError('--scanners requires at least one scanner id');
  }
  const known = new Set(BUILTIN_SCANNERS.map((scanner) => scanner.id));
  const unknown = ids.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    throw new CliUsageError(
      `Unknown scanner${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')} (known: ${[...known].join(', ')})`,
    );
  }
  return ids;
}

/** Validate a comma-separated severity flag (e.g. `--fail-on`). */
export function parseSeverityList(value: string | undefined, flag: string): Severity[] | undefined {
  if (value === undefined) return undefined;
  const items = splitCsv(value);
  if (items.length === 0) {
    throw new CliUsageError(`--${flag} requires at least one severity`);
  }
  const valid = new Set<string>(SEVERITY_ORDER);
  const bad = items.filter((item) => !valid.has(item));
  if (bad.length > 0) {
    throw new CliUsageError(
      `Invalid severit${bad.length > 1 ? 'ies' : 'y'} for --${flag}: ${bad.join(', ')} (expected one of ${SEVERITY_ORDER.join(', ')})`,
    );
  }
  return items as Severity[];
}
