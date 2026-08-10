/**
 * `scanners.secrets` configuration (docs/architecture.md):
 *
 * ```yaml
 * scanners:
 *   secrets:
 *     enabled: true
 *     allowlist: []      # exact secret values, or rule ids (S001…) to suppress
 *     ignorePaths: []    # repo-relative globs, createMatcher semantics
 * ```
 *
 * Invalid entries are warned about and ignored rather than failing the scan —
 * a malformed allowlist must not take the scanner offline. Warnings never echo
 * an allowlist entry, because an allowlist entry is itself a secret value.
 */

import { createMatcher } from '@dl-sentinel/core';
import type { ScanLogger } from '@dl-sentinel/core';

export interface SecretsConfig {
  /** Mirrors the engine's own check; false means "produce nothing". */
  enabled: boolean;
  /** Exact secret values to suppress. */
  allowlistValues: ReadonlySet<string>;
  /** Rule ids to suppress entirely. */
  allowlistRuleIds: ReadonlySet<string>;
  /** True for paths excluded by `ignorePaths`. */
  isIgnoredPath: (relPath: string) => boolean;
}

const RULE_ID_ENTRY = /^S\d{3,}$/i;

function readStringArray(raw: Record<string, unknown>, key: string, logger: ScanLogger): string[] {
  const value = raw[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    logger.warn(`secrets: scanners.secrets.${key} must be an array of strings; ignoring it`);
    return [];
  }
  const out: string[] = [];
  value.forEach((entry, index) => {
    if (typeof entry === 'string' && entry !== '') {
      out.push(entry);
      return;
    }
    // Never log the entry itself: allowlist entries are secret values.
    logger.warn(`secrets: ignoring non-string entry at scanners.secrets.${key}[${index}]`);
  });
  return out;
}

export function readSecretsConfig(raw: Record<string, unknown>, logger: ScanLogger): SecretsConfig {
  const allowlist = readStringArray(raw, 'allowlist', logger);
  const ignorePaths = readStringArray(raw, 'ignorePaths', logger);

  const allowlistValues = new Set<string>();
  const allowlistRuleIds = new Set<string>();
  for (const entry of allowlist) {
    if (RULE_ID_ENTRY.test(entry)) {
      allowlistRuleIds.add(entry.toUpperCase());
    } else {
      allowlistValues.add(entry);
    }
  }

  const matcher = ignorePaths.length === 0 ? undefined : createMatcher(ignorePaths);

  return {
    enabled: raw['enabled'] !== false,
    allowlistValues,
    allowlistRuleIds,
    isIgnoredPath: matcher === undefined ? () => false : (relPath) => matcher(relPath),
  };
}
