/**
 * Parse the action's configuration out of the environment. GitHub Actions
 * surfaces each declared input as an `INPUT_<NAME>` env var (name upper-cased,
 * so the underscore-named inputs in action.yml become INPUT_FAIL_ON etc.), and
 * provides the `GITHUB_*` context vars separately. Everything the action needs
 * is read here into one typed, defaulted structure.
 */

import type { Severity } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';

export interface ActionInputs {
  /** Directory to scan, relative to the workspace. Default '.'. */
  path: string;
  /** Severities that fail the check when newly introduced. Default critical,high. */
  failOn: Severity[];
  /** Optional subset of scanner ids to run; undefined runs them all. */
  scanners?: string[];
  /** Optional path to a committed baseline file (relative to the workspace). */
  baselineFile?: string;
  /** Optional directory holding the base tree, scanned to build a baseline. */
  basePath?: string;
  /** Optional explicit sentinel.yml path (relative to the workspace). */
  config?: string;
  /** Post/update a sticky PR comment. Default true. */
  comment: boolean;
  /** Write a SARIF file of the new findings. Default true. */
  sarif: boolean;
  /** Where to write the SARIF file. Default 'sentinel-results.sarif'. */
  sarifFile: string;
}

const VALID_SEVERITIES = new Set<string>(SEVERITY_ORDER);

/** Trim a value and return undefined if it is absent or blank. */
function nonEmpty(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

/** Parse a comma/whitespace separated list; undefined when nothing is left. */
function parseList(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  const items = value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item !== '');
  return items.length === 0 ? undefined : items;
}

/** Parse a boolean input; `def` is used when the value is absent/blank. */
export function parseBool(value: string | undefined, def: boolean): boolean {
  const v = nonEmpty(value)?.toLowerCase();
  if (v === undefined) return def;
  if (v === 'true' || v === '1' || v === 'yes') return true;
  if (v === 'false' || v === '0' || v === 'no') return false;
  return def;
}

/**
 * Parse and validate a `fail_on` severity list. Throws on an unknown severity
 * so a misconfigured workflow fails loudly (exit 2) rather than silently
 * scanning with a surprising policy.
 */
export function parseSeverityList(value: string | undefined, fallback: Severity[]): Severity[] {
  const items = parseList(value);
  if (items === undefined) return [...fallback];
  for (const item of items) {
    if (!VALID_SEVERITIES.has(item)) {
      throw new Error(
        `Invalid fail_on severity "${item}" (expected one of ${SEVERITY_ORDER.join(', ')})`,
      );
    }
  }
  return items as Severity[];
}

/** Read the action inputs from `env`, applying defaults and validation. */
export function parseInputs(env: NodeJS.ProcessEnv): ActionInputs {
  const inputs: ActionInputs = {
    path: nonEmpty(env.INPUT_PATH) ?? '.',
    failOn: parseSeverityList(env.INPUT_FAIL_ON, ['critical', 'high']),
    comment: parseBool(env.INPUT_COMMENT, true),
    sarif: parseBool(env.INPUT_SARIF, true),
    sarifFile: nonEmpty(env.INPUT_SARIF_FILE) ?? 'sentinel-results.sarif',
  };
  const scanners = parseList(env.INPUT_SCANNERS);
  if (scanners !== undefined) inputs.scanners = scanners;
  const baselineFile = nonEmpty(env.INPUT_BASELINE);
  if (baselineFile !== undefined) inputs.baselineFile = baselineFile;
  const basePath = nonEmpty(env.INPUT_BASE_PATH);
  if (basePath !== undefined) inputs.basePath = basePath;
  const config = nonEmpty(env.INPUT_CONFIG);
  if (config !== undefined) inputs.config = config;
  return inputs;
}

/**
 * The GitHub token used for the PR-comment API call. Prefers the action's own
 * `token` input (INPUT_TOKEN, defaulted to `${{ github.token }}` in action.yml)
 * and falls back to a `GITHUB_TOKEN` in the environment. Undefined when neither
 * is present, which the action treats as "skip commenting".
 */
export function resolveToken(env: NodeJS.ProcessEnv): string | undefined {
  return nonEmpty(env.INPUT_TOKEN) ?? nonEmpty(env.GITHUB_TOKEN);
}
