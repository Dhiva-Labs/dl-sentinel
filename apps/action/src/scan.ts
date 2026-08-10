/**
 * Scanning and the "only new findings" diff. The action runs the same default
 * engine the CLI does, then narrows the head scan's findings to those the pull
 * request introduced. A baseline comes from one of two sources:
 *
 * - a committed baseline file (INPUT_BASELINE), read and validated; or
 * - the base tree itself, checked out by the workflow into a directory
 *   (INPUT_BASE_PATH) and scanned here to build an in-memory baseline.
 *
 * Git operations (checking out the base ref) live in the workflow YAML, not
 * here: this module only accepts a baseline file or an already-present base
 * directory. Because finding ids are stable fingerprints over repo-relative
 * paths, a base tree scanned at any location yields ids that line up with the
 * head scan, so the diff is exact.
 */

import { readFile } from 'node:fs/promises';
import type { Baseline, Finding, Report, SentinelConfig } from '@dl-sentinel/core';
import { applyBaseline, createBaseline, parseBaseline } from '@dl-sentinel/core';
import type { ScanOptions } from '@dl-sentinel/engine';
import { createDefaultEngine } from '@dl-sentinel/preset';

export interface ScanRequest {
  target: string;
  config: SentinelConfig;
  scanners?: string[];
}

/** Run the default engine over a target and return its report. */
export async function scanTarget(req: ScanRequest): Promise<Report> {
  const options: ScanOptions = { target: req.target, config: req.config };
  if (req.scanners !== undefined) options.scanners = req.scanners;
  return createDefaultEngine().scan(options);
}

export interface NewFindingsResult {
  /** Findings the PR introduced (absent from the baseline). */
  newFindings: Finding[];
  /** How many findings were already in the baseline. */
  baselined: number;
  /** True when a baseline was applied (false ⇒ every finding counts as new). */
  baselineApplied: boolean;
}

/**
 * Partition `findings` against a baseline. With no baseline every finding is
 * "new" (the honest default: without a base to compare to, the tool reports
 * everything rather than pretending nothing changed).
 */
export function diffAgainstBaseline(
  findings: readonly Finding[],
  baseline: Baseline | undefined,
): NewFindingsResult {
  if (baseline === undefined) {
    return { newFindings: [...findings], baselined: 0, baselineApplied: false };
  }
  const { newFindings, baselined } = applyBaseline(findings, baseline);
  return { newFindings, baselined: baselined.length, baselineApplied: true };
}

/**
 * Read and validate a committed baseline file. Any problem — unreadable, not
 * JSON, or the wrong shape — throws, but the file's raw bytes are never placed
 * in the error message: a baseline is untrusted input to a security tool.
 */
export async function readBaselineFile(file: string): Promise<Baseline> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    throw new Error(
      `Cannot read baseline file ${file}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    // Omit the parser detail — it can quote bytes from the file.
    throw new Error(`Baseline file ${file} is not valid JSON`);
  }
  try {
    return parseBaseline(data);
  } catch (error) {
    throw new Error(
      `Baseline file ${file} is not a valid DL Sentinel baseline: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * Build an in-memory baseline by scanning a base tree. The same config and
 * scanner subset as the head scan are used so finding ids are directly
 * comparable. `generatedAt` is fixed — the baseline is never written to disk and
 * only its id set matters for the diff — keeping the result deterministic.
 */
export async function baselineFromBase(
  basePath: string,
  config: SentinelConfig,
  scanners: string[] | undefined,
): Promise<Baseline> {
  const req: ScanRequest = { target: basePath, config };
  if (scanners !== undefined) req.scanners = scanners;
  const report = await scanTarget(req);
  return createBaseline(report.findings, {
    target: report.target,
    generatedAt: '1970-01-01T00:00:00.000Z',
  });
}
