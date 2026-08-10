/**
 * The action's orchestration, kept testable: `runAction(io)` reads its whole
 * configuration from `io.env`, does all networking through `io.fetch`, and
 * writes to the GitHub environment files named in `io.env`. It returns a
 * process exit code (see exit-codes.ts) rather than calling `process.exit`, so
 * tests drive it in-process; `main.ts` binds `io` to the real process.
 *
 * Flow: parse inputs → load config → scan the head tree → resolve a baseline
 * (committed file or base-tree scan) → keep only NEW findings → write SARIF →
 * write the Step Summary → post/patch the sticky PR comment → write outputs →
 * exit 1 iff a new finding hits the fail-on severities.
 */

import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import type { Baseline, Report, SentinelConfig, Severity, SeverityStats } from '@dl-sentinel/core';
import { computeStats, evaluatePolicy } from '@dl-sentinel/core';
import { loadConfig } from '@dl-sentinel/engine';
import { renderSarif } from '@dl-sentinel/reporting';
import { readPullRequestContext } from './event.js';
import { EXIT, type ExitCode } from './exit-codes.js';
import { upsertStickyComment } from './github.js';
import { type ActionInputs, parseInputs, resolveToken } from './inputs.js';
import type { ActionIO } from './io.js';
import { baselineFromBase, diffAgainstBaseline, readBaselineFile, scanTarget } from './scan.js';
import { buildSummary } from './summary.js';
import { appendStepSummary, error, notice, warning, writeOutputs } from './workflow.js';

const DEFAULT_API_URL = 'https://api.github.com';

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Convert an absolute path inside `root` to a posix, root-relative path; undefined if outside. */
function insideRoot(root: string, target: string): string | undefined {
  const rel = path.relative(root, target);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return undefined;
  return rel.split(path.sep).join('/');
}

/**
 * Extra exclude globs so the head scan never walks into the base checkout or
 * re-reads a stale SARIF file when either lives inside the scanned tree. A
 * `dir/**` pattern also prunes the directory itself during discovery.
 */
function derivedExcludes(target: string, inputs: ActionInputs, workspace: string): string[] {
  const excludes: string[] = [];
  if (inputs.basePath !== undefined) {
    const rel = insideRoot(target, path.resolve(workspace, inputs.basePath));
    if (rel !== undefined) excludes.push(`${rel}/**`);
  }
  const sarifRel = insideRoot(target, path.resolve(workspace, inputs.sarifFile));
  if (sarifRel !== undefined) excludes.push(sarifRel);
  return excludes;
}

/** Read a baseline from the committed file or the base-tree scan, or undefined. */
async function resolveBaseline(
  io: ActionIO,
  inputs: ActionInputs,
  config: SentinelConfig,
  workspace: string,
): Promise<Baseline | undefined> {
  if (inputs.baselineFile !== undefined) {
    const file = path.resolve(workspace, inputs.baselineFile);
    const baseline = await readBaselineFile(file);
    notice(io, `Applying committed baseline ${file}.`);
    return baseline;
  }
  if (inputs.basePath !== undefined) {
    const baseTarget = path.resolve(workspace, inputs.basePath);
    notice(io, `Building a baseline by scanning the base tree at ${baseTarget}.`);
    return baselineFromBase(baseTarget, config, inputs.scanners);
  }
  return undefined;
}

/** Public entry point. Never throws: any error is reported and mapped to EXIT.ERROR. */
export async function runAction(io: ActionIO): Promise<ExitCode> {
  try {
    return await execute(io);
  } catch (err) {
    error(io, `DL Sentinel action failed: ${messageOf(err)}`);
    return EXIT.ERROR;
  }
}

async function execute(io: ActionIO): Promise<ExitCode> {
  const inputs = parseInputs(io.env);
  const workspace = io.env.GITHUB_WORKSPACE ?? process.cwd();
  const target = path.resolve(workspace, inputs.path);

  // Load config (honors an in-repo sentinel.yml) and apply the fail-on override.
  const configPath =
    inputs.config === undefined ? undefined : path.resolve(workspace, inputs.config);
  const loaded = await loadConfig(target, configPath);
  const baseConfig: SentinelConfig = {
    ...loaded,
    policy: { ...loaded.policy, failOn: inputs.failOn },
  };

  // Scan the head tree, excluding the base checkout / SARIF file if nested.
  const extraExcludes = derivedExcludes(target, inputs, workspace);
  const headConfig: SentinelConfig =
    extraExcludes.length > 0
      ? { ...baseConfig, exclude: [...baseConfig.exclude, ...extraExcludes] }
      : baseConfig;
  const headReport = await scanTarget({ target, config: headConfig, scanners: inputs.scanners });
  const allFindings = headReport.findings;

  // Narrow to findings the PR introduced.
  const baseline = await resolveBaseline(io, inputs, baseConfig, workspace);
  const { newFindings, baselined, baselineApplied } = diffAgainstBaseline(allFindings, baseline);
  const newStats = computeStats(newFindings);
  const policy = evaluatePolicy(newStats, { failOn: inputs.failOn });
  const failed = !policy.pass;

  // SARIF of the NEW findings, so code-scanning shows only what the PR added.
  if (inputs.sarif) {
    const sarifReport: Report = {
      ...headReport,
      findings: newFindings,
      stats: newStats,
      ...(baselineApplied ? { baseline: { newFindings: newFindings.length, baselined } } : {}),
    };
    const sarifPath = path.resolve(workspace, inputs.sarifFile);
    await writeFile(sarifPath, `${renderSarif(sarifReport)}\n`, 'utf8');
    notice(io, `Wrote SARIF (${newFindings.length} finding(s)) to ${sarifPath}.`);
  }

  // Concise, redaction-safe summary — always written to the Step Summary.
  const summary = buildSummary({
    newFindings,
    stats: newStats,
    totalFindings: allFindings.length,
    baselined,
    baselineApplied,
    failOn: inputs.failOn,
    failed,
  });
  await appendStepSummary(io, summary);

  // Sticky PR comment: only on a pull-request event, only with a token.
  const pr = await readPullRequestContext(io);
  if (inputs.comment) {
    if (pr === undefined) {
      notice(io, 'Not a pull_request event; skipping the PR comment.');
    } else {
      const token = resolveToken(io.env);
      if (token === undefined) {
        notice(io, 'No token available; skipping the PR comment (scan results still reported).');
      } else {
        const apiUrl = io.env.GITHUB_API_URL ?? DEFAULT_API_URL;
        try {
          const result = await upsertStickyComment(
            io,
            { apiUrl, repoFullName: pr.repoFullName, prNumber: pr.number, token },
            summary,
          );
          notice(io, `PR comment ${result.action} (HTTP ${result.status ?? 'n/a'}).`);
        } catch (err) {
          // Commenting must never fail the check.
          warning(io, `Could not post the PR comment: ${messageOf(err)}`);
        }
      }
    }
  }

  if (baseline === undefined && pr !== undefined) {
    notice(
      io,
      'No baseline or base_path provided; every finding is reported as new. ' +
        'Provide a committed baseline or check out the base tree to report only PR-introduced findings.',
    );
  }

  await writeOutputs(io, {
    findings_total: String(allFindings.length),
    findings_new: String(newFindings.length),
    failed: String(failed),
  });

  if (failed) {
    error(
      io,
      `DL Sentinel: ${newFindings.length} new finding(s), including ${describeViolations(policy.violations, newStats)} at or above the fail threshold (${inputs.failOn.join(', ')}).`,
    );
    return EXIT.POLICY;
  }
  notice(io, `DL Sentinel: no new findings at the fail threshold (${inputs.failOn.join(', ')}).`);
  return EXIT.OK;
}

/** e.g. "2 critical, 3 high" for the violated severities. */
function describeViolations(violations: readonly Severity[], stats: SeverityStats): string {
  return violations.map((severity) => `${stats[severity]} ${severity}`).join(', ');
}
