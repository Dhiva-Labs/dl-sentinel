/**
 * GitHub Actions runtime conventions, implemented directly rather than through
 * `@actions/core`, so the action keeps the project's near-zero-dependency
 * identity. Two mechanisms are used:
 *
 * - Workflow commands: lines like `::error::message` written to stdout that the
 *   runner interprets (annotations, notices).
 * - Environment files: `$GITHUB_OUTPUT` and `$GITHUB_STEP_SUMMARY` are paths the
 *   action appends to; the runner reads them after the step.
 *
 * See https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions.
 */

import { appendFile } from 'node:fs/promises';
import type { ActionIO } from './io.js';

/** Escape a workflow-command message body (GitHub's documented data escaping). */
function escapeData(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/** Emit a `::notice::` workflow command (informational, no annotation weight). */
export function notice(io: ActionIO, message: string): void {
  io.stdout(`::notice::${escapeData(message)}\n`);
}

/** Emit a `::warning::` workflow command. */
export function warning(io: ActionIO, message: string): void {
  io.stdout(`::warning::${escapeData(message)}\n`);
}

/** Emit an `::error::` workflow command (surfaces as a failed-step annotation). */
export function error(io: ActionIO, message: string): void {
  io.stdout(`::error::${escapeData(message)}\n`);
}

/**
 * Append `name=value` lines to `$GITHUB_OUTPUT` so downstream steps can read
 * `steps.<id>.outputs.<name>`. Values here are always single-line scalars
 * (counts, booleans), so the simple `name=value` form is correct. A no-op when
 * the env var is unset (e.g. running locally).
 */
export async function writeOutputs(io: ActionIO, outputs: Record<string, string>): Promise<void> {
  const file = io.env.GITHUB_OUTPUT;
  if (file === undefined || file === '') return;
  const body = Object.entries(outputs)
    .map(([name, value]) => `${name}=${value}`)
    .join('\n');
  await appendFile(file, `${body}\n`, 'utf8');
}

/**
 * Append Markdown to `$GITHUB_STEP_SUMMARY`, the per-step summary rendered on
 * the run page. A no-op when the env var is unset.
 */
export async function appendStepSummary(io: ActionIO, markdown: string): Promise<void> {
  const file = io.env.GITHUB_STEP_SUMMARY;
  if (file === undefined || file === '') return;
  await appendFile(file, `${markdown}\n`, 'utf8');
}
