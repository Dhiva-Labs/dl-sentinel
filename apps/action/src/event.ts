/**
 * Read the pull-request context from the GitHub event payload. On a
 * `pull_request` (or `pull_request_target`) event the runner writes the webhook
 * payload to the file at `$GITHUB_EVENT_PATH`; the PR number lives at the top
 * level (`number`) and, defensively, at `pull_request.number`. base/head shas
 * and the repo name are informational.
 *
 * The payload is untrusted input to a security tool, so every field is read
 * defensively: anything malformed yields `undefined` (no PR context) rather
 * than throwing, and no payload text is echoed.
 */

import { readFile } from 'node:fs/promises';
import type { ActionIO } from './io.js';

export interface PullRequestContext {
  /** Issue/PR number used for the comment API. */
  number: number;
  /** owner/repo the PR belongs to. */
  repoFullName: string;
  /** Base branch tip sha (informational). */
  baseSha: string;
  /** Head sha (informational). */
  headSha: string;
  /** Base branch ref name, e.g. "main" (informational). */
  baseRef: string;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : undefined;
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

const PR_EVENTS = new Set(['pull_request', 'pull_request_target']);

/**
 * Resolve the PR context, or undefined when this is not a pull-request event or
 * the payload lacks a usable PR number.
 */
export async function readPullRequestContext(
  io: ActionIO,
): Promise<PullRequestContext | undefined> {
  const eventName = io.env.GITHUB_EVENT_NAME;
  if (eventName === undefined || !PR_EVENTS.has(eventName)) return undefined;

  const eventPath = io.env.GITHUB_EVENT_PATH;
  if (eventPath === undefined || eventPath === '') return undefined;

  let raw: string;
  try {
    raw = await readFile(eventPath, 'utf8');
  } catch {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }

  const event = asRecord(parsed);
  if (event === undefined) return undefined;

  const pr = asRecord(event.pull_request);
  const number =
    typeof event.number === 'number'
      ? event.number
      : pr !== undefined && typeof pr.number === 'number'
        ? pr.number
        : undefined;
  if (number === undefined) return undefined;

  const repository = asRecord(event.repository);
  const base = pr !== undefined ? asRecord(pr.base) : undefined;
  const head = pr !== undefined ? asRecord(pr.head) : undefined;

  return {
    number,
    repoFullName:
      (repository !== undefined ? asString(repository.full_name) : '') ||
      asString(io.env.GITHUB_REPOSITORY),
    baseSha: base !== undefined ? asString(base.sha) : '',
    headSha: head !== undefined ? asString(head.sha) : '',
    baseRef: base !== undefined ? asString(base.ref) : '',
  };
}
