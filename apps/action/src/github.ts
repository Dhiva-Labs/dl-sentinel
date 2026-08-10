/**
 * Minimal GitHub REST client for the one thing the action posts: a sticky PR
 * comment. Implemented on the injected `fetch` (io.fetch) with the documented
 * REST endpoints, so there is no `@actions/github`/Octokit dependency and tests
 * can drive it with a fake fetch.
 *
 * "Sticky" means: find a prior comment this action wrote (identified by the
 * hidden marker in its body) and PATCH it; otherwise POST a new one. This keeps
 * one comment per PR instead of a new one on every run.
 */

import type { ActionIO } from './io.js';
import { COMMENT_MARKER } from './summary.js';

export interface CommentTarget {
  /** REST API base, e.g. https://api.github.com (or a GHES host). */
  apiUrl: string;
  /** owner/repo. */
  repoFullName: string;
  /** PR/issue number. */
  prNumber: number;
  /** Bearer token (never logged). */
  token: string;
}

export type CommentAction = 'created' | 'updated' | 'skipped';

export interface CommentResult {
  action: CommentAction;
  status?: number;
  commentId?: number;
}

interface IssueComment {
  id: number;
  body?: string;
}

function baseHeaders(token: string): Record<string, string> {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'dl-sentinel-action',
  };
}

/** Strip a trailing slash so URL joins don't double up. */
function trimSlash(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

/**
 * Find the id of a prior comment authored by this action (body contains
 * {@link COMMENT_MARKER}). Returns undefined when none is found or the list
 * request fails — callers then create a fresh comment.
 */
async function findExistingComment(
  io: ActionIO,
  target: CommentTarget,
): Promise<number | undefined> {
  const base = `${trimSlash(target.apiUrl)}/repos/${target.repoFullName}`;
  const url = `${base}/issues/${target.prNumber}/comments?per_page=100`;
  const res = await io.fetch(url, { method: 'GET', headers: baseHeaders(target.token) });
  if (!res.ok) return undefined;
  const data = (await res.json()) as unknown;
  if (!Array.isArray(data)) return undefined;
  for (const raw of data as IssueComment[]) {
    if (raw !== null && typeof raw.body === 'string' && raw.body.includes(COMMENT_MARKER)) {
      return raw.id;
    }
  }
  return undefined;
}

/**
 * Create or update the sticky comment. Network/HTTP failures are surfaced by
 * throwing; the caller (action.ts) wraps this so a commenting failure only
 * warns and never fails the overall check.
 */
export async function upsertStickyComment(
  io: ActionIO,
  target: CommentTarget,
  body: string,
): Promise<CommentResult> {
  const base = `${trimSlash(target.apiUrl)}/repos/${target.repoFullName}`;
  const writeHeaders = { ...baseHeaders(target.token), 'Content-Type': 'application/json' };

  const existingId = await findExistingComment(io, target);
  if (existingId !== undefined) {
    const res = await io.fetch(`${base}/issues/comments/${existingId}`, {
      method: 'PATCH',
      headers: writeHeaders,
      body: JSON.stringify({ body }),
    });
    if (!res.ok) {
      throw new Error(`GitHub API PATCH comment failed with status ${res.status}`);
    }
    return { action: 'updated', status: res.status, commentId: existingId };
  }

  const res = await io.fetch(`${base}/issues/${target.prNumber}/comments`, {
    method: 'POST',
    headers: writeHeaders,
    body: JSON.stringify({ body }),
  });
  if (!res.ok) {
    throw new Error(`GitHub API POST comment failed with status ${res.status}`);
  }
  return { action: 'created', status: res.status };
}
