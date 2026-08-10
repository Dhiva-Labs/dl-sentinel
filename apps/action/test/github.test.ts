import { describe, expect, it } from 'vitest';
import { upsertStickyComment } from '../src/github.js';
import { COMMENT_MARKER } from '../src/summary.js';
import { captureIO, fakeFetch } from './helpers.js';

const TARGET = {
  apiUrl: 'https://api.github.com',
  repoFullName: 'octo/repo',
  prNumber: 7,
  token: 'ghs_FAKE_TOKEN',
};

const BODY = `${COMMENT_MARKER}\n## DL Sentinel — 1 new finding`;

describe('upsertStickyComment', () => {
  it('creates a new comment when none carries the marker', async () => {
    const fake = fakeFetch({ listComments: [{ id: 1, body: 'unrelated comment' }] });
    const { io } = captureIO({}, fake.fetch);

    const result = await upsertStickyComment(io, TARGET, BODY);

    expect(result.action).toBe('created');
    expect(fake.requests).toHaveLength(2);

    const [list, create] = fake.requests;
    expect(list?.method).toBe('GET');
    expect(list?.url).toBe('https://api.github.com/repos/octo/repo/issues/7/comments?per_page=100');

    expect(create?.method).toBe('POST');
    expect(create?.url).toBe('https://api.github.com/repos/octo/repo/issues/7/comments');
    expect(create?.headers.Authorization).toBe('Bearer ghs_FAKE_TOKEN');
    expect(create?.headers.Accept).toBe('application/vnd.github+json');
    expect(create?.headers['X-GitHub-Api-Version']).toBe('2022-11-28');
    expect(create?.headers['Content-Type']).toBe('application/json');
    const sent = JSON.parse(create?.body ?? '{}') as { body: string };
    expect(sent.body).toContain(COMMENT_MARKER);
  });

  it('updates the existing marker comment via PATCH', async () => {
    const fake = fakeFetch({
      listComments: [
        { id: 10, body: 'someone else' },
        { id: 42, body: `stale results\n${COMMENT_MARKER}\nold` },
      ],
    });
    const { io } = captureIO({}, fake.fetch);

    const result = await upsertStickyComment(io, TARGET, BODY);

    expect(result.action).toBe('updated');
    expect(result.commentId).toBe(42);
    const patch = fake.requests[1];
    expect(patch?.method).toBe('PATCH');
    expect(patch?.url).toBe('https://api.github.com/repos/octo/repo/issues/comments/42');
    expect(patch?.headers.Authorization).toBe('Bearer ghs_FAKE_TOKEN');
    const sent = JSON.parse(patch?.body ?? '{}') as { body: string };
    expect(sent.body).toBe(BODY);
  });

  it('creates a comment when the list request fails (non-ok GET)', async () => {
    const fake = fakeFetch({ listStatus: 403 });
    const { io } = captureIO({}, fake.fetch);
    const result = await upsertStickyComment(io, TARGET, BODY);
    expect(result.action).toBe('created');
    expect(fake.requests[1]?.method).toBe('POST');
  });

  it('throws when the write fails, so the caller can warn', async () => {
    const fake = fakeFetch({ listComments: [], writeStatus: 422 });
    const { io } = captureIO({}, fake.fetch);
    await expect(upsertStickyComment(io, TARGET, BODY)).rejects.toThrow(/422/);
  });

  it('normalizes a trailing slash on the API url', async () => {
    const fake = fakeFetch({ listComments: [] });
    const { io } = captureIO({}, fake.fetch);
    await upsertStickyComment(io, { ...TARGET, apiUrl: 'https://ghe.example.com/api/v3/' }, BODY);
    expect(fake.requests[0]?.url).toBe(
      'https://ghe.example.com/api/v3/repos/octo/repo/issues/7/comments?per_page=100',
    );
  });
});
