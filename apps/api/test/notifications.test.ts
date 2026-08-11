import { createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  bearer,
  createUser,
  fakeFetch,
  failingEngine,
  instantEngine,
  mutableClock,
  postJson,
  sendJsonRequest,
  startTestServer,
  vulnerableApp,
  waitForScan,
} from './support.js';
import type { FakeFetch, TestServer } from './support.js';
import type {
  DeliveryResult,
  NotificationPayload,
  PublicChannel,
  ScheduleRecord,
} from '../src/index.js';
import { PLANTED_SECRETS } from '../../../tests/support/index.js';

const MINUTE = 60_000;
const SECRET = 'signing-secret-EXAMPLE-not-a-real-key';
const HOOK_URL = 'https://hooks.example.test/sentinel';
const SLACK_URL = 'https://hooks.slack.test/services/T000/B000/xxxx';

interface ErrorBody {
  error: { code: string; message: string };
}

async function createChannel(ctx: TestServer, body: unknown, token = ctx.token): Promise<Response> {
  return postJson(ctx.base, '/api/notifications', token, body);
}

async function createdChannel(ctx: TestServer, body: unknown): Promise<PublicChannel> {
  const res = await createChannel(ctx, body);
  if (res.status !== 201) {
    throw new Error(`Expected 201 creating channel, got ${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as PublicChannel;
}

function listChannels(ctx: TestServer): Promise<Response> {
  return fetch(`${ctx.base}/api/notifications`, { headers: bearer(ctx.token) });
}

/** A minimal valid webhook channel body subscribed to everything. */
function webhookBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'webhook',
    url: HOOK_URL,
    events: ['scan.completed', 'scan.failed', 'policy.violated', 'schedule.failed'],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// CRUD and validation
// ---------------------------------------------------------------------------

describe('notification channel CRUD', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: fakeFetch().impl,
    });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('POST /api/notifications creates a channel (201)', async () => {
    const channel = await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));
    expect(typeof channel.id).toBe('string');
    expect(channel.id.length).toBeGreaterThan(0);
    expect(channel.type).toBe('webhook');
    expect(channel.url).toBe(HOOK_URL);
    expect(channel.events).toEqual(['scan.completed']);
    expect(channel.enabled).toBe(true);
    expect(channel.hasSecret).toBe(false);
    expect(Number.isNaN(Date.parse(channel.createdAt))).toBe(false);
    expect(channel.lastError).toBeUndefined();
  });

  it('normalizes the event list to canonical order without duplicates', async () => {
    const channel = await createdChannel(
      ctx,
      webhookBody({ events: ['policy.violated', 'scan.completed', 'policy.violated'] }),
    );
    expect(channel.events).toEqual(['scan.completed', 'policy.violated']);
  });

  it('accepts a slack channel and an explicit enabled:false', async () => {
    const channel = await createdChannel(ctx, {
      type: 'slack',
      url: SLACK_URL,
      events: ['scan.failed'],
      enabled: false,
    });
    expect(channel.type).toBe('slack');
    expect(channel.enabled).toBe(false);
  });

  it('GET /api/notifications lists channels', async () => {
    await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));
    await createdChannel(ctx, { type: 'slack', url: SLACK_URL, events: ['scan.failed'] });
    const res = await listChannels(ctx);
    expect(res.status).toBe(200);
    const list = (await res.json()) as PublicChannel[];
    expect(list.length).toBe(2);
  });

  it('GET /api/notifications/:id returns one, 404 for unknown', async () => {
    const created = await createdChannel(ctx, webhookBody());
    const found = await fetch(`${ctx.base}/api/notifications/${created.id}`, {
      headers: bearer(ctx.token),
    });
    expect(found.status).toBe(200);
    expect(((await found.json()) as PublicChannel).id).toBe(created.id);

    const missing = await fetch(`${ctx.base}/api/notifications/does-not-exist`, {
      headers: bearer(ctx.token),
    });
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as ErrorBody).error.code).toBe('not_found');
  });

  it('PATCH updates enabled, events, url and secret', async () => {
    const created = await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));

    const res = await sendJsonRequest(
      ctx.base,
      `/api/notifications/${created.id}`,
      ctx.token,
      'PATCH',
      {
        enabled: false,
        events: ['scan.failed', 'policy.violated'],
        url: 'https://other.example.test/hook',
        secret: SECRET,
      },
    );
    expect(res.status).toBe(200);
    const updated = (await res.json()) as PublicChannel;
    expect(updated.enabled).toBe(false);
    expect(updated.events).toEqual(['scan.failed', 'policy.violated']);
    expect(updated.url).toBe('https://other.example.test/hook');
    expect(updated.hasSecret).toBe(true);
  });

  it('PATCH with secret:null removes signing; omitting the field keeps it', async () => {
    const created = await createdChannel(ctx, webhookBody({ secret: SECRET }));
    expect(created.hasSecret).toBe(true);

    const untouched = (await (
      await sendJsonRequest(ctx.base, `/api/notifications/${created.id}`, ctx.token, 'PATCH', {
        enabled: false,
      })
    ).json()) as PublicChannel;
    expect(untouched.hasSecret).toBe(true);

    const removed = (await (
      await sendJsonRequest(ctx.base, `/api/notifications/${created.id}`, ctx.token, 'PATCH', {
        secret: null,
      })
    ).json()) as PublicChannel;
    expect(removed.hasSecret).toBe(false);
  });

  it('DELETE returns 204, then 404 for a second delete', async () => {
    const created = await createdChannel(ctx, webhookBody());
    const del = await sendJsonRequest(
      ctx.base,
      `/api/notifications/${created.id}`,
      ctx.token,
      'DELETE',
    );
    expect(del.status).toBe(204);
    expect(await del.text()).toBe('');

    const again = await sendJsonRequest(
      ctx.base,
      `/api/notifications/${created.id}`,
      ctx.token,
      'DELETE',
    );
    expect(again.status).toBe(404);
  });

  it('PATCH returns 404 for an unknown channel', async () => {
    const res = await sendJsonRequest(ctx.base, '/api/notifications/nope', ctx.token, 'PATCH', {
      enabled: false,
    });
    expect(res.status).toBe(404);
  });

  it('answers 405 with an Allow header for an unsupported method', async () => {
    const res = await sendJsonRequest(ctx.base, '/api/notifications', ctx.token, 'PUT', {});
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET, POST');
  });
});

describe('notification channel validation', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: fakeFetch().impl,
    });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  async function expectValidationError(body: unknown): Promise<string> {
    const res = await createChannel(ctx, body);
    expect(res.status).toBe(400);
    const parsed = (await res.json()) as ErrorBody;
    expect(parsed.error.code).toBe('validation_error');
    return parsed.error.message;
  }

  it('rejects an unknown type', async () => {
    const message = await expectValidationError(webhookBody({ type: 'pager' }));
    expect(message).toContain('webhook');
  });

  it('rejects a missing type', async () => {
    await expectValidationError({ url: HOOK_URL, events: ['scan.completed'] });
  });

  it('rejects a malformed url', async () => {
    await expectValidationError(webhookBody({ url: 'not a url' }));
    await expectValidationError(webhookBody({ url: '' }));
    await expectValidationError(webhookBody({ url: 42 }));
  });

  it('rejects a non-https url for a non-local host', async () => {
    const message = await expectValidationError(webhookBody({ url: 'http://example.test/hook' }));
    expect(message).toContain('https');
  });

  it('rejects a non-http(s) scheme', async () => {
    await expectValidationError(webhookBody({ url: 'file:///etc/passwd' }));
    await expectValidationError(webhookBody({ url: 'ftp://example.test/hook' }));
  });

  it('accepts plain http for localhost and 127.0.0.1', async () => {
    for (const url of ['http://localhost:9000/hook', 'http://127.0.0.1:9000/hook']) {
      const channel = await createdChannel(ctx, webhookBody({ url }));
      expect(channel.url).toBe(url);
    }
  });

  it('rejects an empty, missing or unknown event list', async () => {
    await expectValidationError(webhookBody({ events: [] }));
    await expectValidationError({ type: 'webhook', url: HOOK_URL });
    const message = await expectValidationError(webhookBody({ events: ['scan.exploded'] }));
    expect(message).toContain('scan.exploded');
    await expectValidationError(webhookBody({ events: 'scan.completed' }));
  });

  it('rejects a non-string or empty secret', async () => {
    await expectValidationError(webhookBody({ secret: '' }));
    await expectValidationError(webhookBody({ secret: 12345 }));
    await expectValidationError(webhookBody({ secret: 'x'.repeat(1000) }));
  });

  it('rejects a non-object body', async () => {
    const res = await sendJsonRequest(ctx.base, '/api/notifications', ctx.token, 'POST', [1, 2]);
    expect(res.status).toBe(400);
  });

  it('requires authentication on every notification route (401)', async () => {
    const routes: Array<[string, string]> = [
      ['GET', '/api/notifications'],
      ['POST', '/api/notifications'],
      ['GET', '/api/notifications/x'],
      ['PATCH', '/api/notifications/x'],
      ['DELETE', '/api/notifications/x'],
      ['POST', '/api/notifications/x/test'],
    ];
    for (const [method, route] of routes) {
      const res = await fetch(`${ctx.base}${route}`, { method });
      expect(res.status, `${method} ${route}`).toBe(401);
    }
  });
});

// ---------------------------------------------------------------------------
// Secrets are stored but never served or logged
// ---------------------------------------------------------------------------

describe('channel secrets are never disclosed', () => {
  let ctx: TestServer;
  let logLines: string[];

  beforeEach(async () => {
    logLines = [];
    const record = (message: string): void => {
      logLines.push(message);
    };
    ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: fakeFetch().impl,
      logger: { info: record, warn: record, error: record },
    });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('never echoes the secret from create, get, list or patch', async () => {
    const created = await createdChannel(ctx, webhookBody({ secret: SECRET }));
    expect(JSON.stringify(created)).not.toContain(SECRET);
    expect(created.hasSecret).toBe(true);
    expect((created as unknown as Record<string, unknown>)['secret']).toBeUndefined();

    const single = await (
      await fetch(`${ctx.base}/api/notifications/${created.id}`, { headers: bearer(ctx.token) })
    ).text();
    expect(single).not.toContain(SECRET);

    const list = await (await listChannels(ctx)).text();
    expect(list).not.toContain(SECRET);

    const patched = await (
      await sendJsonRequest(ctx.base, `/api/notifications/${created.id}`, ctx.token, 'PATCH', {
        secret: 'another-secret-EXAMPLE',
      })
    ).text();
    expect(patched).not.toContain(SECRET);
    expect(patched).not.toContain('another-secret-EXAMPLE');
  });

  it('never writes the secret to the log, even when delivery fails', async () => {
    const failing = fakeFetch();
    failing.failWith(new Error('connect ECONNREFUSED'));
    const failCtx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: failing.impl,
      logger: {
        info: (m) => logLines.push(m),
        warn: (m) => logLines.push(m),
        error: (m) => logLines.push(m),
      },
    });
    try {
      const channel = await createdChannel(failCtx, webhookBody({ secret: SECRET }));
      await postJson(failCtx.base, `/api/notifications/${channel.id}/test`, failCtx.token, {});
      await failCtx.server.notifier.drain();
      expect(logLines.length).toBeGreaterThan(0);
      const joined = logLines.join('\n');
      expect(joined).not.toContain(SECRET);
      // The URL is a credential for slack-style endpoints, so it is not logged.
      expect(joined).not.toContain(HOOK_URL);
    } finally {
      await failCtx.cleanup();
    }
  });

  it('never writes the secret to the audit log', async () => {
    await createdChannel(ctx, webhookBody({ secret: SECRET }));
    const auditPath = path.join(ctx.dataDir, 'audit.log');
    // The append is fire-and-forget; the flush in cleanup happens later, so read
    // what exists now and assert on it — the secret can never appear at all.
    let raw = '';
    try {
      raw = readFileSync(auditPath, 'utf8');
    } catch {
      raw = '';
    }
    expect(raw).not.toContain(SECRET);
  });

  it('does store the secret on disk — it must, to sign', async () => {
    // The one place it legitimately lives. Asserted so the "never served" tests
    // above cannot pass by the secret having been silently dropped.
    const created = await createdChannel(ctx, webhookBody({ secret: SECRET }));
    const file = path.join(ctx.dataDir, 'notifications', `${created.id}.json`);
    expect(readFileSync(file, 'utf8')).toContain(SECRET);
  });
});

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

describe('notification configuration is admin-only', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: fakeFetch().impl,
    });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('403s every notification route for operator and viewer, reads included', async () => {
    const created = await createdChannel(ctx, webhookBody());
    for (const role of ['operator', 'viewer'] as const) {
      const user = await createUser(ctx, { name: `${role}-user`, role });
      const routes: Array<[string, string, unknown]> = [
        ['GET', '/api/notifications', undefined],
        ['POST', '/api/notifications', webhookBody()],
        ['GET', `/api/notifications/${created.id}`, undefined],
        ['PATCH', `/api/notifications/${created.id}`, { enabled: false }],
        ['DELETE', `/api/notifications/${created.id}`, undefined],
        ['POST', `/api/notifications/${created.id}/test`, {}],
      ];
      for (const [method, route, body] of routes) {
        const res = await sendJsonRequest(ctx.base, route, user.token, method, body);
        expect(res.status, `${role} ${method} ${route}`).toBe(403);
        expect(((await res.json()) as ErrorBody).error.code).toBe('forbidden');
      }
    }
  });

  it('permits an admin user, not just the bootstrap token', async () => {
    const admin = await createUser(ctx, { name: 'admin-user', role: 'admin' });
    const res = await createChannel(ctx, webhookBody(), admin.token);
    expect(res.status).toBe(201);
  });
});

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

describe('delivery on scan lifecycle events', () => {
  let ctx: TestServer;
  let outbound: FakeFetch;

  beforeEach(async () => {
    outbound = fakeFetch();
    ctx = await startTestServer({ rateLimit: { max: 10_000 }, fetch: outbound.impl });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  /** Run a real scan of the vulnerable-app fixture to completion. */
  async function runScan(target = vulnerableApp()): Promise<string> {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: target });
    expect(res.status).toBe(202);
    const { id } = (await res.json()) as { id: string };
    await waitForScan(ctx, id);
    await ctx.server.notifier.drain();
    return id;
  }

  it('POSTs the contract payload, signed, on scan.completed', async () => {
    await createdChannel(ctx, webhookBody({ events: ['scan.completed'], secret: SECRET }));
    const scanId = await runScan();

    const completed = outbound.calls.filter((call) => {
      const parsed = JSON.parse(call.body) as NotificationPayload;
      return parsed.event === 'scan.completed';
    });
    expect(completed.length).toBe(1);
    const call = completed[0];
    if (call === undefined) throw new Error('no delivery recorded');

    expect(call.url).toBe(HOOK_URL);
    expect(call.method).toBe('POST');
    expect(call.headers['Content-Type']).toBe('application/json');
    // The 5s deadline is attached to every delivery.
    expect(call.hasSignal).toBe(true);

    const payload = JSON.parse(call.body) as NotificationPayload;
    expect(Object.keys(payload).sort()).toEqual([
      'event',
      'findingCount',
      'finishedAt',
      'path',
      'project',
      'scanId',
      'stats',
    ]);
    expect(payload.scanId).toBe(scanId);
    expect(payload.path).toContain('vulnerable-app');
    expect(payload.project).toBe('vulnerable-app');
    expect(payload.findingCount).toBeGreaterThan(0);
    expect(payload.stats.critical + payload.stats.high).toBeGreaterThan(0);
    expect(Number.isNaN(Date.parse(payload.finishedAt))).toBe(false);

    // Verify the HMAC exactly as a receiver would: over the raw body bytes.
    const expected = `sha256=${createHmac('sha256', SECRET).update(call.body, 'utf8').digest('hex')}`;
    expect(call.headers['X-Sentinel-Signature']).toBe(expected);
  });

  it('omits the signature header when no secret is configured', async () => {
    await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));
    await runScan();
    expect(outbound.calls.length).toBe(1);
    expect(outbound.calls[0]?.headers['X-Sentinel-Signature']).toBeUndefined();
  });

  it('fires policy.violated for a scan with critical/high findings', async () => {
    await createdChannel(ctx, webhookBody({ events: ['scan.completed', 'policy.violated'] }));
    await runScan();

    const events = outbound.calls.map(
      (call) => (JSON.parse(call.body) as NotificationPayload).event,
    );
    expect(events).toContain('scan.completed');
    expect(events).toContain('policy.violated');
  });

  it('does not fire policy.violated for a clean scan', async () => {
    const clean = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine, // reports zero findings
      fetch: outbound.impl,
    });
    try {
      await createdChannel(clean, webhookBody({ events: ['scan.completed', 'policy.violated'] }));
      const res = await postJson(clean.base, '/api/scans', clean.token, { path: vulnerableApp() });
      const { id } = (await res.json()) as { id: string };
      await waitForScan(clean, id);
      await clean.server.notifier.drain();

      const events = outbound.calls.map(
        (call) => (JSON.parse(call.body) as NotificationPayload).event,
      );
      expect(events).toEqual(['scan.completed']);
    } finally {
      await clean.cleanup();
    }
  });

  it('fires scan.failed when a job fails, and the record still reaches terminal state', async () => {
    const failing = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: () => failingEngine(),
      fetch: outbound.impl,
    });
    try {
      await createdChannel(failing, webhookBody({ events: ['scan.failed'] }));
      const res = await postJson(failing.base, '/api/scans', failing.token, {
        path: vulnerableApp(),
      });
      const { id } = (await res.json()) as { id: string };
      const record = await waitForScan(failing, id);
      await failing.server.notifier.drain();

      expect(record.status).toBe('failed');
      expect(outbound.calls.length).toBe(1);
      const payload = JSON.parse(outbound.calls[0]?.body ?? '{}') as NotificationPayload;
      expect(payload.event).toBe('scan.failed');
      expect(payload.scanId).toBe(id);
      expect(payload.findingCount).toBe(0);
      expect(payload.stats).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    } finally {
      await failing.cleanup();
    }
  });

  it('sends a slack channel a {text} summary with counts and no evidence', async () => {
    await createdChannel(ctx, {
      type: 'slack',
      url: SLACK_URL,
      events: ['scan.completed'],
    });
    await runScan();

    expect(outbound.calls.length).toBe(1);
    const body = outbound.calls[0]?.body ?? '';
    const parsed = JSON.parse(body) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual(['text']);
    const text = parsed['text'] as string;
    expect(text).toContain('scan.completed');
    expect(text).toContain('vulnerable-app');
    for (const label of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
      expect(text).toContain(label);
    }
    // Not one planted fixture secret, and no evidence text, may ride along.
    for (const planted of PLANTED_SECRETS) {
      expect(text, `planted secret leaked into slack text: ${planted.id}`).not.toContain(
        planted.value,
      );
    }
    expect(text).not.toContain('evidence');
  });

  it('sends nothing when no channel is configured', async () => {
    await runScan();
    expect(outbound.calls).toEqual([]);
  });

  it('sends nothing to a disabled channel or an unsubscribed event', async () => {
    await createdChannel(ctx, webhookBody({ events: ['scan.completed'], enabled: false }));
    await createdChannel(ctx, webhookBody({ events: ['schedule.failed'] }));
    await runScan();
    expect(outbound.calls).toEqual([]);
  });

  it('delivers to several channels concurrently', async () => {
    await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));
    await createdChannel(ctx, { type: 'slack', url: SLACK_URL, events: ['scan.completed'] });
    await runScan();
    expect(outbound.calls.length).toBe(2);
    expect(new Set(outbound.calls.map((call) => call.url))).toEqual(new Set([HOOK_URL, SLACK_URL]));
  });
});

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------

describe('delivery failures never affect a scan', () => {
  it('records lastError on a >= 400 response and still completes the scan', async () => {
    const outbound = fakeFetch();
    outbound.respondWith(503);
    const ctx = await startTestServer({ rateLimit: { max: 10_000 }, fetch: outbound.impl });
    try {
      const channel = await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));
      const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
      const { id } = (await res.json()) as { id: string };
      const record = await waitForScan(ctx, id);
      await ctx.server.notifier.drain();

      expect(record.status).toBe('completed');
      const reloaded = (await (
        await fetch(`${ctx.base}/api/notifications/${channel.id}`, { headers: bearer(ctx.token) })
      ).json()) as PublicChannel;
      expect(reloaded.lastError).toContain('503');
    } finally {
      await ctx.cleanup();
    }
  });

  it('records lastError on a timeout/abort and clears it after a success', async () => {
    const outbound = fakeFetch();
    const timeout = new Error('The operation was aborted due to timeout');
    timeout.name = 'TimeoutError';
    outbound.failWith(timeout);
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    try {
      const channel = await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));

      const first = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
      await waitForScan(ctx, ((await first.json()) as { id: string }).id);
      await ctx.server.notifier.drain();

      const failed = (await (
        await fetch(`${ctx.base}/api/notifications/${channel.id}`, { headers: bearer(ctx.token) })
      ).json()) as PublicChannel;
      expect(failed.lastError).toContain('TimeoutError');

      // A later success clears it.
      outbound.reset();
      const second = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
      await waitForScan(ctx, ((await second.json()) as { id: string }).id);
      await ctx.server.notifier.drain();

      const recovered = (await (
        await fetch(`${ctx.base}/api/notifications/${channel.id}`, { headers: bearer(ctx.token) })
      ).json()) as PublicChannel;
      expect(recovered.lastError).toBeUndefined();
    } finally {
      await ctx.cleanup();
    }
  });

  it('reaches terminal state for every scan even when every delivery fails', async () => {
    const outbound = fakeFetch();
    outbound.failWith(new Error('connect ECONNREFUSED 127.0.0.1:1'));
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    try {
      await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));
      const ids: string[] = [];
      for (let i = 0; i < 3; i += 1) {
        const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
        ids.push(((await res.json()) as { id: string }).id);
      }
      for (const id of ids) {
        expect((await waitForScan(ctx, id)).status).toBe('completed');
      }
      await ctx.server.notifier.drain();
      expect(outbound.calls.length).toBe(3);
    } finally {
      await ctx.cleanup();
    }
  });

  it('drain() leaves nothing pending and shutdown produces no unhandled rejection', async () => {
    const rejections: unknown[] = [];
    const onRejection = (reason: unknown): void => {
      rejections.push(reason);
    };
    process.on('unhandledRejection', onRejection);
    const outbound = fakeFetch();
    outbound.failWith(new Error('receiver is gone'));
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    try {
      await createdChannel(ctx, webhookBody({ events: ['scan.completed'] }));
      const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
      await waitForScan(ctx, ((await res.json()) as { id: string }).id);
      await ctx.server.notifier.drain();
      // A second drain on a quiet notifier resolves immediately.
      await ctx.server.notifier.drain();
      expect(outbound.calls.length).toBe(1);
    } finally {
      await ctx.cleanup();
      process.off('unhandledRejection', onRejection);
    }
    // Give a queued microtask/turn a chance to surface a late rejection.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(rejections).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The test endpoint
// ---------------------------------------------------------------------------

describe('POST /api/notifications/:id/test', () => {
  it('round-trips a test event through the real delivery path', async () => {
    const outbound = fakeFetch();
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    try {
      const channel = await createdChannel(ctx, webhookBody({ secret: SECRET }));
      const res = await postJson(ctx.base, `/api/notifications/${channel.id}/test`, ctx.token, {});
      expect(res.status).toBe(200);
      const result = (await res.json()) as DeliveryResult;
      expect(result.ok).toBe(true);
      expect(result.status).toBe(200);
      expect(result.error).toBeUndefined();

      expect(outbound.calls.length).toBe(1);
      const call = outbound.calls[0];
      if (call === undefined) throw new Error('no delivery recorded');
      const payload = JSON.parse(call.body) as NotificationPayload;
      expect(payload.event).toBe('test');
      // Signed like any other webhook delivery.
      const expected = `sha256=${createHmac('sha256', SECRET).update(call.body, 'utf8').digest('hex')}`;
      expect(call.headers['X-Sentinel-Signature']).toBe(expected);
    } finally {
      await ctx.cleanup();
    }
  });

  it('reports a failing receiver as 200 { ok: false } and records lastError', async () => {
    const outbound = fakeFetch();
    outbound.respondWith(404);
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    try {
      const channel = await createdChannel(ctx, webhookBody());
      const res = await postJson(ctx.base, `/api/notifications/${channel.id}/test`, ctx.token, {});
      expect(res.status).toBe(200);
      const result = (await res.json()) as DeliveryResult;
      expect(result.ok).toBe(false);
      expect(result.status).toBe(404);
      expect(result.error).toContain('404');

      const reloaded = (await (
        await fetch(`${ctx.base}/api/notifications/${channel.id}`, { headers: bearer(ctx.token) })
      ).json()) as PublicChannel;
      expect(reloaded.lastError).toContain('404');
    } finally {
      await ctx.cleanup();
    }
  });

  it('tests a disabled channel too (it is a connectivity check, not an event)', async () => {
    const outbound = fakeFetch();
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    try {
      const channel = await createdChannel(ctx, webhookBody({ enabled: false }));
      const res = await postJson(ctx.base, `/api/notifications/${channel.id}/test`, ctx.token, {});
      expect(res.status).toBe(200);
      expect(((await res.json()) as DeliveryResult).ok).toBe(true);
      expect(outbound.calls.length).toBe(1);
    } finally {
      await ctx.cleanup();
    }
  });

  it('404s for an unknown channel', async () => {
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: fakeFetch().impl,
    });
    try {
      const res = await postJson(ctx.base, '/api/notifications/nope/test', ctx.token, {});
      expect(res.status).toBe(404);
    } finally {
      await ctx.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// schedule.failed
// ---------------------------------------------------------------------------

describe('schedule.failed', () => {
  it('fires when a scheduled scan ends failed, carrying the schedule id', async () => {
    const outbound = fakeFetch();
    const clock = mutableClock();
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: () => failingEngine('scheduled scan exploded'),
      fetch: outbound.impl,
      now: clock.now,
      schedulerIntervalMs: 3_600_000,
    });
    try {
      await createdChannel(ctx, webhookBody({ events: ['schedule.failed'] }));
      const schedule = (await (
        await postJson(ctx.base, '/api/schedules', ctx.token, {
          path: vulnerableApp(),
          intervalMs: MINUTE,
        })
      ).json()) as ScheduleRecord;

      clock.advance(MINUTE + 1);
      expect(ctx.server.scheduler.tick()).toBe(1);

      const after = (await (
        await fetch(`${ctx.base}/api/schedules/${schedule.id}`, { headers: bearer(ctx.token) })
      ).json()) as ScheduleRecord;
      const record = await waitForScan(ctx, after.lastScanId as string);
      expect(record.status).toBe('failed');
      await ctx.server.notifier.drain();

      expect(outbound.calls.length).toBe(1);
      const payload = JSON.parse(outbound.calls[0]?.body ?? '{}') as NotificationPayload;
      expect(payload.event).toBe('schedule.failed');
      expect(payload.scheduleId).toBe(schedule.id);
      expect(payload.scanId).toBe(after.lastScanId);
    } finally {
      await ctx.cleanup();
    }
  });

  it('does not fire for a scheduled scan that succeeds', async () => {
    const outbound = fakeFetch();
    const clock = mutableClock();
    const ctx = await startTestServer({
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
      now: clock.now,
      schedulerIntervalMs: 3_600_000,
    });
    try {
      await createdChannel(ctx, webhookBody({ events: ['schedule.failed'] }));
      await postJson(ctx.base, '/api/schedules', ctx.token, {
        path: vulnerableApp(),
        intervalMs: MINUTE,
      });
      clock.advance(MINUTE + 1);
      expect(ctx.server.scheduler.tick()).toBe(1);
      await ctx.server.queue.drain();
      await ctx.server.notifier.drain();
      expect(outbound.calls).toEqual([]);
    } finally {
      await ctx.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

describe('channel persistence across restart', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-notify-'));
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('a fresh server on the same data dir keeps the channel and its secret', async () => {
    const outbound = fakeFetch();
    const first = await startTestServer({
      dataDir,
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    const created = await createdChannel(first, webhookBody({ secret: SECRET }));
    await first.cleanup();

    const second = await startTestServer({
      dataDir,
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: outbound.impl,
    });
    try {
      const res = await fetch(`${second.base}/api/notifications/${created.id}`, {
        headers: bearer(second.token),
      });
      expect(res.status).toBe(200);
      const reloaded = (await res.json()) as PublicChannel;
      expect(reloaded.id).toBe(created.id);
      expect(reloaded.url).toBe(HOOK_URL);
      expect(reloaded.events).toEqual(created.events);
      expect(reloaded.hasSecret).toBe(true);
      expect(JSON.stringify(reloaded)).not.toContain(SECRET);

      // The reloaded secret is the real one: it still signs identically.
      await postJson(second.base, `/api/notifications/${created.id}/test`, second.token, {});
      const call = outbound.calls[outbound.calls.length - 1];
      if (call === undefined) throw new Error('no delivery recorded');
      const expected = `sha256=${createHmac('sha256', SECRET).update(call.body, 'utf8').digest('hex')}`;
      expect(call.headers['X-Sentinel-Signature']).toBe(expected);
    } finally {
      await second.cleanup();
    }
  });

  it('a deleted channel does not come back after a restart', async () => {
    const first = await startTestServer({
      dataDir,
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: fakeFetch().impl,
    });
    const created = await createdChannel(first, webhookBody());
    await sendJsonRequest(first.base, `/api/notifications/${created.id}`, first.token, 'DELETE');
    expect(readdirSync(path.join(dataDir, 'notifications'))).toEqual([]);
    await first.cleanup();

    const second = await startTestServer({
      dataDir,
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
      fetch: fakeFetch().impl,
    });
    try {
      const list = (await (await listChannels(second)).json()) as PublicChannel[];
      expect(list).toEqual([]);
    } finally {
      await second.cleanup();
    }
  });
});
