import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  bearer,
  createUser,
  deleteRequest,
  instantEngine,
  postJson,
  sendJsonRequest,
  startTestServer,
  vulnerableApp,
  waitForAuditEntry,
} from './support.js';
import type { CreatedUser, TestServer } from './support.js';
import type { PublicUser } from '../src/index.js';

const MINUTE = 60_000;

interface ErrorBody {
  error: { code: string; message: string };
}

async function errorBody(res: Response): Promise<ErrorBody> {
  return (await res.json()) as ErrorBody;
}

/** Assert a response is the structured 403 the contract fixes. */
async function expectForbidden(res: Response): Promise<void> {
  expect(res.status).toBe(403);
  const body = await errorBody(res);
  expect(body.error.code).toBe('forbidden');
  expect(typeof body.error.message).toBe('string');
  expect(body.error.message.length).toBeGreaterThan(0);
}

/** Every GET a viewer must be able to make, per the permission matrix. */
const VIEWER_GETS = [
  '/api/scans',
  '/api/findings',
  '/api/rules',
  '/api/schedules',
  '/api/history',
  '/api/trends',
  '/api/me',
];

// ---------------------------------------------------------------------------
// Backcompat: the bootstrap token is the root admin and still passes everything
// ---------------------------------------------------------------------------

describe('bootstrap token remains a full admin', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer({ rateLimit: { max: 10_000 }, engineFactory: instantEngine });
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('passes every viewer GET', async () => {
    for (const route of VIEWER_GETS) {
      const res = await fetch(`${ctx.base}${route}`, { headers: bearer(ctx.token) });
      expect(res.status, `GET ${route} with the root token`).toBe(200);
    }
  });

  it('may start a scan and manage schedules and users', async () => {
    const scan = await postJson(ctx.base, '/api/scans', ctx.token, { path: vulnerableApp() });
    expect(scan.status).toBe(202);

    const created = await postJson(ctx.base, '/api/schedules', ctx.token, {
      path: vulnerableApp(),
      intervalMs: MINUTE,
    });
    expect(created.status).toBe(201);
    const schedule = (await created.json()) as { id: string };
    const patched = await sendJsonRequest(
      ctx.base,
      `/api/schedules/${schedule.id}`,
      ctx.token,
      'PATCH',
      { enabled: false },
    );
    expect(patched.status).toBe(200);
    expect((await deleteRequest(ctx.base, `/api/schedules/${schedule.id}`, ctx.token)).status).toBe(
      204,
    );

    const users = await fetch(`${ctx.base}/api/users`, { headers: bearer(ctx.token) });
    expect(users.status).toBe(200);
  });

  it('GET /api/me reports the root identity', async () => {
    const res = await fetch(`${ctx.base}/api/me`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ name: 'root', role: 'admin' });
  });

  it('root is not a user record: it cannot be listed, patched or deleted', async () => {
    await createUser(ctx, { name: 'Someone', role: 'viewer' });
    const listed = (await (
      await fetch(`${ctx.base}/api/users`, { headers: bearer(ctx.token) })
    ).json()) as PublicUser[];
    expect(listed.some((user) => user.id === 'root')).toBe(false);

    const patch = await sendJsonRequest(ctx.base, '/api/users/root', ctx.token, 'PATCH', {
      role: 'viewer',
    });
    expect(patch.status).toBe(404);
    expect((await deleteRequest(ctx.base, '/api/users/root', ctx.token)).status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

describe('user management', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer({ rateLimit: { max: 10_000 }, engineFactory: instantEngine });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('POST /api/users returns 201 with the one-time token', async () => {
    const res = await postJson(ctx.base, '/api/users', ctx.token, {
      name: 'Ada',
      role: 'operator',
    });
    expect(res.status).toBe(201);
    const created = (await res.json()) as CreatedUser & { tokenHash?: string };
    expect(created.name).toBe('Ada');
    expect(created.role).toBe('operator');
    expect(typeof created.id).toBe('string');
    expect(Number.isNaN(Date.parse(created.createdAt))).toBe(false);
    // A 32-byte random token, hex-encoded.
    expect(created.token).toMatch(/^[0-9a-f]{64}$/);
    expect(created.tokenHash).toBeUndefined();
  });

  it('GET /api/users never exposes token hashes or tokens', async () => {
    const created = await createUser(ctx, { name: 'Grace', role: 'viewer' });
    const res = await fetch(`${ctx.base}/api/users`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(created.token);
    expect(text).not.toContain('tokenHash');

    const users = JSON.parse(text) as PublicUser[];
    const user = users.find((entry) => entry.id === created.id);
    expect(user).toBeDefined();
    expect(Object.keys(user ?? {}).sort()).toEqual(['createdAt', 'disabled', 'id', 'name', 'role']);
    expect(user?.disabled).toBe(false);
  });

  it('GET /api/users/:id returns one user, 404 for an unknown id', async () => {
    const created = await createUser(ctx, { name: 'Alan', role: 'admin' });
    const res = await fetch(`${ctx.base}/api/users/${created.id}`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const user = (await res.json()) as PublicUser;
    expect(user).toEqual({
      id: created.id,
      name: 'Alan',
      role: 'admin',
      createdAt: created.createdAt,
      disabled: false,
    });

    const missing = await fetch(`${ctx.base}/api/users/nope`, { headers: bearer(ctx.token) });
    expect(missing.status).toBe(404);
    expect((await errorBody(missing)).error.code).toBe('not_found');
  });

  it('PATCH /api/users/:id updates role and disabled, 404 for an unknown id', async () => {
    const created = await createUser(ctx, { name: 'Edsger', role: 'viewer' });
    const res = await sendJsonRequest(ctx.base, `/api/users/${created.id}`, ctx.token, 'PATCH', {
      role: 'admin',
      disabled: true,
    });
    expect(res.status).toBe(200);
    const updated = (await res.json()) as PublicUser;
    expect(updated.role).toBe('admin');
    expect(updated.disabled).toBe(true);
    expect(updated.name).toBe('Edsger');

    const missing = await sendJsonRequest(ctx.base, '/api/users/nope', ctx.token, 'PATCH', {
      role: 'viewer',
    });
    expect(missing.status).toBe(404);
  });

  it('DELETE /api/users/:id returns 204, then 404', async () => {
    const created = await createUser(ctx, { name: 'Barbara', role: 'viewer' });
    expect((await deleteRequest(ctx.base, `/api/users/${created.id}`, ctx.token)).status).toBe(204);
    expect((await deleteRequest(ctx.base, `/api/users/${created.id}`, ctx.token)).status).toBe(404);
  });

  it('rejects a missing, empty or over-long name with 400', async () => {
    for (const body of [
      { role: 'viewer' },
      { name: '', role: 'viewer' },
      { name: '   ', role: 'viewer' },
    ]) {
      const res = await postJson(ctx.base, '/api/users', ctx.token, body);
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe('validation_error');
    }
    const long = await postJson(ctx.base, '/api/users', ctx.token, {
      name: 'x'.repeat(65),
      role: 'viewer',
    });
    expect(long.status).toBe(400);
  });

  it('rejects an unknown or missing role with 400', async () => {
    for (const role of [undefined, 'superuser', '', 7]) {
      const res = await postJson(ctx.base, '/api/users', ctx.token, { name: 'Nobody', role });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe('validation_error');
    }
    const patch = await createUser(ctx, { name: 'Nobody', role: 'viewer' });
    const bad = await sendJsonRequest(ctx.base, `/api/users/${patch.id}`, ctx.token, 'PATCH', {
      role: 'superuser',
    });
    expect(bad.status).toBe(400);
  });

  it('rejects a non-boolean disabled with 400', async () => {
    const created = await createUser(ctx, { name: 'Ken', role: 'viewer' });
    const res = await sendJsonRequest(ctx.base, `/api/users/${created.id}`, ctx.token, 'PATCH', {
      disabled: 'yes',
    });
    expect(res.status).toBe(400);
  });

  it('a user name is stored verbatim, including hostile-looking text', async () => {
    // The dashboard renders names via textContent, so nothing is escaped here;
    // assert the value round-trips untouched rather than being silently mangled.
    const name = '<img src=x onerror=alert(1)>';
    const created = await createUser(ctx, { name, role: 'viewer' });
    const res = await fetch(`${ctx.base}/api/users/${created.id}`, { headers: bearer(ctx.token) });
    expect(((await res.json()) as PublicUser).name).toBe(name);
  });
});

// ---------------------------------------------------------------------------
// Role enforcement
// ---------------------------------------------------------------------------

describe('role enforcement', () => {
  let ctx: TestServer;
  let viewer: CreatedUser;
  let operator: CreatedUser;
  let admin: CreatedUser;
  let scheduleId: string;

  beforeAll(async () => {
    ctx = await startTestServer({ rateLimit: { max: 10_000 }, engineFactory: instantEngine });
    viewer = await createUser(ctx, { name: 'Viewer', role: 'viewer' });
    operator = await createUser(ctx, { name: 'Operator', role: 'operator' });
    admin = await createUser(ctx, { name: 'Admin', role: 'admin' });
    const created = await postJson(ctx.base, '/api/schedules', ctx.token, {
      path: vulnerableApp(),
      intervalMs: MINUTE,
    });
    scheduleId = ((await created.json()) as { id: string }).id;
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('a viewer may make every read in the matrix', async () => {
    for (const route of VIEWER_GETS) {
      const res = await fetch(`${ctx.base}${route}`, { headers: bearer(viewer.token) });
      expect(res.status, `GET ${route} as viewer`).toBe(200);
    }
    const one = await fetch(`${ctx.base}/api/schedules/${scheduleId}`, {
      headers: bearer(viewer.token),
    });
    expect(one.status).toBe(200);
  });

  it('a viewer is forbidden from starting a scan', async () => {
    await expectForbidden(
      await postJson(ctx.base, '/api/scans', viewer.token, { path: vulnerableApp() }),
    );
  });

  it('a viewer is forbidden from every schedule mutation', async () => {
    await expectForbidden(
      await postJson(ctx.base, '/api/schedules', viewer.token, {
        path: vulnerableApp(),
        intervalMs: MINUTE,
      }),
    );
    await expectForbidden(
      await sendJsonRequest(ctx.base, `/api/schedules/${scheduleId}`, viewer.token, 'PATCH', {
        enabled: false,
      }),
    );
    await expectForbidden(
      await deleteRequest(ctx.base, `/api/schedules/${scheduleId}`, viewer.token),
    );
  });

  it('a viewer is forbidden from user administration, reads included', async () => {
    await expectForbidden(await fetch(`${ctx.base}/api/users`, { headers: bearer(viewer.token) }));
    await expectForbidden(
      await postJson(ctx.base, '/api/users', viewer.token, { name: 'Sneaky', role: 'admin' }),
    );
  });

  it('an operator may start a scan', async () => {
    const res = await postJson(ctx.base, '/api/scans', operator.token, { path: vulnerableApp() });
    expect(res.status).toBe(202);
  });

  it('an operator keeps every viewer read', async () => {
    for (const route of VIEWER_GETS) {
      const res = await fetch(`${ctx.base}${route}`, { headers: bearer(operator.token) });
      expect(res.status, `GET ${route} as operator`).toBe(200);
    }
  });

  it('an operator is forbidden from schedule mutations and user administration', async () => {
    await expectForbidden(
      await postJson(ctx.base, '/api/schedules', operator.token, {
        path: vulnerableApp(),
        intervalMs: MINUTE,
      }),
    );
    await expectForbidden(
      await sendJsonRequest(ctx.base, `/api/schedules/${scheduleId}`, operator.token, 'PATCH', {
        enabled: false,
      }),
    );
    await expectForbidden(
      await deleteRequest(ctx.base, `/api/schedules/${scheduleId}`, operator.token),
    );
    await expectForbidden(
      await fetch(`${ctx.base}/api/users`, { headers: bearer(operator.token) }),
    );
  });

  it('a non-root admin user may do everything', async () => {
    for (const route of VIEWER_GETS) {
      const res = await fetch(`${ctx.base}${route}`, { headers: bearer(admin.token) });
      expect(res.status, `GET ${route} as admin`).toBe(200);
    }
    expect(
      (await postJson(ctx.base, '/api/scans', admin.token, { path: vulnerableApp() })).status,
    ).toBe(202);

    const created = await postJson(ctx.base, '/api/schedules', admin.token, {
      path: vulnerableApp(),
      intervalMs: MINUTE,
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as { id: string }).id;
    expect(
      (
        await sendJsonRequest(ctx.base, `/api/schedules/${id}`, admin.token, 'PATCH', {
          enabled: false,
        })
      ).status,
    ).toBe(200);
    expect((await deleteRequest(ctx.base, `/api/schedules/${id}`, admin.token)).status).toBe(204);

    // Including creating another user with their own one-time token.
    const nested = await createUser(ctx, { name: 'Made by admin', role: 'viewer' }, admin.token);
    expect(nested.token).toMatch(/^[0-9a-f]{64}$/);
    expect((await deleteRequest(ctx.base, `/api/users/${nested.id}`, admin.token)).status).toBe(
      204,
    );
  });

  it('403 is used for permission, 401 for authentication', async () => {
    const noToken = await postJson(ctx.base, '/api/scans', '', { path: vulnerableApp() });
    expect(noToken.status).toBe(401);
    expect((await errorBody(noToken)).error.code).toBe('unauthorized');

    const forbidden = await postJson(ctx.base, '/api/scans', viewer.token, {
      path: vulnerableApp(),
    });
    expect(forbidden.status).toBe(403);
    expect((await errorBody(forbidden)).error.code).toBe('forbidden');
  });

  it('GET /api/me reports each user identity', async () => {
    const cases: Array<[CreatedUser, string]> = [
      [viewer, 'viewer'],
      [operator, 'operator'],
      [admin, 'admin'],
    ];
    for (const [user, role] of cases) {
      const res = await fetch(`${ctx.base}/api/me`, { headers: bearer(user.token) });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ name: user.name, role });
    }
  });
});

// ---------------------------------------------------------------------------
// Token lifecycle
// ---------------------------------------------------------------------------

describe('user token lifecycle', () => {
  let ctx: TestServer;

  beforeEach(async () => {
    ctx = await startTestServer({ rateLimit: { max: 10_000 }, engineFactory: instantEngine });
  });

  afterEach(async () => {
    await ctx.cleanup();
  });

  it('a disabled user authenticates as invalid (401)', async () => {
    const user = await createUser(ctx, { name: 'Temp', role: 'viewer' });
    expect((await fetch(`${ctx.base}/api/rules`, { headers: bearer(user.token) })).status).toBe(
      200,
    );

    const patched = await sendJsonRequest(ctx.base, `/api/users/${user.id}`, ctx.token, 'PATCH', {
      disabled: true,
    });
    expect(patched.status).toBe(200);

    const after = await fetch(`${ctx.base}/api/rules`, { headers: bearer(user.token) });
    expect(after.status).toBe(401);
    expect((await errorBody(after)).error.code).toBe('unauthorized');

    // Re-enabling restores access.
    await sendJsonRequest(ctx.base, `/api/users/${user.id}`, ctx.token, 'PATCH', {
      disabled: false,
    });
    expect((await fetch(`${ctx.base}/api/rules`, { headers: bearer(user.token) })).status).toBe(
      200,
    );
  });

  it('a deleted user authenticates as invalid (401)', async () => {
    const user = await createUser(ctx, { name: 'Doomed', role: 'admin' });
    expect((await fetch(`${ctx.base}/api/rules`, { headers: bearer(user.token) })).status).toBe(
      200,
    );
    expect((await deleteRequest(ctx.base, `/api/users/${user.id}`, ctx.token)).status).toBe(204);
    expect((await fetch(`${ctx.base}/api/rules`, { headers: bearer(user.token) })).status).toBe(
      401,
    );
  });

  it('rotate invalidates the old token immediately and the new one works', async () => {
    const user = await createUser(ctx, { name: 'Rotator', role: 'operator' });
    const res = await postJson(ctx.base, `/api/users/${user.id}/rotate`, ctx.token, {});
    expect(res.status).toBe(200);
    const rotated = (await res.json()) as { token: string };
    expect(rotated.token).toMatch(/^[0-9a-f]{64}$/);
    expect(rotated.token).not.toBe(user.token);

    expect((await fetch(`${ctx.base}/api/rules`, { headers: bearer(user.token) })).status).toBe(
      401,
    );
    const withNew = await fetch(`${ctx.base}/api/me`, { headers: bearer(rotated.token) });
    expect(withNew.status).toBe(200);
    expect(await withNew.json()).toEqual({ name: 'Rotator', role: 'operator' });
  });

  it('rotating an unknown user is a 404', async () => {
    const res = await postJson(ctx.base, '/api/users/nope/rotate', ctx.token, {});
    expect(res.status).toBe(404);
  });

  it('rate limiting is per caller, not shared across tokens', async () => {
    const limited = await startTestServer({
      rateLimit: { max: 3, windowMs: 60_000 },
      engineFactory: instantEngine,
    });
    try {
      // 1 of 3: creating the user.
      const user = await createUser(limited, { name: 'Quiet', role: 'viewer' });
      // 2 and 3 of 3, then the root token is exhausted.
      for (const expected of [200, 200, 429]) {
        const res = await fetch(`${limited.base}/api/rules`, { headers: bearer(limited.token) });
        expect(res.status).toBe(expected);
      }
      // The user has their own budget and is unaffected.
      const other = await fetch(`${limited.base}/api/rules`, { headers: bearer(user.token) });
      expect(other.status).toBe(200);
    } finally {
      await limited.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Audit attribution and persistence
// ---------------------------------------------------------------------------

describe('audit log attributes the acting user', () => {
  let ctx: TestServer;

  beforeAll(async () => {
    ctx = await startTestServer({ rateLimit: { max: 10_000 }, engineFactory: instantEngine });
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('records root for the bootstrap token and the user id for a user token', async () => {
    const user = await createUser(ctx, { name: 'Audited', role: 'viewer' });
    expect((await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) })).status).toBe(200);
    expect((await fetch(`${ctx.base}/api/trends`, { headers: bearer(user.token) })).status).toBe(
      200,
    );

    const rootEntry = await waitForAuditEntry(
      ctx.dataDir,
      (entry) => entry.path === '/api/rules' && entry.status === 200,
    );
    expect(rootEntry.userId).toBe('root');

    const userEntry = await waitForAuditEntry(
      ctx.dataDir,
      (entry) => entry.path === '/api/trends' && entry.status === 200,
    );
    expect(userEntry.userId).toBe(user.id);
    expect(userEntry.tokenId).toMatch(/^[0-9a-f]{12}$/);
  });

  it('never writes a token to the audit log', async () => {
    const user = await createUser(ctx, { name: 'Secretive', role: 'viewer' });
    expect((await fetch(`${ctx.base}/api/me`, { headers: bearer(user.token) })).status).toBe(200);
    await waitForAuditEntry(ctx.dataDir, (entry) => entry.path === '/api/me');

    const raw = readFileSync(path.join(ctx.dataDir, 'audit.log'), 'utf8');
    expect(raw).not.toContain(user.token);
    expect(raw).not.toContain(ctx.token);
  });
});

describe('users persist across a restart', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-users-'));
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('a user created before a restart still authenticates after it', async () => {
    const first = await startTestServer({
      dataDir,
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
    });
    const user = await createUser(first, { name: 'Persistent', role: 'operator' });
    await first.cleanup();

    const second = await startTestServer({
      dataDir,
      rateLimit: { max: 10_000 },
      engineFactory: instantEngine,
    });
    try {
      const me = await fetch(`${second.base}/api/me`, { headers: bearer(user.token) });
      expect(me.status).toBe(200);
      expect(await me.json()).toEqual({ name: 'Persistent', role: 'operator' });

      const listed = (await (
        await fetch(`${second.base}/api/users`, { headers: bearer(second.token) })
      ).json()) as PublicUser[];
      expect(listed.map((entry) => entry.id)).toContain(user.id);

      // The role survives too: an operator still may not touch schedules.
      await expectForbidden(
        await postJson(second.base, '/api/schedules', user.token, {
          path: vulnerableApp(),
          intervalMs: MINUTE,
        }),
      );
    } finally {
      await second.cleanup();
    }
  });
});
