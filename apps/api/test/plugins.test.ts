import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Finding, ScannerPlugin } from '@dl-sentinel/core';
import { createFinding } from '@dl-sentinel/core';
import { BUILTIN_SCANNERS } from '@dl-sentinel/preset';
import { createServer, startServer } from '../src/index.js';
import type { SentinelApiServer } from '../src/index.js';
import {
  bearer,
  postJson,
  shutdownTestServer,
  silentLogger,
  startTestServer,
  waitForScan,
} from './support.js';
import type { TestServer } from './support.js';

/** The engine's committed fixture plugin, loaded here through SENTINEL_PLUGINS. */
const FIXTURE_PLUGIN = fileURLToPath(
  new URL('../../../packages/engine/test/fixtures/plugins/valid.mjs', import.meta.url),
);
const COLLIDING_PLUGIN = fileURLToPath(
  new URL(
    '../../../packages/engine/test/fixtures/plugins/collides-with-builtin.mjs',
    import.meta.url,
  ),
);

const TEST_TOKEN = 'test-token-abcdefghijklmnop';

/**
 * A hand-built plugin passed straight through `ServerOptions.plugins` — the
 * injection path an embedder (or a test) uses to register a scanner without any
 * dynamic import.
 */
const injectedPlugin: ScannerPlugin = {
  id: 'injected-plugin',
  name: 'Injected Plugin',
  version: '0.5.0',
  categories: ['other'],
  supportedFiles: ['**/*.txt'],
  rules: [
    {
      id: 'IN001',
      title: 'Injected rule fired',
      severity: 'medium',
      defaultConfidence: 'medium',
      category: 'other',
      description: 'Reports every text file the plugin receives.',
      recommendation: 'Nothing to do; this rule exists only to exercise plugin registration.',
      references: [],
    },
  ],
  scan: (context): Promise<Finding[]> =>
    Promise.resolve(
      context.files.map((file) =>
        createFinding({
          ruleId: 'IN001',
          title: 'Injected rule fired',
          description: 'Reports every text file the plugin receives.',
          severity: 'medium',
          confidence: 'medium',
          category: 'other',
          file: file.relPath,
          line: 1,
          evidence: 'injected finding (no file contents are read)',
          recommendation: 'Nothing to do; this rule exists only to exercise plugin registration.',
          references: [],
          scanner: 'injected-plugin',
        }),
      ),
    ),
};

const tempDirs: string[] = [];

/** A scannable directory holding one innocuous text file both plugins report on. */
function scanRootWithTextFile(): string {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-plugins-')));
  tempDirs.push(dir);
  writeFileSync(path.join(dir, 'notes.txt'), 'nothing sensitive in here\n');
  return dir;
}

// Removed once the whole file is done: a `beforeAll` scan root has to outlive
// the individual tests that scan it.
afterAll(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  }
});

describe('ServerOptions.plugins: injected scanners', () => {
  let ctx: TestServer;
  let scanRoot: string;

  beforeAll(async () => {
    scanRoot = scanRootWithTextFile();
    ctx = await startTestServer({ scanRoot, plugins: [injectedPlugin] });
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  it('reports the plugin ids on the resolved runtime', () => {
    expect(ctx.server.sentinel.pluginIds).toEqual(['injected-plugin']);
  });

  it('GET /api/rules includes the plugin rules after the built-ins', async () => {
    const res = await fetch(`${ctx.base}/api/rules`, { headers: bearer(ctx.token) });
    expect(res.status).toBe(200);
    const rules = (await res.json()) as { id: string; scanner: string; severity: string }[];

    const builtinCount = BUILTIN_SCANNERS.reduce((sum, scanner) => sum + scanner.rules.length, 0);
    expect(rules).toHaveLength(builtinCount + 1);
    expect(rules[rules.length - 1]).toMatchObject({ id: 'IN001', scanner: 'injected-plugin' });
  });

  it('a scan runs the plugin and its findings reach the API', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, { path: scanRoot });
    expect(res.status).toBe(202);
    const { id } = (await res.json()) as { id: string };
    const record = await waitForScan(ctx, id);

    expect(record.status).toBe('completed');
    expect(record.report?.scannersRun).toContain('injected-plugin');

    const findings = await fetch(`${ctx.base}/api/scans/${id}/findings`, {
      headers: bearer(ctx.token),
    });
    const list = (await findings.json()) as Finding[];
    const injected = list.find((finding) => finding.ruleId === 'IN001');
    expect(injected).toBeDefined();
    expect(injected?.scanner).toBe('injected-plugin');
    expect(injected?.file).toBe('notes.txt');
  });

  it('accepts the plugin id as a scanner filter and in a scan request', async () => {
    const filtered = await fetch(`${ctx.base}/api/findings?scanner=injected-plugin`, {
      headers: bearer(ctx.token),
    });
    expect(filtered.status).toBe(200);
    expect(((await filtered.json()) as Finding[]).length).toBeGreaterThan(0);

    const created = await postJson(ctx.base, '/api/scans', ctx.token, {
      path: scanRoot,
      scanners: ['injected-plugin'],
    });
    expect(created.status).toBe(202);
  });

  it('still rejects an unknown scanner id', async () => {
    const res = await postJson(ctx.base, '/api/scans', ctx.token, {
      path: scanRoot,
      scanners: ['not-a-scanner'],
    });
    expect(res.status).toBe(400);
  });

  it('rejects a malformed injected plugin at construction', () => {
    expect(() =>
      createServer({
        logger: silentLogger,
        dataDir: scanRootWithTextFile(),
        plugins: [{ ...injectedPlugin, rules: [{ id: 'X' }] } as unknown as ScannerPlugin],
      }),
    ).toThrow(/rules\[0\]/);
  });

  it('refuses to build a server whose plugin shadows a built-in id', () => {
    expect(() =>
      createServer({
        logger: silentLogger,
        dataDir: scanRootWithTextFile(),
        plugins: [{ ...injectedPlugin, id: 'secrets' }],
      }),
    ).toThrow(/secrets/);
  });
});

describe('SENTINEL_PLUGINS: environment-driven startup', () => {
  const started: { server: SentinelApiServer; dataDir: string }[] = [];

  /** Start a real server through the env path, on an ephemeral port. */
  async function startWithEnv(
    env: NodeJS.ProcessEnv,
    scanRoot: string,
  ): Promise<{ base: string; server: SentinelApiServer }> {
    const dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-plugins-data-'));
    const server = await startServer({
      token: TEST_TOKEN,
      scanRoot,
      dataDir,
      logger: silentLogger,
      port: 0,
      env,
    });
    started.push({ server, dataDir });
    if (!server.listening) {
      await new Promise<void>((resolve) => server.once('listening', () => resolve()));
    }
    const address = server.address() as AddressInfo;
    return { base: `http://127.0.0.1:${address.port}`, server };
  }

  afterEach(async () => {
    while (started.length > 0) {
      const entry = started.pop();
      if (entry !== undefined) await shutdownTestServer(entry.server, entry.dataDir, true);
    }
  });

  it('loads the plugins named by the variable and serves their rules', async () => {
    const scanRoot = scanRootWithTextFile();
    const { base, server } = await startWithEnv({ SENTINEL_PLUGINS: FIXTURE_PLUGIN }, scanRoot);

    expect(server.sentinel.pluginIds).toEqual(['fixture-plugin']);
    const res = await fetch(`${base}/api/rules`, { headers: bearer(TEST_TOKEN) });
    const rules = (await res.json()) as { id: string; scanner: string }[];
    expect(rules.some((rule) => rule.id === 'FX001' && rule.scanner === 'fixture-plugin')).toBe(
      true,
    );
  });

  it('runs the loaded plugin as part of a scan', async () => {
    const scanRoot = scanRootWithTextFile();
    const { base, server } = await startWithEnv({ SENTINEL_PLUGINS: FIXTURE_PLUGIN }, scanRoot);

    const res = await postJson(base, '/api/scans', TEST_TOKEN, { path: scanRoot });
    expect(res.status).toBe(202);
    const { id } = (await res.json()) as { id: string };
    const record = await server.queue.waitForJob(id, 10_000);

    expect(record.status).toBe('completed');
    expect(record.report?.findings.some((finding) => finding.ruleId === 'FX001')).toBe(true);
  });

  it('accepts a comma-separated list, ignoring blank entries', async () => {
    const scanRoot = scanRootWithTextFile();
    const { server } = await startWithEnv({ SENTINEL_PLUGINS: ` ${FIXTURE_PLUGIN} , ,` }, scanRoot);
    expect(server.sentinel.pluginIds).toEqual(['fixture-plugin']);
  });

  it('refuses to start when a spec cannot be loaded', async () => {
    const scanRoot = scanRootWithTextFile();
    await expect(
      startWithEnv({ SENTINEL_PLUGINS: './definitely-not-here.mjs' }, scanRoot),
    ).rejects.toMatchObject({
      name: 'UsageError',
      message: expect.stringContaining('./definitely-not-here.mjs') as unknown as string,
    });
  });

  it('refuses to start when a spec collides with a built-in scanner id', async () => {
    const scanRoot = scanRootWithTextFile();
    await expect(startWithEnv({ SENTINEL_PLUGINS: COLLIDING_PLUGIN }, scanRoot)).rejects.toThrow(
      /secrets/,
    );
  });

  it('starts normally when the variable is absent', async () => {
    const scanRoot = scanRootWithTextFile();
    const { server } = await startWithEnv({}, scanRoot);
    expect(server.sentinel.pluginIds).toEqual([]);
  });

  it('warns when createServer is used while SENTINEL_PLUGINS is set', () => {
    const warnings: string[] = [];
    const dataDir = mkdtempSync(path.join(tmpdir(), 'dl-sentinel-api-plugins-data-'));
    const server = createServer({
      dataDir,
      scanRoot: scanRootWithTextFile(),
      env: { SENTINEL_PLUGINS: FIXTURE_PLUGIN },
      token: TEST_TOKEN,
      logger: { ...silentLogger, warn: (message) => warnings.push(message) },
    });
    server.scheduler.stop();
    rmSync(dataDir, { recursive: true, force: true });

    // Loading is asynchronous, so createServer cannot honour the variable; it
    // must say so rather than run silently with fewer scanners.
    expect(warnings.some((message) => message.includes('SENTINEL_PLUGINS'))).toBe(true);
    expect(server.sentinel.pluginIds).toEqual([]);
  });
});
