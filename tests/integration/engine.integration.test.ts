import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type {
  Finding,
  Report,
  ScanContext,
  ScanEvent,
  ScanLogger,
  ScannerPlugin,
  SentinelConfig,
} from '@dl-sentinel/core';
import { createFinding, defaultConfig } from '@dl-sentinel/core';
import * as engineModule from '@dl-sentinel/engine';
import { fixturePath } from '../support/index.js';

/**
 * packages/engine currently exports nothing (`export {}`) — it is being
 * built in parallel on feature/sentinel-core. These interfaces mirror the
 * *documented* public API (docs/architecture.md, "@dl-sentinel/engine"
 * section) verbatim, so the gated tests below are fully and strictly typed
 * against that contract without depending on the real module's exports
 * until it lands. This is the one narrowly-justified `as unknown as` cast in
 * this file — everything past it is ordinary typed code.
 */
interface ScanOptionsLike {
  target: string;
  config?: SentinelConfig;
  configPath?: string;
  scanners?: string[];
  signal?: AbortSignal;
  onEvent?: (event: ScanEvent) => void;
  logger?: ScanLogger;
}

interface ScanEngineLike {
  register(plugin: ScannerPlugin): void;
  plugins(): readonly ScannerPlugin[];
  scan(options: ScanOptionsLike): Promise<Report>;
}

interface EngineModuleLike {
  createEngine: () => ScanEngineLike;
  loadConfig: (targetDir: string, configPath?: string) => Promise<SentinelConfig>;
}

const engineReady = typeof (engineModule as { createEngine?: unknown }).createEngine === 'function';

describe.skipIf(!engineReady)('engine integration (@dl-sentinel/engine)', () => {
  const { createEngine } = engineModule as unknown as EngineModuleLike;

  interface MockScannerState {
    calls: number;
    seenFiles: string[];
    sawAbortedSignal: boolean;
    lastConfig?: Record<string, unknown>;
  }

  interface MockScannerOptions {
    supportedFiles?: string[];
    findingsPerFile?: (relPath: string) => Finding | Finding[] | undefined;
    alwaysThrow?: boolean;
    throwOnFile?: (relPath: string) => boolean;
  }

  function makeMockScanner(
    id: string,
    opts: MockScannerOptions = {},
  ): { plugin: ScannerPlugin; state: MockScannerState } {
    const state: MockScannerState = { calls: 0, seenFiles: [], sawAbortedSignal: false };
    const plugin: ScannerPlugin = {
      id,
      name: id,
      version: '0.0.0',
      categories: ['other'],
      supportedFiles: opts.supportedFiles ?? [],
      rules: [],
      async scan(context: ScanContext): Promise<Finding[]> {
        state.calls += 1;
        state.sawAbortedSignal = context.signal.aborted;
        state.lastConfig = context.config;
        if (opts.alwaysThrow) throw new Error(`${id} always fails`);
        const out: Finding[] = [];
        for (const file of context.files) {
          state.seenFiles.push(file.relPath);
          if (context.signal.aborted) throw new Error(`${id} aborted`);
          if (opts.throwOnFile?.(file.relPath)) {
            throw new Error(`${id} failed on ${file.relPath}`);
          }
          const produced = opts.findingsPerFile?.(file.relPath);
          if (produced) out.push(...(Array.isArray(produced) ? produced : [produced]));
        }
        return out;
      },
    };
    return { plugin, state };
  }

  function mockFinding(scanner: string, file: string, ruleId = 'C001'): Finding {
    return createFinding({
      ruleId,
      title: 'mock finding',
      description: 'Finding produced by a mock scanner for engine integration tests.',
      severity: 'medium',
      confidence: 'medium',
      category: 'other',
      file,
      evidence: 'mock-evidence',
      recommendation: 'n/a',
      references: [],
      scanner,
    });
  }

  describe('registration', () => {
    it('plugins() reflects registered plugins in registration order', () => {
      const engine = createEngine();
      const { plugin: a } = makeMockScanner('mock-a');
      const { plugin: b } = makeMockScanner('mock-b');
      engine.register(a);
      engine.register(b);
      expect(engine.plugins().map((p) => p.id)).toEqual(['mock-a', 'mock-b']);
    });
  });

  describe('scanning the vulnerable-app fixture', () => {
    it('returns a well-formed Report', async () => {
      const engine = createEngine();
      const { plugin } = makeMockScanner('mock-a', {
        findingsPerFile: (relPath) =>
          relPath === '.env' ? mockFinding('mock-a', relPath) : undefined,
      });
      engine.register(plugin);

      const report = await engine.scan({ target: fixturePath('vulnerable-app') });

      expect(report.tool.name).toBeTruthy();
      expect(report.tool.version).toBeTruthy();
      expect(report.target).toContain('vulnerable-app');
      expect(Number.isNaN(new Date(report.startedAt).getTime())).toBe(false);
      expect(Number.isNaN(new Date(report.finishedAt).getTime())).toBe(false);
      expect(report.durationMs).toBeGreaterThanOrEqual(0);
      expect(report.scannersRun).toContain('mock-a');
      expect(report.findings.some((f) => f.file === '.env' && f.scanner === 'mock-a')).toBe(true);
      expect(report.stats.medium).toBe(
        report.findings.filter((f) => f.severity === 'medium').length,
      );
      expect(report.errors).toEqual([]);
    });

    it("filters files to each scanner's supportedFiles globs", async () => {
      const engine = createEngine();
      const { plugin, state } = makeMockScanner('mock-env-only', {
        supportedFiles: ['**/.env*'],
      });
      engine.register(plugin);

      await engine.scan({ target: fixturePath('vulnerable-app') });

      expect(state.seenFiles).toEqual(['.env']);
    });
  });

  describe('failure isolation', () => {
    it('one scanner throwing does not stop the others, and is recorded as a ScannerError', async () => {
      const engine = createEngine();
      const { plugin: ok } = makeMockScanner('mock-ok', {
        findingsPerFile: (relPath) =>
          relPath === '.env' ? mockFinding('mock-ok', relPath) : undefined,
      });
      const { plugin: bad, state: badState } = makeMockScanner('mock-bad', { alwaysThrow: true });
      engine.register(ok);
      engine.register(bad);

      const report = await engine.scan({ target: fixturePath('vulnerable-app') });

      expect(badState.calls).toBe(1);
      expect(report.errors.some((e) => e.scanner === 'mock-bad')).toBe(true);
      expect(report.findings.some((f) => f.scanner === 'mock-ok')).toBe(true);
    });
  });

  describe('scanners option', () => {
    it('runs only the requested subset of registered scanners', async () => {
      const engine = createEngine();
      const { plugin: a, state: stateA } = makeMockScanner('mock-a');
      const { plugin: b, state: stateB } = makeMockScanner('mock-b');
      engine.register(a);
      engine.register(b);

      const report = await engine.scan({
        target: fixturePath('vulnerable-app'),
        scanners: ['mock-a'],
      });

      expect(stateA.calls).toBe(1);
      expect(stateB.calls).toBe(0);
      expect(report.scannersRun).toEqual(['mock-a']);
    });
  });

  describe('config', () => {
    it('never invokes a scanner disabled via scanners[id].enabled === false', async () => {
      const engine = createEngine();
      const { plugin, state } = makeMockScanner('mock-a');
      engine.register(plugin);
      const config: SentinelConfig = {
        ...defaultConfig(),
        scanners: { 'mock-a': { enabled: false } },
      };

      const report = await engine.scan({ target: fixturePath('vulnerable-app'), config });

      expect(state.calls).toBe(0);
      expect(report.scannersRun).not.toContain('mock-a');
    });

    it("passes the scanner's own config section through to its ScanContext", async () => {
      const engine = createEngine();
      const { plugin, state } = makeMockScanner('mock-a');
      engine.register(plugin);
      const config: SentinelConfig = {
        ...defaultConfig(),
        scanners: { 'mock-a': { enabled: true, allowlist: ['foo'] } },
      };

      await engine.scan({ target: fixturePath('vulnerable-app'), config });

      expect(state.lastConfig).toEqual({ enabled: true, allowlist: ['foo'] });
    });
  });

  describe('events', () => {
    it('emits a coherent scan:start .. scan:complete sequence, including scanner:error', async () => {
      const engine = createEngine();
      const { plugin: ok } = makeMockScanner('mock-ok');
      const { plugin: bad } = makeMockScanner('mock-bad', { alwaysThrow: true });
      engine.register(ok);
      engine.register(bad);

      const events: ScanEvent[] = [];
      await engine.scan({
        target: fixturePath('vulnerable-app'),
        onEvent: (event) => events.push(event),
      });

      expect(events[0]?.type).toBe('scan:start');
      expect(events.at(-1)?.type).toBe('scan:complete');
      expect(events.some((e) => e.type === 'files:discovered')).toBe(true);
      expect(events.some((e) => e.type === 'scanner:start' && e.scanner === 'mock-ok')).toBe(true);
      expect(events.some((e) => e.type === 'scanner:complete' && e.scanner === 'mock-ok')).toBe(
        true,
      );
      expect(events.some((e) => e.type === 'scanner:error' && e.scanner === 'mock-bad')).toBe(true);
    });
  });

  describe('cancellation', () => {
    it('propagates an already-aborted signal into each scanner ScanContext', async () => {
      const engine = createEngine();
      const controller = new AbortController();
      controller.abort();
      const { plugin, state } = makeMockScanner('mock-abort-aware');
      engine.register(plugin);

      // Cancellation may surface as a rejection, an empty-ish report, or a
      // completed-but-partial report — the engine's exact contract for a
      // signal already aborted before scan() starts isn't spelled out
      // beyond "cooperative cancellation" (docs/architecture.md). What must
      // hold regardless of that choice is that the scanner actually observed
      // the abort via its ScanContext.
      await engine
        .scan({ target: fixturePath('vulnerable-app'), signal: controller.signal })
        .catch(() => undefined);

      expect(state.sawAbortedSignal).toBe(true);
    });
  });

  describe('file discovery guarantees (runtime-generated inputs, tmpdir only)', () => {
    let tmpRoot: string;

    beforeEach(() => {
      tmpRoot = mkdtempSync(join(tmpdir(), 'dl-sentinel-engine-'));
    });

    afterEach(() => {
      rmSync(tmpRoot, { recursive: true, force: true });
    });

    it('excludes files larger than maxFileSizeBytes', async () => {
      writeFileSync(join(tmpRoot, 'small.txt'), 'ok');
      writeFileSync(join(tmpRoot, 'huge.txt'), 'x'.repeat(4096));

      const engine = createEngine();
      const { plugin, state } = makeMockScanner('mock-size');
      engine.register(plugin);

      const config: SentinelConfig = { ...defaultConfig(), maxFileSizeBytes: 1024 };
      await engine.scan({ target: tmpRoot, config });

      expect(state.seenFiles).toContain('small.txt');
      expect(state.seenFiles).not.toContain('huge.txt');
    });

    it('never follows symlinks during discovery', async () => {
      const outsideDir = mkdtempSync(join(tmpdir(), 'dl-sentinel-outside-'));
      try {
        const outsideFile = join(outsideDir, 'secret-outside.txt');
        writeFileSync(outsideFile, 'should never be scanned');
        writeFileSync(join(tmpRoot, 'real.txt'), 'real file');
        symlinkSync(outsideFile, join(tmpRoot, 'link-to-outside.txt'));

        const engine = createEngine();
        const { plugin, state } = makeMockScanner('mock-symlink');
        engine.register(plugin);

        await engine.scan({ target: tmpRoot });

        expect(state.seenFiles).toContain('real.txt');
        expect(state.seenFiles).not.toContain('link-to-outside.txt');
      } finally {
        rmSync(outsideDir, { recursive: true, force: true });
      }
    });
  });
});
