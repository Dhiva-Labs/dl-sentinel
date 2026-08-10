import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { FileRef, ScanEvent, SentinelConfig } from '@dl-sentinel/core';
import {
  TOOL_NAME,
  TOOL_VERSION,
  createFinding,
  defaultConfig,
  findingFingerprint,
} from '@dl-sentinel/core';
import { createEngine } from '../src/index.js';
import {
  FIXTURE_TREE,
  failingPlugin,
  findingInput,
  makeTempDir,
  mockPlugin,
  pluginReturning,
  recordingLogger,
  testFinding,
} from './helpers.js';

describe('createEngine: registration', () => {
  it('returns registered plugins in registration order', () => {
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'secrets' }));
    engine.register(mockPlugin({ id: 'dependencies' }));
    engine.register(mockPlugin({ id: 'source' }));

    expect(engine.plugins().map((plugin) => plugin.id)).toEqual([
      'secrets',
      'dependencies',
      'source',
    ]);
  });

  it('rejects a duplicate scanner id', () => {
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'secrets' }));

    expect(() => engine.register(mockPlugin({ id: 'secrets' }))).toThrow(
      'A scanner with id "secrets" is already registered',
    );
    expect(engine.plugins()).toHaveLength(1);
  });

  it('rejects a plugin without an id', () => {
    const engine = createEngine();
    expect(() => engine.register(mockPlugin({ id: '' }))).toThrow('non-empty id');
  });

  it('hands out a copy of the plugin list', () => {
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'secrets' }));

    const plugins = engine.plugins() as ReturnType<typeof mockPlugin>[];
    plugins.pop();

    expect(engine.plugins()).toHaveLength(1);
  });
});

describe('scan: execution', () => {
  it('runs every registered scanner and aggregates their findings', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput({ file: 'src/app.ts', line: 1 })]));
    engine.register(
      pluginReturning('beta', [
        findingInput({ file: 'src/util.ts', line: 2, severity: 'critical' }),
        findingInput({ file: 'docs/guide.md', line: 3, severity: 'low' }),
      ]),
    );

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.scannersRun).toEqual(['alpha', 'beta']);
    expect(report.findings).toHaveLength(3);
    expect(report.errors).toEqual([]);
    expect(report.stats).toEqual({ critical: 1, high: 0, medium: 1, low: 1, info: 0 });
  });

  it('sorts findings by severity, then file, then line', async () => {
    const engine = createEngine();
    engine.register(
      pluginReturning('alpha', [
        findingInput({ file: 'z.ts', line: 9, severity: 'low' }),
        findingInput({ file: 'a.ts', line: 2, severity: 'critical' }),
      ]),
    );
    engine.register(
      pluginReturning('beta', [findingInput({ file: 'a.ts', line: 1, severity: 'critical' })]),
    );

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(
      report.findings.map((finding) => [finding.severity, finding.file, finding.line]),
    ).toEqual([
      ['critical', 'a.ts', 1],
      ['critical', 'a.ts', 2],
      ['low', 'z.ts', 9],
    ]);
  });

  it('calls each scanner exactly once, even when no file matches it', async () => {
    let calls = 0;
    let received: readonly FileRef[] = [{ absPath: '/x', relPath: 'x', size: 1 }];
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'rust',
        supportedFiles: ['**/*.rs'],
        scan: async (context) => {
          calls += 1;
          received = context.files;
          return [];
        },
      }),
    );

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(calls).toBe(1);
    expect(received).toEqual([]);
    expect(report.scannersRun).toEqual(['rust']);
  });

  it('gives each scanner a context with the target root, its config section and a UTF-8 reader', async () => {
    const config: SentinelConfig = {
      ...defaultConfig(),
      scanners: { probe: { enabled: true, depth: 3 } },
    };
    let rootDir = '';
    let section: Record<string, unknown> = {};
    let contents = '';

    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'probe',
        supportedFiles: ['src/app.ts'],
        scan: async (context) => {
          rootDir = context.rootDir;
          section = context.config;
          const file = context.files[0];
          if (file !== undefined) contents = await context.readFile(file);
          return [];
        },
      }),
    );

    await engine.scan({ target: FIXTURE_TREE, config });

    expect(rootDir).toBe(FIXTURE_TREE);
    expect(section).toEqual({ enabled: true, depth: 3 });
    expect(contents).toContain('fixture app');
  });

  it('passes an empty config section to scanners with no configuration', async () => {
    let section: Record<string, unknown> | undefined;
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'probe',
        scan: async (context) => {
          section = context.config;
          return [];
        },
      }),
    );

    await engine.scan({ target: FIXTURE_TREE });

    expect(section).toEqual({});
  });

  it('does not let a scanner mutate shared configuration', async () => {
    const config: SentinelConfig = { ...defaultConfig(), scanners: { probe: { enabled: true } } };
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'probe',
        scan: async (context) => {
          context.config.enabled = false;
          return [];
        },
      }),
    );

    await engine.scan({ target: FIXTURE_TREE, config });

    expect(config.scanners.probe).toEqual({ enabled: true });
  });

  it('runs scanners concurrently rather than one after another', async () => {
    const order: string[] = [];
    const engine = createEngine();
    for (const id of ['alpha', 'beta']) {
      engine.register(
        mockPlugin({
          id,
          scan: async () => {
            order.push(`${id}:enter`);
            await new Promise((resolve) => setTimeout(resolve, 20));
            order.push(`${id}:exit`);
            return [];
          },
        }),
      );
    }

    await engine.scan({ target: FIXTURE_TREE });

    expect(order).toEqual(['alpha:enter', 'beta:enter', 'alpha:exit', 'beta:exit']);
  });
});

describe('scan: failure isolation', () => {
  it('records a failing scanner as an error and still reports the other three', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput({ file: 'a.ts' })]));
    engine.register(pluginReturning('beta', [findingInput({ file: 'b.ts' })]));
    engine.register(pluginReturning('gamma', [findingInput({ file: 'c.ts' })]));
    engine.register(failingPlugin('delta', 'delta exploded'));

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.findings.map((finding) => finding.scanner).sort()).toEqual([
      'alpha',
      'beta',
      'gamma',
    ]);
    expect(report.errors).toHaveLength(1);
    expect(report.errors[0]?.scanner).toBe('delta');
    expect(report.errors[0]?.message).toBe('delta exploded');
    expect(report.errors[0]?.stack).toContain('delta exploded');
    // A failed scanner still ran, so it stays in scannersRun.
    expect(report.scannersRun).toEqual(['alpha', 'beta', 'gamma', 'delta']);
  });

  it('isolates a scanner that throws synchronously', async () => {
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'sync',
        scan: () => {
          throw new Error('sync boom');
        },
      }),
    );
    engine.register(pluginReturning('healthy', [findingInput()]));

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.errors).toEqual([
      expect.objectContaining({ scanner: 'sync', message: 'sync boom' }),
    ]);
    expect(report.findings).toHaveLength(1);
  });

  it('isolates a scanner that throws a non-Error value', async () => {
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'rude',
        scan: async () => {
          throw 'just a string';
        },
      }),
    );

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.errors).toEqual([{ scanner: 'rude', message: 'just a string' }]);
    expect(report.findings).toEqual([]);
  });

  it('records every failure when all scanners fail', async () => {
    const engine = createEngine();
    engine.register(failingPlugin('alpha'));
    engine.register(failingPlugin('beta'));

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.errors.map((error) => error.scanner)).toEqual(['alpha', 'beta']);
    expect(report.findings).toEqual([]);
    expect(report.stats).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('logs the failure without touching file contents', async () => {
    const logger = recordingLogger();
    const engine = createEngine();
    engine.register(failingPlugin('delta', 'delta exploded'));

    await engine.scan({ target: FIXTURE_TREE, logger });

    expect(logger.of('error')).toEqual(['Scanner "delta" failed: delta exploded']);
  });
});

describe('scan: finding attribution and dedupe', () => {
  it('re-attributes findings to the scanner that produced them', async () => {
    const logger = recordingLogger();
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'alpha',
        scan: async () => [createFinding({ ...findingInput(), scanner: 'impersonated' })],
      }),
    );

    const report = await engine.scan({ target: FIXTURE_TREE, logger });
    const [finding] = report.findings;
    if (finding === undefined) throw new Error('expected the scanner to produce a finding');

    expect(finding.scanner).toBe('alpha');
    // The scanner id is part of the fingerprint, so the id is recomputed too.
    expect(finding.id).toBe(findingFingerprint(finding));
    expect(logger.of('warn')[0]).toContain('returned a finding attributed to "impersonated"');
  });

  it('leaves correctly attributed findings untouched', async () => {
    const original = testFinding({ scanner: 'alpha' });
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'alpha', scan: async () => [original] }));

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.findings[0]).toEqual(original);
  });

  it('drops duplicate findings emitted twice by the same scanner', async () => {
    const duplicate = testFinding({ scanner: 'alpha' });
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'alpha', scan: async () => [duplicate, { ...duplicate }] }));

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.findings).toHaveLength(1);
  });

  it('dedupes identical findings reported by two different scanners', async () => {
    // Two scanners wrapping the same detection emit the same finding id; the
    // first one seen wins.
    const shared = testFinding({ scanner: 'alpha' });
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'alpha', scan: async () => [shared] }));
    engine.register(mockPlugin({ id: 'beta', scan: async () => [{ ...shared, scanner: 'beta' }] }));

    const report = await engine.scan({ target: FIXTURE_TREE });

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.scanner).toBe('alpha');
    expect(report.stats.medium).toBe(1);
  });
});

describe('scan: scanner selection', () => {
  it('narrows discovered files to each scanner supportedFiles globs', async () => {
    const seen: Record<string, string[]> = {};
    const capture = (id: string, supportedFiles: string[]) =>
      mockPlugin({
        id,
        supportedFiles,
        scan: async (context) => {
          seen[id] = context.files.map((file) => file.relPath);
          return [];
        },
      });

    const engine = createEngine();
    engine.register(capture('typescript', ['**/*.ts']));
    engine.register(capture('envs', ['**/*.env']));
    engine.register(capture('everything', []));

    await engine.scan({ target: FIXTURE_TREE });

    expect(seen.typescript).toEqual(['src/app.ts', 'src/nested/deep/deep.ts', 'src/util.ts']);
    expect(seen.envs).toEqual(['config/sample.env']);
    expect(seen.everything).toHaveLength(9);
  });

  it('skips scanners disabled in configuration', async () => {
    let betaRan = false;
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput()]));
    engine.register(
      mockPlugin({
        id: 'beta',
        scan: async () => {
          betaRan = true;
          return [];
        },
      }),
    );

    const events: ScanEvent[] = [];
    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: { ...defaultConfig(), scanners: { beta: { enabled: false } } },
      onEvent: (event) => events.push(event),
    });

    expect(betaRan).toBe(false);
    expect(report.scannersRun).toEqual(['alpha']);
    expect(events.filter((event) => event.type === 'scanner:start')).toHaveLength(1);
  });

  it('runs a scanner when enabled is true or absent', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput()]));
    engine.register(pluginReturning('beta', [findingInput({ file: 'other.ts' })]));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: { ...defaultConfig(), scanners: { alpha: { enabled: true }, beta: {} } },
    });

    expect(report.scannersRun).toEqual(['alpha', 'beta']);
  });

  it('limits the run to options.scanners, preserving registration order', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput({ file: 'a.ts' })]));
    engine.register(pluginReturning('beta', [findingInput({ file: 'b.ts' })]));
    engine.register(pluginReturning('gamma', [findingInput({ file: 'c.ts' })]));

    const report = await engine.scan({ target: FIXTURE_TREE, scanners: ['gamma', 'alpha'] });

    expect(report.scannersRun).toEqual(['alpha', 'gamma']);
    expect(report.findings.map((finding) => finding.scanner).sort()).toEqual(['alpha', 'gamma']);
  });

  it('rejects unknown ids in options.scanners', async () => {
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'alpha' }));

    await expect(
      engine.scan({ target: FIXTURE_TREE, scanners: ['alpha', 'nope'] }),
    ).rejects.toThrow('Unknown scanner: nope. Registered: alpha');
  });

  it('names every unknown id at once', async () => {
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'alpha' }));

    await expect(
      engine.scan({ target: FIXTURE_TREE, scanners: ['nope', 'also-nope'] }),
    ).rejects.toThrow('Unknown scanners: nope, also-nope');
  });

  it('runs nothing when options.scanners is empty', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput()]));

    const report = await engine.scan({ target: FIXTURE_TREE, scanners: [] });

    expect(report.scannersRun).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it('produces an empty report when nothing is registered', async () => {
    const report = await createEngine().scan({ target: FIXTURE_TREE });

    expect(report.scannersRun).toEqual([]);
    expect(report.findings).toEqual([]);
    expect(report.errors).toEqual([]);
  });
});

describe('scan: configuration sources', () => {
  it('prefers options.config, then configPath, then the target directory file', async () => {
    const { dir, cleanup } = await makeTempDir();
    try {
      await writeFile(
        path.join(dir, 'sentinel.yml'),
        'scanners:\n  probe:\n    source: targetDir\n',
      );
      await writeFile(path.join(dir, 'other.yml'), 'scanners:\n  probe:\n    source: configPath\n');

      let seen: unknown;
      const engine = createEngine();
      engine.register(
        mockPlugin({
          id: 'probe',
          scan: async (context) => {
            seen = context.config.source;
            return [];
          },
        }),
      );

      await engine.scan({ target: dir });
      expect(seen).toBe('targetDir');

      await engine.scan({ target: dir, configPath: path.join(dir, 'other.yml') });
      expect(seen).toBe('configPath');

      await engine.scan({
        target: dir,
        configPath: path.join(dir, 'other.yml'),
        config: { ...defaultConfig(), scanners: { probe: { source: 'options' } } },
      });
      expect(seen).toBe('options');
    } finally {
      await cleanup();
    }
  });

  it('applies include/exclude from the target directory config during discovery', async () => {
    const { dir, cleanup } = await makeTempDir();
    try {
      await mkdir(path.join(dir, 'src'), { recursive: true });
      await writeFile(path.join(dir, 'src', 'app.ts'), 'export const a = 1;\n');
      await writeFile(path.join(dir, 'notes.txt'), 'ignore me\n');
      await writeFile(path.join(dir, 'sentinel.yml'), "include:\n  - '**/*.ts'\n");

      let seen: string[] = [];
      const engine = createEngine();
      engine.register(
        mockPlugin({
          id: 'probe',
          scan: async (context) => {
            seen = context.files.map((file) => file.relPath);
            return [];
          },
        }),
      );

      await engine.scan({ target: dir });

      expect(seen).toEqual(['src/app.ts']);
    } finally {
      await cleanup();
    }
  });

  it('surfaces configuration errors instead of scanning with broken settings', async () => {
    const { dir, cleanup } = await makeTempDir();
    try {
      await writeFile(path.join(dir, 'sentinel.yml'), 'maxFileSizeBytes: nope\n');
      const engine = createEngine();
      engine.register(mockPlugin({ id: 'alpha' }));

      await expect(engine.scan({ target: dir })).rejects.toThrow(
        '"maxFileSizeBytes" must be a positive number',
      );
    } finally {
      await cleanup();
    }
  });
});

describe('scan: target validation', () => {
  it('rejects a target that does not exist', async () => {
    const missing = path.join(FIXTURE_TREE, 'no-such-directory');
    await expect(createEngine().scan({ target: missing })).rejects.toThrow(
      `Scan target does not exist: ${missing}`,
    );
  });

  it('rejects a target that is not a directory', async () => {
    const file = path.join(FIXTURE_TREE, 'README.md');
    await expect(createEngine().scan({ target: file })).rejects.toThrow(
      `Scan target is not a directory: ${file}`,
    );
  });

  it('rejects an empty target', async () => {
    await expect(createEngine().scan({ target: '   ' })).rejects.toThrow(
      'options.target must be a non-empty directory path',
    );
  });
});

describe('scan: report shape', () => {
  it('reports tool, project, target and timings', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput()]));

    const before = Date.now();
    const report = await engine.scan({ target: FIXTURE_TREE });
    const after = Date.now();

    expect(report.tool).toEqual({ name: TOOL_NAME, version: TOOL_VERSION });
    expect(report.project).toBe(path.basename(FIXTURE_TREE));
    expect(report.target).toBe(FIXTURE_TREE);
    expect(Date.parse(report.startedAt)).toBeGreaterThanOrEqual(before - 1);
    expect(Date.parse(report.finishedAt)).toBeLessThanOrEqual(after + 1);
    expect(report.startedAt).toBe(new Date(report.startedAt).toISOString());
    expect(report.finishedAt).toBe(new Date(report.finishedAt).toISOString());
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
    expect(report.durationMs).toBeLessThanOrEqual(after - before);
  });

  it('resolves a relative target to an absolute path', async () => {
    const report = await createEngine().scan({
      target: path.relative(process.cwd(), FIXTURE_TREE),
    });

    expect(path.isAbsolute(report.target)).toBe(true);
    expect(report.target).toBe(FIXTURE_TREE);
  });
});

describe('scan: events', () => {
  it('emits scan:start, files:discovered, per-scanner events and scan:complete in order', async () => {
    const events: ScanEvent[] = [];
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput()]));
    engine.register(mockPlugin({ id: 'beta' }));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      onEvent: (event) => events.push(event),
    });

    expect(events[0]).toEqual({
      type: 'scan:start',
      target: FIXTURE_TREE,
      scanners: ['alpha', 'beta'],
    });
    expect(events[1]).toEqual({ type: 'files:discovered', count: 9 });
    expect(events.at(-1)).toEqual({
      type: 'scan:complete',
      findings: 1,
      durationMs: report.durationMs,
    });

    const types = events.map((event) => event.type);
    expect(types.indexOf('scanner:start')).toBeLessThan(types.indexOf('scanner:complete'));
    expect(events).toContainEqual({
      type: 'scanner:complete',
      scanner: 'alpha',
      findings: 1,
      durationMs: expect.any(Number),
    });
    expect(events).toContainEqual({
      type: 'scanner:complete',
      scanner: 'beta',
      findings: 0,
      durationMs: expect.any(Number),
    });
  });

  it('emits scanner:error instead of scanner:complete for a failing scanner', async () => {
    const events: ScanEvent[] = [];
    const engine = createEngine();
    engine.register(failingPlugin('delta', 'delta exploded'));

    await engine.scan({ target: FIXTURE_TREE, onEvent: (event) => events.push(event) });

    expect(events).toContainEqual({
      type: 'scanner:error',
      scanner: 'delta',
      message: 'delta exploded',
    });
    expect(events.filter((event) => event.type === 'scanner:complete')).toEqual([]);
  });

  it('keeps scanning when an event listener throws', async () => {
    const logger = recordingLogger();
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput()]));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      logger,
      onEvent: () => {
        throw new Error('listener broke');
      },
    });

    expect(report.findings).toHaveLength(1);
    expect(logger.of('warn')).toContain('Scan event listener threw: listener broke');
  });
});

describe('scan: cancellation', () => {
  it('rejects with an AbortError when the signal is already aborted', async () => {
    const events: ScanEvent[] = [];
    const controller = new AbortController();
    controller.abort();
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'alpha' }));

    await expect(
      engine.scan({
        target: FIXTURE_TREE,
        signal: controller.signal,
        onEvent: (event) => events.push(event),
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(events).toEqual([]);
  });

  it('rejects with an AbortError when cancelled mid-scan', async () => {
    const controller = new AbortController();
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'waiter',
        scan: async (context) => {
          await new Promise<void>((resolve) => {
            if (context.signal.aborted) {
              resolve();
              return;
            }
            context.signal.addEventListener('abort', () => resolve(), { once: true });
          });
          throw new Error('scanner noticed the abort');
        },
      }),
    );

    const promise = engine.scan({
      target: FIXTURE_TREE,
      signal: controller.signal,
      onEvent: (event) => {
        if (event.type === 'scanner:start') setTimeout(() => controller.abort(), 0);
      },
    });

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('does not turn a post-abort scanner throw into a ScannerError', async () => {
    const controller = new AbortController();
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'waiter',
        scan: async (context) => {
          await new Promise<void>((resolve) => {
            context.signal.addEventListener('abort', () => resolve(), { once: true });
          });
          throw new Error('aborted');
        },
      }),
    );
    engine.register(pluginReturning('healthy', [findingInput()]));

    const promise = engine.scan({ target: FIXTURE_TREE, signal: controller.signal });
    setTimeout(() => controller.abort(), 10);

    // Cancellation surfaces as a rejection carrying the engine's abort error,
    // not the scanner's throw, and no partial report is produced.
    await expect(promise).rejects.toMatchObject({ name: 'AbortError', message: 'Scan aborted' });
  });

  it('rejects promptly even when a scanner ignores the signal', async () => {
    const controller = new AbortController();
    let release = (): void => {};
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'stubborn',
        scan: async () => {
          await new Promise<void>((resolve) => {
            release = resolve;
          });
          return [];
        },
      }),
    );

    const promise = engine.scan({ target: FIXTURE_TREE, signal: controller.signal });
    setTimeout(() => controller.abort(), 10);

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
    release();
  });

  it('passes the signal through to scanners', async () => {
    const controller = new AbortController();
    let sawAbort = false;
    const engine = createEngine();
    engine.register(
      mockPlugin({
        id: 'watcher',
        scan: async (context) => {
          controller.abort();
          sawAbort = context.signal.aborted;
          return [];
        },
      }),
    );

    await expect(
      engine.scan({ target: FIXTURE_TREE, signal: controller.signal }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(sawAbort).toBe(true);
  });
});
