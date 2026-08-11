import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { Finding } from '@dl-sentinel/core';
import { defaultConfig } from '@dl-sentinel/core';
import { loadConfigWithLogger } from '../src/config.js';
import {
  loadScannerPlugin,
  loadScannerPlugins,
  resolvePluginSource,
  validateScannerPlugin,
} from '../src/index.js';
import { makeTempDir, recordingLogger } from './helpers.js';
import { makeScanContext } from '../../../tests/support/index.js';

/** Directory holding the plain-ESM fixture plugin modules. */
const PLUGIN_DIR = fileURLToPath(new URL('./fixtures/plugins', import.meta.url));
/** This test file's own directory — stands in for a caller's cwd. */
const TEST_DIR = fileURLToPath(new URL('.', import.meta.url));

function fixture(name: string): string {
  return path.join(PLUGIN_DIR, name);
}

/**
 * Await a load that must fail, asserting the engine's `UsageError` shape (the
 * name every app switches on) and returning the message for further assertions.
 */
async function usageFailure(promise: Promise<unknown>): Promise<string> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught, 'expected the plugin load to fail').toBeInstanceOf(Error);
  const error = caught as Error;
  expect(error.name).toBe('UsageError');
  return error.message;
}

const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup !== undefined) await cleanup();
  }
});

async function tempDirWith(files: Record<string, string>): Promise<string> {
  const { dir, cleanup } = await makeTempDir();
  cleanups.push(cleanup);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(path.join(dir, name), content);
  }
  return dir;
}

describe('loadScannerPlugin: a well-formed plugin', () => {
  it('loads the default export and exposes its metadata', async () => {
    const plugin = await loadScannerPlugin(fixture('valid.mjs'));
    expect(plugin.id).toBe('fixture-plugin');
    expect(plugin.name).toBe('Fixture Plugin');
    expect(plugin.version).toBe('1.2.3');
    expect(plugin.categories).toEqual(['other']);
    expect(plugin.supportedFiles).toEqual(['**/*.txt']);
    expect(plugin.rules.map((rule) => rule.id)).toEqual(['FX001']);
    expect(typeof plugin.scan).toBe('function');
  });

  it('produces a deterministic finding when scanned', async () => {
    const plugin = await loadScannerPlugin(fixture('valid.mjs'));
    const dir = await tempDirWith({ 'notes.txt': 'nothing secret here\n' });
    const context = makeScanContext(dir, [
      { absPath: path.join(dir, 'notes.txt'), relPath: 'notes.txt', size: 20 },
    ]);

    const findings: Finding[] = await plugin.scan(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('FX001');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.scanner).toBe('fixture-plugin');
    // Same input, same output: nothing about the finding depends on the clock.
    await expect(plugin.scan(context)).resolves.toEqual(findings);
  });

  it('passes validateScannerPlugin, which callers can run themselves', async () => {
    const plugin = await loadScannerPlugin(fixture('valid.mjs'));
    expect(() => validateScannerPlugin(plugin, 'already-loaded')).not.toThrow();
  });
});

describe('loadScannerPlugin: spec resolution', () => {
  it('accepts an absolute path', async () => {
    await expect(loadScannerPlugin(fixture('valid.mjs'))).resolves.toHaveProperty(
      'id',
      'fixture-plugin',
    );
  });

  it('resolves a ./relative spec against the given cwd', async () => {
    const plugin = await loadScannerPlugin('./fixtures/plugins/valid.mjs', { cwd: TEST_DIR });
    expect(plugin.id).toBe('fixture-plugin');
  });

  it('treats a bare spec ending in a module extension as a path, not a package', async () => {
    const plugin = await loadScannerPlugin('fixtures/plugins/valid.mjs', { cwd: TEST_DIR });
    expect(plugin.id).toBe('fixture-plugin');
  });

  it('reports a relative spec that does not resolve, naming the resolved path', async () => {
    const message = await usageFailure(
      loadScannerPlugin('./fixtures/plugins/absent.mjs', { cwd: TEST_DIR }),
    );
    expect(message).toContain('Cannot load plugin');
    expect(message).toContain('./fixtures/plugins/absent.mjs');
    expect(message).toContain(path.join(PLUGIN_DIR, 'absent.mjs'));
  });

  it('imports anything else as a bare package specifier', async () => {
    // Never installed, and deliberately never fetched: loading must fail
    // locally rather than reach the network.
    const message = await usageFailure(loadScannerPlugin('dl-sentinel-plugin-does-not-exist'));
    expect(message).toContain('dl-sentinel-plugin-does-not-exist');
  });

  it('rejects an empty spec', async () => {
    const message = await usageFailure(loadScannerPlugin('   '));
    expect(message).toContain('non-empty');
  });

  it('resolvePluginSource shows paths absolute and package specifiers unchanged', () => {
    expect(resolvePluginSource('./fixtures/plugins/valid.mjs', TEST_DIR)).toBe(
      fixture('valid.mjs'),
    );
    expect(resolvePluginSource('dl-sentinel-plugin-acme', TEST_DIR)).toBe(
      'dl-sentinel-plugin-acme',
    );
    expect(resolvePluginSource('@acme/sentinel-plugin', TEST_DIR)).toBe('@acme/sentinel-plugin');
  });
});

describe('loadScannerPlugin: rejected modules', () => {
  it('rejects a module without a default export', async () => {
    const message = await usageFailure(loadScannerPlugin(fixture('no-default.mjs')));
    expect(message).toContain('no default export');
    expect(message).toContain('no-default.mjs');
  });

  it('rejects a rule with an invalid severity, naming the field', async () => {
    const message = await usageFailure(loadScannerPlugin(fixture('bad-rules.mjs')));
    expect(message).toContain('rules[0].severity');
    expect(message).toContain('critical, high, medium, low, info');
    expect(message).toContain('bad-rules.mjs');
  });

  it('rejects a plugin whose scan is not a function', async () => {
    const message = await usageFailure(loadScannerPlugin(fixture('scan-not-a-function.mjs')));
    expect(message).toContain('"scan" must be a function');
  });

  it('reports a module that throws while importing, without a stack trace', async () => {
    const message = await usageFailure(loadScannerPlugin(fixture('throws-on-import.mjs')));
    expect(message).toContain('Cannot load plugin');
    expect(message).toContain('throws-on-import.mjs');
    expect(message).toContain('fixture plugin exploded during import');
    // A stack would leak module internals into operator-facing output.
    expect(message).not.toMatch(/\n\s+at\s/);
  });
});

describe('loadScannerPlugins', () => {
  it('preserves the order the specs were given', async () => {
    const plugins = await loadScannerPlugins([
      fixture('valid.mjs'),
      fixture('collides-with-builtin.mjs'),
    ]);
    expect(plugins.map((plugin) => plugin.id)).toEqual(['fixture-plugin', 'secrets']);

    const reversed = await loadScannerPlugins([
      fixture('collides-with-builtin.mjs'),
      fixture('valid.mjs'),
    ]);
    expect(reversed.map((plugin) => plugin.id)).toEqual(['secrets', 'fixture-plugin']);
  });

  it('rejects two plugins that claim the same id', async () => {
    const message = await usageFailure(
      loadScannerPlugins([fixture('valid.mjs'), fixture('duplicate-id.mjs')]),
    );
    expect(message).toContain('Duplicate plugin id "fixture-plugin"');
    expect(message).toContain('duplicate-id.mjs');
    expect(message).toContain('valid.mjs');
  });

  it('rejects the same spec listed twice', async () => {
    const message = await usageFailure(
      loadScannerPlugins([fixture('valid.mjs'), fixture('valid.mjs')]),
    );
    expect(message).toContain('Duplicate plugin id "fixture-plugin"');
  });

  it('returns an empty list for no specs', async () => {
    await expect(loadScannerPlugins([])).resolves.toEqual([]);
  });
});

describe('validateScannerPlugin', () => {
  const wellFormed = {
    id: 'acme',
    name: 'Acme Scanner',
    version: '1.0.0',
    categories: ['other'],
    supportedFiles: [],
    rules: [],
    scan: async () => [],
  };

  function messageOf(value: unknown, label?: string): string {
    try {
      validateScannerPlugin(value, label);
    } catch (error) {
      expect((error as Error).name).toBe('UsageError');
      return (error as Error).message;
    }
    throw new Error('expected validation to fail');
  }

  it('accepts a hand-built plugin', () => {
    expect(() => validateScannerPlugin(wellFormed)).not.toThrow();
  });

  it('rejects non-objects', () => {
    expect(messageOf('a string')).toContain('must be a ScannerPlugin object');
    expect(messageOf(null)).toContain('must be a ScannerPlugin object');
    expect(messageOf([])).toContain('must be a ScannerPlugin object');
  });

  it('rejects an empty or missing id', () => {
    expect(messageOf({ ...wellFormed, id: '' })).toContain('"id" must be a non-empty string');
    expect(messageOf({ ...wellFormed, id: undefined })).toContain('"id"');
  });

  it('rejects non-string entries in categories and supportedFiles', () => {
    expect(messageOf({ ...wellFormed, categories: 'secrets' })).toContain(
      '"categories" must be an array of strings',
    );
    expect(messageOf({ ...wellFormed, supportedFiles: ['ok', 7] })).toContain(
      '"supportedFiles[1]" must be a string',
    );
  });

  it('rejects a missing rules array and malformed rule entries', () => {
    expect(messageOf({ ...wellFormed, rules: undefined })).toContain('"rules" must be an array');
    const badConfidence = {
      ...wellFormed,
      rules: [
        {
          id: 'A001',
          title: 'x',
          description: 'y',
          recommendation: 'z',
          category: 'other',
          severity: 'high',
          defaultConfidence: 'certain',
        },
      ],
    };
    expect(messageOf(badConfidence)).toContain('"rules[0].defaultConfidence" must be one of');
  });

  it('includes the label so an operator knows which plugin was rejected', () => {
    expect(messageOf({ ...wellFormed, version: 4 }, './plugins/acme.mjs')).toContain(
      'Invalid plugin "./plugins/acme.mjs"',
    );
  });

  it('rejects a whitespace-only id', () => {
    expect(messageOf({ ...wellFormed, id: '   ' })).toContain('"id" must be a non-empty string');
  });

  it('never echoes more than a short prefix of an offending value', () => {
    // A plugin's own data must not be able to turn a validation message into a
    // dump of module content, so echoed values are clipped and de-newlined.
    const long = `${'x'.repeat(500)}\nsecond line`;
    const message = messageOf({
      ...wellFormed,
      rules: [
        {
          id: 'A001',
          title: 'x',
          description: 'y',
          recommendation: 'z',
          category: 'other',
          severity: long,
          defaultConfidence: 'medium',
        },
      ],
    });
    expect(message).toContain('"rules[0].severity" must be one of');
    expect(message).not.toContain(long);
    expect(message).not.toContain('\n');
    expect(message.length).toBeLessThan(200);
  });
});

describe('config: a plugins key is ignored, not honored', () => {
  it('warns specifically that plugins load only from --plugin / SENTINEL_PLUGINS', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': 'plugins:\n  - ./attacker-supplied.mjs\nmaxFileSizeBytes: 2048\n',
    });
    const logger = recordingLogger();

    const config = await loadConfigWithLogger(dir, undefined, logger);

    const warning = logger.of('warn').find((message) => message.includes('"plugins"'));
    expect(warning).toBeDefined();
    expect(warning).toContain('--plugin');
    expect(warning).toContain('SENTINEL_PLUGINS');
    expect(warning).toContain('never from a config file');
    // Not lumped in with typos: the operator is told where plugins come from.
    expect(warning).not.toContain('unknown configuration key');
    // The rest of the file still applies, and nothing named "plugins" survives.
    expect(config.maxFileSizeBytes).toBe(2048);
    expect(Object.keys(config)).toEqual(Object.keys(defaultConfig()));
    expect((config as Record<string, unknown>).plugins).toBeUndefined();
  });
});
