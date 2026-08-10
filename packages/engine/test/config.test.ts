import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { DEFAULT_EXCLUDES, defaultConfig } from '@dl-sentinel/core';
import { loadConfigWithLogger } from '../src/config.js';
import { loadConfig } from '../src/index.js';
import { makeTempDir, recordingLogger } from './helpers.js';

const cleanups: (() => Promise<void>)[] = [];

async function tempDirWith(files: Record<string, string> = {}): Promise<string> {
  const { dir, cleanup } = await makeTempDir();
  cleanups.push(cleanup);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(path.join(dir, name), content);
  }
  return dir;
}

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup !== undefined) await cleanup();
  }
});

describe('loadConfig: file lookup', () => {
  it('returns pure defaults when no config file exists', async () => {
    const dir = await tempDirWith();
    await expect(loadConfig(dir)).resolves.toEqual(defaultConfig());
  });

  it('loads sentinel.yml from the target directory', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'maxFileSizeBytes: 2048\n' });
    const config = await loadConfig(dir);
    expect(config.maxFileSizeBytes).toBe(2048);
  });

  it('falls back to sentinel.yaml', async () => {
    const dir = await tempDirWith({ 'sentinel.yaml': 'maxFileSizeBytes: 4096\n' });
    const config = await loadConfig(dir);
    expect(config.maxFileSizeBytes).toBe(4096);
  });

  it('prefers sentinel.yml when both spellings exist', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': 'maxFileSizeBytes: 1\n',
      'sentinel.yaml': 'maxFileSizeBytes: 2\n',
    });
    const config = await loadConfig(dir);
    expect(config.maxFileSizeBytes).toBe(1);
  });

  it('an explicit configPath wins over the target-directory file', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': 'maxFileSizeBytes: 1\n',
      'other.yml': 'maxFileSizeBytes: 999\n',
    });
    const config = await loadConfig(dir, path.join(dir, 'other.yml'));
    expect(config.maxFileSizeBytes).toBe(999);
  });

  it('throws when an explicit configPath does not exist', async () => {
    const dir = await tempDirWith();
    const missing = path.join(dir, 'nope.yml');
    await expect(loadConfig(dir, missing)).rejects.toThrow(`Config file not found: ${missing}`);
  });

  it('throws when the explicit configPath is a directory', async () => {
    const dir = await tempDirWith();
    await expect(loadConfig(dir, dir)).rejects.toThrow('Config file not found');
  });
});

describe('loadConfig: merging over defaults', () => {
  it('merges provided keys and leaves the rest at their defaults', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': [
        'include:',
        "  - 'src/**'",
        'maxFileSizeBytes: 2048',
        'policy:',
        '  failOn: [critical]',
        '',
      ].join('\n'),
    });

    const config = await loadConfig(dir);

    expect(config.include).toEqual(['src/**']);
    expect(config.maxFileSizeBytes).toBe(2048);
    expect(config.policy.failOn).toEqual(['critical']);
    // untouched keys keep their defaults
    expect(config.exclude).toEqual([...DEFAULT_EXCLUDES]);
    expect(config.scanners).toEqual({});
  });

  it('replaces list values instead of concatenating them', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': "exclude:\n  - '**/vendor/**'\n" });
    const config = await loadConfig(dir);
    expect(config.exclude).toEqual(['**/vendor/**']);
  });

  it('deep merges nested scanner settings', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': [
        'scanners:',
        '  secrets:',
        '    enabled: true',
        '    allowlist: [AKIAFAKE]',
        '    options:',
        '      minEntropy: 4.2',
        '  dependencies:',
        '    enabled: false',
        '',
      ].join('\n'),
    });

    const config = await loadConfig(dir);

    expect(config.scanners.secrets).toEqual({
      enabled: true,
      allowlist: ['AKIAFAKE'],
      options: { minEntropy: 4.2 },
    });
    expect(config.scanners.dependencies).toEqual({ enabled: false });
  });

  it('treats an empty document as no configuration at all', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': '' });
    await expect(loadConfig(dir)).resolves.toEqual(defaultConfig());
  });

  it('treats a comments-only document as no configuration at all', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': '# nothing to see here\n' });
    await expect(loadConfig(dir)).resolves.toEqual(defaultConfig());
  });

  it('does not share array state with defaultConfig()', async () => {
    const dir = await tempDirWith();
    const config = await loadConfig(dir);
    config.exclude.push('**/extra/**');
    expect(defaultConfig().exclude).toEqual([...DEFAULT_EXCLUDES]);
  });
});

describe('loadConfig: unknown keys', () => {
  it('warns about unknown top-level keys and keeps going', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': 'maxFileSizeBytes: 512\nmystery: true\nalsoUnknown: [1, 2]\n',
    });
    const logger = recordingLogger();

    const config = await loadConfigWithLogger(dir, undefined, logger);

    expect(config.maxFileSizeBytes).toBe(512);
    const warnings = logger.of('warn');
    expect(
      warnings.some((message) => message.includes('unknown configuration key "mystery"')),
    ).toBe(true);
    expect(
      warnings.some((message) => message.includes('unknown configuration key "alsoUnknown"')),
    ).toBe(true);
    expect(warnings.every((message) => message.includes(path.join(dir, 'sentinel.yml')))).toBe(
      true,
    );
  });

  it('warns about unknown keys nested under policy', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': 'policy:\n  failOn: [high]\n  mode: strict\n',
    });
    const logger = recordingLogger();

    const config = await loadConfigWithLogger(dir, undefined, logger);

    expect(config.policy.failOn).toEqual(['high']);
    expect(
      logger
        .of('warn')
        .some((message) => message.includes('unknown configuration key "policy.mode"')),
    ).toBe(true);
  });

  it('does not warn for a fully known config', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': "include: ['**/*.ts']\n" });
    const logger = recordingLogger();

    await loadConfigWithLogger(dir, undefined, logger);

    expect(logger.of('warn')).toEqual([]);
  });
});

describe('loadConfig: suppress', () => {
  it('defaults suppress to an empty list', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'maxFileSizeBytes: 2048\n' });
    const config = await loadConfig(dir);
    expect(config.suppress).toEqual([]);
  });

  it('parses a list of suppression rules, keeping only known string fields', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': [
        'suppress:',
        '  - rule: S001',
        "    path: '**/*.test.env'",
        '    reason: fake keys used in tests',
        '    expires: 2027-01-01',
        '  - id: 9f2c4a1b8d3e6f70',
        '',
      ].join('\n'),
    });

    const config = await loadConfig(dir);

    expect(config.suppress).toEqual([
      {
        rule: 'S001',
        path: '**/*.test.env',
        reason: 'fake keys used in tests',
        expires: '2027-01-01',
      },
      { id: '9f2c4a1b8d3e6f70' },
    ]);
  });

  it('does not warn about the known suppress key', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'suppress:\n  - rule: S001\n' });
    const logger = recordingLogger();
    await loadConfigWithLogger(dir, undefined, logger);
    expect(logger.of('warn')).toEqual([]);
  });

  it('warns and ignores a non-list suppress value', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'suppress: nope\n' });
    const logger = recordingLogger();

    const config = await loadConfigWithLogger(dir, undefined, logger);

    expect(config.suppress).toEqual([]);
    expect(logger.of('warn').some((m) => m.includes('"suppress" must be a list'))).toBe(true);
  });

  it('warns and skips a malformed entry but keeps the valid ones', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': ['suppress:', '  - rule: S001', '  - just-a-string', '  - id: 42', ''].join(
        '\n',
      ),
    });
    const logger = recordingLogger();

    const config = await loadConfigWithLogger(dir, undefined, logger);

    // The middle (scalar) entry is dropped; the numeric id is a non-string and
    // its entry is dropped too, leaving only the well-formed first rule.
    expect(config.suppress).toEqual([{ rule: 'S001' }]);
    expect(logger.of('warn').some((m) => m.includes('suppress[1]'))).toBe(true);
    expect(logger.of('warn').some((m) => m.includes('suppress[2].id'))).toBe(true);
  });
});

describe('loadConfig: rejects invalid input', () => {
  it('throws on unparseable YAML, naming the file', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'include: [oops\n  - broken: : :\n' });
    const file = path.join(dir, 'sentinel.yml');

    await expect(loadConfig(dir)).rejects.toThrow(new RegExp(`Invalid YAML in ${escape(file)}`));
  });

  it('throws when the document is a list', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': '- one\n- two\n' });
    await expect(loadConfig(dir)).rejects.toThrow(
      /expected a mapping at the top level, got a list/,
    );
  });

  it('throws when the document is a scalar', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'just a string\n' });
    await expect(loadConfig(dir)).rejects.toThrow(
      /expected a mapping at the top level, got a string/,
    );
  });

  it('throws when include is not a list', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': "include: 'src/**'\n" });
    await expect(loadConfig(dir)).rejects.toThrow('"include" must be a list of strings');
  });

  it('throws when include contains a non-string', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': "include: ['src/**', 7]\n" });
    await expect(loadConfig(dir)).rejects.toThrow('"include" must be a list of strings');
  });

  it('throws when maxFileSizeBytes is not a positive number', async () => {
    const text = await tempDirWith({ 'sentinel.yml': "maxFileSizeBytes: 'big'\n" });
    await expect(loadConfig(text)).rejects.toThrow('"maxFileSizeBytes" must be a positive number');

    const zero = await tempDirWith({ 'sentinel.yml': 'maxFileSizeBytes: 0\n' });
    await expect(loadConfig(zero)).rejects.toThrow('"maxFileSizeBytes" must be a positive number');
  });

  it('throws when scanners is not a mapping', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'scanners: [secrets]\n' });
    await expect(loadConfig(dir)).rejects.toThrow('"scanners" must be a mapping');
  });

  it('throws when a scanner section is not a mapping', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'scanners:\n  secrets: true\n' });
    await expect(loadConfig(dir)).rejects.toThrow('"scanners.secrets" must be a mapping');
  });

  it('throws when scanner enabled is not a boolean', async () => {
    const dir = await tempDirWith({
      'sentinel.yml': "scanners:\n  secrets:\n    enabled: 'yes'\n",
    });
    await expect(loadConfig(dir)).rejects.toThrow('"scanners.secrets.enabled" must be a boolean');
  });

  it('throws when policy is not a mapping', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'policy: strict\n' });
    await expect(loadConfig(dir)).rejects.toThrow('"policy" must be a mapping');
  });

  it('throws on an unknown severity in policy.failOn, listing the valid ones', async () => {
    const dir = await tempDirWith({ 'sentinel.yml': 'policy:\n  failOn: [critical, urgent]\n' });
    await expect(loadConfig(dir)).rejects.toThrow(
      /"policy.failOn" contains unknown severity "urgent" \(expected one of critical, high, medium, low, info\)/,
    );
  });
});

/** Escape a path for embedding in a RegExp. */
function escape(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
