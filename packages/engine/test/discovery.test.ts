import { chmod, mkdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { SentinelConfig } from '@dl-sentinel/core';
import { defaultConfig, noopLogger } from '@dl-sentinel/core';
import { BINARY_SNIFF_BYTES, discoverFiles } from '../src/discovery.js';
import { FIXTURE_TREE, makeTempDir, recordingLogger } from './helpers.js';

/** Every file in the fixture tree that a default scan must see, in order. */
const DEFAULT_FIXTURE_FILES = [
  '.hidden.txt',
  'README.md',
  'config/sample.env',
  'data/notes.txt',
  'docs/guide.md',
  'src/app.ts',
  'src/nested/deep/deep.ts',
  'src/util.ts',
  'vendor/legacy.js',
];

function configWith(overrides: Partial<SentinelConfig> = {}): SentinelConfig {
  return { ...defaultConfig(), ...overrides };
}

async function discover(rootDir: string, overrides: Partial<SentinelConfig> = {}) {
  return discoverFiles({ rootDir, config: configWith(overrides), logger: noopLogger });
}

const cleanups: (() => Promise<void>)[] = [];

async function tempTree(
  files: Record<string, string | Buffer>,
): Promise<{ dir: string; write: (rel: string, content: string | Buffer) => Promise<void> }> {
  const { dir, cleanup } = await makeTempDir();
  cleanups.push(cleanup);
  const write = async (rel: string, content: string | Buffer): Promise<void> => {
    const absPath = path.join(dir, rel);
    await mkdir(path.dirname(absPath), { recursive: true });
    await writeFile(absPath, content);
  };
  for (const [rel, content] of Object.entries(files)) {
    await write(rel, content);
  }
  return { dir, write };
}

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup !== undefined) await cleanup();
  }
});

describe('discoverFiles: fixture tree', () => {
  it('discovers every text file, including dotfiles, with default config', async () => {
    const files = await discover(FIXTURE_TREE);
    expect(files.map((file) => file.relPath)).toEqual(DEFAULT_FIXTURE_FILES);
  });

  it('excludes default-excluded directories such as build/', async () => {
    const files = await discover(FIXTURE_TREE);
    expect(files.map((file) => file.relPath)).not.toContain('build/generated.txt');
  });

  it('returns absolute paths, posix-relative paths and real sizes', async () => {
    const files = await discover(FIXTURE_TREE);
    const app = files.find((file) => file.relPath === 'src/app.ts');
    expect(app).toBeDefined();
    expect(app?.absPath).toBe(path.join(FIXTURE_TREE, 'src', 'app.ts'));
    expect(app?.relPath).not.toContain('\\');
    expect(app?.size).toBeGreaterThan(0);
  });

  it('is deterministic across runs', async () => {
    const first = await discover(FIXTURE_TREE);
    const second = await discover(FIXTURE_TREE);
    expect(second).toEqual(first);
  });

  it('applies include globs before exclude globs', async () => {
    const files = await discover(FIXTURE_TREE, { include: ['**/*.ts'] });
    expect(files.map((file) => file.relPath)).toEqual([
      'src/app.ts',
      'src/nested/deep/deep.ts',
      'src/util.ts',
    ]);
  });

  it('honors an exclude that overrides a matching include', async () => {
    const files = await discover(FIXTURE_TREE, {
      include: ['**/*.ts'],
      exclude: ['**/nested/**'],
    });
    expect(files.map((file) => file.relPath)).toEqual(['src/app.ts', 'src/util.ts']);
  });

  it('excludes a whole nested directory', async () => {
    const files = await discover(FIXTURE_TREE, { exclude: ['**/src/**'] });
    const paths = files.map((file) => file.relPath);
    expect(paths).not.toContain('src/app.ts');
    expect(paths).not.toContain('src/nested/deep/deep.ts');
    expect(paths).toContain('docs/guide.md');
  });

  it('excludes single files by exact path', async () => {
    const files = await discover(FIXTURE_TREE, { exclude: ['vendor/legacy.js'] });
    expect(files.map((file) => file.relPath)).not.toContain('vendor/legacy.js');
    expect(files.map((file) => file.relPath)).toContain('src/app.ts');
  });

  it('discovers nothing when include matches nothing', async () => {
    const files = await discover(FIXTURE_TREE, { include: ['**/*.rs'] });
    expect(files).toEqual([]);
  });
});

describe('discoverFiles: pruning', () => {
  it('does not descend into excluded directories', async () => {
    const { dir } = await tempTree({
      'src/app.ts': 'export const a = 1;\n',
      'node_modules/left-pad/index.js': 'module.exports = 1;\n',
      'node_modules/left-pad/nested/deep.js': 'module.exports = 2;\n',
    });
    const logger = recordingLogger();

    const files = await discoverFiles({ rootDir: dir, config: configWith(), logger });

    expect(files.map((file) => file.relPath)).toEqual(['src/app.ts']);
    expect(logger.of('debug')).toContain('Pruning excluded directory node_modules');
  });

  it('keeps walking excluded directories when a negated exclude could re-include files', async () => {
    const { dir } = await tempTree({
      'vendor/lib.js': 'module.exports = 1;\n',
      'vendor/keep.js': 'module.exports = 2;\n',
    });

    const files = await discoverFiles({
      rootDir: dir,
      config: configWith({ exclude: ['**/vendor/**', '!**/vendor/keep.js'] }),
      logger: noopLogger,
    });

    expect(files.map((file) => file.relPath)).toEqual(['vendor/keep.js']);
  });
});

describe('discoverFiles: size and binary limits', () => {
  it('skips files larger than maxFileSizeBytes and keeps files exactly at the cap', async () => {
    const { dir } = await tempTree({
      'at-cap.txt': 'x'.repeat(64),
      'over-cap.txt': 'x'.repeat(65),
    });

    const files = await discoverFiles({
      rootDir: dir,
      config: configWith({ maxFileSizeBytes: 64 }),
      logger: noopLogger,
    });

    expect(files.map((file) => file.relPath)).toEqual(['at-cap.txt']);
  });

  it('skips binaries detected by a NUL byte in the first block', async () => {
    const { dir } = await tempTree({
      'image.bin': Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x1a, 0x0a]),
      'notes.txt': 'plain text\n',
    });

    const files = await discoverFiles({ rootDir: dir, config: configWith(), logger: noopLogger });

    expect(files.map((file) => file.relPath)).toEqual(['notes.txt']);
  });

  it('only sniffs the first 8 KiB, so a later NUL byte does not disqualify a file', async () => {
    const { dir } = await tempTree({
      'late-nul.txt': Buffer.concat([
        Buffer.alloc(BINARY_SNIFF_BYTES, 0x61),
        Buffer.from([0x00]),
        Buffer.from('tail'),
      ]),
    });

    const files = await discoverFiles({ rootDir: dir, config: configWith(), logger: noopLogger });

    expect(files.map((file) => file.relPath)).toEqual(['late-nul.txt']);
  });

  it('treats empty files as text', async () => {
    const { dir } = await tempTree({ 'empty.txt': '' });

    const files = await discoverFiles({ rootDir: dir, config: configWith(), logger: noopLogger });

    expect(files.map((file) => file.relPath)).toEqual(['empty.txt']);
    expect(files[0]?.size).toBe(0);
  });
});

describe('discoverFiles: symlinks', () => {
  it('never follows symlinked files or directories', async () => {
    const { dir } = await tempTree({
      'real.txt': 'real file\n',
      'realdir/inner.txt': 'inside a real directory\n',
      'outside/secret.txt': 'target of the directory symlink\n',
    });
    await symlink(path.join(dir, 'real.txt'), path.join(dir, 'link.txt'));
    await symlink(path.join(dir, 'outside'), path.join(dir, 'linkdir'));
    await symlink(path.join(dir, 'does-not-exist.txt'), path.join(dir, 'broken.txt'));

    const logger = recordingLogger();
    const files = await discoverFiles({ rootDir: dir, config: configWith(), logger });
    const paths = files.map((file) => file.relPath);

    expect(paths).toEqual(['outside/secret.txt', 'real.txt', 'realdir/inner.txt']);
    expect(paths).not.toContain('link.txt');
    expect(paths).not.toContain('linkdir/secret.txt');
    expect(paths).not.toContain('broken.txt');
    expect(logger.of('debug')).toContain('Skipping symlink link.txt');
    expect(logger.of('debug')).toContain('Skipping symlink linkdir');
    expect(logger.of('warn')).toEqual([]);
  });
});

describe('discoverFiles: unreadable paths', () => {
  it('fails rather than reporting an empty tree when the root cannot be read', async () => {
    const missing = path.join(FIXTURE_TREE, 'no-such-directory');

    await expect(discover(missing)).rejects.toThrow(`Cannot read scan target ${missing}`);
  });

  it.skipIf(process.getuid?.() === 0)(
    'warns and continues when a subdirectory cannot be read',
    async () => {
      const { dir } = await tempTree({
        'readable/app.ts': 'export const a = 1;\n',
        'locked/secret.ts': 'export const b = 2;\n',
      });
      await chmod(path.join(dir, 'locked'), 0o000);
      const logger = recordingLogger();

      try {
        const files = await discoverFiles({ rootDir: dir, config: configWith(), logger });

        expect(files.map((file) => file.relPath)).toEqual(['readable/app.ts']);
        expect(logger.of('warn')[0]).toContain('Skipping unreadable directory locked');
      } finally {
        await chmod(path.join(dir, 'locked'), 0o700);
      }
    },
  );
});

describe('discoverFiles: cancellation', () => {
  it('throws an AbortError when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(
      discoverFiles({
        rootDir: FIXTURE_TREE,
        config: configWith(),
        logger: noopLogger,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });
});
