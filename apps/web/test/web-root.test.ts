import { execFileSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { basename, isAbsolute, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

// This test exercises the *built* package (dist/index.js), not the
// '@dl-sentinel/web' -> src/index.ts alias vitest.config.ts sets up for
// other packages' tests. getWebRoot() resolves relative to its own
// compiled file location, and the entire point of this test is to confirm
// that resolution works against the real build output, so it deliberately
// bypasses the alias and imports dist/ directly by path.
const testDir = fileURLToPath(new URL('.', import.meta.url));
const webDir = join(testDir, '..');
const repoRoot = join(webDir, '..', '..');
const distIndex = join(webDir, 'dist', 'index.js');

beforeAll(() => {
  if (!existsSync(distIndex)) {
    // `--force` matters here: it's only valid with `-b` (build mode), not
    // plain `-p`, but it's what makes this reliable — a composite project
    // whose dist/ was removed while its tsconfig.tsbuildinfo cache (see
    // .gitignore) survived would otherwise look "up to date" to a plain
    // `tsc -p` and silently produce no output at all.
    const tscBin = join(repoRoot, 'node_modules', '.bin', 'tsc');
    execFileSync(tscBin, ['-b', webDir, '--force'], { stdio: 'inherit' });
  }
}, 60_000);

describe('getWebRoot', () => {
  it('resolves to an existing absolute directory named "public" containing index.html', async () => {
    expect(existsSync(distIndex)).toBe(true);
    const mod = (await import(pathToFileURL(distIndex).href)) as {
      getWebRoot: () => string;
    };

    const root = mod.getWebRoot();

    expect(isAbsolute(root)).toBe(true);
    expect(basename(root)).toBe('public');
    expect(existsSync(root)).toBe(true);
    expect(statSync(root).isDirectory()).toBe(true);
    expect(existsSync(join(root, 'index.html'))).toBe(true);
    expect(statSync(join(root, 'index.html')).isFile()).toBe(true);
  });

  it('is deterministic across calls', async () => {
    const mod = (await import(pathToFileURL(distIndex).href)) as {
      getWebRoot: () => string;
    };
    expect(mod.getWebRoot()).toBe(mod.getWebRoot());
  });
});
