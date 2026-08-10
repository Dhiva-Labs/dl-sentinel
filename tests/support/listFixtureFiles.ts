import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import type { FileRef } from '@dl-sentinel/core';

function toPosix(p: string): string {
  return p.split('\\').join('/');
}

/**
 * Recursively list every regular file under `dir`, honoring nothing: no
 * include/exclude globs, no size cap, no binary sniffing. This is the "raw
 * truth" of what is on disk, so tests can apply `createMatcher` (or other
 * engine-documented filtering) themselves and check the result against it.
 *
 * Symlinks are skipped (never followed), matching the engine's documented
 * discovery guarantee — but note no committed fixture contains one; runtime
 * symlink fixtures must be created under os.tmpdir() in the test itself.
 */
export function listFixtureFiles(dir: string): FileRef[] {
  const out: FileRef[] = [];

  function walk(current: string): void {
    const entries = readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const absPath = join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        walk(absPath);
        continue;
      }
      if (!entry.isFile()) continue;
      out.push({
        absPath,
        relPath: toPosix(relative(dir, absPath)),
        size: statSync(absPath).size,
      });
    }
  }

  walk(dir);
  return out.sort((a, b) => a.relPath.localeCompare(b.relPath));
}
