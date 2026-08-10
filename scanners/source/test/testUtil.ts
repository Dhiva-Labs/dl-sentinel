import { statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import type { FileRef } from '@dl-sentinel/core';

const FIXTURES_ROOT = fileURLToPath(new URL('./fixtures/', import.meta.url));

/** Absolute path to this scanner's own test/fixtures/, or a path under it. */
export function localFixturePath(...segments: string[]): string {
  return join(FIXTURES_ROOT, ...segments);
}

/** Build a FileRef for a fixture under scanners/source/test/fixtures/. */
export function fileRefFor(relFromFixtures: string): FileRef {
  const absPath = localFixturePath(relFromFixtures);
  return {
    absPath,
    relPath: relFromFixtures.split('\\').join('/'),
    size: statSync(absPath).size,
  };
}
