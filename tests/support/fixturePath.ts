import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

/** Absolute path to tests/fixtures/, resolved relative to this file. */
const FIXTURES_ROOT = fileURLToPath(new URL('../fixtures/', import.meta.url));

/**
 * Resolve an absolute path under tests/fixtures/, e.g.
 * `fixturePath('vulnerable-app', '.env')`.
 */
export function fixturePath(...segments: string[]): string {
  return join(FIXTURES_ROOT, ...segments);
}
