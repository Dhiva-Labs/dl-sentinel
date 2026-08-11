/**
 * Minimal, read-only file discovery for `sentinel graph`.
 *
 * The engine's own `discoverFiles` (packages/engine/src/discovery.ts) isn't
 * part of `@dl-sentinel/engine`'s public API (see docs/architecture.md
 * §engine) and `sentinel graph` has no reason to load a `sentinel.yml` or
 * run the full scan pipeline — it just needs the infra-shaped files under a
 * directory. So this mirrors the engine's documented discovery discipline
 * (include/exclude globs, never follow symlinks, prune excluded
 * directories, stable sorted order) at a scale appropriate for the small
 * set of text config files `buildInfraGraph` consumes, using the same
 * building blocks (`@dl-sentinel/core`'s `createMatcher` and
 * `defaultConfig().exclude`) and the infra scanner's own declared
 * `supportedFiles` globs as the include list — never a re-declared copy of
 * them.
 */
import { lstat, readdir } from 'node:fs/promises';
import path from 'node:path';
import type { Dirent } from 'node:fs';
import { createMatcher, defaultConfig, type PathMatcher } from '@dl-sentinel/core';
import infraScanner from '@dl-sentinel/scanner-infra';

export interface DiscoveredFile {
  absPath: string;
  relPath: string;
}

/** Codepoint ordering: locale-independent, matching the engine's own discovery order. */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

async function classify(entry: Dirent, absPath: string): Promise<'file' | 'directory' | 'other'> {
  if (entry.isSymbolicLink()) return 'other'; // never followed
  if (entry.isDirectory()) return 'directory';
  if (entry.isFile()) return 'file';
  try {
    const stats = await lstat(absPath);
    if (stats.isSymbolicLink()) return 'other';
    if (stats.isDirectory()) return 'directory';
    if (stats.isFile()) return 'file';
  } catch {
    return 'other';
  }
  return 'other';
}

async function walk(
  absDir: string,
  relDir: string,
  isIncluded: PathMatcher,
  isExcluded: PathMatcher,
  out: DiscoveredFile[],
): Promise<void> {
  let entries: Dirent[];
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch {
    return; // unreadable directory: skip quietly, this is a best-effort walk
  }
  entries.sort((a, b) => compareStrings(a.name, b.name));

  for (const entry of entries) {
    const relPath = relDir === '' ? entry.name : `${relDir}/${entry.name}`;
    const absPath = path.join(absDir, entry.name);
    const kind = await classify(entry, absPath);

    if (kind === 'directory') {
      if (isExcluded(`${relPath}/`) || isExcluded(relPath)) continue;
      await walk(absPath, relPath, isIncluded, isExcluded, out);
      continue;
    }
    if (kind !== 'file') continue;
    if (isExcluded(relPath) || !isIncluded(relPath)) continue;
    out.push({ absPath, relPath });
  }
}

/**
 * Discover files under `rootDir` that the infra scanner's `supportedFiles`
 * globs match, honoring the default excludes (`node_modules`, `.git`,
 * `dist`, ...). Returned in stable sorted order by `relPath`.
 */
export async function discoverInfraFiles(rootDir: string): Promise<DiscoveredFile[]> {
  const isIncluded = createMatcher(infraScanner.supportedFiles);
  const isExcluded = createMatcher(defaultConfig().exclude);
  const out: DiscoveredFile[] = [];
  await walk(rootDir, '', isIncluded, isExcluded, out);
  out.sort((a, b) => compareStrings(a.relPath, b.relPath));
  return out;
}
