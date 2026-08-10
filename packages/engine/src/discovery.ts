import { lstat, open, readdir } from 'node:fs/promises';
import path from 'node:path';
import type { Dirent } from 'node:fs';
import type { FileRef, ScanLogger, SentinelConfig } from '@dl-sentinel/core';
import { createMatcher } from '@dl-sentinel/core';
import { errorMessage, throwIfAborted } from './errors.js';

/** Bytes inspected when deciding whether a file is binary. */
export const BINARY_SNIFF_BYTES = 8 * 1024;

export interface DiscoveryOptions {
  /** Absolute path of the scan root. */
  rootDir: string;
  config: SentinelConfig;
  logger: ScanLogger;
  signal?: AbortSignal;
}

type EntryKind = 'file' | 'directory' | 'symlink' | 'other';

/**
 * Walk the target directory and return the files scanners may see.
 *
 * Applied in order, cheapest first: `include` globs, `exclude` globs,
 * `maxFileSizeBytes`, then a NUL-byte sniff of the first
 * {@link BINARY_SNIFF_BYTES}. Symlinked files and directories are never
 * followed. Excluded directories are pruned instead of descended into, so a
 * `node_modules` tree costs one `readdir` entry rather than a full walk.
 * Unreadable entries are skipped with a warning rather than failing the scan.
 *
 * The result is sorted by repo-relative path, so the same tree always yields
 * the same list in the same order.
 */
export async function discoverFiles(options: DiscoveryOptions): Promise<FileRef[]> {
  const { rootDir, config, logger, signal } = options;
  const isIncluded = createMatcher(config.include);
  const isExcluded = createMatcher(config.exclude);
  const maxBytes = config.maxFileSizeBytes;
  // Directory pruning assumes nothing below an excluded directory can be
  // re-included. A negated exclude pattern ("!keep/**") breaks that
  // assumption, so pruning is disabled when one is present.
  const canPrune = !config.exclude.some((pattern) => pattern.startsWith('!'));

  const files: FileRef[] = [];
  let skippedOversize = 0;
  let skippedBinary = 0;
  let skippedSymlinks = 0;

  const walk = async (absDir: string, relDir: string): Promise<void> => {
    throwIfAborted(signal);
    let entries: Dirent[];
    try {
      entries = await readdir(absDir, { withFileTypes: true });
    } catch (error) {
      // An unreadable subdirectory is skipped, but an unreadable root would
      // silently produce an empty "clean" report, so it fails the scan.
      if (relDir === '') {
        throw new Error(`Cannot read scan target ${absDir}: ${errorMessage(error)}`, {
          cause: error,
        });
      }
      logger.warn(`Skipping unreadable directory ${relDir}: ${errorMessage(error)}`);
      return;
    }
    entries.sort((a, b) => compareStrings(a.name, b.name));

    for (const entry of entries) {
      throwIfAborted(signal);
      const relPath = relDir === '' ? entry.name : `${relDir}/${entry.name}`;
      const absPath = path.join(absDir, entry.name);
      const kind = await classify(entry, absPath);

      if (kind === 'symlink') {
        skippedSymlinks += 1;
        logger.debug(`Skipping symlink ${relPath}`);
        continue;
      }
      if (kind === 'directory') {
        if (canPrune && (isExcluded(`${relPath}/`) || isExcluded(relPath))) {
          logger.debug(`Pruning excluded directory ${relPath}`);
          continue;
        }
        await walk(absPath, relPath);
        continue;
      }
      if (kind !== 'file') continue;
      if (!isIncluded(relPath) || isExcluded(relPath)) continue;

      let size: number;
      try {
        const stats = await lstat(absPath);
        if (!stats.isFile()) continue;
        size = stats.size;
      } catch (error) {
        logger.warn(`Skipping unreadable file ${relPath}: ${errorMessage(error)}`);
        continue;
      }

      if (size > maxBytes) {
        skippedOversize += 1;
        logger.debug(`Skipping ${relPath}: ${size} bytes exceeds maxFileSizeBytes (${maxBytes})`);
        continue;
      }

      let binary: boolean;
      try {
        binary = await isBinaryFile(absPath, size);
      } catch (error) {
        logger.warn(`Skipping unreadable file ${relPath}: ${errorMessage(error)}`);
        continue;
      }
      if (binary) {
        skippedBinary += 1;
        logger.debug(`Skipping binary file ${relPath}`);
        continue;
      }

      files.push({ absPath, relPath, size });
    }
  };

  await walk(rootDir, '');
  files.sort((a, b) => compareStrings(a.relPath, b.relPath));
  logger.debug(
    `Discovered ${files.length} files (skipped ${skippedBinary} binary, ${skippedOversize} oversize, ${skippedSymlinks} symlinks)`,
  );
  return files;
}

/**
 * Classify a directory entry without following symlinks. Some filesystems
 * report an unknown dirent type, in which case we fall back to `lstat`.
 */
async function classify(entry: Dirent, absPath: string): Promise<EntryKind> {
  if (entry.isSymbolicLink()) return 'symlink';
  if (entry.isDirectory()) return 'directory';
  if (entry.isFile()) return 'file';
  try {
    const stats = await lstat(absPath);
    if (stats.isSymbolicLink()) return 'symlink';
    if (stats.isDirectory()) return 'directory';
    if (stats.isFile()) return 'file';
  } catch {
    return 'other';
  }
  return 'other';
}

/** A file is treated as binary when a NUL byte appears in its first block. */
async function isBinaryFile(absPath: string, size: number): Promise<boolean> {
  if (size === 0) return false;
  const handle = await open(absPath, 'r');
  try {
    const buffer = Buffer.alloc(Math.min(size, BINARY_SNIFF_BYTES));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).includes(0);
  } finally {
    await handle.close();
  }
}

/** Codepoint ordering: locale-independent, so file order is stable everywhere. */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
