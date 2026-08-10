import { readFileSync, readdirSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FileRef, Finding, ScanContext, ScanLogger } from '@dl-sentinel/core';
import { noopLogger } from '@dl-sentinel/core';
import secretsScanner from '@dl-sentinel/scanner-secrets';

/** This package's own fixtures. */
export const FIXTURE_ROOT = fileURLToPath(new URL('./fixtures/', import.meta.url));

/** The shared, cross-package fixture tree (read-only, owned by tests/). */
export const SHARED_FIXTURE_ROOT = fileURLToPath(
  new URL('../../../tests/fixtures/', import.meta.url),
);

export function fileRef(rootDir: string, relPath: string): FileRef {
  const absPath = join(rootDir, relPath);
  return { absPath, relPath, size: statSync(absPath).size };
}

/**
 * Build a ScanContext directly, the way docs/scanner-interface.md documents —
 * no engine, no shared test helpers, so this package stays self-contained.
 */
export function makeContext(
  rootDir: string,
  files: readonly FileRef[],
  config: Record<string, unknown> = {},
  logger: ScanLogger = noopLogger,
  signal: AbortSignal = new AbortController().signal,
): ScanContext {
  return {
    rootDir,
    files,
    config,
    signal,
    logger,
    readFile: (ref: FileRef) => readFile(ref.absPath, 'utf8'),
  };
}

/** Scan named fixture files from this package's fixture tree. */
export function scanFixtures(
  relPaths: readonly string[],
  config: Record<string, unknown> = {},
  logger: ScanLogger = noopLogger,
): Promise<Finding[]> {
  const files = relPaths.map((relPath) => fileRef(FIXTURE_ROOT, relPath));
  return secretsScanner.scan(makeContext(FIXTURE_ROOT, files, config, logger));
}

/**
 * List every readable text file under `dir`, mirroring the two discovery
 * guarantees a scanner may assume: symlinks are never followed and binary
 * files never arrive (NUL byte in the first 8 KiB).
 */
export function listTextFiles(dir: string): FileRef[] {
  const out: FileRef[] = [];

  function walk(current: string): void {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absPath = join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        walk(absPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const buffer = readFileSync(absPath);
      if (buffer.subarray(0, 8192).includes(0)) continue;
      out.push({
        absPath,
        relPath: relative(dir, absPath).split('\\').join('/'),
        size: buffer.length,
      });
    }
  }

  walk(dir);
  return out.sort((a, b) => a.relPath.localeCompare(b.relPath));
}

/** A logger that records what it was told, for assertions about log safety. */
export function recordingLogger(): { logger: ScanLogger; messages: string[] } {
  const messages: string[] = [];
  const record = (level: string) => (message: string) => {
    messages.push(`${level}: ${message}`);
  };
  return {
    messages,
    logger: {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    },
  };
}
