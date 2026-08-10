import { readFile } from 'node:fs/promises';
import { statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FileRef, ScanContext, ScanLogger } from '@dl-sentinel/core';
import { noopLogger } from '@dl-sentinel/core';

const FIXTURES_ROOT = fileURLToPath(new URL('./fixtures/', import.meta.url));

/** Resolve an absolute path under scanners/dependencies/test/fixtures/. */
export function fixturePath(...segments: string[]): string {
  return join(FIXTURES_ROOT, ...segments);
}

/** Build a FileRef for one fixture file, computing its real size on disk. */
export function fileRef(absPath: string, relPath: string): FileRef {
  return { absPath, relPath, size: statSync(absPath).size };
}

export interface RecordingLogger extends ScanLogger {
  readonly warnings: string[];
  readonly errors: string[];
}

/** A logger that records warn/error calls instead of discarding them, so
 * tests can assert a parser warned about a malformed input. */
export function createRecordingLogger(): RecordingLogger {
  const warnings: string[] = [];
  const errors: string[] = [];
  return {
    warnings,
    errors,
    debug: () => {},
    info: () => {},
    warn: (message: string) => {
      warnings.push(message);
    },
    error: (message: string) => {
      errors.push(message);
    },
  };
}

export interface ContextOptions {
  config?: Record<string, unknown>;
  logger?: ScanLogger;
  signal?: AbortSignal;
}

/** Build a real ScanContext for driving scan() directly, per
 * docs/scanner-interface.md's own testing pattern. */
export function contextFor(
  rootDir: string,
  files: readonly FileRef[],
  options: ContextOptions = {},
): ScanContext {
  const controller = new AbortController();
  return {
    rootDir,
    files,
    config: options.config ?? {},
    signal: options.signal ?? controller.signal,
    logger: options.logger ?? noopLogger,
    readFile: (ref) => readFile(ref.absPath, 'utf8'),
  };
}
