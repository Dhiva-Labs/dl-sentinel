import { readFile } from 'node:fs/promises';
import type { FileRef, ScanContext } from '@dl-sentinel/core';
import { noopLogger } from '@dl-sentinel/core';

/**
 * Build a real ScanContext for driving a scanner's `scan()` directly in
 * tests, without needing the engine. Uses `noopLogger` and a fresh
 * (never-aborted) AbortController, per docs/scanner-interface.md's own
 * testing example.
 */
export function makeScanContext(
  rootDir: string,
  files: readonly FileRef[],
  config: Record<string, unknown> = {},
): ScanContext {
  const controller = new AbortController();
  return {
    rootDir,
    files,
    config,
    signal: controller.signal,
    logger: noopLogger,
    readFile: (ref: FileRef) => readFile(ref.absPath, 'utf8'),
  };
}
