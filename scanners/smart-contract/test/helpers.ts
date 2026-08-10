/** Shared test helpers: fixture loading and ScanContext construction. Not a test file itself. */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { FileRef, ScanContext } from '@dl-sentinel/core';
import { noopLogger } from '@dl-sentinel/core';
import type { ParsedSolidityFile } from '../src/model.js';
import { parseSolidityFile } from '../src/parser.js';

export function fixturePath(rel: string): string {
  return fileURLToPath(new URL(`./fixtures/${rel}`, import.meta.url));
}

export function readFixture(rel: string): string {
  return readFileSync(fixturePath(rel), 'utf8');
}

/** Parse a fixture file by its path relative to test/fixtures/. */
export function parseFixture(rel: string): ParsedSolidityFile {
  return parseSolidityFile(rel, readFixture(rel));
}

export function fileRefFor(rel: string): FileRef {
  const absPath = fixturePath(rel);
  const size = Buffer.byteLength(readFileSync(absPath, 'utf8'), 'utf8');
  return { absPath, relPath: rel, size };
}

export function contextFor(
  files: readonly FileRef[],
  overrides: Partial<ScanContext> = {},
): ScanContext {
  return {
    rootDir: fixturePath(''),
    files,
    config: {},
    signal: new AbortController().signal,
    logger: noopLogger,
    readFile: (ref) => Promise.resolve(readFileSync(ref.absPath, 'utf8')),
    ...overrides,
  };
}
