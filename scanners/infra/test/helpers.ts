import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Finding, FileRef } from '@dl-sentinel/core';
import { createMatcher } from '@dl-sentinel/core';
import {
  fixturePath as sharedFixturePath,
  listFixtureFiles,
  makeScanContext,
} from '../../../tests/support/index.js';
import { infraScanner } from '../src/index.js';

/** Absolute path to scanners/infra/test/fixtures/, resolved relative to this file. */
const FIXTURES_ROOT = fileURLToPath(new URL('./fixtures/', import.meta.url));

export function fixturePath(...segments: string[]): string {
  return join(FIXTURES_ROOT, ...segments);
}

/** Build a FileRef for a scanner-local fixture, given its path relative to fixtures/. */
export function fileRef(relPath: string): FileRef {
  const absPath = fixturePath(relPath);
  const size = readFileSync(absPath, 'utf8').length;
  return { absPath, relPath, size };
}

/** Run the real plugin end to end (classify + parse + rules) over one fixture file. */
export async function scanFixture(relPath: string): Promise<Finding[]> {
  const context = makeScanContext(FIXTURES_ROOT, [fileRef(relPath)]);
  return infraScanner.scan(context);
}

/** Run the real plugin over several fixture files at once (for cross-file isolation tests). */
export async function scanFixtures(relPaths: string[]): Promise<Finding[]> {
  const context = makeScanContext(
    FIXTURES_ROOT,
    relPaths.map((p) => fileRef(p)),
  );
  return infraScanner.scan(context);
}

export function byRule(findings: readonly Finding[], ruleId: string): Finding[] {
  return findings.filter((f) => f.ruleId === ruleId);
}

/** 1-based line number of the first physical line of `text` containing `needle`. */
export function lineOf(text: string, needle: string): number {
  const lines = text.split(/\r\n|\n/);
  const idx = lines.findIndex((l) => l.includes(needle));
  if (idx === -1) throw new Error(`fixture line not found for needle: ${needle}`);
  return idx + 1;
}

/** 1-based line number of the LAST physical line of `text` containing `needle`. */
export function lastLineOf(text: string, needle: string): number {
  const lines = text.split(/\r\n|\n/);
  const idx = lines.reduce((last, l, i) => (l.includes(needle) ? i : last), -1);
  if (idx === -1) throw new Error(`fixture line not found for needle: ${needle}`);
  return idx + 1;
}

export function readFixture(relPath: string): string {
  return readFileSync(fixturePath(relPath), 'utf8');
}

/**
 * Scan the shared cross-cutting fixture app (`vulnerable-app` or
 * `clean-app` under tests/fixtures/, READ-ONLY) exactly as the real engine
 * would: discover every file, then keep only the ones this scanner's own
 * `supportedFiles` globs match, so the test also exercises those glob
 * declarations rather than assuming which files matter.
 */
export async function scanRealFixtureApp(
  appName: 'vulnerable-app' | 'clean-app',
): Promise<Finding[]> {
  const root = sharedFixturePath(appName);
  const all = listFixtureFiles(root);
  const matcher = createMatcher(infraScanner.supportedFiles);
  const files = all.filter((f) => matcher(f.relPath));
  const context = makeScanContext(root, files);
  return infraScanner.scan(context);
}
