import { readFile as fsReadFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { noopLogger } from '@dl-sentinel/core';
import type { FileRef, Finding, ScanLogger, ScannerPlugin } from '@dl-sentinel/core';

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/', import.meta.url));
// The two shared, READ-ONLY fixtures owned by feature/sentinel-testing live at the repo root.
const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

export function fixtureAbsPath(relPath: string): string {
  return path.join(FIXTURES_DIR, relPath);
}

async function toFileRef(absPath: string, relPath: string): Promise<FileRef> {
  const st = await stat(absPath);
  return { absPath, relPath, size: st.size };
}

/** A FileRef for a fixture local to this package (scanners/api/test/fixtures/<relPath>). */
export function localFixture(relPath: string): Promise<FileRef> {
  return toFileRef(fixtureAbsPath(relPath), relPath);
}

/** A FileRef for a shared cross-package fixture (repo-root tests/fixtures/<relPath>), read-only. */
export function sharedFixture(relPath: string): Promise<FileRef> {
  return toFileRef(path.join(REPO_ROOT, relPath), relPath);
}

export interface CapturingLogger {
  logger: ScanLogger;
  warnings: string[];
}

export function createCapturingLogger(): CapturingLogger {
  const warnings: string[] = [];
  return {
    warnings,
    logger: {
      debug: () => {},
      info: () => {},
      warn: (message: string) => warnings.push(message),
      error: () => {},
    },
  };
}

export interface ScanFixturesOptions {
  signal?: AbortSignal;
  logger?: ScanLogger;
  config?: Record<string, unknown>;
}

export async function scanFileRefs(
  scanner: ScannerPlugin,
  files: FileRef[],
  opts: ScanFixturesOptions = {},
): Promise<Finding[]> {
  return scanner.scan({
    rootDir: FIXTURES_DIR,
    files,
    config: opts.config ?? {},
    signal: opts.signal ?? new AbortController().signal,
    logger: opts.logger ?? noopLogger,
    readFile: (ref) => fsReadFile(ref.absPath, 'utf8'),
  });
}

/** Scan one or more local fixtures (relative to scanners/api/test/fixtures/) in one call. */
export async function scanLocalFixtures(
  scanner: ScannerPlugin,
  relPaths: string[],
  opts: ScanFixturesOptions = {},
): Promise<Finding[]> {
  const files = await Promise.all(relPaths.map((p) => localFixture(p)));
  return scanFileRefs(scanner, files, opts);
}

/** Scan a single local fixture (relative to scanners/api/test/fixtures/). */
export async function scanLocalFixture(
  scanner: ScannerPlugin,
  relPath: string,
  opts: ScanFixturesOptions = {},
): Promise<Finding[]> {
  return scanLocalFixtures(scanner, [relPath], opts);
}

export function findingsFor(findings: Finding[], ruleId: string): Finding[] {
  return findings.filter((f) => f.ruleId === ruleId);
}

async function walkDir(dir: string, baseDir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walkDir(full, baseDir)));
    } else if (entry.isFile()) {
      files.push(path.relative(baseDir, full));
    }
  }
  return files;
}

/** Every fixture file under scanners/api/test/fixtures/, as posix-style relative paths. */
export async function listAllLocalFixtures(): Promise<string[]> {
  const files = await walkDir(FIXTURES_DIR, FIXTURES_DIR);
  return files.map((f) => f.split(path.sep).join('/')).sort();
}
