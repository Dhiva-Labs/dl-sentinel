import type { ScanLogger } from '@dl-sentinel/core';
import type { DependencyRecord } from '../types.js';
import { escapeRegExp } from '../paths.js';
import { errorMessage } from '../util.js';

function byNameThenVersion(a: DependencyRecord, b: DependencyRecord): number {
  const byName = a.name.localeCompare(b.name);
  if (byName !== 0) return byName;
  return a.version.localeCompare(b.version);
}

/** Best-effort 1-based line lookup for `"name":` inside a named object section. */
function findLineInSection(
  content: string,
  sectionField: string,
  name: string,
): number | undefined {
  const lines = content.split(/\r\n|\r|\n/);
  const sectionHeaderRe = new RegExp(`"${escapeRegExp(sectionField)}"\\s*:\\s*\\{`);
  let start = 0;
  for (let i = 0; i < lines.length; i += 1) {
    if (sectionHeaderRe.test(lines[i] ?? '')) {
      start = i + 1;
      break;
    }
  }
  const keyRe = new RegExp(`"${escapeRegExp(name)}"\\s*:`);
  for (let i = start; i < lines.length; i += 1) {
    if (keyRe.test(lines[i] ?? '')) return i + 1;
  }
  return undefined;
}

const MANIFEST_FIELDS = ['dependencies', 'devDependencies'] as const;

/**
 * Parse a `package.json`'s `dependencies` and `devDependencies` into
 * declared-range records. Both sections are treated as direct dependencies:
 * package.json never describes transitive packages.
 */
export function parsePackageJson(
  relPath: string,
  content: string,
  logger: ScanLogger,
): DependencyRecord[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch (error) {
    logger.warn(`dependencies: ${relPath} is not valid JSON, skipping (${errorMessage(error)})`);
    return [];
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    logger.warn(`dependencies: ${relPath} does not contain a JSON object, skipping`);
    return [];
  }

  const obj = json as Record<string, unknown>;
  const records: DependencyRecord[] = [];

  for (const field of MANIFEST_FIELDS) {
    const section = obj[field];
    if (section === undefined) continue;
    if (typeof section !== 'object' || section === null || Array.isArray(section)) {
      logger.warn(`dependencies: ${relPath} field "${field}" is not an object, skipping it`);
      continue;
    }
    for (const [name, rawVersion] of Object.entries(section as Record<string, unknown>)) {
      if (typeof rawVersion !== 'string' || rawVersion.length === 0) {
        logger.warn(`dependencies: ${relPath} ${field}.${name} has no string version, skipping it`);
        continue;
      }
      records.push({
        ecosystem: 'npm',
        name,
        version: rawVersion,
        versionKind: 'range',
        direct: true,
        sourceFile: relPath,
        line: findLineInSection(content, field, name),
      });
    }
  }

  return records.sort(byNameThenVersion);
}

/** Extract the trailing package name from a `packages` map key like
 * `"node_modules/foo"` or `"node_modules/bar/node_modules/@scope/name"`. */
function packageNameFromKey(key: string): string | null {
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) return null;
  const rest = key.slice(idx + 'node_modules/'.length);
  return rest.length === 0 ? null : rest;
}

/** True if `key` has exactly one `node_modules/` segment (not nested inside another package). */
function isTopLevelKey(key: string): boolean {
  return key.split('node_modules/').length - 1 === 1;
}

function collectDeclaredNames(section: unknown, into: Set<string>): void {
  if (typeof section !== 'object' || section === null || Array.isArray(section)) return;
  for (const name of Object.keys(section as Record<string, unknown>)) into.add(name);
}

/**
 * Parse a `package-lock.json`'s `packages` map (lockfileVersion 2/3 shape)
 * into exact, resolved records — including transitive dependencies nested at
 * any depth. A package is "direct" when it appears at the top level of
 * `node_modules` *and* the root pseudo-entry (`packages[""]`) declares it.
 * Lockfiles without a `packages` map (v1) are out of scope: skipped with a
 * warning rather than guessed at.
 */
export function parsePackageLock(
  relPath: string,
  content: string,
  logger: ScanLogger,
): DependencyRecord[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch (error) {
    logger.warn(`dependencies: ${relPath} is not valid JSON, skipping (${errorMessage(error)})`);
    return [];
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    logger.warn(`dependencies: ${relPath} does not contain a JSON object, skipping`);
    return [];
  }

  const obj = json as Record<string, unknown>;
  const packages = obj.packages;
  if (typeof packages !== 'object' || packages === null || Array.isArray(packages)) {
    logger.warn(
      `dependencies: ${relPath} has no "packages" map (only lockfileVersion 2/3 is supported), skipping`,
    );
    return [];
  }
  const packagesObj = packages as Record<string, unknown>;

  const directNames = new Set<string>();
  const root = packagesObj[''];
  if (typeof root === 'object' && root !== null && !Array.isArray(root)) {
    const rootObj = root as Record<string, unknown>;
    collectDeclaredNames(rootObj.dependencies, directNames);
    collectDeclaredNames(rootObj.devDependencies, directNames);
    collectDeclaredNames(rootObj.optionalDependencies, directNames);
    collectDeclaredNames(rootObj.peerDependencies, directNames);
  }

  const records: DependencyRecord[] = [];
  for (const [key, value] of Object.entries(packagesObj)) {
    if (key === '') continue;
    const name = packageNameFromKey(key);
    if (!name) continue; // root-adjacent metadata keys, nothing to report
    if (typeof value !== 'object' || value === null || Array.isArray(value)) continue;
    const entry = value as Record<string, unknown>;
    const version = entry.version;
    if (typeof version !== 'string' || version.length === 0) continue; // e.g. link:/workspace entries

    const direct = isTopLevelKey(key) && directNames.has(name);
    records.push({
      ecosystem: 'npm',
      name,
      version,
      versionKind: 'exact',
      direct,
      sourceFile: relPath,
      line: findLineForKey(content, key),
    });
  }

  return records.sort(byNameThenVersion);
}

/** `packages` map keys are unique full paths, so an exact-string search is safe. */
function findLineForKey(content: string, key: string): number | undefined {
  const needle = `"${key}"`;
  const lines = content.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if ((lines[i] ?? '').includes(needle)) return i + 1;
  }
  return undefined;
}
