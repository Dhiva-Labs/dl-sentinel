import type { ScanLogger } from '@dl-sentinel/core';
import type { DependencyRecord } from '../types.js';

/**
 * Strip a `#` comment that starts outside a quoted string. Good enough for
 * the simple, single-line entries this hand-rolled parser targets — not a
 * general TOML tokenizer.
 */
function stripTomlComment(line: string): string {
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') inQuotes = !inQuotes;
    else if (ch === '#' && !inQuotes) return line.slice(0, i);
  }
  return line;
}

const DEP_SECTIONS = new Set(['dependencies', 'dev-dependencies', 'build-dependencies']);

/** `"1.2.3"` or `{ version = "1.2.3", ... }`. Path/git deps have no registry version to check. */
function extractCargoVersion(value: string): string | null {
  const strMatch = /^"([^"]*)"$/.exec(value);
  if (strMatch) return strMatch[1] !== undefined && strMatch[1].length > 0 ? strMatch[1] : null;

  const tableMatch = /^\{(.*)\}$/.exec(value);
  if (tableMatch && tableMatch[1] !== undefined) {
    const inner = tableMatch[1];
    if (/\bpath\s*=/.test(inner) || /\bgit\s*=/.test(inner)) return null;
    const versionMatch = /\bversion\s*=\s*"([^"]*)"/.exec(inner);
    if (versionMatch && versionMatch[1] !== undefined && versionMatch[1].length > 0) {
      return versionMatch[1];
    }
    return null;
  }
  return null;
}

/**
 * Parse `Cargo.toml`'s `[dependencies]`, `[dev-dependencies]`, and
 * `[build-dependencies]` tables. Deliberately not a general TOML parser: it
 * recognizes exactly the two documented shapes (a plain string version, or
 * an inline `{ version = "...", ... }` table) and silently skips anything
 * else (arrays, multi-line strings, target-specific tables like
 * `[target.'cfg(unix)'.dependencies]`) — under-detection is safe here,
 * fabricating a version is not. Cargo's default (bare, unprefixed) version
 * requirement is a caret range, unlike npm's exact-by-default — record
 * `versionKind: 'range'` and let the comparator apply Cargo/caret semantics.
 */
export function parseCargoToml(
  relPath: string,
  content: string,
  logger: ScanLogger,
): DependencyRecord[] {
  const records: DependencyRecord[] = [];
  const lines = content.split(/\r\n|\r|\n/);
  let currentSection: string | null = null;

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const line = stripTomlComment(lines[i] ?? '').trim();
    if (line.length === 0) continue;

    const headerMatch = /^\[([^\]]+)\]$/.exec(line);
    if (headerMatch && headerMatch[1] !== undefined) {
      currentSection = headerMatch[1].trim();
      continue;
    }
    if (currentSection === null || !DEP_SECTIONS.has(currentSection)) continue;

    const entryMatch = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line);
    if (!entryMatch || entryMatch[1] === undefined || entryMatch[2] === undefined) {
      logger.warn(
        `dependencies: ${relPath}:${lineNo} in [${currentSection}] is not a recognized entry, skipping`,
      );
      continue;
    }
    const name = entryMatch[1];
    const version = extractCargoVersion(entryMatch[2].trim());
    if (version === null) continue; // path/git dependency, or unparsed table shape

    records.push({
      ecosystem: 'cargo',
      name,
      version,
      versionKind: 'range',
      direct: true,
      sourceFile: relPath,
      line: lineNo,
    });
  }

  return records;
}

/**
 * Parse `Cargo.lock`'s `[[package]]` blocks for name/version. This is the
 * "simple hand-rolled parser for exactly this shape" the format calls for —
 * no TOML library. `direct` starts `false` here; scan.ts promotes entries
 * whose name is also declared in a sibling Cargo.toml in the same scan
 * (Cargo.lock alone has no reliable direct/transitive marker in the shape
 * this scanner targets).
 */
export function parseCargoLock(
  relPath: string,
  content: string,
  logger: ScanLogger,
): DependencyRecord[] {
  const records: DependencyRecord[] = [];
  const lines = content.split(/\r\n|\r|\n/);

  let inPackage = false;
  let name: string | null = null;
  let version: string | null = null;
  let versionLine = 0;

  const flush = (): void => {
    if (inPackage && name !== null && version !== null) {
      records.push({
        ecosystem: 'cargo',
        name,
        version,
        versionKind: 'exact',
        direct: false,
        sourceFile: relPath,
        line: versionLine,
      });
    } else if (inPackage && name !== null && version === null) {
      logger.warn(
        `dependencies: ${relPath} has a [[package]] entry for "${name}" with no version, skipping it`,
      );
    }
  };

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const line = stripTomlComment(lines[i] ?? '').trim();
    if (line.length === 0) continue;

    if (line === '[[package]]') {
      flush();
      inPackage = true;
      name = null;
      version = null;
      versionLine = 0;
      continue;
    }
    if (/^\[[^\]]+\]$/.test(line)) {
      // A different table (e.g. [metadata]) ends the current package block.
      flush();
      inPackage = false;
      name = null;
      version = null;
      continue;
    }
    if (!inPackage) continue;

    const nameMatch = /^name\s*=\s*"([^"]*)"$/.exec(line);
    if (nameMatch && nameMatch[1] !== undefined) {
      name = nameMatch[1];
      continue;
    }
    const versionMatch = /^version\s*=\s*"([^"]*)"$/.exec(line);
    if (versionMatch && versionMatch[1] !== undefined) {
      version = versionMatch[1];
      versionLine = lineNo;
      continue;
    }
    // source/checksum/dependencies fields: not needed for name/version.
  }
  flush();

  return records;
}
