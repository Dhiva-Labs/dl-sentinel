import type { ScanLogger } from '@dl-sentinel/core';
import type { DependencyRecord } from '../types.js';

function pushRecord(
  records: DependencyRecord[],
  relPath: string,
  line: number,
  name: string,
  version: string,
  indirect: boolean,
): void {
  records.push({
    ecosystem: 'go',
    name,
    version,
    versionKind: 'exact',
    direct: !indirect,
    sourceFile: relPath,
    line,
  });
}

// `<module> <version> [// indirect | // any other comment]`. The trailing
// comment (if any) is captured whole and only checked for "indirect" so a
// benign comment doesn't break the match.
const ENTRY_RE = /^(\S+)\s+(\S+)(?:\s+(.*))?$/;

function isIndirect(trailing: string | undefined): boolean {
  return typeof trailing === 'string' && /\/\/\s*indirect\b/.test(trailing);
}

/**
 * Parse `go.mod`'s `require` directives: both the single-line form
 * (`require module version`) and the parenthesized block form. Every other
 * directive (`module`, `go`, `toolchain`, `exclude`, `replace`, `retract`)
 * is ignored. Versions are recorded as-is ('exact' kind) — go.mod always
 * names one version token per require; there is no range syntax to parse.
 */
export function parseGoMod(
  relPath: string,
  content: string,
  logger: ScanLogger,
): DependencyRecord[] {
  const records: DependencyRecord[] = [];
  const lines = content.split(/\r\n|\r|\n/);
  let inBlock = false;

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const line = (lines[i] ?? '').trim();

    if (!inBlock) {
      if (line.length === 0 || line.startsWith('//')) continue;
      if (/^require\s*\(\s*$/.test(line)) {
        inBlock = true;
        continue;
      }
      const singleMatch = /^require\s+(.+)$/.exec(line);
      if (singleMatch && singleMatch[1] !== undefined) {
        const entry = ENTRY_RE.exec(singleMatch[1].trim());
        if (entry && entry[1] !== undefined && entry[2] !== undefined) {
          pushRecord(records, relPath, lineNo, entry[1], entry[2], isIndirect(entry[3]));
        } else {
          logger.warn(
            `dependencies: ${relPath}:${lineNo} is not a recognizable require line, skipping`,
          );
        }
        continue;
      }
      continue; // module/go/toolchain/exclude/replace/retract/other: not a dependency
    }

    if (line === ')') {
      inBlock = false;
      continue;
    }
    if (line.length === 0 || line.startsWith('//')) continue;

    const entry = ENTRY_RE.exec(line);
    if (!entry || entry[1] === undefined || entry[2] === undefined) {
      logger.warn(
        `dependencies: ${relPath}:${lineNo} inside a require block is not recognized, skipping`,
      );
      continue;
    }
    pushRecord(records, relPath, lineNo, entry[1], entry[2], isIndirect(entry[3]));
  }

  return records;
}
