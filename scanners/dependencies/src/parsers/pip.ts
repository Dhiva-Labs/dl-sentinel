import type { ScanLogger } from '@dl-sentinel/core';
import type { DependencyRecord, VersionKind } from '../types.js';

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*/;

function stripComment(line: string): string {
  const idx = line.indexOf('#');
  return idx === -1 ? line : line.slice(0, idx);
}

interface ParsedRequirement {
  name: string;
  versionKind: VersionKind;
  version?: string;
}

/**
 * Parse the requirement-spec portion of one line (name already consumed).
 * Recognizes a single `==` (exact), or a single `>=`/`<=`/`>`/`<` spec
 * (range, left for the comparator to interpret) — plus bare names with no
 * version at all (unpinned, nothing to check). Comma-compound specs
 * (">=1.0,<2.0"), `~=`, `!=`, and VCS/URL specifiers are rejected here
 * (`null`) rather than recorded as an unmatchable range: this scanner's
 * comparator has no way to use them, so there is nothing worth tracking.
 */
function parseRequirementLine(line: string): ParsedRequirement | null {
  const nameMatch = NAME_RE.exec(line);
  if (!nameMatch) return null;
  const name = nameMatch[0];
  let rest = line.slice(name.length);
  rest = rest.replace(/^\s*\[[^\]]*\]/, ''); // drop extras: name[extra1,extra2]
  rest = rest.trim();

  if (rest.length === 0) return { name, versionKind: 'range', version: undefined };
  if (rest.includes(',')) return null; // compound spec: unclear, not modeled

  const eq = /^==\s*([A-Za-z0-9.!+*_-]+)$/.exec(rest);
  if (eq && eq[1] !== undefined) return { name, versionKind: 'exact', version: eq[1] };

  if (/^(>=|<=|>|<)\S+$/.test(rest)) {
    return { name, versionKind: 'range', version: rest };
  }

  return null; // ~=, !=, VCS/URL specifiers, or anything else unrecognized
}

/**
 * Parse a `requirements.txt` (or `requirements-*.txt`) file. Each
 * non-blank, non-option line is one requirement; `==` pins are exact,
 * `>=`/`<=`/`>`/`<` are recorded as ranges for the comparator, and anything
 * else recognizable-but-unpinned (bare names) or genuinely unrecognizable
 * (VCS urls, `~=`, compound specs) is skipped — the latter with a warning.
 */
export function parseRequirementsTxt(
  relPath: string,
  content: string,
  logger: ScanLogger,
): DependencyRecord[] {
  const records: DependencyRecord[] = [];
  const lines = content.split(/\r\n|\r|\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    let line = stripComment(lines[i] ?? '').trim();
    if (line.length === 0) continue;
    if (line.startsWith('-')) continue; // options: -r, -e, -i, --hash, etc.

    const semi = line.indexOf(';');
    if (semi !== -1) line = line.slice(0, semi).trim();
    if (line.length === 0) continue;

    const parsed = parseRequirementLine(line);
    if (!parsed) {
      logger.warn(`dependencies: ${relPath}:${lineNo} is not a recognizable requirement, skipping`);
      continue;
    }
    if (parsed.version === undefined) continue; // unpinned: nothing to check

    records.push({
      ecosystem: 'pip',
      name: parsed.name,
      version: parsed.version,
      versionKind: parsed.versionKind,
      direct: true,
      sourceFile: relPath,
      line: lineNo,
    });
  }

  return records;
}
