/**
 * Minimal line-based Dockerfile parser: enough structure for the I00x rules
 * without executing or fully validating the file. Handles backslash line
 * continuations, `#`-comments (including a comment-only line breaking up an
 * otherwise-continued instruction, matching real `docker build` behavior),
 * and case-insensitive instruction keywords.
 *
 * Not implemented (documented limitation): `# escape=` parser directives
 * that change the continuation character away from `\`, and heredoc
 * (<<EOF) RUN syntax.
 */

export interface DockerInstruction {
  /** Upper-cased instruction keyword, e.g. 'FROM', 'RUN', 'USER'. */
  instruction: string;
  /** Raw remainder of the instruction, continuation lines joined with a space. */
  args: string;
  /** 1-based line number of the first physical line of this instruction. */
  line: number;
}

export interface DockerStage {
  index: number;
  /** The `AS name` alias for this stage, if any (lower-cased for lookup). */
  name?: string;
  /** Base image reference, with any `--platform=` flag and `AS name` clause removed. */
  image: string;
  /** True when `image` is actually a reference to an earlier stage's name, not a real image. */
  isAlias: boolean;
  fromLine: number;
  lastUser?: { value: string; line: number };
}

export interface ParsedDockerfile {
  instructions: DockerInstruction[];
  stages: DockerStage[];
}

function isCommentOnly(line: string): boolean {
  return line.trim().startsWith('#');
}

/**
 * True when `line` ends (ignoring trailing whitespace) in an odd number of
 * backslashes — an escaped `\\` doesn't count as a continuation marker.
 */
function endsWithContinuation(line: string): { continues: boolean; withoutBackslash: string } {
  const trimmed = line.replace(/[ \t]+$/, '');
  if (!trimmed.endsWith('\\')) return { continues: false, withoutBackslash: line };
  let count = 0;
  for (let i = trimmed.length - 1; i >= 0 && trimmed[i] === '\\'; i--) count++;
  return { continues: count % 2 === 1, withoutBackslash: trimmed.slice(0, -1) };
}

/** Join backslash-continued physical lines into logical instruction lines. */
function buildLogicalLines(text: string): Array<{ text: string; line: number }> {
  const physical = text.split(/\r\n|\n/);
  const logical: Array<{ text: string; line: number }> = [];

  let i = 0;
  while (i < physical.length) {
    const raw = physical[i] ?? '';
    if (raw.trim().length === 0 || isCommentOnly(raw)) {
      i++;
      continue;
    }

    const startLine = i + 1;
    let combined = raw;
    let state = endsWithContinuation(combined);
    while (state.continues && i + 1 < physical.length) {
      i++;
      const next = physical[i] ?? '';
      if (isCommentOnly(next)) {
        // A full comment line inside a continuation is skipped entirely,
        // but does not end the continuation.
        continue;
      }
      // Trim at the join point so accumulated indentation on continuation
      // lines doesn't leak into the logical instruction as literal
      // whitespace; a single space always separates the joined segments.
      combined = `${state.withoutBackslash.replace(/[ \t]+$/, '')} ${next.replace(/^[ \t]+/, '')}`;
      state = endsWithContinuation(combined);
    }

    logical.push({ text: combined, line: startLine });
    i++;
  }

  return logical;
}

export function parseInstructions(text: string): DockerInstruction[] {
  const logical = buildLogicalLines(text);
  const instructions: DockerInstruction[] = [];
  for (const { text: line, line: lineNo } of logical) {
    const match = /^\s*([A-Za-z]+)\s*(.*)$/s.exec(line);
    if (!match) continue;
    const instruction = (match[1] ?? '').toUpperCase();
    const args = (match[2] ?? '').trim();
    instructions.push({ instruction, args, line: lineNo });
  }
  return instructions;
}

/** Strip a leading `--flag=value` (e.g. `--platform=linux/amd64`) from FROM's args. */
function stripLeadingFlags(args: string): string {
  let rest = args.trim();
  while (rest.startsWith('--')) {
    const spaceIdx = rest.search(/\s/);
    if (spaceIdx === -1) return '';
    rest = rest.slice(spaceIdx + 1).trim();
  }
  return rest;
}

function parseFromArgs(args: string): { image: string; name?: string } {
  const rest = stripLeadingFlags(args);
  const tokens = rest.split(/\s+/).filter(Boolean);
  const image = tokens[0] ?? '';
  let name: string | undefined;
  if (tokens[1] && /^as$/i.test(tokens[1]) && tokens[2]) {
    name = tokens[2];
  }
  return { image, name };
}

function isRootUser(value: string): boolean {
  const primary = (value.split(':')[0] ?? '').trim().toLowerCase();
  return primary === 'root' || primary === '0';
}

export function parseDockerfile(text: string): ParsedDockerfile {
  const instructions = parseInstructions(text);
  const stages: DockerStage[] = [];
  const stageNamesLower = new Set<string>();
  let current: DockerStage | undefined;

  for (const inst of instructions) {
    if (inst.instruction === 'FROM') {
      const { image, name } = parseFromArgs(inst.args);
      const isAlias = stageNamesLower.has(image.toLowerCase());
      current = {
        index: stages.length,
        name,
        image,
        isAlias,
        fromLine: inst.line,
      };
      stages.push(current);
      if (name) stageNamesLower.add(name.toLowerCase());
    } else if (inst.instruction === 'USER' && current) {
      current.lastUser = { value: inst.args.trim(), line: inst.line };
    }
  }

  return { instructions, stages };
}

export { isRootUser };
