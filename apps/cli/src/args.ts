/**
 * A minimal, dependency-free flag parser. Each command declares the flags it
 * understands; anything else (unknown option, missing value, value given to a
 * boolean flag) is a {@link CliUsageError}, which the dispatcher maps to exit
 * code 64.
 */

/** A caller mistake: bad flags, unknown command, unusable config/report input. */
export class CliUsageError extends Error {
  constructor(message: string) {
    super(message);
    // `name` is what run() switches on to choose exit code 64; it matches the
    // engine's own UsageError convention (docs/architecture.md §engine).
    this.name = 'UsageError';
  }
}

export interface FlagSpec {
  /** Canonical long name without leading dashes, e.g. `format`. */
  readonly name: string;
  /** Whether the flag consumes the next token (or an `=value`) as its value. */
  readonly takesValue: boolean;
  /** Alternate names without dashes, e.g. `h` for `-h`. */
  readonly aliases?: readonly string[];
}

export interface ParsedFlags {
  /** Positional (non-flag) arguments, in order. */
  readonly positionals: readonly string[];
  /** Value flags, keyed by canonical name (last occurrence wins). */
  readonly values: ReadonlyMap<string, string>;
  /**
   * Every occurrence of each value flag, in command-line order. `values` is the
   * right accessor for a flag that is given once (`--format`); this is the one
   * for a repeatable flag (`--plugin a --plugin b`), where each occurrence adds
   * to the set rather than replacing it.
   */
  readonly lists: ReadonlyMap<string, readonly string[]>;
  /** Boolean flags that were present, by canonical name. */
  readonly bools: ReadonlySet<string>;
}

/** Every value given for a repeatable flag, in order; `[]` when it was absent. */
export function repeated(parsed: ParsedFlags, name: string): string[] {
  return [...(parsed.lists.get(name) ?? [])];
}

/** Parse `tokens` against `specs`. Throws {@link CliUsageError} on any misuse. */
export function parseFlags(tokens: readonly string[], specs: readonly FlagSpec[]): ParsedFlags {
  const byName = new Map<string, FlagSpec>();
  for (const spec of specs) {
    byName.set(spec.name, spec);
    for (const alias of spec.aliases ?? []) byName.set(alias, spec);
  }

  const positionals: string[] = [];
  const values = new Map<string, string>();
  const lists = new Map<string, string[]>();
  const bools = new Set<string>();

  let index = 0;
  let positionalsOnly = false;
  while (index < tokens.length) {
    const token = tokens[index];
    index += 1;
    if (token === undefined) break;

    if (positionalsOnly) {
      positionals.push(token);
      continue;
    }
    if (token === '--') {
      positionalsOnly = true;
      continue;
    }

    const isLong = token.startsWith('--');
    const isShort = !isLong && token.startsWith('-') && token.length > 1;
    if (!isLong && !isShort) {
      positionals.push(token);
      continue;
    }

    const body = isLong ? token.slice(2) : token.slice(1);
    const eq = body.indexOf('=');
    const name = eq === -1 ? body : body.slice(0, eq);
    const inlineValue = eq === -1 ? undefined : body.slice(eq + 1);
    const dashes = isLong ? '--' : '-';

    const spec = byName.get(name);
    if (spec === undefined) {
      throw new CliUsageError(`Unknown option: ${dashes}${name}`);
    }
    if (spec.takesValue) {
      let value = inlineValue;
      if (value === undefined) {
        const next = tokens[index];
        if (next === undefined) {
          throw new CliUsageError(`Option ${dashes}${name} requires a value`);
        }
        value = next;
        index += 1;
      }
      values.set(spec.name, value);
      const seen = lists.get(spec.name);
      if (seen === undefined) lists.set(spec.name, [value]);
      else seen.push(value);
    } else {
      if (inlineValue !== undefined) {
        throw new CliUsageError(`Option ${dashes}${name} does not take a value`);
      }
      bools.add(spec.name);
    }
  }

  return { positionals, values, lists, bools };
}
