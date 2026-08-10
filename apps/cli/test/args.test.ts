import { describe, expect, it } from 'vitest';
import { CliUsageError, parseFlags } from '../src/args.js';
import type { FlagSpec } from '../src/args.js';

const SPECS: readonly FlagSpec[] = [
  { name: 'format', takesValue: true },
  { name: 'output', takesValue: true },
  { name: 'quiet', takesValue: false },
  { name: 'help', takesValue: false, aliases: ['h'] },
];

describe('parseFlags', () => {
  it('collects positional arguments in order', () => {
    const parsed = parseFlags(['scan', 'a', 'b'], SPECS);
    expect(parsed.positionals).toEqual(['scan', 'a', 'b']);
  });

  it('reads a value flag written as two tokens', () => {
    const parsed = parseFlags(['--format', 'json'], SPECS);
    expect(parsed.values.get('format')).toBe('json');
  });

  it('reads a value flag written as --flag=value', () => {
    const parsed = parseFlags(['--format=sarif'], SPECS);
    expect(parsed.values.get('format')).toBe('sarif');
  });

  it('records boolean flags as present', () => {
    const parsed = parseFlags(['--quiet'], SPECS);
    expect(parsed.bools.has('quiet')).toBe(true);
    expect(parsed.bools.has('help')).toBe(false);
  });

  it('resolves short aliases to the canonical name', () => {
    const parsed = parseFlags(['-h'], SPECS);
    expect(parsed.bools.has('help')).toBe(true);
  });

  it('lets the last occurrence of a value flag win', () => {
    const parsed = parseFlags(['--format', 'json', '--format', 'markdown'], SPECS);
    expect(parsed.values.get('format')).toBe('markdown');
  });

  it('treats everything after -- as positional', () => {
    const parsed = parseFlags(['--', '--format', 'json'], SPECS);
    expect(parsed.positionals).toEqual(['--format', 'json']);
    expect(parsed.values.has('format')).toBe(false);
  });

  it('throws a UsageError on an unknown flag', () => {
    expect(() => parseFlags(['--nope'], SPECS)).toThrow(CliUsageError);
    try {
      parseFlags(['--nope'], SPECS);
    } catch (error) {
      expect((error as Error).name).toBe('UsageError');
    }
  });

  it('throws when a value flag is missing its value', () => {
    expect(() => parseFlags(['--format'], SPECS)).toThrow(/requires a value/);
  });

  it('throws when a boolean flag is given a value', () => {
    expect(() => parseFlags(['--quiet=1'], SPECS)).toThrow(/does not take a value/);
  });
});
