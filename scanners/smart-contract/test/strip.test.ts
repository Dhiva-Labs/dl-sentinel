import { describe, expect, it } from 'vitest';
import { stripCommentsAndStrings } from '../src/strip.js';

describe('stripCommentsAndStrings', () => {
  it('preserves line count and line numbers', () => {
    const source = 'line one\nline two\nline three';
    const out = stripCommentsAndStrings(source);
    expect(out).toHaveLength(3);
    expect(out.map((l) => l.line)).toEqual([1, 2, 3]);
    expect(out.map((l) => l.original)).toEqual(['line one', 'line two', 'line three']);
  });

  it('blanks a line comment but keeps the line', () => {
    const out = stripCommentsAndStrings('uint256 x = 1; // set x\nuint256 y = 2;');
    expect(out[0]!.stripped).not.toContain('set x');
    expect(out[0]!.stripped).toContain('uint256 x = 1;');
    expect(out[1]!.stripped).toContain('uint256 y = 2;');
  });

  it('blanks a whole-line comment to only whitespace', () => {
    const out = stripCommentsAndStrings('// just a comment');
    expect(out[0]!.stripped.trim()).toBe('');
  });

  it('blanks a single-line block comment', () => {
    const out = stripCommentsAndStrings('uint256 x = /* inline */ 1;');
    expect(out[0]!.stripped).not.toContain('inline');
    expect(out[0]!.stripped).toContain('uint256 x =');
    expect(out[0]!.stripped).toContain('1;');
  });

  it('blanks a block comment spanning multiple lines, preserving line numbers on both sides', () => {
    const source = 'uint256 a = 1;\n/* start\nmiddle line\nend */\nuint256 b = 2;';
    const out = stripCommentsAndStrings(source);
    expect(out).toHaveLength(5);
    expect(out[0]!.stripped).toContain('uint256 a = 1;');
    expect(out[1]!.stripped.trim()).toBe('');
    expect(out[2]!.stripped.trim()).toBe('');
    expect(out[3]!.stripped.trim()).toBe('');
    expect(out[4]!.stripped).toContain('uint256 b = 2;');
    expect(out[4]!.line).toBe(5);
  });

  it('blanks string literal contents but keeps surrounding code and quote positions', () => {
    const out = stripCommentsAndStrings('require(ok, "transfer failed");');
    expect(out[0]!.stripped).not.toContain('transfer failed');
    expect(out[0]!.stripped).toContain('require(ok,');
    expect(out[0]!.stripped.length).toBe('require(ok, "transfer failed");'.length);
  });

  it('does not treat a // inside a string as a comment start', () => {
    const out = stripCommentsAndStrings('string memory url = "https://example.invalid";');
    expect(out[0]!.stripped).toContain('string memory url =');
    // Everything after the opening quote is blanked, including the //, but
    // the assignment and trailing semicolon must survive.
    expect(out[0]!.stripped.trim().endsWith(';')).toBe(true);
  });

  it('does not treat a quote inside a line comment as starting a string', () => {
    const out = stripCommentsAndStrings('// don\'t worry about this "quote"\nuint256 z = 3;');
    expect(out[0]!.stripped.trim()).toBe('');
    expect(out[1]!.stripped).toContain('uint256 z = 3;');
  });

  it('handles an escaped quote inside a string without ending it early', () => {
    const out = stripCommentsAndStrings(
      'string memory s = "a \\"quoted\\" word"; uint256 after = 1;',
    );
    expect(out[0]!.stripped).toContain('after = 1;');
  });

  it('handles a single-quoted string the same way as double-quoted', () => {
    const out = stripCommentsAndStrings("bytes1 c = 'x'; // trailing comment");
    expect(out[0]!.stripped).toContain('bytes1 c =');
    expect(out[0]!.stripped).not.toContain('trailing comment');
  });

  it('does not crash on an unterminated block comment (malformed input)', () => {
    const out = stripCommentsAndStrings('uint256 a = 1;\n/* never closed\nstill open');
    expect(out).toHaveLength(3);
    expect(out[0]!.stripped).toContain('uint256 a = 1;');
  });

  it('does not crash on an unterminated string literal (malformed input)', () => {
    const out = stripCommentsAndStrings('string memory s = "never closed');
    expect(out).toHaveLength(1);
  });

  it('normalizes CRLF and CR line endings the same as LF', () => {
    const out = stripCommentsAndStrings('a\r\nb\rc');
    expect(out.map((l) => l.original)).toEqual(['a', 'b', 'c']);
  });
});
