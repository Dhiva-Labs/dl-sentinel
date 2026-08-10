import { describe, expect, it } from 'vitest';
import {
  allowsPreVersion,
  isFloatingPragma,
  isOutdatedPragma,
  parsePragmaClauses,
} from '../src/pragma.js';

describe('parsePragmaClauses', () => {
  it('parses a single caret clause', () => {
    expect(parsePragmaClauses('^0.8.0')).toEqual([{ op: '^', major: 0, minor: 8, patch: 0 }]);
  });

  it('parses an AND range with two clauses', () => {
    expect(parsePragmaClauses('>=0.7.0 <0.9.0')).toEqual([
      { op: '>=', major: 0, minor: 7, patch: 0 },
      { op: '<', major: 0, minor: 9, patch: 0 },
    ]);
  });

  it('defaults missing minor/patch to 0', () => {
    expect(parsePragmaClauses('0.8')).toEqual([{ op: '', major: 0, minor: 8, patch: 0 }]);
  });
});

describe('isFloatingPragma', () => {
  it('flags a caret pragma', () => {
    expect(isFloatingPragma('^0.8.0')).toBe(true);
  });

  it('flags a >= pragma', () => {
    expect(isFloatingPragma('>=0.7.0 <0.9.0')).toBe(true);
  });

  it('does not flag an exact-pinned pragma', () => {
    expect(isFloatingPragma('0.8.19')).toBe(false);
    expect(isFloatingPragma('=0.8.19')).toBe(false);
  });
});

describe('isOutdatedPragma', () => {
  it('flags a caret range whose upper reach never gets to 0.8', () => {
    expect(isOutdatedPragma('^0.7.0')).toBe(true);
  });

  it('flags an exact old pin', () => {
    expect(isOutdatedPragma('0.7.6')).toBe(true);
  });

  it('does not flag ^0.8.0 (reaches up to, but not including, 0.9.0)', () => {
    expect(isOutdatedPragma('^0.8.0')).toBe(false);
  });

  it('does not flag an exact-pinned recent version', () => {
    expect(isOutdatedPragma('0.8.19')).toBe(false);
    expect(isOutdatedPragma('=0.8.19')).toBe(false);
  });

  it('does not flag a range whose upper bound reaches 0.8 even if the lower bound is old', () => {
    expect(isOutdatedPragma('>=0.6.0 <0.9.0')).toBe(false);
  });

  it('does not flag an unbounded-above constraint', () => {
    expect(isOutdatedPragma('>=0.7.0')).toBe(false);
  });

  it('does not throw and returns false for unparsable text', () => {
    expect(isOutdatedPragma('not a version')).toBe(false);
  });
});

describe('allowsPreVersion', () => {
  it('^0.8.0 does not allow pre-0.8', () => {
    expect(allowsPreVersion('^0.8.0', 0, 8)).toBe(false);
  });

  it('^0.7.0 allows pre-0.8', () => {
    expect(allowsPreVersion('^0.7.0', 0, 8)).toBe(true);
  });

  it('a range spanning 0.6-0.9 allows pre-0.8', () => {
    expect(allowsPreVersion('>=0.6.0 <0.9.0', 0, 8)).toBe(true);
  });

  it('an exact 0.8.19 pin does not allow pre-0.8', () => {
    expect(allowsPreVersion('0.8.19', 0, 8)).toBe(false);
  });

  it('an exact pre-0.8 pin allows pre-0.8', () => {
    expect(allowsPreVersion('0.7.6', 0, 8)).toBe(true);
  });

  it('does not throw and returns false for unparsable text', () => {
    expect(allowsPreVersion('garbage', 0, 8)).toBe(false);
  });

  it('a bare upper bound with no lower bound is treated as allowing pre-threshold versions', () => {
    expect(allowsPreVersion('<0.9.0', 0, 8)).toBe(true);
  });
});
