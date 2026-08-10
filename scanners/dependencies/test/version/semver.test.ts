import { describe, expect, it } from 'vitest';
import { compareSemVer, parseSemVer, parseSemVerRange } from '../../src/version/semver.js';

describe('parseSemVer', () => {
  it('parses a plain X.Y.Z version', () => {
    expect(parseSemVer('4.17.21')).toEqual({ major: 4, minor: 17, patch: 21 });
    expect(parseSemVer('0.0.1')).toEqual({ major: 0, minor: 0, patch: 1 });
  });

  it('trims surrounding whitespace', () => {
    expect(parseSemVer('  1.2.3  ')).toEqual({ major: 1, minor: 2, patch: 3 });
  });

  it.each(['1.2.3-beta.1', '1.2.3+build.5', '1.2', '1.2.3.4', 'v1.2.3', 'latest', '', '1.2.x'])(
    'returns null for %s (prerelease/build metadata, partial, or non-numeric)',
    (input) => {
      expect(parseSemVer(input)).toBeNull();
    },
  );
});

describe('compareSemVer', () => {
  it('orders by major, then minor, then patch', () => {
    expect(
      compareSemVer({ major: 1, minor: 0, patch: 0 }, { major: 2, minor: 0, patch: 0 }),
    ).toBeLessThan(0);
    expect(
      compareSemVer({ major: 1, minor: 5, patch: 0 }, { major: 1, minor: 2, patch: 0 }),
    ).toBeGreaterThan(0);
    expect(
      compareSemVer({ major: 1, minor: 2, patch: 3 }, { major: 1, minor: 2, patch: 9 }),
    ).toBeLessThan(0);
    expect(compareSemVer({ major: 1, minor: 2, patch: 3 }, { major: 1, minor: 2, patch: 3 })).toBe(
      0,
    );
  });
});

describe('parseSemVerRange', () => {
  describe('bareMeans "exact" (npm)', () => {
    it('treats a bare version as an exact-only point range', () => {
      expect(parseSemVerRange('4.17.15', 'exact')).toEqual({
        min: { major: 4, minor: 17, patch: 15 },
        minInclusive: true,
        max: { major: 4, minor: 17, patch: 15 },
        maxInclusive: true,
      });
    });
  });

  describe('bareMeans "caret" (Cargo)', () => {
    it('treats a bare version as a caret range', () => {
      expect(parseSemVerRange('1.2.3', 'caret')).toEqual({
        min: { major: 1, minor: 2, patch: 3 },
        minInclusive: true,
        max: { major: 2, minor: 0, patch: 0 },
        maxInclusive: false,
      });
    });
  });

  it('parses an explicit "=" as an exact-only point range', () => {
    expect(parseSemVerRange('=1.2.3', 'caret')).toEqual({
      min: { major: 1, minor: 2, patch: 3 },
      minInclusive: true,
      max: { major: 1, minor: 2, patch: 3 },
      maxInclusive: true,
    });
  });

  describe('caret (^)', () => {
    it('^1.2.3 => >=1.2.3 <2.0.0', () => {
      expect(parseSemVerRange('^1.2.3', 'exact')).toEqual({
        min: { major: 1, minor: 2, patch: 3 },
        minInclusive: true,
        max: { major: 2, minor: 0, patch: 0 },
        maxInclusive: false,
      });
    });

    it('^0.2.3 => >=0.2.3 <0.3.0', () => {
      expect(parseSemVerRange('^0.2.3', 'exact')).toEqual({
        min: { major: 0, minor: 2, patch: 3 },
        minInclusive: true,
        max: { major: 0, minor: 3, patch: 0 },
        maxInclusive: false,
      });
    });

    it('^0.0.3 => >=0.0.3 <0.0.4', () => {
      expect(parseSemVerRange('^0.0.3', 'exact')).toEqual({
        min: { major: 0, minor: 0, patch: 3 },
        minInclusive: true,
        max: { major: 0, minor: 0, patch: 4 },
        maxInclusive: false,
      });
    });
  });

  describe('tilde (~)', () => {
    it('~1.2.3 => >=1.2.3 <1.3.0', () => {
      expect(parseSemVerRange('~1.2.3', 'exact')).toEqual({
        min: { major: 1, minor: 2, patch: 3 },
        minInclusive: true,
        max: { major: 1, minor: 3, patch: 0 },
        maxInclusive: false,
      });
    });
  });

  describe('comparator operators', () => {
    it('>=1.2.3 has no upper bound', () => {
      expect(parseSemVerRange('>=1.2.3', 'exact')).toEqual({
        min: { major: 1, minor: 2, patch: 3 },
        minInclusive: true,
        maxInclusive: false,
      });
    });
    it('<=1.2.3 has no lower bound', () => {
      expect(parseSemVerRange('<=1.2.3', 'exact')).toEqual({
        max: { major: 1, minor: 2, patch: 3 },
        maxInclusive: true,
        minInclusive: false,
      });
    });
    it('>1.2.3 is exclusive', () => {
      expect(parseSemVerRange('>1.2.3', 'exact')).toEqual({
        min: { major: 1, minor: 2, patch: 3 },
        minInclusive: false,
        maxInclusive: false,
      });
    });
    it('<1.2.3 is exclusive', () => {
      expect(parseSemVerRange('<1.2.3', 'exact')).toEqual({
        max: { major: 1, minor: 2, patch: 3 },
        maxInclusive: false,
        minInclusive: false,
      });
    });
  });

  describe('conservative refusal: unclear or unsupported forms return null', () => {
    it.each([
      '1.2.x',
      '*',
      '1.0.0 || 2.0.0',
      '1.0.0 - 2.0.0',
      '>=1.0.0 <2.0.0',
      'latest',
      'workspace:*',
      'git+https://example.invalid/foo.git',
      'file:../local-thing',
      '^1.2.3-beta.1',
      '',
      '   ',
    ])('%s -> null', (input) => {
      expect(parseSemVerRange(input, 'exact')).toBeNull();
      expect(parseSemVerRange(input, 'caret')).toBeNull();
    });
  });
});
