import { describe, expect, it } from 'vitest';
import { comparePipVersion, parsePipRange, parsePipVersion } from '../../src/version/pip.js';

describe('parsePipVersion', () => {
  it('parses dotted non-negative integers', () => {
    expect(parsePipVersion('2.6.0')).toEqual([2, 6, 0]);
    expect(parsePipVersion('3')).toEqual([3]);
    expect(parsePipVersion('1.0.0.0')).toEqual([1, 0, 0, 0]);
  });

  it.each(['2.0rc1', '1.0.dev0', '1.0+local', '1.0-post1', '', 'abc', '1..2'])(
    'returns null for %s (non-numeric segment)',
    (input) => {
      expect(parsePipVersion(input)).toBeNull();
    },
  );
});

describe('comparePipVersion', () => {
  it('compares tuples of different lengths by zero-padding the shorter one', () => {
    expect(comparePipVersion([1, 0], [1, 0, 0])).toBe(0);
    expect(comparePipVersion([1, 0, 1], [1, 0])).toBeGreaterThan(0);
    expect(comparePipVersion([2, 6, 0], [2, 6, 1])).toBeLessThan(0);
  });
});

describe('parsePipRange', () => {
  it('parses >=, <=, >, < against a dotted-int version', () => {
    expect(parsePipRange('>=2.6.0')).toEqual({
      min: [2, 6, 0],
      minInclusive: true,
      maxInclusive: false,
    });
    expect(parsePipRange('<=2.6.0')).toEqual({
      max: [2, 6, 0],
      maxInclusive: true,
      minInclusive: false,
    });
    expect(parsePipRange('>2.6.0')).toEqual({
      min: [2, 6, 0],
      minInclusive: false,
      maxInclusive: false,
    });
    expect(parsePipRange('<2.6.0')).toEqual({
      max: [2, 6, 0],
      maxInclusive: false,
      minInclusive: false,
    });
  });

  it('tolerates whitespace between the operator and the version', () => {
    expect(parsePipRange('>= 2.6.0')).toEqual({
      min: [2, 6, 0],
      minInclusive: true,
      maxInclusive: false,
    });
  });

  describe('conservative refusal', () => {
    it.each(['==2.6.0', '~=1.4.2', '!=2.6.1', '>=1.0,<2.0', '*', '', 'latest'])(
      '%s -> null',
      (input) => {
        expect(parsePipRange(input)).toBeNull();
      },
    );
  });
});
