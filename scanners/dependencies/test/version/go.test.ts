import { describe, expect, it } from 'vitest';
import { compareGoVersion, parseGoVersion } from '../../src/version/go.js';

describe('parseGoVersion', () => {
  it('strips the leading v and parses a plain version', () => {
    expect(parseGoVersion('v1.4.0')).toEqual({ major: 1, minor: 4, patch: 0 });
  });

  it('parses a version with the +incompatible tag', () => {
    expect(parseGoVersion('v2.0.0+incompatible')).toEqual({ major: 2, minor: 0, patch: 0 });
  });

  it('parses a pseudo-version by its base only', () => {
    expect(parseGoVersion('v0.0.0-20210101000000-abcdef123456')).toEqual({
      major: 0,
      minor: 0,
      patch: 0,
    });
    expect(parseGoVersion('v1.2.3-20210101000000-abcdef123456')).toEqual({
      major: 1,
      minor: 2,
      patch: 3,
    });
  });

  it('parses the pre-release pseudo-version form (0.yyyymmddhhmmss-hash)', () => {
    expect(parseGoVersion('v1.3.0-0.20210101000000-abcdef123456')).toEqual({
      major: 1,
      minor: 3,
      patch: 0,
    });
  });

  describe('conservative refusal: uncertain forms return null', () => {
    it.each([
      'v1.2.3-beta.1', // genuine prerelease tag, not a pseudo-version
      '1.2.3', // missing leading v
      'v1.2', // partial version
      '',
      'latest',
      'v1.2.3-20210101000000-XYZ', // hash segment not lowercase hex
    ])('%s -> null', (input) => {
      expect(parseGoVersion(input)).toBeNull();
    });
  });
});

describe('compareGoVersion', () => {
  it('orders by major, then minor, then patch', () => {
    const a = { major: 1, minor: 2, patch: 3 };
    const b = { major: 1, minor: 2, patch: 4 };
    expect(compareGoVersion(a, b)).toBeLessThan(0);
    expect(compareGoVersion(b, a)).toBeGreaterThan(0);
    expect(compareGoVersion(a, a)).toBe(0);
  });
});
