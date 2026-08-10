import { describe, expect, it } from 'vitest';
import { shannonEntropy } from '../src/entropy.js';

describe('shannonEntropy', () => {
  it('is 0 for empty and single-symbol strings', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  it('is exactly 2 bits for four equally frequent symbols', () => {
    expect(shannonEntropy('abcd')).toBeCloseTo(2, 10);
  });

  it('is high for machine-generated tokens and lower for prose', () => {
    const token = 'A9fK2mQ7xR4tZ8wB1nC6vD3sE5uH0jL';
    const prose = 'this is a plain sentence about code';
    expect(shannonEntropy(token)).toBeGreaterThan(4);
    expect(shannonEntropy(token)).toBeGreaterThan(shannonEntropy(prose));
  });
});
