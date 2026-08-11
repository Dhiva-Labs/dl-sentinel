import { describe, expect, it } from 'vitest';
import { complianceChips } from '../src/rules.js';

describe('complianceChips', () => {
  it('returns an empty array when compliance is undefined', () => {
    expect(complianceChips(undefined)).toEqual([]);
  });

  it('returns an empty array when compliance is null', () => {
    expect(complianceChips(null)).toEqual([]);
  });

  it('returns an empty array for an empty compliance object', () => {
    expect(complianceChips({})).toEqual([]);
  });

  it('flattens cwe-only compliance', () => {
    expect(complianceChips({ cwe: ['CWE-798'] })).toEqual(['CWE-798']);
  });

  it('flattens owasp-only compliance', () => {
    expect(complianceChips({ owasp: ['A07:2021'] })).toEqual(['A07:2021']);
  });

  it('orders cwe entries before owasp entries, preserving each array’s own order', () => {
    expect(complianceChips({ cwe: ['CWE-798', 'CWE-312'], owasp: ['A07:2021'] })).toEqual([
      'CWE-798',
      'CWE-312',
      'A07:2021',
    ]);
  });

  it('treats missing sub-arrays as empty rather than throwing', () => {
    expect(complianceChips({ cwe: undefined, owasp: ['A03:2021'] })).toEqual(['A03:2021']);
  });
});
