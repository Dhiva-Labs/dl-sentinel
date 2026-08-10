import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A006 sensitive field name in response schema', () => {
  it('flags password/apiKey-shaped fields in a 2xx response schema (via $ref)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a006/sensitive-response-openapi.yaml');
    const a006 = findingsFor(findings, 'A006');
    const matchedFields = a006.map((f) => f.evidence);
    expect(a006).toHaveLength(2);
    expect(matchedFields.some((e) => e.includes('password'))).toBe(true);
    expect(matchedFields.some((e) => e.includes('api_key'))).toBe(true);
    for (const f of a006) {
      expect(f).toMatchObject({ severity: 'medium', confidence: 'medium', qualifier: 'likely' });
    }
  });

  it('does not fire when the response schema has no sensitive-looking field names', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a006/clean-response-openapi.yaml');
    expect(findingsFor(findings, 'A006')).toHaveLength(0);
  });

  it('resolves a $ref cycle without hanging or crashing, still finding the real hit', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a006/ref-cycle-openapi.yaml');
    const a006 = findingsFor(findings, 'A006');
    expect(a006).toHaveLength(1);
    expect(a006[0]?.evidence).toContain('token');
  });
});
