import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A009 unconstrained writable string/numeric fields', () => {
  it('aggregates every unconstrained field into a single finding with a count and example paths', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a009/unconstrained-openapi.yaml');
    const a009 = findingsFor(findings, 'A009');
    // Flood control: exactly one finding for the whole document, never one per field.
    expect(a009).toHaveLength(1);
    const finding = a009[0];
    expect(finding).toMatchObject({
      severity: 'low',
      confidence: 'medium',
      qualifier: 'potential',
    });
    // Fixture has 7 unconstrained fields (2 query params + 5 request body properties).
    expect(finding?.metadata?.count).toBe(7);
    expect(finding?.evidence).toContain('7 unconstrained field(s)');
    // Only a bounded number of example paths should be listed, with a "N more not
    // shown" summary placed BEFORE the example list so 200-char truncation can
    // never eat it.
    const exampleCount = (finding?.evidence.match(/paths\./g) ?? []).length;
    expect(exampleCount).toBeLessThanOrEqual(5);
    expect(finding?.evidence).toContain('2 more not shown');
  });

  it('does not fire when every string/numeric field is constrained', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a009/constrained-openapi.yaml');
    expect(findingsFor(findings, 'A009')).toHaveLength(0);
  });
});
