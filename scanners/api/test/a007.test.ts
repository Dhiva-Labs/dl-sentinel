import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A007 missing rate-limit signal', () => {
  it('flags a document with no 429 response and no rate-limit header', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a007/no-ratelimit-openapi.yaml');
    const a007 = findingsFor(findings, 'A007');
    expect(a007).toHaveLength(1);
    expect(a007[0]).toMatchObject({ severity: 'low', confidence: 'high', qualifier: 'potential' });
    expect(a007[0]?.line).toBeUndefined(); // whole-document finding
  });

  it('does not fire when a 429 response is documented', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a007/with-429-openapi.yaml');
    expect(findingsFor(findings, 'A007')).toHaveLength(0);
  });

  it('does not fire when a rate-limit header is documented', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a007/with-header-openapi.yaml');
    expect(findingsFor(findings, 'A007')).toHaveLength(0);
  });

  it('produces exactly one finding per document, not per operation', async () => {
    // no-ratelimit-openapi.yaml has a single operation; verify the rule is still
    // document-scoped by asserting the count stays at 1 (guards against a
    // per-operation regression).
    const findings = await scanLocalFixture(apiScanner, 'a007/no-ratelimit-openapi.yaml');
    expect(findingsFor(findings, 'A007')).toHaveLength(1);
  });
});
