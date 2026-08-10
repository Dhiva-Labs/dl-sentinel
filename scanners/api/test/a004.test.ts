import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A004 HTTP Basic authentication scheme', () => {
  it('flags type http, scheme basic (OpenAPI 3)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a004/basic-openapi.yaml');
    const a004 = findingsFor(findings, 'A004');
    expect(a004).toHaveLength(1);
    expect(a004[0]).toMatchObject({ severity: 'medium', confidence: 'high', qualifier: 'likely' });
  });

  it('flags type basic (Swagger 2)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a004/basic-swagger.json');
    const a004 = findingsFor(findings, 'A004');
    expect(a004).toHaveLength(1);
  });

  it('does not fire for a bearer scheme', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a004/bearer-openapi.yaml');
    expect(findingsFor(findings, 'A004')).toHaveLength(0);
  });
});
