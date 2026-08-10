import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A008 deprecated/insecure auth flows', () => {
  it('flags an OAuth2 implicit flow (OpenAPI 3)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a008/oauth2-implicit-openapi.yaml');
    const a008 = findingsFor(findings, 'A008');
    expect(a008).toHaveLength(1);
    expect(a008[0]).toMatchObject({ severity: 'medium', confidence: 'high', qualifier: 'likely' });
    expect(a008[0]?.title).toContain('implicit');
  });

  it('does not fire for an OAuth2 authorization code flow (OpenAPI 3)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a008/oauth2-authcode-openapi.yaml');
    expect(findingsFor(findings, 'A008')).toHaveLength(0);
  });

  it('flags an OAuth2 implicit flow (Swagger 2, flow: implicit)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a008/oauth2-implicit-swagger.json');
    expect(findingsFor(findings, 'A008')).toHaveLength(1);
  });

  it('flags HTTP Digest authentication (OpenAPI 3)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a008/digest-openapi.yaml');
    const a008 = findingsFor(findings, 'A008');
    expect(a008).toHaveLength(1);
    expect(a008[0]?.title.toLowerCase()).toContain('digest');
  });

  it('flags OAuth1 auth inherited from a folder in a Postman collection', async () => {
    const findings = await scanLocalFixture(apiScanner, 'postman/collection.json');
    const a008 = findingsFor(findings, 'A008');
    expect(a008).toHaveLength(1);
    expect(a008[0]).toMatchObject({ severity: 'medium', qualifier: 'likely' });
    expect(a008[0]?.evidence).toContain('oauth1');
  });
});
