import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A003 non-HTTPS server/scheme/request URL', () => {
  it('flags a plain http:// server (OpenAPI 3) at medium severity', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a003/http-openapi.yaml');
    const a003 = findingsFor(findings, 'A003');
    expect(a003).toHaveLength(1);
    expect(a003[0]).toMatchObject({ severity: 'medium', qualifier: 'confirmed' });
  });

  it('downgrades a localhost http:// server to info severity', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a003/http-localhost-openapi.yaml');
    const a003 = findingsFor(findings, 'A003');
    expect(a003).toHaveLength(1);
    expect(a003[0]).toMatchObject({ severity: 'info', qualifier: 'confirmed' });
  });

  it('does not fire for an https:// server', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a003/https-openapi.yaml');
    expect(findingsFor(findings, 'A003')).toHaveLength(0);
  });

  it('flags http in Swagger 2 schemes[]', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a003/http-swagger.json');
    const a003 = findingsFor(findings, 'A003');
    expect(a003).toHaveLength(1);
    expect(a003[0]?.severity).toBe('medium');
  });

  it('flags a plain http:// request URL in a Postman collection', async () => {
    const findings = await scanLocalFixture(apiScanner, 'postman/collection.json');
    const a003 = findingsFor(findings, 'A003');
    expect(a003).toHaveLength(1);
    expect(a003[0]?.evidence).toContain('Legacy / Legacy Ping');
    expect(a003[0]?.severity).toBe('medium'); // legacy.example.com is not localhost
  });
});
