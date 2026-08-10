import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A002 API key in query', () => {
  it('flags an apiKey security scheme with in: query (OpenAPI 3)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a002/apikey-query-openapi.yaml');
    const a002 = findingsFor(findings, 'A002');
    expect(a002).toHaveLength(1);
    expect(a002[0]).toMatchObject({ severity: 'high', confidence: 'high', qualifier: 'confirmed' });
    expect(a002[0]?.evidence).toContain('components.securitySchemes.ApiKeyQuery');
  });

  it('does not fire for an apiKey scheme with in: header (OpenAPI 3)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a002/apikey-header-openapi.yaml');
    expect(findingsFor(findings, 'A002')).toHaveLength(0);
  });

  it('flags an apiKey security definition with in: query (Swagger 2)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a002/apikey-query-swagger.json');
    const a002 = findingsFor(findings, 'A002');
    expect(a002).toHaveLength(1);
    expect(a002[0]?.evidence).toContain('securityDefinitions.ApiKeyQuery');
  });

  it('flags a Postman apikey auth block with in: query', async () => {
    const findings = await scanLocalFixture(apiScanner, 'postman/collection.json');
    const a002 = findingsFor(findings, 'A002');
    expect(a002).toHaveLength(1);
    expect(a002[0]).toMatchObject({ severity: 'high', qualifier: 'confirmed' });
    expect(a002[0]?.evidence).toContain('item[0].request.auth');
  });
});
