import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A001 no authentication defined', () => {
  it('flags the whole document when no schemes and no security exist anywhere (OpenAPI 3)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a001/no-schemes-openapi.yaml');
    const a001 = findingsFor(findings, 'A001');
    expect(a001).toHaveLength(1);
    expect(a001[0]).toMatchObject({
      ruleId: 'A001',
      severity: 'high',
      confidence: 'high',
      qualifier: 'confirmed',
      category: 'api',
      scanner: 'api',
      file: 'a001/no-schemes-openapi.yaml',
    });
    expect(a001[0]?.line).toBeUndefined();
  });

  it('flags the whole document when no schemes and no security exist anywhere (Swagger 2)', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a001/no-schemes-swagger.json');
    const a001 = findingsFor(findings, 'A001');
    expect(a001).toHaveLength(1);
    expect(a001[0]?.qualifier).toBe('confirmed');
  });

  it('flags each operation lacking security when schemes exist but there is no global default', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a001/schemes-no-global-openapi.yaml');
    const a001 = findingsFor(findings, 'A001');
    expect(a001).toHaveLength(1);
    expect(a001[0]).toMatchObject({ severity: 'high', confidence: 'high', qualifier: 'likely' });
    expect(a001[0]?.evidence).toContain('paths./widgets.get');
    // YAML source: a real line number should have been resolved.
    expect(a001[0]?.line).toBeGreaterThan(0);
  });

  it('does not fire when a global security requirement covers every operation', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a001/clean-openapi.yaml');
    expect(findingsFor(findings, 'A001')).toHaveLength(0);
  });
});
