import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

describe('A005 state-changing operation without security', () => {
  it('flags a DELETE with no security and no global default as likely', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a005/delete-no-auth-openapi.yaml');
    const a005 = findingsFor(findings, 'A005');
    expect(a005).toHaveLength(1);
    expect(a005[0]).toMatchObject({ severity: 'high', confidence: 'high', qualifier: 'likely' });
  });

  it('flags an explicit operation-level "security: []" override of a global requirement as confirmed', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a005/override-confirmed-openapi.yaml');
    const a005 = findingsFor(findings, 'A005');
    expect(a005).toHaveLength(1);
    expect(a005[0]).toMatchObject({ severity: 'high', qualifier: 'confirmed' });
    expect(a005[0]?.evidence).toContain('override');
  });

  it('does not fire when the operation has its own security requirement', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a005/delete-with-auth-openapi.yaml');
    expect(findingsFor(findings, 'A005')).toHaveLength(0);
  });
});
