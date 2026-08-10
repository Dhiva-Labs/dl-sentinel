import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import { findingsFor, scanLocalFixture } from './helpers.js';

const PLANTED_GITHUB_TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const PLANTED_JWT =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYE5vaKfHVX8';

describe('A010 secrets in Postman collection', () => {
  it('flags a token-shaped collection variable and a token-shaped header value', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a010/secrets-postman.json');
    const a010 = findingsFor(findings, 'A010');
    expect(a010.length).toBeGreaterThanOrEqual(2);
    for (const f of a010) {
      expect(f).toMatchObject({ severity: 'high', qualifier: 'likely' });
    }
    expect(a010.some((f) => f.evidence.includes("variable 'apiToken'"))).toBe(true);
    expect(a010.some((f) => f.evidence.includes("header 'Authorization'"))).toBe(true);
  });

  it('never leaks the raw secret value anywhere in the serialized findings', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a010/secrets-postman.json');
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(PLANTED_GITHUB_TOKEN);
    expect(serialized).not.toContain(PLANTED_JWT);
    expect(serialized).toContain('[REDACTED]');
  });

  it('does not fire for placeholder values and {{variable}} references (including "Bearer {{token}}")', async () => {
    const findings = await scanLocalFixture(apiScanner, 'a010/clean-postman.json');
    expect(findingsFor(findings, 'A010')).toHaveLength(0);
  });
});
