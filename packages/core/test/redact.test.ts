import { describe, expect, it } from 'vitest';
import { containsSecret, redactEvidence, REDACTED, redactValue } from '../src/redact.js';

describe('redactValue', () => {
  it('always returns the marker', () => {
    expect(redactValue('sk_live_supersecretvalue123')).toBe(REDACTED);
    expect(redactValue('')).toBe(REDACTED);
  });
});

describe('redactEvidence', () => {
  it('removes the secret from the evidence line', () => {
    const secret = 'sk_live_abcdef1234567890';
    const out = redactEvidence(`api_key = "${secret}"`, [secret]);
    expect(out).not.toContain(secret);
    expect(out).toContain(REDACTED);
    expect(out).toContain('api_key');
  });

  it('removes every occurrence', () => {
    const secret = 'tok_abcd9999';
    const out = redactEvidence(`${secret} and again ${secret}`, [secret]);
    expect(out).not.toContain(secret);
    expect(out.split(REDACTED)).toHaveLength(3);
  });

  it('handles overlapping secrets longest-first without residue', () => {
    const out = redactEvidence('value=abcdefgh', ['abcd', 'abcdefgh']);
    expect(out).toBe(`value=${REDACTED}`);
  });

  it('redacts multiple distinct secrets', () => {
    const out = redactEvidence('u=alice p=hunter22 t=ghp_zzzz1111', ['hunter22', 'ghp_zzzz1111']);
    expect(out).not.toContain('hunter22');
    expect(out).not.toContain('ghp_zzzz1111');
  });

  it('ignores secrets shorter than 4 chars rather than shredding the line', () => {
    const out = redactEvidence('port = 8080', ['80']);
    expect(out).toBe('port = 8080');
  });

  it('truncates long evidence', () => {
    const long = 'x'.repeat(500);
    const out = redactEvidence(long, []);
    expect(out.length).toBeLessThanOrEqual(201);
    expect(out.endsWith('…')).toBe(true);
  });

  it('trims surrounding whitespace', () => {
    expect(redactEvidence('   const a = 1;   ', [])).toBe('const a = 1;');
  });
});

describe('containsSecret', () => {
  it('detects unredacted values', () => {
    expect(containsSecret('key=verysecret', 'verysecret')).toBe(true);
    expect(containsSecret(`key=${REDACTED}`, 'verysecret')).toBe(false);
  });
});
