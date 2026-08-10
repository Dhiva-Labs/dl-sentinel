import { describe, expect, it } from 'vitest';
import {
  createFinding,
  dedupeFindings,
  findingFingerprint,
  fingerprint,
} from '../src/fingerprint.js';
import type { Finding } from '../src/types.js';

function baseFinding(overrides: Partial<Omit<Finding, 'id'>> = {}): Omit<Finding, 'id'> {
  return {
    ruleId: 'S001',
    title: 'Hardcoded credential detected',
    description: 'A credential-like value was detected.',
    severity: 'critical',
    confidence: 'high',
    category: 'secrets',
    file: 'config/app.env',
    line: 14,
    column: 5,
    evidence: 'API_KEY=[REDACTED]',
    recommendation: 'Move the credential to a secret store.',
    references: [],
    scanner: 'secrets',
    ...overrides,
  };
}

describe('fingerprint', () => {
  it('is deterministic', () => {
    expect(fingerprint('a', 'b', 1)).toBe(fingerprint('a', 'b', 1));
  });

  it('is 16 hex chars', () => {
    expect(fingerprint('x')).toMatch(/^[0-9a-f]{16}$/);
  });

  it('separates parts so boundaries matter', () => {
    expect(fingerprint('ab', 'c')).not.toBe(fingerprint('a', 'bc'));
  });

  it('treats undefined as empty', () => {
    expect(fingerprint(undefined)).toBe(fingerprint(''));
  });
});

describe('findingFingerprint / createFinding', () => {
  it('produces stable ids for identical findings', () => {
    expect(findingFingerprint(baseFinding())).toBe(findingFingerprint(baseFinding()));
  });

  it('differs by rule, file, and position', () => {
    const a = findingFingerprint(baseFinding());
    expect(findingFingerprint(baseFinding({ ruleId: 'S002' }))).not.toBe(a);
    expect(findingFingerprint(baseFinding({ file: 'other.env' }))).not.toBe(a);
    expect(findingFingerprint(baseFinding({ line: 15 }))).not.toBe(a);
  });

  it('createFinding fills the id field', () => {
    const finding = createFinding(baseFinding());
    expect(finding.id).toMatch(/^[0-9a-f]{16}$/);
    expect(finding.id).toBe(findingFingerprint(finding));
  });
});

describe('dedupeFindings', () => {
  it('drops duplicate ids and preserves order', () => {
    const a = createFinding(baseFinding());
    const b = createFinding(baseFinding({ line: 20 }));
    const dup = createFinding(baseFinding());
    const out = dedupeFindings([a, b, dup]);
    expect(out).toHaveLength(2);
    expect(out[0]).toBe(a);
    expect(out[1]).toBe(b);
  });
});
