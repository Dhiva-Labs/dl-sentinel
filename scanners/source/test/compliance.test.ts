import { describe, expect, it } from 'vitest';
import sourceScanner from '../src/index.js';

/**
 * Catalog-wide sweep over every declared rule's optional `compliance`
 * mapping (see docs/rules.md#compliance-mapping). This does not judge
 * whether a mapping is the *right* one -- that call was made rule-by-rule
 * against docs/architecture.md's "only canonical, well-established
 * mappings" rule -- it only catches mechanical drift: malformed ids, empty
 * arrays, duplicates, and a rule whose own `references` cite a CWE that
 * `compliance.cwe` fails to include.
 */

const CWE_ID_RE = /^CWE-\d+$/;
const OWASP_ID_RE = /^A(0[1-9]|10):2021$/;
const CWE_REFERENCE_RE = /cwe\.mitre\.org\/data\/definitions\/(\d+)/i;

describe('source rule catalog: compliance mapping', () => {
  it('every compliance.cwe entry matches /^CWE-\\d+$/', () => {
    for (const rule of sourceScanner.rules) {
      for (const id of rule.compliance?.cwe ?? []) {
        expect(id).toMatch(CWE_ID_RE);
      }
    }
  });

  it('every compliance.owasp entry matches /^A(0[1-9]|10):2021$/', () => {
    for (const rule of sourceScanner.rules) {
      for (const id of rule.compliance?.owasp ?? []) {
        expect(id).toMatch(OWASP_ID_RE);
      }
    }
  });

  it('declared cwe/owasp arrays are non-empty and free of duplicates', () => {
    for (const rule of sourceScanner.rules) {
      const { cwe, owasp } = rule.compliance ?? {};
      if (cwe) {
        expect(cwe.length).toBeGreaterThan(0);
        expect(new Set(cwe).size).toBe(cwe.length);
      }
      if (owasp) {
        expect(owasp.length).toBeGreaterThan(0);
        expect(new Set(owasp).size).toBe(owasp.length);
      }
    }
  });

  it('a present compliance object carries at least one of cwe/owasp', () => {
    for (const rule of sourceScanner.rules) {
      if (rule.compliance) {
        expect(
          (rule.compliance.cwe?.length ?? 0) + (rule.compliance.owasp?.length ?? 0),
        ).toBeGreaterThan(0);
      }
    }
  });

  it('a cwe.mitre.org reference is reflected in compliance.cwe (catches drift)', () => {
    for (const rule of sourceScanner.rules) {
      const citedIds = (rule.references ?? [])
        .map((ref) => CWE_REFERENCE_RE.exec(ref)?.[1])
        .filter((id): id is string => Boolean(id))
        .map((id) => `CWE-${id}`);
      for (const cited of citedIds) {
        expect(rule.compliance?.cwe ?? []).toContain(cited);
      }
    }
  });

  it('every C-rule carries a compliance.cwe mapping (all ten are canonical injection/crypto/access weaknesses)', () => {
    for (const rule of sourceScanner.rules) {
      expect(rule.compliance?.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
