import { describe, expect, it } from 'vitest';
import { smartContractScanner } from '../src/index.js';

/**
 * Catalog-wide sweep over every declared rule's optional `compliance`
 * mapping (see docs/rules.md#compliance-mapping). This does not judge
 * whether a mapping is the *right* one -- that call was made rule-by-rule
 * against docs/architecture.md's "only canonical, well-established
 * mappings" rule -- it only catches mechanical drift: malformed ids, empty
 * arrays, duplicates, and (for the rules that already cite an SWC Registry
 * entry) an accidental cwe.mitre.org reference this scanner never uses.
 */

const CWE_ID_RE = /^CWE-\d+$/;
const OWASP_ID_RE = /^A(0[1-9]|10):2021$/;
const CWE_REFERENCE_RE = /cwe\.mitre\.org\/data\/definitions\/(\d+)/i;

describe('smart-contract rule catalog: compliance mapping', () => {
  it('every compliance.cwe entry matches /^CWE-\\d+$/', () => {
    for (const rule of smartContractScanner.rules) {
      for (const id of rule.compliance?.cwe ?? []) {
        expect(id).toMatch(CWE_ID_RE);
      }
    }
  });

  it('every compliance.owasp entry, if any ever appears, matches /^A(0[1-9]|10):2021$/', () => {
    for (const rule of smartContractScanner.rules) {
      for (const id of rule.compliance?.owasp ?? []) {
        expect(id).toMatch(OWASP_ID_RE);
      }
    }
  });

  it('declared cwe arrays are non-empty and free of duplicates', () => {
    for (const rule of smartContractScanner.rules) {
      const { cwe } = rule.compliance ?? {};
      if (cwe) {
        expect(cwe.length).toBeGreaterThan(0);
        expect(new Set(cwe).size).toBe(cwe.length);
      }
    }
  });

  it('never sets owasp: OWASP Top 10 (2021) is a web-application taxonomy and does not apply to Solidity/EVM findings', () => {
    for (const rule of smartContractScanner.rules) {
      expect(rule.compliance?.owasp).toBeUndefined();
    }
  });

  it('a cwe.mitre.org reference (never expected from this scanner) would still be reflected in compliance.cwe', () => {
    for (const rule of smartContractScanner.rules) {
      const citedIds = (rule.references ?? [])
        .map((ref) => CWE_REFERENCE_RE.exec(ref)?.[1])
        .filter((id): id is string => Boolean(id))
        .map((id) => `CWE-${id}`);
      for (const cited of citedIds) {
        expect(rule.compliance?.cwe ?? []).toContain(cited);
      }
    }
  });

  it('SC009 (floating/outdated pragma) and SC012 (setter without event) deliberately carry no mapping', () => {
    for (const id of ['SC009', 'SC012']) {
      const rule = smartContractScanner.rules.find((r) => r.id === id);
      expect(rule?.compliance).toBeUndefined();
    }
  });
});
