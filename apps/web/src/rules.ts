/**
 * Compliance mapping shape as served by `GET /api/rules` (mirrors
 * `RuleMeta.compliance` in packages/core/src/types.ts). Optional, and only
 * ever recorded for canonical, well-established mappings -- most rules will
 * have neither field, or no `compliance` object at all.
 */
export interface ComplianceLike {
  cwe?: string[];
  owasp?: string[];
}

/**
 * Flattens a rule's compliance mapping into an ordered list of chip labels,
 * e.g. `["CWE-798", "CWE-312", "A07:2021"]` -- CWE ids first, then OWASP Top
 * 10 ids, each group in its own declared order. Returns an empty array for a
 * rule with no mapping (missing, or present with empty/absent sub-arrays),
 * so callers can render nothing rather than an empty chip row.
 */
export function complianceChips(compliance: ComplianceLike | undefined | null): string[] {
  if (!compliance) return [];
  return [...(compliance.cwe ?? []), ...(compliance.owasp ?? [])];
}
