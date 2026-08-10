/**
 * Suppression: dropping findings that a project has reviewed and decided to
 * ignore, declared in sentinel.yml under `suppress`. This generalizes the
 * per-scanner allowlists (e.g. secrets) into one finding-model-level mechanism
 * that every scanner's output passes through.
 *
 * Semantics (see SuppressionRule in types.ts):
 * - A rule matches a finding when EVERY field it specifies matches (AND).
 * - A finding is suppressed when it matches ANY active rule (OR across rules).
 * - A rule specifying no matcher (rule/scanner/path/id) matches nothing, so a
 *   blank entry can never hide everything by accident.
 * - `expires` (ISO date) makes a rule lapse; an expired rule suppresses
 *   nothing, so the finding resurfaces rather than staying hidden forever.
 */

import { matchGlob } from './glob.js';
import type { Finding, SuppressionRule } from './types.js';

/** True if the rule has at least one matcher field. */
export function isActionableRule(rule: SuppressionRule): boolean {
  return (
    rule.rule !== undefined ||
    rule.scanner !== undefined ||
    rule.path !== undefined ||
    rule.id !== undefined
  );
}

/** True if the rule has expired relative to `now` (inclusive). */
export function isExpired(rule: SuppressionRule, now: Date): boolean {
  if (rule.expires === undefined) return false;
  const expiry = Date.parse(rule.expires);
  if (Number.isNaN(expiry)) return false; // an unparseable date never expires the rule
  return now.getTime() >= expiry;
}

/** Does an active, actionable rule match this finding? */
export function ruleMatches(rule: SuppressionRule, finding: Finding, now: Date): boolean {
  if (!isActionableRule(rule)) return false;
  if (isExpired(rule, now)) return false;
  if (rule.id !== undefined && finding.id !== rule.id) return false;
  if (rule.rule !== undefined && finding.ruleId !== rule.rule) return false;
  if (rule.scanner !== undefined && finding.scanner !== rule.scanner) return false;
  if (rule.path !== undefined && !matchGlob(finding.file, rule.path)) return false;
  return true;
}

/** True if any active rule suppresses the finding. */
export function isSuppressed(
  finding: Finding,
  rules: readonly SuppressionRule[],
  now: Date,
): boolean {
  return rules.some((rule) => ruleMatches(rule, finding, now));
}

export interface SuppressionResult {
  /** Findings that survived suppression (what a report should show). */
  active: Finding[];
  /** Findings removed by a suppression rule. */
  suppressed: Finding[];
}

/**
 * Partition findings into active and suppressed. `now` is injected (never read
 * from the clock here) so the function stays pure and testable; callers pass
 * `new Date()`.
 */
export function applySuppressions(
  findings: readonly Finding[],
  rules: readonly SuppressionRule[],
  now: Date,
): SuppressionResult {
  if (rules.length === 0) return { active: [...findings], suppressed: [] };
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const finding of findings) {
    if (isSuppressed(finding, rules, now)) {
      suppressed.push(finding);
    } else {
      active.push(finding);
    }
  }
  return { active, suppressed };
}
