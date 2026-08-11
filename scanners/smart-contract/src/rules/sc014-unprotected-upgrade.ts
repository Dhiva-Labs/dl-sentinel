/**
 * SC014 — unprotected upgrade authorization.
 *
 * A proxy's upgrade path is the single most privileged entry point a contract
 * has: whoever can point it at new code owns everything the proxy holds. Two
 * shapes are checked, both against the resolved guard analysis in guards.ts:
 *
 * - `upgradeTo` / `upgradeToAndCall` declared public/external with no guard.
 *   In a real UUPS deployment these come from the imported proxy base and are
 *   guarded there; a contract that *declares its own* is opting out of that,
 *   so an unguarded one is a genuine finding.
 * - `_authorizeUpgrade` with no guard. This hook exists for exactly one
 *   purpose — to revert for unauthorized callers — so an implementation that
 *   applies no modifier and checks nothing is the classic UUPS bug:
 *
 *       function _authorizeUpgrade(address) internal override {}
 *
 *   Visibility is not filtered for this one: the hook is `internal` by
 *   contract, and it is the proxy machinery, not a direct caller, that
 *   reaches it.
 *
 * Heuristic limits:
 * - Name-driven. A bespoke upgrade mechanism under another name is not found.
 * - As everywhere in guards.ts, a modifier declared outside this file is
 *   assumed to guard, so `_authorizeUpgrade() internal override onlyOwner {}`
 *   is silent whether or not the imported `onlyOwner` is real.
 * - An authorization performed by something other than a modifier, an inline
 *   `msg.sender` check, or a directly-called helper (say, a check three calls
 *   deep) reads as unguarded. Confidence is medium for that reason.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import { isFunctionGuarded } from '../guards.js';
import { resolveContractIn } from '../resolve.js';
import { lineOriginal } from '../util.js';
import type { RuleContext, RuleDefinition } from './types.js';

/** Externally-reachable upgrade entry points (checked only when public/external). */
const UPGRADE_ENTRY_NAMES = new Set(['upgradeto', 'upgradetoandcall']);
/** The UUPS authorization hook (checked at any visibility). */
const AUTHORIZE_HOOK_NAME = '_authorizeupgrade';

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);

    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      const lowered = fn.name.toLowerCase();
      const isHook = lowered === AUTHORIZE_HOOK_NAME;
      const isEntry =
        UPGRADE_ENTRY_NAMES.has(lowered) &&
        (fn.visibility === 'public' || fn.visibility === 'external');
      if (!isHook && !isEntry) continue;
      if (isFunctionGuarded(resolved, fn)) continue;

      const description = isHook
        ? `Function '${fn.name}' is the UUPS upgrade authorization hook, whose only job is to revert for unauthorized callers, but it applies no access-control modifier and performs no caller check. Anyone who can reach the proxy's upgrade entry point can replace the implementation.`
        : `Function '${fn.name}' is ${fn.visibility} and replaces the proxy implementation with no access-control modifier and no caller check, so anyone can point this contract at code of their choosing.`;

      findings.push(
        createFinding({
          ruleId: 'SC014',
          title: 'Unprotected upgrade function',
          description,
          severity: 'high',
          confidence: 'medium',
          category: 'smart-contract',
          file: ctx.relPath,
          line: fn.headerLine,
          evidence: redactEvidence(lineOriginal(ctx.file, fn.headerLine), []),
          recommendation:
            'Restrict the upgrade path to a trusted role — apply an owner/admin modifier to _authorizeUpgrade (or to the upgrade entry point) so unauthorized callers revert.',
          references: [],
          scanner: 'smart-contract',
          metadata: { function: fn.name, kind: isHook ? 'authorize-hook' : 'upgrade-entry' },
        }),
      );
    }
  }

  return findings;
}

export const sc014UnprotectedUpgrade: RuleDefinition = {
  meta: {
    id: 'SC014',
    title: 'Unprotected upgrade function',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'A proxy upgrade path — public/external upgradeTo/upgradeToAndCall, or the _authorizeUpgrade hook at any visibility — carries no access-control guard: no applied modifier whose body checks the caller, and no caller check of its own. An empty _authorizeUpgrade is the classic UUPS misconfiguration.',
    recommendation:
      'Guard the upgrade path with an owner/admin-only modifier so unauthorized callers revert.',
    references: [],
    // Same textbook fit as SC005/SC006/SC007: a sensitive function with no
    // authorization check guarding it.
    compliance: { cwe: ['CWE-862'] },
  },
  evaluate,
};
