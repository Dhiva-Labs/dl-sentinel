/**
 * Integration test against the shared, cross-scanner fixture at
 * tests/fixtures/clean-app/contracts/Safe.sol (READ-ONLY — owned by
 * feature/sentinel-testing). tests/fixtures/README.md documents clean-app as
 * a negative control scanners "must stay quiet on".
 *
 * One documented exception here: Safe.sol's pragma is `^0.8.0` — a caret
 * (floating) pragma per SWC-103, which is the same construct
 * tests/fixtures/vulnerable-app/contracts/Vulnerable.sol uses. SC009 (low
 * severity, high confidence) is deliberately implemented to fire on ANY
 * floating pragma regardless of how recent its floor is — see
 * src/rules/sc009-pragma.ts and src/pragma.ts. That is correct, spec-
 * literal, real-tool-consistent behavior (Slither's solc-version check
 * flags the same pattern at its lowest severity tier); weakening it just to
 * force this shared fixture to zero findings would mean shipping a rule
 * that under-reports a real, if minor, hygiene issue. This is flagged in
 * the handover for the lead to reconcile (e.g. pin the shared fixture's
 * pragma exactly) rather than silently special-cased in the rule. It does
 * not affect the default policy (failOn: critical/high — SC009 is low) or
 * the CLI's exit-code-0-on-clean-app expectation.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { FileRef } from '@dl-sentinel/core';
import { describe, expect, it } from 'vitest';
import smartContractScanner from '../src/index.js';
import { contextFor } from './helpers.js';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SAFE_SOL = 'tests/fixtures/clean-app/contracts/Safe.sol';

function safeFileRef(): FileRef {
  const absPath = fileURLToPath(new URL(`../../../${SAFE_SOL}`, import.meta.url));
  const size = Buffer.byteLength(readFileSync(absPath, 'utf8'), 'utf8');
  return { absPath, relPath: SAFE_SOL, size };
}

describe('clean-app: Safe.sol', () => {
  it('produces no exploit-pattern findings (SC001-SC008, SC010-SC012)', async () => {
    const context = contextFor([safeFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);

    const nonPragmaFindings = findings.filter((f) => f.ruleId !== 'SC009');
    expect(nonPragmaFindings).toEqual([]);
  });

  it('the only finding is the low-severity floating-pragma hygiene note (SC009)', async () => {
    const context = contextFor([safeFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'SC009', severity: 'low', line: 2 });
  });

  it('specifically: checks-effects-interactions withdraw() does not trigger SC001', async () => {
    const context = contextFor([safeFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'SC001')).toBe(false);
  });

  it('specifically: onlyOwner-guarded mint() does not trigger SC007', async () => {
    const context = contextFor([safeFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'SC007')).toBe(false);
  });
});
