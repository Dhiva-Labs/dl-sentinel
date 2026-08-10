/**
 * Integration test against the shared, cross-scanner fixture at
 * tests/fixtures/vulnerable-app/contracts/Vulnerable.sol (READ-ONLY — owned
 * by feature/sentinel-testing; see tests/fixtures/README.md). Runs the full
 * ScannerPlugin, not individual rule.evaluate() calls, to exercise file
 * discovery/reading/sorting the same way the engine would.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { FileRef } from '@dl-sentinel/core';
import { describe, expect, it } from 'vitest';
import smartContractScanner from '../src/index.js';
import { contextFor } from './helpers.js';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const VULNERABLE_SOL = 'tests/fixtures/vulnerable-app/contracts/Vulnerable.sol';

function vulnerableFileRef(): FileRef {
  const absPath = fileURLToPath(new URL(`../../../${VULNERABLE_SOL}`, import.meta.url));
  const size = Buffer.byteLength(readFileSync(absPath, 'utf8'), 'utf8');
  return { absPath, relPath: VULNERABLE_SOL, size };
}

describe('vulnerable-app: Vulnerable.sol', () => {
  it('fires reentrancy, tx.origin, unchecked call, delegatecall, selfdestruct, and mint at the correct lines', async () => {
    const context = contextFor([vulnerableFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);

    const byRule = new Map(findings.map((f) => [f.ruleId, f]));

    expect(byRule.get('SC001')).toMatchObject({ line: 21, severity: 'high' }); // withdraw(): call before write
    expect(byRule.get('SC002')).toMatchObject({ line: 28, severity: 'high' }); // adminWithdraw(): tx.origin
    expect(byRule.get('SC003')).toMatchObject({ line: 34, severity: 'medium' }); // unsafeCall(): discarded result
    expect(byRule.get('SC004')).toMatchObject({ line: 39, severity: 'high' }); // delegateExec(): param target
    expect(byRule.get('SC005')).toMatchObject({ line: 50, severity: 'critical' }); // destroy(): unguarded selfdestruct
    expect(byRule.get('SC007')).toMatchObject({ line: 44, severity: 'high' }); // mint(): unguarded

    for (const f of findings) {
      expect(f.file).toBe(VULNERABLE_SOL);
      expect(f.scanner).toBe('smart-contract');
    }
  });

  it('also flags the floating pragma (SC009), and does not flag rules with no matching pattern', async () => {
    const context = contextFor([vulnerableFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);
    const ruleIds = new Set(findings.map((f) => f.ruleId));

    expect(ruleIds.has('SC009')).toBe(true); // pragma ^0.8.0 is floating

    // No initializer, no pre-0.8 pragma, no block-attribute usage, no
    // deprecated constructs, no owner/admin setter — none of these apply.
    expect(ruleIds.has('SC006')).toBe(false);
    expect(ruleIds.has('SC008')).toBe(false);
    expect(ruleIds.has('SC010')).toBe(false);
    expect(ruleIds.has('SC011')).toBe(false);
    expect(ruleIds.has('SC012')).toBe(false);
  });

  it('is deterministic across repeated scans', async () => {
    const context1 = contextFor([vulnerableFileRef()], { rootDir: REPO_ROOT });
    const context2 = contextFor([vulnerableFileRef()], { rootDir: REPO_ROOT });
    const [first, second] = await Promise.all([
      smartContractScanner.scan(context1),
      smartContractScanner.scan(context2),
    ]);
    expect(first).toEqual(second);
    expect(first.map((f) => f.id)).toEqual(second.map((f) => f.id));
  });
});
