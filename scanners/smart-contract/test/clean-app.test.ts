/**
 * Integration test against the shared, cross-scanner fixture at
 * tests/fixtures/clean-app/contracts/Safe.sol. tests/fixtures/README.md
 * documents clean-app as a negative control that every scanner must stay
 * quiet on, so it must produce zero findings here too.
 *
 * SC009 fires on any floating (`^`/`>=`) pragma per SWC-103, which is
 * correct, spec-literal, real-tool-consistent behavior. To keep clean-app a
 * true zero-findings control the fixture pins its pragma to an exact version
 * (`pragma solidity 0.8.24;`) — the way a security-conscious contract should
 * — rather than the rule being weakened. vulnerable-app keeps the floating
 * pragma so SC009 still has a positive case there.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { FileRef } from '@dl-sentinel/core';
import { describe, expect, it } from 'vitest';
import { functionGuardVerdict } from '../src/guards.js';
import smartContractScanner from '../src/index.js';
import { parseSolidityFile } from '../src/parser.js';
import { resolveFile } from '../src/resolve.js';
import { contextFor } from './helpers.js';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SAFE_SOL = 'tests/fixtures/clean-app/contracts/Safe.sol';

function safeFileRef(): FileRef {
  const absPath = fileURLToPath(new URL(`../../../${SAFE_SOL}`, import.meta.url));
  const size = Buffer.byteLength(readFileSync(absPath, 'utf8'), 'utf8');
  return { absPath, relPath: SAFE_SOL, size };
}

describe('clean-app: Safe.sol', () => {
  it('produces zero findings (a true negative control)', async () => {
    const context = contextFor([safeFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);

    expect(findings).toEqual([]);
  });

  it('specifically: the exact-pinned pragma does not trigger SC009', async () => {
    const context = contextFor([safeFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'SC009')).toBe(false);
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

  it('specifically: the modifier-body analysis proves onlyOwner rather than assuming it', async () => {
    // Safe.sol declares onlyOwner locally with a real require(msg.sender ==
    // owner) body, so this negative is a proven one, not an assumed one.
    const parsed = parseSolidityFile(
      SAFE_SOL,
      readFileSync(fileURLToPath(new URL(`../../../${SAFE_SOL}`, import.meta.url)), 'utf8'),
    );
    const resolved = resolveFile(parsed).contracts.get('Safe')!;
    const mint = parsed.contracts[0]!.functions.find((f) => f.name === 'mint')!;
    expect(functionGuardVerdict(resolved, mint)).toMatchObject({
      status: 'proven',
      modifier: 'onlyOwner',
    });
  });

  it('specifically: none of the contract-model rules (SC013-SC017) fire either', async () => {
    const context = contextFor([safeFileRef()], { rootDir: REPO_ROOT });
    const findings = await smartContractScanner.scan(context);
    const modelRules = ['SC013', 'SC014', 'SC015', 'SC016', 'SC017'];
    expect(findings.filter((f) => modelRules.includes(f.ruleId))).toEqual([]);
  });
});
