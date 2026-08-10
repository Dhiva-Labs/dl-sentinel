import { describe, expect, it } from 'vitest';
import { matchAny } from '@dl-sentinel/core';
import { sourceScanner } from '../src/index.js';
import { fixturePath, listFixtureFiles, makeScanContext } from '../../../tests/support/index.js';

/**
 * Runs the source scanner over the shared, read-only
 * tests/fixtures/vulnerable-app tree (owned by feature/sentinel-testing;
 * never modified here). Only src/unsafe.js and src/unsafe.py fall under
 * this scanner's supportedFiles globs.
 *
 * Not every rule this scanner declares fires here -- vulnerable-app plants
 * one small, deliberately insecure sample per scanner category, not a
 * catalog of every source rule. In particular:
 *  - C004 (deserialization), C007 (insecure randomness), C009 (CORS), and
 *    C010 (chmod) have no matching pattern in these two files at all; they
 *    are covered by this scanner's own fixtures under
 *    scanners/source/test/fixtures/ instead.
 *  - C005 (path traversal) does not fire on unsafe.{js,py}'s
 *    `readUserTemp`/`read_user_temp`, which concatenates a parameter named
 *    `filename` into a path. C005's identifier allowlist (req, request,
 *    params, input, argv) is intentionally tight to keep precision high,
 *    and "filename" is not on it -- see scanners/source/src/rules/
 *    c005-path-traversal.ts and this scanner's handover notes.
 */
describe('source scanner against tests/fixtures/vulnerable-app (read-only shared fixture)', () => {
  it('scans exactly the two supported source files present in the fixture', () => {
    const root = fixturePath('vulnerable-app');
    const files = listFixtureFiles(root).filter((f) =>
      matchAny(f.relPath, sourceScanner.supportedFiles),
    );
    expect(files.map((f) => f.relPath).sort()).toEqual(['src/unsafe.js', 'src/unsafe.py']);
  });

  it('fires the expected rules at the expected files and lines', async () => {
    const root = fixturePath('vulnerable-app');
    const files = listFixtureFiles(root).filter((f) =>
      matchAny(f.relPath, sourceScanner.supportedFiles),
    );
    const ctx = makeScanContext(root, files);

    const findings = await sourceScanner.scan(ctx);
    const summary = findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`).sort();

    expect(summary).toEqual(
      [
        'C001 src/unsafe.js:14',
        'C002 src/unsafe.js:38',
        'C003 src/unsafe.js:23',
        'C006 src/unsafe.js:28',
        'C008 src/unsafe.js:33',
        'C001 src/unsafe.py:15',
        'C002 src/unsafe.py:39',
        'C003 src/unsafe.py:21',
        'C006 src/unsafe.py:26',
        'C008 src/unsafe.py:32',
        'C008 src/unsafe.py:33',
      ].sort(),
    );
  });

  it('never puts a secret value in evidence and always redacts through redactEvidence', async () => {
    const root = fixturePath('vulnerable-app');
    const files = listFixtureFiles(root).filter((f) =>
      matchAny(f.relPath, sourceScanner.supportedFiles),
    );
    const ctx = makeScanContext(root, files);
    const findings = await sourceScanner.scan(ctx);

    for (const finding of findings) {
      expect(finding.evidence.length).toBeLessThanOrEqual(201); // 200 + possible ellipsis
      expect(finding.evidence).not.toContain('\n');
    }
  });
});
