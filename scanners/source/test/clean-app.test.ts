import { describe, expect, it } from 'vitest';
import { matchAny } from '@dl-sentinel/core';
import { sourceScanner } from '../src/index.js';
import { fixturePath, listFixtureFiles, makeScanContext } from '../../../tests/support/index.js';

/**
 * Runs the source scanner over the shared, read-only
 * tests/fixtures/clean-app tree (owned by feature/sentinel-testing; never
 * modified here). clean-app is the negative control: same shape as
 * vulnerable-app, safe equivalents throughout. The source scanner must stay
 * completely silent on it.
 */
describe('source scanner against tests/fixtures/clean-app (read-only shared fixture)', () => {
  it('scans exactly the two supported source files present in the fixture', () => {
    const root = fixturePath('clean-app');
    const files = listFixtureFiles(root).filter((f) =>
      matchAny(f.relPath, sourceScanner.supportedFiles),
    );
    expect(files.map((f) => f.relPath).sort()).toEqual(['src/safe.js', 'src/safe.py']);
  });

  it('reports zero findings', async () => {
    const root = fixturePath('clean-app');
    const files = listFixtureFiles(root).filter((f) =>
      matchAny(f.relPath, sourceScanner.supportedFiles),
    );
    const ctx = makeScanContext(root, files);

    const findings = await sourceScanner.scan(ctx);
    expect(findings).toEqual([]);
  });
});
