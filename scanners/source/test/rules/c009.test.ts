import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C009 permissive CORS configuration', () => {
  it('flags a wildcard origin combined with credentials: true as medium severity', async () => {
    const findings = await scanOne('c009/js-wildcard-with-credentials.js');
    const hits = findings.filter((f) => f.ruleId === 'C009');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      file: 'c009/js-wildcard-with-credentials.js',
      line: 10,
      severity: 'medium',
    });
  });

  it('flags a wildcard origin with no credentials nearby as low severity', async () => {
    const findings = await scanOne('c009/js-wildcard-only.js');
    const hits = findings.filter((f) => f.ruleId === 'C009');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      file: 'c009/js-wildcard-only.js',
      line: 8,
      severity: 'low',
    });
  });

  it('does not flag an explicit origin allowlist even with credentials: true', async () => {
    const findings = await scanOne('c009/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C009')).toHaveLength(0);
  });
});
