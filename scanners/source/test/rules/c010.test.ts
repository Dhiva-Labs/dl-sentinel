import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C010 world-writable file modes', () => {
  it('flags JS fs.chmodSync(path, 0o777)', async () => {
    const findings = await scanOne('c010/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C010');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      file: 'c010/js-positive.js',
      line: 6,
      severity: 'medium',
      confidence: 'high',
    });
  });

  it('does not flag a narrow mode like 0o644', async () => {
    const findings = await scanOne('c010/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C010')).toHaveLength(0);
  });

  it('flags Python os.chmod(path, 0o777)', async () => {
    const findings = await scanOne('c010/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C010');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c010/py-positive.py', line: 5 });
  });

  it('does not flag os.chmod(path, 0o644)', async () => {
    const findings = await scanOne('c010/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C010')).toHaveLength(0);
  });
});
