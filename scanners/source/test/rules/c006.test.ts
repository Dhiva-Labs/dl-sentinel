import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C006 weak hashing for credentials', () => {
  it('flags JS crypto.createHash("md5") near a password mention', async () => {
    const findings = await scanOne('c006/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C006');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c006/js-positive.js', line: 7 });
  });

  it('does not flag md5 used as a file checksum with no password context', async () => {
    const findings = await scanOne('c006/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C006')).toHaveLength(0);
  });

  it('flags Python hashlib.md5() near a password mention', async () => {
    const findings = await scanOne('c006/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C006');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c006/py-positive.py', line: 6 });
  });

  it('does not flag hashlib.md5() used as a checksum with no password context', async () => {
    const findings = await scanOne('c006/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C006')).toHaveLength(0);
  });
});
