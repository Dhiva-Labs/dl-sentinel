import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C007 insecure randomness for secrets', () => {
  it('flags JS Math.random() near a session token mention', async () => {
    const findings = await scanOne('c007/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C007');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c007/js-positive.js', line: 5 });
  });

  it('does not flag Math.random() used for UI/sampling with no secret context', async () => {
    const findings = await scanOne('c007/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C007')).toHaveLength(0);
  });

  it('flags Python random.randint() near an OTP/password mention', async () => {
    const findings = await scanOne('c007/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C007');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c007/py-positive.py', line: 6 });
  });

  it('does not flag random.randint() used for sampling with no secret context', async () => {
    const findings = await scanOne('c007/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C007')).toHaveLength(0);
  });
});
