import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C004 insecure deserialization', () => {
  it('flags Python pickle.loads() unconditionally', async () => {
    const findings = await scanOne('c004/py-pickle-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C004');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      file: 'c004/py-pickle-positive.py',
      line: 5,
      severity: 'high',
      confidence: 'high',
    });
  });

  it('does not flag json.loads()', async () => {
    const findings = await scanOne('c004/py-pickle-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C004')).toHaveLength(0);
  });

  it('flags Python yaml.load() without a Loader= kwarg', async () => {
    const findings = await scanOne('c004/py-yaml-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C004');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c004/py-yaml-positive.py', line: 5 });
  });

  it('does not flag yaml.load(..., Loader=...) or yaml.safe_load()', async () => {
    const findings = await scanOne('c004/py-yaml-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C004')).toHaveLength(0);
  });

  it('flags Ruby Marshal.load() on a non-literal argument', async () => {
    const findings = await scanOne('c004/rb-positive.rb');
    const hits = findings.filter((f) => f.ruleId === 'C004');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c004/rb-positive.rb', line: 2 });
  });

  it('does not flag Ruby Marshal.load() on a literal argument', async () => {
    const findings = await scanOne('c004/rb-negative.rb');
    expect(findings.filter((f) => f.ruleId === 'C004')).toHaveLength(0);
  });

  it('flags PHP unserialize() on a non-literal argument', async () => {
    const findings = await scanOne('c004/php-positive.php');
    const hits = findings.filter((f) => f.ruleId === 'C004');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c004/php-positive.php', line: 4 });
  });

  it('does not flag PHP unserialize() on a literal argument', async () => {
    const findings = await scanOne('c004/php-negative.php');
    expect(findings.filter((f) => f.ruleId === 'C004')).toHaveLength(0);
  });
});
