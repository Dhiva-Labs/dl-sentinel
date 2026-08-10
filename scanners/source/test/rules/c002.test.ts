import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C002 eval / dynamic code execution', () => {
  it('flags JS eval() and new Function() unconditionally', async () => {
    const findings = await scanOne('c002/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C002');
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.line)).toEqual([4, 8]);
  });

  it('does not flag JSON.parse, a function named evaluate, or an unrelated Function binding', async () => {
    const findings = await scanOne('c002/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C002')).toHaveLength(0);
  });

  it('flags Python eval()/exec() on a non-literal argument', async () => {
    const findings = await scanOne('c002/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C002');
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.line)).toEqual([2, 6]);
  });

  it('does not flag Python eval()/exec() on a literal argument', async () => {
    const findings = await scanOne('c002/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C002')).toHaveLength(0);
  });

  it('flags PHP eval() unconditionally', async () => {
    const findings = await scanOne('c002/php-positive.php');
    const hits = findings.filter((f) => f.ruleId === 'C002');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c002/php-positive.php', line: 4 });
  });

  it('does not flag the word "eval" outside of a call', async () => {
    const findings = await scanOne('c002/php-negative.php');
    expect(findings.filter((f) => f.ruleId === 'C002')).toHaveLength(0);
  });
});
