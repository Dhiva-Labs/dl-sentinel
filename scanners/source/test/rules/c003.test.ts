import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C003 SQL built from strings', () => {
  it('flags JS db.query() built from concatenation next to SQL keywords', async () => {
    const findings = await scanOne('c003/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C003');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c003/js-positive.js', line: 5 });
  });

  it('does not flag a parameterized query or a concatenated non-SQL query', async () => {
    const findings = await scanOne('c003/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C003')).toHaveLength(0);
  });

  it('flags Python cursor.execute() built from concatenation next to SQL keywords', async () => {
    const findings = await scanOne('c003/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C003');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c003/py-positive.py', line: 3 });
  });

  it('does not flag a %s-parameterized execute() or a concatenated non-SQL execute()', async () => {
    const findings = await scanOne('c003/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C003')).toHaveLength(0);
  });
});
