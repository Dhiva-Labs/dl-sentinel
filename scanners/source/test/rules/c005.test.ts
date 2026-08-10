import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C005 path traversal risk', () => {
  it('flags JS fs reads/joins built from req/request identifiers', async () => {
    const findings = await scanOne('c005/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C005');
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.line)).toEqual([7, 11]);
    expect(hits.every((h) => h.severity === 'medium' && h.confidence === 'low')).toBe(true);
  });

  it('does not flag a sanitized basename join or a fixed path', async () => {
    const findings = await scanOne('c005/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C005')).toHaveLength(0);
  });

  it('flags Python open()/os.path.join() built from request/params identifiers', async () => {
    const findings = await scanOne('c005/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C005');
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.line)).toEqual([5, 9]);
  });

  it('does not flag a sanitized basename join or a fixed path in Python', async () => {
    const findings = await scanOne('c005/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C005')).toHaveLength(0);
  });
});
