import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C001 command execution from string building', () => {
  it('flags JS exec() whose command is concatenated from a variable', async () => {
    const findings = await scanOne('c001/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C001');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c001/js-positive.js', line: 7, severity: 'high' });
  });

  it('does not flag execFile with array args or exec with a constant string', async () => {
    const findings = await scanOne('c001/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C001')).toHaveLength(0);
  });

  it('flags Python subprocess.check_output(shell=True) with a concatenated command', async () => {
    const findings = await scanOne('c001/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C001');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c001/py-positive.py', line: 6 });
  });

  it('does not flag a constant shell=True command, or shell=True absent', async () => {
    const findings = await scanOne('c001/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C001')).toHaveLength(0);
  });

  it('flags Ruby backtick command interpolation', async () => {
    const findings = await scanOne('c001/rb-positive.rb');
    const hits = findings.filter((f) => f.ruleId === 'C001');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c001/rb-positive.rb', line: 2 });
  });

  it('does not flag a fixed Ruby backtick command', async () => {
    const findings = await scanOne('c001/rb-negative.rb');
    expect(findings.filter((f) => f.ruleId === 'C001')).toHaveLength(0);
  });
});
