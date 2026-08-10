import { describe, expect, it } from 'vitest';
import { sourceScanner } from '../../src/index.js';
import { makeScanContext } from '../../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from '../testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

describe('C008 TLS certificate verification disabled', () => {
  it('flags JS rejectUnauthorized: false', async () => {
    const findings = await scanOne('c008/js-positive.js');
    const hits = findings.filter((f) => f.ruleId === 'C008');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      file: 'c008/js-positive.js',
      line: 6,
      severity: 'high',
      confidence: 'high',
    });
  });

  it('does not flag rejectUnauthorized: true or the default (omitted) option', async () => {
    const findings = await scanOne('c008/js-negative.js');
    expect(findings.filter((f) => f.ruleId === 'C008')).toHaveLength(0);
  });

  it('flags Python requests verify=False', async () => {
    const findings = await scanOne('c008/py-positive.py');
    const hits = findings.filter((f) => f.ruleId === 'C008');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c008/py-positive.py', line: 5 });
  });

  it('does not flag verify=True or the default (omitted) option', async () => {
    const findings = await scanOne('c008/py-negative.py');
    expect(findings.filter((f) => f.ruleId === 'C008')).toHaveLength(0);
  });

  it('flags Go InsecureSkipVerify: true', async () => {
    const findings = await scanOne('c008/go-positive.go');
    const hits = findings.filter((f) => f.ruleId === 'C008');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c008/go-positive.go', line: 10 });
  });

  it('does not flag a Go client with no TLS override', async () => {
    const findings = await scanOne('c008/go-negative.go');
    expect(findings.filter((f) => f.ruleId === 'C008')).toHaveLength(0);
  });

  it('flags PHP CURLOPT_SSL_VERIFYPEER, false', async () => {
    const findings = await scanOne('c008/php-positive.php');
    const hits = findings.filter((f) => f.ruleId === 'C008');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: 'c008/php-positive.php', line: 5 });
  });

  it('does not flag PHP CURLOPT_SSL_VERIFYPEER, true', async () => {
    const findings = await scanOne('c008/php-negative.php');
    expect(findings.filter((f) => f.ruleId === 'C008')).toHaveLength(0);
  });
});
