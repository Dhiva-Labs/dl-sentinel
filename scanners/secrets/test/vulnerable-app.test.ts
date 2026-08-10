import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Finding } from '@dl-sentinel/core';
import secretsScanner from '@dl-sentinel/scanner-secrets';
import { listTextFiles, makeContext, recordingLogger, SHARED_FIXTURE_ROOT } from './helpers.js';
// The shared fixture registry is the source of truth for what is planted in
// tests/fixtures/vulnerable-app; it is read-only from this package's point of
// view (tests/ is owned by another branch).
import { PLANTED_SECRETS } from '../../../tests/support/planted-secrets.js';

const VULNERABLE_APP = join(SHARED_FIXTURE_ROOT, 'vulnerable-app');
const CLEAN_APP = join(SHARED_FIXTURE_ROOT, 'clean-app');
const MALFORMED = join(SHARED_FIXTURE_ROOT, 'malformed');

/**
 * Which rule is expected to cover each registered planted value. The private
 * key body line is covered by the PEM rule, which reports the BEGIN line and
 * spans the block — so it is matched by line range rather than by position.
 */
const EXPECTED_RULE: Record<string, string> = {
  'aws-access-key-id': 'S001',
  'aws-secret-access-key': 'S002',
  'database-url-password': 'S018',
  'github-token': 'S003',
  'private-key-body-line': 'S017',
  'npm-token': 'S013',
};

async function scanTree(dir: string): Promise<Finding[]> {
  return secretsScanner.scan(makeContext(dir, listTextFiles(dir)));
}

describe('the shared vulnerable-app fixture', () => {
  it('detects every secret registered in tests/support/planted-secrets.ts', async () => {
    const findings = await scanTree(VULNERABLE_APP);

    for (const planted of PLANTED_SECRETS) {
      const expectedRule = EXPECTED_RULE[planted.id];
      expect(expectedRule, `no expected rule mapped for ${planted.id}`).toBeDefined();

      const covering = findings.filter(
        (finding) => finding.file === planted.file && finding.ruleId === expectedRule,
      );
      expect(covering.length, `${planted.id} (${planted.file}) was not detected`).toBeGreaterThan(
        0,
      );
    }
  });

  it('covers the private key body line inside the block it reports', async () => {
    const findings = await scanTree(VULNERABLE_APP);
    const planted = PLANTED_SECRETS.find((secret) => secret.id === 'private-key-body-line');
    expect(planted).toBeDefined();

    const pem = findings.find(
      (finding) => finding.ruleId === 'S017' && finding.file === planted?.file,
    );
    expect(pem).toBeDefined();
    expect(pem?.evidence).toBe('-----BEGIN RSA PRIVATE KEY-----');

    // The registered body line must fall inside the reported block.
    const bodyLine = fixtureLineOf(planted?.value ?? '', planted?.file ?? '');
    expect(pem?.line).toBeLessThan(bodyLine);
    expect(pem?.endLine ?? 0).toBeGreaterThan(bodyLine);
  });

  it('never leaks a registered planted value into any finding', async () => {
    const findings = await scanTree(VULNERABLE_APP);
    const serialized = JSON.stringify(findings);
    for (const planted of PLANTED_SECRETS) {
      expect(serialized, `${planted.id} leaked into the findings`).not.toContain(planted.value);
    }
  });

  it('never leaks a registered planted value into a log line', async () => {
    const { logger, messages } = recordingLogger();
    await secretsScanner.scan(
      makeContext(VULNERABLE_APP, listTextFiles(VULNERABLE_APP), {}, logger),
    );
    const logged = messages.join('\n');
    for (const planted of PLANTED_SECRETS) {
      expect(logged, `${planted.id} was logged`).not.toContain(planted.value);
    }
  });

  it('reports only the files that actually carry credentials', async () => {
    const findings = await scanTree(VULNERABLE_APP);
    const files = [...new Set(findings.map((finding) => finding.file))].sort();
    expect(files).toEqual(['.env', 'Dockerfile', 'config/settings.yml', 'docker-compose.yml']);
    for (const finding of findings) {
      expect(finding.evidence.length).toBeLessThanOrEqual(200);
      expect(finding.scanner).toBe('secrets');
    }
  });
});

describe('the shared negative-control fixtures', () => {
  it('stays silent on clean-app', async () => {
    await expect(scanTree(CLEAN_APP)).resolves.toEqual([]);
  });

  it('stays silent, and does not crash, on malformed inputs', async () => {
    await expect(scanTree(MALFORMED)).resolves.toEqual([]);
  });
});

/** 1-based line number of `value` inside a vulnerable-app fixture file. */
function fixtureLineOf(value: string, relPath: string): number {
  const files = listTextFiles(VULNERABLE_APP);
  const file = files.find((candidate) => candidate.relPath === relPath);
  expect(file, `fixture file ${relPath} not found`).toBeDefined();
  const text = readFileSync(file?.absPath ?? '', 'utf8');
  const index = text.split(/\r?\n/).findIndex((line) => line.includes(value));
  expect(index, `planted value not found in ${relPath}`).toBeGreaterThanOrEqual(0);
  return index + 1;
}
