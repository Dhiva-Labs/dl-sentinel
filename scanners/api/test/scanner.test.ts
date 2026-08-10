import { describe, expect, it } from 'vitest';
import { apiScanner } from '../src/index.js';
import {
  createCapturingLogger,
  findingsFor,
  listAllLocalFixtures,
  localFixture,
  scanFileRefs,
  scanLocalFixture,
  scanLocalFixtures,
  sharedFixture,
} from './helpers.js';

describe('apiScanner plugin shape', () => {
  it('exposes the ScannerPlugin contract', () => {
    expect(apiScanner.id).toBe('api');
    expect(apiScanner.categories).toEqual(['api']);
    expect(apiScanner.supportedFiles.length).toBeGreaterThan(0);
    expect(typeof apiScanner.scan).toBe('function');
  });

  it('declares all ten rules with the required RuleMeta fields', () => {
    const ids = apiScanner.rules.map((r) => r.id).sort();
    expect(ids).toEqual([
      'A001',
      'A002',
      'A003',
      'A004',
      'A005',
      'A006',
      'A007',
      'A008',
      'A009',
      'A010',
    ]);
    for (const rule of apiScanner.rules) {
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.category).toBe('api');
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(rule.severity);
      expect(['high', 'medium', 'low']).toContain(rule.defaultConfidence);
      expect(rule.description.length).toBeGreaterThan(0);
      expect(rule.recommendation.length).toBeGreaterThan(0);
    }
  });
});

describe('parsing robustness', () => {
  it('skips malformed YAML with a logger warning instead of throwing', async () => {
    const { logger, warnings } = createCapturingLogger();
    const findings = await scanLocalFixture(apiScanner, 'malformed/bad.yaml', { logger });
    expect(findings).toHaveLength(0);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('skips malformed JSON with a logger warning instead of throwing', async () => {
    const { logger, warnings } = createCapturingLogger();
    const findings = await scanLocalFixture(apiScanner, 'malformed/bad.json', { logger });
    expect(findings).toHaveLength(0);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('silently ignores a well-formed YAML file that is not an API document', async () => {
    const { logger, warnings } = createCapturingLogger();
    const findings = await scanLocalFixture(apiScanner, 'self-identify/random-config.yaml', {
      logger,
    });
    expect(findings).toHaveLength(0);
    expect(warnings).toHaveLength(0); // not a parse error, so no warning either
  });

  it('self-identifies an API document via its "openapi:" key regardless of filename', async () => {
    const findings = await scanLocalFixture(apiScanner, 'self-identify/weird-name.yml');
    // No security anywhere in this fixture -> the whole-document A001 case must fire,
    // proving the file was actually parsed and scanned as an OpenAPI document.
    expect(findingsFor(findings, 'A001')).toHaveLength(1);
  });
});

describe('every finding carries a qualifier (hard rule for the api scanner)', () => {
  it('sets qualifier on every finding across the full local + shared fixture sweep', async () => {
    const localPaths = (await listAllLocalFixtures()).filter((p) => !p.startsWith('malformed/'));
    const localFindings = await scanLocalFixtures(apiScanner, localPaths);

    const vulnerable = await sharedFixture('tests/fixtures/vulnerable-app/openapi.yaml');
    const clean = await sharedFixture('tests/fixtures/clean-app/openapi.yaml');
    const sharedFindings = await scanFileRefs(apiScanner, [vulnerable, clean]);

    const all = [...localFindings, ...sharedFindings];
    expect(all.length).toBeGreaterThan(0);
    for (const finding of all) {
      expect(['confirmed', 'likely', 'potential']).toContain(finding.qualifier);
    }
  });
});

describe('shared cross-package fixtures (owned by feature/sentinel-testing, read-only)', () => {
  it('flags the expected rule categories on the vulnerable-app fixture', async () => {
    const file = await sharedFixture('tests/fixtures/vulnerable-app/openapi.yaml');
    const findings = await scanFileRefs(apiScanner, [file]);
    const ruleIds = new Set(findings.map((f) => f.ruleId));

    expect(ruleIds.has('A001')).toBe(true); // no effective security on any operation
    expect(ruleIds.has('A002')).toBe(true); // ApiKeyQuery scheme is type apiKey, in query
    expect(ruleIds.has('A003')).toBe(true); // http:// server, non-localhost
    expect(ruleIds.has('A005')).toBe(true); // unauthenticated DELETE /users/{id}
  });

  it('produces zero findings on the clean-app fixture', async () => {
    const file = await sharedFixture('tests/fixtures/clean-app/openapi.yaml');
    const findings = await scanFileRefs(apiScanner, [file]);

    // clean-app declares proper bearer auth (global + every operation), an
    // https server, a documented 429 response (satisfying A007), and response
    // schemas with no sensitive-looking fields. A009 does not fire: the
    // fixture's only parameter is the DELETE's path-level "id", and A009
    // deliberately excludes path identifiers (see src/rules/data-rules.ts)
    // to avoid flooding a finding on every routine REST path.
    expect(findings).toHaveLength(0);
  });
});

describe('determinism', () => {
  it('produces identical findings (content, ids, and order) across repeated scans of the same input', async () => {
    const files = await Promise.all([
      localFixture('a001/schemes-no-global-openapi.yaml'),
      localFixture('a006/sensitive-response-openapi.yaml'),
      localFixture('postman/collection.json'),
      localFixture('a009/unconstrained-openapi.yaml'),
    ]);
    const first = await scanFileRefs(apiScanner, files);
    const second = await scanFileRefs(apiScanner, files);
    expect(second).toEqual(first);
    expect(first.length).toBeGreaterThan(0);
  });
});

describe('cancellation', () => {
  it('throws instead of returning findings when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const files = await Promise.all([localFixture('a001/no-schemes-openapi.yaml')]);
    await expect(scanFileRefs(apiScanner, files, { signal: controller.signal })).rejects.toThrow();
  });
});
