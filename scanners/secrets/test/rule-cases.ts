import type { Confidence, Severity } from '@dl-sentinel/core';

/**
 * One row per rule: the fixture that must trigger it, the look-alike fixture
 * that must not, and the exact fake values planted in the positive fixture.
 *
 * The values are duplicated here on purpose — the no-leak assertions need the
 * raw strings, and reading them out of the fixture would let a fixture edit
 * silently weaken the test.
 *
 * Every value follows tests/fixtures/README.md: AWS's vendor-documented
 * example credentials where they exist, otherwise an EXAMPLE / FAKE marker
 * embedded in the value itself.
 */
export interface RuleCase {
  ruleId: string;
  /** Fixture directory, relative to test/fixtures/. */
  dir: string;
  positive: string;
  negative: string;
  severity: Severity;
  confidence: Confidence;
  /** 1-based lines of the positive fixture that must be reported. */
  lines: number[];
  /** Raw fake values planted in the positive fixture. */
  secrets: string[];
  /**
   * False for rules whose evidence carries no secret material to replace. Only
   * S017 qualifies: its evidence is the PEM BEGIN marker line, and key material
   * is never read into the finding in the first place.
   */
  evidenceMarker?: boolean;
}

export const RULE_CASES: readonly RuleCase[] = [
  {
    ruleId: 'S001',
    dir: 's001-aws-access-key-id',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['AKIAIOSFODNN7EXAMPLE'],
  },
  {
    ruleId: 'S002',
    dir: 's002-aws-secret-access-key',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
  },
  {
    ruleId: 'S003',
    dir: 's003-github-token',
    positive: 'positive.yml',
    negative: 'negative.yml',
    severity: 'critical',
    confidence: 'high',
    lines: [3, 4],
    secrets: [
      'ghp_EXAMPLEEXAMPLEEXAMPLE0000000000000000',
      'github_pat_11EXAMPLE0000000000_EXAMPLEEXAMPLEEXAMPLE00000000',
    ],
  },
  {
    ruleId: 'S004',
    dir: 's004-gitlab-token',
    positive: 'positive.yml',
    negative: 'negative.yml',
    severity: 'critical',
    confidence: 'high',
    lines: [3],
    secrets: ['glpat-EXAMPLEEXAMPLE00000000'],
  },
  {
    ruleId: 'S005',
    dir: 's005-slack-token',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['xoxb-EXAMPLE-EXAMPLE-EXAMPLEFAKETOKEN00'],
  },
  {
    ruleId: 'S006',
    dir: 's006-slack-webhook',
    positive: 'positive.yml',
    negative: 'negative.yml',
    severity: 'critical',
    confidence: 'high',
    lines: [3],
    secrets: ['EXAMPLEfakewebhookpath0000'],
  },
  {
    ruleId: 'S007',
    dir: 's007-stripe-live-key',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2, 3],
    secrets: ['sk_live_EXAMPLEfake', 'rk_live_EXAMPLEfake'],
  },
  {
    ruleId: 'S008',
    dir: 's008-stripe-test-key',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'medium',
    confidence: 'high',
    lines: [2],
    secrets: ['sk_test_EXAMPLEfake'],
  },
  {
    ruleId: 'S009',
    dir: 's009-google-api-key',
    positive: 'positive.js',
    negative: 'negative.js',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['AIzaSyEXAMPLE0000EXAMPLE0000EXAMPLE0000'],
  },
  {
    ruleId: 'S010',
    dir: 's010-twilio-api-key',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['SKdeadbeefdeadbeefdeadbeefdeadbeef'],
  },
  {
    ruleId: 'S011',
    dir: 's011-twilio-account',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2, 3],
    secrets: ['ACdeadbeefdeadbeefdeadbeefdeadbeef', 'facefeedfacefeedfacefeedfacefeed'],
  },
  {
    ruleId: 'S012',
    dir: 's012-sendgrid-key',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['SG.EXAMPLEEXAMPLE0000.EXAMPLEEXAMPLEEXAMPLEFAKE00'],
  },
  {
    ruleId: 'S013',
    dir: 's013-npm-token',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE00'],
  },
  {
    ruleId: 'S014',
    dir: 's014-openai-key',
    positive: 'positive.js',
    negative: 'negative.js',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['sk-FAKE1a2b3c4d5e6f7g8h9iJKLMNOP'],
  },
  {
    ruleId: 'S015',
    dir: 's015-azure-storage-key',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2],
    secrets: ['EXAMPLEFAKEACCOUNTKEYEXAMPLEFAKE0000=='],
  },
  {
    ruleId: 'S016',
    dir: 's016-azure-sas-token',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'high',
    confidence: 'high',
    lines: [2],
    secrets: ['EXAMPLEfakesignature0000EXAMPLE%3D'],
  },
  {
    ruleId: 'S017',
    dir: 's017-private-key',
    positive: 'positive.pem',
    negative: 'negative.pem',
    severity: 'critical',
    confidence: 'high',
    lines: [1],
    evidenceMarker: false,
    secrets: [
      'FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYEXAMPLE',
      'FAKEKEYEXAMPLEFAKEKEYEXAMPLEFAKEKEYEXAMPLEFAKEKEYEXAMPLEFAKEKEY',
      'EXAMPLEONLYNOTAREALPRIVATEKEYDONOTUSEEXAMPLEDATAFAKEKEYEXAMPLE',
    ],
  },
  {
    ruleId: 'S018',
    dir: 's018-database-url',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'critical',
    confidence: 'high',
    lines: [2, 3, 4, 5, 6],
    secrets: [
      's3cretEXAMPLEpassw0rd',
      'r00tEXAMPLEpassw0rd',
      'm0ngoEXAMPLEpassw0rd',
      'r3disEXAMPLEpassw0rd',
      'br0kerEXAMPLEpassw0rd',
    ],
  },
  {
    ruleId: 'S019',
    dir: 's019-basic-auth-url',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'high',
    confidence: 'high',
    lines: [2],
    secrets: ['s3cretEXAMPLEt0ken'],
  },
  {
    ruleId: 'S020',
    dir: 's020-jwt',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'medium',
    confidence: 'medium',
    lines: [2],
    secrets: [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFWEFNUExFLUZJWFRVUkUiLCJuYW1lIjoiRml4dHVyZSBVc2VyIiwiaWF0IjowfQ.EXAMPLEfakesignature0000EXAMPLE',
    ],
  },
  {
    ruleId: 'S021',
    dir: 's021-sensitive-assignment',
    positive: 'positive.env',
    negative: 'negative.env',
    severity: 'high',
    confidence: 'high',
    lines: [2, 3],
    secrets: ['zQ8vLm2ZrK9tFAKEbXw4Nc8Jd', 'hunter2FAKEpassw0rd'],
  },
  {
    ruleId: 'S022',
    dir: 's022-high-entropy-assignment',
    positive: 'positive.js',
    negative: 'negative.js',
    severity: 'high',
    confidence: 'medium',
    lines: [3],
    secrets: ['qP7vLm2ZrK9tFAKEbXw4Nc8Jd'],
  },
];

/** Fake values planted in the behaviour fixtures (outside the per-rule table). */
export const BEHAVIOUR_SECRETS: readonly string[] = [
  'ghp_FAKEFAKEFAKEFAKE111111111111111111111',
  'FAKEKEYEXAMPLEFAKEKEYEXAMPLEFAKEKEYEXAMPLE',
  'EXAMPLEONLYNOTAREALPRIVATEKEYFAKEKEY',
];

/** Every fake value this package plants anywhere under test/fixtures/. */
export const ALL_FIXTURE_SECRETS: readonly string[] = [
  ...new Set([...RULE_CASES.flatMap((rule) => rule.secrets), ...BEHAVIOUR_SECRETS]),
];

export function fixtureFile(rule: RuleCase, which: 'positive' | 'negative'): string {
  return `${rule.dir}/${which === 'positive' ? rule.positive : rule.negative}`;
}
