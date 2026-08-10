/**
 * Registry of every fake secret value planted in
 * tests/fixtures/vulnerable-app/, for reuse by core tests, security
 * regression tests, and (eventually) scanner test suites that want to
 * confirm they detect — and redact — these exact values.
 *
 * Every value here is synthetic: see tests/fixtures/README.md for the
 * conventions (vendor-documented example credentials where they exist,
 * otherwise an EXAMPLE/FAKE marker embedded in the value). Do not add a
 * value here that could pass for a real credential.
 */

export interface PlantedSecret {
  /** Short stable identifier for the planted value. */
  id: string;
  /** The exact fake value as it appears in the fixture file. */
  value: string;
  /** Path of the fixture file it's planted in, relative to vulnerable-app/. */
  file: string;
  /** What kind of credential this stands in for. */
  description: string;
}

export const PLANTED_SECRETS: readonly PlantedSecret[] = [
  {
    id: 'aws-access-key-id',
    value: 'AKIAIOSFODNN7EXAMPLE',
    file: '.env',
    description: "AWS's own vendor-documented example access key id.",
  },
  {
    id: 'aws-secret-access-key',
    value: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    file: '.env',
    description: "AWS's own vendor-documented example secret access key.",
  },
  {
    id: 'database-url-password',
    value: 'hunter2EXAMPLEPASSWORD',
    file: '.env',
    description: 'Fake password embedded in a postgres:// connection string (DATABASE_URL).',
  },
  {
    id: 'github-token',
    value: 'ghp_EXAMPLEEXAMPLEEXAMPLE0000000000000000',
    file: 'config/settings.yml',
    description: 'Fake GitHub personal access token (ghp_ prefix).',
  },
  {
    id: 'private-key-body-line',
    value: 'FAKEKEYEXAMPLEFAKEKEYEXAMPLEFAKEKEYEXAMPLEFAKEKEYEXAMPLEFAKEKEY',
    file: 'config/settings.yml',
    description: 'A body line from the fake RSA private key block (tls.private_key).',
  },
  {
    id: 'npm-token',
    value: 'npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE00',
    file: 'Dockerfile',
    description: 'Fake npm publish token (npm_ prefix), planted in an ENV instruction.',
  },
];

/** Just the fake values, for callers that only need the denylist. */
export const PLANTED_SECRET_VALUES: readonly string[] = PLANTED_SECRETS.map((s) => s.value);
