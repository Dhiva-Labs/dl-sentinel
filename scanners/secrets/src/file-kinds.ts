/**
 * File and line classification used to keep the heuristic rules quiet in
 * places where high-entropy strings are normal and harmless.
 */

import { createMatcher } from '@dl-sentinel/core';

/** Files that carry `KEY=value` environment settings. */
const ENV_FILE_PATTERNS: readonly string[] = [
  '**/.env',
  '**/.env.*',
  '**/*.env',
  '**/.envrc',
  '**/env.list',
  '**/environment',
];

/**
 * Files that carry structured configuration. Anything under a `config/`
 * directory counts too, which is how `config/settings.yml` in the shared
 * fixture tree is classified.
 */
const CONFIG_FILE_PATTERNS: readonly string[] = [
  '**/*.yml',
  '**/*.yaml',
  '**/*.json',
  '**/*.json5',
  '**/*.toml',
  '**/*.ini',
  '**/*.cfg',
  '**/*.conf',
  '**/*.config',
  '**/*.properties',
  '**/*.tfvars',
  '**/*.plist',
  '**/config/**',
  '**/configs/**',
  '**/settings/**',
];

/**
 * Generated files where long random-looking strings are expected: dependency
 * lockfiles (integrity hashes), minified bundles, snapshots. Structured token
 * rules still run here — a real `ghp_…` token committed inside a lockfile is
 * still a leak — but entropy and name-based rules do not.
 */
const NOISY_FILE_PATTERNS: readonly string[] = [
  '**/package-lock.json',
  '**/npm-shrinkwrap.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  '**/bun.lock',
  '**/bun.lockb',
  '**/Cargo.lock',
  '**/go.sum',
  '**/Gemfile.lock',
  '**/composer.lock',
  '**/poetry.lock',
  '**/Pipfile.lock',
  '**/*.lock',
  '**/*.min.*',
  '**/*.map',
  '**/*.snap',
  '**/*.bundle.js',
];

const matchEnvFile = createMatcher(ENV_FILE_PATTERNS);
const matchConfigFile = createMatcher(CONFIG_FILE_PATTERNS);
const matchNoisyFile = createMatcher(NOISY_FILE_PATTERNS);

export function isEnvLikeFile(relPath: string): boolean {
  return matchEnvFile(relPath);
}

export function isConfigLikeFile(relPath: string): boolean {
  return matchConfigFile(relPath);
}

export function isNoisyFile(relPath: string): boolean {
  return matchNoisyFile(relPath);
}

/** Subresource-integrity / checksum lines, wherever they appear. */
const INTEGRITY_LINE = /(^|[^A-Za-z])(integrity|checksum|resolved|sha512-|sha384-|sha256-|sha1-)/i;

/** A long hex blob next to a word that explains it is a digest, not a secret. */
const HASH_CONTEXT_LINE =
  /\b(sha|sha1|sha256|sha512|commit|revision|rev|digest|hash|checksum|etag|fingerprint|githead|blob|tree|oid)\b[^\n]{0,24}\b[0-9a-f]{32,}\b/i;

/**
 * True for lines whose high-entropy content is a hash or an integrity value.
 * Consulted by the entropy/context rules, never by the vendor-format rules.
 */
export function isNoisyLine(line: string): boolean {
  return INTEGRITY_LINE.test(line) || HASH_CONTEXT_LINE.test(line);
}
