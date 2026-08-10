/**
 * Placeholder and reference detection — the scanner's main false-positive
 * control.
 *
 * Two independent levels, deliberately applied to different rule tiers:
 *
 * 1. `isNonSecretReference()` — the value is structurally not a credential at
 *    all: an interpolation (`${VAR}`, `{{var}}`, `%s`), an env-var lookup
 *    (`process.env.X`, `os.environ["X"]`), an angle-bracket slot (`<password>`),
 *    or a self-evident dummy word (`password`, `changeme`). Applied to EVERY
 *    rule, structured ones included: `postgres://user:${DB_PASSWORD}@host`
 *    contains no credential no matter how well-formed the URL is.
 *
 * 2. `hasPlaceholderMarker()` — the value carries a documentation marker
 *    (EXAMPLE, SAMPLE, PLACEHOLDER, CHANGEME, YOUR_, XXXX, TODO, DUMMY).
 *    Applied ONLY to the heuristic tier (S021 sensitive assignment, S022
 *    entropy).
 *
 * ## Why marker suppression stops at the structured tier
 *
 * The shared fixture registry (tests/support/planted-secrets.ts) deliberately
 * uses AWS's documented example credentials (`AKIAIOSFODNN7EXAMPLE`,
 * `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) and EXAMPLE-marked tokens
 * (`ghp_EXAMPLE…`) so the fixtures are safely fake. Marker suppression applied
 * to those rules would suppress exactly the values the scanner exists to find.
 *
 * The resolution taken here is the second option offered in the scanner's
 * brief: a format-valid `AKIA…` key is a finding even when it ends in EXAMPLE.
 * Rationale beyond the fixtures — a leaked credential does not stop being
 * leaked because someone typed EXAMPLE into it, the AWS example key is a real
 * (revoked) key shape that appears verbatim in copy-pasted deployment configs,
 * and a scanner that trusts attacker- or author-supplied markers inside the
 * value can be silenced by adding "EXAMPLE" to a live key. Deployments that
 * genuinely carry known-fake values suppress them explicitly through
 * `scanners.secrets.allowlist` (exact values or rule ids), which is the
 * reviewed, auditable way to say "this one is fine".
 *
 * Name-and-entropy rules get the opposite treatment because there the marker is
 * the strongest signal available: `API_KEY=YOUR_API_KEY_HERE` has no format to
 * fall back on.
 *
 * FAKE / TEST markers are NOT treated as placeholders. They are this repo's
 * fixture-marking convention (tests/fixtures/README.md), not a convention real
 * codebases use for "no credential here", so suppressing them would trade real
 * detections for nothing.
 */

/** Documentation markers that mean "fill this in", checked case-insensitively. */
const PLACEHOLDER_MARKERS: readonly string[] = [
  'example',
  'sample',
  'placeholder',
  'changeme',
  'change_me',
  'change-me',
  'replaceme',
  'replace_me',
  'replace-me',
  'your_',
  'your-',
  'yourkey',
  'yourtoken',
  'yoursecret',
  'yourpassword',
  'xxxx',
  'todo',
  'dummy',
  'insert_',
  'insert-',
  'notset',
  'not_set',
  'redacted',
  'omitted',
];

/** Values that are self-evidently a stand-in rather than a credential. */
const DUMMY_VALUES: ReadonlySet<string> = new Set([
  'password',
  'passwd',
  'pass',
  'secret',
  'token',
  'apikey',
  'api_key',
  'key',
  'value',
  'string',
  'none',
  'null',
  'nil',
  'undefined',
  'empty',
  'user',
  'username',
  'admin',
  'root',
  'test',
  'changeit',
  'letmein',
  'hunter2',
]);

/** Interpolations, env lookups, and template slots — never literal secrets. */
const REFERENCE_PATTERNS: readonly RegExp[] = [
  /\$\{[^}]*\}/, // ${VAR}, ${env:VAR}
  /\{\{[^}]*\}\}/, // {{ var }}
  /\{[a-z_][a-z0-9_]*\}/i, // {password} (python str.format)
  /<[^>]*>/, // <your-password>
  /%\([a-z_][a-z0-9_]*\)[sd]/i, // %(password)s
  /%[sdv]\b|%s$|%d$/, // %s, %d
  /\$\([^)]*\)/, // $(command)
  /^\$[A-Za-z_][A-Za-z0-9_]*$/, // $VAR
  /\bprocess\.env\b/, // process.env.X
  /\bos\.environ\b|\bos\.getenv\b/, // os.environ["X"] / os.getenv("X")
  /\bSystem\.getenv\b/,
  /\bEnvironment\.GetEnvironmentVariable\b/,
  /^env[:.]/i, // env:VAR / env.VAR
  /^\*+$/, // ****
  /^x+$/i, // xxxxxxxx
  /^\.+$/, // ......
  /^0+$/, // 0000
];

/**
 * True when the value is a reference, a template slot, or a self-evident dummy
 * rather than credential material. Applies to every rule, every tier.
 */
export function isNonSecretReference(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === '') return true;
  const lower = trimmed.toLowerCase();
  if (DUMMY_VALUES.has(lower)) return true;
  return REFERENCE_PATTERNS.some((pattern) => pattern.test(trimmed));
}

/**
 * True when the value carries a documentation placeholder marker. Only the
 * heuristic tier consults this — see the module comment for why.
 */
export function hasPlaceholderMarker(value: string): boolean {
  const lower = value.toLowerCase();
  return PLACEHOLDER_MARKERS.some((marker) => lower.includes(marker));
}

/**
 * Combined suppression for the heuristic tier: references, dummies, and
 * documentation markers all mean "not a finding".
 */
export function isPlaceholder(value: string): boolean {
  return isNonSecretReference(value) || hasPlaceholderMarker(value);
}
