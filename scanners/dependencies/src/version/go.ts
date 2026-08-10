/**
 * Minimal, conservative Go module version support. go.mod always names a
 * single version token per require (Minimal Version Selection has no range
 * syntax), so this only ever needs to parse one version, never a range.
 */

export interface GoVersion {
  major: number;
  minor: number;
  patch: number;
}

// v1.2.3, optionally with the "+incompatible" build tag Go appends for
// pre-modules major versions. No prerelease suffix allowed here.
const PLAIN_RE = /^v(\d+)\.(\d+)\.(\d+)(?:\+incompatible)?$/;

// Go pseudo-version: vX.Y.Z-yyyymmddhhmmss-abcdef123456, or the pre-release
// form vX.Y.Z-0.yyyymmddhhmmss-abcdef123456 used just before tag X.Y.Z.
const PSEUDO_RE = /^v(\d+)\.(\d+)\.(\d+)-(?:0\.)?\d{14}-[0-9a-f]{12}(?:\+incompatible)?$/;

/**
 * Strip the leading `v` and parse the base `X.Y.Z`. Pseudo-versions compare
 * by their base version only (the commit/date suffix carries no ordering
 * information we can use safely). Anything else — an ordinary prerelease tag
 * like `v1.2.3-beta.1`, a missing `v` prefix, a malformed token — returns
 * `null`, so the caller treats it as unclear rather than guess.
 */
export function parseGoVersion(input: string): GoVersion | null {
  const trimmed = input.trim();
  const plain = PLAIN_RE.exec(trimmed);
  if (plain) {
    return { major: Number(plain[1]), minor: Number(plain[2]), patch: Number(plain[3]) };
  }
  const pseudo = PSEUDO_RE.exec(trimmed);
  if (pseudo) {
    return { major: Number(pseudo[1]), minor: Number(pseudo[2]), patch: Number(pseudo[3]) };
  }
  return null;
}

export function compareGoVersion(a: GoVersion, b: GoVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}
