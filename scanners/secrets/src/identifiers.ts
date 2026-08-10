/**
 * Identifier analysis for the name-based rules (S021, S022).
 *
 * Keys are split into segments on `_ - . /` and camelCase boundaries, then
 * matched against exact segment names and adjacent segment pairs. Segment
 * matching rather than substring matching is what keeps `AUTHOR_NAME` and
 * `authorEmail` out of the results while still catching `AUTH_TOKEN` and
 * `authToken`.
 */

/** Split `AWS_SECRET_ACCESS_KEY` / `clientSecret` into upper-case segments. */
export function identifierSegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+|\s+/)
    .filter((segment) => segment !== '')
    .map((segment) => segment.toUpperCase());
}

/** Segments that on their own mean "this holds a credential". */
const SENSITIVE_SEGMENTS: ReadonlySet<string> = new Set([
  'PASSWORD',
  'PASSWORDS',
  'PASSWD',
  'PWD',
  'PASSPHRASE',
  'SECRET',
  'SECRETS',
  'TOKEN',
  'APIKEY',
  'APIKEYS',
  'APISECRET',
  'AUTH',
  'CREDENTIAL',
  'CREDENTIALS',
  'CREDS',
  'ACCESSTOKEN',
  'AUTHTOKEN',
  'SECRETKEY',
  'PRIVATEKEY',
  'CLIENTSECRET',
]);

/** Adjacent segment pairs that together mean "this holds a credential". */
const SENSITIVE_PAIRS: readonly (readonly [string, string])[] = [
  ['API', 'KEY'],
  ['API', 'SECRET'],
  ['APP', 'SECRET'],
  ['ACCESS', 'TOKEN'],
  ['AUTH', 'TOKEN'],
  ['BEARER', 'TOKEN'],
  ['CLIENT', 'SECRET'],
  ['ENCRYPTION', 'KEY'],
  ['PRIVATE', 'KEY'],
  ['SECRET', 'KEY'],
  ['SESSION', 'KEY'],
  ['SIGNING', 'KEY'],
  ['REFRESH', 'TOKEN'],
];

/**
 * True when an identifier names credential material.
 *
 * Shared by the `.env`/config assignment rule and the entropy rule so both use
 * the same definition of "sensitive name".
 */
export function isSensitiveIdentifier(name: string): boolean {
  const segments = identifierSegments(name);
  if (segments.some((segment) => SENSITIVE_SEGMENTS.has(segment))) return true;
  for (let index = 0; index + 1 < segments.length; index += 1) {
    const first = segments[index];
    const second = segments[index + 1];
    if (first === undefined || second === undefined) continue;
    if (SENSITIVE_PAIRS.some(([a, b]) => a === first && b === second)) return true;
  }
  return false;
}
