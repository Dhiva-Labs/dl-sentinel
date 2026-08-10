import { createHash, timingSafeEqual } from 'node:crypto';

function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/**
 * Constant-time, length-safe token comparison. Both tokens are hashed to
 * fixed-length digests before comparison, so `timingSafeEqual` never throws on
 * a length mismatch and the comparison leaks neither the token's length nor a
 * matching prefix through timing.
 */
export function tokenMatches(provided: string, expected: string): boolean {
  return timingSafeEqual(sha256(provided), sha256(expected));
}

/**
 * A short, non-reversible identifier for a token, used in the audit log. It is
 * a prefix of the token's SHA-256 hash — never the token itself.
 */
export function tokenId(token: string): string {
  return sha256(token).toString('hex').slice(0, 12);
}

/** Extract the credential from an `Authorization: Bearer <token>` header. */
export function extractBearer(header: string | undefined): string | undefined {
  if (header === undefined) return undefined;
  const match = /^Bearer[\t ]+(.+)$/i.exec(header.trim());
  if (match === null) return undefined;
  const token = match[1];
  if (token === undefined) return undefined;
  const trimmed = token.trim();
  return trimmed === '' ? undefined : trimmed;
}
