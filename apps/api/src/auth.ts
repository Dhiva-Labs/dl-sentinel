import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AuthContext, UserRecord } from './types.js';

function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/**
 * The caller id recorded for the bootstrap token (`SENTINEL_API_TOKEN`, or the
 * generated one). Root is a role, not a stored record: it is always `admin`, is
 * never listed by `GET /api/users`, and cannot be patched or deleted — which is
 * what keeps every existing single-token deployment working unchanged.
 */
export const ROOT_USER_ID = 'root';

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

/**
 * The SHA-256 hex digest of a token — the only form in which a user token is
 * ever persisted. Deliberately one-way: a stored hash can neither be logged as
 * a credential nor turned back into the token it came from.
 */
export function hashToken(token: string): string {
  return sha256(token).toString('hex');
}

/**
 * Mint a new user token: 32 cryptographically random bytes, hex-encoded. The
 * caller returns this to the client exactly once (create/rotate) and stores only
 * {@link hashToken} of it.
 */
export function generateUserToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Resolve a presented bearer token to its caller.
 *
 * The bootstrap token is checked first and yields the root admin, so a
 * single-token deployment behaves exactly as it did before users existed.
 * Otherwise the token is hashed once and that digest is compared against every
 * user's stored hash with the same constant-time, length-safe comparison — the
 * loop deliberately runs to completion rather than returning early, so the work
 * does not depend on where in the list a token matches. A disabled user
 * resolves to `undefined` (a 401, exactly like a deleted one).
 *
 * @returns the caller, or `undefined` when the token matches nothing usable.
 */
export function resolveAuth(
  provided: string,
  rootToken: string,
  users: readonly UserRecord[],
): AuthContext | undefined {
  if (tokenMatches(provided, rootToken)) {
    return { userId: ROOT_USER_ID, name: ROOT_USER_ID, role: 'admin' };
  }
  const providedHash = hashToken(provided);
  let matched: UserRecord | undefined;
  for (const user of users) {
    // tokenMatches() hashes both sides again, which keeps the comparison
    // length-uniform even if a stored hash on disk is malformed.
    if (tokenMatches(providedHash, user.tokenHash)) matched = user;
  }
  if (matched === undefined || matched.disabled === true) return undefined;
  return { userId: matched.id, name: matched.name, role: matched.role };
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
