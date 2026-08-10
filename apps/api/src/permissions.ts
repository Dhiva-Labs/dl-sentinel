import type { UserRole } from './types.js';

/** Every role, least to most privileged. */
export const USER_ROLES: readonly UserRole[] = ['viewer', 'operator', 'admin'];

/**
 * Longest accepted user name. A name is only ever stored and echoed back, but
 * an unbounded one would still let an admin bloat the on-disk record set, so it
 * is capped like every other caller-supplied field.
 */
export const MAX_USER_NAME_LENGTH = 64;

/** Privilege ordering. Higher wins; roles are strictly nested. */
const RANK: Record<UserRole, number> = { viewer: 0, operator: 1, admin: 2 };

export function isUserRole(value: unknown): value is UserRole {
  return value === 'admin' || value === 'operator' || value === 'viewer';
}

/** True when `role` is at least as privileged as `required`. */
export function roleAtLeast(role: UserRole, required: UserRole): boolean {
  return RANK[role] >= RANK[required];
}

/**
 * The minimum role for an `/api/*` request, from the matrix fixed in
 * docs/architecture.md (§API server, "Users and RBAC"):
 *
 * | Role     | May do                                                       |
 * | -------- | ------------------------------------------------------------ |
 * | viewer   | every `GET` (scans, findings, reports, rules, history, trends, schedules, me) |
 * | operator | viewer + `POST /api/scans`                                   |
 * | admin    | everything, including schedule mutations and `/api/users*`   |
 *
 * `segments` are the path segments after `api` (so `/api/users/x/rotate` is
 * `['users', 'x', 'rotate']`). Anything not explicitly opened up requires
 * `admin`: the default is fail-closed, so a route added later is locked down
 * until its entry is added here.
 *
 * This runs before routing, so an unknown path with a mutating method is a 403
 * for an under-privileged caller rather than a 404 — deliberately, since
 * telling an unauthorized caller which endpoints exist is itself information.
 */
export function requiredRoleFor(method: string, segments: readonly string[]): UserRole {
  const first = segments[0];
  // User administration is admin-only for every method, reads included: the
  // list of who can reach the API is itself sensitive.
  if (first === 'users') return 'admin';
  if (method === 'GET' || method === 'HEAD') return 'viewer';
  if (method === 'POST' && first === 'scans' && segments.length === 1) return 'operator';
  return 'admin';
}
