/**
 * Role-gating helpers, mirrored in public/app.js. Kept here as the typechecked,
 * unit-tested source of truth for the dashboard's half of the permission matrix
 * fixed in docs/api.md.
 *
 * These only decide what the UI *offers*. The API enforces the same matrix
 * independently and answers `403 { error: { code: "forbidden" } }` regardless of
 * what the dashboard renders — hiding a control is a courtesy, never the
 * security boundary.
 */

export type Role = 'admin' | 'operator' | 'viewer';

/** The things the dashboard gates on, named after the UI affordance. */
export type GatedAction = 'startScan' | 'manageSchedules' | 'manageUsers' | 'manageNotifications';

export function isRole(value: unknown): value is Role {
  return value === 'admin' || value === 'operator' || value === 'viewer';
}

/**
 * Whether a caller with `role` may perform `action`.
 *
 * An unknown role — no token set, `GET /api/me` not answered yet, or a server
 * that sent something unexpected — permits nothing: the dashboard would rather
 * hide a control the user could have used than offer one that 403s.
 */
export function can(role: unknown, action: GatedAction): boolean {
  if (!isRole(role)) return false;
  if (role === 'admin') return true;
  if (action === 'startScan') return role === 'operator';
  // manageSchedules, manageUsers and manageNotifications are admin-only,
  // handled above.
  return false;
}

/** Human label for a role; anything unrecognised reads as "Unknown". */
export function roleLabel(role: unknown): string {
  if (role === 'admin') return 'Admin';
  if (role === 'operator') return 'Operator';
  if (role === 'viewer') return 'Viewer';
  return 'Unknown';
}

/** A user as it arrives from `GET /api/users` — every field treated as untrusted. */
export interface UserLike {
  id?: unknown;
  name?: unknown;
  role?: unknown;
  createdAt?: unknown;
  disabled?: unknown;
}

/** One row of the Users table, already reduced to displayable strings. */
export interface UserRow {
  id: string;
  name: string;
  role: string;
  roleLabel: string;
  /** Raw ISO timestamp; the view formats it for the reader's locale. */
  createdAt: string;
  disabled: boolean;
  status: string;
}

/**
 * Normalize a user record for display. Missing or wrongly typed fields degrade
 * to a dash rather than rendering `undefined`, and the values stay raw strings —
 * the view writes them with `textContent`, so nothing is escaped or stripped
 * here (a name containing markup must survive intact, and render inert).
 */
export function formatUserRow(user: UserLike): UserRow {
  const name = typeof user.name === 'string' && user.name !== '' ? user.name : '—';
  const disabled = user.disabled === true;
  return {
    id: typeof user.id === 'string' ? user.id : '',
    name,
    role: isRole(user.role) ? user.role : '',
    roleLabel: roleLabel(user.role),
    createdAt: typeof user.createdAt === 'string' ? user.createdAt : '',
    disabled,
    status: disabled ? 'Disabled' : 'Active',
  };
}
