import { describe, expect, it } from 'vitest';
import { can, formatUserRow, isRole, roleLabel } from '../src/rbac.js';
import type { GatedAction, Role } from '../src/rbac.js';

describe('isRole', () => {
  it('accepts exactly the three roles', () => {
    for (const role of ['admin', 'operator', 'viewer']) {
      expect(isRole(role)).toBe(true);
    }
  });

  it('rejects anything else', () => {
    for (const value of ['root', 'ADMIN', '', undefined, null, 7, {}]) {
      expect(isRole(value)).toBe(false);
    }
  });
});

describe('can', () => {
  // The dashboard's mirror of the API matrix in docs/api.md, asserted whole so
  // a change to either side shows up as a failing cell rather than a silent
  // divergence.
  const matrix: Record<Role, Record<GatedAction, boolean>> = {
    viewer: { startScan: false, manageSchedules: false, manageUsers: false },
    operator: { startScan: true, manageSchedules: false, manageUsers: false },
    admin: { startScan: true, manageSchedules: true, manageUsers: true },
  };

  for (const role of Object.keys(matrix) as Role[]) {
    for (const action of Object.keys(matrix[role]) as GatedAction[]) {
      it(`${role} ${matrix[role][action] ? 'may' : 'may not'} ${action}`, () => {
        expect(can(role, action)).toBe(matrix[role][action]);
      });
    }
  }

  it('permits nothing for an unknown or absent role', () => {
    for (const value of [undefined, null, '', 'root', 'superuser']) {
      expect(can(value, 'startScan')).toBe(false);
      expect(can(value, 'manageSchedules')).toBe(false);
      expect(can(value, 'manageUsers')).toBe(false);
    }
  });
});

describe('roleLabel', () => {
  it('labels each role', () => {
    expect(roleLabel('admin')).toBe('Admin');
    expect(roleLabel('operator')).toBe('Operator');
    expect(roleLabel('viewer')).toBe('Viewer');
  });

  it('falls back for anything unrecognised', () => {
    expect(roleLabel('root')).toBe('Unknown');
    expect(roleLabel(undefined)).toBe('Unknown');
  });
});

describe('formatUserRow', () => {
  it('formats a complete record', () => {
    expect(
      formatUserRow({
        id: 'u1',
        name: 'Ada',
        role: 'operator',
        createdAt: '2026-08-11T09:00:00.000Z',
        disabled: false,
      }),
    ).toEqual({
      id: 'u1',
      name: 'Ada',
      role: 'operator',
      roleLabel: 'Operator',
      createdAt: '2026-08-11T09:00:00.000Z',
      disabled: false,
      status: 'Active',
    });
  });

  it('marks a disabled user', () => {
    const row = formatUserRow({ id: 'u2', name: 'Grace', role: 'viewer', disabled: true });
    expect(row.disabled).toBe(true);
    expect(row.status).toBe('Disabled');
  });

  it('degrades missing or mistyped fields instead of rendering undefined', () => {
    const row = formatUserRow({});
    expect(row).toEqual({
      id: '',
      name: '—',
      role: '',
      roleLabel: 'Unknown',
      createdAt: '',
      disabled: false,
      status: 'Active',
    });
    expect(formatUserRow({ name: 42, role: 'root', createdAt: 0 }).name).toBe('—');
    expect(formatUserRow({ name: 42, role: 'root', createdAt: 0 }).roleLabel).toBe('Unknown');
    expect(formatUserRow({ name: 42, role: 'root', createdAt: 0 }).createdAt).toBe('');
  });

  it('passes a hostile-looking name through verbatim', () => {
    // The Users view writes this with textContent, so it must arrive intact and
    // render as literal text — sanitizing here would corrupt a legitimate name
    // and would not be the thing keeping the page safe.
    const name = '<img src=x onerror=alert(1)>';
    expect(formatUserRow({ id: 'u3', name, role: 'viewer' }).name).toBe(name);
  });
});
