import { describe, expect, it } from 'vitest';
import { matchAffected } from '../../src/version/match.js';
import type { AffectedRange, Ecosystem, VersionKind } from '../../src/types.js';

interface Case {
  label: string;
  ecosystem: Ecosystem;
  version: string;
  versionKind: VersionKind;
  ranges: AffectedRange[];
  outcome: 'vulnerable-exact' | 'vulnerable-range' | 'clear' | 'unknown';
  fixedVersion?: string;
}

const cases: Case[] = [
  // ---- npm, exact (locked) versions: high-confidence path ----
  {
    label: 'npm exact below fixed -> vulnerable-exact',
    ecosystem: 'npm',
    version: '4.17.15',
    versionKind: 'exact',
    ranges: [{ fixed: '4.17.21' }],
    outcome: 'vulnerable-exact',
    fixedVersion: '4.17.21',
  },
  {
    label: 'npm exact at fixed -> clear (fixed is exclusive)',
    ecosystem: 'npm',
    version: '4.17.21',
    versionKind: 'exact',
    ranges: [{ fixed: '4.17.21' }],
    outcome: 'clear',
  },
  {
    label: 'npm exact below introduced -> clear',
    ecosystem: 'npm',
    version: '4.0.0',
    versionKind: 'exact',
    ranges: [{ introduced: '5.0.0', fixed: '5.1.0' }],
    outcome: 'clear',
  },
  {
    label: 'npm exact at introduced (inclusive) -> vulnerable-exact',
    ecosystem: 'npm',
    version: '5.0.0',
    versionKind: 'exact',
    ranges: [{ introduced: '5.0.0', fixed: '5.1.0' }],
    outcome: 'vulnerable-exact',
    fixedVersion: '5.1.0',
  },
  {
    label: 'npm exact with prerelease metadata -> unknown, never claimed',
    ecosystem: 'npm',
    version: '4.17.15-beta.1',
    versionKind: 'exact',
    ranges: [{ fixed: '4.17.21' }],
    outcome: 'unknown',
  },
  // ---- npm, declared range: medium-confidence path ----
  {
    label: 'npm caret range overlapping an advisory window -> vulnerable-range',
    ecosystem: 'npm',
    version: '^1.2.0',
    versionKind: 'range',
    ranges: [{ introduced: '1.0.0', fixed: '1.3.0' }],
    outcome: 'vulnerable-range',
    fixedVersion: '1.3.0',
  },
  {
    label: 'npm caret range entirely above the fixed version -> clear',
    ecosystem: 'npm',
    version: '^2.0.0',
    versionKind: 'range',
    ranges: [{ introduced: '1.0.0', fixed: '1.3.0' }],
    outcome: 'clear',
  },
  {
    label: 'npm unparseable declared range ("*") -> unknown',
    ecosystem: 'npm',
    version: '*',
    versionKind: 'range',
    ranges: [{ fixed: '1.3.0' }],
    outcome: 'unknown',
  },
  // ---- cargo: bare version means caret (unlike npm's bare-means-exact) ----
  {
    label: 'cargo bare version is a caret range, overlapping -> vulnerable-range',
    ecosystem: 'cargo',
    version: '1.2.3',
    versionKind: 'range',
    ranges: [{ fixed: '1.5.0' }],
    outcome: 'vulnerable-range',
    fixedVersion: '1.5.0',
  },
  {
    label: 'cargo exact (from Cargo.lock) below fixed -> vulnerable-exact',
    ecosystem: 'cargo',
    version: '1.4.9',
    versionKind: 'exact',
    ranges: [{ fixed: '1.5.0' }],
    outcome: 'vulnerable-exact',
    fixedVersion: '1.5.0',
  },
  // ---- pip: dotted-int exact and >=/<= range ----
  {
    label: 'pip exact == pin below fixed -> vulnerable-exact',
    ecosystem: 'pip',
    version: '2.6.0',
    versionKind: 'exact',
    ranges: [{ fixed: '2.6.1' }],
    outcome: 'vulnerable-exact',
    fixedVersion: '2.6.1',
  },
  {
    label: 'pip >= range overlapping an advisory window -> vulnerable-range',
    ecosystem: 'pip',
    version: '>=2.0.0',
    versionKind: 'range',
    ranges: [{ introduced: '1.0.0', fixed: '2.5.0' }],
    outcome: 'vulnerable-range',
    fixedVersion: '2.5.0',
  },
  {
    label: 'pip >= range entirely above the fixed version -> clear',
    ecosystem: 'pip',
    version: '>=3.0.0',
    versionKind: 'range',
    ranges: [{ introduced: '1.0.0', fixed: '2.5.0' }],
    outcome: 'clear',
  },
  {
    label: 'pip unparseable declared range ("~=1.4.2" is not modeled at this layer) -> unknown',
    ecosystem: 'pip',
    version: '~=1.4.2',
    versionKind: 'range',
    ranges: [{ fixed: '2.0.0' }],
    outcome: 'unknown',
  },
  // ---- go: always exact, v-prefixed ----
  {
    label: 'go exact below fixed -> vulnerable-exact',
    ecosystem: 'go',
    version: 'v1.2.3',
    versionKind: 'exact',
    ranges: [{ fixed: 'v1.3.0' }],
    outcome: 'vulnerable-exact',
    fixedVersion: 'v1.3.0',
  },
  {
    label: 'go exact at fixed -> clear',
    ecosystem: 'go',
    version: 'v1.3.0',
    versionKind: 'exact',
    ranges: [{ fixed: 'v1.3.0' }],
    outcome: 'clear',
  },
  {
    label: 'go exact with a genuine prerelease tag -> unknown',
    ecosystem: 'go',
    version: 'v1.2.3-beta.1',
    versionKind: 'exact',
    ranges: [{ fixed: 'v1.3.0' }],
    outcome: 'unknown',
  },
  // ---- cross-cutting conservative-refusal and edge cases ----
  {
    label: 'no advisory ranges at all -> clear',
    ecosystem: 'npm',
    version: '1.0.0',
    versionKind: 'exact',
    ranges: [],
    outcome: 'clear',
  },
  {
    label: 'one unparseable range plus one clear match -> still vulnerable (a definite match wins)',
    ecosystem: 'npm',
    version: '1.0.0',
    versionKind: 'exact',
    ranges: [{ introduced: 'not-a-version', fixed: '2.0.0' }, { fixed: '1.5.0' }],
    outcome: 'vulnerable-exact',
    fixedVersion: '1.5.0',
  },
  {
    label: 'only an unparseable range, no clear match anywhere -> unknown, not clear',
    ecosystem: 'npm',
    version: '9.9.9',
    versionKind: 'exact',
    ranges: [{ introduced: 'not-a-version' }],
    outcome: 'unknown',
  },
];

describe('matchAffected (conservative comparator table)', () => {
  it.each(cases)('$label', ({ ecosystem, version, versionKind, ranges, outcome, fixedVersion }) => {
    const result = matchAffected({ ecosystem, version, versionKind }, ranges);
    expect(result.outcome).toBe(outcome);
    if (fixedVersion !== undefined) {
      expect(result.fixedVersion).toBe(fixedVersion);
    }
  });

  it('falls back to "unknown" for an unrecognized ecosystem rather than throwing (defensive default)', () => {
    const result = matchAffected(
      { ecosystem: 'unknown-ecosystem' as Ecosystem, version: '1.0.0', versionKind: 'exact' },
      [{ fixed: '2.0.0' }],
    );
    expect(result.outcome).toBe('unknown');
  });
});
