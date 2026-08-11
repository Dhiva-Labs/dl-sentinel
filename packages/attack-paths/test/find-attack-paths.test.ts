/**
 * Whole-analyzer properties: determinism, id stability, the bounds that stop a
 * report from flooding, and the honesty contract every path must satisfy.
 */
import { describe, expect, it } from 'vitest';
import type { AttackPath, Finding } from '@dl-sentinel/core';
import { CORRELATION_RULES, MAX_PATHS_PER_RULE, findAttackPaths } from '../src/index.js';
import { composeGraph, correlationId, emptyReport, finding, report, shuffle } from './helpers.js';

/**
 * One report that satisfies every rule in the catalog, so the sweeps below
 * actually see all seven narratives rather than the two easiest ones.
 */
function kitchenSink(): Finding[] {
  return [
    finding({ ruleId: 'I010', file: 'docker-compose.yml', line: 8, severity: 'critical' }),
    finding({ ruleId: 'I011', file: 'docker-compose.yml', line: 9 }),
    finding({ ruleId: 'I012', file: 'docker-compose.yml', line: 11 }),
    finding({ ruleId: 'I014', file: 'docker-compose.yml', line: 13 }),
    finding({ ruleId: 'I016', file: 'docker-compose.yml', line: 15, severity: 'medium' }),
    finding({ ruleId: 'I031', file: 'terraform/main.tf', line: 18 }),
    finding({ ruleId: 'S001', file: '.env', line: 9, severity: 'critical', category: 'secrets' }),
    finding({ ruleId: 'D001', file: 'package-lock.json', line: 3 }),
    finding({ ruleId: 'A001', file: 'openapi.yaml', line: 12 }),
    finding({ ruleId: 'A003', file: 'openapi.yaml', line: 9, severity: 'medium' }),
    finding({ ruleId: 'A005', file: 'openapi.yaml', line: 18 }),
    finding({ ruleId: 'C003', file: 'src/db.js', line: 23 }),
  ];
}

const KITCHEN_SINK_GRAPH = composeGraph([
  { name: 'app', file: 'docker-compose.yml', line: 6, ports: ['5432/tcp'] },
]);

function allPaths(): AttackPath[] {
  return findAttackPaths(report(kitchenSink()), KITCHEN_SINK_GRAPH);
}

describe('findAttackPaths — nothing to correlate', () => {
  it('returns [] for an empty report', () => {
    expect(findAttackPaths(emptyReport())).toEqual([]);
    expect(findAttackPaths(emptyReport(), composeGraph([]))).toEqual([]);
  });

  it('returns [] when findings exist but no rule conditions co-occur', () => {
    const isolated = [
      finding({ ruleId: 'I003', file: 'Dockerfile', line: 4, severity: 'medium' }),
      finding({ ruleId: 'SC009', file: 'contracts/Vault.sol', line: 2, severity: 'low' }),
      finding({ ruleId: 'D002', file: 'package.json', severity: 'info' }),
    ];
    expect(findAttackPaths(report(isolated))).toEqual([]);
  });

  it('never mutates the report it was given', () => {
    const input = report(kitchenSink());
    const before = JSON.stringify(input);
    findAttackPaths(input, KITCHEN_SINK_GRAPH);
    expect(JSON.stringify(input)).toBe(before);
    expect(input.attackPaths).toBeUndefined();
  });
});

describe('findAttackPaths — determinism', () => {
  it('produces identical output for shuffled findings', () => {
    const findings = kitchenSink();
    const baseline = findAttackPaths(report(findings), KITCHEN_SINK_GRAPH);
    for (const seed of [1, 2, 3, 11, 29]) {
      const shuffled = findAttackPaths(report(shuffle(findings, seed)), KITCHEN_SINK_GRAPH);
      expect(shuffled).toEqual(baseline);
    }
  });

  it('produces identical output across repeated calls', () => {
    expect(allPaths()).toEqual(allPaths());
  });

  it('sorts by severity, then confidence, then id', () => {
    const paths = allPaths();
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (let i = 1; i < paths.length; i += 1) {
      const previous = paths[i - 1];
      const current = paths[i];
      if (previous === undefined || current === undefined) continue;
      const bySeverity = rank[previous.severity] - rank[current.severity];
      if (bySeverity !== 0) {
        expect(bySeverity).toBeLessThan(0);
        continue;
      }
      const confidenceRank = (path: AttackPath): number => (path.confidence === 'medium' ? 0 : 1);
      const byConfidence = confidenceRank(previous) - confidenceRank(current);
      if (byConfidence !== 0) {
        expect(byConfidence).toBeLessThan(0);
        continue;
      }
      expect(previous.id < current.id).toBe(true);
    }
  });
});

describe('findAttackPaths — path ids', () => {
  it('derives the id from the correlation rule plus its constituent findings', () => {
    for (const path of allPaths()) {
      expect(path.id).toMatch(/^AP\d{3}:[0-9a-f]{16}$/);
    }
  });

  it('keeps ids stable when the finding order changes', () => {
    const findings = kitchenSink();
    const before = findAttackPaths(report(findings), KITCHEN_SINK_GRAPH).map((path) => path.id);
    const after = findAttackPaths(report(shuffle(findings, 13)), KITCHEN_SINK_GRAPH).map(
      (path) => path.id,
    );
    expect(after).toEqual(before);
  });

  it('gives every path in one report a distinct id', () => {
    const ids = allPaths().map((path) => path.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('changes the id when the constituent findings change', () => {
    const base = kitchenSink();
    const moved = base.map((item) =>
      item.ruleId === 'I010'
        ? finding({ ruleId: 'I010', file: 'docker-compose.yml', line: 99, severity: 'critical' })
        : item,
    );
    const beforeIds = new Set(
      findAttackPaths(report(base), KITCHEN_SINK_GRAPH)
        .filter((path) => correlationId(path.id) === 'AP001')
        .map((path) => path.id),
    );
    const afterIds = findAttackPaths(report(moved), KITCHEN_SINK_GRAPH)
      .filter((path) => correlationId(path.id) === 'AP001')
      .map((path) => path.id);
    for (const id of afterIds) expect(beforeIds.has(id)).toBe(false);
  });
});

describe('findAttackPaths — bounds', () => {
  it('caps a single rule at MAX_PATHS_PER_RULE however many units match', () => {
    const findings = Array.from({ length: MAX_PATHS_PER_RULE + 12 }, (_, index) => [
      finding({
        ruleId: 'I010',
        file: `stacks/s${String(index)}/docker-compose.yml`,
        line: 8,
        severity: 'critical',
      }),
      finding({
        ruleId: 'I016',
        file: `stacks/s${String(index)}/docker-compose.yml`,
        line: 15,
        severity: 'medium',
      }),
    ]).flat();
    const ap001 = findAttackPaths(report(findings)).filter(
      (path) => correlationId(path.id) === 'AP001',
    );
    expect(ap001).toHaveLength(MAX_PATHS_PER_RULE);
  });

  it('keeps every path to at most three steps', () => {
    for (const path of allPaths()) {
      expect(path.steps.length).toBeGreaterThanOrEqual(1);
      expect(path.steps.length).toBeLessThanOrEqual(3);
    }
  });
});

describe('findAttackPaths — the honesty contract', () => {
  it('exercises the whole catalog in the kitchen-sink report', () => {
    const seen = new Set(allPaths().map((path) => correlationId(path.id)));
    expect([...seen].sort()).toEqual(CORRELATION_RULES.map((rule) => rule.id));
  });

  it('never asserts confidence above likely', () => {
    for (const path of allPaths()) {
      expect(path.confidence).not.toBe('high');
      expect(['medium', 'low']).toContain(path.confidence);
    }
  });

  it('phrases every narrative as "could allow"', () => {
    const paths = allPaths();
    expect(paths.length).toBeGreaterThan(0);
    for (const path of paths) {
      expect(path.narrative.toLowerCase()).toContain('could allow');
    }
  });

  it('never claims exploitability anywhere in a path', () => {
    const banned = [
      'exploitable',
      'will allow',
      'is exploited',
      'proves',
      'guaranteed',
      'confirmed exploit',
    ];
    for (const path of allPaths()) {
      const text = [path.title, path.narrative, ...path.steps.map((step) => step.note)]
        .join(' ')
        .toLowerCase();
      for (const phrase of banned) {
        expect(text).not.toContain(phrase);
      }
    }
  });

  it('builds every step on a finding that is really in the report', () => {
    const input = report(kitchenSink());
    const byId = new Map(input.findings.map((item) => [item.id, item]));
    for (const path of findAttackPaths(input, KITCHEN_SINK_GRAPH)) {
      for (const step of path.steps) {
        const source = byId.get(step.findingId);
        expect(source).toBeDefined();
        expect(step.ruleId).toBe(source?.ruleId);
        expect(step.file).toBe(source?.file);
        expect(step.note.length).toBeGreaterThan(0);
        expect(['entry', 'escalation', 'impact']).toContain(step.role);
      }
    }
  });

  it('declares conditions for every rule in the catalog', () => {
    for (const rule of CORRELATION_RULES) {
      expect(rule.id).toMatch(/^AP\d{3}$/);
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.conditions.length).toBeGreaterThan(0);
    }
  });
});
