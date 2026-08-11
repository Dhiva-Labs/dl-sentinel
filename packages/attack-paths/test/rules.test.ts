/**
 * Per-rule conditions: what makes each AP rule fire, and — just as important —
 * what does not. Every rule gets a positive case and negative cases in which
 * each of its conditions is present *alone*, because a "correlation" that fires
 * on one finding is not a correlation.
 */
import { describe, expect, it } from 'vitest';
import type { AttackPath } from '@dl-sentinel/core';
import { findAttackPaths, pathConfidenceLabel } from '../src/index.js';
import { composeGraph, correlationId, finding, report, workloadGraph } from './helpers.js';

function pathsFor(id: string, paths: readonly AttackPath[]): AttackPath[] {
  return paths.filter((path) => correlationId(path.id) === id);
}

function roles(path: AttackPath): string[] {
  return path.steps.map((step) => `${step.role}:${step.ruleId}`);
}

describe('AP001 — privileged workload on an exposed surface', () => {
  const privileged = finding({
    ruleId: 'I010',
    file: 'docker-compose.yml',
    line: 8,
    severity: 'critical',
  });
  const hostNetwork = finding({ ruleId: 'I011', file: 'docker-compose.yml', line: 9 });
  const hostMount = finding({ ruleId: 'I012', file: 'docker-compose.yml', line: 11 });
  const graph = composeGraph([{ name: 'app', file: 'docker-compose.yml', line: 6 }]);

  it('fires on privilege + a separate exposure in the same service, with the mount as impact', () => {
    const [path, ...rest] = pathsFor(
      'AP001',
      findAttackPaths(report([privileged, hostNetwork, hostMount]), graph),
    );
    expect(rest).toHaveLength(0);
    expect(path?.severity).toBe('critical');
    expect(path?.confidence).toBe('medium');
    expect(pathConfidenceLabel(path?.confidence ?? 'low')).toBe('likely');
    expect(roles(path as AttackPath)).toEqual(['entry:I011', 'escalation:I010', 'impact:I012']);
    // Every step references a finding that is genuinely in the report.
    const ids = new Set([privileged.id, hostNetwork.id, hostMount.id]);
    for (const step of path?.steps ?? []) expect(ids.has(step.findingId)).toBe(true);
  });

  it('does not fire on the privilege alone', () => {
    expect(pathsFor('AP001', findAttackPaths(report([privileged]), graph))).toHaveLength(0);
  });

  it('does not fire on the exposure alone', () => {
    const exposure = finding({
      ruleId: 'I016',
      file: 'docker-compose.yml',
      line: 15,
      severity: 'medium',
    });
    expect(pathsFor('AP001', findAttackPaths(report([exposure]), graph))).toHaveLength(0);
  });

  it('does not let a lone host-network finding pair with itself', () => {
    // I011 is both a privilege and an exposure signal; one finding cannot fill
    // both roles, so nothing should come of it on its own.
    expect(pathsFor('AP001', findAttackPaths(report([hostNetwork]), graph))).toHaveLength(0);
  });

  it('does not fire across two unrelated services in one compose file', () => {
    const twoServices = composeGraph([
      { name: 'web', file: 'docker-compose.yml', line: 6 },
      { name: 'db', file: 'docker-compose.yml', line: 20 },
    ]);
    const dbExposure = finding({
      ruleId: 'I016',
      file: 'docker-compose.yml',
      line: 25,
      severity: 'medium',
    });
    expect(
      pathsFor('AP001', findAttackPaths(report([privileged, dbExposure]), twoServices)),
    ).toHaveLength(0);
  });

  it('degrades to potential when no graph links the findings to one service', () => {
    const [withGraph] = pathsFor(
      'AP001',
      findAttackPaths(report([privileged, hostNetwork]), graph),
    );
    const [withoutGraph] = pathsFor('AP001', findAttackPaths(report([privileged, hostNetwork])));
    expect(withGraph?.confidence).toBe('medium');
    expect(withoutGraph?.confidence).toBe('low');
    expect(pathConfidenceLabel(withoutGraph?.confidence ?? 'medium')).toBe('potential');
    // Same findings, same chain: the id must not move with the confidence.
    expect(withoutGraph?.id).toBe(withGraph?.id);
    expect(withoutGraph?.narrative).toContain('the same file `docker-compose.yml`');
  });

  it('accepts a graph-observed published port as the exposure, with no invented step', () => {
    const exposedGraph = composeGraph([
      { name: 'app', file: 'docker-compose.yml', line: 6, ports: ['5432/tcp'] },
    ]);
    const [path] = pathsFor('AP001', findAttackPaths(report([privileged]), exposedGraph));
    expect(path?.steps).toHaveLength(1);
    expect(roles(path as AttackPath)).toEqual(['escalation:I010']);
    expect(path?.narrative).toContain('5432/tcp');
  });

  it('folds a Kubernetes container into its workload so both findings share a unit', () => {
    const k8sGraph = workloadGraph({
      name: 'Deployment/api',
      file: 'k8s/deployment.yaml',
      workloadLine: 7,
      containerLine: 20,
    });
    const findings = [
      finding({
        ruleId: 'I021',
        file: 'k8s/deployment.yaml',
        line: 18,
        metadata: { field: 'hostNetwork' },
      }),
      finding({ ruleId: 'I020', file: 'k8s/deployment.yaml', line: 23, severity: 'critical' }),
    ];
    const [path] = pathsFor('AP001', findAttackPaths(report(findings), k8sGraph));
    expect(path?.confidence).toBe('medium');
    expect(roles(path as AttackPath)).toEqual(['entry:I021', 'escalation:I020']);
  });

  it('treats I021 hostPID as a privilege only, never as an exposure', () => {
    const findings = [
      finding({
        ruleId: 'I021',
        file: 'k8s/deployment.yaml',
        line: 18,
        metadata: { field: 'hostPID' },
      }),
      finding({ ruleId: 'I020', file: 'k8s/deployment.yaml', line: 23, severity: 'critical' }),
    ];
    expect(pathsFor('AP001', findAttackPaths(report(findings)))).toHaveLength(0);
  });
});

describe('AP002 — leaked credential and a reachable service', () => {
  const exposure = finding({
    ruleId: 'I016',
    file: 'docker-compose.yml',
    line: 15,
    severity: 'medium',
  });

  it('fires on a critical secret plus an exposed port, credential first', () => {
    const secret = finding({
      ruleId: 'S001',
      file: '.env',
      line: 9,
      severity: 'critical',
      category: 'secrets',
    });
    const [path, ...rest] = pathsFor('AP002', findAttackPaths(report([secret, exposure])));
    expect(rest).toHaveLength(0);
    expect(path?.severity).toBe('critical');
    expect(roles(path as AttackPath)).toEqual(['entry:S001', 'impact:I016']);
    // .env sits beside the compose file, which is where a compose project reads it from.
    expect(path?.confidence).toBe('medium');
  });

  it('fires on a secret plus a non-loopback plain-http API surface', () => {
    const secret = finding({
      ruleId: 'S003',
      file: '.env',
      line: 2,
      severity: 'critical',
      category: 'secrets',
    });
    const transport = finding({
      ruleId: 'A003',
      file: 'openapi.yaml',
      line: 9,
      severity: 'medium',
    });
    const [path] = pathsFor('AP002', findAttackPaths(report([secret, transport])));
    expect(roles(path as AttackPath)).toEqual(['entry:S003', 'impact:A003']);
  });

  it('drops to potential when the credential lives in a different directory', () => {
    const secret = finding({
      ruleId: 'S001',
      file: 'config/secrets/.env',
      line: 1,
      severity: 'critical',
    });
    const [path] = pathsFor('AP002', findAttackPaths(report([secret, exposure])));
    expect(path?.confidence).toBe('low');
    expect(path?.narrative).toContain('co-location in this repository');
  });

  it('does not fire on the credential alone or the exposure alone', () => {
    const secret = finding({ ruleId: 'S001', file: '.env', line: 9, severity: 'critical' });
    expect(pathsFor('AP002', findAttackPaths(report([secret])))).toHaveLength(0);
    expect(pathsFor('AP002', findAttackPaths(report([exposure])))).toHaveLength(0);
  });

  it('ignores medium/low secret findings — a weak detection is not a chain anchor', () => {
    const weak = finding({ ruleId: 'S022', file: '.env', line: 3, severity: 'medium' });
    expect(pathsFor('AP002', findAttackPaths(report([weak, exposure])))).toHaveLength(0);
  });

  it('never mistakes a smart-contract rule (SC0xx) for a secrets rule', () => {
    const contract = finding({
      ruleId: 'SC001',
      file: 'contracts/Vault.sol',
      line: 21,
      severity: 'critical',
    });
    expect(pathsFor('AP002', findAttackPaths(report([contract, exposure])))).toHaveLength(0);
  });

  it('ignores a loopback A003 the API scanner downgraded to info', () => {
    const secret = finding({ ruleId: 'S001', file: '.env', line: 9, severity: 'critical' });
    const loopback = finding({ ruleId: 'A003', file: 'openapi.yaml', line: 9, severity: 'info' });
    expect(pathsFor('AP002', findAttackPaths(report([secret, loopback])))).toHaveLength(0);
  });
});

describe('AP003 — vulnerable dependency behind an exposed surface', () => {
  const exposure = finding({
    ruleId: 'I016',
    file: 'docker-compose.yml',
    line: 15,
    severity: 'medium',
  });

  it('fires on D001 plus an exposure, floored at high and always potential', () => {
    const vulnerable = finding({
      ruleId: 'D001',
      file: 'package-lock.json',
      line: 3,
      severity: 'medium',
    });
    const [path, ...rest] = pathsFor('AP003', findAttackPaths(report([vulnerable, exposure])));
    expect(rest).toHaveLength(0);
    expect(path?.severity).toBe('high');
    expect(path?.confidence).toBe('low');
    expect(roles(path as AttackPath)).toEqual(['entry:I016', 'impact:D001']);
  });

  it('keeps a critical advisory critical rather than flattening it to the floor', () => {
    const vulnerable = finding({
      ruleId: 'D001',
      file: 'package-lock.json',
      line: 3,
      severity: 'critical',
    });
    const [path] = pathsFor('AP003', findAttackPaths(report([vulnerable, exposure])));
    expect(path?.severity).toBe('critical');
  });

  it('does not fire on the dependency alone or the exposure alone', () => {
    const vulnerable = finding({ ruleId: 'D001', file: 'package-lock.json', line: 3 });
    expect(pathsFor('AP003', findAttackPaths(report([vulnerable])))).toHaveLength(0);
    expect(pathsFor('AP003', findAttackPaths(report([exposure])))).toHaveLength(0);
  });

  it('does not fire on D002 (advisory data not consulted)', () => {
    const skipped = finding({ ruleId: 'D002', file: 'package.json', severity: 'info' });
    expect(pathsFor('AP003', findAttackPaths(report([skipped, exposure])))).toHaveLength(0);
  });
});

describe('AP004 — cloud storage exposure with committed credentials', () => {
  const bucket = finding({ ruleId: 'I031', file: 'terraform/main.tf', line: 18 });
  const key = finding({ ruleId: 'S001', file: '.env', line: 9, severity: 'critical' });

  it('fires on a public bucket plus AWS key material', () => {
    const [path, ...rest] = pathsFor('AP004', findAttackPaths(report([bucket, key])));
    expect(rest).toHaveLength(0);
    expect(path?.severity).toBe('critical');
    expect(path?.confidence).toBe('medium');
    expect(roles(path as AttackPath)).toEqual(['entry:I031', 'escalation:S001']);
  });

  it('does not fire on the bucket alone or the credential alone', () => {
    expect(pathsFor('AP004', findAttackPaths(report([bucket])))).toHaveLength(0);
    expect(pathsFor('AP004', findAttackPaths(report([key])))).toHaveLength(0);
  });

  it('does not fire for a non-AWS credential', () => {
    const github = finding({ ruleId: 'S003', file: '.env', line: 2, severity: 'critical' });
    expect(pathsFor('AP004', findAttackPaths(report([bucket, github])))).toHaveLength(0);
  });
});

describe('AP005 — unauthenticated operation over cleartext', () => {
  const transport = finding({ ruleId: 'A003', file: 'openapi.yaml', line: 9, severity: 'medium' });
  const noAuth = finding({ ruleId: 'A001', file: 'openapi.yaml', line: 12 });
  const stateChanging = finding({ ruleId: 'A005', file: 'openapi.yaml', line: 18 });

  it('fires when both are read out of the same API document', () => {
    const [path, ...rest] = pathsFor('AP005', findAttackPaths(report([transport, noAuth])));
    expect(rest).toHaveLength(0);
    expect(path?.severity).toBe('high');
    expect(path?.confidence).toBe('medium');
    expect(roles(path as AttackPath)).toEqual(['entry:A003', 'impact:A001']);
  });

  it('prefers A005 over A001 — a state-changing operation is the sharper signal', () => {
    const [path] = pathsFor('AP005', findAttackPaths(report([transport, noAuth, stateChanging])));
    expect(roles(path as AttackPath)).toEqual(['entry:A003', 'impact:A005']);
  });

  it('does not fire on either finding alone', () => {
    expect(pathsFor('AP005', findAttackPaths(report([transport])))).toHaveLength(0);
    expect(pathsFor('AP005', findAttackPaths(report([stateChanging])))).toHaveLength(0);
  });

  it('does not pair findings from two different API documents', () => {
    const otherDoc = finding({ ruleId: 'A005', file: 'api/other.yaml', line: 4 });
    expect(pathsFor('AP005', findAttackPaths(report([transport, otherDoc])))).toHaveLength(0);
  });

  it('does not fire for a loopback (info) A003', () => {
    const loopback = finding({ ruleId: 'A003', file: 'openapi.yaml', line: 9, severity: 'info' });
    expect(pathsFor('AP005', findAttackPaths(report([loopback, stateChanging])))).toHaveLength(0);
  });
});

describe('AP006 — injection-class code alongside an API surface', () => {
  const api = finding({ ruleId: 'A001', file: 'openapi.yaml', line: 12 });

  it('fires once on an injection finding plus an API definition', () => {
    const sql = finding({ ruleId: 'C003', file: 'src/db.js', line: 23, category: 'source' });
    const [path, ...rest] = pathsFor('AP006', findAttackPaths(report([sql, api])));
    expect(rest).toHaveLength(0);
    expect(path?.confidence).toBe('low');
    expect(roles(path as AttackPath)).toEqual(['entry:A001', 'impact:C003']);
  });

  it('caps at exactly one path however many injection sites there are', () => {
    const many = Array.from({ length: 40 }, (_, index) =>
      finding({ ruleId: 'C003', file: `src/q${String(index)}.js`, line: index + 1 }),
    );
    const apis = [
      api,
      finding({ ruleId: 'A005', file: 'api/admin.yaml', line: 4 }),
      finding({ ruleId: 'A002', file: 'api/admin.yaml', line: 9 }),
    ];
    const paths = pathsFor('AP006', findAttackPaths(report([...many, ...apis])));
    expect(paths).toHaveLength(1);
    expect(paths[0]?.steps).toHaveLength(2);
    // The aggregate is carried by the narrative rather than by 120 paths.
    expect(paths[0]?.narrative).toContain('40 injection-class findings');
    expect(paths[0]?.narrative).toContain('2 API definitions');
  });

  it('does not fire without an API definition, or without injection findings', () => {
    const sql = finding({ ruleId: 'C003', file: 'src/db.js', line: 23 });
    expect(pathsFor('AP006', findAttackPaths(report([sql])))).toHaveLength(0);
    expect(pathsFor('AP006', findAttackPaths(report([api])))).toHaveLength(0);
  });

  it('does not treat a non-injection source rule as an injection finding', () => {
    const weakHash = finding({ ruleId: 'C006', file: 'src/hash.js', line: 4 });
    expect(pathsFor('AP006', findAttackPaths(report([weakHash, api])))).toHaveLength(0);
  });
});

describe('AP007 — container credential with a host mount', () => {
  const envSecret = finding({ ruleId: 'I014', file: 'docker-compose.yml', line: 13 });
  const mount = finding({ ruleId: 'I012', file: 'docker-compose.yml', line: 11 });
  const graph = composeGraph([{ name: 'app', file: 'docker-compose.yml', line: 6 }]);

  it('fires when both are declared on the same service', () => {
    const [path, ...rest] = pathsFor('AP007', findAttackPaths(report([envSecret, mount]), graph));
    expect(rest).toHaveLength(0);
    expect(path?.severity).toBe('critical');
    expect(path?.confidence).toBe('medium');
    expect(roles(path as AttackPath)).toEqual(['entry:I014', 'escalation:I012']);
    expect(path?.narrative).toContain('the same service `app`');
  });

  it('accepts same-file linkage when no graph is available', () => {
    const [path] = pathsFor('AP007', findAttackPaths(report([envSecret, mount])));
    expect(path?.confidence).toBe('medium');
    expect(path?.narrative).toContain('the same file `docker-compose.yml`');
  });

  it('does not fire on either finding alone', () => {
    expect(pathsFor('AP007', findAttackPaths(report([envSecret]), graph))).toHaveLength(0);
    expect(pathsFor('AP007', findAttackPaths(report([mount]), graph))).toHaveLength(0);
  });

  it('does not pair a credential and a mount declared in different files', () => {
    const elsewhere = finding({ ruleId: 'I022', file: 'k8s/deployment.yaml', line: 30 });
    expect(pathsFor('AP007', findAttackPaths(report([envSecret, elsewhere])))).toHaveLength(0);
  });
});
