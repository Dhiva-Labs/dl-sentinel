/**
 * Builders for synthetic reports and graphs.
 *
 * Correlation is a pure function of a `Report` (plus an optional `InfraGraph`),
 * so every test here constructs exactly the findings its rule needs — no
 * scanner runs, no filesystem. The fixture-app end of the feature is covered by
 * apps/cli/test/paths.test.ts.
 */
import type { Category, Finding, Report, Severity } from '@dl-sentinel/core';
import { computeStats, createFinding } from '@dl-sentinel/core';
import type { GraphEdge, GraphNode, InfraGraph } from '@dl-sentinel/scanner-infra';

export interface FindingSpec {
  ruleId: string;
  file: string;
  line?: number;
  severity?: Severity;
  category?: Category;
  scanner?: string;
  metadata?: Record<string, string | number | boolean>;
}

/** A finding with a real fingerprint id, so path ids behave as they do in production. */
export function finding(spec: FindingSpec): Finding {
  return createFinding({
    ruleId: spec.ruleId,
    title: `${spec.ruleId} fixture finding`,
    description: 'Synthetic finding built for attack-path correlation tests.',
    severity: spec.severity ?? 'high',
    confidence: 'high',
    category: spec.category ?? 'other',
    file: spec.file,
    ...(spec.line === undefined ? {} : { line: spec.line }),
    evidence: `${spec.ruleId} @ ${spec.file}:${String(spec.line ?? 0)}`,
    recommendation: 'Nothing to do; this is a fixture.',
    references: [],
    scanner: spec.scanner ?? 'fixture',
    ...(spec.metadata === undefined ? {} : { metadata: spec.metadata }),
  });
}

/** A report wrapping `findings`; every other field is inert fixture data. */
export function report(findings: readonly Finding[]): Report {
  return {
    tool: { name: 'DL Sentinel', version: '0.1.0' },
    project: 'fixture',
    target: '/fixture',
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:00:01.000Z',
    durationMs: 1000,
    scannersRun: ['fixture'],
    stats: computeStats(findings),
    findings: [...findings],
    errors: [],
  };
}

/** An empty-but-valid report. */
export function emptyReport(): Report {
  return report([]);
}

export interface ServiceSpec {
  name: string;
  file: string;
  line?: number;
  /** Published port labels, e.g. `['5432/tcp']`; each becomes a port node + `exposes` edge. */
  ports?: string[];
}

/**
 * A compose-shaped graph: one `service` node per spec, plus the `port` nodes
 * and `exposes` edges its `ports` imply. Node ids follow the graph builder's
 * own `kind:name:file` scheme so linkage behaves identically.
 */
export function composeGraph(services: readonly ServiceSpec[]): InfraGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  for (const service of services) {
    const serviceId = `service:${service.name}:${service.file}`;
    nodes.push({
      id: serviceId,
      kind: 'service',
      label: service.name,
      source: { file: service.file, line: service.line ?? 1 },
      attrs: {},
    });
    for (const port of service.ports ?? []) {
      const portId = `port:${port}:${service.file}`;
      nodes.push({
        id: portId,
        kind: 'port',
        label: port,
        source: { file: service.file, line: service.line ?? 1 },
        attrs: { protocol: 'tcp' },
      });
      edges.push({ from: serviceId, to: portId, kind: 'exposes' });
    }
  }
  return { nodes, edges };
}

/**
 * A Kubernetes-shaped graph: a workload with one container, linked by the
 * `connects` edge the real builder emits for containment — the edge linkage
 * relies on to fold a container back into its workload.
 */
export function workloadGraph(spec: {
  name: string;
  file: string;
  workloadLine?: number;
  containerLine?: number;
}): InfraGraph {
  const workloadId = `workload:${spec.name}:${spec.file}`;
  const containerId = `container:${spec.name}/app:${spec.file}`;
  return {
    nodes: [
      {
        id: workloadId,
        kind: 'workload',
        label: spec.name,
        source: { file: spec.file, line: spec.workloadLine ?? 1 },
        attrs: {},
      },
      {
        id: containerId,
        kind: 'container',
        label: 'app',
        source: { file: spec.file, line: spec.containerLine ?? 10 },
        attrs: {},
      },
    ],
    edges: [{ from: workloadId, to: containerId, kind: 'connects' }],
  };
}

/** Deterministic shuffle (seeded), for asserting order-independence. */
export function shuffle<T>(items: readonly T[], seed = 7): T[] {
  const out = [...items];
  let state = seed;
  for (let i = out.length - 1; i > 0; i -= 1) {
    state = (state * 1103515245 + 12345) % 2147483648;
    const j = state % (i + 1);
    const a = out[i];
    const b = out[j];
    if (a === undefined || b === undefined) continue;
    out[i] = b;
    out[j] = a;
  }
  return out;
}

/** The `AP00x` correlation id of a path, without its fingerprint suffix. */
export function correlationId(pathId: string): string {
  return pathId.split(':')[0] ?? pathId;
}
