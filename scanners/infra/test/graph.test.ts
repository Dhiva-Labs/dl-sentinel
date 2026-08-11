import { describe, expect, it } from 'vitest';
import type { GraphEdge, GraphNode, InfraGraph, InfraGraphFile } from '../src/index.js';
import { buildInfraGraph, renderInfraGraphMermaid } from '../src/index.js';
import { lineOf, readFixture } from './helpers.js';

function file(relPath: string): InfraGraphFile {
  return { relPath, text: readFixture(relPath) };
}

function byKind(nodes: readonly GraphNode[], kind: GraphNode['kind']): GraphNode[] {
  return nodes.filter((n) => n.kind === kind);
}

function edgesOfKind(edges: readonly GraphEdge[], kind: GraphEdge['kind']): GraphEdge[] {
  return edges.filter((e) => e.kind === kind);
}

describe('buildInfraGraph — compose', () => {
  it('produces the exact nodes and edges for a comprehensive single-file scenario', () => {
    const graph = buildInfraGraph([file('graph/compose-full/docker-compose.yml')]);

    expect(graph.nodes.map((n) => n.id)).toEqual([
      'hostPath:/var/run/docker.sock:graph/compose-full/docker-compose.yml',
      'image:example/app:1.0.0',
      'image:postgres:16',
      'network:host',
      'port:8080/tcp:graph/compose-full/docker-compose.yml',
      'service:app:graph/compose-full/docker-compose.yml',
      'service:db:graph/compose-full/docker-compose.yml',
      'volume:appdata:graph/compose-full/docker-compose.yml',
    ]);

    const byId = new Map(graph.nodes.map((n) => [n.id, n]));
    expect(
      byId.get('hostPath:/var/run/docker.sock:graph/compose-full/docker-compose.yml'),
    ).toMatchObject({
      kind: 'hostPath',
      label: '/var/run/docker.sock',
      attrs: { readOnly: false, dockerSocket: true },
    });
    expect(byId.get('image:example/app:1.0.0')).toMatchObject({
      kind: 'image',
      label: 'example/app:1.0.0',
      attrs: { unpinned: false },
    });
    expect(byId.get('network:host')).toMatchObject({
      kind: 'network',
      label: 'host',
      attrs: { synthesized: true },
    });
    expect(byId.get('port:8080/tcp:graph/compose-full/docker-compose.yml')).toMatchObject({
      kind: 'port',
      label: '8080/tcp',
      attrs: { protocol: 'tcp', hostPort: 8080, containerPort: 8080 },
    });
    expect(byId.get('service:app:graph/compose-full/docker-compose.yml')).toMatchObject({
      kind: 'service',
      label: 'app',
      attrs: { privileged: true },
    });
    expect(byId.get('service:db:graph/compose-full/docker-compose.yml')).toMatchObject({
      kind: 'service',
      label: 'db',
      attrs: { privileged: false },
    });
    expect(byId.get('volume:appdata:graph/compose-full/docker-compose.yml')).toMatchObject({
      kind: 'volume',
      label: 'appdata',
      attrs: { readOnly: false },
    });

    const text = readFixture('graph/compose-full/docker-compose.yml');
    // A compound path (`['services', name]`) resolves to the service body's
    // range, which yaml reports starting at its first child key — not the
    // `db:` key line itself; leaf paths (like the hostPath mount below)
    // resolve exactly to their own line.
    expect(byId.get('service:db:graph/compose-full/docker-compose.yml')?.source.line).toBe(
      lineOf(text, 'image: postgres:16'),
    );
    expect(
      byId.get('hostPath:/var/run/docker.sock:graph/compose-full/docker-compose.yml')?.source.line,
    ).toBe(lineOf(text, '/var/run/docker.sock:/var/run/docker.sock'));

    const app = 'service:app:graph/compose-full/docker-compose.yml';
    const db = 'service:db:graph/compose-full/docker-compose.yml';
    expect(graph.edges).toEqual([
      {
        from: app,
        to: 'hostPath:/var/run/docker.sock:graph/compose-full/docker-compose.yml',
        kind: 'mounts',
      },
      { from: app, to: 'image:example/app:1.0.0', kind: 'uses-image' },
      { from: app, to: 'network:host', kind: 'host-network' },
      { from: app, to: 'network:host', kind: 'privileged' },
      { from: app, to: 'port:8080/tcp:graph/compose-full/docker-compose.yml', kind: 'exposes' },
      { from: app, to: db, kind: 'depends-on' },
      { from: app, to: 'volume:appdata:graph/compose-full/docker-compose.yml', kind: 'mounts' },
      { from: db, to: 'image:postgres:16', kind: 'uses-image' },
    ]);
  });

  it('links depends_on (list and long-syntax map form) and links, dropping a dangling reference', () => {
    const graph = buildInfraGraph([file('graph/compose-relations/docker-compose.yml')]);
    const f = 'graph/compose-relations/docker-compose.yml';

    expect(edgesOfKind(graph.edges, 'depends-on')).toEqual([
      { from: `service:api:${f}`, to: `service:db:${f}`, kind: 'depends-on' },
      { from: `service:web:${f}`, to: `service:api:${f}`, kind: 'depends-on' },
    ]);
    expect(edgesOfKind(graph.edges, 'connects')).toEqual([
      { from: `service:api:${f}`, to: `service:cache:${f}`, kind: 'connects' },
    ]);
    // "missing-service" never appears as an edge target anywhere.
    expect(graph.edges.some((e) => e.to.startsWith('service:missing-service'))).toBe(false);
  });

  it('flags host mounts (short syntax) with dockerSocket set only for the docker.sock path', () => {
    const graph = buildInfraGraph([file('compose/host-mounts/docker-compose.yml')]);
    const hostPaths = byKind(graph.nodes, 'hostPath');
    expect(hostPaths.map((n) => n.label).sort()).toEqual([
      '/',
      '/etc',
      '/home/user/data',
      '/var/run/docker.sock',
    ]);
    const bySock = Object.fromEntries(hostPaths.map((n) => [n.label, n.attrs.dockerSocket]));
    expect(bySock['/var/run/docker.sock']).toBe(true);
    expect(bySock['/']).toBe(false);
    expect(edgesOfKind(graph.edges, 'mounts')).toHaveLength(4);
  });

  it('flags host mounts using the long volume syntax', () => {
    const graph = buildInfraGraph([file('compose/host-mounts-long-syntax/docker-compose.yml')]);
    const hostPaths = byKind(graph.nodes, 'hostPath');
    expect(hostPaths.map((n) => n.label).sort()).toEqual(['/etc', '/opt/data']);
  });

  it('treats named volumes (short and long syntax) as `volume` nodes, and skips anonymous mounts', () => {
    const graph = buildInfraGraph([file('compose/named-volumes/docker-compose.yml')]);
    expect(byKind(graph.nodes, 'hostPath')).toHaveLength(0);
    const volumes = byKind(graph.nodes, 'volume');
    expect(volumes.map((n) => n.label).sort()).toEqual(['appdata', 'cache']);
    // The anonymous container-only entry (`/var/lib/anonymous-container-path`)
    // has no stable source identity and must not produce a node or edge.
    expect(edgesOfKind(graph.edges, 'mounts')).toHaveLength(2);
  });

  it('creates one port node per distinct published port across services', () => {
    const graph = buildInfraGraph([file('compose/db-ports/docker-compose.yml')]);
    const ports = byKind(graph.nodes, 'port');
    expect(ports.map((n) => n.label).sort()).toEqual(['5432/tcp', '6379/tcp', '8080/tcp']);
    expect(edgesOfKind(graph.edges, 'exposes')).toHaveLength(3);
  });

  it('does not flag a service with no privileged/host-network/host-mount configuration', () => {
    const graph = buildInfraGraph([file('compose/not-privileged/docker-compose.yml')]);
    expect(byKind(graph.nodes, 'network')).toHaveLength(0);
    expect(graph.edges).toHaveLength(1); // just uses-image
    expect(graph.edges[0]?.kind).toBe('uses-image');
  });
});

describe('buildInfraGraph — kubernetes', () => {
  it('builds workload + container + image nodes for a Deployment, linked by connects/uses-image', () => {
    const graph = buildInfraGraph([file('kubernetes/clean/deployment.yaml')]);
    const f = 'kubernetes/clean/deployment.yaml';
    const workloadId = `workload:Deployment/clean-example:${f}`;
    const containerId = `container:Deployment/clean-example/app:${f}`;

    expect(graph.nodes.map((n) => n.id).sort()).toEqual(
      [containerId, 'image:example/app:1.0.0', workloadId].sort(),
    );
    expect(graph.edges).toEqual([
      { from: containerId, to: 'image:example/app:1.0.0', kind: 'uses-image' },
      { from: workloadId, to: containerId, kind: 'connects' },
    ]);
    const workload = graph.nodes.find((n) => n.id === workloadId);
    expect(workload?.attrs).toEqual({ hostNetwork: false, hostPID: false, hostIPC: false });
  });

  it('flags hostPath volumes across severity-agnostic tiers, with dockerSocket set correctly', () => {
    const graph = buildInfraGraph([file('kubernetes/hostpath-volumes/pod.yaml')]);
    const hostPaths = byKind(graph.nodes, 'hostPath');
    expect(hostPaths.map((n) => n.label).sort()).toEqual([
      '/',
      '/opt/data',
      '/var/run/docker.sock',
    ]);
    const bySock = Object.fromEntries(hostPaths.map((n) => [n.label, n.attrs.dockerSocket]));
    expect(bySock['/var/run/docker.sock']).toBe(true);
    expect(bySock['/']).toBe(false);
    expect(edgesOfKind(graph.edges, 'mounts')).toHaveLength(3);
  });

  it('collapses hostNetwork/hostPID/hostIPC into a single host-network edge', () => {
    const graph = buildInfraGraph([file('kubernetes/host-namespaces/pod.yaml')]);
    const workload = byKind(graph.nodes, 'workload')[0];
    expect(workload?.attrs).toEqual({ hostNetwork: true, hostPID: true, hostIPC: true });
    expect(edgesOfKind(graph.edges, 'host-network')).toHaveLength(1);
  });

  it('gives initContainers their own container nodes, and only the privileged one edges to host', () => {
    const graph = buildInfraGraph([file('kubernetes/init-containers/pod.yaml')]);
    const containers = byKind(graph.nodes, 'container');
    expect(containers).toHaveLength(2);
    const byLabel = Object.fromEntries(containers.map((n) => [n.label, n.attrs.privileged]));
    expect(byLabel.init).toBe(true);
    expect(byLabel.app).toBe(false);
    expect(edgesOfKind(graph.edges, 'privileged')).toHaveLength(1);
    expect(edgesOfKind(graph.edges, 'connects')).toHaveLength(2); // workload -> each container
  });

  it('creates container -> port exposes edges from containerPort entries', () => {
    const graph = buildInfraGraph([file('graph/k8s-containerports/pod.yaml')]);
    const ports = byKind(graph.nodes, 'port');
    expect(ports.map((n) => n.label).sort()).toEqual(['8080/tcp', '9090/udp']);
    const exposes = edgesOfKind(graph.edges, 'exposes');
    expect(exposes).toHaveLength(2);
    expect(exposes.every((e) => e.from.startsWith('container:'))).toBe(true);
  });

  it('resolves Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob workloads and skips Service/ConfigMap without crashing', () => {
    const graph = buildInfraGraph([file('kubernetes/kind-resolution/manifests.yaml')]);
    const workloads = byKind(graph.nodes, 'workload');
    expect(workloads.map((n) => n.label).sort()).toEqual([
      'CronJob/cronjob-example',
      'DaemonSet/daemonset-example',
      'Deployment/deployment-example',
      'Job/job-example',
      'Pod/pod-example',
      'StatefulSet/statefulset-example',
    ]);
    // Deployment's initContainer + container -> 2 container nodes there,
    // plus one container node per other workload (5) = 7 total.
    expect(byKind(graph.nodes, 'container')).toHaveLength(7);
  });
});

describe('buildInfraGraph — dockerfile', () => {
  it('produces an image node for a pinned base and a port node per EXPOSEd port', () => {
    const graph = buildInfraGraph([file('dockerfile/admin-port/Dockerfile')]);
    const images = byKind(graph.nodes, 'image');
    expect(images).toHaveLength(1);
    expect(images[0]?.attrs.unpinned).toBe(false);
    const ports = byKind(graph.nodes, 'port');
    expect(ports.map((n) => n.label).sort()).toEqual(['22/tcp', '8080/tcp']);
    expect(edgesOfKind(graph.edges, 'exposes')).toHaveLength(2);
    expect(graph.edges.every((e) => e.from === images[0]?.id)).toBe(true);
  });

  it("uses only the final stage's base image in a multi-stage build, not the builder's", () => {
    const graph = buildInfraGraph([file('dockerfile/multistage-final-root/Dockerfile')]);
    const images = byKind(graph.nodes, 'image');
    expect(images).toHaveLength(1);
    expect(images[0]?.label).toContain(
      'sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3',
    );
  });

  it('resolves a final-stage alias (`FROM <earlier-stage>`) back to the real base image', () => {
    const graph = buildInfraGraph([file('dockerfile/stage-alias/Dockerfile')]);
    const images = byKind(graph.nodes, 'image');
    expect(images).toHaveLength(1);
    expect(images[0]?.label).toContain('sha256:');
    expect(images[0]?.label.toLowerCase().startsWith('build')).toBe(false);
  });

  it('produces no image node for a `scratch` base', () => {
    const graph = buildInfraGraph([file('dockerfile/scratch-base/Dockerfile')]);
    expect(graph.nodes).toHaveLength(0);
    expect(graph.edges).toHaveLength(0);
  });
});

describe('buildInfraGraph — cross-file linking', () => {
  it('links a compose service built from a local Dockerfile to both its tagged image and the Dockerfile base image', () => {
    const graph = buildInfraGraph([
      file('graph/compose-build-link/docker-compose.yml'),
      file('graph/compose-build-link/Dockerfile'),
    ]);

    const service = byKind(graph.nodes, 'service')[0];
    expect(service).toBeDefined();
    const usesImage = edgesOfKind(graph.edges, 'uses-image').filter((e) => e.from === service?.id);
    expect(usesImage.map((e) => e.to).sort()).toEqual([
      'image:build-link-fixture:latest',
      'image:node:latest',
    ]);

    // The Dockerfile's own EXPOSE port is still present and attached to its image.
    const ports = byKind(graph.nodes, 'port');
    expect(ports.map((n) => n.label)).toEqual(['3000/tcp']);
    expect(edgesOfKind(graph.edges, 'exposes')).toEqual([
      { from: 'image:node:latest', to: ports[0]?.id, kind: 'exposes' },
    ]);
  });

  it('leaves an unmatched build: context standalone (no crash, no spurious link)', () => {
    const graph = buildInfraGraph([file('graph/compose-build-link/docker-compose.yml')]); // no Dockerfile provided
    const service = byKind(graph.nodes, 'service')[0];
    const usesImage = edgesOfKind(graph.edges, 'uses-image').filter((e) => e.from === service?.id);
    expect(usesImage.map((e) => e.to)).toEqual(['image:build-link-fixture:latest']);
  });
});

describe('buildInfraGraph — determinism', () => {
  const inputs: InfraGraphFile[] = [
    file('graph/compose-full/docker-compose.yml'),
    file('graph/compose-relations/docker-compose.yml'),
    file('kubernetes/hostpath-volumes/pod.yaml'),
    file('kubernetes/init-containers/pod.yaml'),
    file('dockerfile/admin-port/Dockerfile'),
    file('graph/compose-build-link/docker-compose.yml'),
    file('graph/compose-build-link/Dockerfile'),
  ];

  it('produces byte-identical output across repeated builds', () => {
    const first = buildInfraGraph(inputs);
    const second = buildInfraGraph(inputs);
    expect(second).toEqual(first);
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });

  it('is unaffected by the order files are passed in', () => {
    const inOrder = buildInfraGraph(inputs);
    const shuffled = [...inputs].reverse();
    const reversed = buildInfraGraph(shuffled);
    expect(reversed).toEqual(inOrder);

    // A non-trivial permutation, not just a reversal.
    const permuted = [
      inputs[3],
      inputs[0],
      inputs[5],
      inputs[1],
      inputs[6],
      inputs[2],
      inputs[4],
    ].filter((f): f is InfraGraphFile => f !== undefined);
    expect(permuted).toHaveLength(inputs.length);
    const alsoPermuted = buildInfraGraph(permuted);
    expect(alsoPermuted).toEqual(inOrder);
  });
});

describe('buildInfraGraph — id collision safety', () => {
  it('keeps two files that declare a service with the same name as two distinct nodes', () => {
    const graph = buildInfraGraph([
      file('graph/id-collision/a/docker-compose.yml'),
      file('graph/id-collision/b/docker-compose.yml'),
    ]);
    const services = byKind(graph.nodes, 'service');
    expect(services).toHaveLength(2);
    expect(services.map((n) => n.id).sort()).toEqual([
      'service:app:graph/id-collision/a/docker-compose.yml',
      'service:app:graph/id-collision/b/docker-compose.yml',
    ]);
    expect(services[0]?.id).not.toBe(services[1]?.id);
  });
});

describe('buildInfraGraph — malformed input handling', () => {
  it('skips malformed YAML/Dockerfiles without throwing, while a valid file still contributes', () => {
    const inputs: InfraGraphFile[] = [
      file('malformed/invalid.yaml'),
      file('malformed/empty.yml'),
      file('malformed/empty-dockerfile/Dockerfile'),
      file('compose/privileged/docker-compose.yml'),
    ];
    expect(() => buildInfraGraph(inputs)).not.toThrow();
    const graph = buildInfraGraph(inputs);
    expect(byKind(graph.nodes, 'service')).toHaveLength(1);
    expect(graph.nodes.find((n) => n.id.includes('malformed'))).toBeUndefined();
  });

  it('does not crash on a Dockerfile truncated mid-continuation', () => {
    expect(() =>
      buildInfraGraph([file('malformed/truncated-dockerfile/Dockerfile')]),
    ).not.toThrow();
  });

  it('does not crash on malformed (brace-unbalanced) Terraform, and simply ignores it', () => {
    const graph = buildInfraGraph([file('terraform/malformed/main.tf')]);
    expect(graph.nodes).toHaveLength(0);
    expect(graph.edges).toHaveLength(0);
  });
});

describe('renderInfraGraphMermaid', () => {
  function graphOf(nodes: GraphNode[], edges: GraphEdge[] = []): InfraGraph {
    return { nodes, edges };
  }

  it('starts with the flowchart header and produces one node declaration line per node', () => {
    const graph = buildInfraGraph([file('graph/compose-full/docker-compose.yml')]);
    const rendered = renderInfraGraphMermaid(graph);
    const lines = rendered.split('\n').filter((l) => l.length > 0);
    expect(lines[0]).toBe('flowchart LR');

    const nodeLines = lines.filter((l) => /^ {2}n\d+[[({]/.test(l));
    expect(nodeLines).toHaveLength(graph.nodes.length);
  });

  it('assigns classes only to declared node ids', () => {
    const graph = buildInfraGraph([file('graph/compose-full/docker-compose.yml')]);
    const rendered = renderInfraGraphMermaid(graph);
    const lines = rendered.split('\n');
    const declaredIds = new Set(
      lines
        .map((l) => /^ {2}(n\d+)[[({]/.exec(l)?.[1])
        .filter((id): id is string => id !== undefined),
    );
    const classLines = lines.filter((l) => l.startsWith('  class '));
    expect(classLines.length).toBeGreaterThan(0);
    for (const line of classLines) {
      const idsPart = line.replace('  class ', '').split(' ')[0] ?? '';
      for (const id of idsPart.split(',')) {
        expect(declaredIds.has(id)).toBe(true);
      }
    }
  });

  it('styles a hostPath node, a privileged node, and a host-network source node as risky', () => {
    const graph = buildInfraGraph([file('graph/compose-full/docker-compose.yml')]);
    const rendered = renderInfraGraphMermaid(graph);
    const idMap = new Map(graph.nodes.map((n, i) => [n.id, `n${i}`]));

    const hostPathMermaidId = idMap.get(
      'hostPath:/var/run/docker.sock:graph/compose-full/docker-compose.yml',
    );
    const appMermaidId = idMap.get('service:app:graph/compose-full/docker-compose.yml'); // privileged AND host-network source
    const riskyLine = rendered
      .split('\n')
      .find((l) => l.startsWith('  class ') && l.endsWith(' risky'));
    expect(riskyLine).toBeDefined();
    const riskyIds = (riskyLine ?? '').replace('  class ', '').split(' risky')[0]?.split(',') ?? [];
    expect(riskyIds).toContain(hostPathMermaidId);
    expect(riskyIds).toContain(appMermaidId);
  });

  it('gives images, volumes, and ports distinct mermaid shapes from the default box', () => {
    const graph = buildInfraGraph([file('graph/compose-full/docker-compose.yml')]);
    const rendered = renderInfraGraphMermaid(graph);
    expect(rendered).toMatch(/n\d+\(\("example\/app:1\.0\.0"\)\)/); // image: circle
    expect(rendered).toMatch(/n\d+\{\{"8080\/tcp"\}\}/); // port: hexagon
    expect(rendered).toMatch(/n\d+\[\("appdata"\)\]/); // volume: cylinder
  });

  it('never lets an untrusted node label break out of its quoted mermaid string', () => {
    const malicious = 'a"]; click evil';
    const graph = graphOf([
      {
        id: 'service:evil:x',
        kind: 'service',
        label: malicious,
        source: { file: 'x' },
        attrs: { privileged: false },
      },
    ]);
    const rendered = renderInfraGraphMermaid(graph);
    expect(rendered).not.toContain(malicious);
    expect(rendered).toContain('#quot;');
    expect(rendered).toContain('flowchart LR');
  });

  it('renders an empty graph as valid, minimal mermaid', () => {
    const rendered = renderInfraGraphMermaid(graphOf([], []));
    expect(rendered.trim()).toBe('flowchart LR');
  });
});
