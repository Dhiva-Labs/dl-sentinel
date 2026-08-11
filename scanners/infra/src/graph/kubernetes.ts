/**
 * Kubernetes → graph extraction. Reuses the scanner's own YAML plumbing
 * (`util/yaml-docs.ts`) and, importantly, the exact same pod-spec/container
 * resolution the I02x rules use (`../kubernetes/rules.ts`'s exported
 * `resolvePodSpecs`/`collectContainers`) so Pod/Deployment/StatefulSet/
 * DaemonSet/Job/CronJob nesting is handled identically in one place.
 */
import { isKubernetesDoc, lineForPath, parseYamlFile } from '../util/yaml-docs.js';
import { isDockerSocketPath } from '../util/host-path.js';
import { isUnpinnedImageRef } from '../util/image-ref.js';
import { collectContainers, resolvePodSpecs, type PathKey } from '../kubernetes/rules.js';
import type { GraphEdge, GraphNode } from './types.js';
import { HOST_NODE_ID, pushUniqueNode, scopedNodeId, sharedNodeId } from './id.js';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface KubernetesExtraction {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * Extract Kubernetes-sourced graph nodes/edges from one (possibly
 * multi-document) file. Returns `undefined` when the file isn't parseable
 * YAML or no document in it looks like a Kubernetes manifest (`kind` +
 * `apiVersion`) — the caller has already tried compose first.
 */
export function extractKubernetes(file: string, text: string): KubernetesExtraction | undefined {
  const parsed = parseYamlFile(text);
  if (!parsed) return undefined;
  const docsWithJs = parsed.documents.map((doc) => ({ doc, js: doc.toJS() as unknown }));
  if (!docsWithJs.some(({ js }) => isKubernetesDoc(js))) return undefined;

  const lineCounter = parsed.lineCounter;
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  let usesHostNode = false;

  for (const { doc, js } of docsWithJs) {
    if (!isPlainObject(js)) continue; // e.g. a `---` separator with nothing after it
    const lineAt = (path: PathKey[]): number | undefined => lineForPath(doc, lineCounter, path);
    const kind = typeof js.kind === 'string' ? js.kind : 'Workload';
    const metaName =
      isPlainObject(js.metadata) && typeof js.metadata.name === 'string'
        ? js.metadata.name
        : 'unnamed';

    for (const { spec: podSpec, basePath } of resolvePodSpecs(js)) {
      const workloadName = `${kind}/${metaName}`;
      const workloadId = scopedNodeId('workload', workloadName, file);
      const hostNetwork = podSpec.hostNetwork === true;
      const hostPID = podSpec.hostPID === true;
      const hostIPC = podSpec.hostIPC === true;

      nodes.push({
        id: workloadId,
        kind: 'workload',
        label: workloadName,
        source: { file, line: lineAt(['metadata', 'name']) ?? lineAt(['kind']) },
        attrs: { hostNetwork, hostPID, hostIPC },
      });

      if (hostNetwork || hostPID || hostIPC) {
        usesHostNode = true;
        edges.push({ from: workloadId, to: HOST_NODE_ID, kind: 'host-network' });
      }

      // hostPath volumes are declared once per pod spec, not per container;
      // this simplification attaches the mount to the workload rather than
      // resolving each container's individual volumeMounts, matching the
      // graph's descriptive (not exhaustive) scope.
      if (Array.isArray(podSpec.volumes)) {
        podSpec.volumes.forEach((rawVolume, idx) => {
          if (!isPlainObject(rawVolume)) return;
          const hostPath = rawVolume.hostPath;
          if (!isPlainObject(hostPath) || typeof hostPath.path !== 'string') return;
          const hostPathId = scopedNodeId('hostPath', hostPath.path, file);
          pushUniqueNode(nodes, {
            id: hostPathId,
            kind: 'hostPath',
            label: hostPath.path,
            source: { file, line: lineAt([...basePath, 'volumes', idx, 'hostPath', 'path']) },
            attrs: { dockerSocket: isDockerSocketPath(hostPath.path), readOnly: false },
          });
          edges.push({ from: workloadId, to: hostPathId, kind: 'mounts' });
        });
      }

      for (const containerRef of collectContainers(podSpec, basePath)) {
        const containerName =
          typeof containerRef.container.name === 'string'
            ? containerRef.container.name
            : `container${String(containerRef.path[containerRef.path.length - 1] ?? '')}`;
        const containerId = scopedNodeId('container', `${workloadName}/${containerName}`, file);
        const sc = containerRef.container.securityContext;
        const privileged = isPlainObject(sc) && sc.privileged === true;

        nodes.push({
          id: containerId,
          kind: 'container',
          label: containerName,
          source: { file, line: lineAt(containerRef.path) },
          attrs: { privileged },
        });
        // Structural containment: no edge kind in the fixed vocabulary means
        // "contains", so `connects` (the most generic relational kind) is
        // used to link a workload to its containers.
        edges.push({ from: workloadId, to: containerId, kind: 'connects' });

        if (
          typeof containerRef.container.image === 'string' &&
          containerRef.container.image.trim().length > 0
        ) {
          const ref = containerRef.container.image.trim();
          const imageId = sharedNodeId('image', ref);
          pushUniqueNode(nodes, {
            id: imageId,
            kind: 'image',
            label: ref,
            source: { file, line: lineAt([...containerRef.path, 'image']) },
            attrs: { unpinned: isUnpinnedImageRef(ref) },
          });
          edges.push({ from: containerId, to: imageId, kind: 'uses-image' });
        }

        if (privileged) {
          usesHostNode = true;
          edges.push({ from: containerId, to: HOST_NODE_ID, kind: 'privileged' });
        }

        if (Array.isArray(containerRef.container.ports)) {
          containerRef.container.ports.forEach((rawPort, idx) => {
            if (!isPlainObject(rawPort)) return;
            const containerPort =
              typeof rawPort.containerPort === 'number' ? rawPort.containerPort : undefined;
            if (containerPort === undefined) return;
            const protocol =
              typeof rawPort.protocol === 'string' ? rawPort.protocol.toLowerCase() : 'tcp';
            const label = `${containerPort}/${protocol}`;
            const portId = scopedNodeId('port', label, file);
            pushUniqueNode(nodes, {
              id: portId,
              kind: 'port',
              label,
              source: { file, line: lineAt([...containerRef.path, 'ports', idx]) },
              attrs: { protocol, containerPort },
            });
            edges.push({ from: containerId, to: portId, kind: 'exposes' });
          });
        }
      }
    }
  }

  if (usesHostNode) {
    pushUniqueNode(nodes, {
      id: HOST_NODE_ID,
      kind: 'network',
      label: 'host',
      source: { file },
      attrs: { synthesized: true },
    });
  }

  return { nodes, edges };
}
