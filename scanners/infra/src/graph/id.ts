import type { GraphNode, GraphNodeKind } from './types.js';

/**
 * Stable, collision-safe id scheme: `kind:name` for entities that are
 * genuinely global (the same real-world artifact wherever it is
 * mentioned), `kind:name:file` for everything that only means something in
 * the context of the file that declared it.
 *
 * Every node kind that is *declared* inside one file (service, workload,
 * container, volume, hostPath, port) is scoped with {@link scopedNodeId} —
 * the same name in a different file is always a different node, which is
 * what makes two files that happen to declare a service called "app" safe
 * to merge into one graph without collision. `image` nodes use
 * {@link sharedNodeId}: a real image reference (e.g. `postgres:16`) is the
 * same artifact regardless of which file mentions it, so services/
 * containers across files that reference it should fan in to one node. The
 * synthesized host node ({@link HOST_NODE_ID}) is a singleton for the same
 * reason.
 */
export function scopedNodeId(kind: GraphNodeKind, name: string, file: string): string {
  return `${kind}:${name}:${file}`;
}

export function sharedNodeId(kind: GraphNodeKind, name: string): string {
  return `${kind}:${name}`;
}

/**
 * Singleton node representing "the underlying host" — the target of
 * `host-network` edges (`network_mode: host` / `hostNetwork`/`hostPID`/
 * `hostIPC`) and `privileged` edges. There is exactly one of these per
 * graph, however many files or services reach it.
 */
export const HOST_NODE_ID = sharedNodeId('network', 'host');

/**
 * Append `node` unless a node with the same id is already present. Used by
 * each per-source extractor (compose/kubernetes/dockerfile) when a single
 * file's own walk can reach the same shared node twice — e.g. two services
 * in one compose file referencing the same image, or a privileged flag and
 * a host-network flag both wanting the singleton host node. Cross-file
 * dedup happens separately in `build.ts`.
 */
export function pushUniqueNode(nodes: GraphNode[], node: GraphNode): void {
  if (nodes.some((n) => n.id === node.id)) return;
  nodes.push(node);
}
