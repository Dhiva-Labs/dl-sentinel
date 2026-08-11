/**
 * Data model for the infrastructure graph — a deterministic model of the
 * deployment surface built from the same Dockerfile/Compose/Kubernetes
 * parses the infra scanner's rules use. Contract: docs/architecture.md
 * "## Infrastructure graph". The graph is descriptive, not a finding
 * source: it never asserts a value judgement itself, it only exposes the
 * flags (`attrs`) a consumer (the mermaid renderer, or a future
 * attack-path analyzer) can use to do so.
 */

export type GraphNodeKind =
  'service' | 'workload' | 'container' | 'image' | 'volume' | 'network' | 'hostPath' | 'port';

export type GraphEdgeKind =
  'uses-image' | 'mounts' | 'exposes' | 'connects' | 'depends-on' | 'host-network' | 'privileged';

export interface GraphNodeSource {
  /** Repo-relative posix path of the file that declared (or best represents) this node. */
  file: string;
  /** 1-based line number, when a precise source position could be resolved. */
  line?: number;
}

/** Free-form flags a node carries, e.g. `{ privileged: true }`, `{ hostPort: 5432 }`. */
export type GraphNodeAttrs = Record<string, string | number | boolean>;

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  source: GraphNodeSource;
  attrs: GraphNodeAttrs;
}

/**
 * `from`/`to` are always ids of nodes present in the same {@link InfraGraph}'s
 * `nodes` array — `buildInfraGraph` never emits a dangling edge endpoint.
 */
export interface GraphEdge {
  from: string;
  to: string;
  kind: GraphEdgeKind;
}

export interface InfraGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** One scanned file, as handed to `buildInfraGraph`. */
export interface InfraGraphFile {
  /** Repo-relative posix path (used to build node ids and `source.file`). */
  relPath: string;
  text: string;
}
