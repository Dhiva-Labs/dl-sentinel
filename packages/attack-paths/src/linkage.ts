/**
 * Linkage: deciding whether two findings plausibly describe the *same* running
 * thing, and saying so honestly.
 *
 * Two findings in one repository prove nothing about each other. What raises a
 * candidate chain above "these both exist" is a concrete link, and there are
 * exactly two the analyzer will accept:
 *
 * 1. **Graph linkage** — the infrastructure graph resolves both findings to the
 *    same service/workload node (`GraphNode.source.file` plus the nearest
 *    preceding `source.line`). This is the strong link.
 * 2. **File linkage** — both findings are declared in the same document. Weaker
 *    (one compose file can declare unrelated services) but still concrete.
 *
 * Anything else is repository co-occurrence, and every rule that rests on it
 * says `potential`. When no graph is supplied, graph linkage is simply
 * unavailable — it is never guessed at from file paths.
 */
import { posix } from 'node:path';
import type { Finding } from '@dl-sentinel/core';
import type { GraphNode, GraphNodeKind, InfraGraph } from '@dl-sentinel/scanner-infra';

/** Node kinds that stand for "a deployable thing" — the unit a chain happens in. */
const SERVICE_KINDS: ReadonlySet<GraphNodeKind> = new Set<GraphNodeKind>([
  'service',
  'workload',
  'container',
]);

/**
 * The thing a finding belongs to. Graph-backed when the graph could resolve it,
 * otherwise a fallback standing for the whole file.
 */
export interface ServiceUnit {
  /** Graph node id when {@link graphLinked}, else `file:<repo-relative path>`. */
  id: string;
  /** Display name: the node's label, or the file path for a file unit. */
  label: string;
  /** Repo-relative posix path this unit was resolved from. */
  file: string;
  kind: GraphNodeKind | 'file';
  /** True only when the infrastructure graph resolved this unit. */
  graphLinked: boolean;
}

/** Codepoint ordering: locale-independent, matching the graph's own node ordering. */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function fileUnit(file: string): ServiceUnit {
  return { id: `file:${file}`, label: file, file, kind: 'file', graphLinked: false };
}

/**
 * Graph- and file-level linkage over one report/graph pair. Construct with
 * {@link createLinkage}; a linkage built without a graph answers every
 * graph question with "nothing observed" rather than a guess.
 */
export interface Linkage {
  /** True when an infrastructure graph was supplied. */
  readonly hasGraph: boolean;
  /** The unit a finding belongs to — graph node when resolvable, else its file. */
  unitOf(finding: Finding): ServiceUnit;
  /** Port labels (e.g. `5432/tcp`) the graph shows `unit` publishing, sorted. */
  exposedPortsOf(unit: ServiceUnit): string[];
  /** Every graph unit that publishes at least one port, sorted by unit id. */
  exposedUnits(): ServiceUnit[];
}

/**
 * Resolve the graph node a finding sits in: among the service/workload/
 * container nodes declared in the same file, the one whose source line most
 * closely precedes the finding's line. A compose service's key is declared
 * above its `privileged:`/`ports:`/`volumes:` entries, and a pod container
 * above its `securityContext`, so "nearest preceding declaration" is what
 * ownership looks like in both formats.
 */
function resolveNode(
  nodesByFile: ReadonlyMap<string, GraphNode[]>,
  finding: Finding,
): GraphNode | undefined {
  const candidates = nodesByFile.get(finding.file);
  if (candidates === undefined || candidates.length === 0) return undefined;
  const first = candidates[0];
  if (finding.line === undefined) return first;
  let best: GraphNode | undefined;
  for (const node of candidates) {
    const line = node.source.line;
    if (line === undefined || line > finding.line) continue;
    best = node;
  }
  // A finding above every declaration in the file (a document-level finding,
  // say) still belongs to that file's first declared unit rather than to
  // nothing at all.
  return best ?? first;
}

export function createLinkage(graph?: InfraGraph): Linkage {
  if (graph === undefined) {
    return {
      hasGraph: false,
      unitOf: (finding) => fileUnit(finding.file),
      exposedPortsOf: () => [],
      exposedUnits: () => [],
    };
  }

  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));

  // Service-ish nodes per file, ordered by source line then id, so
  // "nearest preceding declaration" is a deterministic scan.
  const nodesByFile = new Map<string, GraphNode[]>();
  for (const node of graph.nodes) {
    if (!SERVICE_KINDS.has(node.kind)) continue;
    const bucket = nodesByFile.get(node.source.file);
    if (bucket === undefined) nodesByFile.set(node.source.file, [node]);
    else bucket.push(node);
  }
  for (const bucket of nodesByFile.values()) {
    bucket.sort(
      (a, b) => (a.source.line ?? 0) - (b.source.line ?? 0) || compareStrings(a.id, b.id),
    );
  }

  // A Kubernetes container is part of its workload, and the workload is the
  // unit an operator deploys — so a container node folds into its parent
  // (the `connects` edge the graph builder emits for containment).
  const parentOfContainer = new Map<string, string>();
  for (const edge of graph.edges) {
    if (edge.kind !== 'connects') continue;
    const from = nodesById.get(edge.from);
    const to = nodesById.get(edge.to);
    if (from?.kind !== 'workload' || to?.kind !== 'container') continue;
    if (!parentOfContainer.has(to.id)) parentOfContainer.set(to.id, from.id);
  }

  const toUnit = (node: GraphNode): ServiceUnit => {
    const parentId = node.kind === 'container' ? parentOfContainer.get(node.id) : undefined;
    const resolved = (parentId === undefined ? undefined : nodesById.get(parentId)) ?? node;
    return {
      id: resolved.id,
      label: resolved.label,
      file: resolved.source.file,
      kind: resolved.kind,
      graphLinked: true,
    };
  };

  // Ports reachable from a unit: its own `exposes` edges, plus those of the
  // containers it owns (a workload exposes what its containers expose).
  const portsByUnit = new Map<string, Set<string>>();
  const addPort = (unitId: string, portNodeId: string): void => {
    const port = nodesById.get(portNodeId);
    if (port?.kind !== 'port') return;
    const bucket = portsByUnit.get(unitId);
    if (bucket === undefined) portsByUnit.set(unitId, new Set([port.label]));
    else bucket.add(port.label);
  };
  for (const edge of graph.edges) {
    if (edge.kind !== 'exposes') continue;
    const from = nodesById.get(edge.from);
    if (from === undefined || !SERVICE_KINDS.has(from.kind)) continue;
    addPort(toUnit(from).id, edge.to);
  }

  return {
    hasGraph: true,
    unitOf: (finding) => {
      const node = resolveNode(nodesByFile, finding);
      return node === undefined ? fileUnit(finding.file) : toUnit(node);
    },
    exposedPortsOf: (unit) => [...(portsByUnit.get(unit.id) ?? [])].sort(compareStrings),
    exposedUnits: () =>
      [...portsByUnit.keys()]
        .sort(compareStrings)
        .map((id) => nodesById.get(id))
        .filter((node): node is GraphNode => node !== undefined)
        .map(toUnit),
  };
}

/** Both findings resolved to the same graph service/workload node. */
export function sameGraphUnit(a: ServiceUnit, b: ServiceUnit): boolean {
  return a.graphLinked && b.graphLinked && a.id === b.id;
}

/** Same repo-relative directory — compose reads its `.env` from exactly there. */
export function sameDirectory(a: string, b: string): boolean {
  return posix.dirname(a) === posix.dirname(b);
}

/**
 * Narrative-ready noun phrase for a link between two findings in the same
 * unit. Written to follow "declared in ...", so it composes into a sentence
 * without the caller having to know whether the link was graph- or file-level.
 */
export function unitPhrase(unit: ServiceUnit): string {
  return unit.graphLinked
    ? `the same ${unit.kind} \`${unit.label}\` (\`${unit.file}\`)`
    : `the same file \`${unit.file}\``;
}

/** Noun phrase for the weakest link the analyzer will report. */
export const REPO_PHRASE = 'co-location in this repository';
