/**
 * Top-level orchestrator: classify each input file, extract per-source
 * nodes/edges, merge everything into one deterministic graph, and
 * best-effort link compose `build:` contexts to the Dockerfile they build.
 */
import { posix } from 'node:path';
import type { GraphEdge, GraphNode, InfraGraph, InfraGraphFile } from './types.js';
import { extractCompose, type ComposeBuildContext } from './compose.js';
import { extractKubernetes } from './kubernetes.js';
import { extractDockerfile } from './dockerfile.js';

export type { InfraGraphFile } from './types.js';

/** Codepoint ordering: locale-independent, so output is stable everywhere (mirrors the engine's own file-sort convention). */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function isDockerfileName(relPath: string): boolean {
  const base = posix.basename(relPath);
  return base === 'Dockerfile' || base.startsWith('Dockerfile.') || base.endsWith('.dockerfile');
}

type FileKind = 'yaml' | 'dockerfile' | 'skip';

function classify(relPath: string): FileKind {
  if (relPath.endsWith('.yml') || relPath.endsWith('.yaml')) return 'yaml';
  if (isDockerfileName(relPath)) return 'dockerfile';
  // Notably includes `.tf`: Terraform is not a graph source (docs/architecture.md
  // "## Infrastructure graph" only names Dockerfile/Compose/Kubernetes), and
  // anything else (package.json, source files, ...) is simply not ours.
  return 'skip';
}

/**
 * Composite lookup key from parts that may themselves contain arbitrary
 * characters (paths, ids). `JSON.stringify` of the tuple delimits the parts
 * unambiguously without having to pick a separator character and hope it
 * never appears in a real path.
 */
function compositeKey(parts: readonly string[]): string {
  return JSON.stringify(parts);
}

/**
 * Build a deterministic infrastructure graph from a set of already-read
 * files. Same input (regardless of array order) always produces the same
 * output; a file that is malformed, unrecognized, or throws during
 * extraction simply contributes nothing — this never throws.
 */
export function buildInfraGraph(files: readonly InfraGraphFile[]): InfraGraph {
  // Sort before processing (not just before returning) so that decisions
  // which depend on "first occurrence wins" — which file's source position
  // is kept for a globally-shared node such as an `image` — are independent
  // of the order the caller happened to pass files in.
  const sortedFiles = [...files].sort((a, b) => compareStrings(a.relPath, b.relPath));

  const nodesById = new Map<string, GraphNode>();
  const edgeKeys = new Set<string>();
  const edges: GraphEdge[] = [];
  const buildContexts: ComposeBuildContext[] = [];
  const dockerfileImageByKey = new Map<string, string>();

  const addNode = (node: GraphNode): void => {
    if (!nodesById.has(node.id)) nodesById.set(node.id, node);
  };
  const addEdge = (edge: GraphEdge): void => {
    const key = compositeKey([edge.from, edge.to, edge.kind]);
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push(edge);
  };

  for (const file of sortedFiles) {
    const kind = classify(file.relPath);
    if (kind === 'skip') continue;
    try {
      if (kind === 'yaml') {
        const compose = extractCompose(file.relPath, file.text);
        if (compose) {
          compose.nodes.forEach(addNode);
          compose.edges.forEach(addEdge);
          buildContexts.push(...compose.buildContexts);
          continue;
        }
        const k8s = extractKubernetes(file.relPath, file.text);
        if (k8s) {
          k8s.nodes.forEach(addNode);
          k8s.edges.forEach(addEdge);
        }
        // Neither compose nor Kubernetes shaped: some other YAML file
        // (app config, OpenAPI, ...) — not this builder's concern.
      } else {
        const df = extractDockerfile(file.relPath, file.text);
        df.nodes.forEach(addNode);
        df.edges.forEach(addEdge);
        if (df.baseImageNodeId) {
          dockerfileImageByKey.set(compositeKey([df.dir, df.basename]), df.baseImageNodeId);
        }
      }
    } catch {
      // Malformed input must never fail graph construction — skip this
      // file's contribution, same tolerance as the scanner itself.
      continue;
    }
  }

  for (const ctx of buildContexts) {
    const imageId = dockerfileImageByKey.get(compositeKey([ctx.contextDir, ctx.dockerfileName]));
    if (imageId && nodesById.has(imageId)) {
      addEdge({ from: ctx.serviceNodeId, to: imageId, kind: 'uses-image' });
    }
    // No matching Dockerfile found in the build context: best-effort link
    // simply doesn't apply, the service node stands on its own.
  }

  const nodes = [...nodesById.values()].sort((a, b) => compareStrings(a.id, b.id));
  edges.sort(
    (a, b) =>
      compareStrings(a.from, b.from) ||
      compareStrings(a.to, b.to) ||
      compareStrings(a.kind, b.kind),
  );

  return { nodes, edges };
}
