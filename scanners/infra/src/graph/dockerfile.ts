/**
 * Dockerfile → graph extraction. Reuses the scanner's own instruction
 * parser (`dockerfile/parse.ts`) — only the interpretation (which
 * instructions become which nodes/edges) is new.
 *
 * A standalone Dockerfile has no service/workload of its own, so it
 * contributes: an `image` node for the final build stage's base image
 * (what this Dockerfile is built FROM — resolving stage-alias `FROM
 * <earlier-stage>` references back to the real image), and `port` nodes
 * for its `EXPOSE`d ports, linked from that image with `exposes`. The
 * top-level builder (`build.ts`) separately best-effort links a compose
 * service's `build:` context to this file's base-image node.
 */
import { posix } from 'node:path';
import { parseDockerfile, type DockerStage } from '../dockerfile/parse.js';
import { isUnpinnedImageRef } from '../util/image-ref.js';
import type { GraphEdge, GraphNode } from './types.js';
import { pushUniqueNode, scopedNodeId, sharedNodeId } from './id.js';

export interface DockerfileExtraction {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** The final stage's base-image node id, when a real (non-`scratch`) base was found. */
  baseImageNodeId?: string;
  /** posix-normalized directory of this Dockerfile, relative to the repo root. */
  dir: string;
  basename: string;
}

/**
 * Resolve the final stage to a real base image, following `FROM
 * <earlier-stage-name>` alias chains backwards (mirroring how `docker
 * build` itself resolves them). Returns `undefined` if the chain doesn't
 * bottom out in a real stage (should not happen for a valid Dockerfile,
 * but malformed input must never throw here).
 */
function resolveFinalStage(stages: readonly DockerStage[]): DockerStage | undefined {
  const final = stages[stages.length - 1];
  if (!final) return undefined;
  if (!final.isAlias) return final;

  const byNameLower = new Map(
    stages.filter((s) => s.name !== undefined).map((s) => [s.name?.toLowerCase(), s] as const),
  );
  let current: DockerStage | undefined = final;
  const seenIndexes = new Set<number>();
  while (current !== undefined && current.isAlias && !seenIndexes.has(current.index)) {
    seenIndexes.add(current.index);
    current = byNameLower.get(current.image.toLowerCase());
  }
  return current !== undefined && !current.isAlias ? current : undefined;
}

export function extractDockerfile(file: string, text: string): DockerfileExtraction {
  const parsed = parseDockerfile(text);
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const dir = posix.dirname(file);
  const basename = posix.basename(file);

  const finalStage = resolveFinalStage(parsed.stages);
  let baseImageNodeId: string | undefined;

  if (finalStage && finalStage.image.trim().toLowerCase() !== 'scratch') {
    const ref = finalStage.image.trim();
    baseImageNodeId = sharedNodeId('image', ref);
    nodes.push({
      id: baseImageNodeId,
      kind: 'image',
      label: ref,
      source: { file, line: finalStage.fromLine },
      attrs: { unpinned: isUnpinnedImageRef(ref) },
    });

    for (const inst of parsed.instructions) {
      if (inst.instruction !== 'EXPOSE') continue;
      for (const token of inst.args.split(/\s+/).filter(Boolean)) {
        const match = /^(\d+)(?:\/(tcp|udp))?$/i.exec(token);
        if (!match?.[1]) continue;
        const port = Number.parseInt(match[1], 10);
        const protocol = (match[2] ?? 'tcp').toLowerCase();
        const label = `${port}/${protocol}`;
        const portId = scopedNodeId('port', label, file);
        pushUniqueNode(nodes, {
          id: portId,
          kind: 'port',
          label,
          source: { file, line: inst.line },
          attrs: { protocol, containerPort: port },
        });
        edges.push({ from: baseImageNodeId, to: portId, kind: 'exposes' });
      }
    }
  }

  return { nodes, edges, baseImageNodeId, dir, basename };
}
